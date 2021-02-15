// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright The Asahi Linux Contributors
 *
 * Based on irq-lpc32xx:
 *   Copyright 2015-2016 Vladimir Zapolskiy <vz@mleia.com>
 * Based on irq-bcm2836:
 *   Copyright 2015 Broadcom
 */

/*
 * AIC is a fairly simple interrupt controller with the following features:
 *
 * - 896 level-triggered hardware IRQs
 *   - Single mask bit per IRQ
 *   - Per-IRQ affinity setting
 *   - Automatic masking on event delivery (auto-ack)
 *   - Software triggering (ORed with hw line)
 * - 2 per-CPU IPIs (meant as "self" and "other", but they are interchangeable if not symmetric)
 * - Automatic prioritization (single event/ack register per CPU, lower IRQs = higher priority)
 * - Automatic masking on ack
 * - Default "this CPU" register view and explicit per-CPU views
 *
 * In addition, this driver also handles FIQs, as these are routed to the same IRQ vector. These
 * are used for Fast IPIs (TODO), the ARMv8 timer IRQs, and performance counters (TODO).
 *
 * Implementation notes:
 *
 * - This driver creates two IRQ domains, one for HW IRQs and internal FIQs, and one for IPIs
 * - Since Linux needs more than 2 IPIs, we implement a software IRQ controller and funnel all IPIs
 *   into one per-CPU IPI (the second "self" IPI is unused).
 * - FIQ hwirq numbers are assigned after true hwirqs, and are per-cpu
 * - DT bindings use 3-cell form (like GIC):
 *   - <0 nr flags> - hwirq #nr
 *   - <1 nr flags> - FIQ #nr
 *     - nr=0  Physical HV timer
 *     - nr=1  Virtual HV timer
 *     - nr=2  Physical guest timer
 *     - nr=3  Virtual guest timer
 *
 */

#define pr_fmt(fmt) "%s: " fmt, __func__

#include <linux/io.h>
#include <linux/irqchip.h>
#include <linux/irqchip/arm-gic-v3.h>
#include <linux/of_address.h>
#include <linux/of_irq.h>
#include <linux/of_platform.h>
#include <linux/slab.h>
#include <asm/exception.h>
#include <asm/sysreg.h>
#include <asm/sysreg_apple.h>

#include <dt-bindings/interrupt-controller/apple-aic.h>

#define AIC_INFO		0x0004
#define AIC_INFO_NR_HW(i)	((i) & 0x0000ffff)

#define AIC_CONFIG		0x0010

#define AIC_WHOAMI		0x2000
#define AIC_EVENT		0x2004
#define AIC_EVENT_TYPE(v)	(v >> 16)
#define AIC_EVENT_NUM(v)	(v & 0xffff)

#define AIC_EVENT_TYPE_HW	1
#define AIC_EVENT_TYPE_IPI	4
#define AIC_EVENT_IPI_OTHER	1
#define AIC_EVENT_IPI_SELF	2

#define AIC_IPI_SEND		0x2008
#define AIC_IPI_ACK		0x200c
#define AIC_IPI_MASK_SET	0x2024
#define AIC_IPI_MASK_CLR	0x2028

#define AIC_IPI_SEND_CPU(cpu)	BIT(cpu)

#define AIC_IPI_OTHER		BIT(0)
#define AIC_IPI_SELF		BIT(31)

#define AIC_TARGET_CPU		0x3000
#define AIC_SW_SET		0x4000
#define AIC_SW_CLR		0x4080
#define AIC_MASK_SET		0x4100
#define AIC_MASK_CLR		0x4180

#define AIC_CPU_IPI_SET(cpu)	(0x5008 + (cpu << 7))
#define AIC_CPU_IPI_CLR(cpu)	(0x500c + (cpu << 7))
#define AIC_CPU_IPI_MASK_SET(cpu) (0x5024 + (cpu << 7))
#define AIC_CPU_IPI_MASK_CLR(cpu) (0x5028 + (cpu << 7))

#define MASK_REG(x)		(4 * ((x) >> 5))
#define MASK_BIT(x)		BIT((x) & 0x1f)

#define AIC_NR_FIQ		4
#define AIC_NR_SWIPI		32

/*
 * Max 31 bits in IPI SEND register (top bit is self).
 * >=32-core chips will need code changes anyway.
 */
#define AIC_MAX_CPUS 31

struct aic_irq_chip {
	void __iomem *base;
	struct irq_domain *hw_domain;
	struct irq_domain *ipi_domain;
	int nr_hw;
	int ipi_hwirq;
};

static atomic_t aic_vipi_flag[AIC_MAX_CPUS];
static atomic_t aic_vipi_mask[AIC_MAX_CPUS];

static struct aic_irq_chip *aic_irqc;

static void aic_handle_ipi(struct pt_regs *regs);

static u32 aic_ic_read(struct aic_irq_chip *ic, u32 reg)
{
	return readl_relaxed(ic->base + reg);
}

static void aic_ic_write(struct aic_irq_chip *ic, u32 reg, u32 val)
{
	writel_relaxed(val, ic->base + reg);
}

/*
 * IRQ irqchip
 */

static void aic_irq_mask(struct irq_data *d)
{
	struct aic_irq_chip *ic = irq_data_get_irq_chip_data(d);

	aic_ic_write(ic, AIC_MASK_SET + MASK_REG(d->hwirq),
		     MASK_BIT(d->hwirq));
}

static void aic_irq_unmask(struct irq_data *d)
{
	struct aic_irq_chip *ic = irq_data_get_irq_chip_data(d);

	aic_ic_write(ic, AIC_MASK_CLR + MASK_REG(d->hwirq),
		     MASK_BIT(d->hwirq));
}

static void aic_irq_eoi(struct irq_data *d)
{
	/*
	 * Reading the interrupt reason automatically acknowledges and masks
	 * the IRQ, so we just unmask it here if needed.
	 */
	if (!irqd_irq_disabled(d) && !irqd_irq_masked(d))
		aic_irq_unmask(d);
}

static void aic_handle_irq(struct pt_regs *regs)
{
	struct aic_irq_chip *ic = aic_irqc;
	u32 event, type, irq;

	do {
		/*
		 * We cannot use a relaxed read here, as DMA needs to be
		 * ordered with respect to the IRQ firing.
		 */
		event = readl(ic->base + AIC_EVENT);
		type = AIC_EVENT_TYPE(event);
		irq = AIC_EVENT_NUM(event);

		if (type == AIC_EVENT_TYPE_HW)
			handle_domain_irq(aic_irqc->hw_domain, irq, regs);
		else if (type == AIC_EVENT_TYPE_IPI && irq == 1)
			aic_handle_ipi(regs);
		else if (event != 0)
			pr_err("Unknown IRQ event %d, %d\n", type, irq);
	} while (event);

	/*
	 * vGIC maintenance interrupts end up here too, so we need to check
	 * for them separately. Just report and disable vGIC for now, until
	 * we implement this properly.
	 */
	if ((read_sysreg_s(SYS_ICH_HCR_EL2) & ICH_HCR_EN) &&
		read_sysreg_s(SYS_ICH_MISR_EL2) != 0) {
		pr_err("vGIC IRQ fired, disabling.\n");
		sysreg_clear_set_s(SYS_ICH_HCR_EL2, ICH_HCR_EN, 0);
	}
}

static int aic_irq_set_affinity(struct irq_data *d,
				const struct cpumask *mask_val, bool force)
{
	irq_hw_number_t hwirq = irqd_to_hwirq(d);
	struct aic_irq_chip *ic = irq_data_get_irq_chip_data(d);
	int cpu;

	if (hwirq > ic->nr_hw)
		return -EINVAL;

	if (force)
		cpu = cpumask_first(mask_val);
	else
		cpu = cpumask_any_and(mask_val, cpu_online_mask);

	aic_ic_write(ic, AIC_TARGET_CPU + hwirq * 4, BIT(cpu));
	irq_data_update_effective_affinity(d, cpumask_of(cpu));

	return IRQ_SET_MASK_OK;
}

static int aic_irq_set_type(struct irq_data *d, unsigned int type)
{
	return (type == IRQ_TYPE_LEVEL_HIGH) ? 0 : -EINVAL;
}

static struct irq_chip aic_chip = {
	.name = "AIC",
	.irq_mask = aic_irq_mask,
	.irq_unmask = aic_irq_unmask,
	.irq_eoi = aic_irq_eoi,
	.irq_set_affinity = aic_irq_set_affinity,
	.irq_set_type = aic_irq_set_type,
};

/*
 * FIQ irqchip
 */

static void aic_fiq_mask(struct irq_data *d)
{
	/* Only the guest timers have real mask bits, unfortunately. */
	switch (d->hwirq) {
	case AIC_TMR_GUEST_PHYS:
		sysreg_clear_set_s(SYS_APL_VM_TMR_MASK,
					VM_TMR_MASK_P, 0);
		break;
	case AIC_TMR_GUEST_VIRT:
		sysreg_clear_set_s(SYS_APL_VM_TMR_MASK,
					VM_TMR_MASK_V, 0);
		break;
	}
}

static void aic_fiq_unmask(struct irq_data *d)
{
	switch (d->hwirq) {
	case AIC_TMR_GUEST_PHYS:
		sysreg_clear_set_s(SYS_APL_VM_TMR_MASK,
					0, VM_TMR_MASK_P);
		break;
	case AIC_TMR_GUEST_VIRT:
		sysreg_clear_set_s(SYS_APL_VM_TMR_MASK,
					0, VM_TMR_MASK_V);
		break;
	}
}

static void aic_fiq_eoi(struct irq_data *d)
{
	/* We mask to ack (where we can), so we need to unmask at EOI. */
	if (!irqd_irq_disabled(d) && !irqd_irq_masked(d))
		aic_fiq_unmask(d);
}

#define TIMER_FIRING(x)                                                        \
	(((x) & (ARCH_TIMER_CTRL_ENABLE | ARCH_TIMER_CTRL_IT_MASK |            \
		 ARCH_TIMER_CTRL_IT_STAT)) ==                                  \
	 (ARCH_TIMER_CTRL_ENABLE | ARCH_TIMER_CTRL_IT_STAT))

static void aic_handle_fiq(struct pt_regs *regs)
{
	/*
	 * It would be really if we had a system register that lets us get
	 * the FIQ source state without having to peek down into sources...
	 * but such a register does not seem to exist.
	 *
	 * So, we have these potential sources to test for:
	 *  - Fast IPIs (not yet used)
	 *  - The 4 timers (CNTP, CNTV for each of HV and guest)
	 *  - Per-core PMCs (not yet supported)
	 *  - Per-cluster uncore PMCs (not yet supported)
	 *
	 * Since not dealing with any of these results in a FIQ storm,
	 * we check for everything here, even things we don't support yet.
	 */

	if (read_sysreg_s(SYS_APL_IPI_SR) & IPI_SR_PENDING) {
		pr_warn("Fast IPI fired. Acking.\n");
		write_sysreg_s(IPI_SR_PENDING, SYS_APL_IPI_SR);
	}

	if (TIMER_FIRING(read_sysreg(cntp_ctl_el0)))
		handle_domain_irq(aic_irqc->hw_domain,
				  aic_irqc->nr_hw + AIC_TMR_HV_PHYS, regs);

	if (TIMER_FIRING(read_sysreg(cntv_ctl_el0)))
		handle_domain_irq(aic_irqc->hw_domain,
				  aic_irqc->nr_hw + AIC_TMR_HV_VIRT, regs);

	if (TIMER_FIRING(read_sysreg_s(SYS_CNTP_CTL_EL02)))
		handle_domain_irq(aic_irqc->hw_domain,
				  aic_irqc->nr_hw + AIC_TMR_GUEST_PHYS, regs);

	if (TIMER_FIRING(read_sysreg_s(SYS_CNTV_CTL_EL02)))
		handle_domain_irq(aic_irqc->hw_domain,
				  aic_irqc->nr_hw + AIC_TMR_GUEST_VIRT, regs);

	if ((read_sysreg_s(SYS_APL_PMCR0) & (PMCR0_IMODE_MASK | PMCR0_IACT))
					 == (PMCR0_IMODE_FIQ | PMCR0_IACT)) {
		/*
		 * Not supported yet, let's figure out how to handle this when
		 * we implement these proprietary performance counters. For now,
		 * just mask it and move on.
		 */
		pr_warn("PMC FIQ fired. Masking.\n");
		sysreg_clear_set_s(SYS_APL_PMCR0, PMCR0_IMODE_MASK | PMCR0_IACT, PMCR0_IMODE_OFF);
	}

	if ((read_sysreg_s(SYS_APL_UPMCR0) & UPMCR0_IMODE_MASK) == UPMCR0_IMODE_FIQ &&
		(read_sysreg_s(SYS_APL_UPMSR) & UPMSR_IACT)) {
		/* Same story with uncore PMCs */
		pr_warn("Uncore PMC FIQ fired. Masking.\n");
		sysreg_clear_set_s(SYS_APL_UPMCR0, UPMCR0_IMODE_MASK, UPMCR0_IMODE_OFF);
	}
}

static struct irq_chip fiq_chip = {
	.name = "AIC-FIQ",
	.irq_mask = aic_fiq_mask,
	.irq_unmask = aic_fiq_unmask,
	.irq_ack = aic_fiq_mask,
	.irq_eoi = aic_fiq_eoi,
	.irq_set_type = aic_irq_set_type,
};

/*
 * Main IRQ domain
 */

static void __exception_irq_entry aic_handle_irq_or_fiq(struct pt_regs *regs)
{
	u64 isr = read_sysreg(isr_el1);

	if (isr & PSR_F_BIT)
		aic_handle_fiq(regs);

	if (isr & PSR_I_BIT)
		aic_handle_irq(regs);
}

static int aic_irq_domain_map(struct irq_domain *id, unsigned int irq,
			      irq_hw_number_t hw)
{
	struct aic_irq_chip *ic = id->host_data;

	if (hw < ic->nr_hw) {
		irq_domain_set_info(id, irq, hw, &aic_chip, id->host_data,
				    handle_fasteoi_irq, NULL, NULL);
		irqd_set_single_target(irq_desc_get_irq_data(irq_to_desc(irq)));
	} else {
		irq_set_percpu_devid(irq);
		irq_domain_set_info(id, irq, hw, &fiq_chip, id->host_data,
				    handle_percpu_devid_irq, NULL, NULL);
	}

	return 0;
}

static int aic_irq_domain_translate(struct irq_domain *id,
				    struct irq_fwspec *fwspec,
				    unsigned long *hwirq,
				    unsigned int *type)
{
	struct aic_irq_chip *ic = id->host_data;

	if (fwspec->param_count != 3 || !is_of_node(fwspec->fwnode))
		return -EINVAL;

	switch (fwspec->param[0]) {
	case AIC_IRQ:
		if (fwspec->param[1] >= ic->nr_hw)
			return -EINVAL;
		*hwirq = 0;
		break;
	case AIC_FIQ:
		if (fwspec->param[1] >= AIC_NR_FIQ)
			return -EINVAL;
		*hwirq = ic->nr_hw;
		break;
	default:
		return -EINVAL;
	}

	*hwirq += fwspec->param[1];
	*type = fwspec->param[2] & IRQ_TYPE_SENSE_MASK;

	return 0;
}

static int aic_irq_domain_alloc(struct irq_domain *domain, unsigned int virq,
				unsigned int nr_irqs, void *arg)
{
	unsigned int type = IRQ_TYPE_NONE;
	struct irq_fwspec *fwspec = arg;
	irq_hw_number_t hwirq;
	int i, ret;

	ret = aic_irq_domain_translate(domain, fwspec, &hwirq, &type);
	if (ret)
		return ret;

	for (i = 0; i < nr_irqs; i++) {
		ret = aic_irq_domain_map(domain, virq + i, hwirq + i);
		if (ret)
			return ret;
	}

	return 0;
}

static void aic_irq_domain_free(struct irq_domain *domain, unsigned int virq,
				unsigned int nr_irqs)
{
	int i;

	for (i = 0; i < nr_irqs; i++) {
		struct irq_data *d = irq_domain_get_irq_data(domain, virq + i);
		irq_set_handler(virq + i, NULL);
		irq_domain_reset_irq_data(d);
	}
}

static const struct irq_domain_ops aic_irq_domain_ops = {
	.translate	= aic_irq_domain_translate,
	.alloc		= aic_irq_domain_alloc,
	.free		= aic_irq_domain_free,
};

/*
 * IPI irqchip
 */

static void aic_ipi_mask(struct irq_data *d)
{
	struct aic_irq_chip *ic = irq_data_get_irq_chip_data(d);
	u32 irq_bit = BIT(irqd_to_hwirq(d));
	int this_cpu = smp_processor_id();

	atomic_and(~irq_bit, &aic_vipi_mask[this_cpu]);

	if (!atomic_read(&aic_vipi_mask[this_cpu]))
		aic_ic_write(ic, AIC_IPI_MASK_SET, AIC_IPI_OTHER);
}

static void aic_ipi_unmask(struct irq_data *d)
{
	struct aic_irq_chip *ic = irq_data_get_irq_chip_data(d);
	u32 irq_bit = BIT(irqd_to_hwirq(d));
	int this_cpu = smp_processor_id();

	atomic_or(irq_bit, &aic_vipi_mask[this_cpu]);

	aic_ic_write(ic, AIC_IPI_MASK_CLR, AIC_IPI_OTHER);
}

static void aic_ipi_send_mask(struct irq_data *d, const struct cpumask *mask)
{
	struct aic_irq_chip *ic = irq_data_get_irq_chip_data(d);
	u32 irq_bit = BIT(irqd_to_hwirq(d));
	u32 send = 0;
	int cpu;

	/*
	 * Ensure that stores to normal memory are visible to the
	 * other CPUs before issuing the IPI. This needs to happen
	 * before setting any vIPI flag bits, since that can race the
	 * atomic_xchg below.
	 */
	wmb();

	for_each_cpu(cpu, mask) {
		if (atomic_read(&aic_vipi_mask[cpu]) & irq_bit) {
			atomic_or(irq_bit, &aic_vipi_flag[cpu]);
			send |= AIC_IPI_SEND_CPU(cpu);
		}
	}

	if (send) {
		/*
		 * Ensure that the vIPI flag writes complete before issuing
		 * the physical IPI.
		 */
		wmb();
		aic_ic_write(ic, AIC_IPI_SEND, send);
	}
}

static struct irq_chip ipi_chip = {
	.name = "AIC-IPI",
	.irq_mask = aic_ipi_mask,
	.irq_unmask = aic_ipi_unmask,
	.ipi_send_mask = aic_ipi_send_mask,
};

/*
 * IPI IRQ domain
 */

static void aic_handle_ipi(struct pt_regs *regs)
{
	int this_cpu = smp_processor_id();
	int i;
	unsigned long firing;

	aic_ic_write(aic_irqc, AIC_IPI_ACK, AIC_IPI_OTHER);

	/*
	 * Ensure that we've received and acked the IPI before we load the vIPI
	 * flags. This pairs with the second wmb() above.
	 */
	mb();

	firing = atomic_xchg(&aic_vipi_flag[this_cpu], 0);

	/*
	 * Ensure that we've exchanged the vIPI flags before running any IPI
	 * handler code. This pairs with the first wmb() above.
	 */
	rmb();

	for_each_set_bit(i, &firing, AIC_NR_SWIPI) {
		handle_domain_irq(aic_irqc->ipi_domain, i, regs);
	}

	aic_ic_write(aic_irqc, AIC_IPI_MASK_CLR, AIC_IPI_OTHER);
}

static int aic_ipi_alloc(struct irq_domain *d, unsigned int virq,
			 unsigned int nr_irqs, void *args)
{
	int i;

	for (i = 0; i < nr_irqs; i++) {
		irq_set_percpu_devid(virq + i);
		irq_domain_set_info(d, virq + i, i, &ipi_chip, d->host_data,
				    handle_percpu_devid_irq, NULL, NULL);
	}

	return 0;
}

static void aic_ipi_free(struct irq_domain *d, unsigned int virq, unsigned int nr_irqs)
{
	/* Not freeing IPIs */
}

static const struct irq_domain_ops aic_ipi_domain_ops = {
	.alloc = aic_ipi_alloc,
	.free = aic_ipi_free,
};

static int aic_init_smp(struct aic_irq_chip *irqc, struct device_node *node)
{
	int base_ipi;

	irqc->ipi_domain =
		irq_domain_create_linear(irqc->hw_domain->fwnode, AIC_NR_SWIPI,
					 &aic_ipi_domain_ops, irqc);
	if (WARN_ON(!irqc->ipi_domain))
		return -ENODEV;

	irqc->ipi_domain->flags |= IRQ_DOMAIN_FLAG_IPI_SINGLE;
	irq_domain_update_bus_token(irqc->ipi_domain, DOMAIN_BUS_IPI);

	base_ipi = __irq_domain_alloc_irqs(irqc->ipi_domain, -1, AIC_NR_SWIPI,
					   NUMA_NO_NODE, NULL, false, NULL);

	if (WARN_ON(!base_ipi)) {
		irq_domain_remove(irqc->ipi_domain);
		return -ENODEV;
	}

	set_smp_ipi_range(base_ipi, AIC_NR_SWIPI);

	return 0;
}

static int aic_init_cpu(unsigned int cpu)
{
	/* Mask all hard-wired per-CPU IRQ/FIQ sources */

	/* vGIC maintenance IRQ */
	sysreg_clear_set_s(SYS_ICH_HCR_EL2, ICH_HCR_EN, 0);

	/* Pending Fast IPI FIQs */
	write_sysreg_s(IPI_SR_PENDING, SYS_APL_IPI_SR);

	/* Timer FIQs */
	sysreg_clear_set(cntp_ctl_el0, 0, ARCH_TIMER_CTRL_IT_MASK);
	sysreg_clear_set(cntv_ctl_el0, 0, ARCH_TIMER_CTRL_IT_MASK);
	sysreg_clear_set_s(SYS_CNTP_CTL_EL02, 0, ARCH_TIMER_CTRL_IT_MASK);
	sysreg_clear_set_s(SYS_CNTV_CTL_EL02, 0, ARCH_TIMER_CTRL_IT_MASK);

	/* PMC FIQ */
	sysreg_clear_set_s(SYS_APL_PMCR0, PMCR0_IMODE_MASK | PMCR0_IACT, PMCR0_IMODE_OFF);

	/* Uncore PMC FIQ */
	sysreg_clear_set_s(SYS_APL_UPMCR0, UPMCR0_IMODE_MASK, UPMCR0_IMODE_OFF);

	/*
	 * Make sure the kernel's idea of logical CPU order is the same as AIC's
	 * If we ever end up with a mismatch here, we will have to introduce
	 * a mapping table similar to what other irqchip drivers do.
	 */
	WARN_ON(aic_ic_read(aic_irqc, AIC_WHOAMI) != smp_processor_id());

	return 0;

}

static int __init aic_of_ic_init(struct device_node *node,
				 struct device_node *parent)
{
	int i;
	void __iomem *regs;
	u32 info;
	struct aic_irq_chip *irqc;

	regs = of_iomap(node, 0);
	if (WARN_ON(!regs))
		return -EIO;

	irqc = kzalloc(sizeof(*irqc), GFP_KERNEL);
	if (!irqc)
		return -ENOMEM;

	aic_irqc = irqc;
	irqc->base = regs;

	info = aic_ic_read(irqc, AIC_INFO);
	irqc->nr_hw = AIC_INFO_NR_HW(info);

	irqc->hw_domain = irq_domain_create_linear(of_node_to_fwnode(node),
						   irqc->nr_hw + AIC_NR_FIQ,
						   &aic_irq_domain_ops, irqc);
	if (WARN_ON(!irqc->hw_domain)) {
		iounmap(irqc->base);
		kfree(irqc);
		return -ENODEV;
	}

	irq_domain_update_bus_token(irqc->hw_domain, DOMAIN_BUS_WIRED);

	if (aic_init_smp(irqc, node)) {
		irq_domain_remove(irqc->hw_domain);
		iounmap(irqc->base);
		kfree(irqc);
		return -ENODEV;
	}

	set_handle_irq(aic_handle_irq_or_fiq);

	for (i = 0; i < BITS_TO_U32(irqc->nr_hw); i++)
		aic_ic_write(irqc, AIC_MASK_SET + i * 4, ~0);
	for (i = 0; i < BITS_TO_U32(irqc->nr_hw); i++)
		aic_ic_write(irqc, AIC_SW_CLR + i * 4, ~0);
	for (i = 0; i < irqc->nr_hw; i++)
		aic_ic_write(irqc, AIC_TARGET_CPU + i * 4, 1);

	cpuhp_setup_state(CPUHP_AP_IRQ_APPLE_AIC_STARTING,
			  "irqchip/apple-aic/ipi:starting",
			  aic_init_cpu, NULL);

	pr_info("AIC: initialized with %d IRQs, %d FIQs, %d vIPIs\n",
		irqc->nr_hw, AIC_NR_FIQ, AIC_NR_SWIPI);

	return 0;
}

IRQCHIP_DECLARE(apple_m1_aic, "apple,aic", aic_of_ic_init);
