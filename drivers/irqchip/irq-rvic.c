// SPDX-License-Identifier: GPL-2.0
/*
 * A Reduced Virtual Interrupt Controler driver
 *
 * Initial draft from Alex Shirshikov <alexander.shirshikov@arm.com>
 *
 * Copyright 2020 Google LLC.
 * Author: Marc Zyngier <maz@kernel.org>
 */


#define pr_fmt(fmt)	"rVIC: " fmt

#include <linux/arm-smccc.h>
#include <linux/cpuhotplug.h>
#include <linux/interrupt.h>
#include <linux/irq.h>
#include <linux/irqchip.h>
#include <linux/irqdomain.h>

#include <linux/irqchip/irq-rvic.h>

#include <asm/exception.h>

#define RVIC_WARN_INTID_TARGET(r, s, intid, mpid)			\
	WARN((r), "Error " s " INTID%ld target %llx (%ld, %ld)\n", \
	     (intid), (mpid),						\
	     RVIC_STATUS_REASON((r)), RVIC_STATUS_INDEX((r)));

#define RVIC_WARN_INTID(r, s, intid)					\
	WARN((r), "Error " s " INTID%ld (%ld, %ld)\n",	\
	     (intid),							\
	     RVIC_STATUS_REASON((r)), RVIC_STATUS_INDEX((r)));

static DEFINE_PER_CPU(unsigned long *, trusted_masked);

struct rvic_data {
	struct fwnode_handle	*fwnode;
	struct irq_domain	*domain;
	unsigned int		nr_trusted;
	unsigned int		nr_untrusted;
};

static struct rvic_data rvic;

static inline int rvic_version(unsigned long *version)
{
	struct arm_smccc_res res;

	arm_smccc_1_1_invoke(SMC64_RVIC_VERSION, &res);
	if (res.a0 == RVIC_STATUS_SUCCESS)
		*version = res.a1;
	return res.a0;
}

static inline unsigned long rvic_info(unsigned long key,
				      unsigned long *value)
{
	struct arm_smccc_res res;

	arm_smccc_1_1_invoke(SMC64_RVIC_INFO, key, &res);
	if (res.a0 == RVIC_STATUS_SUCCESS)
		*value = res.a1;
	return res.a0;
}

static inline unsigned long rvic_enable(void)
{
	struct arm_smccc_res res;

	arm_smccc_1_1_invoke(SMC64_RVIC_ENABLE, &res);
	return res.a0;
}

static inline unsigned long rvic_disable(void)
{
	struct arm_smccc_res res;

	arm_smccc_1_1_invoke(SMC64_RVIC_DISABLE, &res);
	return res.a0;
}

static inline unsigned long rvic_set_masked(unsigned long target,
					    unsigned long intid)
{
	struct arm_smccc_res res;

	arm_smccc_1_1_invoke(SMC64_RVIC_SET_MASKED, target, intid, &res);
	return res.a0;
}

static inline unsigned long rvic_clear_masked(unsigned long target,
					      unsigned long intid)
{
	struct arm_smccc_res res;

	arm_smccc_1_1_invoke(SMC64_RVIC_CLEAR_MASKED, target, intid, &res);
	return res.a0;
}

static inline unsigned long rvic_is_pending(unsigned long target,
					    unsigned long intid,
					    bool *is_pending)
{
	struct arm_smccc_res res;

	arm_smccc_1_1_invoke(SMC64_RVIC_IS_PENDING, target, intid, &res);
	if (res.a0 == RVIC_STATUS_SUCCESS)
		*is_pending = res.a1;
	return res.a0;
}

static inline unsigned long rvic_signal(unsigned long target,
					unsigned long intid)
{
	struct arm_smccc_res res;

	arm_smccc_1_1_invoke(SMC64_RVIC_SIGNAL, target, intid, &res);
	return res.a0;
}

static inline unsigned long rvic_clear_pending(unsigned long target,
					       unsigned long intid)
{
	struct arm_smccc_res res;

	arm_smccc_1_1_invoke(SMC64_RVIC_CLEAR_PENDING, target, intid, &res);
	return res.a0;
}

static inline unsigned long rvic_acknowledge(unsigned long *intid)
{
	struct arm_smccc_res res;

	arm_smccc_1_1_invoke(SMC64_RVIC_ACKNOWLEDGE, &res);
	if (res.a0 == RVIC_STATUS_SUCCESS)
		*intid = res.a1;
	return res.a0;
}

static inline unsigned long rvic_resample(unsigned long intid)
{
	struct arm_smccc_res res;

	arm_smccc_1_1_invoke(SMC64_RVIC_RESAMPLE, intid, &res);
	return res.a0;
}

static u64 rvic_irq_to_mpidr(struct irq_data *data, int *cpup)
{
	int cpu;

	if (data->hwirq < rvic.nr_trusted) {
		*cpup = smp_processor_id();
		return read_cpuid_mpidr() & MPIDR_HWID_BITMASK;
	}

	cpu = cpumask_first(data->common->effective_affinity);
	*cpup = cpu;
	return cpu_logical_map(cpu) & MPIDR_HWID_BITMASK;
}

static void rvic_irq_mask(struct irq_data *data)
{
	unsigned long ret;
	u64 mpidr;
	int cpu;

	mpidr = rvic_irq_to_mpidr(data, &cpu);
	pr_debug("%llu irq %d hwirq %ld masked\n",
		 mpidr, data->irq, data->hwirq);
	ret = rvic_set_masked(mpidr, data->hwirq);
	RVIC_WARN_INTID_TARGET(ret, "masking", data->hwirq, mpidr);

	if (data->hwirq < rvic.nr_trusted)
		set_bit(data->hwirq, per_cpu(trusted_masked, cpu));
}

static void rvic_irq_unmask(struct irq_data *data)
{
	unsigned long ret;
	u64 mpidr;
	int cpu;

	mpidr = rvic_irq_to_mpidr(data, &cpu);
	pr_debug("%llu irq %d hwirq %ld unmasked\n",
		 mpidr, data->irq, data->hwirq);
	ret = rvic_clear_masked(mpidr, data->hwirq);
	RVIC_WARN_INTID_TARGET(ret, "unmasking", data->hwirq, mpidr);

	if (data->hwirq < rvic.nr_trusted)
		clear_bit(data->hwirq, per_cpu(trusted_masked, cpu));
}

static void rvic_irq_eoi(struct irq_data *data)
{
	bool masked;

	/* Resampling is only available on trusted interrupts for now */
	if (data->hwirq < rvic.nr_trusted &&
	    (irqd_get_trigger_type(data) & IRQ_TYPE_LEVEL_MASK)) {
		unsigned long ret;

		ret = rvic_resample(data->hwirq);
		RVIC_WARN_INTID(ret, "resampling", data->hwirq);
	}

	/* irqd_irq_masked doesn't work on percpu-devid interrupts. */
	if (data->hwirq < rvic.nr_trusted)
		masked = test_bit(data->hwirq, *this_cpu_ptr(&trusted_masked));
	else
		masked = irqd_irq_masked(data);

	if (!masked)
		rvic_irq_unmask(data);
}

static void rvic_ipi_send_mask(struct irq_data *data,
			       const struct cpumask *mask)
{
	int cpu;

	for_each_cpu(cpu, mask) {
		u64 mpidr = cpu_logical_map(cpu) & MPIDR_HWID_BITMASK;
		unsigned long ret;

		ret = rvic_signal(mpidr, data->hwirq);
		RVIC_WARN_INTID_TARGET(ret, "signaling", data->hwirq, mpidr);
	}
}

static int rvic_irq_get_irqchip_state(struct irq_data *data,
				      enum irqchip_irq_state which, bool *val)
{
	unsigned long ret;
	u64 mpidr;
	int cpu;

	mpidr = rvic_irq_to_mpidr(data, &cpu);

	switch (which) {
	case IRQCHIP_STATE_PENDING:
		ret = rvic_is_pending(mpidr, data->hwirq, val);
		RVIC_WARN_INTID_TARGET(ret, "getting pending state",
				       data->hwirq, mpidr);
		return ret ? -EINVAL : 0;

	default:
		return -EINVAL;
	};
}

static int rvic_irq_set_irqchip_state(struct irq_data *data,
				      enum irqchip_irq_state which, bool val)
{
	unsigned long ret;
	u64 mpidr;
	int cpu;

	mpidr = rvic_irq_to_mpidr(data, &cpu);

	switch (which) {
	case IRQCHIP_STATE_PENDING:
		if (val)
			ret = rvic_signal(mpidr, data->hwirq);
		else
			ret = rvic_clear_pending(mpidr, data->hwirq);
		RVIC_WARN_INTID_TARGET(ret, "setting pending state",
				       data->hwirq, mpidr);
		return ret ? -EINVAL : 0;

	case IRQCHIP_STATE_MASKED:
		if (val)
			ret = rvic_set_masked(mpidr, data->hwirq);
		else
			ret = rvic_clear_masked(mpidr, data->hwirq);
		RVIC_WARN_INTID_TARGET(ret, "setting masked state",
				       data->hwirq, mpidr);
		return ret ? -EINVAL : 0;

	default:
		return -EINVAL;
	}

}

static int rvic_irq_retrigger(struct irq_data *data)
{
	return !!rvic_irq_set_irqchip_state(data, IRQCHIP_STATE_PENDING, true);
}

static int rvic_set_type(struct irq_data *data, unsigned int type)
{
	/*
	 * Nothing to do here, we're always edge under the hood. Just
	 * weed out untrusted interrupts, as they cannot be level yet.
	 */
	switch (type) {
	case IRQ_TYPE_LEVEL_HIGH:
		if (data->hwirq >= rvic.nr_trusted)
			return -EINVAL;

		fallthrough;
	case IRQ_TYPE_EDGE_RISING:
		return 0;
	default:
		return -EINVAL;
	}
}

static struct irq_chip rvic_chip = {
	.name			= "rvic",
	.irq_mask		= rvic_irq_mask,
	.irq_unmask		= rvic_irq_unmask,
	.irq_eoi		= rvic_irq_eoi,
	.ipi_send_mask		= rvic_ipi_send_mask,
	.irq_get_irqchip_state	= rvic_irq_get_irqchip_state,
	.irq_set_irqchip_state	= rvic_irq_set_irqchip_state,
	.irq_retrigger		= rvic_irq_retrigger,
	.irq_set_type		= rvic_set_type,
};

static asmlinkage void __exception_irq_entry rvic_handle_irq(struct pt_regs *regs)
{
	unsigned long ret, intid;
	int err;

	ret = rvic_acknowledge(&intid);
	if (unlikely(ret == RVIC_STATUS_NO_INTERRUPTS)) {
		pr_debug("CPU%d: Spurious interrupt\n", smp_processor_id());
		return;
	}

	if ((unlikely(ret))) {
		WARN(1, "rVIC: Error acknowledging interrupt (%ld, %ld)\n",
		     RVIC_STATUS_REASON(ret),
		     RVIC_STATUS_INDEX(ret));
		return;
	}

	if (unlikely(intid >= (rvic.nr_trusted + rvic.nr_untrusted))) {
		WARN(1, "Unexpected intid out of range (%lu)\n", intid);
		return;
	}

	pr_debug("CPU%d: IRQ%ld\n", smp_processor_id(), intid);
	err = handle_domain_irq(rvic.domain, intid, regs);
	WARN_ONCE(err, "Unexpected interrupt received %d\n", err);
}

static int rvic_irq_domain_alloc(struct irq_domain *domain, unsigned int virq,
				 unsigned int nr_irqs, void *arg)
{
	struct irq_fwspec *fwspec = arg;
	unsigned int type = IRQ_TYPE_NONE;
	irq_hw_number_t hwirq;
	int i, ret;

	ret = irq_domain_translate_twocell(domain, fwspec, &hwirq, &type);
	if (ret)
		return ret;

	for (i = 0; i < nr_irqs; i++) {
		unsigned int intid = hwirq + i;
		unsigned int irq = virq + i;

		if (intid < 16) {
			irq_set_percpu_devid(irq);
			irq_domain_set_info(domain, irq, intid, &rvic_chip,
					    domain->host_data,
					    handle_percpu_devid_fasteoi_ipi,
					    NULL, NULL);
		} else if (intid < rvic.nr_trusted) {
			irq_set_percpu_devid(irq);
			irq_domain_set_info(domain, irq, intid, &rvic_chip,
					    domain->host_data,
					    handle_percpu_devid_irq,
					    NULL, NULL);
		} else {
			return -EINVAL;
		}
	}

	return 0;
}

static void rvic_irq_domain_free(struct irq_domain *domain, unsigned int virq,
				 unsigned int nr_irqs)
{
	int i;

	for (i = 0; i < nr_irqs; i++) {
		struct irq_data *d = irq_domain_get_irq_data(domain, virq + i);
		irq_set_handler(virq + i, NULL);
		irq_domain_reset_irq_data(d);
	}
}

static const struct irq_domain_ops rvic_irq_domain_ops = {
	.translate	= irq_domain_translate_twocell,
	.alloc		= rvic_irq_domain_alloc,
	.free		= rvic_irq_domain_free,
};

static int rvic_cpu_starting(unsigned int cpu)
{
	u64 mpidr = read_cpuid_mpidr() & MPIDR_HWID_BITMASK;
	unsigned long ret;
	int i;

	rvic_disable();

	for (i = 0; i < (rvic.nr_trusted + rvic.nr_untrusted); i++) {
		rvic_set_masked(mpidr, i);
		rvic_clear_pending(mpidr, i);
	}

	ret = rvic_enable();
	if (ret != RVIC_STATUS_SUCCESS) {
		pr_err("rVIC: error enabling instance (%ld, %ld)\n",
		       RVIC_STATUS_REASON(ret),
		       RVIC_STATUS_INDEX(ret));
		return -ENXIO;
	}

	return 0;
}

static int rvic_cpu_dying(unsigned int cpu)
{
	unsigned long ret;

	ret = rvic_disable();
	if (ret != RVIC_STATUS_SUCCESS) {
		pr_err("rVIC: error disabling instance (%ld, %ld)\n",
		       RVIC_STATUS_REASON(ret),
		       RVIC_STATUS_INDEX(ret));
		return -ENXIO;
	}

	return 0;
}

static void __init rvic_smp_init(struct fwnode_handle *fwnode)
{
	struct irq_fwspec ipi_fwspec = {
		.fwnode		= fwnode,
		.param_count	= 2,
		.param[0]	= 0,
		.param[1]	= IRQ_TYPE_EDGE_RISING,
	};
	int base_ipi;

	cpuhp_setup_state(CPUHP_AP_IRQ_RVIC_STARTING, "irqchip/rvic:starting",
			  rvic_cpu_starting, rvic_cpu_dying);

	base_ipi = __irq_domain_alloc_irqs(rvic.domain, -1, 16,
					   NUMA_NO_NODE, &ipi_fwspec,
					   false, NULL);
	if (WARN_ON(base_ipi < 0))
		return;

	set_smp_ipi_range(base_ipi, 16);
}

static int __init rvic_init(struct device_node *node,
			    struct device_node *parent)
{
	unsigned long ret, version, val;
	int cpu;

	if (arm_smccc_get_version() < ARM_SMCCC_VERSION_1_1) {
		pr_err("SMCCC 1.1 required, abording\n");
		return -EINVAL;
	}

	rvic.fwnode = of_node_to_fwnode(node);

	ret = rvic_version(&version);
	if (ret != RVIC_STATUS_SUCCESS) {
		pr_err("error retrieving version (%ld, %ld)\n",
		       RVIC_STATUS_REASON(ret),
		       RVIC_STATUS_INDEX(ret));
		return -ENXIO;
	}

	if (version < RVIC_VERSION(0, 3)) {
		pr_err("version (%ld, %ld) too old, expected min. (%d, %d)\n",
		       RVIC_VERSION_MAJOR(version),
		       RVIC_VERSION_MINOR(version),
		       0, 3);
		return -ENXIO;
	}

	ret = rvic_info(RVIC_INFO_KEY_NR_TRUSTED_INTERRUPTS, &val);
	if (ret != RVIC_STATUS_SUCCESS) {
		pr_err("error retrieving nr of trusted interrupts (%ld, %ld)\n",
		       RVIC_STATUS_REASON(ret),
		       RVIC_STATUS_INDEX(ret));
		return -ENXIO;
	}

	rvic.nr_trusted = val;

	ret = rvic_info(RVIC_INFO_KEY_NR_UNTRUSTED_INTERRUPTS, &val);
	if (ret != RVIC_STATUS_SUCCESS) {
		pr_err("error retrieving nr of untrusted interrupts (%ld, %ld)\n",
		       RVIC_STATUS_REASON(ret),
		       RVIC_STATUS_INDEX(ret));
		return -ENXIO;
	}

	rvic.nr_untrusted = val;

	pr_info("probed %u trusted interrupts, %u untrusted interrupts\n",
		rvic.nr_trusted, rvic.nr_untrusted);

	rvic.domain = irq_domain_create_linear(rvic.fwnode,
					       rvic.nr_trusted + rvic.nr_untrusted,
					       &rvic_irq_domain_ops, &rvic);
	if (!rvic.domain) {
		pr_warn("Failed to allocate irq domain\n");
		return -ENOMEM;
	}

	for_each_possible_cpu(cpu) {
		unsigned long *map = bitmap_alloc(rvic.nr_trusted, GFP_KERNEL);

		if (!map) {
			pr_warn("Failed to allocate trusted bitmap (CPU %d)\n",
				cpu);
			goto free_percpu;
		}

		/* Default to masked */
		bitmap_fill(map, rvic.nr_trusted);
		per_cpu(trusted_masked, cpu) = map;
	}

	rvic_smp_init(rvic.fwnode);
	set_handle_irq(rvic_handle_irq);

	return 0;

free_percpu:
	for_each_possible_cpu(cpu)
		kfree(per_cpu(trusted_masked, cpu));

	irq_domain_remove(rvic.domain);

	return -ENOMEM;
}

IRQCHIP_DECLARE(rvic, "arm,rvic", rvic_init);
