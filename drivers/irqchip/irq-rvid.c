// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright 2020 Google LLC.
 * Author: Marc Zyngier <maz@kernel.org>
 */

#define pr_fmt(fmt)	"rVID: " fmt

#include <linux/arm-smccc.h>
#include <linux/cpuhotplug.h>
#include <linux/interrupt.h>
#include <linux/irq.h>
#include <linux/irqchip.h>
#include <linux/irqdomain.h>

#include <linux/irqchip/irq-rvic.h>

struct rvid_data {
	struct fwnode_handle	*fwnode;
	struct irq_domain	*domain;
};

static struct rvid_data rvid;

static inline int rvid_version(unsigned long *version)
{
	struct arm_smccc_res res;

	arm_smccc_1_1_invoke(SMC64_RVID_VERSION, &res);
	if (res.a0 == RVID_STATUS_SUCCESS)
		*version = res.a1;
	return res.a0;
}

static inline int rvid_map(unsigned long input,
			   unsigned long target, unsigned long intid)
{
	struct arm_smccc_res res;

	arm_smccc_1_1_invoke(SMC64_RVID_MAP, input, target, intid, &res);
	return res.a0;
}

static inline int rvid_unmap(unsigned long input)
{
	struct arm_smccc_res res;

	arm_smccc_1_1_invoke(SMC64_RVID_UNMAP, input, &res);
	return res.a0;
}

static int rvid_irq_set_affinity(struct irq_data *data,
				 const struct cpumask *mask_val,
				 bool force)
{
	unsigned int old_cpu, cpu;
	bool masked, pending;
	int err = 0, ret;
	u64 mpidr;

	if (force)
		cpu = cpumask_first(mask_val);
	else
		cpu = cpumask_any_and(mask_val, cpu_online_mask);

	if (cpu >= nr_cpu_ids)
		return -EINVAL;

	mpidr = cpu_logical_map(cpu) & MPIDR_HWID_BITMASK;
	old_cpu = cpumask_first(data->common->effective_affinity);
	if (cpu == old_cpu)
		return 0;

	/* Mask on source */
	masked = irqd_irq_masked(data);
	if (!masked)
		irq_chip_mask_parent(data);

	/* Switch to target */
	irq_data_update_effective_affinity(data, cpumask_of(cpu));

	/* Mask on target */
	irq_chip_mask_parent(data);

	/* Map the input signal to the new target */
	ret = rvid_map(data->hwirq, mpidr, data->parent_data->hwirq);
	if (ret != RVID_STATUS_SUCCESS) {
		err = -ENXIO;
		goto unmask;
	}

	/* Back to the source */
	irq_data_update_effective_affinity(data, cpumask_of(old_cpu));

	/* Sample pending state and clear it if necessary */
	err = irq_chip_get_parent_state(data, IRQCHIP_STATE_PENDING, &pending);
	if (err)
		goto unmask;
	if (pending)
		irq_chip_set_parent_state(data, IRQCHIP_STATE_PENDING, false);

	/*
	 * To the target again (for good this time), propagating the
	 * pending bit if required.
	 */
	irq_data_update_effective_affinity(data, cpumask_of(cpu));
	if (pending)
		irq_chip_set_parent_state(data, IRQCHIP_STATE_PENDING, true);
unmask:
	/* Propagate the masking state */
	if (!masked)
		irq_chip_unmask_parent(data);

	return err;
}

static struct irq_chip rvid_chip = {
	.name			= "rvid",
	.irq_mask		= irq_chip_mask_parent,
	.irq_unmask		= irq_chip_unmask_parent,
	.irq_eoi		= irq_chip_eoi_parent,
	.irq_get_irqchip_state	= irq_chip_get_parent_state,
	.irq_set_irqchip_state	= irq_chip_set_parent_state,
	.irq_retrigger		= irq_chip_retrigger_hierarchy,
	.irq_set_type		= irq_chip_set_type_parent,
	.irq_set_affinity	= rvid_irq_set_affinity,
};

static int rvid_irq_domain_alloc(struct irq_domain *domain, unsigned int virq,
				 unsigned int nr_irqs, void *arg)
{
	struct irq_fwspec *fwspec = arg;
	unsigned int type = IRQ_TYPE_NONE;
	irq_hw_number_t hwirq;
	int i, ret;

	ret = irq_domain_translate_onecell(domain, fwspec, &hwirq, &type);
	if (ret)
		return ret;

	for (i = 0; i < nr_irqs; i++) {
		unsigned int intid = hwirq + i;
		unsigned int irq = virq + i;

		/* Get the rVIC to allocate any untrusted intid */
		ret = irq_domain_alloc_irqs_parent(domain, irq, 1, NULL);
		if (WARN_ON(ret))
			return ret;

		irq_domain_set_hwirq_and_chip(domain, irq, intid,
					      &rvid_chip, &rvid);
		irqd_set_affinity_on_activate(irq_get_irq_data(irq));
	}

	return 0;
}

static void rvid_irq_domain_free(struct irq_domain *domain, unsigned int virq,
				 unsigned int nr_irqs)
{
	int i;

	irq_domain_free_irqs_parent(domain, virq, nr_irqs);

	for (i = 0; i < nr_irqs; i++) {
		struct irq_data *d;

		d = irq_domain_get_irq_data(domain, virq + i);
		irq_set_handler(virq + i, NULL);
		irq_domain_reset_irq_data(d);
	}
}

static int rvid_irq_domain_activate(struct irq_domain *domain,
				    struct irq_data *data, bool reserve)
{
	unsigned long ret;
	int cpu, err = 0;
	u64 mpidr;

	cpu = get_cpu();
	mpidr = cpu_logical_map(cpu) & MPIDR_HWID_BITMASK;

	/* Map the input signal */
	ret = rvid_map(data->hwirq, mpidr, data->parent_data->hwirq);
	if (ret != RVID_STATUS_SUCCESS) {
		err = -ENXIO;
		goto out;
	}

	irq_data_update_effective_affinity(data, cpumask_of(cpu));

out:
	put_cpu();
	return err;
}

static void rvid_irq_domain_deactivate(struct irq_domain *domain,
				       struct irq_data *data)
{
	rvid_unmap(data->hwirq);
}

static const struct irq_domain_ops rvid_irq_domain_ops = {
	.translate	= irq_domain_translate_onecell,
	.alloc		= rvid_irq_domain_alloc,
	.free		= rvid_irq_domain_free,
	.activate	= rvid_irq_domain_activate,
	.deactivate	= rvid_irq_domain_deactivate,
};

static int __init rvid_init(struct device_node *node,
			    struct device_node *parent)
{
	struct irq_domain *parent_domain;
	unsigned long ret, version;

	if (arm_smccc_get_version() < ARM_SMCCC_VERSION_1_1) {
		pr_err("SMCCC 1.1 required, aborting\n");
		return -EINVAL;
	}

	if (!parent)
		return -ENXIO;

	parent_domain = irq_find_host(parent);
	if (!parent_domain)
		return -ENXIO;

	rvid.fwnode = of_node_to_fwnode(node);

	ret = rvid_version(&version);
	if (ret != RVID_STATUS_SUCCESS) {
		pr_err("error retrieving version (%ld, %ld)\n",
		       RVID_STATUS_REASON(ret), RVID_STATUS_INDEX(ret));
		return -ENXIO;
	}

	if (version < RVID_VERSION(0, 3)) {
		pr_err("version (%ld, %ld) too old, expected min. (%d, %d)\n",
		       RVID_VERSION_MAJOR(version), RVID_VERSION_MINOR(version),
		       0, 3);
		return -ENXIO;
	}

	pr_info("distributing interrupts to %pOF\n", parent);

	rvid.domain = irq_domain_create_hierarchy(parent_domain, 0, 0,
						  rvid.fwnode,
						  &rvid_irq_domain_ops, &rvid);
	if (!rvid.domain) {
		pr_warn("Failed to allocate irq domain\n");
		return -ENOMEM;
	}

	return 0;
}

IRQCHIP_DECLARE(rvic, "arm,rvid", rvid_init);
