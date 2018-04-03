/*
 * Copyright (C) 2016 ARM Limited, All Rights Reserved.
 * Author: Marc Zyngier <marc.zyngier@arm.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <linux/bitops.h>
#include <linux/interrupt.h>
#include <linux/irqchip.h>
#include <linux/irqchip/chained_irq.h>
#include <linux/irqchip/irq-partition-percpu.h>
#include <linux/irqdomain.h>
#include <linux/seq_file.h>
#include <linux/slab.h>

struct partition_desc {
	struct mutex			lock;
	int				nr_parts;
	struct partition_affinity	*parts;
	struct irq_domain		*domain;
	struct irq_desc			*chained_desc;
	unsigned long			*bitmap;
	struct irq_domain_ops		ops;
	struct irq_fwspec		fwspec;
	void (*convert)(struct irq_fwspec *fwspec);
};

static struct irq_data *partition_get_irqd_chip(struct partition_desc *part,
						struct irq_chip **chip)
{
	if (part->chained_desc) {
		*chip = irq_desc_get_chip(part->chained_desc);
		return irq_desc_get_irq_data(part->chained_desc);
	}

	*chip = NULL;
	return NULL;
}

static bool partition_check_cpu(struct partition_desc *part,
				unsigned int cpu, unsigned int hwirq)
{
	return cpumask_test_cpu(cpu, &part->parts[hwirq].mask);
}

#define PART_IF_METHOD(method, d)					\
	struct partition_desc *part;					\
	struct irq_chip *chip;						\
	struct irq_data *data;						\
									\
	part = irq_data_get_irq_chip_data(d);				\
	data = partition_get_irqd_chip(part, &chip);			\
	if (data &&							\
	    partition_check_cpu(part, smp_processor_id(), d->hwirq) &&	\
	    chip->method)

#define PART_CALL_METHOD_VOID(method, d, ...)				\
	do {								\
		PART_IF_METHOD(method, d)				\
			chip->method(data, ##__VA_ARGS__);		\
	} while(0)

#define PART_CALL_METHOD_INT(retval, method, d, ...)			\
	({								\
		int ret = retval;					\
		PART_IF_METHOD(method, d)				\
			ret = chip->method(data, ##__VA_ARGS__);	\
		ret;							\
	})

static void partition_irq_mask(struct irq_data *d)
{
	PART_CALL_METHOD_VOID(irq_mask, d);
}

static void partition_irq_unmask(struct irq_data *d)
{
	PART_CALL_METHOD_VOID(irq_unmask, d);
}

static int partition_irq_set_irqchip_state(struct irq_data *d,
					   enum irqchip_irq_state which,
					   bool val)
{
	return PART_CALL_METHOD_INT(-EINVAL, irq_set_irqchip_state, d, which, val);
}

static int partition_irq_get_irqchip_state(struct irq_data *d,
					   enum irqchip_irq_state which,
					   bool *val)
{
	return PART_CALL_METHOD_INT(-EINVAL, irq_get_irqchip_state, d, which, val);
}

static int partition_irq_set_type(struct irq_data *d, unsigned int type)
{
	return PART_CALL_METHOD_INT(IRQ_SET_MASK_OK_NOCOPY, irq_set_type, d, type);
}

static void partition_irq_print_chip(struct irq_data *d, struct seq_file *p)
{
	struct partition_desc *part = irq_data_get_irq_chip_data(d);
	struct irq_chip *chip;
	struct irq_data *data;

	data = partition_get_irqd_chip(part, &chip);
	if (data)
		seq_printf(p, " %5s-%lu", chip->name, data->hwirq);
}

static struct irq_chip partition_irq_chip = {
	.irq_mask		= partition_irq_mask,
	.irq_unmask		= partition_irq_unmask,
	.irq_set_type		= partition_irq_set_type,
	.irq_get_irqchip_state	= partition_irq_get_irqchip_state,
	.irq_set_irqchip_state	= partition_irq_set_irqchip_state,
	.irq_print_chip		= partition_irq_print_chip,
};

static void partition_handle_irq(struct irq_desc *desc)
{
	struct partition_desc *part = irq_desc_get_handler_data(desc);
	struct irq_chip *chip = irq_desc_get_chip(desc);
	int cpu = smp_processor_id();
	int hwirq;

	chained_irq_enter(chip, desc);

	for_each_set_bit(hwirq, part->bitmap, part->nr_parts) {
		if (partition_check_cpu(part, cpu, hwirq))
			break;
	}

	if (unlikely(hwirq == part->nr_parts)) {
		handle_bad_irq(desc);
	} else {
		unsigned int irq;
		irq = irq_find_mapping(part->domain, hwirq);
		generic_handle_irq(irq);
	}

	chained_irq_exit(chip, desc);
}

static int partition_domain_alloc(struct irq_domain *domain, unsigned int virq,
				  unsigned int nr_irqs, void *arg)
{
	int ret;
	irq_hw_number_t hwirq;
	unsigned int type;
	struct irq_fwspec *fwspec = arg;
	struct partition_desc *part;

	BUG_ON(nr_irqs != 1);
	ret = domain->ops->translate(domain, fwspec, &hwirq, &type);
	if (ret)
		return ret;

	part = domain->host_data;

	mutex_lock(&part->lock);
	if (!part->fwspec.param_count) {
		part->fwspec = *fwspec;
		part->convert(&part->fwspec);
	}
	mutex_unlock(&part->lock);

	set_bit(hwirq, part->bitmap);
	irq_set_percpu_devid_partition(virq, &part->parts[hwirq].mask);
	irq_domain_set_info(domain, virq, hwirq, &partition_irq_chip, part,
			    handle_percpu_devid_irq, NULL, NULL);
	irq_set_status_flags(virq, IRQ_NOAUTOEN);

	return 0;
}

static void partition_domain_free(struct irq_domain *domain, unsigned int virq,
				  unsigned int nr_irqs)
{
	struct irq_data *d;

	BUG_ON(nr_irqs != 1);

	d = irq_domain_get_irq_data(domain, virq);
	irq_set_handler(virq, NULL);
	irq_domain_reset_irq_data(d);
}

int partition_translate_id(struct partition_desc *desc, void *partition_id)
{
	struct partition_affinity *part = NULL;
	int i;

	for (i = 0; i < desc->nr_parts; i++) {
		if (desc->parts[i].partition_id == partition_id) {
			part = &desc->parts[i];
			break;
		}
	}

	if (WARN_ON(!part)) {
		pr_err("Failed to find partition\n");
		return -EINVAL;
	}

	return i;
}

static int partition_domain_activate(struct irq_domain *domain,
				     struct irq_data *d, bool reserve)
{
	struct partition_desc *part = irq_data_get_irq_chip_data(d);
	int ret = 0;

	mutex_lock(&part->lock);
	if (!part->chained_desc) {
		unsigned int irq;

		irq = irq_create_fwspec_mapping(&part->fwspec);
		if (WARN_ON(!irq)) {
			ret = -EINVAL;
			goto out;
		}

		part->chained_desc = irq_to_desc(irq);
		irq_set_chained_handler_and_data(irq,
						 partition_handle_irq,
						 part);
	}
out:
	mutex_unlock(&part->lock);
	return ret;
}

#ifdef CONFIG_GENERIC_IRQ_DEBUGFS
static atomic_t part_id;
static char *partition_override_name(struct irq_domain *domain)
{
	return kasprintf(GFP_KERNEL, "%s-part-%d",
			 domain->name, atomic_fetch_inc(&part_id));
}
#endif

struct partition_desc *partition_create_desc(struct fwnode_handle *fwnode,
					     struct partition_affinity *parts,
					     int nr_parts,
					     void (*convert)(struct irq_fwspec *fwspec),
					     const struct irq_domain_ops *ops)
{
	struct partition_desc *desc;
	struct irq_domain *d;

	BUG_ON(!ops->select || !ops->translate);

	desc = kzalloc(sizeof(*desc), GFP_KERNEL);
	if (!desc)
		return NULL;

	mutex_init(&desc->lock);

	desc->ops = *ops;
	desc->ops.free = partition_domain_free;
	desc->ops.alloc = partition_domain_alloc;
	desc->ops.activate = partition_domain_activate;
#ifdef CONFIG_GENERIC_IRQ_DEBUGFS
	desc->ops.override_name = partition_override_name;
#endif
	desc->convert = convert;

	d = irq_domain_create_linear(fwnode, nr_parts, &desc->ops, desc);
	if (!d)
		goto out;
	desc->domain = d;

	desc->bitmap = kzalloc(sizeof(long) * BITS_TO_LONGS(nr_parts),
			       GFP_KERNEL);
	if (WARN_ON(!desc->bitmap))
		goto out;

	desc->nr_parts = nr_parts;
	desc->parts = parts;

	return desc;
out:
	if (d)
		irq_domain_remove(d);
	kfree(desc);

	return NULL;
}

struct irq_domain *partition_get_domain(struct partition_desc *dsc)
{
	if (dsc)
		return dsc->domain;

	return NULL;
}
