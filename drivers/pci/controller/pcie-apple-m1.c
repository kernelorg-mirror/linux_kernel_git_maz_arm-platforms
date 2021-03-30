// SPDX-License-Identifier: GPL-2.0
/*
 * Not much of a PCIe host bridge driver for Apple M1.
 *
 * The HW is ECAM compliant, and the driver completely relies on the
 * generic host bridge code, assuming that some generous firmware has
 * set things up already. This may or may not hold true in the future.
 *
 * In fact, this mostly implements the MSI handling.
 *
 * Copyright (C) 2021 Google LLC
 * Author: Marc Zyngier <maz@kernel.org>
 */

#include <linux/kernel.h>
#include <linux/irqdomain.h>
#include <linux/module.h>
#include <linux/msi.h>
#include <linux/of_irq.h>
#include <linux/pci-ecam.h>

struct apple_pcie {
	u32			msi_base;
	u32			nvecs;
	struct mutex		lock;
	struct device		*dev;
	struct irq_domain	*domain;
	unsigned long		*bitmap;
};

static void apple_msi_top_irq_mask(struct irq_data *d)
{
	pr_info("IRQ%d (%ld) masked\n", d->irq, d->parent_data->hwirq);
	pci_msi_mask_irq(d);
	irq_chip_mask_parent(d);
}

static void apple_msi_top_irq_unmask(struct irq_data *d)
{
	pr_info("IRQ%d (%ld) unmasked\n", d->irq, d->parent_data->hwirq);
	pci_msi_unmask_irq(d);
	irq_chip_unmask_parent(d);
}

static void apple_msi_top_irq_eoi(struct irq_data *d)
{
	pr_info("IRQ%d (%ld) eoi\n", d->irq, d->parent_data->hwirq);
	irq_chip_eoi_parent(d);
}

static struct irq_chip apple_msi_top_chip = {
	.name			= "PCIe MSI",
	.irq_mask		= apple_msi_top_irq_mask,
	.irq_unmask		= apple_msi_top_irq_unmask,
	.irq_eoi		= apple_msi_top_irq_eoi,
	.irq_set_affinity	= irq_chip_set_affinity_parent,
	.irq_set_type		= irq_chip_set_type_parent,
};

static void apple_msi_compose_msg(struct irq_data *data, struct msi_msg *msg)
{
	/* The doorbell address is "well known" */
	msg->address_lo = 0;
	msg->address_hi = 0xfffff000;
	msg->data = data->hwirq;
}

static struct irq_chip apple_msi_bottom_chip = {
	.name			= "MSI",
	.irq_mask		= irq_chip_mask_parent,
	.irq_unmask		= irq_chip_unmask_parent,
	.irq_set_affinity 	= irq_chip_set_affinity_parent,
	.irq_eoi		= irq_chip_eoi_parent,
	.irq_set_affinity	= irq_chip_set_affinity_parent,
	.irq_set_type		= irq_chip_set_type_parent,
	.irq_compose_msi_msg	= apple_msi_compose_msg,
};

static int apple_msi_domain_alloc(struct irq_domain *domain, unsigned int virq,
				  unsigned int nr_irqs, void *args)
{
	struct apple_pcie *pcie = domain->host_data;
	struct irq_fwspec fwspec;
	unsigned int i;
	int ret, hwirq;

	mutex_lock(&pcie->lock);

	hwirq = bitmap_find_free_region(pcie->bitmap, pcie->nvecs,
					order_base_2(nr_irqs));

	mutex_unlock(&pcie->lock);

	if (hwirq < 0)
		return -ENOSPC;

	fwspec.fwnode = domain->parent->fwnode;
	fwspec.param_count = 3;
	fwspec.param[0] = 0;
	fwspec.param[1] = hwirq + pcie->msi_base;
	fwspec.param[2] = IRQ_TYPE_EDGE_RISING;

	ret = irq_domain_alloc_irqs_parent(domain, virq, nr_irqs, &fwspec);
	if (ret)
		return ret;

	for (i = 0; i < nr_irqs; i++)
		irq_domain_set_hwirq_and_chip(domain, virq + i, hwirq + i,
					      &apple_msi_bottom_chip,
					      domain->host_data);

	return 0;
}

static void apple_msi_domain_free(struct irq_domain *domain, unsigned int virq,
				  unsigned int nr_irqs)
{
	struct irq_data *d = irq_domain_get_irq_data(domain, virq);
	struct apple_pcie *pcie = domain->host_data;

	mutex_lock(&pcie->lock);

	bitmap_release_region(pcie->bitmap, d->hwirq, order_base_2(nr_irqs));

	mutex_unlock(&pcie->lock);
}

static const struct irq_domain_ops apple_msi_domain_ops = {
	.alloc	= apple_msi_domain_alloc,
	.free	= apple_msi_domain_free,
};

static struct msi_domain_info apple_msi_info = {
	.flags	= (MSI_FLAG_USE_DEF_DOM_OPS | MSI_FLAG_USE_DEF_CHIP_OPS |
		   MSI_FLAG_MULTI_PCI_MSI | MSI_FLAG_PCI_MSIX),
	.chip	= &apple_msi_top_chip,
};

static int apple_msi_init(struct apple_pcie *pcie)
{
	struct fwnode_handle *fwnode = dev_fwnode(pcie->dev);
	struct device_node *parent_intc;
	struct irq_domain *parent;
	void __iomem *port;
	int ret, i = 0;

	do {
		port = devm_of_iomap(pcie->dev, to_of_node(fwnode), i + 3, NULL);
		if (!IS_ERR(port)) {
			/* OpenBSD magic */
			writel(0xfffff000, port + 0x168);
			writel(0, port + 0x128);
			writel((5 << 4) | 1, port + 0x124);
			i++;
		}
	} while (!IS_ERR(port));

	if (i == 0)
		return -ENODEV;

	ret = of_property_read_u32_index(to_of_node(fwnode), "msi-interrupts",
					 0, &pcie->msi_base);
	if (ret)
		return ret;

	ret = of_property_read_u32_index(to_of_node(fwnode), "msi-interrupts",
					 1, &pcie->nvecs);
	if (ret)
		return ret;

	pcie->bitmap = devm_kcalloc(pcie->dev, BITS_TO_LONGS(pcie->nvecs),
				    sizeof(long), GFP_KERNEL);
	if (!pcie->bitmap)
		return -ENOMEM;

	parent_intc = of_irq_find_parent(to_of_node(fwnode));
	parent = irq_find_host(parent_intc);
	if (!parent_intc || !parent) {
		dev_err(pcie->dev, "failed to find parent domain\n");
		return -ENXIO;
	}

	parent = irq_domain_create_hierarchy(parent, 0, pcie->nvecs, fwnode,
					     &apple_msi_domain_ops, pcie);
	if (!parent) {
		dev_err(pcie->dev, "failed to create IRQ domain\n");
		return -ENOMEM;
	}
	irq_domain_update_bus_token(parent, DOMAIN_BUS_NEXUS);

	pcie->domain = pci_msi_create_irq_domain(fwnode, &apple_msi_info,
						 parent);
	if (!pcie->domain) {
		dev_err(pcie->dev, "failed to create MSI domain\n");
		irq_domain_remove(parent);
		return -ENOMEM;
	}

	return 0;
}

#if 0
static void apple_msi_teardown(struct apple_pcie *pcie)
{
	struct irq_domain *parent = pcie->domain->parent;

	irq_domain_remove(pcie->domain);
	irq_domain_remove(parent);
}
#endif

static int apple_m1_pci_init(struct pci_config_window *cfg)
{
	struct device *dev = cfg->parent;
	struct apple_pcie *pcie;

	pcie = devm_kzalloc(dev, sizeof(*pcie), GFP_KERNEL);
	if (!pcie)
		return -ENOMEM;

	pcie->dev = dev;

	mutex_init(&pcie->lock);

	return apple_msi_init(pcie);
}

static const struct pci_ecam_ops apple_m1_cfg_ecam_ops = {
	.init		= apple_m1_pci_init,
	.pci_ops	= {
		.map_bus	= pci_ecam_map_bus,
		.read		= pci_generic_config_read,
		.write		= pci_generic_config_write,
	}
};

static const struct of_device_id apple_pci_of_match[] = {
	{ .compatible = "apple,pcie-m1", .data = &apple_m1_cfg_ecam_ops },
	{ },
};
MODULE_DEVICE_TABLE(of, gen_pci_of_match);

static struct platform_driver apple_pci_driver = {
	.driver = {
		.name = "pcie-apple-m1",
		.of_match_table = apple_pci_of_match,
	},
	.probe = pci_host_common_probe,
	.remove = pci_host_common_remove,
};
module_platform_driver(apple_pci_driver);

MODULE_LICENSE("GPL v2");
