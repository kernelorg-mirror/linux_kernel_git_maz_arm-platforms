// SPDX-License-Identifier: GPL-2.0+
/*
 * PCIe host controller driver for Xilinx Versal CPM DMA Bridge
 *
 * (C) Copyright 2019 - 2020, Xilinx, Inc.
 */

#include <linux/interrupt.h>
#include <linux/irq.h>
#include <linux/irqdomain.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/of_address.h>
#include <linux/of_pci.h>
#include <linux/of_platform.h>
#include <linux/of_irq.h>
#include <linux/pci.h>
#include <linux/platform_device.h>
#include <linux/pci-ecam.h>

#include "../pci.h"

/* Register definitions */
#define XILINX_CPM_PCIE_REG_IDR		0x00000E10
#define XILINX_CPM_PCIE_REG_IMR		0x00000E14
#define XILINX_CPM_PCIE_REG_PSCR	0x00000E1C
#define XILINX_CPM_PCIE_REG_RPSC	0x00000E20
#define XILINX_CPM_PCIE_REG_RPEFR	0x00000E2C
#define XILINX_CPM_PCIE_REG_IDRN	0x00000E38
#define XILINX_CPM_PCIE_REG_IDRN_MASK	0x00000E3C
#define XILINX_CPM_PCIE_MISC_IR_STATUS	0x00000340
#define XILINX_CPM_PCIE_MISC_IR_ENABLE	0x00000348
#define XILINX_CPM_PCIE_MISC_IR_LOCAL	BIT(1)

/* Interrupt registers definitions */
#define XILINX_CPM_PCIE_INTR_LINK_DOWN		BIT(0)
#define XILINX_CPM_PCIE_INTR_HOT_RESET		BIT(3)
#define XILINX_CPM_PCIE_INTR_CFG_TIMEOUT	BIT(8)
#define XILINX_CPM_PCIE_INTR_CORRECTABLE	BIT(9)
#define XILINX_CPM_PCIE_INTR_NONFATAL		BIT(10)
#define XILINX_CPM_PCIE_INTR_FATAL		BIT(11)
#define XILINX_CPM_PCIE_INTR_INTX		BIT(16)
#define XILINX_CPM_PCIE_INTR_MSI		BIT(17)
#define XILINX_CPM_PCIE_INTR_SLV_UNSUPP		BIT(20)
#define XILINX_CPM_PCIE_INTR_SLV_UNEXP		BIT(21)
#define XILINX_CPM_PCIE_INTR_SLV_COMPL		BIT(22)
#define XILINX_CPM_PCIE_INTR_SLV_ERRP		BIT(23)
#define XILINX_CPM_PCIE_INTR_SLV_CMPABT		BIT(24)
#define XILINX_CPM_PCIE_INTR_SLV_ILLBUR		BIT(25)
#define XILINX_CPM_PCIE_INTR_MST_DECERR		BIT(26)
#define XILINX_CPM_PCIE_INTR_MST_SLVERR		BIT(27)
#define XILINX_CPM_PCIE_IMR_ALL_MASK		0x1FF39FF9
#define XILINX_CPM_PCIE_IDR_ALL_MASK		0xFFFFFFFF
#define XILINX_CPM_PCIE_IDRN_MASK		GENMASK(19, 16)
#define XILINX_CPM_PCIE_INTR_CFG_PCIE_TIMEOUT	BIT(4)
#define XILINX_CPM_PCIE_INTR_CFG_ERR_POISON	BIT(12)
#define XILINX_CPM_PCIE_INTR_PME_TO_ACK_RCVD	BIT(15)
#define XILINX_CPM_PCIE_INTR_PM_PME_RCVD	BIT(17)
#define XILINX_CPM_PCIE_INTR_SLV_PCIE_TIMEOUT	BIT(28)
#define XILINX_CPM_PCIE_IDRN_SHIFT		16

/* Root Port Error FIFO Read Register definitions */
#define XILINX_CPM_PCIE_RPEFR_ERR_VALID		BIT(18)
#define XILINX_CPM_PCIE_RPEFR_REQ_ID		GENMASK(15, 0)
#define XILINX_CPM_PCIE_RPEFR_ALL_MASK		0xFFFFFFFF

/* Root Port Status/control Register definitions */
#define XILINX_CPM_PCIE_REG_RPSC_BEN		BIT(0)

/* Phy Status/Control Register definitions */
#define XILINX_CPM_PCIE_REG_PSCR_LNKUP		BIT(11)

/**
 * struct xilinx_cpm_pcie_port - PCIe port information
 * @reg_base: Bridge Register Base
 * @cpm_base: CPM System Level Control and Status Register(SLCR) Base
 * @dev: Device pointer
 * @leg_domain: Legacy IRQ domain pointer
 * @cfg: Holds mappings of config space window
 * @irq_misc: Legacy and error interrupt number
 * @leg_mask_lock: lock for legacy interrupts
 */
struct xilinx_cpm_pcie_port {
	void __iomem *reg_base;
	void __iomem *cpm_base;
	struct device *dev;
	struct irq_domain *leg_domain;
	struct pci_config_window *cfg;
	int irq_misc;
	raw_spinlock_t leg_mask_lock;
};

static inline u32 pcie_read(struct xilinx_cpm_pcie_port *port, u32 reg)
{
	return readl(port->reg_base + reg);
}

static inline void pcie_write(struct xilinx_cpm_pcie_port *port,
			      u32 val, u32 reg)
{
	writel(val, port->reg_base + reg);
}

static inline bool cpm_pcie_link_up(struct xilinx_cpm_pcie_port *port)
{
	return (pcie_read(port, XILINX_CPM_PCIE_REG_PSCR) &
		XILINX_CPM_PCIE_REG_PSCR_LNKUP) ? 1 : 0;
}

/**
 * xilinx_cpm_pcie_clear_err_interrupts - Clear Error Interrupts
 * @port: PCIe port information
 */
static void cpm_pcie_clear_err_interrupts(struct xilinx_cpm_pcie_port *port)
{
	unsigned long val = pcie_read(port, XILINX_CPM_PCIE_REG_RPEFR);

	if (val & XILINX_CPM_PCIE_RPEFR_ERR_VALID) {
		dev_dbg(port->dev, "Requester ID %lu\n",
			val & XILINX_CPM_PCIE_RPEFR_REQ_ID);
		pcie_write(port, XILINX_CPM_PCIE_RPEFR_ALL_MASK,
			   XILINX_CPM_PCIE_REG_RPEFR);
	}
}

static void xilinx_cpm_mask_leg_irq(struct irq_data *data)
{
	struct irq_desc *desc = irq_to_desc(data->irq);
	struct xilinx_cpm_pcie_port *port;
	unsigned long flags;
	u32 mask;
	u32 val;

	port = irq_desc_get_chip_data(desc);
	mask = (1 << data->hwirq) << XILINX_CPM_PCIE_IDRN_SHIFT;
	raw_spin_lock_irqsave(&port->leg_mask_lock, flags);
	val = pcie_read(port, XILINX_CPM_PCIE_REG_IDRN_MASK);
	pcie_write(port, (val & (~mask)), XILINX_CPM_PCIE_REG_IDRN_MASK);
	raw_spin_unlock_irqrestore(&port->leg_mask_lock, flags);
}

static void xilinx_cpm_unmask_leg_irq(struct irq_data *data)
{
	struct irq_desc *desc = irq_to_desc(data->irq);
	struct xilinx_cpm_pcie_port *port;
	unsigned long flags;
	u32 mask;
	u32 val;

	port = irq_desc_get_chip_data(desc);
	mask = (1 << data->hwirq) << XILINX_CPM_PCIE_IDRN_SHIFT;
	raw_spin_lock_irqsave(&port->leg_mask_lock, flags);
	val = pcie_read(port, XILINX_CPM_PCIE_REG_IDRN_MASK);
	pcie_write(port, (val | mask), XILINX_CPM_PCIE_REG_IDRN_MASK);
	raw_spin_unlock_irqrestore(&port->leg_mask_lock, flags);
}

static struct irq_chip xilinx_cpm_leg_irq_chip = {
	.name = "xilinx_cpm_pcie:legacy",
	.irq_enable = xilinx_cpm_unmask_leg_irq,
	.irq_disable = xilinx_cpm_mask_leg_irq,
	.irq_mask = xilinx_cpm_mask_leg_irq,
	.irq_unmask = xilinx_cpm_unmask_leg_irq,
};

/**
 * xilinx_cpm_pcie_intx_map - Set the handler for the INTx and mark IRQ as valid
 * @domain: IRQ domain
 * @irq: Virtual IRQ number
 * @hwirq: HW interrupt number
 *
 * Return: Always returns 0.
 */
static int xilinx_cpm_pcie_intx_map(struct irq_domain *domain,
				    unsigned int irq, irq_hw_number_t hwirq)
{
	irq_set_chip_and_handler(irq, &xilinx_cpm_leg_irq_chip,
				 handle_level_irq);
	irq_set_chip_data(irq, domain->host_data);
	irq_set_status_flags(irq, IRQ_LEVEL);

	return 0;
}

/* INTx IRQ Domain operations */
static const struct irq_domain_ops intx_domain_ops = {
	.map = xilinx_cpm_pcie_intx_map,
};

/**
 * xilinx_cpm_pcie_intr_handler - Interrupt Service Handler
 * @irq: IRQ number
 * @data: PCIe port information
 *
 * Return: IRQ_HANDLED on success and IRQ_NONE on failure
 */
static irqreturn_t xilinx_cpm_pcie_intr_handler(int irq, void *data)
{
	struct xilinx_cpm_pcie_port *port = data;
	struct device *dev = port->dev;
	u32 val, mask, status, bit;
	unsigned long intr_val;

	/* Read interrupt decode and mask registers */
	val = pcie_read(port, XILINX_CPM_PCIE_REG_IDR);
	mask = pcie_read(port, XILINX_CPM_PCIE_REG_IMR);

	status = val & mask;
	if (!status)
		return IRQ_NONE;

	if (status & XILINX_CPM_PCIE_INTR_LINK_DOWN)
		dev_warn(dev, "Link Down\n");

	if (status & XILINX_CPM_PCIE_INTR_HOT_RESET)
		dev_info(dev, "Hot reset\n");

	if (status & XILINX_CPM_PCIE_INTR_CFG_TIMEOUT)
		dev_warn(dev, "ECAM access timeout\n");

	if (status & XILINX_CPM_PCIE_INTR_CORRECTABLE) {
		dev_warn(dev, "Correctable error message\n");
		cpm_pcie_clear_err_interrupts(port);
	}

	if (status & XILINX_CPM_PCIE_INTR_NONFATAL) {
		dev_warn(dev, "Non fatal error message\n");
		cpm_pcie_clear_err_interrupts(port);
	}

	if (status & XILINX_CPM_PCIE_INTR_FATAL) {
		dev_warn(dev, "Fatal error message\n");
		cpm_pcie_clear_err_interrupts(port);
	}

	if (status & XILINX_CPM_PCIE_INTR_INTX) {
		/* Handle INTx Interrupt */
		intr_val = pcie_read(port, XILINX_CPM_PCIE_REG_IDRN);
		intr_val = intr_val >> XILINX_CPM_PCIE_IDRN_SHIFT;

		for_each_set_bit(bit, &intr_val, PCI_NUM_INTX)
			generic_handle_irq(irq_find_mapping(port->leg_domain,
							    bit));
	}

	if (status & XILINX_CPM_PCIE_INTR_SLV_UNSUPP)
		dev_warn(dev, "Slave unsupported request\n");

	if (status & XILINX_CPM_PCIE_INTR_SLV_UNEXP)
		dev_warn(dev, "Slave unexpected completion\n");

	if (status & XILINX_CPM_PCIE_INTR_SLV_COMPL)
		dev_warn(dev, "Slave completion timeout\n");

	if (status & XILINX_CPM_PCIE_INTR_SLV_ERRP)
		dev_warn(dev, "Slave Error Poison\n");

	if (status & XILINX_CPM_PCIE_INTR_SLV_CMPABT)
		dev_warn(dev, "Slave Completer Abort\n");

	if (status & XILINX_CPM_PCIE_INTR_SLV_ILLBUR)
		dev_warn(dev, "Slave Illegal Burst\n");

	if (status & XILINX_CPM_PCIE_INTR_MST_DECERR)
		dev_warn(dev, "Master decode error\n");

	if (status & XILINX_CPM_PCIE_INTR_MST_SLVERR)
		dev_warn(dev, "Master slave error\n");

	if (status & XILINX_CPM_PCIE_INTR_CFG_PCIE_TIMEOUT)
		dev_warn(dev, "PCIe ECAM access timeout\n");

	if (status & XILINX_CPM_PCIE_INTR_CFG_ERR_POISON)
		dev_warn(dev, "ECAM poisoned completion received\n");

	if (status & XILINX_CPM_PCIE_INTR_PME_TO_ACK_RCVD)
		dev_warn(dev, "PME_TO_ACK message received\n");

	if (status & XILINX_CPM_PCIE_INTR_PM_PME_RCVD)
		dev_warn(dev, "PM_PME message received\n");

	if (status & XILINX_CPM_PCIE_INTR_SLV_PCIE_TIMEOUT)
		dev_warn(dev, "PCIe completion timeout received\n");

	/* Clear the Interrupt Decode register */
	pcie_write(port, status, XILINX_CPM_PCIE_REG_IDR);

	/*
	 * XILINX_CPM_PCIE_MISC_IR_STATUS register is mapped to
	 * CPM SLCR block.
	 */
	val = readl(port->cpm_base + XILINX_CPM_PCIE_MISC_IR_STATUS);
	if (val)
		writel(val, port->cpm_base + XILINX_CPM_PCIE_MISC_IR_STATUS);

	return IRQ_HANDLED;
}

/**
 * xilinx_cpm_pcie_init_irq_domain - Initialize IRQ domain
 * @port: PCIe port information
 *
 * Return: '0' on success and error value on failure
 */
static int xilinx_cpm_pcie_init_irq_domain(struct xilinx_cpm_pcie_port *port)
{
	struct device *dev = port->dev;
	struct device_node *node = dev->of_node;
	struct device_node *pcie_intc_node;

	/* Setup INTx */
	pcie_intc_node = of_get_next_child(node, NULL);
	if (!pcie_intc_node) {
		dev_err(dev, "No PCIe Intc node found\n");
		return -EINVAL;
	}

	port->leg_domain = irq_domain_add_linear(pcie_intc_node, PCI_NUM_INTX,
						 &intx_domain_ops,
						 port);
	of_node_put(pcie_intc_node);
	if (!port->leg_domain) {
		dev_err(dev, "Failed to get a INTx IRQ domain\n");
		return -ENOMEM;
	}

	raw_spin_lock_init(&port->leg_mask_lock);
	return 0;
}

/**
 * xilinx_cpm_pcie_init_port - Initialize hardware
 * @port: PCIe port information
 */
static void xilinx_cpm_pcie_init_port(struct xilinx_cpm_pcie_port *port)
{
	if (cpm_pcie_link_up(port))
		dev_info(port->dev, "PCIe Link is UP\n");
	else
		dev_info(port->dev, "PCIe Link is DOWN\n");

	/* Disable all interrupts */
	pcie_write(port, ~XILINX_CPM_PCIE_IDR_ALL_MASK,
		   XILINX_CPM_PCIE_REG_IMR);

	/* Clear pending interrupts */
	pcie_write(port, pcie_read(port, XILINX_CPM_PCIE_REG_IDR) &
		   XILINX_CPM_PCIE_IMR_ALL_MASK,
		   XILINX_CPM_PCIE_REG_IDR);

	/* Enable all interrupts */
	pcie_write(port, XILINX_CPM_PCIE_IMR_ALL_MASK,
		   XILINX_CPM_PCIE_REG_IMR);
	pcie_write(port, XILINX_CPM_PCIE_IDRN_MASK,
		   XILINX_CPM_PCIE_REG_IDRN_MASK);

	/*
	 * XILINX_CPM_PCIE_MISC_IR_ENABLE register is mapped to
	 * CPM SLCR block.
	 */
	writel(XILINX_CPM_PCIE_MISC_IR_LOCAL,
	       port->cpm_base + XILINX_CPM_PCIE_MISC_IR_ENABLE);
	/* Enable the Bridge enable bit */
	pcie_write(port, pcie_read(port, XILINX_CPM_PCIE_REG_RPSC) |
		   XILINX_CPM_PCIE_REG_RPSC_BEN,
		   XILINX_CPM_PCIE_REG_RPSC);
}

static int xilinx_cpm_request_misc_irq(struct xilinx_cpm_pcie_port *port)
{
	struct device *dev = port->dev;
	struct platform_device *pdev = to_platform_device(dev);
	int err;

	port->irq_misc = platform_get_irq(pdev, 0);
	if (port->irq_misc <= 0) {
		dev_err(dev, "Unable to find misc IRQ line\n");
		return port->irq_misc;
	}

	err = devm_request_irq(dev, port->irq_misc,
			       xilinx_cpm_pcie_intr_handler,
			       IRQF_SHARED | IRQF_NO_THREAD,
			       "xilinx-pcie", port);
	if (err) {
		dev_err(dev, "unable to request misc IRQ line %d\n",
			port->irq_misc);
		return err;
	}

	return 0;
}

/**
 * xilinx_cpm_pcie_parse_dt - Parse Device tree
 * @port: PCIe port information
 * @bus_range: Bus resource
 *
 * Return: '0' on success and error value on failure
 */
static int xilinx_cpm_pcie_parse_dt(struct xilinx_cpm_pcie_port *port,
				    struct resource *bus_range)
{
	struct device *dev = port->dev;
	struct platform_device *pdev = to_platform_device(dev);
	struct resource *res;
	int err;

	res = platform_get_resource_byname(pdev, IORESOURCE_MEM, "cfg");
	if (!res)
		return -ENXIO;

	port->cfg = pci_ecam_create(dev, res, bus_range,
				    &pci_generic_ecam_ops);
	if (IS_ERR(port->cfg))
		return PTR_ERR(port->cfg);

	port->reg_base = port->cfg->win;

	port->cpm_base = devm_platform_ioremap_resource_byname(pdev,
							       "cpm_slcr");
	if (IS_ERR(port->cpm_base))
		return PTR_ERR(port->cpm_base);

	err = xilinx_cpm_request_misc_irq(port);
	if (err)
		return err;

	return 0;
}

/**
 * xilinx_cpm_pcie_probe - Probe function
 * @pdev: Platform device pointer
 *
 * Return: '0' on success and error value on failure
 */
static int xilinx_cpm_pcie_probe(struct platform_device *pdev)
{
	struct xilinx_cpm_pcie_port *port;
	struct device *dev = &pdev->dev;
	struct pci_host_bridge *bridge;
	struct resource *bus_range;
	int err;

	bridge = devm_pci_alloc_host_bridge(dev, sizeof(*port));
	if (!bridge)
		return -ENODEV;

	port = pci_host_bridge_priv(bridge);

	port->dev = dev;

	err = pci_parse_request_of_pci_ranges(dev, &bridge->windows,
					      &bridge->dma_ranges, &bus_range);
	if (err) {
		dev_err(dev, "Getting bridge resources failed\n");
		return err;
	}

	err = xilinx_cpm_pcie_parse_dt(port, bus_range);
	if (err) {
		dev_err(dev, "Parsing DT failed\n");
		return err;
	}

	xilinx_cpm_pcie_init_port(port);

	err = xilinx_cpm_pcie_init_irq_domain(port);
	if (err) {
		dev_err(dev, "Failed creating IRQ Domain\n");
		return err;
	}

	bridge->dev.parent = dev;
	bridge->sysdata = port->cfg;
	bridge->busnr = port->cfg->busr.start;
	bridge->ops = &pci_generic_ecam_ops.pci_ops;
	bridge->map_irq = of_irq_parse_and_map_pci;
	bridge->swizzle_irq = pci_common_swizzle;

	err = pci_host_probe(bridge);
	if (err < 0) {
		irq_domain_remove(port->leg_domain);
		devm_free_irq(dev, port->irq_misc, port);
		return err;
	}

	return 0;
}

static const struct of_device_id xilinx_cpm_pcie_of_match[] = {
	{ .compatible = "xlnx,versal-cpm-host-1.00", },
	{}
};

static struct platform_driver xilinx_cpm_pcie_driver = {
	.driver = {
		.name = "xilinx-cpm-pcie",
		.of_match_table = xilinx_cpm_pcie_of_match,
		.suppress_bind_attrs = true,
	},
	.probe = xilinx_cpm_pcie_probe,
};

builtin_platform_driver(xilinx_cpm_pcie_driver);
