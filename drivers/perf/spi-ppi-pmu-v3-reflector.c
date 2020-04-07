// SPDX-License-Identifier: GPL-2.0
// ARM PMUv3 SPI to PPI reflector

#include <linux/interrupt.h>
#include <linux/module.h>
#include <linux/of_address.h>
#include <linux/of_device.h>
#include <linux/of_irq.h>
#include <linux/of_platform.h>
#include <linux/platform_device.h>
#include <linux/slab.h>
#include <linux/spinlock.h>

#define DRIVER_NAME		"PPI-SPI PMUv3 reflector"

static int ppi, spi;

static void generate_ppi(void *info)
{
	if (lower_32_bits(read_sysreg(pmovsclr_el0)))
		WARN_ON_ONCE(irq_set_irqchip_state(ppi, IRQCHIP_STATE_PENDING, true));
}

static irqreturn_t pmu_handle_thread_irq(int irq, void *dev)
{
	bool state;

	do {
		on_each_cpu(generate_ppi, NULL, true);

		WARN_ON(irq_get_irqchip_state(spi, IRQCHIP_STATE_PENDING,
					      &state));
	} while (state);

	enable_irq(spi);

	return IRQ_HANDLED;
}

static irqreturn_t pmu_handle_irq(int irq, void *dev)
{
	/*
	 * We must generate an interrupt on the local CPU first, as
	 * the thread is going to result in a context-switch and we
	 * won't be able to observe the interrupted context anymore.
	 */
	generate_ppi(NULL);
	disable_irq_nosync(irq);

	return IRQ_WAKE_THREAD;
}

static int spi_ppi_pmu_probe(struct platform_device *pdev)
{
	struct device_node *np;
	u32 phandle;
	int ret;

	spi = platform_get_irq(pdev, 0);
	if (spi <= 0)
		return -ENXIO;

	ret = of_property_read_u32(dev_of_node(&pdev->dev), "reflect-to",
				   &phandle);
	if (ret < 0)
		return -ENXIO;

	np = of_find_node_by_phandle(phandle);
	if (!np)
		return -ENODEV;

	ppi = irq_of_parse_and_map(np, 0);
	if (ppi <= 0 || !irq_is_percpu_devid(ppi))
		return -EINVAL;

	ret = request_threaded_irq(spi, pmu_handle_irq, pmu_handle_thread_irq,
				   0, "reflector", pdev);

	if (!ret)
		dev_info(&pdev->dev, "redirecting IRQ%d to %pOF IRQ%d\n",
			 spi, np, ppi);

	return WARN_ON(ret);
}

static const struct of_device_id spi_ppi_pmu_matches[] = {
	{
		.compatible = "uglyhack,spi-ppi-pmu-reflector",
		.data	= NULL,
	},
	{},
};
MODULE_DEVICE_TABLE(of, spi_ppi_pmu_matches);

static struct platform_driver spi_ppi_pmu_driver = {
	.driver = {
		   .name = DRIVER_NAME,
		   .of_match_table = spi_ppi_pmu_matches,
		  },
	.probe = spi_ppi_pmu_probe,
};

module_platform_driver(spi_ppi_pmu_driver);
MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION(DRIVER_NAME " support");
