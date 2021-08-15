/*
 * AHCI SATA platform driver
 *
 * Copyright 2004-2005  Red Hat, Inc.
 *   Jeff Garzik <jgarzik@pobox.com>
 * Copyright 2010  MontaVista Software, LLC.
 *   Anton Vorontsov <avorontsov@ru.mvista.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kthread.h>
#include <linux/pm.h>
#include <linux/device.h>
#include <linux/of_device.h>
#include <linux/platform_device.h>
#include <linux/libata.h>
#include <linux/ahci_platform.h>
#include "ahci.h"
#include <linux/delay.h>

#include <linux/of_address.h>
#include <linux/reset-helper.h> // rstc_get
#include <linux/reset.h>
#include <linux/of_gpio.h>
#include <linux/suspend.h>

#include <scsi/scsi_device.h>
#include <soc/realtek/rtd129x_cpu.h>

#include "libata.h"

#define DRV_NAME_RTK "ahci_rtk"

#define MAX_PORT 2
#define RESET_NUM 3


//#define SATA_SUPPORT_LED_CONTROL	1

#if defined(SATA_SUPPORT_LED_CONTROL)
static u32 blink_gpio_0 = 0;
static u32 blink_gpio_1 = 0;

static u32 hdd_detect_gpio_0 = 0;
static u32 hdd_detect_gpio_1 = 0;

static int irq_number_0 = 0;
static int irq_number_1 = 0;
#endif

struct ahci_port_data {
	unsigned int speed;
	unsigned int phy_status;
	struct reset_control *rstc[RESET_NUM];
	void __iomem *port_reg;
};

struct rtk_ahci_dev {
	struct device *dev;
	void __iomem *base;
	void __iomem *ukbase;

	unsigned int port_num;
	struct ahci_port_data port[MAX_PORT];

	int present_io[MAX_PORT];
	unsigned int speed_limit;
	unsigned int spread_spectrum;
	unsigned int rx_sensitivity;
	unsigned int tx_driving;

	struct ahci_host_priv *hpriv;
};

static struct rtk_ahci_dev ahci_dev = {0};

static ssize_t ahci_rtk_transmit_led_message(struct ata_port *ap, u32 state,
					     ssize_t size);
static void ahci_rtk_postreset(struct ata_link *link, unsigned int *class);
static void ahci_rtk_host_stop(struct ata_host *host);

void ahci_handle_port_interrupt(struct ata_port *ap,
				void __iomem *port_mmio, u32 status);

static void ahci_rtk_reset_port(int port_num)
{
	struct ata_host *host = dev_get_drvdata(ahci_dev.dev);
	void __iomem *port_mmio;
	struct ata_port *ap;

	spin_lock(&host->lock);
	ap = host->ports[port_num];
	port_mmio = ahci_port_base(ap);
	ahci_handle_port_interrupt(ap, port_mmio, 0x00400000);
	spin_unlock(&host->lock);
}

#if defined(SATA_SUPPORT_LED_CONTROL)
static irqreturn_t hdd0_detect_function(int irq, void* dev_id)
{
	int value;

	value = gpio_get_value(hdd_detect_gpio_0);

	if (value)
		ahci_rtk_reset_port(0);

	return IRQ_HANDLED;
}

static irqreturn_t hdd1_detect_function(int irq, void* dev_id)
{
	int value;

	value = gpio_get_value(hdd_detect_gpio_1);

	if (value)
		ahci_rtk_reset_port(1);

	return IRQ_HANDLED;
}
#endif

static void ahci_rtk_host_stop(struct ata_host *host)
{
	struct ahci_host_priv *hpriv = host->private_data;

	ahci_platform_disable_resources(hpriv);
}

static void ahci_rtk_postreset(struct ata_link *link, unsigned int *class)
{
	struct ata_port *ap = link->ap;

#if defined(SATA_SUPPORT_LED_CONTROL)
	if (ap->port_no == 0 && gpio_is_valid(blink_gpio_0))
		ata_link_online(link) ? gpio_set_value(blink_gpio_0, 1) : gpio_set_value(blink_gpio_0, 0);

	if (ap->port_no == 1 && gpio_is_valid(blink_gpio_1))
		ata_link_online(link) ? gpio_set_value(blink_gpio_1, 1) : gpio_set_value(blink_gpio_1, 0);
#endif

	return ahci_ops.postreset(link, class);
}

static ssize_t ahci_rtk_transmit_led_message(struct ata_port *ap, u32 state,
					     ssize_t size)
{
#if defined(SATA_SUPPORT_LED_CONTROL)
	if (ap->port_no == 0 && gpio_is_valid(blink_gpio_0))
		(state & EM_MSG_LED_VALUE_ON) ? gpio_set_value(blink_gpio_0, 1) : gpio_set_value(blink_gpio_0, 0);

	if (ap->port_no == 1 && gpio_is_valid(blink_gpio_1))
		(state & EM_MSG_LED_VALUE_ON) ? gpio_set_value(blink_gpio_1, 1) : gpio_set_value(blink_gpio_1, 0);
#endif

	return ahci_ops.transmit_led_message(ap, state, size);
}

struct ata_port_operations ahci_rtk_ops = {
	.inherits	= &ahci_ops,
	.host_stop	= ahci_rtk_host_stop,
	.postreset	= ahci_rtk_postreset,
	.transmit_led_message = ahci_rtk_transmit_led_message,
};

static const struct ata_port_info ahci_port_info = {
	.flags		= AHCI_FLAG_COMMON | ATA_FLAG_EM | ATA_FLAG_SW_ACTIVITY,
	.pio_mask	= ATA_PIO4,
	.udma_mask	= ATA_UDMA6,
	.port_ops	= &ahci_rtk_ops,
};

static struct scsi_host_template ahci_platform_sht = {
	AHCI_SHT(DRV_NAME_RTK),
};

static const char *rst_name[MAX_PORT][20] = {
	{
//		"sata_func_exist_0",
//		"rstn_sata_phy_pow_0",
		"rstn_sata_0",
		"rstn_sata_phy_0",
		"rstn_sata_phy_pow_0",
	},
	{
//		"sata_func_exist_1",
//		"rstn_sata_phy_pow_1",
		"rstn_sata_1",
		"rstn_sata_phy_1",
		"rstn_sata_phy_pow_1",
	},
};

static int rtk_check_phy_calibration(unsigned int port)
{
	void __iomem *chk_reg;
	unsigned int reg;
	unsigned int calibrate = 0;

	chk_reg = ioremap(0x980171e0, 0x1);
	reg = readl(chk_reg);
	if(port == 0)
		calibrate = reg & 0x1F;
	else if(port == 1)
		calibrate = (reg & 0x3E0) >> 5;
	printk("[SATA] SATA calibrate = %d\n", calibrate);

	iounmap(chk_reg);
	return calibrate;
}

static void writel_delay(unsigned int value, void __iomem *address)
{
	writel(value, address);
	mdelay(1);
}

static void config_sata_phy(unsigned int port)
{
	void __iomem *base = ahci_dev.base;

	struct device_node* child = NULL;
	struct device_node* child_node = NULL;
	u32 index, tx_driving_val;
	int tx_driving_count = 0;

	writel_delay(port, base + 0xF64);

	writel_delay(0x00001111, base + 0xF60);
	writel_delay(0x00005111, base + 0xF60);
	writel_delay(0x00009111, base + 0xF60);

	if(ahci_dev.spread_spectrum==0) {
		printk("[SATA] spread-spectrum disable\n");
		writel_delay(0x538E0411, base + 0xF60);
		writel_delay(0x538E4411, base + 0xF60);
		writel_delay(0x538E8411, base + 0xF60);
	} else {
		printk("[SATA] spread-spectrum enable\n");
		writel_delay(0x738E0411, base + 0xF60);
		writel_delay(0x738E4411, base + 0xF60);
		writel_delay(0x738E8411, base + 0xF60);

		writel_delay(0x35910811, base + 0xF60);
		writel_delay(0x35914811, base + 0xF60);
		writel_delay(0x35918811 , base + 0xF60);

		writel_delay(0x02342711, base + 0xF60);
		writel_delay(0x02346711, base + 0xF60);
		writel_delay(0x0234a711, base + 0xF60);
	}
	writel_delay(0x336a0511, base + 0xF60);
	writel_delay(0x336a4511, base + 0xF60);
	writel_delay(0x336a8511, base + 0xF60);

	writel_delay(0xE0700111, base + 0xF60);
	writel_delay(0xE05C4111, base + 0xF60);
	writel_delay(0xE04A8111, base + 0xF60);

	writel_delay(0x00150611, base + 0xF60);
	writel_delay(0x00154611, base + 0xF60);
	writel_delay(0x00158611, base + 0xF60);

	writel_delay(0xC6000A11, base + 0xF60);
	writel_delay(0xC6004A11, base + 0xF60);
	writel_delay(0xC6008A11, base + 0xF60);

	writel_delay(0x70000211, base + 0xF60);
	writel_delay(0x70004211, base + 0xF60);
	writel_delay(0x70008211, base + 0xF60);

	writel_delay(0xC6600A11, base + 0xF60);
	writel_delay(0xC6604A11, base + 0xF60);
	writel_delay(0xC6608A11, base + 0xF60);

	writel_delay(0x20041911, base + 0xF60);
	writel_delay(0x20045911, base + 0xF60);
	writel_delay(0x20049911, base + 0xF60);

	writel_delay(0x94aa2011, base + 0xF60);
	writel_delay(0x94aa6011, base + 0xF60);
	writel_delay(0x94aaa011, base + 0xF60);

	// for rx sensitivity
	if(get_rtd129x_cpu_revision() == RTD129x_CHIP_REVISION_A00 || get_rtd129x_cpu_revision() == RTD129x_CHIP_REVISION_A01) {
		writel_delay(0x72100911, base + 0xF60);
		writel_delay(0x72104911, base + 0xF60);
		writel_delay(0x72108911, base + 0xF60);
	} else if(get_rtd129x_cpu_revision() >= RTD129x_CHIP_REVISION_B00) {
		writel_delay(0x42100911, base + 0xF60);
		writel_delay(0x42104911, base + 0xF60);
		writel_delay(0x42108911, base + 0xF60);
	}

	/*
	if(ahci_dev.port[port].phy_status==0) {
		writel_delay(0x27640311, base + 0xF60);
		writel_delay(0x27644311, base + 0xF60);
		writel_delay(0x27648311, base + 0xF60);
	} else if(ahci_dev.port[port].phy_status==2) {
		writel_delay(0x27710311, base + 0xF60);
		writel_delay(0x27714311, base + 0xF60);
		writel_delay(0x27718311, base + 0xF60);
	}*/

	if(get_rtd129x_cpu_revision() == RTD129x_CHIP_REVISION_A00 || get_rtd129x_cpu_revision() == RTD129x_CHIP_REVISION_A01) {
		writel_delay(0x27710311, base + 0xF60);
		writel_delay(0x27684311, base + 0xF60);
		writel_delay(0x27668311, base + 0xF60);
	} else if(get_rtd129x_cpu_revision() >= RTD129x_CHIP_REVISION_B00) {
		if(rtk_check_phy_calibration(port) >= 0x16)
			writel_delay(0x27730311, base + 0xF60);
		else
			writel_delay(0x27710311, base + 0xF60);
		writel_delay(0x276d4311, base + 0xF60);
		writel_delay(0x276d8311, base + 0xF60);

		writel_delay(0x7c002a11, base + 0xF60);
		writel_delay(0x7c006a11, base + 0xF60);
		writel_delay(0x7c00aa11, base + 0xF60);
	}

	writel_delay(0x29001011, base + 0xF60);
	writel_delay(0x29005011, base + 0xF60);
	writel_delay(0x29009011, base + 0xF60);

#ifdef CONFIG_MACH_QNAPTS
#if defined(TSX28A)
	printk("[SATA] set tx-driving Gen3 to 573mV\n");
	writel_delay(0x94a42011, base + 0xF60);
	writel_delay(0x94a46011, base + 0xF60);
	writel_delay(0x94a6a011, base + 0xF60);
	writel_delay(0x384a2111, base + 0xF60);
	writel_delay(0x384a6111, base + 0xF60);
	writel_delay(0x486aa111, base + 0xF60);
#elif defined(TSXA28A)
	printk("[SATA] set tx-driving Gen3 to 573mV\n");
	writel_delay(0x94a62011, base + 0xF60);
	writel_delay(0x94a66011, base + 0xF60);
	writel_delay(0x94a6a011, base + 0xF60);
	writel_delay(0x486a2111, base + 0xF60);
	writel_delay(0x486a6111, base + 0xF60);
	writel_delay(0x486aa111, base + 0xF60);
#endif
#else
	if(ahci_dev.tx_driving==2) {
		printk("[SATA] set tx-driving to L (level 2)\n");
		writel_delay(0x94a72011, base + 0xF60);
		writel_delay(0x94a76011, base + 0xF60);
		writel_delay(0x94a7a011, base + 0xF60);
		writel_delay(0x587a2111, base + 0xF60);
		writel_delay(0x587a6111, base + 0xF60);
		writel_delay(0x587aa111, base + 0xF60);
	} else if(ahci_dev.tx_driving == 8) { //This case is for SYNOLOGY
		printk("[SATA] set tx-driving to L (level 8)\n");
		if(port==0) {
			writel_delay(0x94af2011, base + 0xF60);
			writel_delay(0x94af6011, base + 0xF60);
			writel_delay(0x94afa011, base + 0xF60);
			writel_delay(0xf8fa2111, base + 0xF60);
			writel_delay(0xf8fa6111, base + 0xF60);
			writel_delay(0xf8faa111, base + 0xF60);
		} else if(port==1) {
			writel_delay(0x94a82011, base + 0xF60);
			writel_delay(0x94a86011, base + 0xF60);
			writel_delay(0x94a8a011, base + 0xF60);
			writel_delay(0xf88a2111, base + 0xF60);
			writel_delay(0xf88a6111, base + 0xF60);
			writel_delay(0xf88aa111, base + 0xF60);
		}
	}
#endif
	for_each_child_of_node(ahci_dev.dev->of_node, child) {
		if (port == 0) {
			if (child->name && (of_node_cmp(child->name, "sata-port0") == 0)) {
				child_node = child;
				break;
			}
		}

		if (port == 1) {
			if (child->name && (of_node_cmp(child->name, "sata-port1") == 0)) {
				child_node = child;
				break;
			}
		}
	}

	if (child_node)
		tx_driving_count = of_property_count_u32_elems(child_node, "tx-driving-data");

	if (tx_driving_count > 0) {
		for (index=0;index<tx_driving_count;index++) {
			of_property_read_u32_index(child_node, "tx-driving-data", index, &tx_driving_val);
			writel_delay(tx_driving_val, base + 0xF60);
		}
	}

	// RX power saving off
	writel_delay(0x40000C11, base + 0xF60);
	writel_delay(0x40004C11, base + 0xF60);
	writel_delay(0x40008C11, base + 0xF60);

	writel_delay(0x00271711, base + 0xF60);
	writel_delay(0x00275711, base + 0xF60);
	writel_delay(0x00279711, base + 0xF60);
}

static void config_sata_mac(unsigned int port)
{
	unsigned int val;
	void __iomem *base, *port_base;

	base = ahci_dev.base;
	port_base = ahci_dev.port[port].port_reg;

	writel_delay(port, base + 0xF64);

	/* SATA MAC */
//	writel_delay(0x2, port_base + 0x144);
	writel_delay(0x6726ff81, base);
	val = readl(base);
	writel_delay(0x6737ff81, base);
	val = readl(base);

//	writel_delay(0x83090c15, base + 0xbc);
//	writel_delay(0x83090c15, base + 0xbc);

	writel_delay(0x80000001, base + 0x4);
	writel_delay(0x80000002, base + 0x4);

	val = readl(base + 0x14);
	writel_delay((val & ~0x1), base + 0x14);
	val = readl(base + 0xC);
	writel_delay((val | 0x3), base + 0xC);
	val = readl(base + 0x18);
	val |= port << 1;
	writel_delay(val, base + 0x18);

	writel_delay(0xffffffff, port_base + 0x114);
//	writel_delay(0x05040000, port_base + 0x100);
//	writel_delay(0x05040400, port_base + 0x108);

	val = readl(port_base + 0x170);
	writel_delay(0x88, port_base + 0x170);
	val = readl(port_base + 0x118);
	writel_delay(0x10, port_base + 0x118);
	val = readl(port_base + 0x118);
	writel_delay(0x4016, port_base + 0x118);
	val = readl(port_base + 0x140);
	writel_delay(0xf000, port_base + 0x140);

	writel_delay(0x3c300, base + 0xf20);

	writel_delay(0x700, base + 0xA4);

	//Set to Auto mode
	if(ahci_dev.port[port].speed == 0)
		writel_delay(0xA, base + 0xF68);
	else if(ahci_dev.port[port].speed == 2)
		writel_delay(0x5, base + 0xF68);
	else if(ahci_dev.port[port].speed == 1)
		writel_delay(0x0, base + 0xF68);
}

static int send_oob(unsigned int port)
{
	unsigned int val=0;

	if(port==0) {
		val = readl(ahci_dev.ukbase + 0x80);
		val |= 0x115;
	} else if(port==1) {
		val = readl(ahci_dev.ukbase + 0x80);
		val |= 0x12A;
	}
	writel(val, ahci_dev.ukbase + 0x80);

	return 0;
}

void set_rx_sensitivity(unsigned int port, unsigned int rx_sens)
{
	void __iomem *base, *port_base;
	unsigned int val;

	base = ahci_dev.base;
	port_base = ahci_dev.port[port].port_reg;

	writel_delay(port, base + 0xF64);

	val = readl(port_base + 0x12C);
	val = val & ~0x1;
	writel_delay(val, port_base + 0x12c);

	if(rx_sens==0) {
		printk("[SATA] change rx_sensitivy to %d\n", rx_sens);
		writel_delay(0x27640311, base + 0xF60);
		writel_delay(0x27644311, base + 0xF60);
		writel_delay(0x27648311, base + 0xF60);
	} else if(rx_sens==2) {
		printk("[SATA] change rx_sensitivy to %d\n", rx_sens);
		writel_delay(0x27710311, base + 0xF60);
		writel_delay(0x27714311, base + 0xF60);
		writel_delay(0x27718311, base + 0xF60);
	}
	val = val | 0x1;
	writel_delay(val, port_base + 0x12c);
	val = val & ~0x1;
	writel_delay(val, port_base + 0x12c);

	val = val | 0x4;
	writel_delay(val, port_base + 0x12c);
	val = val & ~0x4;
	writel_delay(val, port_base + 0x12c);
}

int change_rx_sensitivity(unsigned int id)
{
	unsigned int port;
	if(id > ahci_dev.port_num) {
		printk("[SATA] this port is larger than port number");
		return -1;
	}

	port = id - 1;
	if(ahci_dev.port[port].phy_status==0)
		ahci_dev.port[port].phy_status = 2;
	else
		ahci_dev.port[port].phy_status = 0;

	set_rx_sensitivity(port, ahci_dev.port[port].phy_status);
	return 0;
}
EXPORT_SYMBOL_GPL(change_rx_sensitivity);

static int rtk_ahci_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct ahci_host_priv *hpriv;
	struct ahci_port_data *port_data;
	int ret, i, j;
#if defined(SATA_SUPPORT_LED_CONTROL)
	int gpio;
#endif

	ahci_dev.dev = &pdev->dev;

	ahci_dev.base = of_iomap(pdev->dev.of_node, 0);
	if (!ahci_dev.base) {
		dev_err(dev, "no mmio space(SATA host)\n");
		return -EINVAL;
	}

	ahci_dev.ukbase = of_iomap(pdev->dev.of_node, 1);
	if (!ahci_dev.ukbase) {
		dev_err(dev, "no mmio space(ukbase)\n");
		return -EINVAL;
	}

	//Get port number from device tree
	ahci_dev.port_num = of_get_child_count(dev->of_node);
	if(!ahci_dev.port_num)
		ahci_dev.port_num = 1;
	else if(ahci_dev.port_num > MAX_PORT)
		ahci_dev.port_num = MAX_PORT;

#if defined(SATA_SUPPORT_LED_CONTROL)
	for(i=0; i<ahci_dev.port_num; i++) {
		gpio = of_get_gpio(dev->of_node, i);
		if(gpio<0) {
			dev_err(dev, "can't find gpio to enable sata power\n");
			return -EINVAL;
		}
		gpio_request(gpio, dev->of_node->name);
		gpio_set_value(gpio, 1);
		gpio_free(gpio);
	}

	blink_gpio_0 = of_get_named_gpio_flags(dev->of_node, "blink-gpios", 0, NULL);
	if (gpio_is_valid(blink_gpio_0))
		gpio_request(blink_gpio_0, "blink-gpios(0)");

	blink_gpio_1 = of_get_named_gpio_flags(dev->of_node, "blink-gpios", 1, NULL);
	if (gpio_is_valid(blink_gpio_1))
		gpio_request(blink_gpio_1, "blink-gpios(1)");

	{
		hdd_detect_gpio_0 = of_get_named_gpio_flags(dev->of_node, "hdd-detect-gpios", 0, NULL);
		if (gpio_is_valid(hdd_detect_gpio_0)) {
			gpio_request(hdd_detect_gpio_0, "hdd-detect-gpio(0)");
			gpio_direction_input(hdd_detect_gpio_0);
			irq_number_0 = gpio_to_irq(hdd_detect_gpio_0);
			if (!irq_number_0)
				printk(KERN_ERR "Get irq number fail\n");

			irq_set_irq_type(irq_number_0, IRQ_TYPE_EDGE_BOTH);
			if (request_irq(irq_number_0, hdd0_detect_function, IRQF_SHARED, "hdd0_detect", &ahci_dev))
				printk(KERN_ERR "Register IRQ(%d) fail\n", irq_number_0);
		}

		hdd_detect_gpio_1 = of_get_named_gpio_flags(dev->of_node, "hdd-detect-gpios", 1, NULL);
		if (gpio_is_valid(hdd_detect_gpio_1)) {
			gpio_request(hdd_detect_gpio_1, "hdd-detect-gpio(1)");
			gpio_direction_input(hdd_detect_gpio_1);

			irq_number_1 = gpio_to_irq(hdd_detect_gpio_1);
			if (!irq_number_1)
				printk(KERN_ERR "Get irq number fail\n");

			irq_set_irq_type(irq_number_1, IRQ_TYPE_EDGE_BOTH);
			if (request_irq(irq_number_1, hdd1_detect_function, IRQF_SHARED, "hdd1_detect", &ahci_dev))
				printk(KERN_ERR "Register IRQ(%d) fail\n", irq_number_1);
		}
	}
#endif

	//Get reset information
	for(i=0; i<ahci_dev.port_num; i++) {

		port_data = &ahci_dev.port[i];

		for(j=0; j<RESET_NUM; j++) {
			port_data->rstc[j] = rstc_get(rst_name[i][j]);
			if(!port_data->rstc[j]) {
				dev_err(dev, "can't not get reset\n");
				return -EINVAL;
			}
		}
		ahci_dev.port[i].port_reg = ahci_dev.base + i*0x80;
	}

#if defined(SATA_SUPPORT_LED_CONTROL)
	for(i=0; i<ahci_dev.port_num; i++) {
		ahci_dev.present_io[i] = of_get_gpio(dev->of_node, i+ahci_dev.port_num);
		if(ahci_dev.present_io[i]<0)
			continue;
		gpio_request(ahci_dev.present_io[i], dev->of_node->name);
		gpio_direction_input(ahci_dev.present_io[i]);
	}
#endif

	ahci_dev.spread_spectrum = 0;
	ahci_dev.rx_sensitivity = 0;
	ahci_dev.speed_limit = 0;
	ahci_dev.tx_driving = 3;

	of_property_read_u32(dev->of_node, "rx-sensitivity", &ahci_dev.rx_sensitivity);
	of_property_read_u32(dev->of_node, "spread-spectrum", &ahci_dev.spread_spectrum);
	of_property_read_u32(dev->of_node, "speed-limit", &ahci_dev.speed_limit);
	of_property_read_u32(dev->of_node, "tx-driving", &ahci_dev.tx_driving);

	hpriv = ahci_platform_get_resources(pdev);
	if (IS_ERR(hpriv))
		return PTR_ERR(hpriv);

	ahci_dev.hpriv = hpriv;
	ret = ahci_platform_enable_resources(hpriv);
	if (ret)
		return ret;

	for(i=0; i<ahci_dev.port_num; i++) {

		reset_control_assert(ahci_dev.port[i].rstc[0]);
		reset_control_assert(ahci_dev.port[i].rstc[1]);

		msleep(100);

		reset_control_deassert(ahci_dev.port[i].rstc[0]);
		reset_control_deassert(ahci_dev.port[i].rstc[1]);
	}

	for(i=0; i<ahci_dev.port_num; i++) {
		ahci_dev.port[i].phy_status = ahci_dev.rx_sensitivity;
		ahci_dev.port[i].speed = ahci_dev.speed_limit;
		config_sata_mac(i);
		config_sata_phy(i);
		reset_control_deassert(ahci_dev.port[i].rstc[2]);
		send_oob(i);
	}

	ahci_platform_init_host(pdev, hpriv, &ahci_port_info, &ahci_platform_sht);

	return 0;
}

static int rtk_ahci_remove(struct platform_device *pdev)
{
	int ret;

	printk("[SATA] enter %s\n", __FUNCTION__);

	ret = ata_platform_remove_one(pdev);
	if (ret)
		return ret;

#if defined(SATA_SUPPORT_LED_CONTROL)
	if (gpio_is_valid(blink_gpio_0))
		gpio_free(blink_gpio_0);

	if (gpio_is_valid(blink_gpio_1))
		gpio_free(blink_gpio_1);

	if (irq_number_0)
		free_irq(irq_number_0, &ahci_dev);

	if (irq_number_1)
		free_irq(irq_number_1, &ahci_dev);

	if (gpio_is_valid(hdd_detect_gpio_0))
		gpio_free(hdd_detect_gpio_0);

	if (gpio_is_valid(hdd_detect_gpio_1))
		gpio_free(hdd_detect_gpio_1);
#endif

	printk("[SATA] exit %s\n", __FUNCTION__);
	return 0;
}

#ifdef CONFIG_PM
static int rtk_ahci_suspend(struct device *dev)
{
	struct ata_host *host;
	struct ahci_host_priv *hpriv;
	int rc, i, j;

	printk("[SATA] enter %s\n", __FUNCTION__);

	host = dev_get_drvdata(dev);
	hpriv = host->private_data;

	rc = ahci_platform_suspend_host(dev);
	if (rc)
		return rc;
	if(RTK_PM_STATE == PM_SUSPEND_STANDBY) {
		ahci_platform_disable_clks(hpriv);
	} else {
		ahci_platform_disable_resources(hpriv);
		for(i=0; i<ahci_dev.port_num; i++)
			for(j=0; j<RESET_NUM; j++)
				reset_control_assert(ahci_dev.port[i].rstc[j]);
	}

	printk("[SATA] exit %s\n", __FUNCTION__);
	return 0;
}

static int rtk_ahci_resume(struct device *dev)
{
	struct ata_host *host;
	struct ahci_host_priv *hpriv;
	int rc, i;
#if defined(SATA_SUPPORT_LED_CONTROL)
	int gpio;
#endif

	printk("[ATA] enter %s\n", __FUNCTION__);

	host = dev_get_drvdata(dev);
	hpriv = host->private_data;

#if defined(SATA_SUPPORT_LED_CONTROL)
	for(i=0; i<ahci_dev.port_num; i++) {
		gpio = of_get_gpio(dev->of_node, i);
		gpio_request(gpio, dev->of_node->name);
		gpio_set_value(gpio, 1);
		gpio_free(gpio);
	}
#endif

	if(RTK_PM_STATE == PM_SUSPEND_STANDBY) {
		ahci_platform_enable_clks(hpriv);
	} else {
		rc = ahci_platform_enable_resources(hpriv);
		if (rc)
			return rc;

		for(i=0; i<ahci_dev.port_num; i++) {
			reset_control_deassert(ahci_dev.port[i].rstc[0]);
			reset_control_deassert(ahci_dev.port[i].rstc[1]);
		}

		for(i=0; i<ahci_dev.port_num; i++) {
			config_sata_mac(i);
			config_sata_phy(i);
			reset_control_deassert(ahci_dev.port[i].rstc[2]);
			send_oob(i);
		}
	}

	rc = ahci_platform_resume_host(dev);
	if (rc)
		goto disable_resources;

	/* We resumed so update PM runtime state */
	pm_runtime_disable(dev);
	pm_runtime_set_active(dev);
	pm_runtime_enable(dev);

	printk("[ATA] exit %s\n", __FUNCTION__);
	return 0;

disable_resources:
	ahci_platform_disable_resources(hpriv);

	return rc;
}
//static SIMPLE_DEV_PM_OPS(rtk_ahci_pm_ops, ahci_platform_suspend, ahci_platform_resume);
static SIMPLE_DEV_PM_OPS(rtk_ahci_pm_ops, rtk_ahci_suspend, rtk_ahci_resume);
#endif

static const struct of_device_id rtk_ahci_of_match[] = {
	{ .compatible = "Realtek,ahci-sata", },
	{},
};
MODULE_DEVICE_TABLE(of, rtk_ahci_of_match);

static struct platform_driver ahci_driver = {
	.probe = rtk_ahci_probe,
	.remove = rtk_ahci_remove,
	.driver = {
		.name = DRV_NAME_RTK,
		.of_match_table = rtk_ahci_of_match,
#ifdef CONFIG_PM
		.pm = &rtk_ahci_pm_ops,
#endif
	},
};
module_platform_driver(ahci_driver);

MODULE_DESCRIPTION("AHCI SATA platform driver");
MODULE_AUTHOR("Anton Vorontsov <avorontsov@ru.mvista.com>");
MODULE_LICENSE("GPL");
MODULE_ALIAS("platform:ahci");
