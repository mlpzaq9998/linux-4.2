#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/io.h>
#include <linux/interrupt.h>
#include <linux/sched.h>
#include <linux/delay.h>
#include <linux/workqueue.h>
#include <linux/pci.h>
#include <linux/dmi.h>

struct lpc_wa_data {
	unsigned long base_addr;
	void (*enable)(void);
	void (*disable)(unsigned long);
	int check_dmi;
};

enum lpc_wa_devices {
	LPC_BRASWELL = 0,
	LPC_APOLLOLAKE,
	LPC_WA_LAST,
};

static struct timer_list timer_to_disable, timer_to_loop;
static u8 __iomem *base_addr = NULL;
static struct lpc_wa_data *workaround_data = NULL;
static spinlock_t wa_lock;

static void apl_wa_enable(void);
static void apl_wa_disable(unsigned long);
static void bsl_wa_enable(void);
static void bsl_wa_disable(unsigned long);

static int loop_duration = 5 * 1000;
module_param(loop_duration, int, S_IRUSR | S_IWUSR);

static int wa_duration = 1;
module_param(wa_duration, int, S_IRUSR | S_IWUSR);

static int dont_do_wa = 0;
module_param(dont_do_wa, int, S_IRUSR | S_IWUSR);

/*
 * cannot set private date to struct pci_dev,
 * that means we cannot get/set information
 * via sysfs, the only way to display statistics
 * is module parameters.
 */

static int wa_disabled_count = 0;
module_param(wa_disabled_count, int, S_IRUSR | S_IWUSR);


static struct lpc_wa_data wa_info[] = {
	[LPC_BRASWELL] = {
		.base_addr = 0xFED08000,
		.check_dmi = 0,
		.enable = bsl_wa_enable,
		.disable = bsl_wa_disable,
	},
	[LPC_APOLLOLAKE] = {
		.base_addr = 0xE00F8000 ,
		.check_dmi = 1,
		.enable = apl_wa_enable,
		.disable = apl_wa_disable,
	},
};

static const struct pci_device_id lpc_wa_ids [] = {
	{ PCI_VDEVICE(INTEL, 0x5AE8), LPC_APOLLOLAKE },
	{ PCI_VDEVICE(INTEL, 0x229C), LPC_BRASWELL },
	{ 0, },
};

static void loop_timer(unsigned long data)
{
	unsigned long flags;
	spin_lock_irqsave(&wa_lock, flags);

	if(!dont_do_wa) {
		workaround_data->enable();
		mod_timer(&timer_to_disable, jiffies + msecs_to_jiffies(wa_duration)) ;
	}
	mod_timer(&timer_to_loop, jiffies + msecs_to_jiffies(loop_duration)) ;
	spin_unlock_irqrestore(&wa_lock, flags);
}

static void workaround_disable(unsigned long data)
{
	unsigned long flags;
	spin_lock_irqsave(&wa_lock, flags);
	workaround_data->disable(data);
	wa_disabled_count++;
	spin_unlock_irqrestore(&wa_lock, flags);
}

void intel_lpc_workaround(void)
{
}

EXPORT_SYMBOL(intel_lpc_workaround);

static int __init lpc_serialirq_callback(const struct dmi_system_id *d)
{
	dont_do_wa = 1;
	return 0;
}

static struct dmi_system_id lpc_serialirq_dmi_table[] __initdata = {
	{
	.callback = lpc_serialirq_callback,
	.matches = {
		DMI_MATCH(DMI_BIOS_VERSION, "SJ01"),
		},
	},
	{
	.callback = lpc_serialirq_callback,
	.matches = {
		DMI_MATCH(DMI_BIOS_VERSION, "AR5"),
		},
	},
	{},
};

static void bsl_wa_enable(void)
{
	u8 val;
	// SCNT -- offset 10h
	val = readb(base_addr + 0x10);
	// MD: Mode: When set, the SERIRQ is in continuous mode.
	//           When cleared, SERIRQ is in quiet mode
	val |= (1 << 7);
	writeb(val, base_addr + 0x10);
}

static void bsl_wa_disable(unsigned long data)
{
	u8 val;
	val = readb(base_addr + 0x10);
	val &= ~(1 << 7);
	writeb(val, base_addr + 0x10);
}

static void apl_wa_enable(void)
{
	u8 val;
	val = readb(base_addr + 0xE0);
	val &= ~(1);
	writeb(val, base_addr + 0xE0);
	// Serial IRQ Control -- offset 64h
	val = readb(base_addr + 0x64);
	// MD: Mode: When set, the SERIRQ is in continuous mode.
	//           When cleared, SERIRQ is in quiet mode
	val |= (1 << 6);
	writeb(val, base_addr + 0x64);
}

static void apl_wa_disable(unsigned long data)
{
	u8 val;
	val = readb(base_addr + 0xE0);
	val |= 1;
	writeb(val, base_addr + 0xE0);
	val = readb(base_addr + 0x64);
	val &= ~(1 << 6);
	writeb(val, base_addr + 0x64);
}

static int lpc_wa_probe(struct pci_dev *dev,
		const struct pci_device_id *id)
{
	struct lpc_wa_data *w = &wa_info[id->driver_data];

	if (w->check_dmi == 1){
		dmi_check_system(lpc_serialirq_dmi_table);
	}

	base_addr = ioremap(w->base_addr, 0x100);

	if(!base_addr)
		return -1;

	setup_timer(&timer_to_disable, workaround_disable, 0);
	setup_timer(&timer_to_loop, loop_timer, 0);
	spin_lock_init(&wa_lock);
	workaround_data = w;

	mod_timer(&timer_to_loop, jiffies + msecs_to_jiffies(loop_duration)) ;

	return 0;
}

static void lpc_wa_remove(struct pci_dev *dev)
{
	del_timer_sync(&timer_to_loop);
	del_timer_sync(&timer_to_disable);
	if(base_addr) {
		iounmap(base_addr);
		base_addr = 0;
	}
	workaround_data = NULL;
}

static int __init lpc_wa_init(void)
{
	int idx;
	struct pci_dev *pdev;

	for(idx = 0, pdev = NULL; idx < LPC_WA_LAST; idx++) {

		pdev = pci_get_device(lpc_wa_ids[idx].vendor, lpc_wa_ids[idx].device, pdev);
		if(pdev != NULL) {
			return lpc_wa_probe(pdev, &lpc_wa_ids[idx]);
		}
	}

	return -1;
}

static void __exit lpc_wa_exit(void)
{
	int idx;
	struct pci_dev *pdev;

	for(idx = 0, pdev = NULL; idx < LPC_WA_LAST; idx++) {

		pdev = pci_get_device(lpc_wa_ids[idx].vendor, lpc_wa_ids[idx].device, pdev);
		if(pdev != NULL) {
			return lpc_wa_remove(pdev);
		}
	}
}

MODULE_LICENSE("GPL");
module_init(lpc_wa_init);
module_exit(lpc_wa_exit);
