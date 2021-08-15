#include <linux/init.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/string.h>

#include <plat/devs.h>

static int __init realtek_init(void)
{
	realtek_add_all_devices();
	return 0;
};
arch_initcall(realtek_init)
