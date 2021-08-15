#include <linux/init.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/string.h>

#include <plat/devs.h>

static int __init marvell_init(void)
{
	marvell_add_all_devices();
	return 0;
};
arch_initcall(marvell_init)
