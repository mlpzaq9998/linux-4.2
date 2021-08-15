#include <linux/i2c.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Allen, Su");
MODULE_DESCRIPTION("RTC RX8900 Support");

static struct i2c_board_info rx8900_i2c_info[] __initdata = {
	{
		I2C_BOARD_INFO("rx8900", 0x32),
		.irq = 13,
	},
};

struct i2c_client *i2c_result;

static int __init rx8900_i2c_init(void)
{
	struct i2c_client *adap;

	printk(KERN_INFO "rx8900-i2c: rx8900_i2c_init start.");
	adap = i2c_get_adapter(0);
	i2c_result = i2c_new_device(adap, &rx8900_i2c_info);
	if (i2c_result == NULL) {
		printk(KERN_ERR
			"rx8900-i2c: cannot register board I2C devices\n");
	}

	return 0;
}

static void __exit rx8900_i2c_cleanup(void)
{
	i2c_unregister_device(i2c_result);
	printk(KERN_INFO "rx8900-i2c: rx8900_i2c_cleanup.\n");
}

late_initcall(rx8900_i2c_init);
