#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/platform_device.h>

#if defined(CONFIG_SERIAL_SOFTUART_MVEBU_A3700)
static struct platform_device qnap_device_softuart = {
	.name		= "qnap-3700-softuart",
	.id		= -1,
};

void __init qnap_add_device_softuart(void)
{
	platform_device_register(&qnap_device_softuart);
};
#else
void __init qnap_add_device_softuart(void)
{
	return;
};
#endif
