#include <linux/gpio/consumer.h>
#include <linux/gpio/driver.h>

#include <linux/gpio.h>

#include "gpiolib.h"

#if defined(CONFIG_ARCH_ALPINE) && defined(CONFIG_MACH_QNAPTS)
#include <linux/delay.h>
#endif

void gpio_free(unsigned gpio)
{
	gpiod_free(gpio_to_desc(gpio));
}
EXPORT_SYMBOL_GPL(gpio_free);

/**
 * gpio_request_one - request a single GPIO with initial configuration
 * @gpio:	the GPIO number
 * @flags:	GPIO configuration as specified by GPIOF_*
 * @label:	a literal description string of this GPIO
 */
int gpio_request_one(unsigned gpio, unsigned long flags, const char *label)
{
	struct gpio_desc *desc;
	int err;

	desc = gpio_to_desc(gpio);

	/* Compatibility: assume unavailable "valid" GPIOs will appear later */
	if (!desc && gpio_is_valid(gpio))
		return -EPROBE_DEFER;

	err = gpiod_request(desc, label);
	if (err)
		return err;

	if (flags & GPIOF_OPEN_DRAIN)
		set_bit(FLAG_OPEN_DRAIN, &desc->flags);

	if (flags & GPIOF_OPEN_SOURCE)
		set_bit(FLAG_OPEN_SOURCE, &desc->flags);

	if (flags & GPIOF_ACTIVE_LOW)
		set_bit(FLAG_ACTIVE_LOW, &desc->flags);

	if (flags & GPIOF_DIR_IN)
		err = gpiod_direction_input(desc);
	else
		err = gpiod_direction_output_raw(desc,
				(flags & GPIOF_INIT_HIGH) ? 1 : 0);

	if (err)
		goto free_gpio;

	if (flags & GPIOF_EXPORT) {
		err = gpiod_export(desc, flags & GPIOF_EXPORT_CHANGEABLE);
		if (err)
			goto free_gpio;
	}

	return 0;

 free_gpio:
	gpiod_free(desc);
	return err;
}
EXPORT_SYMBOL_GPL(gpio_request_one);

int gpio_request(unsigned gpio, const char *label)
{
	struct gpio_desc *desc = gpio_to_desc(gpio);

	/* Compatibility: assume unavailable "valid" GPIOs will appear later */
	if (!desc && gpio_is_valid(gpio))
		return -EPROBE_DEFER;

	return gpiod_request(desc, label);
}
EXPORT_SYMBOL_GPL(gpio_request);

/**
 * gpio_request_array - request multiple GPIOs in a single call
 * @array:	array of the 'struct gpio'
 * @num:	how many GPIOs in the array
 */
int gpio_request_array(const struct gpio *array, size_t num)
{
	int i, err;

	for (i = 0; i < num; i++, array++) {
		err = gpio_request_one(array->gpio, array->flags, array->label);
		if (err)
			goto err_free;
	}
	return 0;

err_free:
	while (i--)
		gpio_free((--array)->gpio);
	return err;
}
EXPORT_SYMBOL_GPL(gpio_request_array);

/**
 * gpio_free_array - release multiple GPIOs in a single call
 * @array:	array of the 'struct gpio'
 * @num:	how many GPIOs in the array
 */
void gpio_free_array(const struct gpio *array, size_t num)
{
	while (num--)
		gpio_free((array++)->gpio);
}
EXPORT_SYMBOL_GPL(gpio_free_array);

#if defined(CONFIG_ARCH_ALPINE) && defined(CONFIG_MACH_QNAPTS)
#define AL_PCIE_RESET_GPIO_PIN      38
int al_nas_do_pcie_reset(void)
{
    int err;
    int val = 0;
    err = gpio_request(AL_PCIE_RESET_GPIO_PIN, "pcie reset gpio pin");
    if (err) {
        printk("Error: can't find pcie reset gpio pin %d\n", AL_PCIE_RESET_GPIO_PIN);
        return -1;
    }
    gpio_direction_output(AL_PCIE_RESET_GPIO_PIN, 1);
    gpio_set_value(AL_PCIE_RESET_GPIO_PIN, 0);
    val = gpio_get_value(AL_PCIE_RESET_GPIO_PIN);
    mdelay(5000);
    return 0;
}
EXPORT_SYMBOL_GPL(al_nas_do_pcie_reset);
#endif
