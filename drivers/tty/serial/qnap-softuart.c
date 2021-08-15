#include <linux/io.h>
#include <linux/fs.h>
#include <linux/of.h>
#include <linux/irq.h>
#include <linux/clk.h>
#include <linux/err.h>
#include <linux/tty.h>
#include <linux/slab.h>
#include <linux/gpio.h>
#include <linux/init.h>
#include <linux/kmod.h>
#include <linux/sysfs.h>
#include <linux/sched.h>
#include <linux/delay.h>
#include <linux/timer.h>
#include <linux/mutex.h>
#include <linux/regmap.h>
#include <linux/bitops.h>
#include <linux/kernel.h>
#include <linux/device.h>
#include <linux/module.h>
#include <linux/ioport.h>
#include <linux/serial.h>
#include <linux/proc_fs.h>
#include <linux/version.h>
#include <linux/tty_flip.h>
#include <linux/of_device.h>
#include <linux/irqdomain.h>
#include <linux/interrupt.h>
#include <linux/workqueue.h>
#include <linux/miscdevice.h>
#include <linux/serial_core.h>
#include <linux/gpio/driver.h>
#include <linux/hwmon-sysfs.h>
#include <linux/gpio/consumer.h>
#include <linux/platform_device.h>
#include <linux/pinctrl/consumer.h>
#include <linux/irqchip/chained_irq.h>

#include <asm/io.h>
#include <asm/irq.h>
#include <asm/signal.h>
#include <asm/uaccess.h>

#define SOFTUART_VERSION        "0.0.1-t5"

//static int BAUDRATE = 4800;
//static int BAUDRATE = 9600;
//static int BAUDRATE = 19200;
static int BAUDRATE = 19200;

module_param(BAUDRATE, int, 0);
MODULE_PARM_DESC(BAUDRATE, " Baudrate value [default = 19200] (min=1200, max=19200)");

#define TX_BUFFER_SIZE  256
#define RX_BUFFER_SIZE  256

#define PFX "softuart: "

static struct hrtimer hrtimer_tx;
static struct hrtimer hrtimer_rx;

unsigned char TX_DATA = 0;
unsigned char RX_DATA = 0;
unsigned char TX_BUFFER[TX_BUFFER_SIZE+1];
unsigned char RX_BUFFER[RX_BUFFER_SIZE+1];

static int initialized;
unsigned int tx_len = 0;
unsigned int tx_len_totol = 0;
unsigned int rx_len = 0;

static struct proc_dir_entry *proc_softuart_root = NULL;
static uint g_mode = 0;
static struct gpio uart1_gpios[] = {
	{ 18, GPIOF_OUT_INIT_HIGH, "UART1 TX" },
//	{ 19, GPIOF_OUT_INIT_HIGH, "UART1 RX" },
	{ 19, GPIOF_IN, "UART1 RX" },
};

struct uart_port *softuart_global_port;
unsigned int softuart_rx_lock = 0;

struct softuart_uart_data {
	struct uart_port	port;
	struct device		*dev;
};

static DEFINE_MUTEX(softuart_lock);		   /* race on probe */

static char *mode_name[] =
{
	"NULL",
};

void setting_mode(uint cmd)
{
	unsigned int i, len;

	switch(cmd) {
	case 6:
		softuart_rx_lock = 1;
#if 0
		TX_BUFFER[0] = 0x50;
		tx_len_totol = strlen(TX_BUFFER);
#endif
#if 0
		TX_BUFFER[0] = 0xAA;
		TX_BUFFER[1] = 0x55;
		TX_BUFFER[2] = 0x5a;
		TX_BUFFER[3] = 0xa5;
#endif
#if 0
		TX_BUFFER[0] = 0x31;
		TX_BUFFER[1] = '2';
		TX_BUFFER[2] = 'C';
		TX_BUFFER[3] = '@';
#endif
#if 1
                TX_BUFFER[0] = '@';
                TX_BUFFER[1] = 'C';
                TX_BUFFER[2] = '2';
                TX_BUFFER[3] = 0x31;
		tx_len_totol = strlen(TX_BUFFER);
#endif
		hrtimer_start(&hrtimer_tx,  ktime_set(0, 0), HRTIMER_MODE_REL);
		break;
	case 7:
		len = strlen(RX_BUFFER);
		for(i=0;i<len;i++) {
			 printk("RX_BUFFER[%d] = 0x%x\n",i, RX_BUFFER[i]);
		}
		memset(RX_BUFFER, 0, RX_BUFFER_SIZE+1);
		rx_len = 0;
		softuart_rx_lock = 0;
		break;
	default:
		printk("SoftUart Control function error\n");
		break;
	}

	return;
};

static ssize_t gpio_read_proc(struct file *filp, char __user *buffer, size_t count, loff_t *offp)
{
	int len=0;

	printk("mode__name[%d] = %s\n", g_mode, mode_name[g_mode]);

	return len;
};

static ssize_t gpio_write_proc(struct file *filp, const char __user *buffer, size_t count, loff_t *offp)
{
	int len=count;
	unsigned char value[100];
	unsigned int tmp;

	if(copy_from_user(value, buffer, len)) {
		return 0;
	}
	value[len]='\0';

	sscanf(value,"%u\n", &tmp);
	//printk("tmp=%d\n", tmp);
	setting_mode(tmp);
	g_mode = tmp;

	return count;
};



static const struct file_operations softuart_proc_fileops = {
	.owner			= THIS_MODULE,
	.read			= gpio_read_proc,
	.write			= gpio_write_proc
};

static void GPIOOutputValueSet(int gpio, bool value)
{
	if (value)
		gpio_set_value(gpio, 1);
	else
		gpio_set_value(gpio, 0);
};

static unsigned char GPIOInputValueGet(int gpio)
{
	unsigned tmp = 0;

	tmp = gpio_get_value(gpio);
	if(tmp)
		return 1;
	else
		return 0;
};

static enum hrtimer_restart FunctionTimerTX(struct hrtimer *unused)
{
	static int bit=-1;

	// Data ready to send
	if(tx_len < tx_len_totol) {
		// Start bit
		if(bit == -1) {
			GPIOOutputValueSet(uart1_gpios[0].gpio, (0 & bit++));
		// Data bits
		} else if(bit >= 0 && bit <= 7) {
			GPIOOutputValueSet(uart1_gpios[0].gpio, ((TX_BUFFER[tx_len] & (1 << bit)) >> bit));
			bit++;
		// Stop bit
		} else if(bit == 8) {
			GPIOOutputValueSet(uart1_gpios[0].gpio, 1);
			if(tx_len == tx_len_totol - 1) {
				TX_BUFFER[tx_len] = 0x00;
				tx_len=0;
				tx_len_totol = 0;
			} else {
				TX_BUFFER[tx_len] = 0x00;
				tx_len++;
			}
			bit = -1;
		}
	}

	hrtimer_forward_now(&hrtimer_tx, ktime_set(0, (1000000/BAUDRATE)*1000));

	return HRTIMER_RESTART;
};

static enum hrtimer_restart FunctionTimerRX(struct hrtimer *unused)
{
	static int bit = -1;
	struct tty_port *tport = &softuart_global_port->state->port;

	// Start bit received
	if(GPIOInputValueGet(uart1_gpios[1].gpio) == 0 && bit == -1) {
		bit++;
	// Data bits
	} else if(bit >= 0 && bit < 8) {
		if(GPIOInputValueGet(uart1_gpios[1].gpio) == 0)
			RX_DATA &= 0b01111111;
		else
			RX_DATA |= ~0b01111111;

		if(bit!=7)
			RX_DATA >>= 1;
		bit++;
	// Stop bit
	} else if(bit == 8) {
		bit = -1;
		RX_BUFFER[rx_len] = RX_DATA;
		if(softuart_rx_lock == 0) {
			tty_insert_flip_char(tport, RX_BUFFER[rx_len], TTY_FRAME);
			tty_flip_buffer_push(tport);
			rx_len = 0;
		} else {
			rx_len++;
		}
	}

	hrtimer_forward_now(&hrtimer_rx, ktime_set(0, (1000000/BAUDRATE)*1000));

	return HRTIMER_RESTART;
};

/* Core UART Driver Operations */
static unsigned int softuart_uart_tx_empty(struct uart_port *port)
{
	return TIOCSER_TEMT;
};

static unsigned int softuart_uart_get_mctrl(struct uart_port *port)
{
	return 0;
};

static void softuart_uart_set_mctrl(struct uart_port *port, unsigned int mctrl)
{
	return;
};

static void softuart_uart_stop_tx(struct uart_port *port)
{
	return;
};

static void softuart_uart_start_tx(struct uart_port *port)
{
	unsigned int i = 0;

	if (uart_circ_empty(&port->state->xmit) || uart_tx_stopped(port))
		return;

	i = 0;
	tx_len = 0;
	tx_len_totol = 0;
	memset(TX_BUFFER,'\0',TX_BUFFER_SIZE+1);
	while(1) {
		if(uart_circ_empty(&port->state->xmit))
			break;

		//printk("data[%d] = 0x%x\n", port->state->xmit.tail, port->state->xmit.buf[port->state->xmit.tail]);
		TX_BUFFER[i++] = port->state->xmit.buf[port->state->xmit.tail];
		port->icount.tx++;
		port->state->xmit.tail = (port->state->xmit.tail + 1) & (UART_XMIT_SIZE - 1);
	}

	port->state->xmit.tail = 0;
	port->state->xmit.head = 0;
	memset(port->state->xmit.buf, 0x00, i);
	tx_len_totol = strlen(TX_BUFFER);
	hrtimer_start(&hrtimer_tx,  ktime_set(0, 0), HRTIMER_MODE_REL);

	if (uart_circ_chars_pending(&port->state->xmit) < WAKEUP_CHARS)
		uart_write_wakeup(port);

	uart_handle_sysrq_char(&port, 0xaa);

	return;
};

static void softuart_uart_stop_rx(struct uart_port *port)
{
	return;
};

static void softuart_uart_break_ctl(struct uart_port *port, int brk)
{
	return;
};

static int softuart_uart_startup(struct uart_port *port)
{
	// init TX/RX buffer
	tx_len = 0;
	tx_len_totol = 0;
	memset(TX_BUFFER,'\0',TX_BUFFER_SIZE+1);

	rx_len = 0;
	memset(RX_BUFFER,'\0',RX_BUFFER_SIZE+1);

	return 0;
};

static void softuart_uart_shutdown(struct uart_port *port)
{
	// init TX/RX buffer
	tx_len = 0;
	tx_len_totol = 0;
	memset(TX_BUFFER,'\0',TX_BUFFER_SIZE+1);

	rx_len = 0;
	softuart_rx_lock = 0;
	memset(RX_BUFFER,'\0',RX_BUFFER_SIZE+1);

	return;
};

static void softuart_uart_set_termios(struct uart_port *port,
				   struct ktermios *termios,
				   struct ktermios *old)
{
	int baud = 0;

	baud = tty_termios_baud_rate(termios);
	switch(baud) {
	case 1200:
		BAUDRATE = 1200;
		break;
	case 2400:
		BAUDRATE = 2400;
		break;
	case 4800:
		BAUDRATE = 4800;
		break;
	case 9600:
		BAUDRATE = 9600;
		break;
	case 19200:
	default:
		BAUDRATE = 19200;
		break;
	}

	/* The serial layer calls into this once with old = NULL when setting
	   up initially */
	if (old)
		tty_termios_copy_hw(termios, old);

	tty_termios_encode_baud_rate(termios, baud, baud);
	uart_update_timeout(port, termios->c_cflag, baud);

	return;
};

static const char *softuart_uart_type(struct uart_port *port)
{
	return "SOFTUART";
};

static void softuart_uart_release_port(struct uart_port *port)
{
	return;
};

static int softuart_uart_request_port(struct uart_port *port)
{
	return 0;
};

static const struct uart_ops softuart_uart_ops = {
	.tx_empty	= softuart_uart_tx_empty,
	.set_mctrl	= softuart_uart_set_mctrl,
	.get_mctrl	= softuart_uart_get_mctrl,
	.stop_tx	= softuart_uart_stop_tx,
	.start_tx	= softuart_uart_start_tx,
	.stop_rx	= softuart_uart_stop_rx,
	.break_ctl	= softuart_uart_break_ctl,
	.startup	= softuart_uart_startup,
	.shutdown	= softuart_uart_shutdown,
	.set_termios	= softuart_uart_set_termios,
	.type		= softuart_uart_type,
	.release_port	= softuart_uart_release_port,
	.request_port	= softuart_uart_request_port,
};
/* Core UART Driver Operations END */

static struct uart_driver softuart_uart_driver = {
	.owner          = THIS_MODULE,
	.driver_name    = "qnap_softuart",
	.dev_name       = "ttyQNAP",
	.major		= 0,
	.minor		= 0,
	.nr             = 1,
};

static ssize_t softuart_store(struct device *dev, struct device_attribute *attr, const char *sysfsbuf, size_t count)
{
	int hex_len, n;
	unsigned char cmd;

	sscanf(sysfsbuf, "%c\n", &cmd);
	switch(cmd) {
	case 'a':
	case 'A':
		softuart_rx_lock = 1;
		memset(TX_BUFFER,'\0',TX_BUFFER_SIZE+1);
		for(n=2;n<strlen(sysfsbuf)-1;n++)
		{
			TX_BUFFER[n-2] = sysfsbuf[n];
			if(strlen(TX_BUFFER) == TX_BUFFER_SIZE+1)
				memset(TX_BUFFER,'\0',TX_BUFFER_SIZE+1);
		}
		tx_len_totol = strlen(TX_BUFFER);
		hrtimer_start(&hrtimer_tx,  ktime_set(0, 0), HRTIMER_MODE_REL);
		break;
	case 'h':
	case 'H':
		softuart_rx_lock = 1;
		memset(TX_BUFFER,'\0',TX_BUFFER_SIZE+1);
		hex_len = 0;
		for(n=2;n<strlen(sysfsbuf)-1;n+=5)
		{
			TX_BUFFER[hex_len++] = simple_strtol(sysfsbuf+n, NULL, 16);
		}
		tx_len_totol = strlen(TX_BUFFER);
		hrtimer_start(&hrtimer_tx,  ktime_set(0, 0), HRTIMER_MODE_REL);
		break;
	default:
		return -EINVAL;
		break;
	}

	return count;
};

static ssize_t softuart_show(struct device *dev, struct device_attribute *attr, char *sysfsbuf)
{
	int len = 0, i;

	len = strlen(RX_BUFFER);
	for(i=0;i<len-1;i++) {
		printk("RX Buffer[%d] ASCII = %c, HEX = 0x%x\n", i, RX_BUFFER[i], RX_BUFFER[i]);
	}

	if(len>0)
		printk("RX Buffer[%d] Sum HEX = 0x%x\n", i, RX_BUFFER[len-1]);

	memset(RX_BUFFER,'\0',RX_BUFFER_SIZE+1);
	rx_len = 0;
	softuart_rx_lock = 0;

	return 0;
};

static DEVICE_ATTR(softuart_data, S_IRUGO | S_IWUSR, softuart_show, softuart_store);

static struct attribute *softuart_attributes[] = {
	&dev_attr_softuart_data.attr,
	NULL
};

static const struct attribute_group softuart_attribute_group = {
	.attrs = softuart_attributes
};

#define PFX "softuart: "
static int softuart_probe(struct platform_device *pdev)
{
	struct proc_dir_entry *mode;
	struct softuart_uart_data *data;
	int ret;

	if(initialized)
		return 0;

	initialized = 1;

	// init gpio array request
	ret = gpio_request_array(uart1_gpios, ARRAY_SIZE(uart1_gpios));
	if(ret < 0) {
		printk(KERN_ERR "%s: gpio_request failed for gpios\n", __func__);
		goto err;
	}

	// Set GPIO TX default Value
	gpio_set_value(uart1_gpios[0].gpio, 1);

	// register uart node
	ret = uart_register_driver(&softuart_uart_driver);
	if (ret < 0) {
		printk(KERN_ERR "Couldn't register softuart driver\n");
		goto err_gpio;
	}

	// alloc memory for uart node
	data = devm_kzalloc(&pdev->dev, sizeof(*data), GFP_KERNEL);
	if(!data) {
		printk(KERN_ERR "Couldn't alloc memory in driver\n");
		goto err_uart;
	}

	data->dev		= &pdev->dev;
	data->port.dev		= &pdev->dev;
	data->port.type		= PORT_SOFTUART;
	data->port.ops		= &softuart_uart_ops;
	data->port.regshift	= 0;
	data->port.fifosize	= 16;
	data->port.flags	= UPF_BOOT_AUTOCONF;
	data->port.line		= 0;
	data->port.membase	= NULL;
	data->port.irq		= 63;
	data->port.irqflags	= IRQF_SHARED;
	softuart_global_port	= &data->port;
	platform_set_drvdata(pdev, &data->port);

	// create uart note
	ret = uart_add_one_port(&softuart_uart_driver, &data->port);
	if(ret) {
		printk(KERN_ERR "uart_add_one_port failed for line, err=%i\n", ret);
		goto err_free_uart_alloc;
	}

	// hrtimer init TX timer
	hrtimer_init(&hrtimer_tx, CLOCK_REALTIME, HRTIMER_MODE_REL);
	hrtimer_tx.function = FunctionTimerTX;

	// hrtimer init RX timer and start RX timer
	hrtimer_init(&hrtimer_rx, CLOCK_REALTIME, HRTIMER_MODE_REL);
	hrtimer_rx.function = FunctionTimerRX;
	hrtimer_start(&hrtimer_rx,  ktime_set(0, 0), HRTIMER_MODE_REL);

	// init TX/RX buffer
	tx_len = 0;
	tx_len_totol = 0;
	memset(TX_BUFFER,'\0',TX_BUFFER_SIZE+1);

	rx_len = 0;
	memset(RX_BUFFER,'\0',RX_BUFFER_SIZE+1);

	// sysfs
	ret = sysfs_create_group(&pdev->dev.kobj, &softuart_attribute_group);
	if(ret < 0) {
		printk(KERN_ERR "Couldn't create softuart sysfs node\n");
		goto err_remove_uart_one;
	}

	// procfs
	proc_softuart_root = proc_mkdir("softuart", NULL);
	if(!proc_softuart_root) {
		printk(KERN_ERR "Couldn't create softuart folder in procfs\n");
		goto err_sysfs;
	}

	// create file of folder in procfs
	mode = proc_create("mode", S_IRUGO | S_IXUGO | S_IFREG, proc_softuart_root, &softuart_proc_fileops);
	if(!mode) {
		printk(KERN_ERR "Couldn't create softuart procfs node\n");
		goto err_procfs;
	}

	// Show Version
	printk(KERN_INFO "SOFTUART INFO [ver: %s] SOFTUART Baud Rate = %d, enable successfully!\n", SOFTUART_VERSION, BAUDRATE);
	printk(KERN_INFO "SOFTUART GPIO TX Number = %d, GPIO RX Number = %d\n", uart1_gpios[0].gpio, uart1_gpios[1].gpio);

	return 0;

err_procfs:
	remove_proc_entry("softuart", NULL);

err_sysfs:
	sysfs_remove_group(&pdev->dev.kobj, &softuart_attribute_group);

err_remove_uart_one:
	uart_remove_one_port(&softuart_uart_driver, &data->port);

err_free_uart_alloc:
	kfree(data);

err_uart:
	uart_unregister_driver(&softuart_uart_driver);

err_gpio:
	gpio_free_array(uart1_gpios, ARRAY_SIZE(uart1_gpios));

err:
	initialized = 0;
	printk(KERN_WARNING "applesmc: driver init failed !!\n");

	return 0;
};

static int softuart_remove(struct platform_device *pdev)
{
	struct softuart_uart_data *data = platform_get_drvdata(pdev);

	if(initialized == 0)
		return 0;

	hrtimer_cancel(&hrtimer_tx);
	hrtimer_cancel(&hrtimer_rx);

	gpio_free_array(uart1_gpios, ARRAY_SIZE(uart1_gpios));

	uart_remove_one_port(&softuart_uart_driver, &data->port);
	uart_unregister_driver(&softuart_uart_driver);

	sysfs_remove_group(&pdev->dev.kobj, &softuart_attribute_group);

	remove_proc_entry("mode", proc_softuart_root);
	remove_proc_entry("softuart", NULL);

	kfree(data);

	return 0;
};

static struct platform_driver softuart_plat_driver = {
	.driver = {
		.name		= "qnap-3700-softuart",
		.owner		= THIS_MODULE
	},
	.probe = softuart_probe,
	.remove = softuart_remove,
};

#define PFX "softuart: "
static int __init softuart_init_module(void)
{
	int rv;

	rv = platform_driver_register(&softuart_plat_driver);
	if(rv) {
		printk(KERN_ERR PFX "Unable to register "
			"driver: %d\n", rv);
		return rv;
	}

	return rv;
};

static void __exit softuart_cleanup_module(void)
{
	platform_driver_unregister(&softuart_plat_driver);

	return;
};

module_init(softuart_init_module);
module_exit(softuart_cleanup_module);

MODULE_AUTHOR("Yong-Yu Yeh <tomyeh@qnap.com>");
MODULE_DESCRIPTION("SOFTUART driver");
MODULE_LICENSE("GPL");
