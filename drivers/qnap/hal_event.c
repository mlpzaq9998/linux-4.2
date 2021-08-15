#include <linux/kernel.h>
#include <linux/module.h>
#include <net/netlink.h>
#include <qnap/hal_event.h>

#define MAX_ENCLOSURE_ID 64
#define MAX_COUNT_IN_CONTAINER 192

#if defined(CONFIG_MACH_QNAPTS)
extern atomic_t max_wakeup_pds[MAX_ENCLOSURE_ID];
extern unsigned long nas_wakeup_interval;
extern int max_wakeup_pd_num;
static struct sock *hal_netlink;
DEFINE_SPINLOCK(hal_container_lock);
static LIST_HEAD(hal_container_head);

typedef struct __HAL_NETLINK_CB {
	struct list_head node;
	NETLINK_EVT event;
	struct work_struct netlink_work;
} HAL_NETLINK_CB;

static void add_to_hal_container(HAL_NETLINK_CB *netlink_cb)
{
	unsigned long irq_flags;
	HAL_NETLINK_CB *old_netlink_cb;
	struct list_head *tmp;
	int count = 0;

	spin_lock_irqsave(&hal_container_lock, irq_flags);

	list_for_each(tmp, &hal_container_head)
		count += 1;

	if (count >= MAX_COUNT_IN_CONTAINER) {
		old_netlink_cb = list_entry(hal_container_head.next,
					    HAL_NETLINK_CB, node);
		list_del(&old_netlink_cb->node);
		kfree(old_netlink_cb);
	}
	list_add_tail(&netlink_cb->node, &hal_container_head);
	spin_unlock_irqrestore(&hal_container_lock, irq_flags);
}

int set_max_wakeup_pds(int enc_id, int max_pds)
{
	if (enc_id < 0 || enc_id > (MAX_ENCLOSURE_ID - 1))
		return -1;
	atomic_set(&max_wakeup_pds[enc_id], max_pds);
    
	// Store the maximum max_wakeup_pds for the this unit
	if (enc_id == 0)
		max_wakeup_pd_num = max_pds;
	return 0;
}
EXPORT_SYMBOL(set_max_wakeup_pds);

int set_max_wakeup_interval(int enc_id, unsigned long wakeup_interval)
{
	if (enc_id < 0 || enc_id > (MAX_ENCLOSURE_ID - 1))
		return -1;
    
	// Default wakeup interval 6000 if the wakeup_interval sent was 0
	if (wakeup_interval == 0)
		nas_wakeup_interval = 6000;
	else
		nas_wakeup_interval = wakeup_interval;
	return 0;
}
EXPORT_SYMBOL(set_max_wakeup_interval);

int set_hal_netlink_sock(struct sock *new_netlink_socket)
{
	hal_netlink = new_netlink_socket;
	return 0;
}
EXPORT_SYMBOL(set_hal_netlink_sock);

struct sock *get_hal_netlink_sock(void)
{
	return hal_netlink;
}
EXPORT_SYMBOL(get_hal_netlink_sock);

static void hal_netlink_func(struct work_struct *work)
{
	HAL_NETLINK_CB *netlink_cb = NULL;

	netlink_cb = container_of(work, HAL_NETLINK_CB, netlink_work);
	if (hal_netlink != NULL) {
		struct sk_buff *skb;
		struct nlmsghdr *nlh;
		NETLINK_EVT *event;
		int size = sizeof(NETLINK_EVT) + 1;
		int len = NLMSG_SPACE(size);
		int ret;

		skb = alloc_skb(len, GFP_KERNEL);
		if (!skb) {
			pr_warn("%s:%d:skb = NULL\n", __func__, __LINE__);
		} else {
			nlh = NLMSG_PUT(skb, 0, 0, 0, size);
			nlh->nlmsg_flags = 0;
			event = (NETLINK_EVT *)NLMSG_DATA(nlh);
			memcpy(event, &netlink_cb->event, sizeof(NETLINK_EVT));
			ret = netlink_broadcast(hal_netlink, skb, 0, 5,
						GFP_KERNEL);
			if (ret < 0)
				add_to_hal_container(netlink_cb);
			else
				kfree(netlink_cb);
			return;
nlmsg_failure:
			if (skb)
				kfree_skb(skb);
		}
		kfree(netlink_cb);
	} else
		add_to_hal_container(netlink_cb);
}

void retrieve_hal_container(void)
{
	struct list_head *node, *tmp;
	HAL_NETLINK_CB *netlink_cb;
	unsigned long irq_flags;

	spin_lock_irqsave(&hal_container_lock, irq_flags);
	list_for_each_safe(node, tmp, &hal_container_head) {
		netlink_cb = list_entry(node, HAL_NETLINK_CB, node);
		INIT_WORK(&netlink_cb->netlink_work, hal_netlink_func);
		schedule_work(&netlink_cb->netlink_work);
		list_del(node);
	}
	spin_unlock_irqrestore(&hal_container_lock, irq_flags);
}
EXPORT_SYMBOL(retrieve_hal_container);


int send_hal_netlink(NETLINK_EVT *hal_event)
{
	HAL_NETLINK_CB *netlink_cb = NULL;

	netlink_cb = kmalloc(sizeof(HAL_NETLINK_CB), GFP_ATOMIC);

	if (netlink_cb == NULL) {
		pr_err("%s fail:memory allocate fail\n", __func__);
		return -1;
	}

	memcpy(&netlink_cb->event, hal_event, sizeof(NETLINK_EVT));
	INIT_WORK(&netlink_cb->netlink_work, hal_netlink_func);
	schedule_work(&netlink_cb->netlink_work);

	return 0;
}
EXPORT_SYMBOL(send_hal_netlink);
#endif

