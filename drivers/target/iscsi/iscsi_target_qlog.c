/**
 * $Header: /home/cvsroot/NasX86/Kernel/linux-3.12.6/drivers/target/iscsi/iscsi_target_log.c,v 1.2 2014/07/02 08:48:30 jschen Exp $
 *
 * Copyright (c) 2009, 2010 QNAP SYSTEMS, INC.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 * @brief	iscsi target connection log function for lio target kernel modules.
 * @author	Nike Chen
 * @date	2009/11/23
 *
 * $Id: iscsi_target_log.c,v 1.2 2014/07/02 08:48:30 jschen Exp $
 */

#include <linux/version.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <net/sock.h>
#include <net/netlink.h>
#include <linux/skbuff.h>
#include <linux/time.h>
#include <linux/netlink.h>
#include <target/iscsi/iscsi_target_core.h>
#include <qnap/netlink_extern.h>
#include "iscsi_target_qlog.h"

/**/
static int __qnap_nl_post_log_send(int conn_type, int log_type, 
	char *initiator_iqn, char *target_iqn, char *ip);

static int __qnap_nl_rt_conf_update (int conn_type, int log_type, 
	char *key, char *val);

static int s_pid = -1;
static struct sock *nls = NULL;

struct nl_func nl_func_call = {
	.nl_post_log_send		= __qnap_nl_post_log_send,
	.nl_rt_conf_update		= __qnap_nl_rt_conf_update,
};

static int __qnap_nl_rt_conf_update (
	int conn_type,
	int log_type,
	char *key,
	char *val
	)
{
	iscsi_conn_log *msg = NULL;
	int ret = -EPERM, size, skblen;
	struct sk_buff *skb = NULL;
	struct nlmsghdr *nlh = NULL;


	if (s_pid < 0 || !nls)
		return ret;

	if (!key || !val)
		return ret;

	if (conn_type != ISCSI_RT_CONF_UPDATE)
		return ret;

	if (!IS_RT_CONF_UPDATE_OP(log_type))
		return ret;

	size = sizeof(*msg);
	skblen = NLMSG_SPACE(size);
	skb = alloc_skb(skblen, GFP_KERNEL);

	if (!skb) {
		pr_err("%s: fail to allocate log buffer\n", __func__);
		return ret;
	}

	// fill up the buffer
	nlh = nlmsg_put(skb, s_pid, 0, 0, (size - sizeof(*nlh)), 0);
	if (!nlh) {
		printk("%s: fail to fill with the log buffer\n", __func__);
		kfree_skb(skb);
		return ret;
	}
		
	msg = (iscsi_conn_log*) NLMSG_DATA(nlh);
	msg->conn_type = conn_type;
	msg->log_type = log_type;

	memset(msg->u.rt_conf_update_data.key, 0, 
		sizeof(msg->u.rt_conf_update_data.key));

	memset(msg->u.rt_conf_update_data.val, 0, 
		sizeof(msg->u.rt_conf_update_data.val));

	strcpy(msg->u.rt_conf_update_data.key, key);
	strcpy(msg->u.rt_conf_update_data.val, val);

	ret = nlmsg_unicast(nls, skb, s_pid);

	return ret;
}

/* iscsi target log send function */
static int __qnap_nl_log_send_msg(
	int conn_type, 
	int log_type, 
	char *init_iqn, 
	char *target_iqn,
	char *ip
	)
{
	iscsi_conn_log* conn_logP = NULL;
	int ret = -1;
	struct sk_buff *skb = NULL;
	struct nlmsghdr *nlh = NULL;
	int size;
	int skblen;


	if (s_pid < 0 || !nls) {
		// printk("iscsi netlink is not ready, abort the log!!\n");
		return ret;
	}

	// allocate the log buffer
	size = sizeof(*conn_logP);
	skblen = NLMSG_SPACE(size);
	skb = alloc_skb(skblen, GFP_KERNEL);

	if (!skb) {
		printk("Fail to allocate log buffer, abort the log!!\n");
		return ret;
	}	
	
	// fill up the buffer
	nlh = nlmsg_put(skb, s_pid, 0, 0, (size - sizeof(*nlh)), 0);
	if (!nlh) {
		printk("Fail to fill with the log buffer, abort the log!!\n");
		kfree_skb(skb);
		return ret;
	}


	conn_logP = (iscsi_conn_log*) NLMSG_DATA(nlh);
	conn_logP->conn_type = conn_type;
	conn_logP->log_type = log_type;
	
	if (init_iqn)
		strcpy(conn_logP->u.post_log_data.init_iqn, init_iqn);
	if (ip)
		strcpy(conn_logP->u.post_log_data.init_ip, ip);
	if (target_iqn)
		strcpy(conn_logP->u.post_log_data.target_iqn, target_iqn);
		
	//ret = netlink_broadcast(nls, skb, 0, dst_groups, GFP_KERNEL);
	ret = nlmsg_unicast(nls, skb, s_pid);
	/*
	if (ret < 0)
		printk("Fail to send iscsi connection log (%s,%s,%s) size = %d, error code = 0x%x.\n", 
			init_iqn, ip, target_iqn, size, ret);
	else
		printk("Send iscsi connection log (%s,%s,%s) size = %d, successfully.\n",
			init_iqn, ip, target_iqn, size);
	*/

	// NOTE!! the allocated skb buffer should not deallocate explicitly, system will free
	// it in the appropriate time.
	// kfree_skb(skb);
	
	return ret;
}

/** iscsi target log receive function.
*/
static int __qnap_nl_log_rcv_msg(struct sk_buff *skb, struct nlmsghdr *nlh)
{
	// just need the pid right now

	s_pid = NETLINK_CB(skb).portid;

	printk("%s: get log pid = %d.\n", __func__, s_pid);
	return 0;
}

/** iscsi target log receive upper layer function.
*/
static void __qnap_nl_log_rcv(struct sk_buff *skb)
{
	netlink_rcv_skb(skb, &__qnap_nl_log_rcv_msg);
}

static int __qnap_nl_post_log_send(
	int conn_type,
	int log_type,
	char *initiator_iqn,
	char *target_iqn,
	char *ip
	)
{
	__qnap_nl_log_send_msg(conn_type, log_type, initiator_iqn, 
		target_iqn, ip);

	return 0;
}


/** iscsi target log subsystem initialize function.
*/
static int __qnap_nl_log_init(void)
{

	struct netlink_kernel_cfg cfg = {
		.input		= __qnap_nl_log_rcv,
		.groups 	= 0,
		.cb_mutex	= NULL,
	};

	nls = netlink_kernel_create(&init_net, NETLINK_ISCSI_TARGET, &cfg);

	if (!nls)
		printk("Fail to initiate iscsi target qlog!\n");
	else
		printk("Initiate iscsi target qlog successfully.\n");
	return 0;
}

/** iscsi target log subsystem cleanup function.
*/
static void __qnap_nl_log_cleanup(void)
{
	if (nls) {
		netlink_kernel_release(nls);
		printk("iscsi target qlog cleanup successfully.\n");
	}
}

void *qnap_nl_get_nl_func(void)
{
	return (void *)&nl_func_call;
}
EXPORT_SYMBOL(qnap_nl_get_nl_func);

int __init qnap_nl_init_module(void)
{
	/* initialize iscis netlink interface */
	__qnap_nl_log_init();
	return 0;
}

void __exit qnap_nl_cleanup_module(void)
{
	/* cleanup iscsi netlink interface */
	__qnap_nl_log_cleanup();
	return;
}



MODULE_DESCRIPTION("QNAP iSCSI Netlink Interface Module for target infrastructure");
MODULE_VERSION("1.0");
MODULE_AUTHOR("QNAP SYSTEMS, INC");
MODULE_LICENSE("GPL");

module_init(qnap_nl_init_module);
module_exit(qnap_nl_cleanup_module);


