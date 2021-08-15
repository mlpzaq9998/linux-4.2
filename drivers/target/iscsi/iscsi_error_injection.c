/*******************************************************************************
 * This file contains a stress test features to the iSCSI Target Core Driver.
 *
 * (c) Copyright 2016 QNAP, Inc.
 *
 * Author: Jim Hsia <jim@qnap.com>
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
 ******************************************************************************/

#include <linux/init.h>
#include <linux/module.h>
#include <linux/slab.h>

#include <linux/configfs.h>

#include <linux/jiffies.h>

#include <linux/delay.h>
#include <linux/random.h>

#include "iscsi_error_injection.h"

struct config_group *g_iscsi_error_injection_group = NULL;
extern struct iscsi_error_injection_ops *iscsi_ej_ops;

struct iscsi_error_injection_item {
	struct config_item item;
	u64 lun;
	unsigned int enable;
	unsigned int delay_time;
	unsigned int tx_delay_time;
	unsigned int random_level;
	unsigned int cid;
	char target_name[224];
	char initiator_name[224];

	/* define for statistics */
	unsigned long random_distribution[ISCSI_ERROR_INJECTION_RANDOM_BOUNDARY];
	unsigned long total_random;
};

static inline struct config_item *to_item(struct list_head *entry)
{
	return container_of(entry, struct config_item, ci_entry);
}

static inline struct iscsi_error_injection_item *to_iscsi_error_injection_item(struct config_item *item)
{
	return item ? container_of(item, struct iscsi_error_injection_item, item) : NULL;
}

static void iscsi_error_injection_dump_parameters(struct iscsi_error_injection_item *ej_item)
{
	if (ej_item) {
		pr_info("[ISCSI_ERROR_INJECTION] === Dump Test Plan =============================\n");
		pr_info("[ISCSI_ERROR_INJECTION] Test Plan Name: %s\n", ej_item->item.ci_name);
		pr_info("[ISCSI_ERROR_INJECTION] Target Name: %s\n", ej_item->target_name);
		pr_info("[ISCSI_ERROR_INJECTION] Initiator Name: %s\n", ej_item->initiator_name);
		pr_info("[ISCSI_ERROR_INJECTION] Enable Settings: 0x%x\n", ej_item->enable);
		pr_info("[ISCSI_ERROR_INJECTION] Lun Settings: 0x%lx\n", ej_item->lun);
		pr_info("[ISCSI_ERROR_INJECTION] Cid Settings: 0x%x\n", ej_item->cid);
		pr_info("[ISCSI_ERROR_INJECTION] RX Delay Settings: %d\n", ej_item->delay_time);
		pr_info("[ISCSI_ERROR_INJECTION] TX Delay Settings: %d\n", ej_item->tx_delay_time);
		pr_info("[ISCSI_ERROR_INJECTION] Random Settings: %d\n", ej_item->random_level);
		pr_info("[ISCSI_ERROR_INJECTION] === End of Dump Test Plan =======================\n");
	} else
		pr_info("[ISCSI_ERROR_INJECTION] Null Item\n");
}

static void iscsi_error_injection_dump_random_distribution(struct iscsi_error_injection_item *ej_item)
{
	int i;
	if (ej_item) {
		pr_info("[ISCSI_ERROR_INJECTION] === Dump Random Distribution ========================\n");
		for (i = 0; i < ISCSI_ERROR_INJECTION_RANDOM_BOUNDARY; i++) {
			pr_info("[ISCSI_ERROR_INJECTION] %3u %10u\n", i, ej_item->random_distribution[i]);
		}
		pr_info("[ISCSI_ERROR_INJECTION] === End of Dump Random Distribution =================\n");
	} else
		pr_info("[ISCSI_ERROR_INJECTION] Null Item\n");
}

int iscsi_error_injection_exec_delay_process(char *target_name, char *initiator_name, int lun_num, int cid)
{
	struct list_head *entry;
	int ret = 0;
	unsigned long j1, j2, diff;

	if (!g_iscsi_error_injection_group)
		return ret;

	j1 = jiffies;
	list_for_each(entry, &g_iscsi_error_injection_group->cg_children) {
		struct config_item *item = to_item(entry);

		if (config_item_name(item)) {
			struct iscsi_error_injection_item *ej_item = to_iscsi_error_injection_item(item);
			if (ISCSI_ERROR_INJECTION_DELAY_PROCESS_ENABLE(ej_item->enable)
			  && ISCSI_ERROR_INJECTION_CHECK_LUN_SETTING(ej_item->lun, lun_num)
			  && ISCSI_ERROR_INJECTION_CHECK_CID_SETTING(ej_item->cid, cid-1)
			  && !strcmp(ej_item->target_name, target_name)
			  && !strcmp(ej_item->initiator_name, initiator_name)) {
				  msleep(ej_item->delay_time);
				  j2 = jiffies;
				  diff = (j2-j1);
				  pr_debug("[ISCSI_ERROR_INJECTION] %s: lapsed time: %ld ms, cid: %d, lun: %d\n", __func__, diff, cid, lun_num);
				  ret = 1;
				  break;
			}
		}
	}
	return ret;
}
EXPORT_SYMBOL(iscsi_error_injection_exec_delay_process);

int iscsi_error_injection_exec_tx_delay_process(char *target_name, char *initiator_name, int lun_num, int cid)
{
	struct list_head *entry;
	int ret = 0;
	unsigned long j1, j2, diff;

	if (!g_iscsi_error_injection_group)
		return ret;

	j1 = jiffies;
	list_for_each(entry, &g_iscsi_error_injection_group->cg_children) {
		struct config_item *item = to_item(entry);

		if (config_item_name(item)) {
			struct iscsi_error_injection_item *ej_item = to_iscsi_error_injection_item(item);
			if (ISCSI_ERROR_INJECTION_TX_DELAY_PROCESS_ENABLE(ej_item->enable)
			  && ISCSI_ERROR_INJECTION_CHECK_LUN_SETTING(ej_item->lun, lun_num)
			  && ISCSI_ERROR_INJECTION_CHECK_CID_SETTING(ej_item->cid, cid-1)
			  && !strcmp(ej_item->target_name, target_name)
			  && !strcmp(ej_item->initiator_name, initiator_name)) {
				  msleep(ej_item->tx_delay_time);
				  j2 = jiffies;
				  diff = (j2-j1);
				  pr_debug("[ISCSI_ERROR_INJECTION] %s: lapsed time: %ld ms, cid: %d, lun: %d\n", __func__, diff, cid, lun_num);
				  ret = 1;
				  break;
			}
		}
	}
	return ret;
}
EXPORT_SYMBOL(iscsi_error_injection_exec_tx_delay_process);

int iscsi_error_injection_exec_random_drop(char *target_name, char *initiator_name, int lun_num, int cid)
{
	struct list_head *entry;
	int ret = 0;
	unsigned long num, random;
	unsigned long j1, j2, diff;

	if (!g_iscsi_error_injection_group)
		return ret;

	j1 = jiffies;
	list_for_each(entry, &g_iscsi_error_injection_group->cg_children) {
		struct config_item *item = to_item(entry);

		if (config_item_name(item)) {
			struct iscsi_error_injection_item *ej_item = to_iscsi_error_injection_item(item);
			if (ISCSI_ERROR_INJECTION_RANDOM_DROP_ENABLE(ej_item->enable)
			  && ISCSI_ERROR_INJECTION_CHECK_LUN_SETTING(ej_item->lun, lun_num)
			  && ISCSI_ERROR_INJECTION_CHECK_CID_SETTING(ej_item->cid, cid-1)
			  && !strcmp(ej_item->target_name, target_name)
			  && !strcmp(ej_item->initiator_name, initiator_name)) {

				  get_random_bytes(&num, sizeof(num));
				  random = num%ISCSI_ERROR_INJECTION_RANDOM_BOUNDARY;
				  //ej_item->total_random += 1;
				  ej_item->random_distribution[random] += 1;
				  if (random < ej_item->random_level) {
					  ret = 1;
					  j2 = jiffies;
					  diff = (j2-j1)*HZ;
					  pr_debug("[ISCSI_ERROR_INJECTION] %s: lapsed time: %ld, random value: %ld\n", __func__, diff, random);
					  break;
				  }
			} else {
				pr_debug("[ISCSI_ERROR_INJECTION] Target Name: %s\n", target_name);
				pr_debug("[ISCSI_ERROR_INJECTION] Initiator Name: %s\n", initiator_name);
				pr_debug("[ISCSI_ERROR_INJECTION] Lun: %d\n", lun_num);
				pr_debug("[ISCSI_ERROR_INJECTION] Cid: %d\n", cid-1);
			}
		}
	}
	return ret;
}
EXPORT_SYMBOL(iscsi_error_injection_exec_random_drop);

static struct configfs_attribute iscsi_error_injection_item_attr_enable= {
	.ca_owner = THIS_MODULE,
	.ca_name = "enable",
	.ca_mode = S_IRUGO | S_IWUSR,
};

static struct configfs_attribute iscsi_error_injection_item_attr_delay_time= {
	.ca_owner = THIS_MODULE,
	.ca_name = "delay_time",
	.ca_mode = S_IRUGO | S_IWUSR,
};

static struct configfs_attribute iscsi_error_injection_item_attr_tx_delay_time= {
	.ca_owner = THIS_MODULE,
	.ca_name = "tx_delay_time",
	.ca_mode = S_IRUGO | S_IWUSR,
};

static struct configfs_attribute iscsi_error_injection_item_attr_random_level= {
	.ca_owner = THIS_MODULE,
	.ca_name = "random_level",
	.ca_mode = S_IRUGO | S_IWUSR,
};

static struct configfs_attribute iscsi_error_injection_item_attr_lun= {
	.ca_owner = THIS_MODULE,
	.ca_name = "lun",
	.ca_mode = S_IRUGO | S_IWUSR,
};

static struct configfs_attribute iscsi_error_injection_item_attr_cid= {
	.ca_owner = THIS_MODULE,
	.ca_name = "cid",
	.ca_mode = S_IRUGO | S_IWUSR,
};

static struct configfs_attribute iscsi_error_injection_item_attr_target_name= {
	.ca_owner = THIS_MODULE,
	.ca_name = "target_name",
	.ca_mode = S_IRUGO | S_IWUSR,
};

static struct configfs_attribute iscsi_error_injection_item_attr_initiator_name= {
	.ca_owner = THIS_MODULE,
	.ca_name = "initiator_name",
	.ca_mode = S_IRUGO | S_IWUSR,
};

static struct configfs_attribute iscsi_error_injection_item_attr_random_distribution= {
	.ca_owner = THIS_MODULE,
	.ca_name = "random_distribution",
	.ca_mode = S_IRUGO,
};

static struct configfs_attribute iscsi_error_injection_item_attr_dump_settings= {
	.ca_owner = THIS_MODULE,
	.ca_name = "dump_settings",
	.ca_mode = S_IRUGO,
};

static struct configfs_attribute *iscsi_error_injection_item_attrs[] = {
	&iscsi_error_injection_item_attr_enable,
	&iscsi_error_injection_item_attr_delay_time,
	&iscsi_error_injection_item_attr_tx_delay_time,
	&iscsi_error_injection_item_attr_random_level,
	&iscsi_error_injection_item_attr_lun,
	&iscsi_error_injection_item_attr_cid,
	&iscsi_error_injection_item_attr_initiator_name,
	&iscsi_error_injection_item_attr_target_name,
	&iscsi_error_injection_item_attr_random_distribution,
	&iscsi_error_injection_item_attr_dump_settings,
	NULL,
};

static ssize_t iscsi_error_injection_item_attr_show(struct config_item *item,
				      struct configfs_attribute *attr,
				      char *page)
{
	ssize_t count;
	struct iscsi_error_injection_item *iscsi_error_injection_item = to_iscsi_error_injection_item(item);
	int i, j, average, max, min;

	if (!strcmp(attr->ca_name, "enable"))
		count = sprintf(page, "0x%x\n", iscsi_error_injection_item->enable);
	else if (!strcmp(attr->ca_name, "delay_time"))
		count = sprintf(page, "%u\n", iscsi_error_injection_item->delay_time);
	else if (!strcmp(attr->ca_name, "tx_delay_time"))
		count = sprintf(page, "%u\n", iscsi_error_injection_item->tx_delay_time);
	else if (!strcmp(attr->ca_name, "random_level"))
		count = sprintf(page, "%u\n", iscsi_error_injection_item->random_level);
	else if (!strcmp(attr->ca_name, "lun"))
		count = sprintf(page, "0x%llx\n", iscsi_error_injection_item->lun);
	else if (!strcmp(attr->ca_name, "cid"))
		count = sprintf(page, "0x%x\n", iscsi_error_injection_item->cid);
	else if (!strcmp(attr->ca_name, "target_name"))
		count = sprintf(page, "%s\n", iscsi_error_injection_item->target_name);
	else if (!strcmp(attr->ca_name, "initiator_name"))
		count = sprintf(page, "%s\n", iscsi_error_injection_item->initiator_name);
	else if (!strcmp(attr->ca_name, "dump_settings")) {
		iscsi_error_injection_dump_parameters(iscsi_error_injection_item);
		count = sprintf(page, "[ISCSI_ERROR_INJECTION] === Dump Test Plan =============================\n"
			"[ISCSI_ERROR_INJECTION] Test Plan Name: %s\n"
			"[ISCSI_ERROR_INJECTION] Target Name: %s\n"
			"[ISCSI_ERROR_INJECTION] Initiator Name: %s\n"
			"[ISCSI_ERROR_INJECTION] Enable Settings: 0x%x\n"
			"[ISCSI_ERROR_INJECTION] Lun Settings: 0x%lx\n"
			"[ISCSI_ERROR_INJECTION] Cid Settings: 0x%x\n"
			"[ISCSI_ERROR_INJECTION] RX Delay Settings: %d\n"
			"[ISCSI_ERROR_INJECTION] TX Delay Settings: %d\n"
			"[ISCSI_ERROR_INJECTION] Random Settings: %d\n"
			"[ISCSI_ERROR_INJECTION] === End of Dump Test Plan =======================\n", iscsi_error_injection_item->item.ci_name, iscsi_error_injection_item->target_name, iscsi_error_injection_item->initiator_name, iscsi_error_injection_item->enable, iscsi_error_injection_item->lun, iscsi_error_injection_item->cid, iscsi_error_injection_item->delay_time, iscsi_error_injection_item->tx_delay_time, iscsi_error_injection_item->random_level);
	} else if (!strcmp(attr->ca_name, "random_distribution")) {
		for (i = 0; i < ISCSI_ERROR_INJECTION_RANDOM_BOUNDARY; i++) {
			if (i == 0) {
				max = min = 0;
				iscsi_error_injection_item->total_random = 0;
			} else if (iscsi_error_injection_item->random_distribution[max] < iscsi_error_injection_item->random_distribution[i])
				max = i;
			else if (iscsi_error_injection_item->random_distribution[min] > iscsi_error_injection_item->random_distribution[i])
				min = i;

			iscsi_error_injection_item->total_random += iscsi_error_injection_item->random_distribution[i];
		}
		iscsi_error_injection_dump_random_distribution(iscsi_error_injection_item);
		count = sprintf(page, "[ISCSI_ERROR_INJECTION] === Dump Random Distribution =============================\n"
			"  MAX: %ld (%d)\n"
			"  MIN: %ld (%d)\n"
			"  DIFF: %ld \n"
			"  AVERAGE: %ld\n"
			"[ISCSI_ERROR_INJECTION] === End of Dump Random Distribution ======================\n",
			iscsi_error_injection_item->random_distribution[max], max,
			iscsi_error_injection_item->random_distribution[min], min,
			iscsi_error_injection_item->random_distribution[max]-iscsi_error_injection_item->random_distribution[min],
			iscsi_error_injection_item->total_random/ISCSI_ERROR_INJECTION_RANDOM_BOUNDARY);
	} else
		count = sprintf(page, "incorrect access\n");

	return count;
}

static ssize_t iscsi_error_injection_item_attr_store(struct config_item *item,
				       struct configfs_attribute *attr,
				       const char *page, size_t count)
{
	struct iscsi_error_injection_item *iscsi_error_injection_item = to_iscsi_error_injection_item(item);
	unsigned long tmp;
	char *p = (char *) page;
	int i = 0;

	if (!strcmp(attr->ca_name, "target_name")) {
		p[count-1] = '\0';
		strcpy(iscsi_error_injection_item->target_name, p);
	} else if (!strcmp(attr->ca_name, "initiator_name")) {
		p[count-1] = '\0';
		strcpy(iscsi_error_injection_item->initiator_name, p);
	} else {
		tmp = simple_strtoul(p, &p, 10);
		if (!p || (*p && (*p != '\n')))
			return -EINVAL;

		if (tmp > INT_MAX)
			return -ERANGE;

		if (!strcmp(attr->ca_name, "enable")) {
			if (ISCSI_ERROR_INJECTION_DELAY_PROCESS_ENABLE(iscsi_error_injection_item->enable)^ISCSI_ERROR_INJECTION_DELAY_PROCESS_ENABLE(tmp)) {
				if (ISCSI_ERROR_INJECTION_DELAY_PROCESS_ENABLE(tmp))
					pr_debug("[ISCSI_ERROR_INJECTION] %s: enable rx delay process\n", item->ci_name);
				else
					pr_debug("[ISCSI_ERROR_INJECTION] %s: disable rx delay process\n", item->ci_name);
			}

			if (ISCSI_ERROR_INJECTION_RANDOM_DROP_ENABLE(iscsi_error_injection_item->enable)^ISCSI_ERROR_INJECTION_RANDOM_DROP_ENABLE(tmp)) {
				for (i = 0; i < ISCSI_ERROR_INJECTION_RANDOM_BOUNDARY; i++) {
					iscsi_error_injection_item->random_distribution[i] = 0;
				}
				iscsi_error_injection_item->total_random = 0;
				if (ISCSI_ERROR_INJECTION_RANDOM_DROP_ENABLE(tmp))
					pr_debug("[ISCSI_ERROR_INJECTION] %s: enable random drop\n", item->ci_name);
				else
					pr_debug("[ISCSI_ERROR_INJECTION] %s: disable random drop\n", item->ci_name);
			}

			if (ISCSI_ERROR_INJECTION_TX_DELAY_PROCESS_ENABLE(iscsi_error_injection_item->enable)^ISCSI_ERROR_INJECTION_TX_DELAY_PROCESS_ENABLE(tmp)) {
				if (ISCSI_ERROR_INJECTION_TX_DELAY_PROCESS_ENABLE(tmp))
					pr_debug("[ISCSI_ERROR_INJECTION] %s: enable tx delay process\n", item->ci_name);
				else
					pr_debug("[ISCSI_ERROR_INJECTION] %s: disable tx delay process\n", item->ci_name);
			}

			iscsi_error_injection_item->enable = tmp;
		} else if (!strcmp(attr->ca_name, "delay_time"))
			iscsi_error_injection_item->delay_time = tmp;
		else if (!strcmp(attr->ca_name, "tx_delay_time"))
			iscsi_error_injection_item->tx_delay_time = tmp;
		else if (!strcmp(attr->ca_name, "random_level"))
			iscsi_error_injection_item->random_level = tmp;
		else if (!strcmp(attr->ca_name, "lun"))
			iscsi_error_injection_item->lun = tmp;
		else if (!strcmp(attr->ca_name, "cid"))
			iscsi_error_injection_item->cid = tmp;
		else
			pr_debug("[ISCSI_ERROR_INJECTION] incorrect access\n");
	}

	return count;
}

static void iscsi_error_injection_item_release(struct config_item *item)
{
	kfree(to_iscsi_error_injection_item(item));
}

static struct configfs_item_operations iscsi_error_injection_item_item_ops = {
	.release		= iscsi_error_injection_item_release,
	.show_attribute		= iscsi_error_injection_item_attr_show,
	.store_attribute	= iscsi_error_injection_item_attr_store,
};

static struct config_item_type iscsi_error_injection_item_type = {
	.ct_item_ops	= &iscsi_error_injection_item_item_ops,
	.ct_attrs	= iscsi_error_injection_item_attrs,
	.ct_owner	= THIS_MODULE,
};


struct iscsi_error_injection_group {
	struct config_group group;
	struct iscsi_error_injection_item item;
};

static inline struct iscsi_error_injection_group *to_iscsi_error_injection_group(struct config_item *item)
{
	return item ? container_of(to_config_group(item), struct iscsi_error_injection_group, group) : NULL;
}

static struct config_item *iscsi_error_injection_group_make_item(struct config_group *group, const char *name)
{
	struct iscsi_error_injection_item *iscsi_error_injection_item;

	iscsi_error_injection_item = kzalloc(sizeof(struct iscsi_error_injection_item), GFP_KERNEL);
	if (!iscsi_error_injection_item)
		return ERR_PTR(-ENOMEM);

	config_item_init_type_name(&iscsi_error_injection_item->item, name,
				   &iscsi_error_injection_item_type);

	iscsi_error_injection_item->enable = 0;
	iscsi_error_injection_item->delay_time = 0;
	iscsi_error_injection_item->tx_delay_time = 0;
	iscsi_error_injection_item->random_level = 0;
	iscsi_error_injection_item->lun = 0;
	iscsi_error_injection_item->cid = 0;
	memset(iscsi_error_injection_item->target_name, 0, 224);
	memset(iscsi_error_injection_item->initiator_name, 0, 224);

	iscsi_error_injection_item->total_random = 0;
	memset(iscsi_error_injection_item->random_distribution, 0, ISCSI_ERROR_INJECTION_RANDOM_BOUNDARY);

	return &iscsi_error_injection_item->item;
}

static void iscsi_error_injection_group_drop_item(
		struct config_group *group,
		struct config_item *item)
{
	config_item_put(item);
}

static struct configfs_attribute iscsi_error_injection_group_attr_description = {
	.ca_owner = THIS_MODULE,
	.ca_name = "readme",
	.ca_mode = S_IRUGO,
};

static struct configfs_attribute *iscsi_error_injection_group_attrs[] = {
	&iscsi_error_injection_group_attr_description,
	NULL,
};

static ssize_t iscsi_error_injection_group_attr_show(struct config_item *item,
					 struct configfs_attribute *attr,
					 char *page)
{
	if (g_iscsi_error_injection_group == NULL)
		return sprintf(page, "[ISCSI_ERROR_INJECTION] ISCSI_ERROR_INJECTION not init\n");

	return sprintf(page, "QNAP iSCSI TS Module\n"
						 "\n"
						 "This subsystem inject some test condition the test module for iSCSI tests\n");
}

static void iscsi_error_injection_group_release(struct config_item *item)
{
	kfree(to_iscsi_error_injection_group(item));
}

static struct configfs_item_operations iscsi_error_injection_group_item_ops = {
	.release	= iscsi_error_injection_group_release,
	.show_attribute	= iscsi_error_injection_group_attr_show,
};

static struct configfs_group_operations iscsi_error_injection_group_group_ops = {
	.make_item	= iscsi_error_injection_group_make_item,
	.drop_item	= iscsi_error_injection_group_drop_item,
};

static struct config_item_type iscsi_error_injection_group_type = {
	.ct_item_ops	= &iscsi_error_injection_group_item_ops,
	.ct_group_ops	= &iscsi_error_injection_group_group_ops,
	.ct_attrs	= iscsi_error_injection_group_attrs,
	.ct_owner	= THIS_MODULE,
};

static struct configfs_subsystem iscsi_error_injection_group_subsys = {
	.su_group = {
		.cg_item = {
			.ci_namebuf = "iscsi_err_injection",
			.ci_type = &iscsi_error_injection_group_type,
		},
	},
};

static int __init iscsi_error_injection_configfs_init(void)
{
	int ret;
	struct configfs_subsystem *subsys;

	subsys = &iscsi_error_injection_group_subsys;
	config_group_init(&subsys->su_group);

	mutex_init(&subsys->su_mutex);
	ret = configfs_register_subsystem(subsys);

	if (ret) {
		printk(KERN_ERR "Error %d on registering subsystem %s\n", ret, subsys->su_group.cg_item.ci_namebuf);
		goto fail_init;
	}

	g_iscsi_error_injection_group = &subsys->su_group;
	iscsi_ej_ops = kzalloc(sizeof(struct iscsi_error_injection_ops), GFP_KERNEL);
	if (iscsi_ej_ops) {
		iscsi_ej_ops->rx_delay_process = iscsi_error_injection_exec_delay_process;
		iscsi_ej_ops->tx_delay_process = iscsi_error_injection_exec_tx_delay_process;
		iscsi_ej_ops->random_drop = iscsi_error_injection_exec_random_drop;
	}
	return 0;

fail_init:
	configfs_unregister_subsystem(subsys);
	return ret;
}

static void __exit iscsi_error_injection_configfs_exit(void)
{
	struct list_head *entry, *tmp;

	if (iscsi_ej_ops) {
		kfree(iscsi_ej_ops);
		iscsi_ej_ops = NULL;
	}

	if (g_iscsi_error_injection_group) {
		list_for_each_safe(entry, tmp, &g_iscsi_error_injection_group->cg_children) {
			struct config_item *item = to_item(entry);
			config_item_put(item);
		}
	}
	mutex_destroy(&iscsi_error_injection_group_subsys.su_mutex);
	configfs_unregister_subsystem(&iscsi_error_injection_group_subsys);
}

MODULE_VERSION("0.9");
MODULE_AUTHOR("jimhsia@qnap.com");
MODULE_LICENSE("GPL");

module_init(iscsi_error_injection_configfs_init);
module_exit(iscsi_error_injection_configfs_exit);
