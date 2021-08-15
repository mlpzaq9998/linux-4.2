/*
 * Target core clustered api
 *
 * Copyright (C) 2015 Red Hat, Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 */
#include <linux/spinlock.h>
#include <linux/module.h>
#include <linux/list.h>

#include <target/target_core_base.h>
#include <target/target_core_cluster.h>

static LIST_HEAD(cluster_api_list);
static DEFINE_MUTEX(cluster_api_mutex);

int core_cluster_api_register(struct se_cluster_api *api)
{
	struct se_cluster_api *a;

	INIT_LIST_HEAD(&api->api_list);

	mutex_lock(&cluster_api_mutex);
	list_for_each_entry(a, &cluster_api_list, api_list) {
		if (!strcmp(a->name, api->name)) {
			pr_err("%p is already registered with duplicate name "
				"%s, unable to process request\n", a, a->name);
			mutex_unlock(&cluster_api_mutex);
			return -EEXIST;
		}
	}

	list_add_tail(&api->api_list, &cluster_api_list);
	mutex_unlock(&cluster_api_mutex);
	return 0;
}
EXPORT_SYMBOL(core_cluster_api_register);

void core_cluster_api_unregister(struct se_cluster_api *api)
{
        mutex_lock(&cluster_api_mutex);
        list_del(&api->api_list);
        mutex_unlock(&cluster_api_mutex);
}
EXPORT_SYMBOL(core_cluster_api_unregister);

int core_cluster_attach(struct se_device *dev, char *name)
{
	struct se_cluster_api *api;
	int ret = -EINVAL;

	mutex_lock(&cluster_api_mutex);
	list_for_each_entry(api, &cluster_api_list, api_list) {
		if (!strcmp(api->name, name)) {
			ret = api->attach_device(dev);
			if (!ret) {
				dev->dev_dr.cluster_api = api;
				if (!try_module_get(api->owner)) {
					api->detach_device(dev);
					ret = -EBUSY;
				}
			}
			break;
		}
	}
	mutex_unlock(&cluster_api_mutex);
	return ret;
}

void core_cluster_detach(struct se_device *dev)
{
	struct qnap_se_dev_dr *dr = &dev->dev_dr;

	mutex_lock(&cluster_api_mutex);
	if (dr->cluster_api) {
		dr->cluster_api->detach_device(dev);
		module_put(dr->cluster_api->owner);
		dr->cluster_api = NULL;
	}
	mutex_unlock(&cluster_api_mutex);
}
