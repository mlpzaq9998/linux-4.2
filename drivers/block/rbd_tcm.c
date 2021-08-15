/*
 * rbd callouts for clustered target core support
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
#include <linux/module.h>
#include <linux/list.h>
#include <linux/blkdev.h>
#include <linux/workqueue.h>

#include <linux/delay.h>

#include <target/target_core_cluster.h>
#include <target/target_core_base.h>
#include <target/target_core_backend.h>
#include <target/target_core_fabric.h>
#include <target/target_core_backend.h>

#include "rbd.h"

struct rbd_tcm_device;
struct rbd_device;

struct rbd_tcm_reset_event {
	struct work_struct work;
	struct rbd_tcm_device *rbd_tcm_dev;
	u64 notify_id;
};

struct rbd_tcm_device {
	struct rbd_device *rbd_dev;
	struct se_device *se_dev;

	struct rbd_tcm_reset_event reset_evt;
};

static int rbd_tcm_start_reset(struct se_device *se_dev, u32 timeout)
{
	struct rbd_tcm_device *rbd_tcm_dev = se_dev->cluster_dev_data;
	int rc;

	if (!timeout)
		/* lio wants an infinite timeout */
		timeout = 300;
	rc = rbd_obj_notify_scsi_event_sync(rbd_tcm_dev->rbd_dev,
					    RBD_NOTIFY_OP_SCSI_LUN_RESET,
					    timeout);
	if (rc < 0)
		return -EIO;
	else
		return 0;
}

static void rbd_tcm_reset_event_workfn(struct work_struct *work)
{
	struct rbd_tcm_reset_event *evt = container_of(work,
					struct rbd_tcm_reset_event, work);
	struct rbd_tcm_device *rbd_tcm_dev = evt->rbd_tcm_dev;
	struct rbd_device *rbd_dev = rbd_tcm_dev->rbd_dev;
	int ret;

	/* currently always succeeds since it just waits */
	target_local_tmr_lun_reset(rbd_tcm_dev->se_dev, NULL, NULL, NULL);

	/* TODO - return a scsi error code in payload when needed */
	ret = rbd_obj_notify_ack_sync(rbd_dev, evt->notify_id);
	if (ret)
		rbd_warn(rbd_dev, "Could not ack reset completion. "
			 "Error %d",  ret);
}

void rbd_tcm_reset_notify_handle(void *data, u64 notify_id)
{
	struct rbd_tcm_device *rbd_tcm_dev = data;

	cancel_work_sync(&rbd_tcm_dev->reset_evt.work);
	rbd_tcm_dev->reset_evt.notify_id = notify_id;
	schedule_work(&rbd_tcm_dev->reset_evt.work);
}

static int rbd_tcm_detach_device(struct se_device *se_dev)
{
	struct request_queue *q = ibock_se_device_to_q(se_dev);
	struct rbd_tcm_device *rbd_tcm_dev = se_dev->cluster_dev_data;

	cancel_work_sync(&rbd_tcm_dev->reset_evt.work);
	se_dev->cluster_dev_data = NULL;
	rbd_detach_tcm_dev(q->queuedata);
	kfree(rbd_tcm_dev);
	return 0;
}

static int rbd_tcm_attach_device(struct se_device *se_dev)
{
	struct request_queue *q = ibock_se_device_to_q(se_dev);
	struct rbd_tcm_device *rbd_tcm_dev;

	rbd_tcm_dev = kzalloc(sizeof(*rbd_tcm_dev), GFP_KERNEL);
	if (!rbd_tcm_dev)
		return -ENOMEM;
	rbd_tcm_dev->rbd_dev = q->queuedata;
	rbd_tcm_dev->se_dev = se_dev;
	INIT_WORK(&rbd_tcm_dev->reset_evt.work, rbd_tcm_reset_event_workfn);
	rbd_tcm_dev->reset_evt.rbd_tcm_dev = rbd_tcm_dev;

	se_dev->cluster_dev_data = rbd_tcm_dev;
	return rbd_attach_tcm_dev(q->queuedata, rbd_tcm_dev);
}

static struct se_cluster_api rbd_tcm_template = {
	.name		= "rbd",
	.owner		= THIS_MODULE,
	.reset_device	= rbd_tcm_start_reset,
	.attach_device	= rbd_tcm_attach_device,
	.detach_device	= rbd_tcm_detach_device,
};

int rbd_tcm_register(void)
{
	return core_cluster_api_register(&rbd_tcm_template);
}

void rbd_tcm_unregister(void)
{
	core_cluster_api_unregister(&rbd_tcm_template);
}
