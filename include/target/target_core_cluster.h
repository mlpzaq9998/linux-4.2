#ifndef TARGET_CORE_CLUSTER_H
#define TARGET_CORE_CLUSTER_H

#include <linux/list.h>
#include <linux/module.h>
#include <linux/blkdev.h>

struct se_device;

struct se_cluster_api {
	char *name;
	struct module *owner;
	struct list_head api_list;

	int (*attach_device)(struct se_device *dev);
	int (*detach_device)(struct se_device *dev);
	/**
	 * reset_device - stop and cleanup running commands on all nodes.
	 * @dev: LU's request queue to execute reset for
	 * @timeout: timeout for reset operation
	 *
	 * Return 0 for success or -Exyz error code. If the operation
	 * takes longer than timeout seconds then -ETIMEDOUT should be returned.
	 */
	int (*reset_device)(struct se_device *dev, u32 timeout);
};

extern int core_cluster_api_register(struct se_cluster_api *);
extern void core_cluster_api_unregister(struct se_cluster_api *api);
extern int core_cluster_attach(struct se_device *dev, char *name);
extern void core_cluster_detach(struct se_device *dev);

#endif
