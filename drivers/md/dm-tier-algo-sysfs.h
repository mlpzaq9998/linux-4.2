#ifndef DM_TIER_ALGO_SYSFS_H
#define DM_TIER_ALGO_SYSFS_H

#include "dm-tier-algo.h"
#include <linux/kobject.h>

struct dm_sysfs_attr {
	struct attribute attr;
	ssize_t (*show)(struct dm_tier_algo *, char *);
	ssize_t (*store)(struct dm_tier_algo *, const char *, size_t);
};

#define DM_ATTR_RO(_name) \
       struct dm_sysfs_attr dm_attr_##_name = \
       __ATTR(_name, S_IRUGO, dm_attr_##_name##_show, NULL)

#define DM_ATTR_WO(_name) \
       struct dm_sysfs_attr dm_attr_##_name = \
       __ATTR(_name, S_IWUSR, NULL, dm_attr_##_name##_store)

#define DM_ATTR_WR(_name) \
       struct dm_sysfs_attr dm_attr_##_name = \
       __ATTR(_name, S_IRUGO|S_IWUSR, dm_attr_##_name##_show, dm_attr_##_name##_store)

ssize_t dm_attr_show(struct kobject *kobj, struct attribute *attr,
                            char *page);
ssize_t dm_attr_store(struct kobject *kobj, struct attribute *attr,
                             const char *buf, size_t count);

#endif
