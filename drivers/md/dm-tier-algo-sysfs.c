#include "dm-tier-algo-sysfs.h"

ssize_t dm_attr_show(struct kobject *kobj, struct attribute *attr,
                            char *page)
{
	struct dm_tier_algo *a = container_of(kobj, struct dm_tier_algo, kobj);
	struct dm_sysfs_attr *dm_attr;
	ssize_t ret;

	dm_attr = container_of(attr, struct dm_sysfs_attr, attr);
	if (!dm_attr->show)
		return -EIO;

	ret = dm_attr->show(a, page);

	return ret;
}

ssize_t dm_attr_store(struct kobject *kobj, struct attribute *attr,
                             const char *buf, size_t count)
{
	struct dm_sysfs_attr *dm_attr;
	struct dm_tier_algo *a = container_of(kobj, struct dm_tier_algo, kobj);
	ssize_t ret;

	dm_attr = container_of(attr, struct dm_sysfs_attr, attr);
	if (!dm_attr->show)
		return -EIO;

	ret = dm_attr->store(a, buf, count);

	return ret;
}
