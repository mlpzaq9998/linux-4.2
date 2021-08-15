#include "dm-tier-algo-sysfs.h"
#include "dm-tier-algo-utility.h"
#include <linux/device-mapper.h>
#include <linux/vmalloc.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/delay.h>

#define DM_MSG_PREFIX   "timeout-algo"

#define COOL_DOWN_DEFAULT 0

struct per_block_stats {
	atomic_t lastused;
};

struct timeout {
	struct dm_tier_algo algo;

	atomic_t cool_down;
	dm_block_t block_num;
	struct per_block_stats *block_stats;
};

static struct timeout *to_timeout_algo(struct dm_tier_algo *a)
{
	return container_of(a, struct timeout, algo);
}

static ssize_t dm_attr_cool_down_show(struct dm_tier_algo *a, char *buf)
{
	struct timeout *timeout = to_timeout_algo(a);

	sprintf(buf, "%d seconds\n", atomic_read(&timeout->cool_down));

	return strlen(buf);
}

static ssize_t dm_attr_cool_down_store(struct dm_tier_algo *a, const char *buf, size_t count)
{
	int cool_down;
	struct timeout *timeout = to_timeout_algo(a);

	if (kstrtouint(buf, 0, &cool_down))
		return -EINVAL;

	atomic_set(&timeout->cool_down, cool_down);

	return count;
}

static void dm_timeout_kobj_release(struct kobject *kobj)
{
	struct dm_tier_algo *a = container_of(kobj, struct dm_tier_algo, kobj);
	struct timeout *timeout = to_timeout_algo(a);

	vfree(timeout->block_stats);
	kfree(timeout);
}

static DM_ATTR_WR(cool_down);

static struct attribute *dm_attrs[] = {
	&dm_attr_cool_down.attr,
	NULL,
};

static const struct sysfs_ops dm_sysfs_ops = {
	.show   = dm_attr_show,
	.store  = dm_attr_store,
};

static struct kobj_type dm_ktype = {
	.sysfs_ops      = &dm_sysfs_ops,
	.default_attrs  = dm_attrs,
	.release = dm_timeout_kobj_release,
};

static void timeout_update(struct dm_tier_algo *a, dm_block_t b, struct bio *bio)
{
	struct timeout *timeout = to_timeout_algo(a);

	atomic_set(&timeout->block_stats[b].lastused, (int)get_seconds());
}

static void timeout_clear(struct dm_tier_algo *a, dm_block_t b)
{
	return;
}

static bool ifneed_migrate_down(struct timeout *timeout, 
	struct analyze_data *data, dm_block_t block, uint32_t *tierid)
{
	int cool_down;
	time_t curseconds = get_seconds();

	if (*tierid >= data->tier_num - 1)
		return false;

	cool_down = atomic_read(&timeout->cool_down);
	if ((int)curseconds - atomic_read(&timeout->block_stats[block].lastused) >= cool_down)
		return find_next_tid(data, tierid) ? false : true;

	return false;
}

static uint64_t timeout_score(struct per_block_stats *bstats)
{
	time_t curseconds = get_seconds();

	return (int)curseconds - atomic_read(&bstats->lastused);
}

static void arrange_stats(struct timeout *timeout, struct analyze_data *data)
{
	dm_block_t b = 0, size = data->total_block_num;
	struct per_block_stats *stats;
	struct per_block_info *info;
	uint32_t tid;
	uint64_t score, max = 0, min = UINT_MAX;
	unsigned long *map = data->block_from;

	for (b = 0; b < size; b++) {
		b = ta_find_next_allocated(map, size, b);
		if (b >= size)
			break;

		tid = ta_get_tierid(map, b);
		stats = &timeout->block_stats[b];
		info = &data->block_info[b];

		info->index = b;
		info->score = score = timeout_score(stats);

		data->tscore += score;
		max = score > max ? score : max;
		min = score < min ? score : min;
	}
	update_cluster_set_attr(&data->set, max, min);
}

static void timeout_build_cluster_set(struct analyze_data *data)
{
	dm_block_t b = 0, size = data->total_block_num;
	struct per_block_info *info;
 
	for (b = 0; b < size; b++) {
		b = ta_find_next_allocated(data->block_from, size, b);
		if (b >= size)
			break;

		info = &data->block_info[b];
		__cluster_set_add(&data->set, info);
	}	
}

struct walking_callback {
	void *ctx1;
	void *ctx2;
	void (*fn)(void *ctx1, void *ctx2, struct per_block_info *info);
};

static void cluster_set_walker(void *context, struct per_block_info *info)
{
	struct walking_callback *wcb = (struct walking_callback *)context;

	wcb->fn(wcb->ctx1, wcb->ctx2, info);
}

static void timeout_cluster_set_walk(struct cluster_set *set, 
	void (*fn)(void *ctx1, void *ctx2, struct per_block_info *info),
	void *ctx1, void *ctx2)
{
	struct walking_callback wcb = {
		.fn = fn,
		.ctx1 = ctx1,
		.ctx2 = ctx2,
	};

	return __cluster_set_walk(set, cluster_set_walker, &wcb);
}

static void data_analysis_callback(void *ctx1, void *ctx2, struct per_block_info *info)
{
	struct dm_tier_algo *a = (struct dm_tier_algo *)ctx1;
	struct timeout *timeout = to_timeout_algo(a);
	struct analyze_data *data = (struct analyze_data *)ctx2;
	uint32_t src_tid, new_tid;

	new_tid = src_tid = ta_get_tierid(data->block_from, info->index);

	if (ifneed_migrate_down(timeout, data, info->index, &new_tid))
		ta_store_tierid(data->block_to, info->index, new_tid);
	else
		ta_store_tierid(data->block_to, info->index, src_tid);

	timeout_clear(a, info->index);
	data->total_migrate_block += 1;	
}

static void data_analysis(struct dm_tier_algo *a, struct analyze_data *data)
{
	struct timeout *timeout = to_timeout_algo(a);

	arrange_stats(timeout, data);
 	timeout_build_cluster_set(data);

	timeout_cluster_set_walk(&data->set, 
		data_analysis_callback, a, data);
	return;
}

static int timeout_analyze(struct dm_tier_algo *a, struct analyze_data *data)
{
	data->total_migrate_block = 0;
	data_analysis(a, data);

	return 0;
}

static int timeout_resize(struct dm_tier_algo *a, dm_block_t new_block_num)
{
	struct timeout *timeout = to_timeout_algo(a);
	struct per_block_stats *new_stats;

	if (timeout->block_num == new_block_num)
		return 0;

	new_stats = vzalloc(new_block_num * sizeof(struct per_block_stats));

	if (timeout->block_stats && timeout->block_num)
		memcpy(new_stats, timeout->block_stats, 
			timeout->block_num * sizeof(struct per_block_stats));

	vfree(timeout->block_stats);
	timeout->block_stats = new_stats;
	timeout->block_num = new_block_num;

	return 0;
}

static void init_algo_functions(struct timeout *timeout)
{
	timeout->algo.update = timeout_update;
	timeout->algo.clear = timeout_clear;
	timeout->algo.analyze = timeout_analyze;
	timeout->algo.resize = timeout_resize;
}

static struct dm_tier_algo* timeout_create(struct kobject *kobj)
{
	struct timeout *timeout;

	timeout = kzalloc(sizeof(*timeout), GFP_KERNEL);
	if (!timeout) {
		DMERR("No memory for timeout algorithm private data");
		return NULL;
	}

	init_algo_functions(timeout);
	timeout->block_stats = NULL;
	timeout->block_num = 0;

	atomic_set(&timeout->cool_down, COOL_DOWN_DEFAULT);

	if (kobject_init_and_add(&timeout->algo.kobj, &dm_ktype,
	                         kobj, "%s", "timeout"))
		goto bad_kobj;

	return &timeout->algo;

bad_kobj:
	kfree(timeout);

	return NULL;
}

static struct dm_tier_algo_type timeout_algo_type = {
	.name = "timeout",
	.version = {1, 0, 0},
	.owner = THIS_MODULE,
	.create = timeout_create
};

static int __init timeout_algo_register(void)
{
	return dm_tier_algo_register(&timeout_algo_type);
}

static void __exit timeout_algo_unregister(void)
{
	dm_tier_algo_unregister(&timeout_algo_type);
}

module_init(timeout_algo_register);
module_exit(timeout_algo_unregister);

MODULE_AUTHOR("Webber Huang");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("TIER TIMEOUT ALGORITHM");
MODULE_VERSION("1.0");
