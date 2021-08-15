#include "dm-tier-algo-sysfs.h"
#include "dm-tier-algo-utility.h"
#include <linux/device-mapper.h>
#include <linux/vmalloc.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/delay.h>

#define DM_MSG_PREFIX   "btier-algo"

#define COOL_DOWN_DEFAULT 86400
#define DEGRADE_RATIO_DEFAULT 50
#define COLLECT_TIME_DEFAULT 10
#define RESERVE_RATIO_DEFAULT 40

struct per_tier_stats {
	uint64_t total_reads;
	uint64_t total_writes;
	uint64_t average_reads;
	uint64_t average_writes;
};

struct per_block_stats {
	uint32_t index;
	uint64_t score;
	atomic_t readcount;
	atomic_t writecount;
	atomic_t lastused;
	struct rb_node rb_node;
};

struct btier {
	struct dm_tier_algo algo;

	atomic_t cool_down;
	atomic_t collect_time;
	atomic_t degrade_ratio;
	atomic_t reserve_ratio;

	dm_block_t block_num;
	struct per_tier_stats *tier_stats;
	struct per_block_stats *block_stats;
	struct rb_root sort_block_list;
};

static struct btier *to_btier_algo(struct dm_tier_algo *a)
{
	return container_of(a, struct btier, algo);
}

static ssize_t dm_attr_cool_down_show(struct dm_tier_algo *a, char *buf)
{
	struct btier *btier = to_btier_algo(a);

	sprintf(buf, "%d seconds\n", atomic_read(&btier->cool_down));

	return strlen(buf);
}

static ssize_t dm_attr_cool_down_store(struct dm_tier_algo *a, const char *buf, size_t count)
{
	int cool_down;
	struct btier *btier = to_btier_algo(a);

	if (kstrtouint(buf, 0, &cool_down))
		return -EINVAL;

	atomic_set(&btier->cool_down, cool_down);

	return count;
}

static ssize_t dm_attr_degrade_ratio_show(struct dm_tier_algo *a, char *buf)
{
	struct btier *btier = to_btier_algo(a);

	sprintf(buf, "%d percent\n", atomic_read(&btier->degrade_ratio));

	return strlen(buf);
}

static ssize_t dm_attr_degrade_ratio_store(struct dm_tier_algo *a, const char *buf, size_t count)
{
	int degrade_ratio;
	struct btier *btier = to_btier_algo(a);

	if (kstrtouint(buf, 0, &degrade_ratio))
		return -EINVAL;

	atomic_set(&btier->degrade_ratio, degrade_ratio);

	return count;
}

static ssize_t dm_attr_reserve_ratio_show(struct dm_tier_algo *a, char *buf)
{
	struct btier *btier = to_btier_algo(a);

	sprintf(buf, "%d percent\n", atomic_read(&btier->reserve_ratio));

	return strlen(buf);
}

static ssize_t dm_attr_reserve_ratio_store(struct dm_tier_algo *a, const char *buf, size_t count)
{
	int reserve_ratio;
	struct btier *btier = to_btier_algo(a);

	if (kstrtouint(buf, 0, &reserve_ratio))
		return -EINVAL;

	atomic_set(&btier->reserve_ratio, reserve_ratio);

	return count;
}

static ssize_t dm_attr_collect_time_show(struct dm_tier_algo *a, char *buf)
{
	struct btier *btier = to_btier_algo(a);

	sprintf(buf, "%d seconds\n", atomic_read(&btier->collect_time));

	return strlen(buf);
}

static ssize_t dm_attr_collect_time_store(struct dm_tier_algo *a, const char *buf, size_t count)
{
	int collect_time;
	struct btier *btier = to_btier_algo(a);

	if (kstrtouint(buf, 0, &collect_time))
		return -EINVAL;

	atomic_set(&btier->collect_time, collect_time);

	return count;
}

static void dm_btier_kobj_release(struct kobject *kobj)
{
	struct dm_tier_algo *a = container_of(kobj, struct dm_tier_algo, kobj);
	struct btier *btier = to_btier_algo(a);

	DMERR("%s: called", __func__);
	vfree(btier->block_stats);
	kfree(btier->tier_stats);
	kfree(btier);
	DMERR("%s: left", __func__);
}

static DM_ATTR_WR(cool_down);
static DM_ATTR_WR(degrade_ratio);
static DM_ATTR_WR(reserve_ratio);
static DM_ATTR_WR(collect_time);

static struct attribute *dm_attrs[] = {
	&dm_attr_cool_down.attr,
	&dm_attr_degrade_ratio.attr,
	&dm_attr_reserve_ratio.attr,
	&dm_attr_collect_time.attr,
	NULL,
};

static const struct sysfs_ops dm_sysfs_ops = {
	.show   = dm_attr_show,
	.store  = dm_attr_store,
};

static struct kobj_type dm_ktype = {
	.sysfs_ops      = &dm_sysfs_ops,
	.default_attrs  = dm_attrs,
	.release = dm_btier_kobj_release,
};

static void btier_clear(struct dm_tier_algo *a, dm_block_t b)
{
	struct btier *btier = to_btier_algo(a);

	atomic_set(&btier->block_stats[b].readcount, 0);
	atomic_set(&btier->block_stats[b].writecount, 0);
}

static void btier_degrade(struct dm_tier_algo *a, dm_block_t b)
{
	int readcount, writecount, degrade_ratio;
	struct btier *btier = to_btier_algo(a);

	degrade_ratio = atomic_read(&btier->degrade_ratio);
	readcount = atomic_read(&btier->block_stats[b].readcount)*degrade_ratio/ONE_HUNDRED;
	writecount = atomic_read(&btier->block_stats[b].writecount)*degrade_ratio/ONE_HUNDRED;

	atomic_set(&btier->block_stats[b].readcount, readcount);
	atomic_set(&btier->block_stats[b].writecount, writecount);
}

static void btier_update(struct dm_tier_algo *a, dm_block_t b, struct bio *bio)
{
	struct btier *btier = to_btier_algo(a);
	struct per_block_stats *stats = btier->block_stats;
	enum temperature temper;

	atomic_set(&btier->block_stats[b].lastused, (int)get_seconds());
	if (!bio)
		return;

	temper = get_temper(bio);
	if (bio_data_dir(bio) == READ)
		atomic_add(freq_regulate[temper], &stats[b].readcount);
	else if (bio_data_dir(bio) == WRITE)
		atomic_add(freq_regulate[temper], &stats[b].writecount);

	if (atomic_read(&stats[b].readcount) > MAX_STAT_COUNT)
		atomic_sub(MAX_STAT_DECAY, &stats[b].readcount);

	if (atomic_read(&stats[b].writecount) > MAX_STAT_COUNT)
		atomic_sub(MAX_STAT_DECAY, &stats[b].writecount);
}

static bool ifneed_migrate_down(struct btier *btier, struct analyze_data *data, dm_block_t block, uint32_t *tierid)
{
	uint64_t hitcount = 0;
	uint64_t avghitcount = 0;
	uint64_t hysteresis = 0;
	int collect_time = atomic_read(&btier->collect_time);
	time_t curseconds = get_seconds();
	int cool_down = atomic_read(&btier->cool_down);

	if (*tierid >= data->tier_num - 1)
		return false;

	if (ta_anchormap_get(data->anchormap, block) == ANCHOR_COLD)
		return find_next_tid(data, tierid) ? false : true;

	if (cool_down && (int)curseconds - atomic_read(&btier->block_stats[block].lastused) > cool_down)
		return find_next_tid(data, tierid) ? false : true;

	hitcount = atomic_read(&btier->block_stats[block].readcount) + atomic_read(&btier->block_stats[block].writecount);
	avghitcount = btier->tier_stats[*tierid].average_reads + btier->tier_stats[*tierid].average_writes;
	hysteresis = avghitcount;
	do_div(hysteresis, data->tier_num);

	if (hitcount < avghitcount - hysteresis &&
		(int)curseconds - atomic_read(&btier->block_stats[block].lastused) > collect_time)
		return find_next_tid(data, tierid) ? false : true;

	return false;

}

static bool ifneed_migrate_up(struct btier *btier, struct analyze_data *data, dm_block_t block, uint32_t *tierid)
{
	uint64_t hitcount = 0;
	uint64_t avghitcount = 0;
	uint64_t hysteresis = 0;
	uint64_t avghitcountprevtier = 0;
	int target_tierid;

	/*
	 * Top level tier cannot be migrated up again
	 */
	if (!*tierid)
		return false;

	if (ta_anchormap_get(data->anchormap, block) == ANCHOR_HOT)
		return find_prev_tid(data, tierid) ? false : true;	

	hitcount = atomic_read(&btier->block_stats[block].readcount) + atomic_read(&btier->block_stats[block].writecount);
	avghitcount = btier->tier_stats[*tierid].average_reads + btier->tier_stats[*tierid].average_writes;
	hysteresis = avghitcount;
	do_div(hysteresis, data->tier_num);

	if (hitcount > avghitcount + hysteresis) {
		for (target_tierid = *tierid - 1; target_tierid >= 0; target_tierid--) {
			if (!is_tier_disabled(data, (uint32_t)target_tierid))
				break;
		}

		if (target_tierid < 0) 
			return false;

		avghitcountprevtier = btier->tier_stats[target_tierid].average_reads + btier->tier_stats[target_tierid].average_writes;
		hysteresis = avghitcountprevtier;
		do_div(hysteresis, data->tier_num);

		if (hitcount > avghitcountprevtier - hysteresis) {
			*tierid = target_tierid;
			return true;
		}
	}

	return false;
}

#define btier_bs(node) rb_entry((node), struct per_block_stats, rb_node)

static void __btier_block_rb_add(struct btier *btier, struct per_block_stats *stats)
{
	struct rb_node **rbp, *parent = NULL;
	struct per_block_stats *bs;

	rbp = &btier->sort_block_list.rb_node;
	while (*rbp) {
		parent = *rbp;
		bs = btier_bs(parent);

		if (stats->score > bs->score)
			rbp = &(*rbp)->rb_left;
		else
			rbp = &(*rbp)->rb_right;
	}

	rb_link_node(&stats->rb_node, parent, rbp);
	rb_insert_color(&stats->rb_node, &btier->sort_block_list);
}

static struct per_block_stats *__extract_sorted_block(struct btier *btier)
{
	struct rb_node *node;
	struct per_block_stats *stats;

	if (RB_EMPTY_ROOT(&btier->sort_block_list))
		return NULL;

	node = rb_first(&btier->sort_block_list);
	stats = btier_bs(node);
	rb_erase(node, &btier->sort_block_list);

	return stats;
}

static void init_tier_stats(struct btier *btier)
{
	int i;

	for (i = 0; i < MAX_TIER_LEVEL; i++) {
		btier->tier_stats[i].total_reads = 0;
		btier->tier_stats[i].total_writes = 0;
		btier->tier_stats[i].average_reads = 0;
		btier->tier_stats[i].average_writes = 0;
	}
}

static uint64_t btier_score(struct btier *btier, struct per_block_stats *bstats, enum anchor anchor)
{
	int cool_down;
	time_t curseconds = get_seconds();

	if (anchor != ANCHOR_CLEAR)
		return anchor == ANCHOR_HOT ? MAX_STAT_COUNT : 0;

	cool_down = atomic_read(&btier->cool_down);

	if (cool_down &&
	    (int)curseconds - atomic_read(&bstats->lastused) > cool_down)
		return 0;

	return atomic_read(&bstats->readcount) + atomic_read(&bstats->writecount);
}

static void profile_fisrt_round(struct dm_tier_algo *a, struct analyze_data *data, struct profile *profile)
{
	dm_block_t index = 0;
	struct btier *btier = to_btier_algo(a);
	unsigned long size = data->total_block_num;

	for (index = 0; index < size; index++) {
		bool migrate = false;
		uint32_t old_tierid, new_tierid;

		index = ta_find_next_allocated(data->block_from, size, index);
		if (index >= size)
			break;

		old_tierid = new_tierid = ta_get_tierid(data->block_from, index);
		if (old_tierid != SSD_TIER_ID)
			migrate = ifneed_migrate_down(btier, data, index, &new_tierid) ||
				  ifneed_migrate_up(btier, data, index, &new_tierid);

		if (migrate) {
			inc_tier_profile(profile, old_tierid, 
				old_tierid < new_tierid ? INTEND_DN : INTEND_UP, 1);
		}

		ta_store_tierid(data->block_to, index, new_tierid);		
	}

}

static void profile_second_round(struct dm_tier_algo *a, struct analyze_data *data, struct profile *profile)
{
	dm_block_t index = 0;
	struct btier *btier = to_btier_algo(a);
	unsigned long size = data->total_block_num;

	for (index = 0; index < size; index++) {
		uint32_t old_tierid, new_tierid;

		index = ta_find_next_allocated(data->block_from, size, index);
		if (index >= size)
			break;

		old_tierid = ta_get_tierid(data->block_from, index);
		new_tierid = ta_get_tierid(data->block_to, index);

		if (old_tierid != new_tierid || old_tierid != SSD_TIER_ID)
			continue;

		if (!reach_reserve(profile, SSD_TIER_ID) && 
			ifneed_migrate_down(btier, data, index, &new_tierid)) {
			if (is_remain_profile(profile, new_tierid, INTEND_UP)) {
				dec_tier_profile(profile, new_tierid, INTEND_UP, 1);
				inc_tier_profile(profile, new_tierid, MIGR_UP, 1);
				inc_tier_profile(profile, old_tierid, MIGR_DN, 1);
				ta_store_tierid(data->block_to, index, new_tierid);
			} else if (is_remain_profile(profile, new_tierid, FREE_BLKS)) {
				dec_tier_profile(profile, new_tierid, FREE_BLKS, 1);
				inc_tier_profile(profile, old_tierid, FREE_BLKS, 1);
				inc_tier_profile(profile, old_tierid, MIGR_DN, 1);
				ta_store_tierid(data->block_to, index, new_tierid);
			}
		}
	}
}

static int dryrun_analysis(struct dm_tier_algo *a, struct analyze_data *data)
{
	dm_block_t index = 0;
	struct per_block_stats *bstats;
	struct scorer scorer_drun[MAX_TIER_LEVEL];
	struct btier *btier = to_btier_algo(a);
	dm_block_t mapped[MAX_TIER_LEVEL] = {0}, size = data->total_block_num;
	uint64_t total_access = 0, ssd_access = 0;

	if (!RB_EMPTY_ROOT(&btier->sort_block_list))
		DMERR("%s:%d, sort list not empty !!", __func__, __LINE__);

	for (index = 0; index < size; index++) {
		uint32_t tierid;

		index = ta_find_next_allocated(data->block_to, size, index);
		if (index >= size)
			break;

		bstats = &btier->block_stats[index];
		tierid = ta_get_tierid(data->block_to, (dm_block_t)index);

		mapped[tierid]++;
		__btier_block_rb_add(btier, bstats);

		total_access += atomic_read(&bstats->readcount) + 
			atomic_read(&bstats->writecount);

		if (tierid == SSD_TIER_ID)
			ssd_access += atomic_read(&bstats->readcount) + 
				atomic_read(&bstats->writecount);

		if (!is_dryrun(data))
			btier_degrade(a, index);		
	}

	ssd_access *= ONE_HUNDRED;
	if (total_access)
		do_div(ssd_access, total_access);
	else
		ssd_access = 0;

	scorer_init(scorer_drun, data->sco_pf_drun, mapped, ssd_access);
	while ((bstats = __extract_sorted_block(btier))) {
		//uint32_t old_tierid = ta_get_tierid(data->block_from, bstats->index);
		uint32_t new_tierid = ta_get_tierid(data->block_to, bstats->index);

		scorer_update(scorer_drun, new_tierid, bstats->score);

		/*
		 * In order to be compatible with Tier Anchor, cache-like
		 * Btier may create dummy tasks (same old and new tierid)
		 */

		 //FIXME: Biter not support clustering
		 /*	
		if (!score_entry_create_and_queue(&data->score_list, 
			bstats->index, old_tierid, new_tierid, bstats->score))
			DMERR("%s:%d, generate score entry for block %u failed !!", 
				__func__, __LINE__, bstats->index);
		else
			data->total_migrate_block += 1;
		*/
	}

	return 0;
}

static void arrange_stats(struct dm_tier_algo *a, struct analyze_data *data, struct profile *profile)
{
	struct btier *btier = to_btier_algo(a);
	unsigned int i;
	dm_block_t index = 0;
	dm_block_t mapped[MAX_TIER_LEVEL] = {0}, size = data->total_block_num;
	struct per_block_stats *bstats;
	struct scorer scorer_org[MAX_TIER_LEVEL];
	uint64_t total_access = 0, ssd_access = 0;

	init_tier_stats(btier);

	while (index < size) {
		uint32_t tierid;

		index = ta_find_next_allocated(data->block_from, size, index);
		if (index >= size)
			break;

		bstats = &btier->block_stats[index];
		bstats->index = index;
		bstats->score = 	btier_score(btier, bstats, ta_anchormap_get(data->anchormap, index));
		data->tscore += bstats->score;

		tierid = ta_get_tierid(data->block_from, (dm_block_t)index);
		btier->tier_stats[tierid].total_reads += atomic_read(&bstats->readcount);
		btier->tier_stats[tierid].total_writes += atomic_read(&bstats->writecount);

		index++;
		mapped[tierid]++;

		__btier_block_rb_add(btier, bstats);
	}

	for (i = 0; i < MAX_TIER_LEVEL; i++) {
		if (is_tier_disabled(data, i))
			continue;

		btier->tier_stats[i].average_reads = btier->tier_stats[i].total_reads;
		btier->tier_stats[i].average_writes = btier->tier_stats[i].total_writes;

		do_div(btier->tier_stats[i].average_reads, data->block_num[i]);
		do_div(btier->tier_stats[i].average_writes, data->block_num[i]);

		total_access += (btier->tier_stats[i].total_reads + btier->tier_stats[i].total_writes);
		if (i == SSD_TIER_ID)
			ssd_access = (btier->tier_stats[i].total_reads + btier->tier_stats[i].total_writes);
	}	

	ssd_access *= ONE_HUNDRED;
	if (total_access)
		do_div(ssd_access, total_access);
	else
		ssd_access = 0;

	set_profile_free(profile, mapped);
	scorer_init(scorer_org, data->sco_pf_org, mapped, ssd_access);

	while ((bstats = __extract_sorted_block(btier)))
		scorer_update(scorer_org, ta_get_tierid(data->block_from, bstats->index), bstats->score);	

}

static int btier_analyze(struct dm_tier_algo *a, struct analyze_data *data)
{
	struct profile *profile;
	struct btier *btier = to_btier_algo(a);
	int reserve_ratio = atomic_read(&btier->reserve_ratio);

	profile = create_profile(data, reserve_ratio);
	if (IS_ERR(profile)) {
		DMERR("No memory for profile !!");
		return PTR_ERR(profile);
	}

	arrange_stats(a, data, profile);
	/*
	 * Analyzing start
	 */
	data->total_migrate_block = 0;
	profile_fisrt_round(a, data, profile);
	simulate_profile(profile);
	profile_second_round(a, data, profile);
	regulate_block_to(data, profile);
	dryrun_analysis(a, data);
	destroy_profile(profile);

	return 0;
}

static int btier_resize(struct dm_tier_algo *a, dm_block_t new_block_num)
{
	struct btier *btier = to_btier_algo(a);
	struct per_block_stats *new_stats;

	if (btier->block_num == new_block_num)
		return 0;

	new_stats = vzalloc(new_block_num * sizeof(struct per_block_stats));

	if (btier->block_stats && btier->block_num)
		memcpy(new_stats, btier->block_stats, btier->block_num * sizeof(struct per_block_stats));

	vfree(btier->block_stats);
	btier->block_stats = new_stats;
	btier->block_num = new_block_num;

	return 0;
}

static void init_algo_functions(struct btier *btier)
{
	btier->algo.update = btier_update;
	btier->algo.clear = btier_clear;
	btier->algo.analyze = btier_analyze;
	btier->algo.resize = btier_resize;
}

static struct dm_tier_algo* btier_create(struct kobject *kobj)
{
	struct btier *btier;

	btier = kzalloc(sizeof(*btier), GFP_KERNEL);
	if (!btier) {
		DMERR("No memory for btier algorithm private data");
		return NULL;
	}

	init_algo_functions(btier);

	btier->tier_stats = kzalloc(sizeof(struct per_tier_stats) * MAX_TIER_LEVEL, GFP_KERNEL);
	if (!btier->tier_stats) {
		DMERR("No memory for btier per tier statistics");
		goto bad_tier_stats;
	}
	init_tier_stats(btier);

	btier->block_stats = NULL;
	btier->block_num = 0;

	atomic_set(&btier->cool_down, COOL_DOWN_DEFAULT);
	atomic_set(&btier->collect_time, COLLECT_TIME_DEFAULT);
	atomic_set(&btier->degrade_ratio, DEGRADE_RATIO_DEFAULT);
	atomic_set(&btier->reserve_ratio, RESERVE_RATIO_DEFAULT);
	btier->sort_block_list = RB_ROOT;

	if (kobject_init_and_add(&btier->algo.kobj, &dm_ktype,
	                         kobj, "%s", "btier"))
		goto bad_kobj;

	return &btier->algo;

bad_kobj:
	kfree(btier->tier_stats);
bad_tier_stats:
	kfree(btier);

	return NULL;
}

static struct dm_tier_algo_type btier_algo_type = {
	.name = "btier",
	.version = {1, 0, 0},
	.owner = THIS_MODULE,
	.create = btier_create
};

static int __init btier_algo_register(void)
{
	return dm_tier_algo_register(&btier_algo_type);
}

static void __exit btier_algo_unregister(void)
{
	dm_tier_algo_unregister(&btier_algo_type);
}

module_init(btier_algo_register);
module_exit(btier_algo_unregister);

MODULE_AUTHOR("Dennis Yang, Webber Huang");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("TIER BTIER ALGORITHM");
