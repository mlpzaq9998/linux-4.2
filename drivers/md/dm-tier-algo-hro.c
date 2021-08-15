#include "dm-tier-algo-sysfs.h"
#include "dm-tier-algo-utility.h"
#include <linux/vmalloc.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/delay.h>
#include <linux/device-mapper.h>

#define DM_MSG_PREFIX "HRO-algo"

#define DEFAULT_RANDOM_THRESHOLD 4
#define DEFAULT_WEIGHT 25
#define DEGRADE_SHIFT 1

struct per_block_stats {
	atomic_t readcount;
	atomic_t writecount;
	atomic_t io_length;
	atomic_t remainder;
	atomic_t randomness;	
};

struct io_tracker {
	unsigned nr_seq_samples;
	sector_t last_end_sector;
	dm_block_t seq_start_block;
	dm_block_t seq_end_block;
	spinlock_t lock;
};

struct hro {
	struct dm_tier_algo algo;

	atomic_t weight;
	atomic_t random_threshold;

	struct io_tracker iot;
	unsigned long block_num;
	struct per_block_stats *block_stats;
};

static long get_random(struct per_block_stats *stats)
{
	return atomic_read(&stats->randomness);
}

static struct hro *to_hro_algo(struct dm_tier_algo *a)
{
	return container_of(a, struct hro, algo);
}

static ssize_t dm_attr_weight_percentage_show(struct dm_tier_algo *a, char *buf)
{
	struct hro *hro = to_hro_algo(a);

	sprintf(buf, "%d\n", atomic_read(&hro->weight));

	return strlen(buf);
}

static ssize_t dm_attr_weight_percentage_store(struct dm_tier_algo *a, const char *buf, size_t count)
{
	int weight;
	struct hro *hro = to_hro_algo(a);

	if (kstrtouint(buf, 0, &weight))
		return -EINVAL;

	atomic_set(&hro->weight, weight);

	return count;
}

static ssize_t dm_attr_random_threshold_show(struct dm_tier_algo *a, char *buf)
{
	struct hro *hro = to_hro_algo(a);

	sprintf(buf, "%d\n", atomic_read(&hro->random_threshold));

	return strlen(buf);
}


static ssize_t dm_attr_random_threshold_store(struct dm_tier_algo *a, const char *buf, size_t count)
{
	int random_threshold;
	struct hro *hro = to_hro_algo(a);

	if (kstrtouint(buf, 0, &random_threshold))
		return -EINVAL;

	atomic_set(&hro->random_threshold, random_threshold);

	return count;
}

static void dm_hro_kobj_release(struct kobject *kobj)
{
	struct dm_tier_algo *a = container_of(kobj, struct dm_tier_algo, kobj);
	struct hro *hro = to_hro_algo(a);

	vfree(hro->block_stats);
	kfree(hro);
}

static DM_ATTR_WR(weight_percentage);
static DM_ATTR_WR(random_threshold);

static struct attribute *dm_attrs[] = {
	&dm_attr_weight_percentage.attr,
	&dm_attr_random_threshold.attr,
	NULL,
};

static const struct sysfs_ops dm_sysfs_ops = {
	.show   = dm_attr_show,
	.store  = dm_attr_store,
};

static struct kobj_type dm_ktype = {
	.sysfs_ops      = &dm_sysfs_ops,
	.default_attrs  = dm_attrs,
	.release = dm_hro_kobj_release,
};

static void iot_reset(struct io_tracker *iot)
{
	iot->nr_seq_samples = 0;
	iot->last_end_sector = 0;
	iot->seq_start_block = 0;
	iot->seq_end_block = 0;
}

static void iot_examine_bio(struct hro *hro, dm_block_t b, struct bio *bio)
{
	unsigned long flags;
	struct io_tracker *iot = &hro->iot;
	struct per_block_stats *stats = hro->block_stats;

	spin_lock_irqsave(&iot->lock, flags);

	if (bio->bi_iter.bi_sector == iot->last_end_sector + 1)
		iot->nr_seq_samples++;
	else {
		dm_block_t i;
		unsigned len = iot->seq_end_block - iot->seq_start_block;

		for (i = iot->seq_start_block; i <= iot->seq_end_block; i++) {
			if (len < atomic_read(&hro->random_threshold)) {
				// Check if randomness overflow
				WARN_ON(get_random(&stats[i]) == INT_MAX);
				atomic_inc(&stats[i].randomness);
			} else {
				uint64_t freq, temp;

				freq = temp = atomic_read(&stats[i].readcount) +
				              atomic_read(&stats[i].writecount);
				temp *= atomic_read(&stats[i].io_length);
				temp += atomic_read(&stats[i].remainder) + len;

				atomic_set(&stats[i].remainder, do_div(temp, freq + 1));
				atomic_set(&stats[i].io_length, temp);
			}
		}

		iot_reset(iot);
		iot->seq_start_block = b;
	}

	iot->seq_end_block = b;
	iot->last_end_sector = bio_end_sector(bio) - 1;

	spin_unlock_irqrestore(&iot->lock, flags);
}

static void hro_clear(struct dm_tier_algo *a, dm_block_t b)
{
	struct hro *hro = to_hro_algo(a);

	atomic_set(&hro->block_stats[b].readcount, 0);
	atomic_set(&hro->block_stats[b].writecount, 0);
	atomic_set(&hro->block_stats[b].io_length, 0);
	atomic_set(&hro->block_stats[b].remainder, 0);
	atomic_set(&hro->block_stats[b].randomness, 0);
}

static void hro_degrade(struct dm_tier_algo *a, dm_block_t b)
{
	struct hro *hro = to_hro_algo(a);
	int readcount, writecount, randomness;

	readcount = atomic_read(&hro->block_stats[b].readcount);
	writecount = atomic_read(&hro->block_stats[b].writecount);
	randomness = atomic_read(&hro->block_stats[b].randomness);

	atomic_set(&hro->block_stats[b].readcount, readcount >> DEGRADE_SHIFT);
	atomic_set(&hro->block_stats[b].writecount, writecount >> DEGRADE_SHIFT);
	atomic_set(&hro->block_stats[b].randomness, randomness >> DEGRADE_SHIFT);
}


/*
 * we keep hitcounts the same only for recieving cold bio,
 * so if the block recieved cold bio is shared,
 * the block still can increase the hitcounts from normal bio
 */
static void hro_update(struct dm_tier_algo *a, dm_block_t b, struct bio *bio)
{
	struct hro *hro = to_hro_algo(a);
	struct per_block_stats *stats = hro->block_stats;
	enum temperature temper;

	if (!bio)
		return;

	iot_examine_bio(hro, b, bio);
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

static uint64_t hro_score(struct per_block_stats *stats, int weight, enum anchor anchor)
{
	uint64_t score, freq;

	if (anchor != ANCHOR_CLEAR)
		return anchor == ANCHOR_HOT ? MAX_STAT_COUNT : 0;	

	freq = atomic_read(&stats->readcount) +
	       atomic_read(&stats->writecount);

	score = freq * (get_random(stats) + 1);
	do_div(score, atomic_read(&stats->io_length) + 1);

	return (!score && freq ) ? 1 : score;
}

static void arrange_stats(struct hro *hro, struct analyze_data *data, 
	bool update, bool from, dm_block_t *mapped, 
	uint64_t *total_access, uint64_t *ssd_access)
{
	dm_block_t b = 0, size = data->total_block_num;
	struct per_block_stats *stats;
	struct per_block_info *info;
	uint32_t tid;
	uint64_t score, max = 0, min = UINT_MAX;
	unsigned long *map = from ? data->block_from : data->block_to;

	for (b = 0; b < size; b++) {
		b = ta_find_next_allocated(map, size, b);
		if (b >= size)
			break;

		tid = ta_get_tierid(map, b);
		stats = &hro->block_stats[b];
		info = &data->block_info[b];

		if (update) {
			info->index = b;
			info->score = score = hro_score(stats, atomic_read(&hro->weight),
				ta_anchormap_get(data->anchormap, b));

			data->tscore += score;
			max = score > max ? score : max;
			min = score < min ? score : min;
		}

		(*total_access) += atomic_read(&stats->readcount) +
			atomic_read(&stats->writecount);

		if (tid == SSD_TIER_ID)
			(*ssd_access) += atomic_read(&stats->readcount) + 
				atomic_read(&stats->writecount);
		mapped[tid]++;
	}

	if (update)
		update_cluster_set_attr(&data->set, max, min);
}

static void hro_build_cluster_set(struct analyze_data *data)
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
	void *ctx3;
	void (*fn)(void *ctx1, void *ctx2, void *ctx3, 
		struct per_block_info *info);
};

static void cluster_set_walker(void *context, struct per_block_info *info)
{
	struct walking_callback *wcb = (struct walking_callback *)context;

	wcb->fn(wcb->ctx1, wcb->ctx2, wcb->ctx3, info);
}

static void hro_cluster_set_walk(struct cluster_set *set, 
	void (*fn)(void *ctx1, void *ctx2, void *ctx3, 
		struct per_block_info *info),
	void *ctx1, void *ctx2, void *ctx3)
{
	struct walking_callback wcb = {
		.fn = fn,
		.ctx1 = ctx1,
		.ctx2 = ctx2,
		.ctx3 = ctx3
	};

	return __cluster_set_walk(set, cluster_set_walker, &wcb);
}

static void rawdata_analysis_callback(void *ctx1, void *ctx2, 
	void *ctx3, struct per_block_info *info)
{
	struct analyze_data *data = (struct analyze_data *)ctx1;
	struct scorer *scorer_org = (struct scorer *)ctx2;
	dm_block_t *block_num = (dm_block_t *)ctx3;
	uint32_t tid = 0, src_tid, bottom_tid;

	while (is_tier_disabled(data, tid) || !block_num[tid])
		BUG_ON(++tid >= MAX_TIER_LEVEL);

	if (!info->score) {
		if (find_bottom_tid(data, &bottom_tid)) {
			DMINFO("%s:%d, fail to get bottom tid !", __func__, __LINE__);
			return;
		}

		if (tid != bottom_tid && block_num[bottom_tid])
			tid = bottom_tid;
	}

	src_tid = ta_get_tierid(data->block_from, info->index);
	scorer_update(scorer_org, src_tid, info->score);
	ta_store_tierid(data->block_to, info->index, tid);
	DMDEBUG("%s:%d, tier(%u) put block(%u) !", __func__, __LINE__, tid, info->index);
	block_num[tid]--;
}

static void rawdata_analysis(struct dm_tier_algo *a, struct analyze_data *data)
{
	struct hro *hro = to_hro_algo(a);
	struct scorer scorer_org[MAX_TIER_LEVEL];
	dm_block_t mapped[MAX_TIER_LEVEL] = {0};
	dm_block_t block_num[MAX_TIER_LEVEL];
	uint64_t total_access = 0, ssd_access = 0;

	memcpy(block_num, data->block_num, sizeof(block_num));

	arrange_stats(hro, data, true, true, mapped, &total_access, &ssd_access);
	ssd_access *= ONE_HUNDRED;
 	if (total_access)
 		do_div(ssd_access, total_access);
 	else
 		ssd_access = 0;

 	scorer_init(scorer_org, data->sco_pf_org, mapped, ssd_access);
 	hro_build_cluster_set(data);

	hro_cluster_set_walk(&data->set, rawdata_analysis_callback, 
		data, scorer_org, block_num);
	return;
}	

static void dryrun_callback(void *ctx1, void *ctx2, 
	void *ctx3, struct per_block_info *info)
{
	struct dm_tier_algo *a = (struct dm_tier_algo *)ctx1;
	struct analyze_data *data = (struct analyze_data *)ctx2;
	struct scorer *scorer_drun = (struct scorer *)ctx3;
	uint32_t new_tierid;

	new_tierid = ta_get_tierid(data->block_to, info->index);
	scorer_update(scorer_drun, new_tierid, info->score);
	data->total_migrate_block += 1;	

	if (!is_dryrun(data))
		hro_degrade(a, info->index);
}

static void dryrun_analysis(struct dm_tier_algo *a, struct analyze_data *data)
{
	struct hro *hro = to_hro_algo(a);
	struct scorer scorer_drun[MAX_TIER_LEVEL];
	dm_block_t mapped[MAX_TIER_LEVEL] = {0};
	uint64_t total_access = 0, ssd_access = 0;

	arrange_stats(hro, data, false, false, mapped, &total_access, &ssd_access);
	ssd_access *= ONE_HUNDRED;
	if (total_access)
		do_div(ssd_access, total_access);
	else
		ssd_access = 0;
	scorer_init(scorer_drun, data->sco_pf_drun, mapped, ssd_access);

	hro_cluster_set_walk(&data->set, dryrun_callback, 
		a, data, scorer_drun);

	return;
}

static int hro_analyze(struct dm_tier_algo *a, struct analyze_data *data)
{
	data->total_migrate_block = 0;
	rawdata_analysis(a, data);
 	dryrun_analysis(a, data); 
 	return 0;
 }

static int hro_resize(struct dm_tier_algo *a, dm_block_t new_block_num)
{
	struct hro *hro = to_hro_algo(a);
	struct per_block_stats *new_stats;

	if (hro->block_num == new_block_num)
		return 0;

	new_stats = vzalloc(new_block_num * sizeof(struct per_block_stats));

	if (hro->block_stats && hro->block_num)
		memcpy(new_stats, hro->block_stats,
			hro->block_num * sizeof(struct per_block_stats));

	vfree(hro->block_stats);
	hro->block_stats = new_stats;
	hro->block_num = new_block_num;
	
	return 0;
}

static void init_algo_functions(struct hro *hro)
{
	hro->algo.update = hro_update;
	hro->algo.clear = hro_clear;
	hro->algo.analyze = hro_analyze;
	hro->algo.resize = hro_resize;
}

static struct dm_tier_algo* hro_create(struct kobject *kobj)
{
	struct hro *hro;

	hro = kzalloc(sizeof(*hro), GFP_KERNEL);
	if (!hro) {
		DMERR("No memory for HRO algorithm private data");
		return NULL;
	}

	init_algo_functions(hro);
	iot_reset(&hro->iot);
	spin_lock_init(&hro->iot.lock);

	hro->block_num = 0;
	hro->block_stats = NULL;

	atomic_set(&hro->weight, DEFAULT_WEIGHT);
	atomic_set(&hro->random_threshold, DEFAULT_RANDOM_THRESHOLD);

	if (kobject_init_and_add(&hro->algo.kobj, &dm_ktype, 
		kobj, "%s", "hro"))
		goto bad_kobj;

	return &hro->algo;

bad_kobj:
	kfree(hro);

	return NULL;
}

static struct dm_tier_algo_type hro_algo_type = {
	.name = "hro",
	.version = {1, 0, 0},
	.owner = THIS_MODULE,
	.create = hro_create
};

static int __init hro_algo_register(void)
{
	return dm_tier_algo_register(&hro_algo_type);
}

static void __exit hro_algo_unregister(void)
{
	dm_tier_algo_unregister(&hro_algo_type);
}

module_init(hro_algo_register);
module_exit(hro_algo_unregister);

MODULE_AUTHOR("Dennis Yang, Webber Huang");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Tier Hot Random Offloading Algorithm");
MODULE_VERSION("1.0");
