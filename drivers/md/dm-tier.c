#include "dm-tier-algo-internal.h"
#include "dm-tier-algo-utility.h"
#include "dm-tier.h"
#include <linux/init.h>
#include <linux/module.h>
#include <linux/delay.h>
#include <linux/vmalloc.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>

#define DM_MSG_PREFIX   "tier"
#define MAPPING_POOL_SIZE 1024
#define COMMIT_PERIOD HZ

#define DEFAULT_ALGO "hro"

#define MIGRATION_NUM 10
#define MIGRATION_MIN 3
#define MIGRATION_RETRY 2

#define SWAP_BLK_RATIO 100
#define SWAP_BLK_DEFAULT 400
#define SWAP_LOW_LIMIT 10

#define TIER_BYPASS_OFF -1

#define PROC_FS_NAME "Qtier"
#define QTIER_VERSION "Qtier-2.0"

#define DEFAULT_RESERVE_RATIO 25
#define RESERVE_MAX 100

#define MIGRATE_FULL 1
#define NO_SWAP 2
#define IN_BOUND 3
#define OUT_OF_BOUND 4

/*
 * flag_bits:
 *   MIGR_ANCHORS_ONLY  - Only migrate anchor blocks
 */
#define MIGR_ANCHORS_ONLY 0

static struct dm_kcopyd_throttle dm_kcopyd_throttle = {100, 0, 0, 0, 0};
static struct kmem_cache *_migrate_mapping_cache;
static struct kmem_cache *_trim_info_cache;

#define NR_TSCORE_REC 5
struct migration_data {
	struct analyze_data *adata;
	atomic_t migration_count;
	struct completion complete;
	uint64_t avg_tscore;
	wait_queue_head_t wait_for_migrate;
};

/*Tier events*/
enum tevent {
	AUTO_TIERING = 0,
	STOP_AUTO_TIERING,
	DRYRUN,
	SUSPEND,
	RESUME,
	ANCHOR_UPDATE,
	FINISH,
	__MAX_NR_TEVENT
};

static char * const msg_str[__MAX_NR_TEVENT] = {
	"auto_tiering",
	"stop_auto_tiering",
	"data_analysis",
	"tiering_suspend",
	"tiering_resume",
	"anchor_update",
	"tiering_finish"
};

/*migration state*/
enum mstate {
	MIG_IDLE = 0,
	MIG_PROCESS,
	MIG_CNL_WAIT,
	MIG_SPND_WAIT,
	MIG_SUSPEND,
	MIG_RESUME,
	MIG_DRUN_ALGO, /*state for dryrun or set algorithm*/
	MIG_RECALCULATE,
	__MAX_NR_MSTATE
};

static char * const state_name[__MAX_NR_MSTATE] = {
	"Migration stop\n",
	"Migration processing\n",
	"Migration cancel waiting\n",
	"Migration suspend waiting\n",
	"Migration suspend\n",
	"Migration resume\n",
	"Migration dryrun\n",
	"Migration recalcuating\n"
};

struct transition_work {
	atomic_t state;
	atomic_t busy;
	struct completion complete;
	struct workqueue_struct *trans_wq;

 	struct work_struct start_worker;
	struct work_struct stop_worker;
	struct work_struct dryrun_worker;
	struct work_struct suspend_worker;
	struct work_struct resume_worker;
	struct work_struct anchor_upd_worker;
	struct work_struct finish_worker;
};

#define DEFAULT_LEARN_WINDOW 86400
struct commander {
	unsigned long last_opt;
	unsigned long learn_wind;
    	struct delayed_work dwork;
};

#define MAX_GATE_RECORD 32
#define MAX_GATE_DEGREE 32

/*Tier events*/
enum gate_type {
	HOLD_BACK = 0,
	THROTTLED,
	BEST_EFFORT,
	__MAX_NR_GTYPE
};

static char * const gtype_str[__MAX_NR_GTYPE] = {
	"hold_back\n",
	"throttled\n",
	"best_effort\n"
};

struct gate {
	atomic_t applied;
	atomic_t factor;
	atomic_t type;
	int index;
	int degree;
	uint8_t records[MAX_GATE_RECORD];
	wait_queue_head_t wait;
};

enum io_pattern {
	PATTERN_SEQUENTIAL,
	PATTERN_RANDOM
};

struct io_tracker {
	enum io_pattern pattern;

	unsigned nr_seq_samples;
	unsigned nr_rand_samples;
	unsigned thresholds[2];

	sector_t last_end_sector;
};

#define CACHE_HASH_BITS 7

#define CACHE_ENABLE 0
#define CACHE_ALL_IO 1

struct cache_stats {
	atomic64_t cache_hit;
	atomic64_t total_io;
	atomic64_t promote;
	atomic64_t demote;
};

#define CACHE_GEN_BITS 8
#define CACHE_GEN_MASK ((1 << CACHE_GEN_BITS) - 1)

struct cache {
	unsigned long flags;
	struct mutex lock;
	atomic_t period;
	atomic_t promote_threshold;
	struct completion complete;
	atomic_t demote_on_the_fly;
	atomic_t promote_on_the_fly;
	atomic_t max_fly_count;
	struct list_head lru_list;
	struct cache_stats stats;
	struct io_tracker io_tracker;
	struct list_head promote_wait_list;
	struct delayed_work pioneer;
	struct workqueue_struct *wq;
	unsigned int generation;
	unsigned int promote_wait_sec;
	DECLARE_HASHTABLE(table, CACHE_HASH_BITS);
	DECLARE_HASHTABLE(pre_cache, CACHE_HASH_BITS);
};

struct progress {
	atomic_t total;
	atomic_t processed;
};

struct tier {
	uint32_t thin_blk_size;
	uint32_t sector_per_block;
	int sector_per_block_shift;
	struct kobject kobj;

	struct dm_kcopyd_client *migrator;
	struct workqueue_struct *migration_wq;
	struct work_struct migrate_worker;
	struct gate gate;
	struct progress progress;

	struct workqueue_struct *tier_wq;
	struct work_struct tier_worker;
	struct transition_work transition_work;
	struct bio_list block_pm_bios;

	struct workqueue_struct *cmndr_wq;
	struct commander cmndr;

	struct workqueue_struct *discard_wq;
	struct delayed_work discard_worker;

	struct list_head prepared_mappings;
	struct list_head prepared_migrates;
	struct list_head prepared_discards;
	struct list_head prepared_trims;
	struct list_head deferred_cells;

	struct dm_deferred_set *tier_io_ds;

	mempool_t *migrate_mapping_pool;
	mempool_t *trim_info_pool;

	unsigned int tier_num;
	atomic_t migration_num;
	dm_block_t block_num;

	struct per_tier_stat *tier_stats;
	struct reserve_ctrl rctrl;
	struct anchor_stat anchor_stat;
	struct migration_data migr_data;

	spinlock_t score_lock;
	struct score_profiler sco_pf_org[MAX_TIER_LEVEL];
	struct score_profiler sco_pf_drun[MAX_TIER_LEVEL];

	unsigned long *tier_map; //record LBA tier id, 2 bits for each LBA
	unsigned long *anchormap;

	unsigned long flags;

	rwlock_t tiermap_lock;
	rwlock_t anchormap_lock;

	struct dm_bio_prison *prison;
	spinlock_t lock;
	struct tier_c *tier_ctx;

	struct workqueue_struct *wq;
	struct work_struct worker;

	struct dm_tier_metadata *tmd;
	struct dm_tier_algo *algo;

	struct cache cache;

	atomic_t stats_switch;
	atomic_t swap_not_ready;
	atomic_t bypass_tier;
	atomic_t enable_discard;
	atomic_t config_lock;
};

#define SSD 0

static bool check_tier_discard_passdown(struct tier *tier, unsigned int tierid);
static void tier_defer_task(struct tier *tier, struct dm_tier_new_mapping *m);

/*----------------------------------------------------------------*/

#define DEFAULT_GATE_FACTOR 500

static void gate_init(struct gate *gate)
{
	atomic_set(&gate->applied, 0);
	atomic_set(&gate->factor, DEFAULT_GATE_FACTOR);
	atomic_set(&gate->type, THROTTLED);
	init_waitqueue_head(&gate->wait);
}

static void set_gate_factor(struct gate *gate, int factor)
{
	atomic_set(&gate->factor, factor);
}

static int get_gate_factor(struct gate *gate)
{
	return atomic_read(&gate->factor);
}

static int set_gate_type(struct gate *gate, const char *type_str)
{
	enum gate_type gtype;

	for (gtype = HOLD_BACK; gtype < __MAX_NR_GTYPE; gtype++) {
		if (!strcmp(type_str, gtype_str[gtype])) {
			atomic_set(&gate->type, gtype);
			return 0;
		}
	}

	return -EINVAL;
}

static char* get_gate_type(struct gate *gate)
{
	return gtype_str[atomic_read(&gate->type)];
}

static void gate_reset(struct gate *gate)
{
	gate->index = 0;
	gate->degree = 0;
	memset(gate->records, 0, MAX_GATE_RECORD);
}

static void gate_lock(struct gate *gate, struct bio_list *bios, struct list_head *cells)
{
	if (!atomic_read(&gate->applied) &&
			!(bio_list_empty(bios) && list_empty(cells))) {
		atomic_set(&gate->applied, 1);
		DMDEBUG("%s:%d, gate locked !!", __func__, __LINE__);
	}
}

static void gate_unlock(struct gate *gate)
{
	if (atomic_read(&gate->applied)) {
		atomic_set(&gate->applied, 0);

		if (waitqueue_active(&gate->wait))
			wake_up(&gate->wait);

		DMDEBUG("%s:%d, gate unlocked !!", __func__, __LINE__);
	}
}

static void gate_wait_unlock(struct gate *gate)
{
	DEFINE_WAIT(wait);
	do {
		prepare_to_wait(&gate->wait, &wait, TASK_UNINTERRUPTIBLE);
		if (!atomic_read(&gate->applied))
			break;

		io_schedule();
	} while(1);

	finish_wait(&gate->wait, &wait);
}

static void gate_record(struct gate *gate)
{
	int *index = &gate->index;
	uint8_t temp = gate->records[*index];

	gate->records[*index] = (uint8_t)atomic_read(&gate->applied);

	if (gate->records[*index] != temp) {
		temp ? gate->degree-- : gate->degree++;
		DMDEBUG("%s:%d, gate degree(%d) !!", __func__, __LINE__, gate->degree);
	}

	(*index)++;
	(*index) %= MAX_GATE_RECORD;
}

static int gate_wait(struct gate *gate)
{
	if (gate->degree) {
		DMDEBUG("%s:%d, gate wait for %d factors !!", __func__, __LINE__, gate->degree);
		msleep(gate->degree * atomic_read(&gate->factor));
	}

	return gate->degree;
}

static void gate_control(struct gate *gate)
{

record_again:
	gate_record(gate);

	switch (atomic_read(&gate->type)) {
		case HOLD_BACK:
			if(gate_wait(gate))
				goto record_again;
			break;
		case THROTTLED:
			if (gate_wait(gate) == MAX_GATE_DEGREE)
				goto record_again;
			break;
		case BEST_EFFORT:
			break;
	}
}

/*----------------------------------------------------------------*/

static void progress_start(struct progress *p, int total)
{
	atomic_set(&p->total, total);
	atomic_set(&p->processed, 0);
}

static void progress_update(struct progress *p)
{
	atomic_inc(&p->processed);
}

static void progress_total_refresh(struct progress *p, int change)
{
	atomic_add(change, &p->total);
}

static void progress_get(struct progress *p, int *total, int *processed)
{
	*total = atomic_read(&p->total);
	*processed = atomic_read(&p->processed);
}

/*----------------------------------------------------------------*/

#define RANDOM_THRESHOLD_DEFAULT 4
#define SEQUENTIAL_THRESHOLD_DEFAULT 512

static void iot_init(struct io_tracker *t,
		     int sequential_threshold, int random_threshold)
{
	t->pattern = PATTERN_RANDOM;
	t->nr_seq_samples = 0;
	t->nr_rand_samples = 0;
	t->last_end_sector = 0;
	t->thresholds[PATTERN_RANDOM] = random_threshold;
	t->thresholds[PATTERN_SEQUENTIAL] = sequential_threshold;
}

static enum io_pattern iot_pattern(struct io_tracker *t)
{
	return t->pattern;
}

static void iot_update_stats(struct io_tracker *t, struct bio *bio)
{
	if (bio->bi_iter.bi_sector == t->last_end_sector + 1)
		t->nr_seq_samples++;
	else {
		/*
		 * Just one non-sequential IO is enough to reset the
		 * counters.
		 */
		if (t->nr_seq_samples) {
			t->nr_seq_samples = 0;
			t->nr_rand_samples = 0;
		}

		t->nr_rand_samples++;
	}

	t->last_end_sector = bio_end_sector(bio) - 1;
}

static void iot_check_for_pattern_switch(struct io_tracker *t)
{
	switch (t->pattern) {
	case PATTERN_SEQUENTIAL:
		if (t->nr_rand_samples >= t->thresholds[PATTERN_RANDOM]) {
			t->pattern = PATTERN_RANDOM;
			t->nr_seq_samples = t->nr_rand_samples = 0;
		}
		break;

	case PATTERN_RANDOM:
		if (t->nr_seq_samples >= t->thresholds[PATTERN_SEQUENTIAL]) {
			t->pattern = PATTERN_SEQUENTIAL;
			t->nr_seq_samples = t->nr_rand_samples = 0;
		}
		break;
	}
}

static void iot_examine_bio(struct io_tracker *t, struct bio *bio)
{
	iot_update_stats(t, bio);
	iot_check_for_pattern_switch(t);
}

/*----------------------------------------------------------------*/

struct entry {
	struct hlist_node hlist;
	struct list_head list;
	dm_block_t block;
	int hit_count;
	bool promoted;
	unsigned int generation;
};

/*
 * Debug only
 */
static void dump_lru_list(struct cache *cache)
{
	int i = 0;
	struct entry *e;

	DMERR("--- list start ---");
	list_for_each_entry(e, &cache->lru_list, list) {
		DMERR("%d - %llu", i++, e->block);
	}
	DMERR("--- list stop ---");
}

static void __cache_generation_tick(struct cache *cache)
{
	cache->generation++;
	cache->generation &= CACHE_GEN_MASK;
}

static void cache_examine_bio(struct cache *cache, struct bio *bio)
{
	atomic64_inc(&cache->stats.total_io);
	iot_examine_bio(&cache->io_tracker, bio);
}

static void cache_entry_init(struct entry *e, dm_block_t block)
{
	e->promoted = false;
	e->hit_count = 0;
	e->block = block;
	INIT_LIST_HEAD(&e->list);
	INIT_HLIST_NODE(&e->hlist);
}

static struct entry* cache_entry_alloc(struct cache *cache, dm_block_t block)
{
	struct entry *e = NULL;

	e = kzalloc(sizeof(struct entry), GFP_NOWAIT);
	if (!e)
		return NULL;

	cache_entry_init(e, block);
	return e;
}

static void __cache_entry_enqueue(struct cache *cache, struct entry *e, bool pre_cache)
{
	e->hit_count = 0;
	e->generation = cache->generation;
	if (pre_cache)
		hash_add(cache->pre_cache, &e->hlist, e->block);
	else {
		list_add_tail(&e->list, &cache->lru_list);
		hash_add(cache->table, &e->hlist, e->block);
	}
}

static void cache_entry_enqueue(struct cache *cache, struct entry *e, bool pre_cache)
{

	mutex_lock(&cache->lock);
	__cache_entry_enqueue(cache, e, pre_cache);
	mutex_unlock(&cache->lock);
}

static struct entry* cache_entry_create_and_queue(struct cache *cache, 
						  dm_block_t block, 
						  bool pre_cache)
{
	struct entry *e;

	e = cache_entry_alloc(cache, block);
	if (e)
		cache_entry_enqueue(cache, e, pre_cache);

	return e;
}

static struct entry* __cache_lookup(struct cache *cache, dm_block_t block)
{
	struct entry *e;

	hash_for_each_possible(cache->table, e, hlist, block) {
		if (e->block == block)
			return e;
	}

	return NULL;
}

static struct entry* __pre_cache_lookup(struct cache *cache, dm_block_t block)
{
	struct entry *e;

	hash_for_each_possible(cache->pre_cache, e, hlist, block) {
		if (e->block == block)
			return e;
	}

	return NULL;
}

static void cache_free(struct entry *e)
{
	kfree(e);
}

static void __cache_remove_entry(struct entry *e)
{
	list_del_init(&e->list);
	hash_del(&e->hlist);
}

static void cache_entry_destroy(struct cache *cache, struct entry *e)
{
	mutex_lock(&cache->lock);
	__cache_remove_entry(e);
	mutex_unlock(&cache->lock);

	cache_free(e);
}

static void cache_remove(struct cache *cache, dm_block_t block)
{
	struct entry *e = NULL;

	mutex_lock(&cache->lock);
	e = __cache_lookup(cache, block);
	if (!e)
		e = __pre_cache_lookup(cache, block);

	if (e) {
		__cache_remove_entry(e);
		cache_free(e);
	}
	mutex_unlock(&cache->lock);
}

static struct entry *cache_get_lru(struct cache *cache)
{
	struct entry *e = NULL;

	mutex_lock(&cache->lock);

	e = list_first_entry_or_null(&cache->lru_list, struct entry, list);
	if (e)
		__cache_remove_entry(e);

	mutex_unlock(&cache->lock);

	return e;
}

static int cache_reset_lru(struct cache *cache, dm_block_t block, int can_block)
{
	struct entry *e;
	int r = -EINVAL;

	if (can_block)
		mutex_lock(&cache->lock);
	else if (!mutex_trylock(&cache->lock))
		return -EWOULDBLOCK;

	e = __cache_lookup(cache, block);
	if (e) {
		r = 0;
		e->hit_count++;
		list_del_init(&e->list);
		list_add_tail(&e->list, &cache->lru_list);
		atomic64_inc(&cache->stats.cache_hit);
	}

	mutex_unlock(&cache->lock);
	return r;
}

static void cache_wait_for_promote(struct tier *tier, struct dm_tier_new_mapping *m)
{
	struct cache *cache = &tier->cache;

	m->promote = true;

	mutex_lock(&cache->lock);
	m->generation = cache->generation;
	list_add_tail(&m->list, &cache->promote_wait_list);
	mutex_unlock(&cache->lock);
}

static void cache_migrate_issue(struct tier *tier, struct dm_tier_new_mapping *m)
{
	struct cache *cache = &tier->cache;

	BUG_ON(!(m->promote ^ m->demote));

	atomic64_inc(m->promote ? &cache->stats.promote : &cache->stats.demote);
	atomic_inc(m->promote ? &cache->promote_on_the_fly : &cache->demote_on_the_fly);

	if (!dm_deferred_set_add_work(tier->tier_io_ds, &m->list))
		tier_defer_task(tier, m);
}

static void cache_migrate_complete(struct tier *tier, struct dm_tier_new_mapping *m)
{
	atomic_t *operator, *checker;

	operator = m->promote ? &tier->cache.promote_on_the_fly : 
		&tier->cache.demote_on_the_fly;

	checker = m->promote ? &tier->cache.demote_on_the_fly : 
		&tier->cache.promote_on_the_fly;

	if (atomic_dec_and_test(operator) && !atomic_read(checker)) {
		DMINFO("%s:%d, send cache completion !!", __func__, __LINE__);
		complete(&tier->cache.complete);
	}
}

static void cache_enable(struct cache *cache)
{
	set_bit(CACHE_ENABLE, &cache->flags);
}

static void cache_disable(struct cache *cache)
{
	clear_bit(CACHE_ENABLE, &cache->flags);
}

static bool is_cache_disabled(struct cache *cache)
{
	return test_bit(CACHE_ENABLE, &cache->flags) ? false : true;
}

static bool aware_io(struct bio *bio)
{
	return bio->bi_rw & REQ_IO_AWARE;
}

static int should_cache(struct cache *cache, struct bio *bio)
{
	if (is_cache_disabled(cache) || !aware_io(bio))
		return 0;

	return (test_bit(CACHE_ALL_IO, &cache->flags) ||
			iot_pattern(&cache->io_tracker) == PATTERN_RANDOM);
}

/*
 * Put block into pre_cache state.
 * Return 0 if success, 1 if cache entry is ready for promotion.
 */
static int ready_to_promote(struct tier *tier, dm_block_t block)
{
	struct entry *e = NULL;
	struct cache *cache = &tier->cache;

	mutex_lock(&cache->lock);
	e = __pre_cache_lookup(cache, block);
	if (e)
		goto found;

	/*
	 * FIXME: if this will blocks, 
	 * we need to release lock before we alloc cache entry.
	 */
	e = cache_entry_alloc(cache, block);
	if (!e)
		goto finished;

	__cache_entry_enqueue(cache, e, true);

found:
	if (!e->promoted &&
		(e->hit_count == INT_MAX ||
		 e->hit_count++ > atomic_read(&cache->promote_threshold))) {
		/*
		 * update generation to prevent this entry from
		 * getting removed before we promote it
		 */
		e->generation = cache->generation;
		mutex_unlock(&cache->lock);
		return 1;
	}

finished:
	mutex_unlock(&cache->lock);
	return 0;
}

static int mark_entry_promoted(struct cache *cache, dm_block_t block)
{
	struct entry *e = NULL;

	mutex_lock(&cache->lock);
	e = __pre_cache_lookup(cache, block);
	if (!e) {
		DMERR("%s: mark non-exist pre_cache entry", __func__);
		goto err_out;
	}

	e->promoted = true;
err_out:
	mutex_unlock(&cache->lock);

	return e ? 0 : -EINVAL;
}

static struct entry* promote_from_pre_cache(struct cache *cache, dm_block_t block)
{
	struct entry *e = NULL;

	mutex_lock(&cache->lock);
	e = __pre_cache_lookup(cache, block);
	if (!e) {
		DMDEBUG("%s: promote non-exist pre cache entry", __func__);
		goto err_out;
	}

	__cache_remove_entry(e);
	__cache_entry_enqueue(cache, e, false);
err_out:
	mutex_unlock(&cache->lock);

	return e;
}

#define DEFAULT_PROMOTE_PERIOD 10
#define DEFAULT_PROMOTE_THRESHOLD 128

#define CACHE_MIGRATE_MAX_COUNT

static void cache_stats_init(struct cache_stats *stats)
{
	atomic64_set(&stats->cache_hit, 0);
	atomic64_set(&stats->total_io, 0);
	atomic64_set(&stats->demote, 0);
	atomic64_set(&stats->promote, 0);
}

static int cache_avaiable_for_demote(struct cache *cache)
{
	return (atomic_read(&cache->demote_on_the_fly) < atomic_read(&cache->max_fly_count));
}

static int cache_avaiable_for_promote(struct cache *cache)
{
	return (atomic_read(&cache->promote_on_the_fly) < atomic_read(&cache->max_fly_count));
}

static int cache_set_max_flier(struct cache *cache, dm_block_t swap)
{
	dm_block_t reserve = swap >> 4;

	if (swap <= MIGRATION_NUM)
		atomic_set(&cache->max_fly_count, 0);
	else if (reserve <= MIGRATION_NUM)
		atomic_set(&cache->max_fly_count, swap - MIGRATION_NUM);
	else
		atomic_set(&cache->max_fly_count, swap - reserve);

	return 0;
}

static int do_promotion(struct tier *tier, struct dm_tier_new_mapping *m);
static void do_pioneer(struct work_struct *ws)
{
	int i;
	struct entry *e;
	struct hlist_node *tmp;
	struct cache *cache = container_of(to_delayed_work(ws), struct cache, pioneer);
	struct tier *tier = container_of(cache, struct tier, cache);
	struct list_head mappings;
	struct dm_tier_new_mapping *m, *t;

	mutex_lock(&cache->lock);
	__cache_generation_tick(cache);

	/*
	 * Remove pre_cache entries which are not qualified for promotion
	 */
	hash_for_each_safe(cache->pre_cache, i, tmp, e, hlist) {
		if (e->generation == cache->generation) {
			__cache_remove_entry(e);
			cache_free(e);
		}
	}

	INIT_LIST_HEAD(&mappings);
	list_splice_init(&cache->promote_wait_list, &mappings);

	mutex_unlock(&cache->lock);

	/*
	 * Traverse promote_wait_list to promote any entry meeting its deadline
	 */
	list_for_each_entry_safe(m, t, &mappings, list) {
		unsigned int deadline = (m->generation + cache->promote_wait_sec) & CACHE_GEN_MASK;

		if (deadline == cache->generation) {
			list_del_init(&m->list);
			if (do_promotion(tier, m))
				mempool_free(m, tier->migrate_mapping_pool);
		}
	}

	mutex_lock(&cache->lock);
	list_splice(&mappings, &cache->promote_wait_list);
	mutex_unlock(&cache->lock);

	queue_delayed_work(cache->wq, &cache->pioneer, atomic_read(&cache->period) * HZ);
}

static void cache_reclaim(struct cache *cache)
{
	int i;
	struct entry *e, *temp;
	struct hlist_node *tmp;
	struct tier *tier = container_of(cache, struct tier, cache);
	struct list_head mappings;
	struct dm_tier_new_mapping *m, *t;

	mutex_lock(&cache->lock);

	hash_for_each_safe(cache->pre_cache, i, tmp, e, hlist) {
		__cache_remove_entry(e);
		cache_free(e);
	}

	list_for_each_entry_safe(e, temp, &cache->lru_list, list) {
		__cache_remove_entry(e);
		cache_free(e);
	}

	INIT_LIST_HEAD(&mappings);
	list_splice_init(&cache->promote_wait_list, &mappings);

	mutex_unlock(&cache->lock);

	list_for_each_entry_safe(m, t, &mappings, list) {
		list_del_init(&m->list);
		mempool_free(m, tier->migrate_mapping_pool);
	}

}

static int cache_init(struct cache *cache)
{
	cache->flags = 0;
	cache->generation = 0;
	cache->promote_wait_sec = 2;
	mutex_init(&cache->lock);
	INIT_LIST_HEAD(&cache->lru_list);
	INIT_LIST_HEAD(&cache->promote_wait_list);
	hash_init(cache->table);
	hash_init(cache->pre_cache);
	init_completion(&cache->complete);
	atomic_set(&cache->max_fly_count, 0);
	atomic_set(&cache->demote_on_the_fly, 0);
	atomic_set(&cache->promote_on_the_fly, 1);
	atomic_set(&cache->period, DEFAULT_PROMOTE_PERIOD);
	atomic_set(&cache->promote_threshold, DEFAULT_PROMOTE_THRESHOLD);
	cache_stats_init(&cache->stats);
	iot_init(&cache->io_tracker, SEQUENTIAL_THRESHOLD_DEFAULT, RANDOM_THRESHOLD_DEFAULT);
	INIT_DELAYED_WORK(&cache->pioneer, do_pioneer);
	cache_enable(cache);

	cache->wq = alloc_ordered_workqueue("dm-tier-cache-" DM_MSG_PREFIX, WQ_MEM_RECLAIM);
	if (!cache->wq)
		return -ENOMEM;

	return 0;
}

static void stop_cache(struct cache *cache)
{
	cancel_delayed_work_sync(&cache->pioneer);
	flush_workqueue(cache->wq);

	if (!atomic_dec_and_test(&cache->promote_on_the_fly) 
	    || atomic_read(&cache->demote_on_the_fly))
		wait_for_completion(&cache->complete);

	atomic_set(&cache->promote_on_the_fly, 1);
	init_completion(&cache->complete);
}

static void cache_destroy(struct cache *cache)
{
	cache_reclaim(cache);
	destroy_workqueue(cache->wq);
}

/*----------------------------------------------------------------*/
static bool check_reserve(struct tier *tier)
{
	bool r;

	dm_tier_has_reserve(tier->tmd, &r);
	return r;
}

static int config_reserve(struct tier *tier,
			  enum reserve_type rtype,
			  unsigned int tid,
			  dm_block_t begin,
			  dm_block_t end)
{
	dm_block_t tier_real_size, tier_size;
	bool has_reserve = false;
	int r;

	r = dm_tier_get_data_dev_real_size(tier->tmd, tid, &tier_real_size);
	if (r)
		return r;

	r = dm_tier_get_data_dev_size(tier->tmd, tid, &tier_size);
	if (r)
		return r;

	if (begin > end || end > tier_real_size) {
		DMINFO("config wrong range b:%llu e:%llu real_size:%llu",
			begin, end, tier_real_size);
		return -EINVAL;
	}

	/*
	 * FIXME: it's a temporaily check to 
	 * make the reserve length <= tier dev logical size
	 */
	if ((end - begin) > tier_size)
		end -= (end - begin - tier_size);

	if (!atomic_add_unless(&tier->config_lock, 1, 1)) {
		DMINFO("Cannot config reserve during locked");
		return -EBUSY;
	}

	has_reserve = check_reserve(tier);
	if (has_reserve) {
		DMINFO("tier already has forbidden zone");
		r = -EINVAL;
		goto out;
	}

	rctrl_config(&tier->rctrl, rtype, (int)tid,
		     tier_real_size, begin, end);

	DMINFO("config res type(%d) tid(%u) size(%llu)",
	       rtype, tid, tier_real_size);

	DMINFO("config res begin(%llu) end(%llu) retain(%llu)",
	       begin, end, end - begin);

out:
	WARN_ON(!atomic_add_unless(&tier->config_lock, -1, 0));
	return r;
}

static int config_reserve_with_ratio(struct tier *tier,
				     unsigned int tid,
				     unsigned int ratio)
{
	dm_block_t tier_size, rlen;
	int r;

	if (ratio > RESERVE_MAX) {
		DMINFO("config reserve with wrong ratio: %u", ratio);
		return -EINVAL;
	}

	r = dm_tier_get_data_dev_size(tier->tmd, tid, &tier_size);
	if (r)
		return r;

	rlen = tier_size * ratio;
	do_div(rlen, 100);
	return config_reserve(tier, USAGE_CTRL, tid, 0, rlen);
}

static int turnon_reserve(struct tier *tier)
{
	int r;
	struct reserve_ctrl *rctrl = &tier->rctrl;
	int rtid = rctrl_get_tierid(rctrl);
	dm_block_t begin = rctrl_get_begin(rctrl);
	dm_block_t end = rctrl_get_end(rctrl);

	DMINFO("turn on reserve control");
	r = dm_tier_set_boundary(tier->tmd, (unsigned int)rtid, begin, end);
	if (r)
		DMINFO("set boundary fail with r(%d)", r);

	return r;
}

/*
 * if this function is not called from tiering process,
 * the function call shoulde be followed by stop tiering,
 * or make sure there is no tiering process
 */
static int turnoff_reserve(struct tier *tier)
{
	int r;

	DMINFO("turn off reserve control");
	r = dm_tier_chk_and_clear_boundary(tier->tmd);
	if (r)
		DMINFO("clear boundary fail with r(%d)", r);

	return r;
}

/*----------------------------------------------------------------*/

static void set_mstate(struct transition_work *tw, enum mstate m)
{
	atomic_set(&tw->state, m);
}

static enum mstate get_mstate(struct transition_work *tw)
{
	return atomic_read(&tw->state);
}

static void do_start(struct work_struct *ws);
static void do_stop(struct work_struct *ws);
static void do_dryrun(struct work_struct *ws);
static void do_suspend(struct work_struct *ws);
static void do_resume(struct work_struct *ws);
static void do_anchor_upd(struct work_struct *ws);
static void do_finish(struct work_struct *ws);

static int init_transition_work(struct transition_work *tw)
{
	set_mstate(tw, MIG_IDLE);
	atomic_set(&tw->busy, 1);
	init_completion(&tw->complete);

	tw->trans_wq = alloc_ordered_workqueue("dm-" DM_MSG_PREFIX, WQ_MEM_RECLAIM);
	if (!tw->trans_wq)
		return -ENOMEM;

	INIT_WORK(&tw->start_worker, do_start);
	INIT_WORK(&tw->stop_worker, do_stop);
	INIT_WORK(&tw->dryrun_worker, do_dryrun);
	INIT_WORK(&tw->suspend_worker, do_suspend);
	INIT_WORK(&tw->resume_worker, do_resume);
	INIT_WORK(&tw->anchor_upd_worker, do_anchor_upd);
	INIT_WORK(&tw->finish_worker, do_finish);

	return 0;
}

void destroy_transition_work(struct transition_work *tw)
{
	destroy_workqueue(tw->trans_wq);
}

static void free_migration_data(struct tier *tier);
static int put_anchors_in_queue(struct tier *tier);
static int process_state_transition(struct tier *tier, enum tevent t);
static void do_start(struct work_struct *ws)
{
	struct transition_work *tw = container_of(ws, struct transition_work, start_worker);
	struct tier *tier = container_of(tw, struct tier, transition_work);
	enum mstate m;

	m = get_mstate(tw);
	if (m >= __MAX_NR_MSTATE) {
		DMINFO("%s:%d, Unknow  State!!", __func__, __LINE__);
		return;
	}

	switch (m) {
		case MIG_IDLE:
			if (!atomic_add_unless(&tier->config_lock, 1, 1)) {
				DMINFO("Can't start tiering as config locked");
				return;
			}
			atomic_inc(&tw->busy);
			set_mstate(tw, MIG_PROCESS);
			queue_work(tier->tier_wq, &tier->tier_worker);
			break;
		case MIG_PROCESS:
		case MIG_CNL_WAIT:
		case MIG_SPND_WAIT:
		case MIG_SUSPEND:
		case MIG_RESUME:
		case MIG_DRUN_ALGO:
		case MIG_RECALCULATE:
		default:
			break;
	}
}

static void do_stop(struct work_struct *ws)
{
	struct transition_work *tw = container_of(ws, struct transition_work,
						  stop_worker);
	struct tier *tier = container_of(tw, struct tier, transition_work);
	enum reserve_type rtype = rctrl_get_type(&tier->rctrl);
	enum mstate m;

	m = get_mstate(tw);
	if (m >= __MAX_NR_MSTATE) {
		DMINFO("%s:%d, Unknow  State!!", __func__, __LINE__);
		return;
	}

	switch (m) {
		case MIG_PROCESS:
		case MIG_RESUME:
			set_mstate(tw, MIG_CNL_WAIT);
			cancel_work_sync(&tier->tier_worker);
			cancel_work_sync(&tier->migrate_worker);
			break;
		case MIG_SUSPEND:
			if (rtype == DRIVE_OUT)
				atomic_set(&tier->enable_discard, 1);

			if (tier->migr_data.adata)
				free_migration_data(tier);

			if (atomic_dec_and_test(&tw->busy))
				complete(&tw->complete);

			set_mstate(tw, MIG_IDLE);
			WARN_ON(!atomic_add_unless(&tier->config_lock, -1, 0));
			break;
		case MIG_IDLE:
		case MIG_CNL_WAIT:
		case MIG_SPND_WAIT:
		case MIG_DRUN_ALGO:
		case MIG_RECALCULATE:
		default:
			break;
	}
}

static void do_dryrun(struct work_struct *ws)
{
	struct transition_work *tw = container_of(ws, struct transition_work, dryrun_worker);
	struct tier *tier = container_of(tw, struct tier, transition_work);
	enum mstate m;

	m = get_mstate(tw);
	if (m >= __MAX_NR_MSTATE) {
		DMINFO("%s:%d, Unknow  State!!", __func__, __LINE__);
		return;
	}

	switch (m) {
		case MIG_IDLE:
			atomic_inc(&tw->busy);
			set_mstate(tw, MIG_DRUN_ALGO);
			queue_work(tier->tier_wq, &tier->tier_worker);
			break;
		case MIG_PROCESS:
		case MIG_CNL_WAIT:
		case MIG_SPND_WAIT:
		case MIG_SUSPEND:
		case MIG_RESUME:
		case MIG_DRUN_ALGO:
		case MIG_RECALCULATE:
		default:
			break;
	}
}

static void do_suspend(struct work_struct *ws)
{
	struct transition_work *tw = container_of(ws, struct transition_work,
						  suspend_worker);
	struct tier *tier = container_of(tw, struct tier, transition_work);
	enum mstate m;

	m = get_mstate(tw);
	if (m >= __MAX_NR_MSTATE) {
		DMINFO("%s:%d, Unknow  State!!", __func__, __LINE__);
		return;
	}

	switch (m) {
		case MIG_PROCESS:
		case MIG_RESUME:
			set_mstate(tw, MIG_SPND_WAIT);
			cancel_work_sync(&tier->tier_worker);
			cancel_work_sync(&tier->migrate_worker);
			break;
		case MIG_IDLE:
		case MIG_CNL_WAIT:
		case MIG_SPND_WAIT:
		case MIG_SUSPEND:
		case MIG_DRUN_ALGO:
		case MIG_RECALCULATE:
		default:
			break;
	}
}

static void do_resume(struct work_struct *ws)
{
	struct transition_work *tw = container_of(ws, struct transition_work, resume_worker);
	struct tier *tier = container_of(tw, struct tier, transition_work);
	enum mstate m;

	m = get_mstate(tw);
	if (m >= __MAX_NR_MSTATE) {
		DMINFO("%s:%d, Unknow  State!!", __func__, __LINE__);
		return;
	}

	switch (m) {
		case MIG_SUSPEND:
			set_mstate(tw, MIG_RESUME);
			queue_work(tier->tier_wq, &tier->tier_worker);
			break;
		case MIG_IDLE:
		case MIG_PROCESS:
		case MIG_CNL_WAIT:
		case MIG_SPND_WAIT:
		case MIG_RESUME:
		case MIG_DRUN_ALGO:
		case MIG_RECALCULATE:
		default:
			break;
	}
}

static void do_anchor_upd(struct work_struct *ws)
{
	struct transition_work *tw = container_of(ws, struct transition_work, anchor_upd_worker);
	struct tier *tier = container_of(tw, struct tier, transition_work);
	enum mstate m;

	m = get_mstate(tw);
	if (m >= __MAX_NR_MSTATE) {
		DMINFO("%s:%d, Unknow  State!!", __func__, __LINE__);
		return;
	}

	switch (m) {
		case MIG_IDLE:
			atomic_inc(&tw->busy);
			set_mstate(tw, MIG_PROCESS);
			set_bit(MIGR_ANCHORS_ONLY, &tier->flags);
			smp_mb__after_atomic();
			queue_work(tier->tier_wq, &tier->tier_worker);
			break;		
		case MIG_PROCESS:
		case MIG_RESUME:
			set_mstate(tw, MIG_RECALCULATE);
			cancel_work_sync(&tier->tier_worker);
			cancel_work_sync(&tier->migrate_worker);
			break;
		case MIG_SUSPEND:
			set_mstate(tw, MIG_RECALCULATE);
			put_anchors_in_queue(tier);
			process_state_transition(tier, FINISH);
			break;
		case MIG_CNL_WAIT:
		case MIG_SPND_WAIT:
		case MIG_DRUN_ALGO:
		case MIG_RECALCULATE:
		default:
			break;
	}
}

static void do_finish(struct work_struct *ws)
{
	struct transition_work *tw = container_of(ws, struct transition_work,
						  finish_worker);
	struct tier *tier = container_of(tw, struct tier, transition_work);
	enum reserve_type rtype = rctrl_get_type(&tier->rctrl);
	enum mstate m;

	m = get_mstate(tw);
	if (m >= __MAX_NR_MSTATE) {
		DMINFO("%s:%d, Unknow  State!!", __func__, __LINE__);
		return;
	}

	switch (m) {
		case MIG_PROCESS:
		case MIG_CNL_WAIT:
		case MIG_RESUME:
		case MIG_DRUN_ALGO:
			if (rtype == DRIVE_OUT)
				atomic_set(&tier->enable_discard, 1);

			if (tier->migr_data.adata)
				free_migration_data(tier);

			if (atomic_dec_and_test(&tw->busy))
				complete(&tw->complete);

			set_mstate(tw, MIG_IDLE);
			WARN_ON(!atomic_add_unless(&tier->config_lock, -1, 0));
			break;
		case MIG_SPND_WAIT:
			DMDEBUG("%s: data migration suspend", __func__);
			set_mstate(tw, MIG_SUSPEND);
			break;
		case MIG_RECALCULATE:
			set_mstate(tw, MIG_RESUME);
			queue_work(tier->tier_wq, &tier->tier_worker);		
			break;
		case MIG_IDLE:
		case MIG_SUSPEND:
		default:
			break;
	}
}

static bool tier_migrateable(struct tier *tier)
{
	if (tier && !atomic_read(&tier->swap_not_ready) && !tier->tier_ctx->bypass)
		return true;
	else
		return false;
}

static enum tevent get_tevent(const char *message)
{
	enum tevent t = 0;

	for (t = AUTO_TIERING; t < __MAX_NR_TEVENT; t++)
		if (!strcasecmp(message, msg_str[t]))
			break;
	return t;
}

static int process_state_transition(struct tier *tier, enum tevent t)
{
	int r = 0;
	struct transition_work *tw = &tier->transition_work;

	if (!tier_migrateable(tier))
		return 0;

	switch (t) {
		case AUTO_TIERING:
			queue_work(tw->trans_wq, &tw->start_worker);
			break;
		case STOP_AUTO_TIERING:
			queue_work(tw->trans_wq, &tw->stop_worker);
			break;
		case DRYRUN:
			queue_work(tw->trans_wq, &tw->dryrun_worker);
			break;
		case SUSPEND:
			queue_work(tw->trans_wq, &tw->suspend_worker);
			break;
		case RESUME:
			queue_work(tw->trans_wq, &tw->resume_worker);
			break;
		case ANCHOR_UPDATE:
			queue_work(tw->trans_wq, &tw->anchor_upd_worker);
			break;			
		case FINISH:
			queue_work(tw->trans_wq, &tw->finish_worker);
			break;
		default:
			r = -EINVAL;
	};

	return r;
}

static void must_stop_migrate(struct tier *tier)
{
	struct transition_work *tw = &tier->transition_work;

	process_state_transition(tier, STOP_AUTO_TIERING);

	cancel_work_sync(&tw->start_worker);
	cancel_work_sync(&tw->dryrun_worker);
	cancel_work_sync(&tw->suspend_worker);
	cancel_work_sync(&tw->resume_worker);

	if (!atomic_dec_and_test(&tw->busy))
		wait_for_completion(&tw->complete);

	atomic_set(&tw->busy, 1);
	init_completion(&tw->complete);
}

/*----------------------------------------------------------------*/

static void init_commander(struct commander *cmndr, work_func_t func)
{
	cmndr->last_opt = get_seconds();
	cmndr->learn_wind = DEFAULT_LEARN_WINDOW;
	INIT_DELAYED_WORK(&cmndr->dwork, func);
}

static int check_arg_count(unsigned argc, unsigned args_required)
{
	if (argc != args_required) {
		DMWARN("Message received with %u arguments instead of %u.",
		       argc, args_required);
		return -EINVAL;
	}

	return 0;
}

static inline bool is_tier_enable(struct tier_c *tc, unsigned int tid)
{
	return (tc->enable_map & (0x1 << tid))? true : false;
}

static inline bool check_discard_passdown(struct tier *tier)
{
	return tier->tier_ctx->discard_passdown;
}

static unsigned int get_active_tier_num(unsigned int enable_map)
{
	int active_tier_num = 1;

	while (enable_map & (enable_map - 1)) {
		active_tier_num++;
		enable_map = (enable_map & (enable_map - 1));
	}

	return active_tier_num;
}

static void init_tier_context(struct tier_c *tc)
{
	tc->tier = NULL;
	tc->tier_num = 0;
	tc->tier_dev = NULL;
	tc->tier_blk_size = 0;
	tc->enable_map = 0x7; //enable all tiers by default
	tc->discard_passdown = 0x0;
	tc->bypass = true;
}

static void clear_tierid(struct tier *tier, dm_block_t block)
{
	unsigned long flags;

	write_lock_irqsave(&tier->tiermap_lock, flags);
	ta_clear_tierid(tier->tier_map, block);
	write_unlock_irqrestore(&tier->tiermap_lock, flags);
}

static void store_tierid(struct tier *tier, dm_block_t block, uint32_t tierid)
{
	unsigned long flags;

	write_lock_irqsave(&tier->tiermap_lock, flags);
	ta_store_tierid(tier->tier_map, block, tierid);
	write_unlock_irqrestore(&tier->tiermap_lock, flags);
}

static uint32_t get_tierid(struct tier *tier, dm_block_t block)
{
	uint32_t tierid;
	unsigned long flags;

	read_lock_irqsave(&tier->tiermap_lock, flags);
	tierid = ta_get_tierid(tier->tier_map, block);
	read_unlock_irqrestore(&tier->tiermap_lock, flags);

	return tierid;
}

static void anchormap_clear(struct tier *tier, dm_block_t block)
{
	unsigned long flags;

	write_lock_irqsave(&tier->anchormap_lock, flags);
	ta_anchormap_clear(tier->anchormap, block);
	write_unlock_irqrestore(&tier->anchormap_lock, flags);
}

static void anchormap_store(struct tier *tier, dm_block_t block, enum anchor anchor)
{
	unsigned long flags;

	write_lock_irqsave(&tier->anchormap_lock, flags);
	ta_anchormap_store(tier->anchormap, block, anchor);
	write_unlock_irqrestore(&tier->anchormap_lock, flags);
}

static enum anchor anchormap_get(struct tier *tier, dm_block_t block)
{
	enum anchor anchor;
	unsigned long flags;

	read_lock_irqsave(&tier->anchormap_lock, flags);
	anchor = ta_anchormap_get(tier->anchormap, block);
	read_unlock_irqrestore(&tier->anchormap_lock, flags);

	return anchor;
}

static int anchormap_copy(struct tier *tier, unsigned long *new_bitmap)
{
	unsigned long flags;

	read_lock_irqsave(&tier->anchormap_lock, flags);
	bitmap_copy(new_bitmap, tier->anchormap, 
		tier->block_num * ANCHOR_BITS);
	read_unlock_irqrestore(&tier->anchormap_lock, flags);

	return 0;
}

static dm_block_t anchormap_search(struct tier *tier, unsigned long size, dm_block_t offset)
{
	unsigned long flags;
	dm_block_t index;

	read_lock_irqsave(&tier->anchormap_lock, flags);
	index = ta_anchormap_search(tier->anchormap, tier->block_num, offset);
	read_unlock_irqrestore(&tier->anchormap_lock, flags);

	return index;
}

static int anchormap_wipe(struct tier *tier)
{
	unsigned long flags;

	write_lock_irqsave(&tier->anchormap_lock, flags);
	bitmap_zero(tier->anchormap, tier->block_num * ANCHOR_BITS);
	write_unlock_irqrestore(&tier->anchormap_lock, flags);

	return 0;
}

static bool anchored_block(struct tier *tier, dm_block_t block)
{
	bool r;
	unsigned long flags;

	read_lock_irqsave(&tier->anchormap_lock, flags);
	r = ta_anchored_block(tier->anchormap, block);
	read_unlock_irqrestore(&tier->anchormap_lock, flags);

	return r;
}

static bool anchor_io(struct bio *bio)
{
	return bio->bi_rw & REQ_ANCHOR;
}

/*
 * FIXEME: Remove Qtier Anchor with shortcut for QTS 4.3.5
 */
static enum anchor get_io_anchor(struct bio *bio)
{
	DMINFO("%s:%d, this function should not be used", __func__, __LINE__);
	BUG_ON(1);

	return 0;
}

static enum alloc_order get_alloc_order_temp(enum temperature temper)
{
	return (enum alloc_order)temper;
}

static enum alloc_order get_alloc_order_anchor(enum anchor anchor)
{
	enum alloc_order r = NORMAL_ALLOC;

	if (anchor != ANCHOR_CLEAR)
		r = (anchor == ANCHOR_HOT ? HOT_ALLOC : COLD_ALLOC);

	return r;
}

static bool anchored_mapping(struct dm_tier_lookup_result *result)
{
	return result->reserve != ANCHOR_CLEAR;
}

static enum anchor get_mapping_achor(struct dm_tier_lookup_result *result)
{
	return (enum anchor)result->reserve;
}

static int generator_map(void *context1, void *context2, void *context3,
	dm_block_t block, struct dm_tier_lookup_result *result)
{
	struct tier *tier = (struct tier *)context1;
	unsigned long *map = (unsigned long *)context2;
	dm_block_t *mapped = (dm_block_t *)context3;

	(*mapped)++;
	ta_store_tierid(tier->tier_map, block, result->tierid);
	__set_dinfo(map, block);
	if (anchored_mapping(result))
		ta_anchormap_store(tier->anchormap, block, get_mapping_achor(result));

	return 0;
}

static int tier_bitmap_scan(struct tier *tier, unsigned long *map, dm_block_t *mapped)
{
	return tier_mapping_walk(tier->tmd, generator_map, tier, map, mapped);
}

static int display_map(void *context1, void *context2, void *context3, 
	dm_block_t block, struct dm_tier_lookup_result *result)
{
	struct tier *tier = (struct tier *)context1;
	int r = 0;
	unsigned dinfo;

	r = get_dinfo(tier->tmd, block, &dinfo);
	if (r)
		return r;

	DMINFO("LBA[%llu] in PBA[%d-%llu] anchor(%d) dinfo(0x%x)",
		block, result->tierid, result->block,
		anchormap_get(tier, block), dinfo);

	return 0;
}

static int tier_bitmap_display(struct tier *tier)
{
	return tier_mapping_walk(tier->tmd, display_map, tier, NULL, NULL);
}

static int display_swap_info(struct tier *tier)
{
	int r = 0;
	unsigned int i;
	struct tier_c *tc = tier->tier_ctx;
	dm_block_t free_blks, total_blks, swap_blocks;

	for (i = 0; i < tier->tier_num; i++) {
		if (!is_tier_enable(tc, i))
			continue;

		r = dm_tier_get_swap_blkcnt(tier->tmd, i, &swap_blocks);
		if (r) {
			DMERR("failed to swap block count");
			return r;
		}

		r = dm_tier_get_data_dev_real_size(tier->tmd, i, &total_blks);
		if (r) {
			DMERR("failed to retrieve data device size");
			return r;
		}

		r = dm_tier_get_free_blk_real_cnt(tier->tmd, i, &free_blks);
		if (r) {
			DMERR("failed to retrieve free block count");
			return r;
		}
		DMINFO("tier%d total_blks(%llu) free_blks(%llu) swap_blks(%llu) !!", 
			i, total_blks, free_blks, swap_blocks);
	}
	return r;
}

static int tier_bitmap_copy(struct tier *tier, unsigned long *new_bitmap)
{
	unsigned long flags;

	read_lock_irqsave(&tier->tiermap_lock, flags);
	bitmap_copy(new_bitmap, tier->tier_map, tier->block_num * TIER_BITS);
	read_unlock_irqrestore(&tier->tiermap_lock, flags);

	return 0;
}

static void init_migration_stats(struct tier *tier)
{
	tier->block_num = 0;
	tier->tier_stats = NULL;
	tier->tier_map = NULL;
	tier->anchormap = NULL;
}

static void free_migration_stats(struct tier *tier)
{
	vfree(tier->tier_stats);
	vfree(tier->tier_map);
	vfree(tier->anchormap);
}

static bool tier_blk_size_is_power_of_two(struct tier *tier)
{
	return tier->sector_per_block_shift >= 0;
}

static void init_move_data(struct tier *tier)
{
	unsigned int i;

	for (i = 0; i < tier->tier_num; i++) {
		atomic_set(&tier->tier_stats[i].move_up, 0);
		atomic_set(&tier->tier_stats[i].move_within, 0);
		atomic_set(&tier->tier_stats[i].move_down, 0);
	}
}

static int get_tier_move_data(struct tier *tier, unsigned int tierid, int move_data_type)
{
	atomic_t *move_data = NULL;;

	switch (move_data_type) {
	case MOVE_UP:
		move_data = &tier->tier_stats[tierid].move_up;
		break;
	case MOVE_WITHIN:
		move_data = &tier->tier_stats[tierid].move_within;
		break;
	case MOVE_DOWN:
		move_data = &tier->tier_stats[tierid].move_down;
		break;
	default:
		return 0;
	}

	return atomic_read(move_data);
}

static void inc_tier_move_data(struct tier *tier, unsigned int tierid, int move_data_type)
{
	atomic_t *move_data = NULL;

	switch (move_data_type) {
	case MOVE_UP:
		move_data = &tier->tier_stats[tierid].move_up;
		break;
	case MOVE_WITHIN:
		move_data = &tier->tier_stats[tierid].move_within;
		break;
	case MOVE_DOWN:
		move_data = &tier->tier_stats[tierid].move_down;
		break;
	default:
		return;
	}

	atomic_inc(move_data);
}

static void init_anchor_stat(struct anchor_stat *as)
{
	atomic_set(&as->hot_finish, 0);
	atomic_set(&as->cold_finish, 0);
	atomic_set(&as->hot_total, 0);
	atomic_set(&as->cold_total, 0);
}

static int get_anchor_stat(struct anchor_stat *as, int data_type)
{
	atomic_t *data = NULL;

	switch (data_type) {
	case ANCHOR_HOT_FINISH:
		data = &as->hot_finish;
		break;
	case ANCHOR_COLD_FINISH:
		data = &as->cold_finish;
		break;
	case ANCHOR_HOT_TOTAL:
		data = &as->hot_total;
		break;
	case ANCHOR_COLD_TOTAL:
		data = &as->cold_total;
		break;		
	default:
		return 0;
	}

	return atomic_read(data);
}

static void inc_anchor_stat(struct anchor_stat *as, int data_type)
{
	atomic_t *data = NULL;

	switch (data_type) {
	case ANCHOR_HOT_FINISH:
		data = &as->hot_finish;
		break;
	case ANCHOR_COLD_FINISH:
		data = &as->cold_finish;
		break;
	case ANCHOR_HOT_TOTAL:
		data = &as->hot_total;
		break;
	case ANCHOR_COLD_TOTAL:
		data = &as->cold_total;
		break;		
	default:
		return;
	}

	atomic_inc(data);
}

static dm_block_t get_bio_block(struct tier *tier, struct bio *bio)
{
	sector_t block_nr = bio->bi_iter.bi_sector;

	if (tier_blk_size_is_power_of_two(tier))
		block_nr >>= tier->sector_per_block_shift;
	else
		(void) sector_div(block_nr, tier->sector_per_block);

	return block_nr;
}

/*
 * Returns the _complete_ blocks that this bio covers.
 */
static void get_bio_block_range(struct tier *tier, struct bio *bio,
				dm_block_t *begin, dm_block_t *end)
{
	sector_t b = bio->bi_iter.bi_sector;
	sector_t e = b + (bio->bi_iter.bi_size >> SECTOR_SHIFT);

	b += tier->sector_per_block - 1ull; /* so we round up */

	if (tier_blk_size_is_power_of_two(tier)) {
		b >>= tier->sector_per_block_shift;
		e >>= tier->sector_per_block_shift;
	} else {
		(void) sector_div(b, tier->sector_per_block);
		(void) sector_div(e, tier->sector_per_block);
	}

	if (e < b)
		/* Can happen if the bio is within a single block. */
		e = b;

	*begin = b;
	*end = e;
}

static void build_key(struct tier *tier, dm_block_t b, 
	dm_block_t e, struct dm_cell_key *key)
{
	key->virtual = 2; // Actually this is more like a group ID
	key->dev = 0;
	key->addr_begin = 0;
	key->addr_end = 0 + (e - b);
	key->block_begin = b;
	key->block_end = e;
}

static void build_tier_key(struct tier *tier, dm_block_t b, struct dm_cell_key *key)
{
	build_key(tier, b, b + 1, key);
}

static void inc_tier_io_entry(struct tier *tier, struct bio *bio)
{
	struct dm_tier_endio_hook *h;

	/*
	if (bio->bi_rw & REQ_DISCARD)
		return;
	*/

	h = dm_per_bio_data(bio, sizeof(struct dm_tier_endio_hook));
	h->tier_io_entry = dm_deferred_entry_inc(tier->tier_io_ds);
}


static sector_t convert_tier_address(struct tier *tier, dm_block_t b)
{
	dm_block_t db_fix = b;

	return (tier_blk_size_is_power_of_two(tier))? 
		db_fix << tier->sector_per_block_shift : 
		db_fix * tier->sector_per_block;
}

/**
 * __blkdev_issue_discard_async - queue a discard with async completion
 * @bdev:	blockdev to issue discard for
 * @sector:	start sector
 * @nr_sects:	number of sectors to discard
 * @gfp_mask:	memory allocation flags (for bio_alloc)
 * @flags:	BLKDEV_IFL_* flags to control behaviour
 * @parent_bio: parent discard bio that all sub discards get chained to
 *
 * Description:
 *    Asynchronously issue a discard request for the sectors in question.
 *    NOTE: this variant of blk-core's blkdev_issue_discard() is a stop-gap
 *    that is being kept local to DM thinp until the block changes to allow
 *    late bio splitting land upstream.
 */
static int __blkdev_issue_discard_async(struct block_device *bdev, 
	sector_t sector, sector_t nr_sects, gfp_t gfp_mask, 
	unsigned long flags, struct bio *parent_bio)
{
	struct request_queue *q = bdev_get_queue(bdev);
	int type = REQ_WRITE | REQ_DISCARD;
	unsigned int max_discard_sectors, granularity;
	int alignment;
	struct bio *bio;
	int ret = 0;
	struct blk_plug plug;

	if (!q)
		return -ENXIO;

	if (!blk_queue_discard(q))
		return -EOPNOTSUPP;

	/* Zero-sector (unknown) and one-sector granularities are the same.  */
	granularity = max(q->limits.discard_granularity >> 9, 1U);
	alignment = (bdev_discard_alignment(bdev) >> 9) % granularity;

	/*
	 * Ensure that max_discard_sectors is of the proper
	 * granularity, so that requests stay aligned after a split.
	 */
	max_discard_sectors = min(q->limits.max_discard_sectors, UINT_MAX >> 9);
	max_discard_sectors -= max_discard_sectors % granularity;
	if (unlikely(!max_discard_sectors)) {
		/* Avoid infinite loop below. Being cautious never hurts. */
		return -EOPNOTSUPP;
	}

	if (flags & BLKDEV_DISCARD_SECURE) {
		if (!blk_queue_secdiscard(q))
			return -EOPNOTSUPP;
		type |= REQ_SECURE;
	}

	blk_start_plug(&plug);
	while (nr_sects) {
		unsigned int req_sects;
		sector_t end_sect, tmp;

		/*
		 * Required bio_put occurs in bio_endio thanks to bio_chain below
		 */
		bio = bio_alloc(gfp_mask, 1);
		if (!bio) {
			ret = -ENOMEM;
			break;
		}

		req_sects = min_t(sector_t, nr_sects, max_discard_sectors);

		/*
		 * If splitting a request, and the next starting sector would be
		 * misaligned, stop the discard at the previous aligned sector.
		 */
		end_sect = sector + req_sects;
		tmp = end_sect;
		if (req_sects < nr_sects &&
		    sector_div(tmp, granularity) != alignment) {
			end_sect = end_sect - alignment;
			sector_div(end_sect, granularity);
			end_sect = end_sect * granularity + alignment;
			req_sects = end_sect - sector;
		}

		bio_chain(bio, parent_bio);

		bio->bi_iter.bi_sector = sector;
		bio->bi_bdev = bdev;

		bio->bi_iter.bi_size = req_sects << 9;
		nr_sects -= req_sects;
		sector = end_sect;

		submit_bio(type, bio);

		/*
		 * We can loop for a long time in here, if someone does
		 * full device discards (like mkfs). Be nice and allow
		 * us to schedule out to avoid softlocking if preempt
		 * is disabled.
		 */
		cond_resched();
	}
	blk_finish_plug(&plug);

	return ret;
}

static int issue_discard(struct tier *tier, uint32_t tierid, dm_block_t data_b, 
	dm_block_t data_e, struct bio *parent_bio)
{
	struct tier_c *tier_ctx = tier->tier_ctx;

	sector_t s = convert_tier_address(tier, data_b);
	sector_t len = convert_tier_address(tier, data_e - data_b);

	return __blkdev_issue_discard_async(tier_ctx->tier_dev[tierid]->bdev, s, len,
					    GFP_NOWAIT, 0, parent_bio);
}

static void remap(struct tier *tier, struct bio *bio, dm_block_t block, uint32_t tierid)
{
	sector_t bi_sector = bio->bi_iter.bi_sector;
	struct tier_c *tier_ctx = tier->tier_ctx;

	bio->bi_bdev = tier_ctx->tier_dev[tierid]->bdev;

	if (tier_blk_size_is_power_of_two(tier))
		bio->bi_iter.bi_sector = convert_tier_address(tier, block) |
				(bi_sector & (tier->sector_per_block - 1));
	else
		bio->bi_iter.bi_sector = convert_tier_address(tier, block) +
				 sector_div(bi_sector, tier->sector_per_block);

	if (tierid == SSD_TIER_ID &&
		!(bio->bi_rw & (REQ_DISCARD | REQ_FLUSH | REQ_FUA)))
		set_bit(BIO_TIER_SSD, &bio->bi_flags);

	WARN_ON(bio_flagged(bio, BIO_HINT));
}

static void remap_and_issue(struct tier *tier, struct bio *bio, dm_block_t block, uint32_t tierid)
{
	remap(tier, bio, block, tierid);
	generic_make_request(bio);
}

void wake_tier_worker(struct tier *tier)
{
	queue_work(tier->wq, &tier->worker);
}

static void wake_migrate_worker(struct tier *tier)
{
	queue_work(tier->migration_wq, &tier->migrate_worker);
}

static void cell_error(struct tier *tier,
                       struct dm_bio_prison_cell *cell)
{
	dm_cell_error(tier->prison, cell, -EIO);
	dm_bio_prison_free_cell(tier->prison, cell);
}

static void cell_release_no_holder(struct tier *tier,
				   struct dm_bio_prison_cell *cell,
				   struct bio_list *bios)
{
	dm_cell_release_no_holder(tier->prison, cell, bios);
	dm_bio_prison_free_cell(tier->prison, cell);
}

static void cell_defer_no_holder(struct tier *tier, struct dm_bio_prison_cell *cell)
{
	unsigned long flags;

	spin_lock_irqsave(&tier->lock, flags);
	cell_release_no_holder(tier, cell, &tier->block_pm_bios);
	spin_unlock_irqrestore(&tier->lock, flags);

	wake_tier_worker(tier);
}


static int bio_detain(struct tier *tier, struct dm_cell_key *key, struct bio *bio,
		      struct dm_bio_prison_cell **cell_result)
{
	int r;
	struct dm_bio_prison_cell *cell_prealloc;

	/*
	 * Allocate a cell from the prison's mempool.
	 * This might block but it can't fail.
	 */
	cell_prealloc = dm_bio_prison_alloc_cell(tier->prison, GFP_NOIO);

	r = dm_bio_detain(tier->prison, key, bio, cell_prealloc, cell_result);
	if (r)
		/*
		 * We reused an old cell; we can get rid of
		 * the new one.
		 */
		dm_bio_prison_free_cell(tier->prison, cell_prealloc);

	return r;
}

static void cell_visit_release(struct tier *tier, void (*fn)(void *, struct dm_bio_prison_cell *),
				void *context, struct dm_bio_prison_cell *cell)
{
	dm_cell_visit_release(tier->prison, fn, context, cell);
	dm_bio_prison_free_cell(tier->prison, cell);
}

struct remap_info {
	struct bio_list defer_bios;
	struct bio_list issue_bios;
	struct tier *tier;
	dm_block_t block;
};

static void __inc_remap_and_issue_cell(void *context,
				       struct dm_bio_prison_cell *cell)
{
	struct remap_info *info = context;
	struct bio *bio;

	while ((bio = bio_list_pop(&cell->bios))) {
		if (bio->bi_rw & (REQ_DISCARD | REQ_ANCHOR))
			bio_list_add(&info->defer_bios, bio);
		else {
			inc_tier_io_entry(info->tier, bio);

			/*
			 * We can't issue the bios with the bio prison lock
			 * held, so we add them to a list to issue on
			 * return from this function.
			 */
			bio_list_add(&info->issue_bios, bio);
			algo_update_stats(info->tier->algo, info->block, bio);
		}
	}
}

static void tier_defer_bio(struct tier *tier, struct bio *bio);
static void inc_remap_and_issue_cell(struct tier *tier,
				     struct dm_bio_prison_cell *cell,
				     struct dm_tier_lookup_result *result,
				     dm_block_t block)
{
	struct bio *bio;
	struct remap_info info;

	bio_list_init(&info.defer_bios);
	bio_list_init(&info.issue_bios);
	info.tier = tier;
	info.block = block;

	/*
	 * We have to be careful to inc any bios we're about to issue
	 * before the cell is released, and avoid a race with new bios
	 * being added to the cell.
	 */
	cell_visit_release(tier, __inc_remap_and_issue_cell,
			   &info, cell);

	while ((bio = bio_list_pop(&info.defer_bios)))
		tier_defer_bio(tier, bio);

	while ((bio = bio_list_pop(&info.issue_bios)))
		remap_and_issue(tier, bio, result->block, result->tierid);
}

static struct dm_tier_new_mapping *mapping_alloc(struct tier *tier)
{
	struct dm_tier_new_mapping *m = NULL;

	m = mempool_alloc(tier->migrate_mapping_pool, GFP_ATOMIC);
	if (!m)
		return NULL;

	memset(m, 0, sizeof(struct dm_tier_new_mapping));
	INIT_LIST_HEAD(&m->list);

	return m;
}

static struct dm_tier_trim_info *trim_info_alloc(struct tier *tier)
{
	struct dm_tier_trim_info *info = NULL;

	info = mempool_alloc(tier->trim_info_pool, GFP_ATOMIC);
	if (!info)
		return NULL;

	memset(info, 0, sizeof(struct dm_tier_trim_info));
	INIT_LIST_HEAD(&info->list);

	return info;
}

static void queue_trim_info(struct dm_tier_trim_info *info)
{
	unsigned long flags;
	struct tier *tier = info->tier;
	
	spin_lock_irqsave(&tier->lock, flags);
	list_add_tail(&info->list, &tier->prepared_trims);
	spin_unlock_irqrestore(&tier->lock, flags);

	wake_tier_worker(tier);
}

static void trim_endio(struct bio *bio, int err)
{
	/*
	 * It doesn't matter if the passdown discard failed, we still want
	 * to unmap (we ignore err).
	 */
	queue_trim_info(bio->bi_private);
	bio_put(bio);
}

static int issue_tier_trim(struct tier *tier, 
	uint32_t tid, dm_block_t begin, dm_block_t end)
{
	int r = 0;
	dm_block_t tier_begin, tier_end;
	struct bio *discard_parent;
	struct dm_tier_trim_info *info;

	if (!check_tier_discard_passdown(tier, tid))
		return r;

	while (begin != end) {
		info = trim_info_alloc(tier);
		if (!info)
			return -ENOMEM;

		r = dm_tier_find_unmapped_alloc_swap_and_blk(tier->tmd, tid,
			begin, end, &tier_begin, &tier_end);
		if (r) {
			mempool_free(info, tier->trim_info_pool);
			DMINFO("%s:%d, fail to find unmapped rage and inc count",
				__func__, __LINE__);
			return r;
		}

		/*
		 * the region blocks are all mapped, or lack of swap space
		 */
		if (tier_begin == tier_end) {
			 if (tier_end != end) 
			 	msleep(100);
			mempool_free(info, tier->trim_info_pool);
			goto next_run;
		}

		info->tier = tier;
		info->tid = tid;
		info->tier_begin = tier_begin;
		info->tier_end = tier_end;

		discard_parent = bio_alloc(GFP_NOIO, 1);
		if (!discard_parent) {
			DMWARN("unable to allocate parent discard bio. Skipping it.");
			queue_trim_info(info);
		} else {
			discard_parent->bi_end_io = trim_endio;
			discard_parent->bi_private = info;

			r = issue_discard(tier, tid, tier_begin, 
				tier_end, discard_parent);

			bio_endio(discard_parent, r);			
		}

next_run:
		begin = tier_end;
	}

	return r;
}

static void process_prepared_trims(struct tier *tier)
{
	unsigned long flags;
	struct list_head trims;
	struct dm_tier_trim_info *info, *tmp;
	int r = 0;

	INIT_LIST_HEAD(&trims);
	spin_lock_irqsave(&tier->lock, flags);
	list_splice_init(&tier->prepared_trims, &trims);
	spin_unlock_irqrestore(&tier->lock, flags);

	list_for_each_entry_safe(info, tmp, &trims, list) {
		r = dm_tier_remove_swap_dec_range(tier->tmd, 
			info->tid, info->tier_begin, info->tier_end);
		if (r)
			DMINFO("%s:%d, dec data range failed", __func__, __LINE__);

		list_del(&info->list);
		mempool_free(info, tier->trim_info_pool);
	}
}

static void passdown_endio(struct bio *bio, int err)
{
	bio_endio(bio->bi_private, err);
	bio_put(bio);
}

/*
 * FIXME: DM local hack to defer parent bios's end_io until we
 * _know_ all chained sub range discard bios have completed.
 * Will go away once late bio splitting lands upstream!
 */
static inline void __bio_inc_remaining(struct bio *bio)
{
	bio->bi_flags |= (1 << BIO_CHAIN);
	smp_mb__before_atomic();
	atomic_inc(&bio->__bi_remaining);
}

static void break_up_discard_bio(struct tier *tier,
	dm_block_t begin, dm_block_t end, struct bio *bio)
{
	int r;
	dm_block_t virt_begin, virt_end, data_begin;
	uint32_t tid;
	struct bio *discard_parent;

	while (begin != end) {
		r = dm_tier_find_mapped_range(tier->tmd, begin,
			end, &virt_begin, &virt_end, &data_begin, &tid);
		if (r)
			/*
			 * Silently fail, letting any mappings we've
			 * created complete.
			 */
			break;

		if (!check_tier_discard_passdown(tier, tid)) {
			begin = virt_end;
			continue;
		}

		discard_parent = bio_alloc(GFP_NOIO, 1);
		if (!discard_parent)
			DMWARN("unable to allocate top level discard bio for passdown.  Skipping passdown.");
		else {
			__bio_inc_remaining(bio);

			discard_parent->bi_end_io = passdown_endio;
			discard_parent->bi_private = bio;

			r = issue_discard(tier, tid, data_begin,
				data_begin + (virt_end - virt_begin), discard_parent);

			bio_endio(discard_parent, r);
		}

		begin = virt_end;
	}
}

static void process_discard_cell(struct tier *tier, struct dm_bio_prison_cell *cell)
{
	struct bio *bio = cell->holder;
	struct dm_tier_endio_hook *h = dm_per_bio_data(bio, sizeof(struct dm_tier_endio_hook));

	/*
	 * The cell will only get freed once the origin bio completes.
	 * This means it will remain locked while all the individual
	 * passdown bios are in flight.
	 */
	h->cell = cell;

	inc_tier_io_entry(tier, bio);
	break_up_discard_bio(tier, cell->key.block_begin, cell->key.block_end, bio);

	/*
	 * We complete the bio now, knowing that the bi_remaining field
	 * will prevent completion until the sub range discards have
	 * completed.
	 */
	bio_endio(bio, 0);	
}

#define RETRY_TIMES 3

static int must_alloc_block(struct tier *tier, uint32_t old_tierid, uint32_t new_tierid, dm_block_t *block)
{
	int r, retry = 0;

retry:
	r = dm_tier_alloc_blk_remove_swap(tier->tmd, old_tierid, new_tierid, block);
	if (r == -ENOSPC && !retry) {
		retry = 1;
		dm_tier_commit_metadata(tier->tmd);
		goto retry;
	}

	return r;
}

static int must_alloc_swap_blk(struct tier *tier, uint32_t tierid, dm_block_t *block)
{
	int r, retry = 0;

retry:
	r = dm_tier_alloc_swap_block(tier->tmd, tierid, block);
	if (r == -ENOSPC && !retry) {
		retry = 1;
		dm_tier_commit_metadata(tier->tmd);
		goto retry;
	}

	return r;

}

static int must_alloc_lower_block(struct tier *tier, uint32_t *tierid, dm_block_t *block)
{
	int r, retry = 0;

retry:
	r = dm_tier_alloc_lower_block(tier->tmd, tierid, tier->tier_ctx->enable_map, block);
	if (r == -ENOSPC && !retry) {
		retry = 1;
		dm_tier_commit_metadata(tier->tmd);
		goto retry;
	}

	return r;
}

static int must_alloc_tier_block(struct tier *tier, uint32_t tierid, dm_block_t *block)
{
	int r, retry = 0;

retry:
	r = dm_tier_alloc_block(tier->tmd, tierid, block);
	if (r == -ENOSPC && !retry) {
		retry = 1;
		dm_tier_commit_metadata(tier->tmd);
		goto retry;
	}

	return r;
}

/*
 * When using this function, we definitely have to acquire block.
 */
static int must_find_and_alloc_block(struct tier *tier, 
				     enum alloc_order ao,
				     uint32_t *tierid,
				     dm_block_t *block)
{
	int r, retry = 0;
	bool has_reserve = false;

retry:
	r = dm_tier_find_free_tier_and_alloc(tier->tmd, tierid, ao,
					     tier->tier_ctx->enable_map, block);
	if (r == -ENOSPC) {
		has_reserve = check_reserve(tier);
		if (!has_reserve || !retry) {
			retry = 1;
			dm_tier_commit_metadata(tier->tmd);
			goto retry;
		}

		/*reserve is on and retried, just return error code */
	}

	return r;
}

static int do_promotion(struct tier *tier, struct dm_tier_new_mapping *m)
{
	int r = -EINVAL;
	struct entry *e;
	struct dm_cell_key key;
	struct dm_bio_prison_cell *cell;
	struct dm_tier_lookup_result result;
	struct cache *cache = &tier->cache;
	dm_block_t new_block, block = m->virt_block;

	if (!cache_avaiable_for_promote(cache))
		return -EBUSY;

	build_tier_key(tier, block, &key);
	if (bio_detain(tier, &key, NULL, &cell))
		return -EBUSY;

	e = promote_from_pre_cache(cache, block);
	if (!e)
		goto fail_promote;

	/*
	 * We double-checked if this block is still whick it used to be
	 */
	r = dm_tier_find_block(tier->tmd, block, 1, &result);
	if (r)
		goto fail_found;

	if (m->old.block != result.block ||
		m->old.tierid != result.tierid) {
		r = -EINVAL;
		goto fail_found;
	}

	r = must_alloc_block(tier, m->old.tierid, SSD, &new_block);
	if (r)
		goto fail_found;

	DMDEBUG("%s: promote block %llu from %d:%llu to %d:%llu", __func__,
			block, m->old.tierid, m->old.block, SSD, new_block);
	/*
	 * Copy block to this new lower-level block
	 */
	m->cell = cell;
	m->new.block = new_block;
	m->new.tierid = SSD;
	m->new.reserve = 0;

	cache_migrate_issue(tier, m);

	return 0;

fail_found:
	cache_entry_destroy(cache, e);
fail_promote:
	cell_defer_no_holder(tier, cell);

	return r;
}

static int promote(struct tier *tier, dm_block_t block,
	struct dm_bio_prison_cell *cell, struct dm_tier_lookup_result *old)
{
	struct dm_tier_new_mapping *m;
	struct bio *bio = cell->holder;

	m = mapping_alloc(tier);
	if (!m)
		return -ENOMEM;

	if (mark_entry_promoted(&tier->cache, block)) {
		mempool_free(m, tier->migrate_mapping_pool);
		return -EINVAL;
	}

	m->tier = tier;
	m->virt_block = block;
	m->old = *old;

	inc_tier_io_entry(tier, bio);
	remap_and_issue(tier, bio, m->old.block, m->old.tierid);
	inc_remap_and_issue_cell(tier, cell, old, block);
	cache_wait_for_promote(tier, m);

	return 0;
}

static int demote(struct tier *tier, struct dm_tier_lookup_result *swap)
{
	int r = -EBUSY, retry = 0;
	struct entry *e;
	struct cache *cache = &tier->cache;
	struct dm_cell_key key;
	struct dm_bio_prison_cell *cell;
	struct dm_tier_new_mapping *m;
	bool in_bound = false;

	if (!cache_avaiable_for_demote(cache))
		goto resource_busy;

	m = mapping_alloc(tier);
	if (!m) {
		r = -ENOMEM;
		goto resource_busy;
	}

retry_lru:
	e = cache_get_lru(cache);
	if (!e) {
		r = -ENOSPC;
		goto no_lru_entry;
	}

	build_tier_key(tier, e->block, &key);
	if (bio_detain(tier, &key, NULL, &cell)) {
		cache_entry_enqueue(cache, e, false);
		if (retry++ < RETRY_TIMES)
			goto retry_lru;
		else
			goto no_lru_entry;
	}

	/*
	 * Find cache mapping
	 */
	r = dm_tier_find_block(tier->tmd, e->block, 1, &m->old);
	if (r) {
		cache_free(e);
		goto find_block_err;
	}

	if (m->old.tierid != SSD) {
		r = -ENODATA;
		cache_free(e);
		goto find_block_err;
	}

	r = dm_tier_in_reserve(tier->tmd, &m->old, &in_bound);
	if (r || in_bound) {
		r = r ? r : -EBUSY;
		cache_free(e);
		goto find_block_err;
	}

	if (is_cache_disabled(cache)) {
		r = -EBUSY;
		goto alloc_fail;
	}

	r = must_alloc_lower_block(tier, &m->new.tierid, &m->new.block);
	if (r)
		goto alloc_fail;

	DMDEBUG("%s: demote block %llu->%d:%llu to %d:%llu", __func__,
		e->block, m->old.tierid, m->old.block, m->new.tierid, m->new.block);

	/*
	 * Copy block to this new lower-level block
	 */
	m->demote = true;
	m->tier = tier;
	m->virt_block = e->block;
	m->cell = cell;

	cache_migrate_issue(tier, m);
	cache_free(e);

	return 0;

alloc_fail:
	cache_entry_enqueue(cache, e, false);
find_block_err:
	cell_defer_no_holder(tier, cell);
no_lru_entry:
	mempool_free(m, tier->migrate_mapping_pool);
resource_busy:
	/*
	 * Since demotion fails, what we have now should be a swap block from SSD.
	 */
	if (dm_tier_free_swap_block(tier->tmd, swap->tierid, swap->block))
		DMERR("%s: demote free swap block failed", __func__);

	return r;
}

#define NO_DEMOTE_NEEDED 0
#define DEMOTE_REQUIRED 1

static int alloc_cache_block(struct tier *tier, dm_block_t block, 
	struct dm_tier_lookup_result *result)
{
	int r;

	result->tierid = SSD;

	/*
	 * CACHE: allocate from SSD only
	 */
	r = dm_tier_alloc_block(tier->tmd, SSD, &result->block);
	if (r && r != -ENOSPC) {
		DMINFO("%s:%d, Error !! Allocate tier data block fail !!", __func__, __LINE__);
		return r;
	} else if (r == -ENOSPC) {
		/*
		 * CACHE: if allocation fail due to -ENOSPC, we demote block from SSD and remap to swap space first
		 */
		r = must_alloc_swap_blk(tier, SSD, &result->block);
		if (r)
			return r;

		return DEMOTE_REQUIRED;
	}

	return NO_DEMOTE_NEEDED;
}

/*
 * check if SSD #free blocks hits cache-like reserve
 */
static bool hit_reserve(struct tier *tier)
{
	int r = 0;
	dm_block_t free_blks, retain;

	retain = rctrl_get_retain(&tier->rctrl);
	r = dm_tier_get_free_block_count(tier->tmd, SSD, &free_blks);
	if (r) {
		DMERR("failed to retrieve SSD free blks");
		return false;
	}

	return free_blks <= retain;
}

static int cache_alloc(struct tier *tier, struct bio *bio,
	struct dm_tier_lookup_result *result,
	struct dm_bio_prison_cell *cell)
{
	int r = -ENOSPC;
	struct cache *cache = &tier->cache;
	dm_block_t block = get_bio_block(tier, bio);

	r = alloc_cache_block(tier, block, result);
	switch (r) {
		case -ENOSPC:
		case -EBUSY:
			break;
		/*
		 * If no demotion is required or we succeed to demote one SSD block, we remap this bio directly.
		 */
		case DEMOTE_REQUIRED:
			/*
			 * If we need to demote but fail, fallthrough here
			 */
			if (demote(tier, result))
				break;
		case NO_DEMOTE_NEEDED:
			goto finish_alloc;
		default:
			return r;
	}

	r = must_find_and_alloc_block(tier, HOT_ALLOC, &result->tierid, &result->block);
	if (r)
		return r;	

finish_alloc:
	if (result->tierid == SSD && !is_cache_disabled(cache)
		&& !cache_entry_create_and_queue(cache, block, false))
		DMWARN("%s: allocate cache entry failed", __func__);

	r = dm_tier_insert_block(tier->tmd, block, result->block, result->tierid);
	if (r) {
		DMINFO("%s:%d, Error !! Insert tier data block %llu -> %u:%llu fail !!",
			__func__, __LINE__, block, result->tierid, result->block);
		return r;
	}

	DMDEBUG("%s:%d, insert mapping LBA[%llu] to PBA[%u-%llu]", 
		__func__, __LINE__, block, result->tierid, result->block);		

	algo_update_stats(tier->algo, block, bio);
	store_tierid(tier, block, result->tierid);

	inc_tier_io_entry(tier, bio);

	remap_and_issue(tier, bio, result->block, result->tierid);
	inc_remap_and_issue_cell(tier, cell, result, block);

	return 0;
}

static int normal_alloc(struct tier *tier, struct bio *bio,
	struct dm_tier_lookup_result *result,
	struct dm_bio_prison_cell *cell, enum alloc_order ao)
{
	int r = -ENOSPC;
	dm_block_t block = get_bio_block(tier, bio);

	r = must_find_and_alloc_block(tier, ao, &result->tierid, &result->block);
	if (r)
		return r;

	r = dm_tier_insert_block(tier->tmd, block, result->block, result->tierid);
	if (r) {
		DMINFO("%s:%d, Error !! Insert tier data block %llu -> %u:%llu fail !!",
			__func__, __LINE__, block, result->tierid, result->block);
		return r;
	}

	DMDEBUG("%s:%d, insert mapping LBA[%llu] to PBA[%u-%llu]", 
		__func__, __LINE__, block, result->tierid, result->block);

	algo_update_stats(tier->algo, block, bio);
	store_tierid(tier, block, result->tierid);

	inc_tier_io_entry(tier, bio);

	if (anchor_io(bio)) {
		anchormap_store(tier, block, get_io_anchor(bio));
		DMDEBUG("%s:%d, update block %llu anchor as %d !!", __func__, __LINE__, 
			block, get_io_anchor(bio));

		if (bio_flagged(bio, BIO_HINT)) {
			cell_defer_no_holder(tier, cell);
			bio_endio(bio, 0);
			return 0;
		}
	}

	remap_and_issue(tier, bio, result->block, result->tierid);
	inc_remap_and_issue_cell(tier, cell, result, block);	

	return 0;
}

static int tier_new_block(struct tier *tier, struct bio *bio,
	struct dm_tier_lookup_result *result, struct dm_bio_prison_cell *cell)
{
	struct cache *cache = &tier->cache;
	enum alloc_order ao;
	bool hit_res = hit_reserve(tier);

	if (bio_data_dir(bio) == READ) {
		zero_fill_bio(bio);
		cell_defer_no_holder(tier, cell);
		bio_endio(bio, 0);
		return 0;
	}

	if (!bio->bi_iter.bi_size) {
		inc_tier_io_entry(tier, bio);
		cell_defer_no_holder(tier, cell);
		// FIXME: not necessary have 0th tier?
		remap_and_issue(tier, bio, 0, 0);
		return 0;
	}

	/*
	 * CACHE: We will try to cache this if we are dealing with random pattern and cache is enabled.
	 * and SSD tier hits reserve threshold
	 */
	if (hit_res && should_cache(cache, bio) && !anchor_io(bio))
		return cache_alloc(tier, bio, result, cell);

	if (hit_res && !anchor_io(bio))
		ao = COLD_ALLOC;
	else {
		ao = anchor_io(bio) ? 
			get_alloc_order_anchor(get_io_anchor(bio)) : 
			get_alloc_order_temp(get_temper(bio));	
	}

	return normal_alloc(tier, bio, result, cell, ao);
}

static void prepared_swap_reallot(struct tier *tier, struct dm_tier_new_mapping *m)
{
	int r;

	r = dm_tier_insert_block(tier->tmd, m->virt_block, 
		m->new.block, m->new.tierid);
	if (r) {
		DMERR("swap reallot update mapping fail, %llu from %u:%llu to %u:%llu", 
			m->virt_block, m->old.tierid, m->old.block, m->new.tierid, m->new.block);
		return;
	}

	DMDEBUG("swap reallot %llu from %u:%llu to %u:%llu finished",
		m->virt_block, m->old.tierid, m->old.block, m->new.tierid, m->new.block);

	if (atomic_dec_and_test(&tier->migr_data.migration_count))
		complete(&tier->migr_data.complete);
}

static void block_migrate_complete(struct tier *tier);
static void prepared_tier_mapping(struct tier *tier, struct dm_tier_new_mapping *m)
{
	int r;

	if (m->swap_reallot) {
		prepared_swap_reallot(tier, m);
		return;
	}

	if (m->err) {
		/* We should stop the data migration process*/
		process_state_transition(tier, STOP_AUTO_TIERING);

		DMERR("%s: migrate block %llu is error-out",
		      __func__, m->virt_block);
		cell_error(tier, m->cell);
		goto out;
	}

	r = m->demand ? 
		dm_tier_insert_block_check_retain(tier->tmd, m->virt_block, 
			m->new.block, m->new.tierid, m->old) :
		dm_tier_insert_block_free_swap(tier->tmd, m->virt_block, 
			m->new.block, m->new.tierid, m->old);
	if (r) {
		/* We should stop the data migration process*/
		process_state_transition(tier, STOP_AUTO_TIERING);

		DMERR("%s: migratiton block %llu insert mapping fail",
		      __func__, m->virt_block);
		cell_error(tier, m->cell);
		goto out;
	}

	DMDEBUG("Migrate block %llu from %u:%llu to %u:%llu finished",
		m->virt_block, m->old.tierid, m->old.block,
		m->new.tierid, m->new.block);

	store_tierid(tier, m->virt_block, m->new.tierid);
	algo_update_stats(tier->algo, m->virt_block, NULL);
	inc_remap_and_issue_cell(tier, m->cell, &m->new, m->virt_block);

out:
	if (m->demote | m->promote)
		cache_migrate_complete(tier, m);
	else {
		block_migrate_complete(tier);
		inc_tier_move_data(tier, (unsigned int)m->old.tierid, 
			m->new.tierid < m->old.tierid ? MOVE_UP : MOVE_DOWN);
	}
}

static void process_prepared_mapping(struct tier *tier)
{
	unsigned long flags;
	struct list_head mappings;
	struct dm_tier_new_mapping *m, *tmp;

	INIT_LIST_HEAD(&mappings);
	spin_lock_irqsave(&tier->lock, flags);
	list_splice_init(&tier->prepared_mappings, &mappings);
	spin_unlock_irqrestore(&tier->lock, flags);

	list_for_each_entry_safe(m, tmp, &mappings, list) {
		prepared_tier_mapping(tier, m);
		list_del(&m->list);
		mempool_free(m, tier->migrate_mapping_pool);
	}
}

static void process_prepared_gc(struct tier *tier)
{
	int r;
	unsigned long flags;
	struct list_head discards;
	struct dm_tier_new_mapping *m, *tmp;

	INIT_LIST_HEAD(&discards);
	spin_lock_irqsave(&tier->lock, flags);
	list_splice_init(&tier->prepared_discards, &discards);
	spin_unlock_irqrestore(&tier->lock, flags);

	list_for_each_entry_safe(m, tmp, &discards, list) {
		r = dm_tier_remove_block(tier->tmd, m->virt_block);
		if (r) {
			cell_defer_no_holder(tier, m->cell);
			list_del(&m->list);
			mempool_free(m, tier->migrate_mapping_pool);

			/*
			 * If the space allocation is not via bio
			 * (e.q. thick, fallocate) in dm-thin,
			 * there is no corresponding mapping in tier
			 */
			 if (r != -ENODATA)
				return;

			 continue;
		}

		DMDEBUG("finish removing LBA[%llu] !!", m->virt_block);
		cache_remove(&tier->cache, m->virt_block);
		algo_clear_stats(tier->algo, m->virt_block);
		clear_tierid(tier, m->virt_block);
		cell_defer_no_holder(tier, m->cell);
		list_del(&m->list);
		mempool_free(m, tier->migrate_mapping_pool);
	}
}

static bool in_ssd(struct dm_tier_lookup_result *result)
{
	return result->tierid == SSD;
}

static bool tiering_idle(struct tier *tier)
{
	return get_mstate(&tier->transition_work) == MIG_IDLE;
}

static void tier_defer_cell(struct tier *tier, struct dm_bio_prison_cell *cell);
static void process_cell(struct tier *tier, struct dm_bio_prison_cell *cell)
{
	int r;
	struct bio *bio = cell->holder;
	struct dm_tier_lookup_result result;
	dm_block_t block = get_bio_block(tier, bio);
	enum anchor old_anchor, new_anchor;

	r = dm_tier_find_block(tier->tmd, block, 1, &result);
	switch (r) {
	case -ENODATA:
		r = tier_new_block(tier, bio, &result, cell);
		if (r == -ENOSPC) {
			/*
			 * block allocation ran into reserve control,
			 * if in DRIVE_OUT mode, we should terminate tiering process
			 */
			turnoff_reserve(tier);
			DMINFO("%s, lack of free for drive_out", __func__);
			process_state_transition(tier, STOP_AUTO_TIERING);
			tier_defer_cell(tier, cell);
		} else if (r)
			cell_error(tier, cell);
		break;
	case 0:
		algo_update_stats(tier->algo, block, bio);
		/*
		 * if SSD, update LRU.
		 * if HDD, check if block is already in pre-cached state. If so, try promoting to SSD.
		 */
		if (!is_cache_disabled(&tier->cache) && 
			!anchored_block(tier, block) && 
			!anchor_io(bio)) {

			if (in_ssd(&result)) {
				cache_reset_lru(&tier->cache, block, 1);
			 } else if (should_cache(&tier->cache, bio) &&
				ready_to_promote(tier, block) &&
				!promote(tier, block, cell, &result))
				break;
		}

		inc_tier_io_entry(tier, bio);

		if (anchor_io(bio)) {
			new_anchor = get_io_anchor(bio);
			old_anchor = anchormap_get(tier, block);

			if (new_anchor != old_anchor) {
				anchormap_store(tier, block, new_anchor);
				DMDEBUG("update tier blk %llu -> %u:%llu anchor %d !!",
					block, result.tierid, result.block, new_anchor);
			}

			if (bio_flagged(bio, BIO_HINT)) {
				cell_defer_no_holder(tier, cell);
				bio_endio(bio, 0);
				return;
			}
		}

		remap_and_issue(tier, bio, result.block, result.tierid);
		inc_remap_and_issue_cell(tier, cell, &result, block);
		break;
	default:
		cell_error(tier, cell);
		break;
	}
}

static void process_tier_deferred_cells(struct tier *tier)
{
	unsigned long flags;
	struct list_head cells;
	struct dm_bio_prison_cell *cell, *tmp;

	INIT_LIST_HEAD(&cells);

	spin_lock_irqsave(&tier->lock, flags);
	list_splice_init(&tier->deferred_cells, &cells);
	spin_unlock_irqrestore(&tier->lock, flags);

	if (list_empty(&cells)) {
		return;
	}

	list_for_each_entry_safe(cell, tmp, &cells, user_list) {

		list_del(&cell->user_list);

		if (cell->holder->bi_rw & REQ_DISCARD)
			process_discard_cell(tier, cell);
		else
			process_cell(tier, cell);

	}
}

static void process_discard_bio(struct tier *tier, struct bio *bio)
{
	dm_block_t begin, end;
	struct dm_cell_key key;
	struct dm_bio_prison_cell *cell;

	get_bio_block_range(tier, bio, &begin, &end);
	if (begin == end) {
		/*
		 * The discard covers less than a block.
		 */
		bio_endio(bio, 0);
		return;
	}

	build_key(tier, begin, end, &key);
	if (bio_detain(tier, &key, bio, &cell))
		/*
		 * Potential starvation issue: We're relying on the
		 * fs/application being well behaved, and not trying to
		 * send IO to a region at the same time as discarding it.
		 * If they do this persistently then it's possible this
		 * cell will never be granted.
		 */
		return;

	process_discard_cell(tier, cell);
}

static void process_bio(struct tier *tier, struct bio *bio)
{
	struct dm_cell_key key;
	struct dm_bio_prison_cell *cell;
	dm_block_t block = get_bio_block(tier, bio);

	build_tier_key(tier, block, &key);
	if (bio_detain(tier, &key, bio, &cell))
		return;

	process_cell(tier, cell);
}

static void process_tier_deferred_bios(struct tier *tier)
{
	unsigned long flags;
	struct bio *bio;
	struct bio_list bios;
	struct blk_plug plug;

	bio_list_init(&bios);

	spin_lock_irqsave(&tier->lock, flags);
	bio_list_merge(&bios, &tier->block_pm_bios);
	bio_list_init(&tier->block_pm_bios);
	spin_unlock_irqrestore(&tier->lock, flags);

	if (bio_list_empty(&bios))
		return;

	blk_start_plug(&plug);
	while ((bio = bio_list_pop(&bios))) {

		if (bio->bi_rw & REQ_DISCARD)
			process_discard_bio(tier, bio);
		else
			process_bio(tier, bio);
	}
	blk_finish_plug(&plug);
}

static void process_tier_deferred_works(struct tier *tier)
{
	process_tier_deferred_cells(tier);
	process_tier_deferred_bios(tier);
}

static int scan_map(struct tier *tier, dm_block_t flt_idx)
{
	int r = 0;
	dm_block_t index = 0 ;
	dm_block_t size = tier->block_num - (flt_idx << FILTER_REVISE) ;
	struct dm_cell_key key;
	struct dm_bio_prison_cell *cell;
	unsigned dinfo;
	unsigned long *map;

	size = size < (1 << FILTER_REVISE) ? size : (1 << FILTER_REVISE);
	DMDEBUG("%s:%d, search map start addr(%llu) with size(%llu) !!", __func__, __LINE__,
		flt_idx * FLTR_TO_LONG, size);

	r = clone_map(tier->tmd, flt_idx * FLTR_TO_LONG, size, &map);
	if (r)
		return r;

	for (; index < size; index++) {
		struct dm_tier_new_mapping *m;
		dm_block_t block;

		index = map_search(map, size, index);
		if (index >= size)
			break;

		if (__get_dinfo(map, index) != MAP_MASK)
			continue;

		block = (flt_idx << FILTER_REVISE) + index;
		build_tier_key(tier, block, &key);
		if (bio_detain(tier, &key, NULL, &cell)) {
			r = -EBUSY;
			continue;
		}

		r = check_dinfo(tier->tmd, block, &dinfo);
		if (r) {
			DMERR_LIMIT("gc check dinfo failed");
			cell_defer_no_holder(tier, cell);
			break;
		}

		if (dinfo == MAP_MASK) {
			m = mapping_alloc(tier);
			if (!m) {
				r = -ENOMEM;
				DMERR_LIMIT("gc memory allocate failed");
				cell_defer_no_holder(tier, cell);
				break;
			}

			m->tier = tier;
			m->discard = true;
			m->virt_block = block;
			m->cell = cell;

			DMDEBUG("%s:%d, start removing LBA[%llu] !!", __func__, __LINE__, block);
			if (!dm_deferred_set_add_work(tier->tier_io_ds, &m->list))
				tier_defer_task(tier, m);
			continue;
		}

		cell_defer_no_holder(tier, cell);
	}

	vfree(map);
	return r;
}

static void do_garbage_collect(struct work_struct *ws)
{
	struct tier *tier = container_of(to_delayed_work(ws), struct tier, discard_worker);
	dm_block_t index = 0;
	dm_block_t fsize = DIV_ROUND_UP(tier->block_num,
				(dm_block_t)1 << FILTER_REVISE);
	int bypass = atomic_read(&tier->bypass_tier);
	int r = 0;

	if (!atomic_read(&tier->enable_discard) || bypass != TIER_BYPASS_OFF)
		goto requeue;

	for (index = 0; index < fsize; index++) {
		if (filter_search(tier->tmd, fsize, index, &index)) {
			DMERR_LIMIT("gc filter search failed");
			return;
		}

		if (index >= fsize)
			break;

		DMDEBUG("%s:%d, scan filter(%llu) !!", __func__, __LINE__, index);
		r = scan_map(tier, index);
		if (r == -EBUSY) {
			if (check_and_reset_filter(tier->tmd, index)) {
				DMERR_LIMIT("gc check and reset filter failed");
				return;
			}
		} else if (r) {
			DMERR_LIMIT("gc scan map failed");
			return;
		}
	}

requeue:
	queue_delayed_work(tier->discard_wq, &tier->discard_worker, COMMIT_PERIOD);
}

static void do_commander(struct work_struct *ws)
{
	struct commander *cmndr = container_of(to_delayed_work(ws), struct commander, dwork);
	struct tier *tier = container_of(cmndr, struct tier, cmndr);
	unsigned long now = get_seconds();
	int bypass = atomic_read(&tier->bypass_tier);

	if (bypass != TIER_BYPASS_OFF || !atomic_read(&tier->stats_switch))
		goto cmndr_depart;

	if (now - cmndr->last_opt < cmndr->learn_wind)
		goto cmndr_depart;

	must_stop_migrate(tier);
	process_state_transition(tier, AUTO_TIERING);
	cmndr->last_opt = now;

cmndr_depart:
	queue_delayed_work(tier->cmndr_wq, &cmndr->dwork, HZ);
}

static void do_tier_worker(struct work_struct *ws)
{
	struct tier *tier = container_of(ws, struct tier, worker);

	gate_lock(&tier->gate, &tier->block_pm_bios, &tier->deferred_cells);
	process_prepared_mapping(tier);
	process_prepared_gc(tier);
	process_prepared_trims(tier);
	process_tier_deferred_works(tier);
	gate_unlock(&tier->gate);
}

static void tier_defer_bio(struct tier *tier, struct bio *bio)
{
	unsigned long flags;

	spin_lock_irqsave(&tier->lock, flags);
	bio_list_add(&tier->block_pm_bios, bio);
	spin_unlock_irqrestore(&tier->lock, flags);

	wake_tier_worker(tier);
}

static void tier_defer_cell(struct tier *tier, struct dm_bio_prison_cell *cell)
{
	unsigned long flags;

	spin_lock_irqsave(&tier->lock, flags);
	list_add_tail(&cell->user_list, &tier->deferred_cells);
	spin_unlock_irqrestore(&tier->lock, flags);

	wake_tier_worker(tier);
}

static void tier_hook_bio(struct tier *tier, struct bio *bio)
{
	struct dm_tier_endio_hook *h = dm_per_bio_data(bio, sizeof(struct dm_tier_endio_hook));

	h->tier = tier;
	h->tier_io_entry = NULL;
	h->cell = NULL;
}

static bool check_tier_discard_passdown(struct tier *tier, unsigned int tierid)
{
	return (tier->tier_ctx->discard_passdown & (0x1 << tierid)) ? true : false;
}

static int tier_bio_bypass_map(struct tier *tier, struct bio *bio, dm_block_t block, int bypass)
{
	bool discard_passdown = check_tier_discard_passdown(tier, (unsigned int)bypass);

	if (((bio->bi_rw & REQ_DISCARD) && !discard_passdown) || bio_flagged(bio, BIO_HINT)) {
		bio_endio(bio, 0);
		return DM_MAPIO_SUBMITTED;
	}

	remap(tier, bio, block, (uint32_t)bypass);
	return DM_MAPIO_REMAPPED;
}

int tier_bio_map(struct tier *tier, struct bio *bio)
{
	int r, bypass = atomic_read(&tier->bypass_tier);
	dm_block_t block = get_bio_block(tier, bio);
	struct dm_tier_lookup_result result;
	struct dm_bio_prison_cell *cell;
	struct dm_cell_key key;
	struct cache *cache = &tier->cache;

	tier_hook_bio(tier, bio);

	if (bypass != TIER_BYPASS_OFF)
		return tier_bio_bypass_map(tier, bio, block, bypass);

	/* DM-TIERING: We bypass REQ_FUA in this layer */
	if (bio->bi_rw & (REQ_DISCARD | REQ_ANCHOR)) {
		tier_defer_bio(tier, bio);
		return DM_MAPIO_SUBMITTED;
	} else if (bio->bi_rw & REQ_FLUSH) {
		remap(tier, bio, 0, dm_bio_get_target_bio_nr(bio));
		return DM_MAPIO_REMAPPED;
	}

	/*
	 * CACHE: detect I/O pattern, 
	  * only for file with aware_io extended attribue
	 */
	if (aware_io(bio))
		cache_examine_bio(cache, bio);

	build_tier_key(tier, block, &key);
	if (bio_detain(tier, &key, bio, &cell))
		return DM_MAPIO_SUBMITTED;

	r = dm_tier_find_block(tier->tmd, block, 0, &result);
	switch (r) {
	case 0:
		/*
		 * if SSD, update LRU.
		 * if HDD, check if we need to cache this and increase
		 * access count accordingly
		 */
		if (!is_cache_disabled(cache) && !anchored_block(tier, block)) {
			if (in_ssd(&result)) {
				if (cache_reset_lru(cache, block, 0) == -EWOULDBLOCK)
					goto defer_bio;
			} else if (should_cache(cache, bio))
				goto defer_bio;
		}

		algo_update_stats(tier->algo, block, bio);
		inc_tier_io_entry(tier, bio);
		cell_defer_no_holder(tier, cell);
		remap(tier, bio, result.block, result.tierid);
		return DM_MAPIO_REMAPPED;
defer_bio:
	case -EWOULDBLOCK:
	case -ENODATA:
		tier_defer_cell(tier, cell);
		return DM_MAPIO_SUBMITTED;
	default:
		DMERR("%s: find block return error code %d", __func__, r);
		bio_io_error(bio);
		cell_defer_no_holder(tier, cell);
		return DM_MAPIO_SUBMITTED;
	}
}

static void tier_defer_task(struct tier *tier, struct dm_tier_new_mapping *m)
{
	unsigned long flags;

	spin_lock_irqsave(&tier->lock, flags);
	list_add(&m->list, m->discard ?
		&tier->prepared_discards : &tier->prepared_migrates);
	spin_unlock_irqrestore(&tier->lock, flags);

	m->discard ? wake_tier_worker(tier) : wake_migrate_worker(tier);
}

int tier_endio(struct dm_target *ti, struct bio *bio, int err)
{
	struct list_head work;
	struct dm_tier_new_mapping *m, *tmp;
	struct dm_tier_endio_hook *h = dm_per_bio_data(bio, sizeof(struct dm_tier_endio_hook));
	struct tier *tier = h->tier;

	if (h->tier_io_entry) {
		INIT_LIST_HEAD(&work);
		dm_deferred_entry_dec(h->tier_io_entry, &work);

		if (!list_empty(&work)) {
			list_for_each_entry_safe(m, tmp, &work, list) {
				list_del_init(&m->list);
				tier_defer_task(tier, m);
			}
		}
	}

	if (h->cell)
		cell_defer_no_holder(tier, h->cell);

	return 0;
}

void tier_resume(struct tier *tier)
{
	struct cache *cache = &tier->cache;
	struct commander *cmndr = &tier->cmndr;

	queue_delayed_work(cache->wq, &cache->pioneer, atomic_read(&cache->period) * HZ);
	queue_delayed_work(tier->discard_wq, &tier->discard_worker, COMMIT_PERIOD);
	queue_delayed_work(tier->cmndr_wq, &cmndr->dwork, HZ);
}

void tier_postsuspend(struct tier *tier)
{
	struct commander *cmndr = &tier->cmndr;

	must_stop_migrate(tier);
	turnoff_reserve(tier);

	cancel_delayed_work_sync(&tier->discard_worker);
	flush_workqueue(tier->discard_wq);

	cancel_delayed_work_sync(&cmndr->dwork);
	flush_workqueue(tier->cmndr_wq);

	stop_cache(&tier->cache);
}

int parse_tier_settings(struct dm_arg_set *as, unsigned *argc, 
	char *arg_name, struct dm_target *ti, void **context)
{
	int r;
	char *temp = arg_name;
	struct tier_c *tc;
	unsigned int i = 0, j;

	tc = *context = kzalloc(sizeof(struct tier_c), GFP_KERNEL);
	if (!tc) {
		ti->error = "Insufficient memory";
		return -ENOMEM;
	}

	init_tier_context(tc);

	strsep(&temp, ":");
	r = kstrtouint(strsep(&temp,":"), 10, &(tc->tier_num));
	if (r || tc->tier_num <= 0 || tc->tier_num > MAX_TIER_LEVEL) {
		ti->error = "Incorrect tier num";
		goto free_tc;
	}

	tc->tier_dev = kmalloc(tc->tier_num * sizeof(struct dm_dev *), GFP_KERNEL);
	if (!tc->tier_dev) {
		ti->error = "No memory for tiering device structure";
		r = -ENOMEM;
		goto free_tc;
	}

	for (i = 0; i < tc->tier_num; i++) {
		arg_name = (char *)dm_shift_arg(as);
		(*argc)--;

		r = dm_get_device(ti, arg_name, FMODE_READ | FMODE_WRITE, &tc->tier_dev[i]);
		if (r) {
			ti->error = "Error getting tiering device";
			goto tier_error;
		}
	}

	tc->tier_blk_size = TIER_BLK_SIZE;
	return r;

tier_error:
	for (j = 0; j < i; j++)
		dm_put_device(ti, tc->tier_dev[j]);
	kfree(tc->tier_dev);

free_tc:
	kfree(tc);
	return r;
}

static int parse_tier_enableMap(char *arg_name, struct dm_target *ti, struct tier_c *tc)
{
	int r;
	char *temp = arg_name;

	if (!tc)
		return -EINVAL;

	strsep(&temp, ":");
	r = kstrtouint(strsep(&temp,":"), 10, &tc->enable_map);
	if (r) {
		ti->error = "Tier enable map";
		return r;
	}

	DMDEBUG("%s: enable_map = %u.", __func__, tc->enable_map);
	return r;
}

static int set_bypass_off(struct tier_c *tc)
{
	if (!tc)
		return -EINVAL;

	tc->bypass = false;
	return 0;
}

int parse_tier_features(struct dm_arg_set *as, unsigned *argc, 
	char *arg_name, struct dm_target *ti, void *context)
{
	int r = -EINVAL;

	if (!strncasecmp(arg_name, "enable_map:", 11))
		r = parse_tier_enableMap(arg_name, ti, (struct tier_c *)context);
	else if (!strcasecmp(arg_name, "bypass_off"))
		r = set_bypass_off((struct tier_c *)context);

	if (r)
		tier_ctx_dtr(ti, (struct tier_c *)context);

	return r;
}

static int get_tier_dev_size_info(struct tier *tier, unsigned int tierid, 
	dm_block_t *free_blks, dm_block_t *alloc_blks, dm_block_t *total_blks)
{
	int r = 0;

	r = dm_tier_get_data_dev_size(tier->tmd, tierid, total_blks);
	if (r) {
		DMERR("failed to retrieve data device size");
		return r;
	}

	r = dm_tier_get_free_block_count(tier->tmd, tierid, free_blks);
	if (r) {
		DMERR("failed to #free blks");
		return r;
	}

	(*alloc_blks) = (*total_blks) - (*free_blks);
	return 0;
}

/*----------------------------------------------------------------*/

struct dm_sysfs_attr {
	struct attribute attr;
	ssize_t (*show)(struct tier *, char *);
	ssize_t (*store)(struct tier *, const char *, size_t);
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

static ssize_t dm_attr_show(struct kobject *kobj, struct attribute *attr,
                            char *page)
{
	struct dm_sysfs_attr *dm_attr;
	struct tier *tier;
	ssize_t ret;

	dm_attr = container_of(attr, struct dm_sysfs_attr, attr);
	if (!dm_attr->show)
		return -EIO;

	tier = container_of(kobj, struct tier, kobj);
	ret = dm_attr->show(tier, page);

	return ret;
}

static ssize_t dm_attr_store(struct kobject *kobj, struct attribute *attr,
                             const char *buf, size_t count)
{
	struct dm_sysfs_attr *dm_attr;
	struct tier *tier;
	ssize_t ret;

	dm_attr = container_of(attr, struct dm_sysfs_attr, attr);
	if (!dm_attr->show)
		return -EIO;

	tier = container_of(kobj, struct tier, kobj);
	ret = dm_attr->store(tier, buf, count);

	return ret;
}

static ssize_t dm_attr_tier_statistics_show(struct tier *tier, char *buf)
{
	int total, processed;
	unsigned int i = 0, r = 0;
	unsigned long alloc_tier;

	if (!tier_migrateable(tier) ||
		dm_tier_get_alloc_tier(tier->tmd, &alloc_tier))
		return -EIO;

	sprintf(buf + strlen(buf), "Allocate Tier - Tier%lu\n", alloc_tier);

	for (i = 0; i < tier->tier_num; i++) {
		dm_block_t free_blks = 0, alloc_blks = 0, total_blks = 0;

		if (!is_tier_enable(tier->tier_ctx, i))
			continue;

		r = get_tier_dev_size_info(tier, i, &free_blks, &alloc_blks, &total_blks);
		if (r)
			return r;

		sprintf(buf + strlen(buf), "Tier %d free blocks: %llu blocks\n", i, free_blks);
		sprintf(buf + strlen(buf), "Tier %d allocated blocks: %llu blocks\n", i, alloc_blks);
		sprintf(buf + strlen(buf), "Tier %d total_blks blocks: %llu blocks\n", i, total_blks);
		sprintf(buf + strlen(buf), "Tier %d data move up: %d blocks\n", 
			i, get_tier_move_data(tier, i, MOVE_UP));
		sprintf(buf + strlen(buf), "Tier %d data move within: %d blocks\n", 
			i, get_tier_move_data(tier, i, MOVE_WITHIN));
		sprintf(buf + strlen(buf), "Tier %d data move down: %d blocks\n", 
			i, get_tier_move_data(tier, i, MOVE_DOWN));
	}

	progress_get(&tier->progress, &total, &processed);
	sprintf(buf + strlen(buf), "Migration Progress: %d/%d \n", processed, total);
	return strlen(buf);
}

static ssize_t dm_attr_migration_status_show(struct tier *tier, char *buf)
{
	sprintf(buf, state_name[get_mstate(&tier->transition_work)]);

	 return strlen(buf);
}

static ssize_t dm_attr_auto_tiering_setting_show(struct tier *tier, char *buf)
{
	if (!tier_migrateable(tier))
		return -EINVAL;

	sprintf(buf, "%d\n", atomic_read(&tier->stats_switch));

	return strlen(buf);
}

static ssize_t dm_attr_auto_tiering_setting_store(struct tier *tier, const char *buf, size_t count)
{
	int r, temp;

	if (!tier_migrateable(tier))
		return -EINVAL;

	r = kstrtoint(buf, 10, &temp);
	if (r)
		return r;

	atomic_set(&tier->stats_switch, temp);

	return count;
}

static ssize_t dm_attr_migration_num_show(struct tier *tier, char *buf)
{
	if (!tier_migrateable(tier))
		return -EINVAL;

	sprintf(buf, "%d\n", atomic_read(&tier->migration_num));

	return strlen(buf);
}

static ssize_t dm_attr_migration_num_store(struct tier *tier, const char *buf, size_t count)
{
	int r, temp;

	if (!tier_migrateable(tier))
		return -EINVAL;

	r = kstrtoint(buf, 10, &temp);
	if (r)
		return r;

	if (temp <= MIGRATION_MIN + 1)
		return -EINVAL;

	atomic_set(&tier->migration_num, temp);

	return count;
}

static ssize_t dm_attr_tier_info_show(struct tier *tier, char *buf)
{
	sprintf(buf, "Swap space: %sready\n", atomic_read(&tier->swap_not_ready) ? "not " : "");
	sprintf(buf + strlen(buf), "Tier bypass: %s\n",
			atomic_read(&tier->bypass_tier) != TIER_BYPASS_OFF ? "yes" : "no");
	return strlen(buf);
}

static ssize_t dm_attr_tier_algo_show(struct tier *tier, char *buf)
{
	sprintf(buf, "%s\n", dm_tier_algo_get_name(tier->algo));

	return strlen(buf);
}

static ssize_t dm_attr_origin_analysis_show(struct tier *tier, char *buf)
{
	unsigned tid;
	unsigned long i, flags;
	struct score_profiler *sp;

	spin_lock_irqsave(&tier->score_lock, flags);

	sprintf(buf, "SSD utilization %llu%%\n", tier->sco_pf_org[SSD_TIER_ID].ssd_access);
	for (tid = 0; tid < MAX_TIER_LEVEL; tid++) {
		sp = &tier->sco_pf_org[tid];
		if (!sp->p_num)
			continue;

		for (i = 0; i < sp->p_num; i++)
			sprintf(buf + strlen(buf), "%u %lu %llu\n", tid, i + 1, sp->score[i]);
	}

	spin_unlock_irqrestore(&tier->score_lock, flags);
	return strlen(buf);
}

static ssize_t dm_attr_dryrun_analysis_show(struct tier *tier, char *buf)
{
	unsigned tid;
	unsigned long i, flags;
	struct score_profiler *sp;

	spin_lock_irqsave(&tier->score_lock, flags);

	sprintf(buf, "SSD utilization %llu%%\n", tier->sco_pf_drun[SSD_TIER_ID].ssd_access);
	for (tid = 0; tid < MAX_TIER_LEVEL; tid++) {
		sp = &tier->sco_pf_drun[tid];
		if (!sp->p_num)
			continue;

		for (i = 0; i < sp->p_num; i++)
			sprintf(buf + strlen(buf), "%u %lu %llu\n", tid, i + 1, sp->score[i]);
	}

	spin_unlock_irqrestore(&tier->score_lock, flags);
	return strlen(buf);
}

static ssize_t dm_attr_cache_warming_period_show(struct tier *tier, char *buf)
{
	struct cache *cache = &tier->cache;

	sprintf(buf, "%u\n", atomic_read(&cache->period) << 8);

	return strlen(buf);
}

static ssize_t dm_attr_cache_warming_period_store(struct tier *tier,
	const char *buf, size_t count)
{
	int r, temp;
	struct cache *cache = &tier->cache;

	r = kstrtoint(buf, 10, &temp);
	if (r || temp < 256)
		return r;

	atomic_set(&cache->period, temp >> 8);

	return count;
}

static ssize_t dm_attr_cache_promote_threshold_show(struct tier *tier, char *buf)
{
	struct cache *cache = &tier->cache;

	sprintf(buf, "%u\n", atomic_read(&cache->promote_threshold));

	return strlen(buf);
}

static ssize_t dm_attr_cache_promote_threshold_store(struct tier *tier,
	const char *buf, size_t count)
{
	int r, temp;
	struct cache *cache = &tier->cache;

	r = kstrtoint(buf, 10, &temp);
	if (r)
		return r;

	atomic_set(&cache->promote_threshold, temp);

	return count;
}

static ssize_t dm_attr_cache_all_io_show(struct tier *tier, char *buf)
{
	struct cache *cache = &tier->cache;

	sprintf(buf, "%d\n", test_bit(CACHE_ALL_IO, &cache->flags));

	return strlen(buf);
}

static ssize_t dm_attr_cache_all_io_store(struct tier *tier,
		const char *buf,
		size_t count)
{
	int r;
	unsigned int temp;
	struct cache *cache = &tier->cache;

	r = kstrtouint(buf, 10, &temp);
	if (r)
		return r;

	if (!temp)
		clear_bit(CACHE_ALL_IO, &cache->flags);
	else
		set_bit(CACHE_ALL_IO, &cache->flags);

	return count;
}

static ssize_t dm_attr_cache_enabled_show(struct tier *tier, char *buf)
{
	struct cache *cache = &tier->cache;

	sprintf(buf, "%d\n", is_cache_disabled(cache) ? 0 : 1);

	return strlen(buf);
}

static ssize_t dm_attr_cache_enabled_store(struct tier *tier,
		const char *buf,
		size_t count)
{
	int r;
	unsigned int temp;
	struct cache *cache = &tier->cache;

	if (!is_tier_enable(tier->tier_ctx, SSD))
		return -EINVAL;

	r = kstrtouint(buf, 10, &temp);
	if (r)
		return r;

	if (!temp)
		cache_disable(cache);
	else
		cache_enable(cache);

	return count;
}

static ssize_t dm_attr_cache_promote_wait_sec_show(struct tier *tier, char *buf)
{
	struct cache *cache = &tier->cache;

	mutex_lock(&cache->lock);
	sprintf(buf, "%u\n", cache->promote_wait_sec - 1);
	mutex_unlock(&cache->lock);

	return strlen(buf);
}

static ssize_t dm_attr_cache_promote_wait_sec_store(struct tier *tier,
		const char *buf,
		size_t count)
{
	int r;
	unsigned int temp;
	struct cache *cache = &tier->cache;

	r = kstrtouint(buf, 10, &temp);
	if (r)
		return r;

	if (temp > 254)
		return -EINVAL;

	mutex_lock(&cache->lock);
	cache->promote_wait_sec = temp + 1;
	mutex_unlock(&cache->lock);

	return count;
}

static ssize_t dm_attr_cache_statistics_show(struct tier *tier, char *buf)
{
	struct cache *cache = &tier->cache;

	sprintf(buf + strlen(buf), "cache_hit: %ld\n", atomic64_read(&cache->stats.cache_hit));
	sprintf(buf + strlen(buf), "total_io : %ld\n", atomic64_read(&cache->stats.total_io));
	sprintf(buf + strlen(buf), "promote  : %ld\n", atomic64_read(&cache->stats.promote));
	sprintf(buf + strlen(buf), "demote   : %ld\n", atomic64_read(&cache->stats.demote));

	return strlen(buf);
}

static ssize_t dm_attr_learn_window_show(struct tier *tier, char *buf)
{
	struct commander *cmndr = &tier->cmndr;

	sprintf(buf, "%lu\n", cmndr->learn_wind);
	return strlen(buf);
}

static ssize_t dm_attr_learn_window_store(struct tier *tier,
		const char *buf,
		size_t count)
{
	int r;
	unsigned long temp;
	struct commander *cmndr = &tier->cmndr;

	r = kstrtoul(buf, 10, &temp);
	if (r)
		return r;

	cmndr->learn_wind = temp;
	return count;
}

static ssize_t dm_attr_throttle_factor_show(struct tier *tier, char *buf)
{
	struct gate *gate = &tier->gate;

	sprintf(buf, "%d\n", get_gate_factor(gate));
	return strlen(buf);
}

static ssize_t dm_attr_throttle_factor_store(struct tier *tier,
		const char *buf,
		size_t count)
{
	int r;
	unsigned long temp;
	struct gate *gate = &tier->gate;

	r = kstrtoul(buf, 10, &temp);
	if (r)
		return r;

	set_gate_factor(gate, temp);
	return count;
}

static ssize_t dm_attr_throttle_type_show(struct tier *tier, char *buf)
{
	struct gate *gate = &tier->gate;

	sprintf(buf, get_gate_type(gate));
	return strlen(buf);
}

static ssize_t dm_attr_throttle_type_store(struct tier *tier,
		const char *buf,
		size_t count)
{
	struct gate *gate = &tier->gate;

	return set_gate_type(gate, buf) ? -EINVAL : count;
}

static ssize_t dm_attr_anchor_statistics_show(struct tier *tier, char *buf)
{
	struct anchor_stat *as = &tier->anchor_stat;

	sprintf(buf + strlen(buf), "Tier hot anchor progress %d/%d\n", 
		get_anchor_stat(as, ANCHOR_HOT_FINISH), get_anchor_stat(as, ANCHOR_HOT_TOTAL));

	sprintf(buf + strlen(buf), "Tier cold anchor progress %d/%d\n", 
		get_anchor_stat(as, ANCHOR_COLD_FINISH), get_anchor_stat(as, ANCHOR_COLD_TOTAL));	

	return strlen(buf);
}

static ssize_t dm_attr_reserve_status_show(struct tier *tier, char *buf)
{
	int r;
	struct reserve_ctrl *rctrl = &tier->rctrl;
	dm_block_t swap_blocks, retain_free, ratio;
	enum reserve_type rtype = rctrl_get_type(rctrl);
	int rtid = rctrl_get_tierid(rctrl);
	bool has_reserve = false;

	if (rtid == RESERVE_TIER_DISABLE)
		return -EINVAL;

	r = dm_tier_get_swap_blkcnt(tier->tmd, (unsigned int)rtid, &swap_blocks);
	if (r)
		return r;

	r = dm_tier_get_retain_free(tier->tmd, (unsigned int)rtid, &retain_free);
	if (r)
		return r;

	has_reserve = check_reserve(tier);
	sprintf(buf + strlen(buf), "type: %s\n", rctrl_get_type_str(rctrl));
	sprintf(buf + strlen(buf), "tier id: %d\n", rtid);
	sprintf(buf + strlen(buf), "dev size: %llu\n", rctrl_get_dev_size(rctrl));
	sprintf(buf + strlen(buf), "onoff: %s\n", has_reserve ? "on" : "off");
	sprintf(buf + strlen(buf), "retain: %llu\n", rctrl_get_retain(rctrl));
	if (rtype == USAGE_CTRL) {
		ratio = rctrl_get_retain(rctrl) * 100;
		do_div(ratio, rctrl_get_dev_size(rctrl) - swap_blocks);
		sprintf(buf + strlen(buf), "ratio: %llu percent\n", ratio);
	} else {
		sprintf(buf + strlen(buf), "begin: %llu\n", rctrl_get_begin(rctrl));
		sprintf(buf + strlen(buf), "end: %llu\n", rctrl_get_end(rctrl));
	}
	sprintf(buf + strlen(buf), "(swap: %llu)\n", swap_blocks);
	sprintf(buf + strlen(buf), "(retain_free: %llu)\n", retain_free);

	return strlen(buf);
}

static void __tier_destroy(struct tier *tier);

static void dm_tier_kobj_release(struct kobject *kobj)
{
	struct tier *tier = container_of(kobj, struct tier, kobj);

	__tier_destroy(tier);
}

static DM_ATTR_RO(tier_statistics);
static DM_ATTR_RO(migration_status);
static DM_ATTR_WR(auto_tiering_setting);
static DM_ATTR_WR(migration_num);
static DM_ATTR_RO(tier_info);
static DM_ATTR_RO(tier_algo);
static DM_ATTR_RO(origin_analysis);
static DM_ATTR_RO(dryrun_analysis);
static DM_ATTR_WR(cache_warming_period);
static DM_ATTR_WR(cache_promote_threshold);
static DM_ATTR_WR(cache_all_io);
static DM_ATTR_WR(cache_enabled);
static DM_ATTR_RO(cache_statistics);
static DM_ATTR_WR(cache_promote_wait_sec);
static DM_ATTR_WR(learn_window);
static DM_ATTR_WR(throttle_factor);
static DM_ATTR_WR(throttle_type);
static DM_ATTR_RO(anchor_statistics);
static DM_ATTR_RO(reserve_status);

static struct attribute *dm_attrs[] = {
	&dm_attr_tier_statistics.attr,
	&dm_attr_migration_status.attr,
	&dm_attr_auto_tiering_setting.attr,
	&dm_attr_migration_num.attr,
	&dm_attr_tier_info.attr,
	&dm_attr_tier_algo.attr,
	&dm_attr_origin_analysis.attr,
	&dm_attr_dryrun_analysis.attr,
	&dm_attr_cache_warming_period.attr,
	&dm_attr_cache_promote_threshold.attr,
	&dm_attr_cache_all_io.attr,
	&dm_attr_cache_enabled.attr,
	&dm_attr_cache_statistics.attr,
	&dm_attr_cache_promote_wait_sec.attr,
	&dm_attr_learn_window.attr,
	&dm_attr_throttle_factor.attr,
	&dm_attr_throttle_type.attr,
	&dm_attr_anchor_statistics.attr,
	&dm_attr_reserve_status.attr,
	NULL,
};

static const struct sysfs_ops dm_sysfs_ops = {
	.show   = dm_attr_show,
	.store  = dm_attr_store,
};

static struct kobj_type dm_ktype = {
	.sysfs_ops      = &dm_sysfs_ops,
	.default_attrs  = dm_attrs,
	.release = dm_tier_kobj_release,
};

/*----------------------------------------------------------------*/

static void do_migration(struct work_struct *ws);
static void data_migration(struct work_struct *ws);

static struct tier *tier_create(struct tier_c *tc,
				struct dm_tier_metadata *tmd,
				dm_block_t data_size,
				uint32_t thin_blk_size,
				struct kobject *pool_kobj,
				struct workqueue_struct *wq)
{
	int r;
	void *err_p;
	struct tier *tier;
	uint32_t tier_blk_size = tc->tier_blk_size;

	tier = kzalloc(sizeof(*tier), GFP_KERNEL);
	if (!tier) {
		err_p = ERR_PTR(-ENOMEM);
		goto bad_tier;
	}

	tier->sector_per_block = tier_blk_size;
	if (tier_blk_size & (tier_blk_size - 1))
		tier->sector_per_block_shift = -1;
	else
		tier->sector_per_block_shift = __ffs(tier_blk_size);

	tier->migration_wq = alloc_ordered_workqueue("dm-" DM_MSG_PREFIX, WQ_MEM_RECLAIM);
	if (!tier->migration_wq) {
		err_p = ERR_PTR(-ENOMEM);
		goto bad_migration_wq;
	}

	gate_init(&tier->gate);
	INIT_WORK(&tier->migrate_worker, do_migration);

	tier->tier_wq = alloc_ordered_workqueue("dm-" DM_MSG_PREFIX, WQ_MEM_RECLAIM);
	if (!tier->tier_wq) {
		err_p = ERR_PTR(-ENOMEM);
		goto bad_tier_wq;
	}
	INIT_WORK(&tier->tier_worker, data_migration);

	r = init_transition_work(&tier->transition_work);
	if (r) {
		err_p = ERR_PTR(r);
		goto bad_transiton_work;
	}

	tier->cmndr_wq = alloc_ordered_workqueue("dm-" DM_MSG_PREFIX, WQ_MEM_RECLAIM);
	if (!tier->cmndr_wq) {
		err_p = ERR_PTR(-ENOMEM);
		goto bad_cmndr_wq;
	}
	init_commander(&tier->cmndr, do_commander);

	tier->discard_wq = alloc_ordered_workqueue("dm-tier-discard-" DM_MSG_PREFIX, WQ_MEM_RECLAIM);
	if (!tier->discard_wq) {
		err_p = ERR_PTR(-ENOMEM);
		goto bad_discard_wq;
	}

	INIT_DELAYED_WORK(&tier->discard_worker, do_garbage_collect);

	rwlock_init(&tier->tiermap_lock);
	rwlock_init(&tier->anchormap_lock);

	init_migration_stats(tier);
	bio_list_init(&tier->block_pm_bios);

	INIT_LIST_HEAD(&tier->prepared_migrates);
	INIT_LIST_HEAD(&tier->prepared_discards);
	INIT_LIST_HEAD(&tier->prepared_mappings);
	INIT_LIST_HEAD(&tier->prepared_trims);
	INIT_LIST_HEAD(&tier->deferred_cells);

	// PATCH: init new deferred_set pool
	tier->tier_io_ds = dm_deferred_set_create();
	if (!tier->tier_io_ds) {
		err_p = ERR_PTR(-ENOMEM);
		goto bad_tier_io_ds;
	}

	tier->migrate_mapping_pool = mempool_create_slab_pool(MAPPING_POOL_SIZE, 
		_migrate_mapping_cache);
	if (!tier->migrate_mapping_pool) {
		err_p = ERR_PTR(-ENOMEM);
		goto bad_migration_mapping_pool;
	}

	tier->trim_info_pool = mempool_create_slab_pool(MAPPING_POOL_SIZE, 
		_trim_info_cache);
	if (!tier->trim_info_pool) {
		err_p = ERR_PTR(-ENOMEM);
		goto bad_trim_info_pool;
	}	

	tier->prison = dm_bio_prison_create();
	if (!tier->prison) {
		err_p = ERR_PTR(-ENOMEM);
		goto bad_prison;
	}

	tier->wq = wq;

	tier->migrator = dm_kcopyd_client_create(&dm_kcopyd_throttle);
	if (IS_ERR(tier->migrator)) {
		err_p = tier->migrator;
		goto bad_migrate_kcopyd_client;
	}

	r = cache_init(&tier->cache);
	if (r) {
		err_p = ERR_PTR(r);
		goto bad_cache;
	}

	r = kobject_init_and_add(&tier->kobj, &dm_ktype,
	                         pool_kobj, "%s", "tier");
	if (r) {
		err_p = ERR_PTR(r);
		goto bad_kobject;
	}

	INIT_WORK(&tier->worker, do_tier_worker);

	spin_lock_init(&tier->lock);
	spin_lock_init(&tier->score_lock);
	memset(tier->sco_pf_org, 0, sizeof(tier->sco_pf_org));
	memset(tier->sco_pf_drun, 0, sizeof(tier->sco_pf_drun));

	tier->thin_blk_size = thin_blk_size;
	tier->tier_num =0;
	tier->tier_ctx = NULL;
	tier->tmd = tmd;
	atomic_set(&tier->migration_num, MIGRATION_NUM);
	atomic_set(&tier->stats_switch, 1);
	atomic_set(&tier->swap_not_ready, 0);
	atomic_set(&tier->bypass_tier, -1);
	atomic_set(&tier->enable_discard, 1);
	atomic_set(&tier->config_lock, 0);
	rctrl_init(&tier->rctrl);

	(void) do_div(data_size, tier->sector_per_block);

	return tier;

bad_kobject:
	cache_destroy(&tier->cache);
bad_cache:
	dm_kcopyd_client_destroy(tier->migrator);
bad_migrate_kcopyd_client:
	dm_bio_prison_destroy(tier->prison);
bad_prison:
	mempool_destroy(tier->trim_info_pool);
bad_trim_info_pool:
	mempool_destroy(tier->migrate_mapping_pool);
bad_migration_mapping_pool:
	dm_deferred_set_destroy(tier->tier_io_ds);
bad_tier_io_ds:
	destroy_workqueue(tier->discard_wq);
bad_cmndr_wq:
	destroy_transition_work(&tier->transition_work);
bad_transiton_work:
	destroy_workqueue(tier->tier_wq);
bad_discard_wq:
	destroy_workqueue(tier->cmndr_wq);
bad_tier_wq:
	destroy_workqueue(tier->migration_wq);
bad_migration_wq:
	kfree(tier);
bad_tier:
	return err_p;
}

int tier_ctr(struct dm_target *ti, 
	struct kobject *pool_kobj, 
	struct tier **tier, 
	struct tier_c *tc, 
	struct dm_tier_metadata *tmd, 
	int created, 
	uint32_t sectors_per_block, 
	struct workqueue_struct *wq)
{
	int r;

	if (created) {
		*tier = tier_create(tc, tmd, (dm_block_t)ti->len, sectors_per_block, pool_kobj, wq);
		if (IS_ERR(*tier)) {
			DMERR("create tier failed");
			return PTR_ERR(*tier);
		}

		(*tier)->algo = dm_tier_algo_create(DEFAULT_ALGO, &(*tier)->kobj);
		if (IS_ERR((*tier)->algo)) {
			r = PTR_ERR((*tier)->algo);
			goto bad_algo;
		}

	} else {
		dm_tier_algo_get((*tier)->algo);
		kobject_get(&(*tier)->kobj);
	}

	tc->tier = *tier;
	ti->num_flush_bios = tc->tier_num;
	ti->per_bio_data_size = sizeof(struct dm_tier_endio_hook);
	r = dm_set_target_max_io_len(ti, (*tier)->sector_per_block);
	if (r)
		goto bad;

	return 0;

bad:
	dm_tier_algo_put((*tier)->algo);
bad_algo:
	kobject_put(&(*tier)->kobj);
	return r;
}

void tier_io_hints(struct tier *tier, struct queue_limits *limits)
{
	limits->discard_granularity = tier->sector_per_block << SECTOR_SHIFT;
	limits->max_discard_sectors = 2048 * 1024 * 16; /* 16G */
}

static int tier_flush_anchors(struct tier *tier)
{
	unsigned long *map;
	dm_block_t index = 0, size = tier->block_num;
	struct dm_tier_lookup_result result;
	struct dm_bio_prison_cell *cell;
	struct dm_cell_key key;
	int r = 0, retry = 0;
	enum anchor anchor;
	int bypass = atomic_read(&tier->bypass_tier);

	if (bypass != TIER_BYPASS_OFF)
		return r;

	if (!size) { 
		DMERR("%s: try to allocate map with zero size !", __func__);
		return -ENOMEM;
	}

	map = vzalloc(BITS_TO_LONGS(size * TIER_BITS) * sizeof(unsigned long));
	if (!map) {
		DMERR("%s: no memory for flush used map", __func__);
		return -ENOMEM;
	}

	tier_bitmap_copy(tier, map);

	while (1) {
		index = ta_find_next_allocated(map, size, index);

		if (index >= size) {
			if (!retry) {
				r = 0;
				goto free_map;
			} else {
				index = retry = 0;
				continue;
			}
		}

		build_tier_key(tier, index, &key);
		if (bio_detain(tier, &key, NULL, &cell)) {
			index++;
			retry = 1;
			msleep(100);
			continue;
		}

		ta_clear_tierid(map, index);
		r = dm_tier_find_block(tier->tmd, index, 1, &result);
		switch (r) {
			case -ENODATA:
				anchormap_clear(tier, index);
				DMERR_LIMIT("%s:%d, flush anchormap get return code %d !!", 
					__func__, __LINE__, r);
				cell_defer_no_holder(tier, cell);
				break;
			case 0:	
				anchor = anchormap_get(tier, index);
				if (anchor != get_mapping_achor(&result)) {

					r = dm_tier_insert_block_reserve(tier->tmd, index, result.block, result.tierid,
						(uint32_t)anchor);
					if (r) {
						DMINFO("%s:%d, Error !! Insert tier data block %llu -> %u:%llu res %u fail !!",
							__func__, __LINE__, index, result.tierid, result.block, (uint32_t)anchor);
						cell_defer_no_holder(tier, cell);
						goto free_map;
					}

					DMDEBUG("%s:%d, Update tier mapping %llu -> %u:%llu res %u !!", __func__, __LINE__,
						index, result.tierid, result.block, (uint32_t)anchor);					
				}
				cell_defer_no_holder(tier, cell);
				break;
			default:
				cell_defer_no_holder(tier, cell);
				DMERR_LIMIT("%s:%d, find mapping get unexpected return %d !!", 
					__func__, __LINE__, r);				
				goto free_map;	
		}
	}

free_map:
	vfree(map);
	return r;
}

static void __tier_destroy(struct tier *tier)
{
	tier_flush_anchors(tier);

	flush_work(&tier->migrate_worker);
	flush_work(&tier->tier_worker);

	free_migration_stats(tier);

	destroy_workqueue(tier->migration_wq);
	destroy_workqueue(tier->tier_wq);
	destroy_transition_work(&tier->transition_work);
	destroy_workqueue(tier->cmndr_wq);
	destroy_workqueue(tier->discard_wq);

	dm_deferred_set_destroy(tier->tier_io_ds);
	mempool_destroy(tier->trim_info_pool);
	mempool_destroy(tier->migrate_mapping_pool);
	dm_bio_prison_destroy(tier->prison);

	dm_kcopyd_client_destroy(tier->migrator);
	cache_destroy(&tier->cache);

	kfree(tier);
}

void tier_ctx_dtr(struct dm_target *ti, struct tier_c *tier_ctx)
{
	unsigned int i;

	if (!tier_ctx)
		return;

	for (i = 0; i < tier_ctx->tier_num; i++) {
		DMINFO("%s:%d, put device %s !!", __func__, __LINE__, tier_ctx->tier_dev[i]->name);
		dm_put_device(ti, tier_ctx->tier_dev[i]);
	}
	kfree(tier_ctx->tier_dev);
	kfree(tier_ctx);
}

void tier_dtr(struct dm_target *ti, struct tier_c *tier_ctx)
{
	struct tier *tier;

	if (!tier_ctx) {
		DMERR("%s: left", __func__);
		return;
	}

	tier = tier_ctx->tier;
	dm_tier_algo_put(tier->algo);
	kobject_put(&tier->kobj);

	tier_ctx_dtr(ti, tier_ctx);
}

static bool is_factor(sector_t block_size, uint32_t n)
{
	return !sector_div(block_size, n);
}

static bool dev_supports_discard(struct block_device *bdev)
{
	struct request_queue *q = bdev_get_queue(bdev);
	return q && blk_queue_discard(q);
}

static bool passdown_checking(struct tier *tier, struct block_device *data_bdev)
{
	struct queue_limits *data_limits;
	sector_t block_size = tier->sector_per_block << SECTOR_SHIFT;
	const char *reason = NULL;
	char buf[BDEVNAME_SIZE];

	data_limits = &bdev_get_queue(data_bdev)->limits;

	if (!dev_supports_discard(data_bdev))
		reason = "discard unsupported";

	else if (data_limits->max_discard_sectors < tier->sector_per_block)
		reason = "max discard sectors smaller than a block";

	else if (data_limits->discard_granularity > block_size)
		reason = "discard granularity larger than a block";

	else if (!is_factor(block_size, data_limits->discard_granularity))
		reason = "discard granularity not a factor of block size";

	if (reason) {
		DMWARN("Data device (%s) %s: Disabling discard passdown.", bdevname(data_bdev, buf), reason);
		return false;
	}

	return true;
}

void passdown_tier_discard(struct tier_c *tier_ctx)
{
	unsigned int i;
	struct block_device *data_bdev;

	for (i = 0; i < tier_ctx->tier_num; i++) {
		if (!is_tier_enable(tier_ctx, i))
			continue;

		DMDEBUG("%s:%d, %s !!", __func__, __LINE__, tier_ctx->tier_dev[i]->name);
		data_bdev = tier_ctx->tier_dev[i]->bdev;
		if (passdown_checking(tier_ctx->tier, data_bdev))
			tier_ctx->discard_passdown |= (0x1 << i);
	}
}

static void update_bitmap(void **ptr_addr, void **new_addr, uint64_t size)
{
	if (*ptr_addr && size) {
		memcpy(*new_addr, *ptr_addr, size);
		vfree(*ptr_addr);
	}

	*ptr_addr = *new_addr;
}

static dm_block_t get_data_dev_size_in_blocks(struct block_device *bdev, uint32_t data_block_size)
{
	sector_t data_dev_size = i_size_read(bdev->bd_inode) >> SECTOR_SHIFT;
	sector_div(data_dev_size, data_block_size);

	return data_dev_size;
}

static int maybe_resize_migr_stats(struct tier *tier, 
	dm_block_t block_num, dm_block_t *mapped)
{
	int r = 0;
	uint8_t *new_tier_map, *new_anchormap, *temp;
	dm_block_t old_size = tier->block_num;
	unsigned int old_tier_num = tier->tier_num;
	struct tier_c *tier_ctx = tier->tier_ctx;
	struct per_tier_stat *new_stats;
	unsigned long total = BITS_TO_LONGS(block_num * MAP_PACE);
	unsigned long *map;

	/* Always resize algorithm, since we do not know if user switch to new algorithm */
	r = algo_resize(tier->algo, block_num);
	if (r)
		return r;

	if (old_tier_num != tier_ctx->tier_num) {
		tier->tier_num = tier_ctx->tier_num;
		new_stats = vzalloc(tier->tier_num * sizeof(struct per_tier_stat));
		if (!new_stats) {
			DMERR("%s: allocate tier stats failed", __func__);
			return -ENOMEM;
		}
		update_bitmap((void **)&tier->tier_stats, 
			(void **)&new_stats, tier->tier_num * sizeof(struct per_tier_stat));
	}

	/*---- new tier_map ----*/
	new_tier_map = vzalloc(BITS_TO_LONGS(block_num * TIER_BITS) * sizeof(unsigned long));
	if (!new_tier_map) {
		DMERR("%s: allocate migration tier_map failed", __func__);
		return -ENOMEM;
	}

	/*
	 * We need to rescan the tier_map
	 */
	temp = (uint8_t *)tier->tier_map;
	tier->tier_map = (unsigned long *)new_tier_map;
	vfree(temp);

	/*---- new anchor map ----*/
	new_anchormap = vzalloc(BITS_TO_LONGS(block_num * ANCHOR_BITS) * sizeof(unsigned long));
	if (!new_anchormap) {
		DMERR("%s: allocate migration tier_map failed", __func__);
		return -ENOMEM;
	}
	update_bitmap((void **)&tier->anchormap, (void **)&new_anchormap,
		BITS_TO_LONGS(old_size * ANCHOR_BITS) * sizeof(unsigned long));

	/*
	 * new discard map and  scan to 
	 * construct tierid map and anchor map
	 */
	map = vzalloc(total * sizeof(long));
	if (!map) {
		DMWARN("%s: allocation of temp map1 for tier failed", __func__);
		return -ENOMEM;
	}

	(*mapped) = 0;
	r = tier_bitmap_scan(tier, map, mapped);
	if (r)
		goto out;

	r = construct_map(tier->tmd, map, block_num);

out:
	vfree(map);

	return r;
}

static int calculate_swap(struct tier *tier, unsigned int tierid, dm_block_t *swap)
{
	int r = -EINVAL;
	dm_block_t temp;
	struct tier_c *tc = tier->tier_ctx;

	if (!is_tier_enable(tc, tierid))
		goto out;

	*swap = 0;
	r = dm_tier_get_data_dev_real_size(tier->tmd, tierid, &temp);
	if (r) {
		DMINFO("%s:%d, failed to get real device size for tier(%d)", 
			__func__, __LINE__, tierid);
		goto out;
	}

	(void) do_div(temp, SWAP_BLK_RATIO);
	temp = temp > 0 ? temp : 1;
	*swap = (temp < SWAP_BLK_DEFAULT) ? temp : SWAP_BLK_DEFAULT;

out:
	return r;
}

static int swap_reallot_issue(struct tier *tier, unsigned int old_tid, 
	dm_block_t *swap, dm_block_t lower_limit)
{
	int r = 0;
	unsigned int new_tid;
	unsigned long *map;
	dm_block_t index = 0, size = tier->block_num;
	struct dm_tier_lookup_result old, new;
	struct dm_tier_new_mapping *m;
	struct tier_c *tc = tier->tier_ctx;
	struct migration_data *md = &tier->migr_data;

	map = vzalloc(BITS_TO_LONGS(size * TIER_BITS) * sizeof(unsigned long));
	if (!map) {
		DMERR("%s: no memory for reallot used map", __func__);
		return -ENOMEM;
	}

	tier_bitmap_copy(tier, map);
	while (swap[old_tid] < lower_limit) {
		index = ta_find_next_allocated(map, size, index);

		if (index >= size) {
			DMERR("lack of mapping on tier%u", old_tid);
			r = -EINVAL;
			goto free_map;
		} else if (ta_get_tierid(map, index) != old_tid) {
			index++;
			continue;
		}

		for (new_tid = 0; new_tid < tier->tier_num; new_tid++)
			if (is_tier_enable(tc, new_tid) && new_tid != old_tid 
				&& swap[new_tid] > lower_limit)
				break;

		if (new_tid >= tier->tier_num) {
			DMERR("lack of swap reallot candidate for tier%u", old_tid);
			r = -ENOSPC;
			goto free_map;
		}

		r = dm_tier_find_block(tier->tmd, index, 1, &old);
		if (r) {
			DMERR("reallot find mapping error for blk(%llu)", index);
			goto free_map;
		}

		m = mapping_alloc(tier);
		if (!m) {
			WARN_ON(1);
			r = -ENOMEM;
			goto free_map;
		}

		new.tierid = new_tid;
		new.reserve = 0;
		r = must_alloc_swap_blk(tier, new_tid, &new.block);
		if (r) {
			DMERR("reallot fail to allocate swap on tier%d)", new_tid);
			mempool_free(m, tier->migrate_mapping_pool);
			goto free_map;
		}

		atomic_inc(&md->migration_count);
		m->tier = tier;
		m->virt_block = index;
		m->cell = NULL;
		m->new = new;
		m->old = old;
		m->swap_reallot = true;

		cache_remove(&tier->cache, index);

		if (!dm_deferred_set_add_work(tier->tier_io_ds, &m->list))
			tier_defer_task(tier, m);

		DMDEBUG("(swap reallot) migrate block %llu from %u:%llu to %u:%llu", 
			index, old.tierid, old.block, new.tierid, new.block);

		swap[new_tid]--;
		swap[old_tid]++;
		index++;
	}

free_map:
	vfree(map);
	return r;
}

static void wait_for_migrate_complete(struct tier *tier);
static int swap_reallot(struct tier *tier, dm_block_t *swap, dm_block_t lower_limit)
{
	int r = 0;
	unsigned int i;
	struct tier_c *tc = tier->tier_ctx;
	struct migration_data *md = &tier->migr_data;

	atomic_set(&md->migration_count, 1);
	init_completion(&md->complete);

	for (i = 0; i < tier->tier_num; i++) {
		if (!is_tier_enable(tc, i) || swap[i] >= lower_limit)
			continue;

		r = swap_reallot_issue(tier, i, swap, lower_limit);
		if (r)
			break;

		DMINFO("after swap reallot, tier%u has %llu swap", i, swap[i]);
	}

	if (r)
		atomic_or(1, &tier->swap_not_ready);

	wait_for_migrate_complete(tier);
	return r;
}

#define NEED_SWAP_REALLOT 1
static int set_swap(struct tier *tier, dm_block_t *swap, dm_block_t lower_limit)
{
	int r = 0, ret = 0;
	unsigned int i;
	struct tier_c *tc = tier->tier_ctx;

	for (i = 0; i < tier->tier_num; i++) {
		if (!is_tier_enable(tc, i))
			continue;

		if (swap[i] < lower_limit) {
			DMINFO("tier%d swap lower than limit", i);
			ret = NEED_SWAP_REALLOT;
		}

		DMINFO("set tier%d with swap(%llu)", i, swap[i]);
		r = dm_tier_set_swap_block(tier->tmd, i, swap[i]);
		if (r) {
			DMINFO("%s:%d, fail to set swap for tierid(%d)", 
				__func__, __LINE__, i);
			return r;
		}

		if (i == SSD) {
			r = cache_set_max_flier(&tier->cache, swap[i]);
			if (r)
				return r;
		}
	}

	return ret ? ret : r;
}

#define NEED_SWAP_RESCAN 1
static int maybe_resize_swap_space(struct tier *tier, dm_block_t mapped)
{
	int r, retry = 0;
	unsigned int i;
	struct tier_c *tc = tier->tier_ctx;
	unsigned int active_tiers = get_active_tier_num(tc->enable_map);
	dm_block_t nr_zombie = 0, tmp, lower_limit = UINT_MAX;
	dm_block_t total_alloc = 0, total_swap = 0, avg_swap = 0;
	dm_block_t default_swap[MAX_TIER_LEVEL] = {0};
	dm_block_t swap[MAX_TIER_LEVEL] = {0};
	dm_block_t nr_alloc[MAX_TIER_LEVEL] = {0};
	dm_block_t nr_real_free[MAX_TIER_LEVEL] = {0};


	for (i = 0; i < tier->tier_num; i++) {
		if (!is_tier_enable(tc, i))
			continue;

		r = dm_tier_get_allocate_count(tier->tmd, i, nr_alloc + i);
		if (r) {
			DMINFO("%s:%d, fail to get nr_alloc for tierid(%d)", 
				__func__, __LINE__, i);
			return r;
		}

		r = dm_tier_get_free_blk_real_cnt(tier->tmd, i, nr_real_free + i);
		if (r) {
			DMINFO("%s:%d, fail to get nr_real free for tierid(%d)", 
				__func__, __LINE__, i);
			return r;
		}

		r = calculate_swap(tier, i, default_swap + i);
		if (r) {
			DMINFO("%s:%d, fail to calculate swap for tierid(%d)", 
				__func__, __LINE__, i);
			return r;
		}

		total_alloc += nr_alloc[i];
		total_swap += default_swap[i];
		lower_limit = default_swap[i] < lower_limit ?
			default_swap[i] : lower_limit;

		DMINFO("tier%d: nr_real_free(%llu) default_swap(%llu)", 
			i, nr_real_free[i], default_swap[i]);
	}

	nr_zombie = total_alloc > mapped ? total_alloc - mapped : nr_zombie;
	DMINFO("alloc(%llu) mapped(%llu) nr_zombie(%llu) total_swap(%llu)", 
		total_alloc, mapped, nr_zombie, total_swap);

	if (!nr_zombie) {
		DMINFO("zombie non-exist, config swap with lower limit(%llu)", lower_limit);
		memcpy(swap, default_swap, sizeof(swap));
		goto config_swap;
	}

	r = dm_tier_set_zombie_exist(tier->tmd);
	if (r)
		return r;

	if (nr_zombie > total_swap - active_tiers) {
		atomic_or(1, &tier->swap_not_ready);
		DMINFO("Due to abnormal shutdown, pool is overwhelmed by zombie blks");
		return r;
	}

	total_swap -= nr_zombie;
	avg_swap = total_swap;
	do_div(avg_swap, active_tiers);
	DMINFO("After cover zombie, total_swap(%llu) avg_swap(%llu)", total_swap, avg_swap);

	i = 0;
	while(total_swap) {
		if (i >= MAX_TIER_LEVEL && retry)
			break;

		if (i >= MAX_TIER_LEVEL && !retry) {
			i = 0;
			retry = 1;
			continue;
		}

		if (!is_tier_enable(tc, i)) {
			i++;
			continue;
		}

		if (!retry) {
			tmp = min(nr_real_free[i], avg_swap);
			tmp = min(tmp, total_swap);
		} else
			tmp = min(nr_real_free[i] - swap[i], total_swap);

		total_swap -= tmp;
		swap[i] += tmp;
		DMINFO("tier%u extend swap to %llu, total_swap remain %llu", 
			i, swap[i], total_swap);
		i++;
	}

	if (total_swap) {
		BUG_ON(1);
		return -EINVAL;
	}

	lower_limit = avg_swap < SWAP_LOW_LIMIT ?
		avg_swap : SWAP_LOW_LIMIT;
	DMINFO("zombie exist, config swap with lower limit(%llu)", lower_limit);

config_swap:
	r = set_swap(tier, swap, lower_limit);
	if (r == NEED_SWAP_REALLOT) {
		r = swap_reallot(tier, swap, lower_limit);
		r = r ? r :  NEED_SWAP_RESCAN;
	}

	return r;
}

static bool need_bypass_tier(struct tier_c *tc)
{
	return tc->bypass ;
}

int maybe_resize_tier_data_dev(struct dm_target *ti, struct tier *tier, bool *need_commit)
{
	int r = 0;
	unsigned int i, last_tier_enabled = TIER_BYPASS_OFF;
	sector_t data_size = ti->len;
	uint32_t data_block_size = tier->sector_per_block;
	dm_block_t tier_data_size, mapped = 0;
	struct tier_c *tc = tier->tier_ctx;

	*need_commit = false;

	(void) sector_div(data_size, tier->sector_per_block);

	for (i = 0; i < tc->tier_num; i++) {
		if (!is_tier_enable(tc, i)) {
			DMDEBUG("%s:%d, Do not resize tier data device fot tier %d !!", __func__, __LINE__, i);
			continue;
		}

		last_tier_enabled = i;
		tier_data_size = get_data_dev_size_in_blocks(tc->tier_dev[i]->bdev, data_block_size);
		DMDEBUG("%s:%d, tier_data_dev[%d] extends to %llu blocks for block_size = %lu", 
			__func__, __LINE__, i, tier_data_size, data_block_size);

		r = dm_tier_resize_data_dev(tier->tmd, i, tier_data_size);
		if (r) {
			DMERR("failed to resize tier data device");
			return r;
		}
	}

	if (need_bypass_tier(tc)) {
		atomic_set(&tier->bypass_tier, (int)last_tier_enabled);
		atomic_or(1, &tier->swap_not_ready);
		goto finish;
	}

retry:
	r = maybe_resize_migr_stats(tier, (dm_block_t)data_size, &mapped);
	if (r)
		return r;

	r = dm_tier_commit_metadata(tier->tmd);
	if (r)
		return r;

	tier->block_num = (dm_block_t)data_size;

	r = maybe_resize_swap_space(tier, mapped);
	if (r == NEED_SWAP_RESCAN)
		goto retry;
	else if (r)
		return r;

	if (!is_tier_enable(tier->tier_ctx, SSD_TIER_ID))
		goto finish;

	r = config_reserve_with_ratio(tier, SSD_TIER_ID, DEFAULT_RESERVE_RATIO);
	if (r)
		return r;

finish:
	*need_commit = true;
	return 0;
}

/*
 * For now, we do not use this since we need to free tier context in tier_ctr
 */
void bind_tier_to_context(struct tier *tier, struct tier_c *tc)
{
	tier->tier_ctx = tc;
}

int tier_iterate_devices(struct tier_c *tc, struct dm_target *ti,
				iterate_devices_callout_fn fn, void *data)
{
	int ret = 0;
	unsigned int i = 0;

	do {
		if (!is_tier_enable(tc, i))
			continue;
		ret = fn(ti, tc->tier_dev[i], 0, get_data_dev_size_in_blocks(tc->tier_dev[i]->bdev, 1), data);
	} while (!ret && ++i < tc->tier_num);

	return ret;
}

int tier_merge(struct tier_c *tc, struct dm_target *ti, struct bvec_merge_data *bvm,
		      struct bio_vec *biovec, int max_size)
{
	int tmp;
	unsigned int i;
	struct request_queue *q;

	bvm->bi_sector &= (tc->tier_blk_size - 1);
	tmp = max_size;
	for (i = 0; i < tc->tier_num; i++) {
		if (is_tier_enable(tc, i)) {
			q = bdev_get_queue(tc->tier_dev[i]->bdev);
			if (!q->merge_bvec_fn)
				continue;

			bvm->bi_bdev = tc->tier_dev[i]->bdev;
			tmp = min(tmp, q->merge_bvec_fn(q, bvm, biovec));
		}
	}

	return tmp;
}

void emit_tier_flags(struct tier_c *tc, char *result,
		       unsigned *size, unsigned maxlen, unsigned *count)
{
	unsigned int i;
	unsigned sz = *size;
	char buf[BDEVNAME_SIZE];

	if(!tc->bypass)
		*count += tc->tier_num + 3;
	else
		*count += tc->tier_num + 2;

	DMEMIT("%u ", *count);
	DMEMIT("TIER:%d ", tc->tier_num);
	for (i = 0; i < tc->tier_num; i++)
		DMEMIT("%s ", format_dev_t(buf, tc->tier_dev[i]->bdev->bd_dev));

	DMEMIT("enable_map:%d ", tc->enable_map);
	if(!tc->bypass)
		DMEMIT("bypass_off ");
	*size = sz;
}

int tier_is_congested(struct tier_c *tc, struct dm_target_callbacks *cb, int bdi_bits)
{
	int i, r = 0;
	struct request_queue *q;

	for (i=0; i < tc->tier_num; i++) {
		q = bdev_get_queue(tc->tier_dev[i]->bdev);
		r |= bdi_congested(&q->backing_dev_info, bdi_bits);
	}

	return r;
}

static int init_analyze_data(struct tier *tier, struct analyze_data **adata)
{
	int r, shrink = 0;
	struct analyze_data *ad;
	dm_block_t total = 0, mappings = 0;
	unsigned int i, rtid = rctrl_get_tierid(&tier->rctrl);
	enum reserve_type rtype = rctrl_get_type(&tier->rctrl);
	dm_block_t retain = rctrl_get_retain(&tier->rctrl);

	ad = *adata = kzalloc(sizeof(struct analyze_data), GFP_KERNEL);
	if (!ad) {
		DMERR("%s: no memory for analyze_data", __func__);
		return -ENOMEM;
	}

	ad->tier_num = tier->tier_ctx->tier_num;
	ad->total_block_num = tier->block_num;
	ad->block_from = vzalloc(BITS_TO_LONGS(tier->block_num * TIER_BITS)
				 * sizeof(unsigned long));
	if (!ad->block_from) {
		DMERR("%s: no memory for adata->block_from", __func__);
		goto bad_adata_bf;
	}

	ad->block_to = vzalloc(BITS_TO_LONGS(tier->block_num * TIER_BITS)
			       * sizeof(unsigned long));
	if (!ad->block_to) {
		DMERR("%s: no memory for adata->block_to", __func__);
		goto bad_adata_bt;
	}

	ad->anchormap = vzalloc(BITS_TO_LONGS(tier->block_num * ANCHOR_BITS) * sizeof(unsigned long));
	if (!ad->anchormap) {
		DMERR("%s: no memory for adata->anchormap", __func__);
		goto bad_adata_am;
	}

	ad->block_info = vzalloc(tier->block_num *
				 sizeof(struct per_block_info));
	if (!ad->block_info) {
		DMERR("%s: no memory for adata->block_info", __func__);
		goto bad_adata_bl;
	}

	if (cluster_set_init(&ad->set)) {
		DMERR("%s: cluster set init error", __func__);
		goto bad_cs_init;
	}

	/*
	 * Take a snapshot of current tier_map
	 */
	tier_bitmap_copy(tier, ad->block_from);

	for (i = 0; i < MAX_TIER_LEVEL; i++) {
		if (!is_tier_enable(tier->tier_ctx, i))
			ad->block_num[i] = 0;
		else {
			r = dm_tier_get_data_dev_size(tier->tmd, i, &ad->block_num[i]);
			if (r)
				goto bad_set_adata_bn;

			total += ad->block_num[i];
			DMINFO("block_num[%u] = %llu", i, ad->block_num[i]);
		}
	}

	anchormap_copy(tier, ad->anchormap);
	ad->dryrun = get_mstate(&tier->transition_work) == MIG_DRUN_ALGO;

	mappings = ta_get_mapping_count(ad->block_from, tier->block_num);
	shrink = mappings - (total - retain);
	DMINFO("shrink = %d mappings = %llu total = %llu retain = %llu", 
		shrink, mappings, total, retain);

	if (shrink > 0) {
		if (rtype == USAGE_CTRL) {
			rctrl_sub_retain(&tier->rctrl, shrink);
		} else {
			r = -ENOSPC;
			DMINFO("forbidden zone can't be satisified");
			goto bad_set_adata_bn;
		}
	}

	if (rtid != RESERVE_TIER_DISABLE) {
		ad->block_num[rtid] -= rctrl_get_retain(&tier->rctrl);
		DMINFO("block_num[%u] = %llu", rtid, ad->block_num[rtid]);
	}

	migration_stack_init(&ad->stack);
	if (test_and_clear_bit(MIGR_ANCHORS_ONLY, &tier->flags)) {
		set_bit(MIGR_ANCHORS_ONLY, &ad->flags);
		smp_mb__after_atomic();
	}

	return 0;

bad_set_adata_bn:
	cluster_set_reclaim(&ad->set);
bad_cs_init:
	vfree(ad->block_info);
bad_adata_bl:
	vfree(ad->anchormap);
bad_adata_am:
	vfree(ad->block_to);
bad_adata_bt:
	vfree(ad->block_from);
bad_adata_bf:
	kfree(ad);
	*adata = NULL;

	return -ENOMEM;
}

static void free_analyze_data(struct analyze_data *adata)
{
	migration_stack_reclaim(&adata->stack);
	cluster_set_reclaim(&adata->set);
	vfree(adata->block_info);
	vfree(adata->anchormap);
	vfree(adata->block_to);
	vfree(adata->block_from);
	kfree(adata);
}

static void free_migration_data(struct tier *tier)
{
	free_analyze_data(tier->migr_data.adata);
	tier->migr_data.adata = NULL;
}

static int get_migration_goal(struct tier *tier)
{
	int r;
	struct migration_data *md = &tier->migr_data;
	enum reserve_type rtype = rctrl_get_type(&tier->rctrl);

	init_move_data(tier);

	if (rtype == DRIVE_OUT) {
		/*
		 * wait for cache complete,
		 * to make sure the swap status
		 */
		cache_disable(&tier->cache);
		gate_wait_unlock(&tier->gate);
		stop_cache(&tier->cache);

		r = turnon_reserve(tier);
		if (r)
			return r;

		/*
		 * disable discard, and wait on-fly-IO for one round,
		 * make sure we would not miss any blk in forbidden region
		 */
		atomic_set(&tier->enable_discard, 0);
		gate_wait_unlock(&tier->gate);
	}

	r = init_analyze_data(tier, &md->adata);
	if (r)
		goto fail_init_ad;

	atomic_set(&md->migration_count, 1);
	init_completion(&md->complete);

	r = algo_analyze(tier->algo, md->adata);
	if (r)
		goto fail_algo_analyze;

	progress_start(&tier->progress, md->adata->total_migrate_block);
	return 0;

fail_algo_analyze:
	free_migration_data(tier);
fail_init_ad:
	turnoff_reserve(tier);
	return r;
}

static bool reach_max_migrate_io(struct tier *tier)
{
	return atomic_read(&tier->migr_data.migration_count) >=
		atomic_read(&tier->migration_num);
}

static int available_migrations(struct tier *tier)
{
	return atomic_read(&tier->migration_num) 
		- atomic_read(&tier->migr_data.migration_count);
}

static void block_migrate_complete(struct tier *tier)
{
	struct migration_data *md = &tier->migr_data;

	if (atomic_dec_and_test(&tier->migr_data.migration_count))
		complete(&tier->migr_data.complete);

	if (available_migrations(tier) && waitqueue_active(&md->wait_for_migrate))
		wake_up(&md->wait_for_migrate);
}

static int check_migration_status(struct tier *tier,
				  struct per_block_info *info,
				  struct dm_tier_lookup_result *result,
				  struct dm_bio_prison_cell **cell)
{
	int r;
	struct dm_cell_key key;
	struct analyze_data *ad = tier->migr_data.adata;
	uint32_t old_tierid = ta_get_tierid(ad->block_from, info->index);
	uint32_t new_tierid = ta_get_tierid(ad->block_to, info->index);
	bool in_bound = false;

	if (reach_max_migrate_io(tier))
		return MIGRATE_FULL;

	build_tier_key(tier, info->index, &key);
	if (bio_detain(tier, &key, NULL, cell))
		return -EBUSY;

	atomic_inc(&tier->migr_data.migration_count);
	r = dm_tier_find_block(tier->tmd, info->index, 1, result);
	if (r) {
		DMDEBUG("%s:%d, LBA[%u] mapping is already removed !!",
			__func__, __LINE__, info->index);
		goto release_cell;
	}

	r = dm_tier_in_reserve(tier->tmd, result, &in_bound);
	if (r)
		goto release_cell;

	if (in_bound)
		return IN_BOUND;

	if (result->tierid != old_tierid) {
		DMDEBUG("LBA[%u] at tier%u but reallocated at PBA[%d-%llu] !!",
			info->index, old_tierid, result->tierid, result->block);

		r = -ENODATA;
		goto release_cell;
	}

	if (old_tierid == new_tierid) {
		r = -EINVAL;
		goto release_cell;
	}

	return r;

release_cell:
	cell_defer_no_holder(tier, *cell);
	atomic_dec(&tier->migr_data.migration_count);

	return r;
}

static int get_dest_tier(struct tier *tier, struct per_block_info *info, uint32_t *dest_tier)
{
	struct tier_c *tc = tier->tier_ctx;
	unsigned int enable_map = tc->enable_map, i;
	struct analyze_data *ad = tier->migr_data.adata;
	uint32_t old_tierid;
	uint32_t new_tierid;

	old_tierid = ta_get_tierid(ad->block_from, info->index);
	new_tierid = ta_get_tierid(ad->block_to, info->index);

	enable_map &= ~(unsigned int)(1 << old_tierid | 1 << new_tierid);
	for (i = 0; i < tc->tier_num; i++) {
		if (enable_map & (1 << i)) {
			*dest_tier = (uint32_t)i;
			return 0;
		}
	}

	return -ENODEV;
}

static int cancel_tiering(struct tier *tier)
{
	enum mstate m = get_mstate(&tier->transition_work);

	return (m == MIG_CNL_WAIT || m == MIG_SPND_WAIT 
		|| m == MIG_RECALCULATE);
}

static void wait_for_migrate_complete(struct tier *tier)
{
	if (!atomic_dec_and_test(&tier->migr_data.migration_count))
		wait_for_completion(&tier->migr_data.complete);

	atomic_set(&tier->migr_data.migration_count, 1);
	init_completion(&tier->migr_data.complete);
}

static int demand_migrate_block(struct tier *tier, 
				struct per_block_info *info,
				dm_block_t *swap_shortage)
{
	int r;
	struct dm_tier_new_mapping *m;
	struct dm_cell_key key;
	struct dm_bio_prison_cell *cell;
	dm_block_t new_block;
	struct dm_tier_lookup_result result;
	struct analyze_data *ad = tier->migr_data.adata;
	uint32_t new_tierid;
	enum alloc_order ao;
	bool on_reserve_tier = false, in_bound = false;

	if (reach_max_migrate_io(tier))
		return -EBUSY;

	build_tier_key(tier, info->index, &key);
	if (bio_detain(tier, &key, NULL, &cell))
		return -EBUSY;

	atomic_inc(&tier->migr_data.migration_count);
	r = dm_tier_find_block(tier->tmd, info->index, 1, &result);
	if (r) {
		WARN_ON(r != -ENODATA);
		goto release_cell;
	}

	r = dm_tier_on_reserve_tid(tier->tmd, &result, &on_reserve_tier);
	if (r || !on_reserve_tier) {
		r = r ? r : -ENODATA;
		goto release_cell;
	}

	r = dm_tier_in_reserve(tier->tmd, &result, &in_bound);
	if (r)
		goto release_cell;

	if (!in_bound && !swap_shortage) {
		r = OUT_OF_BOUND;
		goto release_cell;
	}

	m = mapping_alloc(tier);
	if (!m) {
		WARN_ON(1);
		r = -ENOMEM;
		goto release_cell;
	}

	/* use target tid as allocation hint*/
	ao = (enum alloc_order)ta_get_tierid(ad->block_to, info->index);
	r = must_find_and_alloc_block(tier, ao, &new_tierid, &new_block);
	if (r) {
		WARN_ON(r != -ENOSPC);
		goto release_mapping;
	}

	if (new_tierid != ta_get_tierid(ad->block_to, info->index))
		DMDEBUG("blk%u->%u:%llu intend to tier%u but forced to tier%u",
			info->index, result.tierid,  result.block,
			ta_get_tierid(ad->block_to, info->index), new_tierid);

	m->tier = tier;
	m->virt_block = info->index;
	m->cell = cell;
	m->new.block = new_block;
	m->new.tierid = new_tierid;
	m->new.reserve = 0;
	m->old = result;
	m->demand = true;

	if (!in_bound && swap_shortage)
		(*swap_shortage)--;

	cache_remove(&tier->cache, info->index);

	if (!dm_deferred_set_add_work(tier->tier_io_ds, &m->list))
		tier_defer_task(tier, m);

	DMDEBUG("%s, demand block %u from %d:%llu to %u:%llu !!!", __func__, 
		info->index, result.tierid, result.block, new_tierid, new_block);

	return 0;

release_mapping:
	mempool_free(m, tier->migrate_mapping_pool);
release_cell:
	cell_defer_no_holder(tier, cell);
	atomic_dec(&tier->migr_data.migration_count);
	return r;
}

static int migrate_block_demand_mode(struct tier *tier,
				     struct per_block_info *info,
				     dm_block_t *swap_shortage)
{
	struct analyze_data *ad = tier->migr_data.adata;
	int r = 0;

	r = demand_migrate_block(tier, info, swap_shortage);
	DMDEBUG("%s:%d, demand entry: %u get r(%d) !!",
		__func__, __LINE__, info->index, r);
	switch (r) {
	case -ENODATA:
	case 0:
		progress_update(&tier->progress);
		break;
	case -ENOSPC:
		turnoff_reserve(tier);
		DMINFO("%s, lack of free for drive_out", __func__);
		process_state_transition(tier, STOP_AUTO_TIERING);
	case -EBUSY:
	case OUT_OF_BOUND:
		cluster_set_add(&ad->set, info);
		msleep(100);
		break;
	default:
		return r;
	}

	return r;
}

static void update_anchor_status(struct anchor_stat *as, 
	dm_block_t index, unsigned long *anchormap)
{
	enum anchor anchor;

	BUG_ON(!anchormap);

	anchor = ta_anchormap_get(anchormap, index);

	inc_anchor_stat(as, anchor == ANCHOR_HOT ? 
		ANCHOR_HOT_FINISH : ANCHOR_COLD_FINISH);
}

static int chain_migrate_block(struct tier *tier, struct per_block_info *info)
{
	struct analyze_data *ad = tier->migr_data.adata;
	struct dm_bio_prison_cell *cell;
	struct dm_tier_lookup_result result;
	uint32_t dest_tier, new_tierid;
	struct per_block_info *next_info;
	unsigned int active_tiers;
	struct dm_tier_new_mapping *m;
	dm_block_t new_block;
	int r;
	bool in_bound = false;

	new_tierid = ta_get_tierid(ad->block_to, info->index);
	active_tiers = get_active_tier_num(tier->tier_ctx->enable_map);

	r = check_migration_status(tier, info, &result, &cell);
	if (r && r != IN_BOUND) {
		WARN_ON(r != -EBUSY && r !=-ENODATA 
			&& r != MIGRATE_FULL && r != -EINVAL);
		return r;
	}

	in_bound = (r == IN_BOUND);
	m = mapping_alloc(tier);
	if (!m) {
		r = -ENOMEM;
		WARN_ON(1);
		goto release_entry;
	}

	if (in_bound)
		r = must_alloc_tier_block(tier, new_tierid, &new_block);
	else
		r = must_alloc_block(tier, result.tierid, new_tierid, &new_block);

	if (!r)
		goto migrate_entry;
	else if (r != -ENOSPC) {
		WARN_ON(r != -EBUSY);
		r = r == -EBUSY ? NO_SWAP : r;
		goto free_mapping;
	}

	if (migration_stack_len(&ad->stack) >= active_tiers - 1) {
		r = -ENODEV;
		goto free_mapping;
	}

	r = get_dest_tier(tier, info, &dest_tier);
	if (r)
		goto free_mapping;

	next_info = cluster_set_match_and_get(&ad->set, 
		ad->block_from, ad->block_to, new_tierid, dest_tier);
	if (!next_info) {
		r = -ENODEV;
		goto free_mapping;
	}

	migration_stack_push(&ad->stack, info);
	migration_stack_push(&ad->stack, next_info);

	r = -ENOSPC;
	goto free_mapping;

migrate_entry:
	m->tier = tier;
	m->virt_block = info->index;
	m->cell = cell;
	m->new.block = new_block;
	m->new.tierid = new_tierid;
	m->new.reserve = 0;
	m->old = result;
	m->demand = in_bound;

	cache_remove(&tier->cache, info->index);

	if (!dm_deferred_set_add_work(tier->tier_io_ds, &m->list))
		tier_defer_task(tier, m);

	DMDEBUG("%s, (chain) (%s) migrate blk %u from %d:%llu to %u:%llu !!!", 
		__func__, m->demand ? "demand" : "not demand", info->index,
		result.tierid, result.block, new_tierid, new_block);
	return 0;


free_mapping:
	mempool_free(m, tier->migrate_mapping_pool);
release_entry:
	cell_defer_no_holder(tier, cell);
	atomic_dec(&tier->migr_data.migration_count);

	return r;
}

static int migrate_block_chain_mode(struct tier *tier)
{
	struct migration_data *md = &tier->migr_data;
	struct analyze_data *ad = tier->migr_data.adata;
	struct per_block_info *info;
	struct dm_bio_prison_cell *cell;
	struct dm_tier_lookup_result result;
	int r;

	while (!cancel_tiering(tier)) {
		int len = 0, i;
		DEFINE_WAIT(wait);

		info = migration_stack_pop(&ad->stack);
		if (!info)
			return 0;

		r = chain_migrate_block(tier, info);
		DMDEBUG("%s:%d, chain migrate : %u get r(%d) !!", 
			__func__, __LINE__, info->index, r);
recheck:
		switch (r) {
		case IN_BOUND:
			migrate_block_demand_mode(tier, info, NULL);
			break;
		case -ENOSPC:
			WARN_ON(migration_stack_len(&ad->stack) < STACK_MIN);
			break;
		case -ENODEV:	
			len = migration_stack_len(&ad->stack);
			for (i = len+1 ; i > 1;  i--) {
				cluster_set_add(&ad->set, info);
				info = migration_stack_pop(&ad->stack);
			}

			/*
			 * we need to check if the botton task in the reserve range
			 */
			r = check_migration_status(tier, info, &result, &cell);
			if (!r || r == IN_BOUND) {
				cell_defer_no_holder(tier, cell);
				atomic_dec(&tier->migr_data.migration_count);
			}

			if (r)
				goto recheck;

			progress_update(&tier->progress);
			break;
		case -EINVAL:
			/*
			 * Remove the un-moved block from cache entry
			 */
			cache_remove(&tier->cache, info->index);
		case -ENODATA:
			if (ta_anchormap_get(ad->anchormap, info->index)) {
				update_anchor_status(&tier->anchor_stat, 
					info->index, ad->anchormap);
				ta_anchormap_clear(ad->anchormap, info->index);
			}
			progress_update(&tier->progress);
			break;
		case 0:
			if (ta_anchormap_get(ad->anchormap, info->index)) {
				update_anchor_status(&tier->anchor_stat, 
					info->index, ad->anchormap);
				ta_anchormap_clear(ad->anchormap, info->index);
			}
			progress_update(&tier->progress);
			wait_for_migrate_complete(tier);
			break;
		case MIGRATE_FULL:
			migration_stack_push(&ad->stack, info);
			do {
				prepare_to_wait(&md->wait_for_migrate,
					&wait, TASK_UNINTERRUPTIBLE);
				if (available_migrations(tier))
					break;

				io_schedule();
			} while(1);

			finish_wait(&md->wait_for_migrate, &wait);
			break;
		case NO_SWAP:
		case -EBUSY:
			migration_stack_push(&ad->stack, info);
			msleep(100);
			break;
		default:
			return r;
		}

		cond_resched();
	}

	return 0;
}

static int migrate_block_swap_mode(struct tier *tier, 
				   uint32_t old_tierid,
				   uint32_t new_tierid,
				   dm_block_t *new_swap)
{
	int r = 0;
	dm_block_t old_swap;
	struct migration_data *migr_data = &tier->migr_data;
	struct analyze_data *ad = migr_data->adata;
	struct dm_bio_prison_cell *cell;
	struct dm_tier_new_mapping *m;
	struct dm_tier_lookup_result result;
	struct per_block_info *info;
	wait_queue_t wait;

reget:
	info = cluster_set_match_and_get(&ad->set, ad->block_from, 
		ad->block_to, new_tierid, old_tierid);
	if (!info)
		return -ENOSPC;

	r = check_migration_status(tier, info, &result, &cell);
	switch (r) {
		case 0:
			goto memory_alloc;
		case -EBUSY:
			cluster_set_add(&ad->set, info);
			msleep(100);
			goto reget;
		case MIGRATE_FULL:
			cluster_set_add(&ad->set, info);
			init_wait(&wait);
			do {
				prepare_to_wait(&migr_data->wait_for_migrate,
					&wait, TASK_UNINTERRUPTIBLE);
				if (available_migrations(tier))
					break;

				io_schedule();
			} while(1);

			finish_wait(&migr_data->wait_for_migrate, &wait);
			goto reget;
		case -ENODATA:
			if (ta_anchormap_get(ad->anchormap, info->index)) {
				update_anchor_status(&tier->anchor_stat,
					info->index, ad->anchormap);
				ta_anchormap_clear(ad->anchormap, info->index);
			}
			progress_update(&tier->progress);
			goto reget;
		case IN_BOUND:
			cell_defer_no_holder(tier, cell);
			atomic_dec(&migr_data->migration_count);
			migrate_block_demand_mode(tier, info, NULL);
			goto reget;
		default:
			WARN_ON(1);
			return r;
	}

memory_alloc:
	m = mapping_alloc(tier);
	if (!m) {
		WARN_ON(1);
		r = -ENOMEM;
		goto bad_swap_alloc;
	}

	r = must_alloc_swap_blk(tier, new_tierid, new_swap);
	if (r) {
		WARN_ON(r != -EBUSY);
		r = r == -EBUSY ? NO_SWAP : r;
		goto bad_new_swap;
	}

	r = must_alloc_swap_blk(tier, old_tierid, &old_swap);
	if (r) {
		WARN_ON(r != -EBUSY);
		r = r == -EBUSY ? NO_SWAP : r;
		goto bad_old_swap;
	}

	m->tier = tier;
	m->virt_block = info->index;
	m->cell = cell;
	m->new.block = old_swap;
	m->new.tierid = old_tierid;
	m->new.reserve = 0;
	m->old = result;

	if (!dm_deferred_set_add_work(tier->tier_io_ds, &m->list))
		tier_defer_task(tier, m);

	DMDEBUG("%s, (swap) (not demand) migr blk %u from %d:%llu to %d:%llu",
		__func__, info->index, result.tierid, 
		result.block, old_tierid, old_swap);

	if (ta_anchormap_get(ad->anchormap, info->index)) {
		update_anchor_status(&tier->anchor_stat, 
			info->index, ad->anchormap);
		ta_anchormap_clear(ad->anchormap, info->index);
	}
	cache_remove(&tier->cache, info->index);
	progress_update(&tier->progress);

	return 0;

bad_old_swap:
	dm_tier_free_swap_block(tier->tmd, new_tierid, *new_swap);
bad_new_swap:
	mempool_free(m, tier->migrate_mapping_pool);
bad_swap_alloc:
	cluster_set_add(&ad->set, info);
	atomic_dec(&migr_data->migration_count);
	cell_defer_no_holder(tier, cell);
	return r;
}

static int migrate_block_to_tier(struct tier *tier, struct per_block_info *info)
{
	int r;
	bool swap = false;
	struct dm_tier_new_mapping *m;
	struct dm_bio_prison_cell *cell;
	dm_block_t new_block, swap_block;
	struct dm_tier_lookup_result result;
	struct analyze_data *ad = tier->migr_data.adata;
	uint32_t new_tierid;
	bool in_bound = false;

	new_tierid = ta_get_tierid(ad->block_to, info->index);

	r = check_migration_status(tier, info, &result, &cell);
	if (r && r != IN_BOUND) {
		WARN_ON(r != -EINVAL && r != -EBUSY 
			&& r != -ENODATA && r != MIGRATE_FULL);
		return r;
	}

	in_bound = (r == IN_BOUND);

	m = mapping_alloc(tier);
	if (!m) {
		WARN_ON(1);
		r = -ENOMEM;
		goto bad_mapping_alloc;
	}

	if (in_bound)
		r = must_alloc_tier_block(tier, new_tierid, &new_block);
	else
		r = must_alloc_block(tier, result.tierid, new_tierid, &new_block);

	if (!r)
		goto ready_to_migrate;
	else if (in_bound) {
		WARN_ON(r != -ENOSPC);
		goto release_mapping;
	} else if (r != -ENOSPC) {
		WARN_ON(r != -EBUSY);
		r = r == -EBUSY ? NO_SWAP : r;
		goto release_mapping;
	}

	swap = true;
	r = migrate_block_swap_mode(tier, result.tierid, new_tierid, &swap_block);
	if (r)
		goto release_mapping;

ready_to_migrate:
	m->tier = tier;
	m->virt_block = info->index;
	m->cell = cell;
	m->new.block = swap ? swap_block : new_block;
	m->new.tierid = new_tierid;
	m->new.reserve = 0;
	m->old = result;
	m->demand = in_bound;

	cache_remove(&tier->cache, info->index);

	if (!dm_deferred_set_add_work(tier->tier_io_ds, &m->list))
		tier_defer_task(tier, m);

	DMDEBUG("%s, (%s) (%s) migrate blk %u from %d:%llu to %u:%llu", 
		__func__, swap ? "swap": "normal", 
		m->demand ? "demand" : "not demand", info->index, result.tierid,
		result.block, new_tierid, swap ? swap_block : new_block);

	return 0;

release_mapping:
	mempool_free(m, tier->migrate_mapping_pool);
bad_mapping_alloc:
	cell_defer_no_holder(tier, cell);
	atomic_dec(&tier->migr_data.migration_count);

	return r;
}

static void migrate_complete(int read_err, unsigned long write_err, void *context)
{
	unsigned long flags;
	struct dm_tier_new_mapping *m = context;
	struct tier *tier = m->tier;

	m->err = read_err || write_err ? -EIO : 0;

	spin_lock_irqsave(&tier->lock, flags);
	list_add_tail(&m->list, &tier->prepared_mappings);
	spin_unlock_irqrestore(&tier->lock, flags);

	wake_tier_worker(tier);
}

static void do_migration(struct work_struct *ws)
{
	unsigned long flags;
	struct list_head maps;
	struct dm_tier_new_mapping *m, *tmp;
	struct tier *tier = container_of(ws, struct tier, migrate_worker);

	INIT_LIST_HEAD(&maps);
	spin_lock_irqsave(&tier->lock, flags);
	list_splice_init(&tier->prepared_migrates, &maps);
	spin_unlock_irqrestore(&tier->lock, flags);

	list_for_each_entry_safe(m, tmp, &maps, list) {
		int r;
		struct dm_io_region from, to;

		from.bdev = tier->tier_ctx->tier_dev[m->old.tierid]->bdev;
		from.sector = m->old.block * tier->sector_per_block;
		from.count = tier->sector_per_block;

		to.bdev = tier->tier_ctx->tier_dev[m->new.tierid]->bdev;
		to.sector = m->new.block * tier->sector_per_block;
		to.count = tier->sector_per_block;

		list_del_init(&m->list);

		r = dm_kcopyd_copy(tier->migrator, &from, 1, &to, 0, 
			migrate_complete, m);
		if (r < 0) {
			/* We should stop the data migration process*/
			process_state_transition(tier, STOP_AUTO_TIERING);

			if (m->demote | m->promote) {
				cell_defer_no_holder(tier, m->cell);
				cache_migrate_complete(tier, m);
			} else {
				if (!m->swap_reallot)
					cell_defer_no_holder(tier, m->cell);
				block_migrate_complete(tier);
			}
			mempool_free(m, tier->migrate_mapping_pool);
			DMERR_LIMIT("dm_kcopyd_copy() for migration failed");
		}
	}
}

static int put_anchors_in_queue(struct tier *tier)
{
	dm_block_t index = 0;
	dm_block_t size = tier->block_num;
	struct analyze_data *ad = tier->migr_data.adata;
	struct anchor_stat *as = &tier->anchor_stat;
	struct per_block_info *info = NULL;
	int change = 0;

	BUG_ON(!ad);
	anchormap_copy(tier, ad->anchormap);

	for (; index < size; index++) {
		uint32_t old_tierid, new_tierid;
		enum anchor anchor;

		index = ta_anchormap_search(ad->anchormap, size, index);
		if (index >= size)
			break;
		
		/*update current tierid to analyze data*/
		old_tierid = get_tierid(tier, index);
		ta_store_tierid(ad->block_from, index, old_tierid);

		anchor = ta_anchormap_get(ad->anchormap, index);
		inc_anchor_stat(as, anchor == ANCHOR_HOT ? 
			ANCHOR_HOT_TOTAL : ANCHOR_COLD_TOTAL);

		info = cluster_set_find_and_get(&ad->set, index);
		if (info)
			change--;
		else {
			info = &ad->block_info[index];
			info->index = index;
		}
		info->score = anchor == ANCHOR_HOT ? MAX_STAT_COUNT : 0;

		if (anchor == ANCHOR_HOT)
			find_top_tid(ad, &new_tierid);
		else
			find_bottom_tid(ad, &new_tierid);		
		ta_store_tierid(ad->block_to, info->index, new_tierid);

		DMDEBUG("%s:%d, update blk %llu tier %u -> %u with  %s !!", 
			__func__, __LINE__, index, old_tierid, new_tierid, 
			anchor == ANCHOR_HOT ? "MAX_STAT_COUNT" : "ZERO");

		/*
		 * update with the blocks already on the assign tier
		 */
		if (old_tierid != new_tierid) {
			cluster_set_add(&ad->set, info);
			change++;			
		} else {		
			inc_anchor_stat(as, anchor == ANCHOR_HOT ? 
				ANCHOR_HOT_FINISH : ANCHOR_COLD_FINISH);
			ta_anchormap_clear(ad->anchormap, index);
			cache_remove(&tier->cache, index);
		}	
	}

	progress_total_refresh(&tier->progress, change);
	return 0;
}

static int anchors_migrate(struct tier *tier)
{
	struct migration_data *md = &tier->migr_data;
	struct analyze_data *ad = tier->migr_data.adata;
	dm_block_t index = 0;
	dm_block_t size = tier->block_num;
	int r = 0, retry = 0;

	for (; index < size && !cancel_tiering(tier); index++) {
		struct per_block_info *info;
		DEFINE_WAIT(wait);

		index = ta_anchormap_search(ad->anchormap, size, index);
		if (index >= size) {
			if (!retry)
				return 0;
			else {
				index = retry = 0;
				continue;
			}
		}

		info = cluster_set_find_and_get(&ad->set, index);
		if (!info) {
			DMINFO("%s:%d, missing entry for block %llu !!",
				__func__, __LINE__, index);
			ta_anchormap_clear(ad->anchormap, index);
			continue;
		}

		gate_control(&tier->gate);

		r = migrate_block_to_tier(tier, info);
		DMDEBUG("%s:%d, migrate info: %u !!", __func__, __LINE__, info->index);
		switch (r) {
		case -ENOSPC:
			migration_stack_push(&ad->stack, info);
			migrate_block_chain_mode(tier);
			break;
		case -ENODATA:
		case 0:
			update_anchor_status(&tier->anchor_stat, 
				info->index, ad->anchormap);
			ta_anchormap_clear(ad->anchormap, index);
			progress_update(&tier->progress);
			break;
		case MIGRATE_FULL:
			cluster_set_add(&ad->set, info);
			do {
				prepare_to_wait(&md->wait_for_migrate,
					&wait, TASK_UNINTERRUPTIBLE);
				if (available_migrations(tier))
					break;

				io_schedule();
			} while(1);

			finish_wait(&md->wait_for_migrate, &wait);
			retry = 1;
			break;
		case NO_SWAP:
		case -EBUSY:
			cluster_set_add(&ad->set, info);
			msleep(100);
			retry = 1;
			break;
		case -EINVAL:
			WARN_ON(1);				
		default:
			ta_anchormap_clear(ad->anchormap, index);
			return r;
		}

		cond_resched();
	}
	return 0;
}

/*
 * Once the boundary is set, the tier's swap may be occupied,
 * So we need to restore the required swap space
 */
static int swap_restore_ifneed(struct tier *tier)
{
	struct analyze_data *ad = tier->migr_data.adata;
	unsigned int rtid = rctrl_get_tierid(&tier->rctrl);
	uint32_t new_tid = rtid, bottom_tid;
	struct per_block_info *info;
	int r = 0;
	dm_block_t swap_shortage;

	dm_tier_commit_metadata(tier->tmd);
	r = dm_tier_get_swap_shortage(tier->tmd, rtid, &swap_shortage);
	if (r)
		return r;

	r = find_bottom_tid(ad, &bottom_tid);
	if (r) {
		DMINFO("fail to find bottom tier");
		return r;
	}

	DMDEBUG("%s, swap_shortage %llu", __func__, swap_shortage);
	while (swap_shortage && !cancel_tiering(tier)) {

next_tier:
		if (new_tid != bottom_tid) {
			r = find_next_tid(ad, &new_tid);
			if (r) {
				DMINFO("fail to find next tier for swap restore");
				return r;
			}
		} else
			new_tid = SSD_TIER_ID;

		if (new_tid == rtid) {
			DMINFO("%s, lack of free space for reserve", __func__);
			return -EINVAL;
		}

		info = cluster_set_match_and_get(&ad->set, 
			ad->block_from, ad->block_to, rtid, new_tid);
		if (!info)
			goto next_tier;

		r = migrate_block_demand_mode(tier, info, &swap_shortage);
		if (r == -ENODATA) {
			dm_tier_commit_metadata(tier->tmd);
			r = dm_tier_get_swap_shortage(tier->tmd, rtid, &swap_shortage);
			if (r)
				return r;

		} else if (r && r != -EBUSY)
			return r;

		new_tid = rtid;
		DMDEBUG("%s, swap_shortage %llu", __func__, swap_shortage);
	}

	return 0;
}

static int tier_migrate(struct tier *tier)
{
	struct migration_data *md = &tier->migr_data;
	struct analyze_data *ad = tier->migr_data.adata;
	bool has_reserve = check_reserve(tier);
	int r = 0;

	if (has_reserve) {
		r = swap_restore_ifneed(tier);
		if (r)
			return r;
	}

	while (!cancel_tiering(tier)) {
		DEFINE_WAIT(wait);
		struct per_block_info *info = cluster_set_extract(&ad->set);
		if (!info)
			return 0;

		gate_control(&tier->gate);

		r = migrate_block_to_tier(tier, info);
		DMDEBUG("%s:%d, migrate entry: %llu get r(%d) !!",
			__func__, __LINE__, info->index, r);
		switch (r) {
		case -ENOSPC:
			migration_stack_push(&ad->stack, info);
			migrate_block_chain_mode(tier);
			break;
		case -EINVAL:
			/*
			 * Remove the un-moved block from cache entry
			 */
			cache_remove(&tier->cache, info->index);
		case -ENODATA:	
		case 0:
			progress_update(&tier->progress);
			break;
		case NO_SWAP:
		case -EBUSY:
			cluster_set_add(&ad->set, info);
			msleep(100);
			break;
		case MIGRATE_FULL:
			cluster_set_add(&ad->set, info);
			do {
				prepare_to_wait(&md->wait_for_migrate, 
					&wait, TASK_UNINTERRUPTIBLE);
				if (available_migrations(tier))
					break;

				io_schedule();
			} while(1);

			finish_wait(&md->wait_for_migrate, &wait);
			break;
		default:
			return r;
		}

		cond_resched();
	}

	return 0;
}

static void score_profiler_update(struct tier *tier)
{
	unsigned long flags;

	spin_lock_irqsave(&tier->score_lock, flags);
	memcpy(tier->sco_pf_org, tier->migr_data.adata->sco_pf_org, sizeof(tier->sco_pf_org));
	memcpy(tier->sco_pf_drun, tier->migr_data.adata->sco_pf_drun, sizeof(tier->sco_pf_drun));
	spin_unlock_irqrestore(&tier->score_lock, flags);

	return;
}

static void update_avg_tscore(struct migration_data *md)
{
	struct analyze_data *adata = md->adata;
	uint64_t threshold;

	DMDEBUG("%s:%d, tscore(%llu) average tscore(%llu) !!", __func__, __LINE__,
		adata->tscore, md->avg_tscore);

	threshold = md->avg_tscore * (NR_TSCORE_REC - 1);
	do_div(threshold, NR_TSCORE_REC);

	adata->below_avg_score = adata->tscore < threshold;

	md->avg_tscore = md->avg_tscore * (NR_TSCORE_REC -1) + adata->tscore;
	do_div(md->avg_tscore, NR_TSCORE_REC);
}

static bool must_migrate(struct tier *tier)
{
	struct analyze_data *ad = tier->migr_data.adata;
	enum reserve_type rtype = rctrl_get_type(&tier->rctrl);

	return !strcmp(dm_tier_algo_get_name(tier->algo), "timeout") 
		|| rtype == DRIVE_OUT || test_bit(MIGR_ANCHORS_ONLY, &ad->flags);
}

static void data_migration(struct work_struct *ws)
{
	int r = 0;
	struct tier *tier = container_of(ws, struct tier, tier_worker);
	struct analyze_data *ad = NULL;
	struct migration_data *md = &tier->migr_data;

	if (!tier->migr_data.adata) {
		r = get_migration_goal(tier);
		if (r) {
			DMINFO("Update migration statics fail");
			goto out_migr;
		}

		score_profiler_update(tier);

		if (get_mstate(&tier->transition_work) == MIG_DRUN_ALGO)
			goto out_migr;

		update_avg_tscore(&tier->migr_data);
		if (tier->migr_data.adata->below_avg_score)
			DMINFO("total score less than average !!");
	}

	init_anchor_stat(&tier->anchor_stat);
	put_anchors_in_queue(tier);
	gate_reset(&tier->gate);
	init_waitqueue_head(&md->wait_for_migrate);
	anchors_migrate(tier);

	ad = tier->migr_data.adata;
	if (must_migrate(tier) || !ad->below_avg_score)
		r = tier_migrate(tier);

	wait_for_migrate_complete(tier);
	if (r)
		turnoff_reserve(tier);

out_migr:
	process_state_transition(tier, FINISH);
	return ;
}

static int process_display_mapping_mesg(unsigned argc, char **argv, struct tier *tier)
{
	int r;

	r = check_arg_count(argc, 1);
	if (r)
		return r;

	DMINFO("%s:%d, Start of display tiering mapping !!", __func__, __LINE__);
	r = tier_bitmap_display(tier);
	if (r)
		DMINFO("stop auto tiering thread failed");

	DMINFO("%s:%d, End of display tiering mapping !!", __func__, __LINE__);
	return r;
}

static int process_set_alloc_tier_mesg(unsigned argc, char **argv, struct tier *tier)
{
	int r;
	unsigned long alloc_tier;

	r = check_arg_count(argc, 2);
	if (r)
		return r;

	r = kstrtoul(argv[1], 10, &alloc_tier);
	if (r || alloc_tier >= tier->tier_num) {
		DMINFO("set allocation tier failed");
		return r;
	}

	r = dm_tier_set_alloc_tier(tier->tmd, alloc_tier);
	if (r)
		DMINFO("set allocation tier failed");

	DMINFO("%s:%d, set allocate tier as %lu success !! ", __func__, __LINE__, alloc_tier);

	return r;
}

static int process_set_algo_mesg(struct dm_target *ti, unsigned argc, char **argv, struct tier *tier)
{
	int r;
	struct dm_tier_algo *new;
	struct transition_work *tw = &tier->transition_work;

	r = check_arg_count(argc, 2);
	if (r)
		return r;

	if (!dm_suspended(ti) ||
		!tiering_idle(tier)) {
		DMERR("pool has not been suspended yet or tierin process "
			  "is not in idle state.");
		return -EBUSY;
	}

	atomic_inc(&tw->busy);
	set_mstate(&tier->transition_work, MIG_DRUN_ALGO);
	new = dm_tier_algo_create(argv[1], &tier->kobj);
	if (IS_ERR(new)) {
		DMERR("new tier algo create failed");
		r =  PTR_ERR(new);
		goto error;
	}

	dm_tier_algo_put(tier->algo);
	tier->algo = new;

	if (atomic_dec_and_test(&tw->busy))
		complete(&tw->complete);
	set_mstate(tw, MIG_IDLE);
	return 0;

error:
	if (atomic_dec_and_test(&tw->busy))
		complete(&tw->complete);
	set_mstate(tw, MIG_IDLE);
	return r;
}

static int process_dump_lru_mesg(struct dm_target *ti, unsigned argc, char **argv, struct tier *tier)
{
	int r;

	r = check_arg_count(argc, 1);
	if (r)
		return r;

	dump_lru_list(&tier->cache);

	return 0;
}

static int process_commit_mesg(struct dm_target *ti, unsigned argc, char **argv, struct tier *tier)
{
	int r;

	r = check_arg_count(argc, 1);
	if (r)
		return r;

	dm_tier_commit_metadata(tier->tmd);

	return 0;
}

static int process_enable_discard_mesg(struct dm_target *ti, unsigned argc, char **argv, struct tier *tier)
{
	int r;

	r = check_arg_count(argc, 1);
	if (r)
		return r;

	atomic_set(&tier->enable_discard, 1);

	return 0;
}

static int process_disable_discard_mesg(struct dm_target *ti, unsigned argc, char **argv, struct tier *tier)
{
	int r;

	r = check_arg_count(argc, 1);
	if (r)
		return r;

	atomic_set(&tier->enable_discard, 0);

	return 0;
}

static int process_state_trans_mesg(struct dm_target *ti, unsigned argc, char **argv, struct tier *tier)
{
	int r;
	enum tevent t;

	r = check_arg_count(argc, 1);
	if (r)
		return r;

	t = get_tevent(argv[0]);
	if (t >= __MAX_NR_TEVENT) {
		DMINFO("%s:%d, Unknow Tier event !!", __func__, __LINE__);
		return -EINVAL;
	}

	r = process_state_transition(tier, t);
	return r;
}

static int process_config_reserve_ratio_mesg(struct dm_target *ti, 
					     unsigned argc,
					     char **argv,
					     struct tier *tier)
{
	int r;
	unsigned int tid, ratio;
	struct tier_c *tier_ctx = tier->tier_ctx;

	r = check_arg_count(argc, 4);
	if (r) {
		DMINFO("config reserve ratio with wrong arg count");
		return r;
	}

	r = kstrtouint(argv[2], 10, &tid);
	if (r || tid >= tier->tier_num || !is_tier_enable(tier_ctx, tid)) {
		DMINFO("config reserve tierid failed");
		return r ? r : -EINVAL;
	}

	r = kstrtouint(argv[3], 10, &ratio);
	if (r) {
		DMINFO("config reserve threshold failed");
		return -EINVAL;
	}

	return config_reserve_with_ratio(tier, tid, ratio);
}

static int process_config_reserve_mesg(struct dm_target *ti, 
				       unsigned argc,
				       char **argv,
				       struct tier *tier)
{
	int r;
	enum reserve_type rtype;
	unsigned int tid;
	dm_block_t begin, end;
	bool zombie_exist = false;
	struct tier_c *tier_ctx = tier->tier_ctx;

	for (rtype = USAGE_CTRL; rtype < __MAX_NR_RTYPE; rtype++)
		if (!strcmp(argv[1], rtype_str[rtype]))
			break;

	if (rtype == __MAX_NR_RTYPE) {
		DMINFO("config reserve with wrong type");
		return -EINVAL;
	}

	if (rtype == USAGE_CTRL)
		return process_config_reserve_ratio_mesg(ti, argc, argv, tier);

	r = kstrtouint(argv[2], 10, &tid);
	if (r || tid >= tier->tier_num || !is_tier_enable(tier_ctx, tid)) {
		DMINFO("config reserve tierid failed");
		return r ? r : -EINVAL;
	}

	r = check_arg_count(argc, 5);
	if (r) {
		DMINFO("config reserve with wrong arg count");
		return r;
	}

	r = kstrtou64(argv[3], 10, &begin);
	if (r) {
		DMINFO("config reserve begin failed");
		return -EINVAL;
	}

	r = kstrtou64(argv[4], 10, &end);
	if (r) {
		DMINFO("config reserve end failed");
		return -EINVAL;
	}

	r = dm_tier_get_zombie_exist(tier->tmd, &zombie_exist);
	if (zombie_exist) {
		DMINFO("pool with zombie can't config forbidden zone");
		return -EINVAL;
	}

	return config_reserve(tier, rtype, tid, begin, end);
}

static int process_turnoff_reserve_mesg(struct dm_target *ti,
					unsigned argc,
					char **argv,
					struct tier *tier)
{
	int r;

	r = check_arg_count(argc, 1);
	if (r)
		return r;

	if (!atomic_add_unless(&tier->config_lock, 1, 1)) {
		DMINFO("Can't turnoff reserve during locked");
		return -EBUSY;
	}

	r = turnoff_reserve(tier);
	WARN_ON(!atomic_add_unless(&tier->config_lock, -1, 0));
	return r;
}

static int process_get_free_blkcnt_mesg(struct dm_target *ti, unsigned argc, char **argv, struct tier *tier)
{
	int r;
	unsigned int tid;
	dm_block_t begin, end, result;

	r = check_arg_count(argc, 4);
	if (r)
		return r;

	r = kstrtouint(argv[1], 10, &tid);
	if (r || tid >= tier->tier_num || !is_tier_enable(tier->tier_ctx, tid)) {
		DMINFO("get free block count failed");
		return r ? r : -EINVAL;
	}

	r = kstrtou64(argv[2], 10, &begin);
	if (r) {
		DMINFO("get free block count failed");
		return -EINVAL;
	}

	r = kstrtou64(argv[3], 10, &end);
	if (r) {
		DMINFO("get free block count failed");
		return -EINVAL;
	}

	r = dm_tier_get_free_blk_cnt_range(tier->tmd, tid, begin, end, &result);
	if (r)
		DMINFO("get free block count failed");
	else
		DMINFO("%u: %llu - %llu has %llu free blocks", 
		       tid, begin, end, result);

       return r;
}

struct bio_batch {
	atomic_t done;
	unsigned long flags;
	struct completion *wait;
};

static void bio_batch_end_io(struct bio *bio, int err)
{
	struct bio_batch *bb = bio->bi_private;

	if (err && (err != -EOPNOTSUPP))
		clear_bit(BIO_UPTODATE, &bb->flags);
	if (atomic_dec_and_test(&bb->done))
		complete(bb->wait);
	bio_put(bio);
}

static int __blkdev_issue_anchor(struct block_device *bdev, sector_t sector,
                                  sector_t nr_sects, gfp_t gfp_mask, int mode)
{
	int ret;
	struct bio *bio;
	struct bio_batch bb;
	unsigned int sz;
	DECLARE_COMPLETION_ONSTACK(wait);
	int type = REQ_WRITE | mode;
	atomic_set(&bb.done, 1);
	bb.flags = 1 << BIO_UPTODATE;
	bb.wait = &wait;
	ret = 0;
	while (nr_sects != 0) {
		bio = bio_alloc(gfp_mask,
			min(nr_sects, (sector_t)BIO_MAX_PAGES));
		if (!bio) {
			ret = -ENOMEM;
			break;
		}
		bio->bi_iter.bi_sector = sector;
		bio->bi_bdev = bdev;
		bio->bi_end_io = bio_batch_end_io;
		bio->bi_private = &bb;
		set_bit(BIO_HINT, &bio->bi_flags);
		while (nr_sects != 0) {
			sz = min((sector_t) PAGE_SIZE >> 9 , nr_sects);
			ret = bio_add_page(bio, ZERO_PAGE(0), sz << 9, 0);
			nr_sects -= ret >> 9;
			sector += ret >> 9;
			if (ret < (sz << 9))
				break;
		}
		ret = 0;
		atomic_inc(&bb.done);
		submit_bio(type, bio);
	}
	/* Wait for bios in-flight */
	if (!atomic_dec_and_test(&bb.done))
		wait_for_completion_io(&wait);
	if (!test_bit(BIO_UPTODATE, &bb.flags))
		/* One of bios in the batch was completed with error.*/
		ret = -EIO;
	return ret;
}

static int get_blkdev_anchor(const char *message)
{
	if (!strcasecmp(message, "anchor_hot"))
		return REQ_ANCHOR_HOT;
	else if (!strcasecmp(message, "anchor_cold"))
		return REQ_ANCHOR_COLD;
	else if (!strcasecmp(message, "anchor_clear"))
		return REQ_ANCHOR_CLEAR;
	else
		return -1;
}

static int process_set_anchored_blk_mesg(struct dm_target *ti, unsigned argc, char **argv, struct tier *tier)
{
	int r, mode;
	dm_block_t block, nr_blks;
	struct mapped_device *md = dm_table_get_md(ti->table);
	struct block_device *bdev;

	r = check_arg_count(argc, 4);
	if (r)
		return r;

	r = kstrtou64(argv[1], 10, &block);
	if (r) {
		DMINFO("set allocation tier failed");
		return r;
	}

	r = kstrtou64(argv[2], 10, &nr_blks);
	if (r) {
		DMINFO("set allocation tier failed");
		return r;
	}

	mode = get_blkdev_anchor(argv[3]);
	if (mode < 0) {
		DMINFO("%s:%d, Unknow Anchor Setting !!", __func__, __LINE__);
		return -EINVAL;
	}

	bdev = bdget_disk(dm_disk(md), 0);
	if (!bdev) {
		DMERR("%s: get reference to block device fail", __func__);
		return -EINVAL;
	}

	r = __blkdev_issue_anchor(bdev, convert_tier_address(tier, block),
		nr_blks * tier->sector_per_block, GFP_NOFS, mode);
	if (r)
		DMINFO("set anchored block failed");

	return r;
}

static int process_wipe_all_anchor_mesg(struct dm_target *ti, unsigned argc, char **argv, struct tier *tier)
{
	int r;

	r = check_arg_count(argc, 1);
	if (r)
		return r;

	r = anchormap_wipe(tier);
	if (r)
		DMINFO("wipe all anchor failed");

	return r;
}

static int process_issue_tier_trim_mesg(struct dm_target *ti, unsigned argc, char **argv, struct tier *tier)
{
	int r;
	unsigned long tid;
	struct tier_c *tc = tier->tier_ctx;
	uint32_t data_block_size = tier->sector_per_block;
	dm_block_t dev_size;

	r = check_arg_count(argc, 2);
	if (r)
		return r;

	r = kstrtoul(argv[1], 10, &tid);
	if (r || tid >= tier->tier_num) {
		DMINFO("tier discard failed");
		return r;
	}	

	dev_size = get_data_dev_size_in_blocks(tc->tier_dev[tid]->bdev, data_block_size);
	r = issue_tier_trim(tier, tid, 0, dev_size);
	if (r)
		DMINFO("tier discard failed");

	return r;
}

static int process_create_zombie_mesg(struct dm_target *ti, unsigned argc, char **argv, struct tier *tier)
{
	int r;
	unsigned long nr_zombie, i;
	unsigned tid;
	dm_block_t block;

	r = check_arg_count(argc, 2);
	if (r)
		return r;

	r = kstrtoul(argv[1], 10, &nr_zombie);
	if (r) {
		DMINFO("tier create zombie failed");
		return r;
	}

	for (i = 0; i < nr_zombie; i++) {
		r = must_find_and_alloc_block(tier, NORMAL_ALLOC, &tid, &block);
		if (r) {
			DMINFO("create zombie fail");
			break;
		}

		DMINFO("create zombie at %u:%llu", tid, block);
	}

	return r;
}

static int process_set_swap_mesg(struct dm_target *ti, unsigned argc, char **argv, struct tier *tier)
{
	int r;
	unsigned long tid;
	dm_block_t swap;

	r = check_arg_count(argc, 3);
	if (r)
		return r;

	r = kstrtoul(argv[1], 10, &tid);
	if (r) {
		DMINFO("set swap failed");
		return r;
	}

	r = kstrtou64(argv[2], 10, &swap);
	if (r) {
		DMINFO("set swap failed");
		return r;
	}

	r = dm_tier_set_swap_block(tier->tmd, tid, swap);
	if (r)
		DMINFO("set swap failed");

	return r;
}

static int process_display_swap_mesg(struct dm_target *ti, unsigned argc, char **argv, struct tier *tier)
{
	int r;

	r = display_swap_info(tier);
	if (r)
		DMINFO("set swap failed");

	return r;
}

int process_tier_mesg(struct dm_target *ti, unsigned argc, char **argv, struct tier *tier)
{
	int r = -EINVAL;

	if (!strcasecmp(argv[0], "display_mapping"))
		r = process_display_mapping_mesg(argc, argv, tier);

	else if (!strcasecmp(argv[0], "set_alloc_tier"))
		r = process_set_alloc_tier_mesg(argc, argv, tier);

	else if (!strcasecmp(argv[0], "set_algo"))
		r = process_set_algo_mesg(ti, argc, argv, tier);

	else if (!strcasecmp(argv[0], "dump_lru"))
		r = process_dump_lru_mesg(ti, argc, argv, tier);

	else if (!strcasecmp(argv[0], "commit"))
		r = process_commit_mesg(ti, argc, argv, tier);

	else if (!strcasecmp(argv[0], "enable_discard"))
		r = process_enable_discard_mesg(ti, argc, argv, tier);

	else if (!strcasecmp(argv[0], "disable_discard"))
		r = process_disable_discard_mesg(ti, argc, argv, tier);

	else if (!strcasecmp(argv[0], "auto_tiering"))
		r = process_state_trans_mesg(ti, argc, argv, tier);

	else if (!strcasecmp(argv[0], "stop_auto_tiering"))
		r = process_state_trans_mesg(ti, argc, argv, tier);

	else if (!strcasecmp(argv[0], "data_analysis"))
		r = process_state_trans_mesg(ti, argc, argv, tier);

	else if (!strcasecmp(argv[0], "tiering_suspend"))
		r = process_state_trans_mesg(ti, argc, argv, tier);

	else if (!strcasecmp(argv[0], "tiering_resume"))
		r = process_state_trans_mesg(ti, argc, argv, tier);

	else if (!strcasecmp(argv[0], "anchor_update"))
		r = process_state_trans_mesg(ti, argc, argv, tier);	

	else if (!strcasecmp(argv[0], "set_anchored_blk"))
		r = process_set_anchored_blk_mesg(ti, argc, argv, tier);

	else if (!strcasecmp(argv[0], "wipe_all_anchor"))
		r = process_wipe_all_anchor_mesg(ti, argc, argv, tier);

	else if (!strcasecmp(argv[0], "issue_tier_trim"))
		r = process_issue_tier_trim_mesg(ti, argc, argv, tier);

	else if (!strcasecmp(argv[0], "create_zombie"))
		r = process_create_zombie_mesg(ti, argc, argv, tier);

	else if (!strcasecmp(argv[0], "set_swap"))
		r = process_set_swap_mesg(ti, argc, argv, tier);

	else if (!strcasecmp(argv[0], "display_swap"))
		r = process_display_swap_mesg(ti, argc, argv, tier);

	else if (!strcasecmp(argv[0], "config_reserve"))
		r = process_config_reserve_mesg(ti, argc, argv, tier);

	else if (!strcasecmp(argv[0], "turnoff_reserve"))
		r = process_turnoff_reserve_mesg(ti, argc, argv, tier);

	else if (!strcasecmp(argv[0], "get_free_blkcnt"))
		r = process_get_free_blkcnt_mesg(ti, argc, argv, tier);

	else
		DMWARN("Unrecognised tier pool target message received: %s", argv[0]);

	return r;
}

static int qtier_proc_show(struct seq_file *m, void *v)
{
	seq_printf(m, "%s\n", QTIER_VERSION);
	return 0;
}

static int qtier_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, qtier_proc_show, NULL);
}

static const struct file_operations qtier_proc_fops = {
	.owner = THIS_MODULE,
	.open = qtier_proc_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

int tier_init(void)
{
	struct proc_dir_entry *proc_entry;

	_migrate_mapping_cache = KMEM_CACHE(dm_tier_new_mapping, 0);
	if (!_migrate_mapping_cache)
		return -ENOMEM ;

	_trim_info_cache = KMEM_CACHE(dm_tier_trim_info, 0);
	if (!_trim_info_cache)
		goto bad_trim_info_create;

	proc_entry = proc_create(PROC_FS_NAME, 0644, NULL, &qtier_proc_fops);
	if (proc_entry == NULL)
		goto bad_proc_create;

	return 0;

bad_proc_create:
	kmem_cache_destroy(_trim_info_cache);
bad_trim_info_create:
	kmem_cache_destroy(_migrate_mapping_cache);
	return -ENOMEM;
}

void tier_exit(void)
{
	remove_proc_entry(PROC_FS_NAME, NULL);
	kmem_cache_destroy(_trim_info_cache);
	kmem_cache_destroy(_migrate_mapping_cache);
}
