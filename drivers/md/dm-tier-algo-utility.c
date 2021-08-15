#include "dm-tier-algo-utility.h"
#include <linux/device-mapper.h>
#include <asm/processor.h>
#include <linux/vmalloc.h>

#define DM_MSG_PREFIX  "tier-algo-utility"
#define CLUSTER_NUM 65536

/*
 * Tier ID bitmap manuplate methods
 */
void ta_clear_tierid(unsigned long *map, dm_block_t block)
{
	dm_block_t pos = block;
	uint64_t offset = do_div(pos, BLOCKS_PER_LONG);
	unsigned long mask = ~(unsigned long)(TIER_MASK << (offset * TIER_BITS));

	if (!map) {
		DMINFO("%s: pool->tier_map is NULL", __func__);
		return;
	}

	map[pos] &= mask;
}

void ta_store_tierid(unsigned long *map, dm_block_t block, uint32_t tierid)
{
	dm_block_t pos = block;
	uint64_t offset = do_div(pos, BLOCKS_PER_LONG);

	ta_clear_tierid(map, block);
	map[pos] |= ((unsigned long)(tierid + 1)) << (offset * TIER_BITS);
}

uint32_t ta_get_tierid(unsigned long *map, dm_block_t block)
{
	uint32_t tierid;
	dm_block_t pos = block;
	uint64_t offset = do_div(pos, BLOCKS_PER_LONG);

	tierid = (map[pos] >> (offset * TIER_BITS)) & TIER_MASK;

	return tierid - 1;
}

dm_block_t ta_find_next_allocated(unsigned long *bitmap, unsigned long size, dm_block_t offset)
{
	dm_block_t index = offset * TIER_BITS;

	index = find_next_bit(bitmap,  size * TIER_BITS, index);
	do_div(index, TIER_BITS);
	return index;
}

dm_block_t ta_find_next_target_tier(unsigned long *bitmap, unsigned long size, dm_block_t offset, uint32_t tierid)
{
	dm_block_t index = offset;

	while (1) {
		index = ta_find_next_allocated(bitmap, size, index);
		if (index >= size || ta_get_tierid(bitmap, index) == tierid)
			break;

		index++;
	}

	return index;
}

dm_block_t ta_get_mapping_count(unsigned long *bitmap, unsigned long size)
{
	dm_block_t b = 0, mappings = 0;

	for (b = 0; b < size; b++) {
		b = ta_find_next_allocated(bitmap, size, b);
		if (b >= size)
			break;

		mappings++;
	}

	return mappings;
}

/*
 * Tier Anchor bitmap manuplate methods
 */
void ta_anchormap_clear(unsigned long *map, dm_block_t block)
{
	dm_block_t pos = block;
	uint64_t offset = do_div(pos, ANCHORS_PER_LONG);
	unsigned long mask = ~(unsigned long)(ANCHOR_MASK << (offset * ANCHOR_BITS));

	if (!map) {
		DMINFO("%s: pool->tier_map is NULL", __func__);
		return;
	}

	map[pos] &= mask;
}

void ta_anchormap_store(unsigned long *map, dm_block_t block, enum anchor anchor)
{
	dm_block_t pos = block;
	uint64_t offset = do_div(pos, ANCHORS_PER_LONG);

	ta_anchormap_clear(map, block);
	map[pos] |= ((unsigned long)anchor) << (offset * ANCHOR_BITS);
}

enum anchor ta_anchormap_get(unsigned long *map, dm_block_t block)
{
	enum anchor anchor;
	dm_block_t pos = block;
	uint64_t offset = do_div(pos, ANCHORS_PER_LONG);

	anchor = (map[pos] >> (offset * ANCHOR_BITS)) & ANCHOR_MASK;

	return anchor;
}

dm_block_t ta_anchormap_search(unsigned long *map, unsigned long size, dm_block_t offset)
{
	dm_block_t index = offset * ANCHOR_BITS;

	index = find_next_bit(map,  size * ANCHOR_BITS, index);
	do_div(index, ANCHOR_BITS);
	return index;
}

bool ta_anchored_block(unsigned long *map, dm_block_t block)
{
	return ta_anchormap_get(map, block) != ANCHOR_CLEAR;
}

bool is_tier_disabled(struct analyze_data *data, uint32_t tierid)
{
	return data->block_num[tierid] ? false : true;
}

int find_next_tid(struct analyze_data *data, uint32_t *tierid)
{
	uint32_t target_tid = *tierid;

	do {
		target_tid++;
	} while (target_tid < data->tier_num && is_tier_disabled(data, target_tid));

	if (target_tid < data->tier_num && !is_tier_disabled(data, target_tid)) {
		*tierid = target_tid;
		return 0;
	}

	return -EINVAL;
}

int find_top_tid(struct analyze_data *data, uint32_t *tierid)
{
	int target_tid = -1;

	do {
		target_tid++;
	} while (target_tid < data->tier_num && is_tier_disabled(data, (uint32_t)target_tid));

	if (target_tid < data->tier_num && !is_tier_disabled(data, (uint32_t)target_tid)) {
		*tierid = (uint32_t)target_tid;
		return 0;
	}

	return -EINVAL;
}

int find_prev_tid(struct analyze_data *data, uint32_t *tierid)
{
	int target_tid = *tierid;

	do {
		target_tid--;
	} while (target_tid >= 0 && is_tier_disabled(data, (uint32_t)target_tid));

	if (target_tid >= 0 && !is_tier_disabled(data, (uint32_t)target_tid)) {
		*tierid = (uint32_t)target_tid;
		return 0;
	}

	return -EINVAL;
}

int find_bottom_tid(struct analyze_data *data, uint32_t *tierid)
{
	int target_tid = MAX_TIER_LEVEL;

	do {
		target_tid--;
	} while(target_tid >= 0 && is_tier_disabled(data, (uint32_t)target_tid));

	if (target_tid >= 0 && !is_tier_disabled(data, (uint32_t)target_tid)) {
		*tierid = (uint32_t)target_tid;
		return 0;
	}

	return -EINVAL;	
}

int get_temper(struct bio *bio)
{
	enum temperature temper = NORMAL;

	if (bio->bi_rw & REQ_HOTDATA)
		temper = HOT;
	else if (bio->bi_rw & REQ_COLDDATA)
		temper = COLD;

	return temper;
}

void scorer_init(struct scorer *scorer, struct score_profiler *score_pf, 
       dm_block_t *mapped, uint64_t ssd_access)
{
	int i;

	score_pf[SSD_TIER_ID].ssd_access = ssd_access;
	for (i = 0; i < MAX_TIER_LEVEL; i++) {
		dm_block_t gap = mapped[i];

		do_div(gap, PROFILE_POINT);
		scorer[i].gap = gap ? gap : 1;
		scorer[i].counter = 1;
		scorer[i].p = &score_pf[i].p_num;
		scorer[i].pscore = score_pf[i].score;
	}
}

void scorer_update(struct scorer *scorer, uint32_t tid, uint64_t score)
{
	unsigned long p;

	scorer = &scorer[tid];
	p = *scorer->p;

	if (scorer->gap && !--scorer->counter && p < PROFILE_POINT) {
		(*scorer->p)++;
		scorer->pscore[p] = score;
		scorer->counter = scorer->gap;
	}
}

bool is_dryrun(struct analyze_data *data)
{
	return data->dryrun;
}

/*
 *  Utilities for cluster set
 */
int cluster_set_init(struct cluster_set *set)
{
	int i;
	mutex_init(&set->lock);
	set->max_score = 0;
	set->min_score = UINT_MAX;
	set->gap = 1;
	set->clusters = vzalloc(CLUSTER_NUM * sizeof(struct cluster));
	if (!set->clusters)
		return -ENOMEM;

	for (i = 0; i < CLUSTER_NUM; i++)
		STAILQ_INIT(&set->clusters[i]);	
	return 0;
}

void cluster_set_reclaim(struct cluster_set *set)
{
	int i;
	struct per_block_info *info;

	for (i = 0; i < CLUSTER_NUM; i++)
		while((info = STAILQ_FIRST(&set->clusters[i])) != NULL)
			STAILQ_REMOVE_HEAD(&set->clusters[i], next);

	vfree(set->clusters);	
}

void update_cluster_set_attr(struct cluster_set *set, uint64_t max, uint64_t min)
{
	uint64_t gap;

	gap = max - min;
	do_div(gap, CLUSTER_NUM);

	mutex_lock(&set->lock);
	set->max_score = max;
	set->min_score = min;
	set->gap = gap < 1 ? 1 : gap;
	mutex_unlock(&set->lock);
}

void __cluster_set_add(struct cluster_set *set, struct per_block_info *info)
{
	uint64_t index;

	index = info->score - set->min_score;
	do_div(index, set->gap);
	index = index < CLUSTER_NUM ? index : CLUSTER_NUM - 1;
	STAILQ_INSERT_TAIL(&set->clusters[index], info, next);
	DMDEBUG("%s:%d, clusters(%llu) add block[%u] with score(%llu)",
		__func__, __LINE__, index, info->index, info->score);
}

void cluster_set_add(struct cluster_set *set, struct per_block_info *info)
{
	mutex_lock(&set->lock);
	__cluster_set_add(set, info);
	mutex_unlock(&set->lock);
}

static struct per_block_info *__cluster_set_extract(struct cluster_set *set)
{
 	int i;
	struct per_block_info *info = NULL;

	for (i = CLUSTER_NUM -1; i >= 0; i--) {
		while((info = STAILQ_FIRST(&set->clusters[i])) != NULL) {
			STAILQ_REMOVE_HEAD(&set->clusters[i], next);
			i = 0; //break out nested loop
			break;
		}
	}

	return info;
}

struct per_block_info *cluster_set_extract(struct cluster_set *set)
{
	struct per_block_info *info = NULL;

	mutex_lock(&set->lock);
	info = __cluster_set_extract(set);
	mutex_unlock(&set->lock);

	if (info)
		DMDEBUG("%s:%d, cluster set extract block[%u]", 
			__func__, __LINE__, info->index);

	return info;
}

struct per_block_info *cluster_set_find_and_get(struct cluster_set *set, uint32_t index)
{
	struct per_block_info *tmp, *info = NULL;
	int i, cluster_id;

	mutex_lock(&set->lock);

	for (i = CLUSTER_NUM -1; i >= 0; i--) {
		STAILQ_FOREACH(tmp, &set->clusters[i], next)
			if (tmp->index == index) {
				info = tmp;
				cluster_id = i;
				i = 0;
				break;
			}
 	}

	if (info) {
		STAILQ_REMOVE(&set->clusters[cluster_id], info, 
			per_block_info, next);		
		DMDEBUG("%s:%d, cluster set find and get block[%u]", 
			__func__, __LINE__, info->index);
 	}

	mutex_unlock(&set->lock);

	return info;
}

/*
 * find the migration job from old_tid to new_tid,
 * if new_tid = U32_MAX, it means the target tier can be any one
 */
struct per_block_info * cluster_set_match_and_get(struct cluster_set *set, 
	unsigned long *block_from, unsigned long *block_to, 
	uint32_t old_tid, uint32_t new_tid)
{
	struct per_block_info *tmp, *info = NULL;
	int i, cluster_id;
	
	mutex_lock(&set->lock);

	for (i = CLUSTER_NUM -1; i >= 0; i--) {
		STAILQ_FOREACH(tmp, &set->clusters[i], next)
			if (ta_get_tierid(block_from, tmp->index) == old_tid)
				if (ta_get_tierid(block_to, tmp->index) == new_tid
					|| new_tid == U32_MAX) {
				info = tmp;
				cluster_id = i;
				i = 0;
				break;
			}
	}

	if (info) {
		STAILQ_REMOVE(&set->clusters[cluster_id], info, 
			per_block_info, next);
		DMDEBUG("%s:%d, cluster set match and get block[%u]", 
			__func__, __LINE__, info->index);		
	}

	mutex_unlock(&set->lock);
	return info;
}

/* scan the cluster set in decreasing order*/
void __cluster_set_walk(struct cluster_set *set, 
	void (*fn)(void *context, struct per_block_info *info), void *context)
{
	int i;
	struct per_block_info *info;

	for (i = CLUSTER_NUM -1; i >= 0; i--) {
		STAILQ_FOREACH(info, &set->clusters[i], next)
			fn(context, info);
	}	
}

void dump_cluster_set(struct cluster_set *set)
{
	int i;
	struct per_block_info *info;

	mutex_lock(&set->lock);
	for (i = CLUSTER_NUM -1; i >= 0; i--) {
		DMINFO("%s:%d, clusters(%d) ", __func__, __LINE__, i);
		STAILQ_FOREACH(info, &set->clusters[i], next)
			DMINFO("%s:%d, get block[%u]", __func__, __LINE__, info->index);
	}
	mutex_unlock(&set->lock);
}

/* -------------------------------------------------------------------- */

/*
 *  Utilities for migration stack 
 */
void migration_stack_init(struct migration_stack *stack)
{
	mutex_init(&stack->lock);
	STAILQ_INIT(&stack->list);
}

int migration_stack_len(struct migration_stack *stack)
{
	struct per_block_info *info;
	int count = 0;

	mutex_lock(&stack->lock);
	STAILQ_FOREACH(info, &stack->list, next)
		count++;
	mutex_unlock(&stack->lock);
	
	return count;	
}

static void __migration_stack_push(struct migration_stack *stack, struct per_block_info *info)
{
	STAILQ_INSERT_HEAD(&stack->list, info, next);
}

void migration_stack_push(struct migration_stack *stack, struct per_block_info *info)
{
	mutex_lock(&stack->lock);
	__migration_stack_push(stack, info);
	mutex_unlock(&stack->lock);

	DMDEBUG("%s:%d, stack push block[%u]", __func__, __LINE__, info->index);
}

static struct per_block_info *__migration_stack_pop(struct migration_stack *stack)
{
	struct per_block_info *info = NULL;

	if ((info = STAILQ_FIRST(&stack->list)) != NULL)
		STAILQ_REMOVE_HEAD(&stack->list, next);

	return info;
}

struct per_block_info* migration_stack_pop(struct migration_stack *stack)
{
	struct per_block_info *info = NULL;

	mutex_lock(&stack->lock);
	info = __migration_stack_pop(stack);
	mutex_unlock(&stack->lock);

	if (info)
		DMDEBUG("%s:%d, stack pop block %u !!", 
			__func__, __LINE__, info->index);
	return info;	
}

void migration_stack_reclaim(struct migration_stack *stack)
{
	struct per_block_info *info;

	mutex_lock(&stack->lock);
	while ((info = STAILQ_FIRST(&stack->list)) != NULL)
		STAILQ_REMOVE_HEAD(&stack->list, next);
	mutex_unlock(&stack->lock);
}

/* -------------------------------------------------------------------- */

/*
 *  Utilities for reserve ctrl
 */
void rctrl_init(struct reserve_ctrl *rctrl)
{
	atomic_set(&rctrl->type, USAGE_CTRL);
	rctrl->tierid = RESERVE_TIER_DISABLE;
	rctrl->dev_size = 0;
	atomic64_set(&rctrl->retain, 0);
	atomic64_set(&rctrl->begin, U64_MAX);
	atomic64_set(&rctrl->end, U64_MAX);
}

void rctrl_config(struct reserve_ctrl *rctrl, 
		  enum reserve_type type,
		  int tid,
		  dm_block_t size,
		  dm_block_t begin,
		  dm_block_t end)
{
	atomic_set(&rctrl->type, type);
	rctrl->tierid = tid;
	rctrl->dev_size = size;
	atomic64_set(&rctrl->begin, begin);
	atomic64_set(&rctrl->end, end);
	atomic64_set(&rctrl->retain, end - begin);
}

enum reserve_type rctrl_get_type(struct reserve_ctrl *rctrl)
{
	return atomic_read(&rctrl->type);
}

char* rctrl_get_type_str(struct reserve_ctrl *rctrl)
{
	return rtype_str[atomic_read(&rctrl->type)];
}

int rctrl_get_tierid(struct reserve_ctrl *rctrl)
{
	return rctrl->tierid;
}

dm_block_t rctrl_get_dev_size(struct reserve_ctrl *rctrl)
{
	return rctrl->dev_size;
}

void rctrl_sub_retain(struct reserve_ctrl *rctrl, int shrink)
{
	WARN_ON(atomic64_sub_return(shrink, &rctrl->retain) < 0);
}

dm_block_t rctrl_get_retain(struct reserve_ctrl *rctrl)
{
	return atomic64_read(&rctrl->retain);
}

dm_block_t rctrl_get_begin(struct reserve_ctrl *rctrl)
{
	return atomic64_read(&rctrl->begin);
}

dm_block_t rctrl_get_end(struct reserve_ctrl *rctrl)
{
	return atomic64_read(&rctrl->end);
}
/* -------------------------------------------------------------------- */

/*
 * Profile manuplate methods
 */
static bool is_tier_prof_disable(struct profile *profile, unsigned int tierid)
{
	struct per_tier_profile *tier_profile = profile->tier_profiles+tierid;

	return tier_profile->total_blks ? false : true;
}

static void simulate_swap(struct profile *profile, unsigned int src_tier, unsigned int dst_tier)
{
	struct per_tier_profile *profile_src = profile->tier_profiles+src_tier;
	struct per_tier_profile *profile_dst = profile->tier_profiles+dst_tier;

	enum profile_class intend_src = src_tier < dst_tier ? INTEND_DN : INTEND_UP;
	enum profile_class intend_dst = src_tier < dst_tier ? INTEND_UP : INTEND_DN;

	enum profile_class migr_src = src_tier < dst_tier ? MIGR_DN : MIGR_UP;
	enum profile_class migr_dst = src_tier < dst_tier ? MIGR_UP : MIGR_DN;

	dm_block_t *blks_intd_src = (dm_block_t *)profile_src + intend_src;
	dm_block_t *blks_intd_dst = (dm_block_t *)profile_dst + intend_dst;
	dm_block_t migr_unit = *blks_intd_src < *blks_intd_dst ?
		*blks_intd_src : *blks_intd_dst;

	inc_tier_profile(profile, dst_tier, migr_dst, migr_unit);
	dec_tier_profile(profile, dst_tier, intend_dst, migr_unit);	
	inc_tier_profile(profile, src_tier, migr_src, migr_unit);
	dec_tier_profile(profile, src_tier, intend_src, migr_unit);
}

static void simulate_migr(struct profile *profile, unsigned int src_tier, unsigned int dst_tier)
{
	struct per_tier_profile *profile_src = profile->tier_profiles+src_tier;
	struct per_tier_profile *profile_dst = profile->tier_profiles+dst_tier;

	enum profile_class intend_dir = src_tier < dst_tier ? INTEND_DN : INTEND_UP;
	enum profile_class migr_dir = src_tier < dst_tier ? MIGR_DN : MIGR_UP;

	dm_block_t *intend_blks = (dm_block_t *)profile_src + intend_dir;
	dm_block_t *free_blks = (dm_block_t *)profile_dst + FREE_BLKS;
	dm_block_t migr_unit = *intend_blks < *free_blks ? *intend_blks : *free_blks;

	dec_tier_profile(profile, dst_tier, FREE_BLKS, migr_unit);
	inc_tier_profile(profile, src_tier, FREE_BLKS, migr_unit);
	inc_tier_profile(profile, src_tier, migr_dir, migr_unit);
	dec_tier_profile(profile, src_tier, intend_dir, migr_unit);

	if (*intend_blks)
		simulate_swap(profile, src_tier, dst_tier);
}

static void simulate_tiers_down(struct profile *profile)
{
	int src_tier;
	unsigned int tier_num = profile->tier_num;

	for (src_tier = (tier_num - 2) ; src_tier >= 0 ; src_tier --) {
		int dst_tier;
		if (is_tier_prof_disable(profile, (unsigned int)src_tier))
			continue;

		for (dst_tier = (src_tier + 1); dst_tier < tier_num; dst_tier ++) {
			if (!is_tier_prof_disable(profile, (unsigned int)dst_tier))
				break;
		}

		if (dst_tier >= tier_num) {
			DMDEBUG("%s:%d, Corresponding tier for tier(%d) migrate down doesn't exist !!", 
				__func__, __LINE__, src_tier);
			continue;
		}
		simulate_migr(profile, (unsigned int)src_tier, (unsigned int)dst_tier);
	}
}

static void simulate_tiers_up(struct profile *profile)
{
	int src_tier;
	unsigned int tier_num = profile->tier_num;

	for( src_tier = 1; src_tier < tier_num; src_tier ++) {
		int dst_tier;
		if (is_tier_prof_disable(profile, (unsigned int)src_tier))	
			continue;

		for (dst_tier = (src_tier - 1); dst_tier >= 0; dst_tier --) {
			if (!is_tier_prof_disable(profile, (unsigned int)dst_tier))
				break;
		}

		if (dst_tier < 0) {
			DMDEBUG("%s:%d, Corresponding tier for tier(%d) migrate up doesn't exist !!", 
				__func__, __LINE__, src_tier);
			continue;
		}
		simulate_migr(profile, (unsigned int)src_tier, (unsigned int)dst_tier);
	}
}

struct profile * create_profile(struct analyze_data *data, int reserve_ratio)
{
	struct profile *profile;
	void *err_p;
	unsigned int i;
	dm_block_t reserve;

	profile = kzalloc(sizeof(*profile), GFP_KERNEL);
	if (!profile) {
		DMINFO("%s:%d, create profiles !!", __func__, __LINE__);
		err_p = ERR_PTR(-ENOMEM);
		return err_p;
	}

	profile->tier_num = data->tier_num;
	profile->tier_profiles = kzalloc(sizeof(struct per_tier_profile) * data->tier_num, GFP_KERNEL);
	if (!profile->tier_profiles) {
		DMINFO("%s:%d, create tier_profiles fail !!", __func__, __LINE__);
		err_p = ERR_PTR(-ENOMEM);
		goto free_profile;
	}

	for (i = 0; i < profile->tier_num; i++) {
		set_tier_profile(profile, i, TOTAL_BLKS, data->block_num[i]);
		set_tier_profile(profile, i, FREE_BLKS, data->block_num[i]);
		reserve = data->block_num[i]*reserve_ratio;
		do_div(reserve, ONE_HUNDRED);
		set_tier_profile(profile, i, RES_BLKS, reserve);
	}

	return profile;

free_profile:
	kfree(profile);
	return err_p;	
}

void destroy_profile(struct profile *profile)
{
	kfree(profile->tier_profiles);
	kfree(profile);
}

int inc_tier_profile(struct profile *profile, unsigned int tierid, enum profile_class class, dm_block_t val)
{
	struct per_tier_profile *tier_profile = profile->tier_profiles+tierid;
	dm_block_t *record;

	if (class >= __MAX_NR_TYPE) {
		DMERR("%s: Invalid profile class !!", __func__);
		return  -EINVAL;
	}

	record = (dm_block_t *)tier_profile + class;
	(*record) += val;

	return 0;
}

int dec_tier_profile(struct profile *profile, unsigned int tierid, enum profile_class class, dm_block_t val)
{
	struct per_tier_profile *tier_profile = profile->tier_profiles+tierid;
	dm_block_t *record;

	if (class >= __MAX_NR_TYPE) {
		DMERR("%s: Invalid profile class !!", __func__);
		return  -EINVAL;
	}

	record = (dm_block_t *)tier_profile + class;
	(*record) -= val;	

	return 0;
}

int set_tier_profile(struct profile *profile, unsigned int tierid, enum profile_class class, dm_block_t val)
{
	struct per_tier_profile *tier_profile = profile->tier_profiles+tierid;
	dm_block_t *record;

	if (class >= __MAX_NR_TYPE) {
		DMERR("%s: Invalid profile class !!", __func__);
		return  -EINVAL;
	}

	record = (dm_block_t *)tier_profile + class;
	(*record) = val;

	return 0;
}

bool reach_reserve(struct profile *profile, unsigned int tierid)
{
	struct per_tier_profile *tier_profile = profile->tier_profiles+tierid;

	dm_block_t total_blks = tier_profile->total_blks;
	dm_block_t free_blks = tier_profile->free_blks;
	dm_block_t res_blks = tier_profile->res_blks;

	return (total_blks - free_blks) > res_blks ? false : true;
}

bool is_remain_profile(struct profile *profile, unsigned int tierid, enum profile_class class)
{
	struct per_tier_profile *tier_profile = profile->tier_profiles+tierid;
	dm_block_t *intend;

	if (class > __MAX_NR_TYPE) {
		DMERR("Invalid profile intend class");
		return  false;
	}

	intend = (dm_block_t *)tier_profile + class;
	return (*intend) ? true : false;
}

void simulate_profile(struct profile *profile)
{
	simulate_tiers_down(profile);
	simulate_tiers_up(profile);
}

void dump_profile(struct profile *profile)
{
	unsigned int i;
	unsigned int tier_num = profile->tier_num;
	struct per_tier_profile *tier_profile;

	DMINFO("%s:%d, ---- Dump Profile Result ----", __func__, __LINE__);
	for (i = 0; i < tier_num; i++) {
		if (is_tier_prof_disable(profile, i))	
			continue;

		tier_profile = profile->tier_profiles+i;
		DMINFO("%s:%d, Tier[%d] intend_dn(%llu)", __func__, __LINE__, i, tier_profile->intend_dn);
		DMINFO("%s:%d, Tier[%d] intend_up(%llu)", __func__, __LINE__, i, tier_profile->intend_up);
		DMINFO("%s:%d, Tier[%d] migr_dn(%llu)", __func__, __LINE__, i, tier_profile->migr_dn);
		DMINFO("%s:%d, Tier[%d] migr_up(%llu)", __func__, __LINE__, i, tier_profile->migr_up);
		DMINFO("%s:%d, Tier[%d] free_blks(%llu)", __func__, __LINE__, i, tier_profile->free_blks);
		DMINFO("%s:%d, Tier[%d] total_blks(%llu)", __func__, __LINE__, i, tier_profile->total_blks);
		DMINFO("%s:%d, Tier[%d] res_blks(%llu)", __func__, __LINE__, i, tier_profile->res_blks);
		DMINFO("%s:%d, ", __func__, __LINE__);
	}

}

int set_profile_free(struct profile *profile, dm_block_t *allocated)
{
	unsigned int i, tier_num = profile->tier_num;;

	for (i = 0; i < tier_num; i++) {
		if (is_tier_prof_disable(profile, i))	
			continue;

		dec_tier_profile(profile, i, FREE_BLKS, allocated[i]);
	}
	return 0;
}

int regulate_block_to(struct analyze_data *data, struct profile *profile)
{
	dm_block_t index = 0;
	unsigned long size = data->total_block_num;

	for (index = 0; index < size; index++) {
		uint32_t old_tierid, new_tierid;
		enum profile_class migr_dir;

		index = ta_find_next_allocated(data->block_from, size, index);
		if (index >= size)
			break;

		old_tierid = ta_get_tierid(data->block_from, index);
		new_tierid = ta_get_tierid(data->block_to, index);

		if (old_tierid == new_tierid)
			continue;

		migr_dir = old_tierid < new_tierid ? MIGR_DN : MIGR_UP;

		if (is_remain_profile(profile, old_tierid, migr_dir))
			dec_tier_profile(profile, old_tierid, migr_dir, 1);
		else
			ta_store_tierid(data->block_to, index, old_tierid);

	}

	return 0;
}
