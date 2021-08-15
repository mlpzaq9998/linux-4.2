#ifndef DM_TIER_ALGO_UTILITY_H
#define DM_TIER_ALGO_UTILITY_H

#include "dm-tier-algo.h"

#define BLKS_PER_BYTE 4
#define BITS_IN_BYTE 8

#define TIER_BITS (fls(MAX_TIER_LEVEL))
#define TIER_MASK ((1UL << TIER_BITS) - 1)
#define BLOCKS_PER_LONG (BITS_PER_LONG / TIER_BITS)

#define ONE_HUNDRED 100

#define SSD_TIER_ID 0

#define MAX_STAT_COUNT 10000000	/* We count max 10 million hits, hits are reset upon migration */
#define MAX_STAT_DECAY 500000	/* Loose 5% hits per walk when we have reached the max */

#define STACK_MIN 2

enum temperature {
	HOT = 0,
	NORMAL,
	COLD,
	__NR_TEMPER_STATE
};

static const int freq_regulate[__NR_TEMPER_STATE] = {4, 2, 0};

enum anchor {
	ANCHOR_CLEAR = 0,
	ANCHOR_HOT,
	ANCHOR_COLD,
	__NR_ANCHOR_STATE
};

#define ANCHOR_BITS (fls(__NR_ANCHOR_STATE))
#define ANCHOR_MASK ((1UL << ANCHOR_BITS) - 1)
#define ANCHORS_PER_LONG (BITS_PER_LONG / ANCHOR_BITS)

enum profile_class {
	INTEND_DN = 0,
	INTEND_UP,
	MIGR_DN,
	MIGR_UP,
	FREE_BLKS,
	TOTAL_BLKS,
	RES_BLKS,
	__MAX_NR_TYPE
};

struct per_tier_profile {
	dm_block_t intend_dn;
	dm_block_t intend_up;
	dm_block_t migr_dn;
	dm_block_t migr_up;
	dm_block_t free_blks;
	dm_block_t total_blks;
	dm_block_t res_blks;
};

struct profile
{
	unsigned int tier_num;
	struct per_tier_profile *tier_profiles;
};

void ta_clear_tierid(unsigned long *map, dm_block_t block);
uint32_t ta_get_tierid(unsigned long *map, dm_block_t block);
void ta_store_tierid(unsigned long *map, dm_block_t block, uint32_t tierid);
dm_block_t ta_find_next_allocated(unsigned long *bitmap, unsigned long size, dm_block_t offset);
dm_block_t ta_find_next_target_tier(unsigned long *bitmap, unsigned long size, dm_block_t offset, uint32_t tierid);
dm_block_t ta_get_mapping_count(unsigned long *bitmap, unsigned long size);

void ta_anchormap_clear(unsigned long *map, dm_block_t block);
void ta_anchormap_store(unsigned long *map, dm_block_t block, enum anchor anchor);
enum anchor ta_anchormap_get(unsigned long *map, dm_block_t block);
dm_block_t ta_anchormap_search(unsigned long *map, unsigned long size, dm_block_t offset);
bool ta_anchored_block(unsigned long *map, dm_block_t block);

bool is_tier_disabled(struct analyze_data *data, uint32_t tierid);
int find_next_tid(struct analyze_data *data, uint32_t *tierid);
int find_top_tid(struct analyze_data *data, uint32_t *tierid);
int find_prev_tid(struct analyze_data *data, uint32_t *tierid);
int find_bottom_tid(struct analyze_data *data, uint32_t *tierid);

int get_temper(struct bio *bio);

void scorer_init(struct scorer *scorer, struct score_profiler *score_pf, dm_block_t *mapped, uint64_t ssd_access);
void scorer_update(struct scorer *scorer, uint32_t tid, uint64_t score);

bool is_dryrun(struct analyze_data *data);

/*
 *  Utilities for cluster set
 */
int cluster_set_init(struct cluster_set *set);
void cluster_set_reclaim(struct cluster_set *set);
void update_cluster_set_attr(struct cluster_set *set, uint64_t max, uint64_t min);
void __cluster_set_add(struct cluster_set *set, struct per_block_info *info);
void cluster_set_add(struct cluster_set *set, struct per_block_info *info);
struct per_block_info *cluster_set_extract(struct cluster_set *set);
struct per_block_info * cluster_set_find_and_get(struct cluster_set *set, uint32_t index);
struct per_block_info * cluster_set_match_and_get(struct cluster_set *set, unsigned long *block_from, 
	unsigned long *block_to, uint32_t old_tid, uint32_t new_tid);
void __cluster_set_walk(struct cluster_set *set, 
	void (*fn)(void *context, struct per_block_info *info), void *context);
void dump_cluster_set(struct cluster_set *set);

/*
 *  Utilities for migration stack 
 */
void migration_stack_init(struct migration_stack *stack);
int migration_stack_len(struct migration_stack *stack);
struct per_block_info* migration_stack_pop(struct migration_stack *stack);
void migration_stack_push(struct migration_stack *stack, struct per_block_info *info);
void migration_stack_reclaim(struct migration_stack *stack);

/*
 *  Utilities for reserve context
 */
void rctrl_init(struct reserve_ctrl *rctrl);
void rctrl_config(struct reserve_ctrl *rctrl, 
		  enum reserve_type type,
		  int tid,
		  dm_block_t size,
		  dm_block_t begin,
		  dm_block_t end);
enum reserve_type rctrl_get_type(struct reserve_ctrl *rctrl);
char* rctrl_get_type_str(struct reserve_ctrl *rctrl);
int rctrl_get_tierid(struct reserve_ctrl *rctrl);
dm_block_t rctrl_get_dev_size(struct reserve_ctrl *rctrl);
void rctrl_sub_retain(struct reserve_ctrl *rctrl, int shrink);
dm_block_t rctrl_get_retain(struct reserve_ctrl *rctrl);
dm_block_t rctrl_get_begin(struct reserve_ctrl *rctrl);
dm_block_t rctrl_get_end(struct reserve_ctrl *rctrl);

/*
 * Profile manuplate methods
 */
struct profile * create_profile(struct analyze_data *data, int reserve_ratio);
void destroy_profile(struct profile *profile);
int inc_tier_profile(struct profile *profile, unsigned int tierid, enum profile_class class, dm_block_t val);
int dec_tier_profile(struct profile *profile, unsigned int tierid, enum profile_class class, dm_block_t val);
int set_tier_profile(struct profile *profile, unsigned int tierid, enum profile_class class, dm_block_t val);
bool reach_reserve(struct profile *profile, unsigned int tierid);
bool is_remain_profile(struct profile *profile, unsigned int tierid, enum profile_class class);
void simulate_profile(struct profile *profile);
void dump_profile(struct profile *profile);
int set_profile_free(struct profile *profile, dm_block_t *allocated);
int regulate_block_to(struct analyze_data *data, struct profile *profile);

#endif
