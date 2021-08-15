#ifndef DM_TIER_ALGO_INTERNAL_H
#define DM_TIER_ALGO_INTERNAL_H

#include "dm-tier-algo.h"

static inline void algo_update_stats(struct dm_tier_algo *a, dm_block_t b, struct bio *bio)
{
	a->update(a, b, bio);
}

static inline void algo_clear_stats(struct dm_tier_algo *a, dm_block_t b)
{
	a->clear(a, b);
}

static inline int algo_resize(struct dm_tier_algo *a, dm_block_t new_block_num)
{
	return a->resize(a, new_block_num);
}

static inline int algo_analyze(struct dm_tier_algo *a, struct analyze_data *adata)
{
	return a->analyze(a, adata);
}

void dm_tier_algo_get(struct dm_tier_algo *a);
void dm_tier_algo_put(struct dm_tier_algo *a);
char *dm_tier_algo_get_name(struct dm_tier_algo *a);
struct dm_tier_algo *dm_tier_algo_create(const char *name, struct kobject *kobj);

#endif
