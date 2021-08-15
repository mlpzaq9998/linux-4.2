/*
 * Copyright (C) 2014-2015 QNAP, Inc.
 *
 * This file is released under the GPL.
 */

#include "dm-tier-metadata.h"
#include "persistent-data/dm-space-map.h"
#include "persistent-data/dm-space-map-disk.h"
#include "persistent-data/dm-transaction-manager.h"

#include <linux/fs.h>
#include <linux/list.h>
#include <linux/device-mapper.h>
#include <linux/workqueue.h>
#include <linux/vmalloc.h>

#define MAX_TIER_LEVEL 3
#define DM_MSG_PREFIX   "tier_metadata"

#define DEFAULT_ALLOC_TIER 0

#define RESERVE_TIER_DISABLE -1

struct dm_tier_metadata {
	uint32_t tier_num;
	unsigned long alloc_tier;

	struct dm_transaction_manager *tm;
	struct dm_transaction_manager *nb_tm;

	struct dm_space_map *tier_data_sm[MAX_TIER_LEVEL];

	struct dm_btree_info info;
	struct dm_btree_info nb_info;

	int *need_commit;

	dm_block_t root;
	dm_block_t swap_block[MAX_TIER_LEVEL];
	dm_block_t swap_total[MAX_TIER_LEVEL];
	dm_block_t retain_free[MAX_TIER_LEVEL];
	sector_t block_size;

	bool zombie_exist;

	// hook back to dm_pool_metadata
	struct rw_semaphore *lock;
	bool *fail_io;

	struct free_map *free_map;
	atomic_t gc_ready;

	void *metadata;
	int (*commit)(void *metadata);
	bool changed;
	int rtid;
};

static inline uint64_t pack_tier_block(uint32_t t, dm_block_t b, uint32_t res)
{
	return ((dm_block_t)t << 61) | (b << 24) | res;
}

static inline void unpack_tier_block(uint64_t v, uint32_t *t, dm_block_t *b, uint32_t *res)
{
	*t = v >> 61;
	*b = (v >> 24) & (((dm_block_t)1 << 37) - 1);
	if (res)
		*res = v & ((1 << 24) - 1);
}

// PATCH: new btree manipulation function for tier_data_sm
static void data_block_inc(void *context, const void *value_le)
{
	struct dm_space_map **sma = context;
	__le64 v_le;
	uint64_t nb;
	uint32_t tierid;
	uint32_t t;

	memcpy(&v_le, value_le, sizeof(v_le));
	unpack_tier_block(le64_to_cpu(v_le), &tierid, &nb, &t);
	dm_sm_inc_block(sma[tierid], nb);
}

static void data_block_dec(void *context, const void *value_le)
{
	struct dm_space_map **sma = context;
	__le64 v_le;
	uint64_t nb;
	uint32_t tierid;
	uint32_t t;

	memcpy(&v_le, value_le, sizeof(v_le));
	unpack_tier_block(le64_to_cpu(v_le), &tierid, &nb, &t);
	dm_sm_dec_block(sma[tierid], nb);
}

static int data_block_equal(void *context, const void *value1_le, const void *value2_le)
{
	__le64 v1_le, v2_le;
	uint64_t b1, b2;
	uint32_t t1, t2, r1, r2;

	memcpy(&v1_le, value1_le, sizeof(v1_le));
	memcpy(&v2_le, value2_le, sizeof(v2_le));
	unpack_tier_block(le64_to_cpu(v1_le), &t1, &b1, &r1);
	unpack_tier_block(le64_to_cpu(v2_le), &t2, &b2, &r2);

	return (b1 == b2) && (t1 == t2);
}

struct walking_callback {
	void *context1;
	void *context2;
	void *context3;
	int (*fn)(void *context1, void *context2, void *context3,
		dm_block_t block, struct dm_tier_lookup_result *result);
};

static int mapping_walker(void *context, uint64_t *keys, void *leaf)
{
	__le64 *value = leaf;
	struct dm_tier_lookup_result result;
	struct walking_callback *wcb = (struct walking_callback *)context;

	unpack_tier_block(le64_to_cpu(*value), 
		&result.tierid, &result.block, &result.reserve);

	return wcb->fn(wcb->context1, wcb->context2, 
		wcb->context3, (dm_block_t)*keys, &result);
}

static void __clear_dinfo(unsigned long *map, dm_block_t block)
{
	bitmap_clear(map, block * MAP_PACE, MAP_PACE);
}

void __set_dinfo(unsigned long *map, dm_block_t block)
{
	bitmap_set(map, block * MAP_PACE, MAP_PACE);
}

unsigned __get_dinfo(unsigned long *map, dm_block_t block)
{
	unsigned dinfo = 0;
	int bit, j = 0;

	for (bit = block * MAP_PACE; bit< (block * MAP_PACE + MAP_PACE); bit++) {
		if (test_bit(bit, map))
			dinfo |= 0x1 << j;
		j++;    
	}       

	return dinfo;
}


int get_dinfo(struct dm_tier_metadata *tmd, dm_block_t block, unsigned *dinfo)
{
	unsigned long flags;
	struct free_map *free_map = tmd->free_map;

	if (!atomic_read(&tmd->gc_ready))
		return -EINVAL;

	spin_lock_irqsave(&free_map->lock, flags);
	*dinfo = __get_dinfo(free_map->map, block);
	spin_unlock_irqrestore(&free_map->lock, flags);

	return 0;
}

int check_dinfo(struct dm_tier_metadata *tmd,
		dm_block_t block,
		unsigned *dinfo)
{
	unsigned long flags;
	struct free_map *free_map = tmd->free_map;

	if (!atomic_read(&tmd->gc_ready))
		return -EINVAL;

	spin_lock_irqsave(&free_map->lock, flags);
	*dinfo = __get_dinfo(free_map->map, block);
	if (*dinfo == MAP_MASK)
		__clear_dinfo(free_map->map, block);
	spin_unlock_irqrestore(&free_map->lock, flags);

	return 0;
}

int check_and_reset_filter(struct dm_tier_metadata *tmd, dm_block_t flt_idx)
{
	unsigned long flags;
	struct free_map *free_map = tmd->free_map;

	if (!atomic_read(&tmd->gc_ready))
		return -EINVAL;

	spin_lock_irqsave(&free_map->lock, flags);
	if (!test_bit(flt_idx, free_map->filter)) 
		bitmap_set(free_map->filter, flt_idx, 1);
	spin_unlock_irqrestore(&free_map->lock, flags);

	return 0;
}

static unsigned long __bitmap_search(unsigned long *bitmap, unsigned long size, 
	unsigned long offset, int unit)
{
	unsigned long index = offset * unit;

	index = find_next_bit(bitmap, size * unit, index);
	do_div(index, unit);
	return index;
}

int filter_search(struct dm_tier_metadata *tmd,
		  unsigned long size,
		  unsigned long offset,
		  dm_block_t *index)
{
	unsigned long flags;
	struct free_map *free_map = tmd->free_map;

	if (!atomic_read(&tmd->gc_ready))
		return -EINVAL;

	spin_lock_irqsave(&free_map->lock, flags);
	*index = __bitmap_search(free_map->filter, size, offset, FILTER_PACE);
	if (*index < size)
		bitmap_clear(free_map->filter, *index, 1);
	spin_unlock_irqrestore(&free_map->lock, flags);

	return 0;
}

int clone_map(struct dm_tier_metadata *tmd,
	      dm_block_t start,
	      unsigned size,
	      unsigned long **map)
{
	unsigned long flags;
	struct free_map *free_map = tmd->free_map;
	unsigned long total = BITS_TO_LONGS(size * MAP_PACE);

	if (!atomic_read(&tmd->gc_ready))
		return -EINVAL;

	*map = vzalloc(total * sizeof(long));
	if (!*map) { 
		DMERR("%s%d, clone map with size %lu failed", 
			__func__, __LINE__, total * sizeof(long));
		return -ENOMEM;
	}

	spin_lock_irqsave(&free_map->lock, flags);
	bitmap_copy(*map, free_map->map + start, size * MAP_PACE);
	spin_unlock_irqrestore(&free_map->lock, flags);

	return 0;
}

int construct_map(struct dm_tier_metadata *tmd,
		  unsigned long *map,
		  dm_block_t block_num)
{
	unsigned long flags;
	struct free_map *free_map = tmd->free_map;

	if (!atomic_read(&tmd->gc_ready))
		return -EINVAL;

	spin_lock_irqsave(&free_map->lock, flags);
	bitmap_and(free_map->map, free_map->map, map, block_num * MAP_PACE);
	spin_unlock_irqrestore(&free_map->lock, flags);

	return 0;
}

unsigned long map_search(unsigned long *map, 
	unsigned long size, unsigned long offset)
{
	unsigned long index;
	
	index = __bitmap_search(map, size, offset, MAP_PACE);
	return index;
}

int tier_mapping_walk(struct dm_tier_metadata *tmd,
	int (*fn)(void *context1, void *context2, void *context3, 
		dm_block_t block, struct dm_tier_lookup_result *result),
	void *context1, void *context2, void *context3)
{
	struct walking_callback wcb = {
		.fn = fn,
		.context1 = context1,
		.context2 = context2,
		.context3 = context3
	};

	return dm_btree_walk_iter(&tmd->info, tmd->root, mapping_walker, &wcb);
}

static int __get_swap_blkcnt(struct dm_tier_metadata *tmd,
			     unsigned int tierid, 
			     dm_block_t *blkcnt)
{
	*blkcnt = tmd->swap_block[tierid];
	return 0;
}

int dm_tier_get_swap_blkcnt(struct dm_tier_metadata *tmd,
			    unsigned int tierid, 
			    dm_block_t *blkcnt)
{
	int r = -EINVAL;

	down_read(tmd->lock);

	if (!*tmd->fail_io)
		r = __get_swap_blkcnt(tmd, tierid, blkcnt);

	up_read(tmd->lock);
	return r;
}

int dm_tier_set_swap_block(struct dm_tier_metadata *tmd, 
			   unsigned int tierid, 
			   dm_block_t block)
{
	int r = -EINVAL;
	dm_block_t result;

	down_write(tmd->lock);

	if (*tmd->fail_io)
		goto fail_io;

	r = dm_sm_get_nr_free(tmd->tier_data_sm[tierid], &result);
	if (r)
		goto fail_io;

	if (result < block)
		r = -ENOSPC;
	else
		tmd->swap_total[tierid] = tmd->swap_block[tierid] = block;

fail_io:
	up_write(tmd->lock);
	return r;
}

int dm_tier_set_zombie_exist(struct dm_tier_metadata *tmd)
{
	down_write(tmd->lock);
	tmd->zombie_exist = true;
	up_write(tmd->lock);
	return 0;
}

int dm_tier_get_zombie_exist(struct dm_tier_metadata *tmd, bool *result)
{
	down_read(tmd->lock);
	(*result) = tmd->zombie_exist;
	up_read(tmd->lock);
	return 0;
}

static int __find_next_mapped_block(struct dm_tier_metadata *tmd, dm_block_t block,
	dm_block_t *vblock, struct dm_tier_lookup_result *result)
{
	int r;
	__le64 value;
	uint64_t block_time = 0;

	r = dm_btree_lookup_next(&tmd->info, tmd->root, &block, vblock, &value);
	if (!r) {
		block_time = le64_to_cpu(value);
		unpack_tier_block(block_time, &result->tierid,
			&result->block, &result->reserve);
	}

	return r;
}

static int __find_block(struct dm_tier_metadata *tmd, 
	dm_block_t block, struct dm_tier_lookup_result *result)
{
	int r = -EINVAL;
	__le64 value;
	uint64_t block_time = 0;
	struct dm_btree_info *info;

	info = &tmd->info;

	r = dm_btree_lookup(info, tmd->root, &block, &value);
	if (!r) {
		block_time = le64_to_cpu(value);
		unpack_tier_block(block_time, &result->tierid,
			&result->block, &result->reserve);
	}

	return r;
}

static int __find_mapped_range(struct dm_tier_metadata *tmd,
	dm_block_t begin, dm_block_t end,
	dm_block_t *virt_begin, dm_block_t *virt_end,
	dm_block_t *data_begin, uint32_t *tid)
{
	int r;
	dm_block_t data_end;
	struct dm_tier_lookup_result lookup;

	if (end < begin)
		return -ENODATA;

	r = __find_next_mapped_block(tmd, begin, &begin, &lookup);
	if (r)
		return r;

	if (begin >= end)
		return -ENODATA;

	*virt_begin = begin;
	*data_begin = lookup.block;
	*tid = lookup.tierid;

	begin++;
	data_end = *data_begin + 1;
	while (begin != end) {
		r = __find_block(tmd, begin, &lookup);
		if (r) {
			if (r == -ENODATA)
				break;
			else
				return r;
		}

		if ((lookup.block != data_end) ||
		    (lookup.tierid != *tid))
			break;

		data_end++;
		begin++;
	}

	*virt_end = begin;
	return 0;
}

int dm_tier_find_mapped_range(struct dm_tier_metadata *tmd,
	dm_block_t begin, dm_block_t end,
	dm_block_t *virt_begin, dm_block_t *virt_end,
	dm_block_t *data_begin, uint32_t *tid)
{
	int r = -EINVAL;

	down_read(tmd->lock);
	if (!*tmd->fail_io)
		r = __find_mapped_range(tmd, begin, end, virt_begin,
					virt_end, data_begin, tid);

	up_read(tmd->lock);
	return r;
}

int dm_tier_find_block(struct dm_tier_metadata *tmd, dm_block_t block,
	int can_block, struct dm_tier_lookup_result *result)
{
	int r = -EINVAL;
	__le64 value;
	uint64_t block_time = 0;
	struct dm_btree_info *info;

	if (can_block) {
		down_read(tmd->lock);
		info = &tmd->info;
	} else if (down_read_trylock(tmd->lock))
		info = &tmd->nb_info;
	else
		return -EWOULDBLOCK;

	if (!*tmd->fail_io)
		r = dm_btree_lookup(info, tmd->root, &block, &value);

	up_read(tmd->lock);

	if (!r) {
		block_time = le64_to_cpu(value);
		unpack_tier_block(block_time, &result->tierid,
			&result->block, &result->reserve);
	}

	return r;
}

int dm_tier_set_alloc_tier(struct dm_tier_metadata *tmd, unsigned long alloc_tier)
{
	down_write(tmd->lock);
	tmd->alloc_tier = alloc_tier;
	up_write(tmd->lock);
	return 0;
}

int dm_tier_get_alloc_tier(struct dm_tier_metadata *tmd, unsigned long *alloc_tier)
{
	down_read(tmd->lock);
	*alloc_tier = tmd->alloc_tier;
	up_read(tmd->lock);
	return 0;
}

static int __get_free_block_count(struct dm_tier_metadata *tmd, 
				  unsigned int tierid, 
				  dm_block_t *result)
{
	return dm_sm_get_nr_free(tmd->tier_data_sm[tierid], result);
}

static const unsigned int find_seq[MAX_TIER_LEVEL][MAX_TIER_LEVEL] = {
	{0, 1, 2},
	{1, 2, 0},
	{2, 1, 0}
};

static int __dm_tier_set_boundary(struct dm_tier_metadata *tmd, 
				  unsigned int tierid,
				  dm_block_t b, 
				  dm_block_t e)
{
	int r = -EINVAL;
	dm_block_t retain_free;

	r = dm_sm_register_boundary(tmd->tier_data_sm[tierid], b, e);
	if (r)
		return r;

	r = dm_sm_get_nr_free_range(tmd->tier_data_sm[tierid], 
				    b, e, &retain_free);
	if (!r)
		tmd->retain_free[tierid] = retain_free;

	return r;
}

static int __dm_tier_get_boundary(struct dm_tier_metadata *tmd, 
				  unsigned int tierid, 
				  dm_block_t *b, 
				  dm_block_t *e)
{
	return dm_sm_get_boundary(tmd->tier_data_sm[tierid], b, e);
}

static int __dm_tier_clear_boundary(struct dm_tier_metadata *tmd,
				    unsigned int tierid)
{
	int r = -EINVAL;

	r = dm_sm_register_boundary(tmd->tier_data_sm[tierid],
				    U64_MAX, U64_MAX);
	if (!r)
		tmd->retain_free[tierid] = 0;

	return r;
}

/*
 * FIXME: we may get less nr_free than real nr_free,
 * which may lead to false alarm -ENOSPC, 
 * we should change swap conunt as transaction base to fix this issue
 */
static int __alloc_tier_block(struct dm_tier_metadata *tmd, 
			      unsigned int tierid, 
			      dm_block_t *block)
{
	int r;
	dm_block_t free_blks;

	r = __get_free_block_count(tmd, tierid, &free_blks);
	if (r)
		return r;

	r = -ENOSPC;
	if (free_blks <= tmd->retain_free[tierid])
		return r;

	free_blks -= tmd->retain_free[tierid];
	if (free_blks > tmd->swap_block[tierid])
		r = dm_sm_new_block(tmd->tier_data_sm[tierid], block);

	return r;
}

int dm_tier_get_retain_free(struct dm_tier_metadata *tmd, 
			    unsigned int tierid, 
			    dm_block_t *retain_free)
{
	down_read(tmd->lock);
	(*retain_free) = tmd->retain_free[tierid];
	up_read(tmd->lock);
	return 0;
}

int dm_tier_alloc_lower_block(struct dm_tier_metadata *tmd,
			      unsigned int *tierid,
			      unsigned int enable_map, 
			      dm_block_t *block)
{
	int r = -EINVAL;

	down_write(tmd->lock);

	if (*tmd->fail_io)
		goto fail_io;

	*tierid += 1;
	for (; *tierid < MAX_TIER_LEVEL; (*tierid)++) {
		if (!(enable_map & (1 << *tierid)))
			continue;

		r = __alloc_tier_block(tmd, *tierid, block);
		if (r == -ENOSPC)
			continue;
		else
			break;
	}

	if (!r)
		*tmd->need_commit = 1;
fail_io:
	up_write(tmd->lock);
	return r;
}

int dm_tier_find_free_tier_and_alloc(struct dm_tier_metadata *tmd,
				     uint32_t *tierid,
				     enum alloc_order ao,
				     unsigned int enable_map,
				     dm_block_t *block)
{
	int r = -EINVAL;
	const unsigned int *seq;
	unsigned int i;

	down_write(tmd->lock);

	seq = (ao == NORMAL_ALLOC) ? 
		find_seq[tmd->alloc_tier] : find_seq[ao];	

	if (*tmd->fail_io)
		goto fail_io;

	for (i = 0; i < MAX_TIER_LEVEL; i++) {
		if (!(enable_map & (1 << seq[i])))
			continue;

		r = __alloc_tier_block(tmd, seq[i], block);
		if (r == -ENOSPC)
			continue;
		else
			break;
	}

	if (!r) {
		*tierid = seq[i];
		*tmd->need_commit = 1;
	}

fail_io:
	up_write(tmd->lock);
	return r;
}

int dm_tier_alloc_block(struct dm_tier_metadata *tmd, 
			unsigned int tierid,
			dm_block_t *block)
{
	int r = -EINVAL;

	down_write(tmd->lock);

	if (*tmd->fail_io)
		goto fail_io;

	r = __alloc_tier_block(tmd, tierid, block);

	if (!r)
		*tmd->need_commit = 1;
fail_io:
	up_write(tmd->lock);
	return r;
}

int dm_tier_alloc_blk_remove_swap(struct dm_tier_metadata *tmd, 
				  unsigned int old_tierid,
				  unsigned int new_tierid,
				  dm_block_t *block)
{
	int r = -EINVAL;

	down_write(tmd->lock);

	if (*tmd->fail_io)
		goto fail_io;

	if (tmd->swap_block[old_tierid])
		tmd->swap_block[old_tierid]--;
	else {
		r = -EBUSY;
		goto fail_io;
	}

	r = __alloc_tier_block(tmd, new_tierid, block);
	if (r)
		tmd->swap_block[old_tierid]++;
	else
		*tmd->need_commit = 1;

fail_io:
	up_write(tmd->lock);
	return r;
}

static int __alloc_data_range(struct dm_tier_metadata *tmd, 
	uint32_t tid, dm_block_t b, dm_block_t e)
{
	int r = 0;

	for (; b != e; b++) {
		r = dm_sm_alloc_block(tmd->tier_data_sm[tid], b);
		if (r)
			break;
	}

	return r;
}

static int __add_swap_block(struct dm_tier_metadata *tmd, 
	uint32_t tid, dm_block_t cnt)
{
	tmd->swap_block[tid] += cnt;
	return 0;
}

static int __dec_swap_block(struct dm_tier_metadata *tmd,
	uint32_t tid, dm_block_t cnt)
{
	if (tmd->swap_block[tid] < cnt)
		return -EINVAL;

	tmd->swap_block[tid] -= cnt;
	return 0;
}

static int __dec_data_range(struct dm_tier_metadata *tmd, 
	uint32_t tid, dm_block_t b, dm_block_t e)
{
	int r = 0;

	for (; b != e; b++) {
		r = dm_sm_dec_block(tmd->tier_data_sm[tid], b);
		if (r)
			break;
	}

	return r;
}

static int __tier_block_is_used(struct dm_tier_metadata *tmd, 
				uint32_t tid,
				dm_block_t b,
				bool *result)
{
	int r;
	uint32_t ref_count;

	r = dm_sm_get_count(tmd->tier_data_sm[tid], b, &ref_count);
	if (!r)
		*result = (ref_count != 0);

	return r;
}

static int __find_unmapped_range(struct dm_tier_metadata *tmd,
				 uint32_t tid,
				 dm_block_t begin,
				 dm_block_t end,
				 dm_block_t *tier_begin,
				 dm_block_t *tier_end)
{
	int r;
	bool used = true;
	dm_block_t e;

	/* find start of unmapped run */
	for (; begin < end; begin++) {
		r = __tier_block_is_used(tmd, tid, begin, &used);
		if (r)
			return r;

		if (!used)
			break;
	}

	*tier_begin = begin;
	if (begin == end) {
		*tier_end = end;
		return 0;
	}

	/* find end of run */
	for(e = *tier_begin + 1; e != end; e++) {
		r = __tier_block_is_used(tmd, tid, e, &used);
		if (r)
			return r;

		if (used)
			break;
	}

	*tier_end = e;
	return 0;
}

int dm_tier_find_unmapped_alloc_swap_and_blk(struct dm_tier_metadata *tmd,
	uint32_t tid, dm_block_t begin, dm_block_t end,
	dm_block_t *tier_begin, dm_block_t *tier_end)
{
	int r;
	dm_block_t swap_cnt = 0;

	down_write(tmd->lock);

	r = __find_unmapped_range(tmd, tid, begin, end, tier_begin, tier_end);
	if (r)
		goto unlock;

	r = __get_swap_blkcnt(tmd, tid, &swap_cnt);
	if (r)
		goto unlock;

	if (swap_cnt < *tier_end - *tier_begin)
		*tier_end = *tier_begin + swap_cnt;

	r = __dec_swap_block(tmd, tid, *tier_end - *tier_begin);
	if (r)
		goto unlock;

	r = __alloc_data_range(tmd, tid, *tier_begin, *tier_end);
	if (r)
		goto fail_inc_range;

	*tmd->need_commit = 1;
	up_write(tmd->lock);
	return 0;

fail_inc_range:
	__add_swap_block(tmd, tid, *tier_end - *tier_begin);
unlock:
	up_write(tmd->lock);
	return r;
}

int dm_tier_remove_swap_dec_range(struct dm_tier_metadata *tmd, 
	uint32_t tid, dm_block_t b, dm_block_t e)
{
	int r = 0;

	down_write(tmd->lock);

	r = __add_swap_block(tmd, tid, e - b);
	if (r)
		goto unlock;

	r = __dec_data_range(tmd, tid, b, e);
	if (r)
		goto fail_dec_range;

	*tmd->need_commit = 1;
	up_write(tmd->lock);
	return 0;

fail_dec_range:
	__dec_swap_block(tmd, tid, e - b);
unlock:
	up_write(tmd->lock);
	return r;
}

static int __insert_block(struct dm_tier_metadata *tmd,
			  dm_block_t block,
			  dm_block_t data_block,
			  uint32_t tierid,
			  uint32_t res)
{
	int r, inserted;
	__le64 value;

	value = cpu_to_le64(pack_tier_block(tierid, data_block, res));
	__dm_bless_for_disk(&value);


	r = dm_btree_insert_notify(&tmd->info, tmd->root, &block,
		&value, &tmd->root, &inserted);
	if (r)
		return r;

	tmd->changed = true;
	return 0;
}

int dm_tier_insert_block(struct dm_tier_metadata *tmd, 
			 dm_block_t block,
			 dm_block_t data_block,
			 uint32_t tierid)
{
	int r = -EINVAL;

	down_write(tmd->lock);

	if (*tmd->fail_io)
		goto fail_io;

	r = __insert_block(tmd, block, data_block, tierid, 0);
	if (!r)
		*tmd->need_commit = 1;

fail_io:
	up_write(tmd->lock);
	return r;
}

int dm_tier_insert_block_reserve(struct dm_tier_metadata *tmd, 
				 dm_block_t block,
				 dm_block_t data_block,
				 uint32_t tierid,
				 uint32_t res)
{
	int r;

	down_write(tmd->lock);
	r = __insert_block(tmd, block, data_block, tierid, res);
	if (!r)
		*tmd->need_commit = 1;
	up_write(tmd->lock);

	return r;
}

int dm_tier_insert_block_free_swap(struct dm_tier_metadata *tmd,
				   dm_block_t block,
				   dm_block_t data_block,
				   unsigned int tierid,
				   struct dm_tier_lookup_result old)
{
	int r = -EINVAL;

	down_write(tmd->lock);

	if (*tmd->fail_io)
		goto fail_io;

	r = __insert_block(tmd, block, data_block, tierid, old.reserve);
	if (!r) {
		tmd->swap_block[old.tierid]++;
		*tmd->need_commit = 1;
	}

fail_io:
	up_write(tmd->lock);
	return r;
}

int dm_tier_insert_block_check_retain(struct dm_tier_metadata *tmd,
				      dm_block_t block,
				      dm_block_t data_block,
				      unsigned int tierid,
				      struct dm_tier_lookup_result old)
{
	int r = -EINVAL;
	dm_block_t b, e;

	down_write(tmd->lock);

	if (*tmd->fail_io)
		goto fail_io;

	r = __dm_tier_get_boundary(tmd, old.tierid, &b, &e);
	if (r)
		goto fail_io;

	r = __insert_block(tmd, block, data_block, tierid, old.reserve);
	if (!r) {
		if (old.block >= b && old.block < e)
			tmd->retain_free[old.tierid]++;
		*tmd->need_commit = 1;
	}

fail_io:
	up_write(tmd->lock);
	return r;
}

int dm_tier_remove_block(struct dm_tier_metadata *tmd, dm_block_t block)
{
	int r = -EINVAL;
	struct dm_tier_lookup_result lookup;
	dm_block_t b, e;

	down_write(tmd->lock);

	if (*tmd->fail_io)
		goto fail_io;

	r = __find_block(tmd, block, &lookup);
	if (r)
		goto fail_io;

	r = __dm_tier_get_boundary(tmd, lookup.tierid, &b, &e);
	if (r)
		goto fail_io;

	r = dm_btree_remove(&tmd->info, tmd->root, &block, &tmd->root);
	if (!r) {
		tmd->changed = true;
		*tmd->need_commit = 1;
		if (lookup.block >= b && lookup.block < e)
			tmd->retain_free[lookup.tierid]++;
	}

fail_io:
	up_write(tmd->lock);
	return r;
}

/*
 * FIXME: we may get false alarm -ENOSPC, even swap cnt > 0
 * we should change swap conunt as transaction base to fix this issue
 */
int dm_tier_alloc_swap_block(struct dm_tier_metadata *tmd, 
			     unsigned int tierid,
			     dm_block_t *result)
{
	int r = -EINVAL;
	dm_block_t free_blks;

	down_write(tmd->lock);

	if (*tmd->fail_io)
		goto fail_io;

	r = -EBUSY;
	if (!tmd->swap_block[tierid])
		goto fail_io;

	r = __get_free_block_count(tmd, tierid, &free_blks);
	if (r)
		goto fail_io;

	r = -ENOSPC;
	if (free_blks <= tmd->retain_free[tierid])
		goto fail_io;

	r = dm_sm_new_block(tmd->tier_data_sm[tierid], result);
	if (r)
		goto fail_io;

	tmd->swap_block[tierid]--;
	*tmd->need_commit = 1;

fail_io:
	up_write(tmd->lock);
	return r;
}

int dm_tier_free_swap_block(struct dm_tier_metadata *tmd, 
			    unsigned int tierid,
			    dm_block_t block)
{
	int r = -EINVAL;

	down_write(tmd->lock);

	if (*tmd->fail_io)
		goto fail_io;

	r = dm_sm_dec_block(tmd->tier_data_sm[tierid], block);
	if (!r) {
		tmd->swap_block[tierid]++;
		*tmd->need_commit = 1;
	}

fail_io:
	up_write(tmd->lock);
	return r;
}

int dm_tier_get_data_dev_size(struct dm_tier_metadata *tmd, 
			      unsigned int tierid,
			      dm_block_t *result)
{
	int r = -EINVAL;

	down_read(tmd->lock);
	if (!*tmd->fail_io)
		r = dm_sm_get_nr_blocks(tmd->tier_data_sm[tierid], result);
	if (!r)
		*result -= tmd->swap_total[tierid];
	up_read(tmd->lock);

	return r;
}

static int __dm_tier_get_data_dev_real_size(struct dm_tier_metadata *tmd, 
					    unsigned int tierid,
					    dm_block_t *result)
{
	int r = -EINVAL;

	r = dm_sm_get_nr_blocks(tmd->tier_data_sm[tierid], result);

	return r;
}

int dm_tier_get_data_dev_real_size(struct dm_tier_metadata *tmd, 
				   unsigned int tierid,
				   dm_block_t *result)
{
	int r = -EINVAL;

	down_read(tmd->lock);
	if (!*tmd->fail_io)
		r = __dm_tier_get_data_dev_real_size(tmd, tierid, result);
	up_read(tmd->lock);

	return r;
}

/*
 * FIXME: we may report less nr_free than real nr_free,
 * we should change swap conunt as transaction base to fix this issue
 */
int dm_tier_get_free_block_count(struct dm_tier_metadata *tmd, 
				 unsigned int tierid,
				 dm_block_t *result)
{
	int r = -EINVAL;
	dm_block_t nr_free;

	down_read(tmd->lock);

	if (*tmd->fail_io)
		goto fail_io;

	r = __get_free_block_count(tmd, tierid, &nr_free);
	if (r)
		goto fail_io;

	(*result) = nr_free >= tmd->swap_block[tierid] ?
		nr_free - tmd->swap_block[tierid] : 0;

fail_io:
	up_read(tmd->lock);
	return r;
}

int dm_tier_get_free_blk_real_cnt(struct dm_tier_metadata *tmd, 
				  unsigned int tierid,
				  dm_block_t *result)
{
	int r = -EINVAL;

	down_read(tmd->lock);

	if (!*tmd->fail_io)
		r = __get_free_block_count(tmd, tierid, result);

	up_read(tmd->lock);
	return r;
}

int dm_tier_get_free_blk_cnt_range(struct dm_tier_metadata *tmd, 
				   unsigned int tierid,
				   dm_block_t begin, 
				   dm_block_t end,
				   dm_block_t *result)
{
	int r = -EINVAL;

	down_read(tmd->lock);

	if (!*tmd->fail_io)
		r = dm_sm_get_nr_free_range(tmd->tier_data_sm[tierid],
					    begin, end, result);

	up_read(tmd->lock);
	return r;
}

/*
 * this function get the total #allocated block,
 * include allocated swaps and zombies
 */
int dm_tier_get_allocate_count(struct dm_tier_metadata *tmd, 
			       unsigned int tierid,
			       dm_block_t *result)
{
	int r = -EINVAL;
	dm_block_t nr_blocks, nr_free;

	down_read(tmd->lock);

	if (*tmd->fail_io)
		goto fail_io;

	r = __dm_tier_get_data_dev_real_size(tmd, tierid, &nr_blocks);
	if (r)
		goto fail_io;

	r = __get_free_block_count(tmd, tierid, &nr_free);
	if (r)
		goto fail_io;

	*result = (nr_blocks - nr_free);

fail_io:
	up_read(tmd->lock);
	return r;
}

/*
 * FIXME: this function only can be called during no swaps is allocated,
 * no zombies and no discard is on-the-fly, besides, becuase the data in
 * forbidden region must be found, commit is needed before use this function
 */
int dm_tier_get_swap_shortage(struct dm_tier_metadata *tmd, 
			      unsigned int tierid,
			      dm_block_t *shortage)
{
	int r = -EINVAL;
	dm_block_t free_blks, swap;

	(*shortage) = 0;

	down_read(tmd->lock);

	if (*tmd->fail_io)
		goto fail_io;

	r = __get_free_block_count(tmd, tierid, &free_blks);
	if (r)
		goto fail_io;

	r = __get_swap_blkcnt(tmd, tierid, &swap);
	if (r)
		goto fail_io;

	if (free_blks < tmd->retain_free[tierid]) {
		r = -EINVAL;
		goto fail_io;
	}

	if (swap >= (free_blks - tmd->retain_free[tierid]))
		(*shortage) = swap - (free_blks - tmd->retain_free[tierid]);

fail_io:
	up_read(tmd->lock);
	return r;
}

int dm_tier_set_boundary(struct dm_tier_metadata *tmd, 
			 unsigned int tierid,
			 dm_block_t b,
			 dm_block_t e)
{
	int ret = -EINVAL;

	down_write(tmd->lock);

	if (*tmd->fail_io)
		goto fail_io;

	ret = __dm_tier_set_boundary(tmd, tierid, b, e);
	if (ret)
		goto fail_io;

	tmd->rtid = (int)tierid;

fail_io:
	up_write(tmd->lock);
	return ret;
}

int dm_tier_chk_and_clear_boundary(struct dm_tier_metadata *tmd)
{
	int r = -EINVAL;

	down_write(tmd->lock);

	if (*tmd->fail_io)
		goto fail_io;

	if (tmd->rtid == RESERVE_TIER_DISABLE){
		r = 0;
		goto fail_io;
	}

	r = __dm_tier_clear_boundary(tmd, (unsigned int)tmd->rtid);
	if (r)
		goto fail_io;

	tmd->rtid = RESERVE_TIER_DISABLE;

fail_io:
	up_write(tmd->lock);
	return r;
}

int dm_tier_has_reserve(struct dm_tier_metadata *tmd, bool *result)
{
	down_read(tmd->lock);
	*result = tmd->rtid == RESERVE_TIER_DISABLE ? false : true;
	up_read(tmd->lock);
	return 0;
}

int dm_tier_on_reserve_tid(struct dm_tier_metadata *tmd,
			   struct dm_tier_lookup_result *blk,
			   bool *result)
{
	down_read(tmd->lock);

	*result = false;
	if (tmd->rtid == RESERVE_TIER_DISABLE || tmd->rtid != blk->tierid)
		goto out;

	*result = true;

out:
	up_read(tmd->lock);
	return 0;
}

int dm_tier_in_reserve(struct dm_tier_metadata *tmd,
		       struct dm_tier_lookup_result *blk,
		       bool *result)
{
	dm_block_t b, e;
	int r = -EINVAL;

	down_read(tmd->lock);

	if (*tmd->fail_io)
		goto out;

	r = 0;
	if (tmd->rtid == RESERVE_TIER_DISABLE || tmd->rtid != blk->tierid) {
		*result = false;
		goto out;
	}

	r = __dm_tier_get_boundary(tmd, (unsigned int)tmd->rtid, &b, &e);
	if (r)
		goto out;

	*result = blk->block >= b && blk->block < e;

out:
	up_read(tmd->lock);
	return 0;
}

int dm_tier_resize_data_dev(struct dm_tier_metadata *tmd, 
	unsigned int tierid, dm_block_t new_count)
{
	int r = -EINVAL;

	DMDEBUG("%s: resize tier %u to %llu", __func__, tierid, new_count);
	down_write(tmd->lock);

	if (*tmd->fail_io)
		goto out;

	if (tierid < tmd->tier_num) {
		dm_block_t old_count;
		struct dm_space_map *sm = tmd->tier_data_sm[tierid];

		r = dm_sm_get_nr_blocks(sm, &old_count);
		if (r)
			goto out;

		if (new_count == old_count)
			goto out;

		if (new_count < old_count) {
			DMERR("cannot reduce size of space map");
			r = -EINVAL;
			goto out;
		}

		r = dm_sm_extend(sm, new_count - old_count);
	} else
		DMERR("Cannot resize space map of unused tier");
out:
	if (!r) {
		tmd->changed = true;
		*tmd->need_commit = 1;
	}
	up_write(tmd->lock);

	return r;
}

static void __hook_pool_metadata(struct dm_tier_metadata *tmd, struct pmd_hook *h)
{
	tmd->tm = h->tm;
	tmd->nb_tm = h->nb_tm;
	tmd->fail_io = h->fail_io;
	tmd->lock = h->root_lock;
	tmd->need_commit = h->need_commit;
	tmd->metadata = h->metadata;
	tmd->commit = h->commit;
	tmd->free_map = h->free_map;

	tmd->info.tm = tmd->tm;
	tmd->info.levels = 1;
	tmd->info.value_type.context = tmd->tier_data_sm;
	tmd->info.value_type.inc = data_block_inc;
	tmd->info.value_type.dec = data_block_dec;
	tmd->info.value_type.size = sizeof(__le64);
	tmd->info.value_type.equal = data_block_equal;

	memcpy(&tmd->nb_info, &tmd->info, sizeof(tmd->nb_info));
	tmd->nb_info.tm = tmd->nb_tm;

	return;
}

int dm_tier_format_metadata(void *context, struct pmd_hook *h)
{
	int r;
	unsigned int i, j;
	struct dm_tier_metadata *tmd = (struct dm_tier_metadata *)context;

	if (!tmd)
		return 0;

	__hook_pool_metadata(tmd, h);

	for (i = 0; i < tmd->tier_num; i++) {
		tmd->tier_data_sm[i] = dm_sm_disk_create(tmd->tm, 0, NULL);
		if (IS_ERR(tmd->tier_data_sm[i])) {
			DMERR("sm_disk_create tier sm failed");
			r = PTR_ERR(tmd->tier_data_sm[i]);
			goto bad_tier_sm;
		}
	}

	r = dm_btree_empty(&tmd->info, &tmd->root);
	if (r < 0) {
		DMERR("couldn't create pool map root");
		goto bad_tier_sm;
	}

	atomic_set(&tmd->gc_ready, 1);
	return 0;

bad_tier_sm:
	for (j = 0; j < i; j++)
		dm_sm_destroy(tmd->tier_data_sm[j]);

	return r;
}

int dm_tier_open_metadata(void *context, struct pmd_hook *h, 
	struct thin_disk_superblock *disk_super)
{
	int r;
	unsigned int i, j ;
	size_t data_len = 0;
	void *sm_root;
	struct dm_tier_metadata *tmd = (struct dm_tier_metadata *)context;

	if (!tmd)
		return 0;

	__hook_pool_metadata(tmd, h);

	for (i=0; i < tmd->tier_num; i++) {
		switch (i) {
		case 0:
			sm_root = disk_super->tier0_data_space_map_root;
			data_len = sizeof(disk_super->tier0_data_space_map_root);
			break;
		case 1:
			sm_root = disk_super->tier1_data_space_map_root;
			data_len = sizeof(disk_super->tier1_data_space_map_root);
			break;
		case 2:
			sm_root = disk_super->tier2_data_space_map_root;
			data_len = sizeof(disk_super->tier2_data_space_map_root);
			break;
		default:
			DMERR("%s: cannot recognize tier number greater than 3", __func__);
			r = -EINVAL;
			goto err_out;
		}

		tmd->tier_data_sm[i] = dm_sm_disk_open(tmd->tm, sm_root, data_len, NULL);
		if (IS_ERR(tmd->tier_data_sm[i])) {
			DMERR("sm_disk_open tier data sm failed");
			r = PTR_ERR(tmd->tier_data_sm[i]);
			goto err_out;
		}
	}

	atomic_set(&tmd->gc_ready, 1);
	return 0;

err_out:
	for (j = 0; j < i; j++)
		dm_sm_destroy(tmd->tier_data_sm[j]);

	return r;
}

void dm_tier_destory_metadata(void *context)
{
	unsigned int i;
	struct dm_tier_metadata *tmd = (struct dm_tier_metadata *)context;

	if (!tmd)
		return;

	atomic_set(&tmd->gc_ready, 0);
	for (i = 0; i < tmd->tier_num; i++)
		dm_sm_destroy(tmd->tier_data_sm[i]);

	return;
}


void __tier_begin_transaction(void *context, struct thin_disk_superblock *disk_super)
{
	struct dm_tier_metadata *tmd = (struct dm_tier_metadata *)context;

	if (!tmd)
		return;

	tmd->tier_num = le32_to_cpu(disk_super->tier_num);
	tmd->root = le64_to_cpu(disk_super->pool_mapping_root);
	tmd->block_size = le32_to_cpu(disk_super->tier_block_size);
}

bool __is_tier_changed(void *context)
{
	struct dm_tier_metadata *tmd = (struct dm_tier_metadata *)context;

	if (!tmd)
		return false;

	return tmd->changed;
}

int __tier_commit_metadata(void *context, struct thin_disk_superblock *disk_super)
{
	int r;
	unsigned int i;
	size_t data_len;
	void *sm_root = NULL;
	struct dm_tier_metadata *tmd = (struct dm_tier_metadata *)context;

	if (!tmd)
		return 0;

	for (i = 0; i < tmd->tier_num; i++) {
		r = dm_sm_commit(tmd->tier_data_sm[i]);
		if (r < 0)
			return r;
	}

	disk_super->pool_mapping_root = cpu_to_le64(tmd->root);
	disk_super->tier_num = cpu_to_le32(tmd->tier_num);
	disk_super->tier_block_size = cpu_to_le32(tmd->block_size);

	for (i = 0; i < tmd->tier_num; i++) {
		switch (i) {
			case 0:
				sm_root = &disk_super->tier0_data_space_map_root;
				break;
			case 1:
				sm_root = &disk_super->tier1_data_space_map_root;
				break;
			case 2:
				sm_root = &disk_super->tier2_data_space_map_root;
				break;
		}

		r = dm_sm_root_size(tmd->tier_data_sm[i], &data_len);
		if (r < 0)
			return r;

		r = dm_sm_copy_root(tmd->tier_data_sm[i], sm_root,
				    data_len);
		if (r < 0)
			return r;
	}

	tmd->changed = false;
	return 0;
}

int __tier_init_metadata(void *context, void **p)
{
	struct tier_c *tc = (struct tier_c *)context;
	struct dm_tier_metadata *tmd;

	if (!tc) {
		*p = NULL;
		return 0;
	}

	tmd = *p = kzalloc(sizeof(struct dm_tier_metadata), GFP_KERNEL);
	if (!tmd) {
		DMERR("%s: could not alloacte tier metadata structure", __func__);
		return -EINVAL;
	}

	tmd->tier_num = tc->tier_num;
	tmd->alloc_tier = DEFAULT_ALLOC_TIER;
	tmd->block_size = tc->tier_blk_size;
	tmd->changed = false;
	tmd->rtid = RESERVE_TIER_DISABLE;
	atomic_set(&tmd->gc_ready, 0);
	return 0;
}

void __tier_free_metadata(void *context)
{
	struct dm_tier_metadata *tmd = (struct dm_tier_metadata *)context;

	kfree(tmd);
}

int dm_tier_commit_metadata(struct dm_tier_metadata *tmd)
{
	void *metadata = tmd->metadata;

	if (tmd->commit)
		return tmd->commit(metadata);
	else
		return -EINVAL;
}
