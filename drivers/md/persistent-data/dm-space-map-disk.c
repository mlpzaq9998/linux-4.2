/*
 * Copyright (C) 2011 Red Hat, Inc.
 *
 * This file is released under the GPL.
 */

#include "dm-space-map-common.h"
#include "dm-space-map-disk.h"
#include "dm-space-map.h"
#include "dm-transaction-manager.h"

#include <linux/list.h>
#include <linux/slab.h>
#include <linux/export.h>
#include <linux/device-mapper.h>
#include <linux/vmalloc.h>

#define DM_MSG_PREFIX "space map disk"
#define FILTER_SHIFT 17

/*----------------------------------------------------------------*/

/*
 * Space map interface.
 */
struct sm_disk {
	struct dm_space_map sm;

	struct ll_disk ll;
	struct ll_disk old_ll;

	dm_block_t begin;
	dm_block_t nr_allocated_this_transaction;

	/*
	 * A bitmap for tier space reclaim
	 */
	struct free_map *free_map;

	dm_block_t bound_b, bound_e;
};

static void sm_release_free_map(struct sm_disk *smd)
{
	if (!smd->free_map)
		return;

	vfree(smd->free_map->filter);
	vfree(smd->free_map->map);
}

static int sm_disk_get_nr_free_range(struct dm_space_map *sm, 
	dm_block_t begin, dm_block_t end, dm_block_t *count)
{
	dm_block_t b, result;
	int r = 0, r1 = 0, free_blks = 0;
	struct sm_disk *smd = container_of(sm, struct sm_disk, sm);

	*count = 0;
	for (b = begin; !r; b = result + free_blks) {
		r = sm_ll_find_serial_free_blks(&smd->ll, b, end, &result, &free_blks);
		if (r) {
			if (r != -ENOSPC) {
				DMWARN("%s: get free count before boundary failure", __func__);
				r1 = r;
			}
			break;
		}

		(*count) += free_blks;
	}

	return r1;
}

static void sm_disk_destroy(struct dm_space_map *sm)
{
	struct sm_disk *smd = container_of(sm, struct sm_disk, sm);

	sm_release_free_map(smd);
	kfree(smd);
}

static void __update_bitmap(void **ptr_addr, void **new_addr, uint64_t size)
{
	if (*ptr_addr && size) {
		memcpy(*new_addr, *ptr_addr, size);
		vfree(*ptr_addr);
	}

	*ptr_addr = *new_addr;
}

static void sm_resize_free_map(struct sm_disk *smd, dm_block_t extra_blocks)
{
	unsigned long flags, *new_fltr, *new_map;
	unsigned long total = BITS_TO_LONGS(smd->ll.nr_blocks);
	unsigned long org = BITS_TO_LONGS(smd->ll.nr_blocks - extra_blocks);

	if (!smd->free_map)
		return;	

	new_fltr = vzalloc(DIV_ROUND_UP(total, (long)1 << FILTER_SHIFT) * sizeof(long));
	if (!new_fltr)
		DMERR("%s: resize filter to size %llu failed", __func__, smd->ll.nr_blocks);

	new_map = vzalloc(total * sizeof(unsigned long));
	if (!new_map)
		DMERR("%s: resize free_map to size %llu failed, free_map got freed", __func__, smd->ll.nr_blocks);

	spin_lock_irqsave(&smd->free_map->lock, flags);

	__update_bitmap((void **)&smd->free_map->filter, (void **)&new_fltr, 
		DIV_ROUND_UP(org, (long)1 << FILTER_SHIFT) * sizeof(unsigned long));	

	__update_bitmap((void **)&smd->free_map->map, (void **)&new_map, 
		org * sizeof(unsigned long));

	spin_unlock_irqrestore(&smd->free_map->lock, flags);
}

static int sm_disk_extend(struct dm_space_map *sm, dm_block_t extra_blocks)
{
	int r;
	struct sm_disk *smd = container_of(sm, struct sm_disk, sm);

	r = sm_ll_extend(&smd->ll, extra_blocks);
	if (!r) 
		sm_resize_free_map(smd, extra_blocks);

	return r;
}

static int sm_disk_get_nr_blocks(struct dm_space_map *sm, dm_block_t *count)
{
	struct sm_disk *smd = container_of(sm, struct sm_disk, sm);
	*count = smd->old_ll.nr_blocks;

	return 0;
}

static int sm_disk_get_nr_free(struct dm_space_map *sm, dm_block_t *count)
{
	struct sm_disk *smd = container_of(sm, struct sm_disk, sm);
	*count = (smd->old_ll.nr_blocks - smd->old_ll.nr_allocated) - smd->nr_allocated_this_transaction;

	return 0;
}

static int sm_disk_get_count(struct dm_space_map *sm, dm_block_t b,
			     uint32_t *result)
{
	struct sm_disk *smd = container_of(sm, struct sm_disk, sm);
	return sm_ll_lookup(&smd->ll, b, result);
}

static int sm_disk_count_is_more_than_one(struct dm_space_map *sm, dm_block_t b,
					  int *result)
{
	int r;
	uint32_t count;

	r = sm_disk_get_count(sm, b, &count);
	if (r)
		return r;

	*result = count > 1;

	return 0;
}

static int sm_disk_set_count(struct dm_space_map *sm, dm_block_t b,
			     uint32_t count)
{
	int r;
	uint32_t old_count;
	enum allocation_event ev;
	struct sm_disk *smd = container_of(sm, struct sm_disk, sm);

	r = sm_ll_insert(&smd->ll, b, count, &ev);
	if (!r) {
		switch (ev) {
		case SM_NONE:
			break;

		case SM_ALLOC:
			/*
			 * This _must_ be free in the prior transaction
			 * otherwise we've lost atomicity.
			 */
			smd->nr_allocated_this_transaction++;
			break;

		case SM_FREE:
			/*
			 * It's only free if it's also free in the last
			 * transaction.
			 */
			r = sm_ll_lookup(&smd->old_ll, b, &old_count);
			if (r)
				return r;

			if (!old_count)
				smd->nr_allocated_this_transaction--;
			break;
		}
	}

	return r;
}

static int sm_disk_inc_block(struct dm_space_map *sm, dm_block_t b)
{
	int r;
	unsigned long flags;
	enum allocation_event ev;
	struct sm_disk *smd = container_of(sm, struct sm_disk, sm);

	r = sm_ll_inc(&smd->ll, b, &ev);
	if (!r && (ev == SM_ALLOC)) {
		/*
		 * This _must_ be free in the prior transaction
		 * otherwise we've lost atomicity.
		 */
		smd->nr_allocated_this_transaction++;
		if (smd->free_map) {
			spin_lock_irqsave(&smd->free_map->lock, flags);
			bitmap_clear(smd->free_map->map, (unsigned int)b, 1);
			spin_unlock_irqrestore(&smd->free_map->lock, flags);
		}
	}

	return r;
}

static int sm_disk_dec_block(struct dm_space_map *sm, dm_block_t b)
{
	int r;
	unsigned long flags;
	enum allocation_event ev;
	struct sm_disk *smd = container_of(sm, struct sm_disk, sm);

	r = sm_ll_dec(&smd->ll, b, &ev);
	if (!r && (ev == SM_FREE) && smd->free_map) {
		spin_lock_irqsave(&smd->free_map->lock, flags);
		bitmap_set(smd->free_map->map, (unsigned int)b, 1);
		bitmap_set(smd->free_map->filter, (unsigned int)b >> FILTER_SHIFT, 1);
		spin_unlock_irqrestore(&smd->free_map->lock, flags);
	}
	return r;
}

static int sm_disk_alloc_block(struct dm_space_map *sm, dm_block_t b)
{
	int r;
	unsigned long flags;
	enum allocation_event ev;
	struct sm_disk *smd = container_of(sm, struct sm_disk, sm);

	r = sm_ll_inc(&smd->ll, b, &ev);
	if (!r) {
		/*
		 * This _must_ be free in the prior transaction
		 * otherwise we've lost atomicity.
		 */
		BUG_ON(ev != SM_ALLOC);
		smd->begin = max(smd->begin, b + 1);
		smd->nr_allocated_this_transaction++;
		if (smd->free_map) {
			spin_lock_irqsave(&smd->free_map->lock, flags);
			bitmap_clear(smd->free_map->map, (unsigned int)b, 1);
			spin_unlock_irqrestore(&smd->free_map->lock, flags);
		}
	}

	return r;
}

static int sm_disk_new_block(struct dm_space_map *sm, dm_block_t *b)
{
	int r;
	unsigned long flags;
	enum allocation_event ev;
	struct sm_disk *smd = container_of(sm, struct sm_disk, sm);

retry:
	/* FIXME: we should loop round a couple of times */
	r = sm_ll_find_free_block(&smd->old_ll, smd->begin, smd->old_ll.nr_blocks, b);
	if (r)
		return r;
	else if (*b >= smd->bound_b && *b < smd->bound_e) {
		smd->begin = smd->bound_e;
		goto retry;
	}

	smd->begin = *b + 1;
	r = sm_ll_inc(&smd->ll, *b, &ev);
	if (!r) {
		BUG_ON(ev != SM_ALLOC);	
		smd->nr_allocated_this_transaction++;
		if (smd->free_map) {
			spin_lock_irqsave(&smd->free_map->lock, flags);
			bitmap_clear(smd->free_map->map, (unsigned int)(*b), 1);
			spin_unlock_irqrestore(&smd->free_map->lock, flags);
		}
	}

	return r;
}

static int sm_disk_commit(struct dm_space_map *sm)
{
	int r;
	dm_block_t nr_free;
	struct sm_disk *smd = container_of(sm, struct sm_disk, sm);

	r = sm_disk_get_nr_free(sm, &nr_free);
	if (r)
		return r;

	r = sm_ll_commit(&smd->ll);
	if (r)
		return r;

	memcpy(&smd->old_ll, &smd->ll, sizeof(smd->old_ll));
	smd->begin = 0;
	smd->nr_allocated_this_transaction = 0;

	r = sm_disk_get_nr_free(sm, &nr_free);
	if (r)
		return r;

	return 0;
}

static int sm_disk_root_size(struct dm_space_map *sm, size_t *result)
{
	*result = sizeof(struct disk_sm_root);

	return 0;
}

static int sm_disk_copy_root(struct dm_space_map *sm, void *where_le, size_t max)
{
	struct sm_disk *smd = container_of(sm, struct sm_disk, sm);
	struct disk_sm_root root_le;

	root_le.nr_blocks = cpu_to_le64(smd->ll.nr_blocks);
	root_le.nr_allocated = cpu_to_le64(smd->ll.nr_allocated);
	root_le.bitmap_root = cpu_to_le64(smd->ll.bitmap_root);
	root_le.ref_count_root = cpu_to_le64(smd->ll.ref_count_root);

	if (max < sizeof(root_le))
		return -ENOSPC;

	memcpy(where_le, &root_le, sizeof(root_le));

	return 0;
}

static int dm_disk_register_boundary(struct dm_space_map *sm, dm_block_t b, dm_block_t e)
{
	struct sm_disk *smd = container_of(sm, struct sm_disk, sm);

	smd->bound_b = b;
	smd->bound_e = e;
	return 0;
}
static int dm_disk_get_boundary(struct dm_space_map *sm, dm_block_t *b, dm_block_t *e)
{
	struct sm_disk *smd = container_of(sm, struct sm_disk, sm);

	*b = smd->bound_b;
	*e = smd->bound_e;
	return 0;
}

/*----------------------------------------------------------------*/

static struct dm_space_map ops = {
	.destroy = sm_disk_destroy,
	.extend = sm_disk_extend,
	.get_nr_blocks = sm_disk_get_nr_blocks,
	.get_nr_free = sm_disk_get_nr_free,
	.get_nr_free_range = sm_disk_get_nr_free_range,
	.get_count = sm_disk_get_count,
	.count_is_more_than_one = sm_disk_count_is_more_than_one,
	.set_count = sm_disk_set_count,
	.inc_block = sm_disk_inc_block,
	.dec_block = sm_disk_dec_block,
	.alloc_block = sm_disk_alloc_block,
	.new_block = sm_disk_new_block,
	.commit = sm_disk_commit,
	.root_size = sm_disk_root_size,
	.copy_root = sm_disk_copy_root,
	.register_threshold_callback = NULL,
	.register_boundary = dm_disk_register_boundary,
	.get_boundary = dm_disk_get_boundary
};

static void sm_allocate_free_map(struct sm_disk *smd, int create)
{
	dm_block_t b, result;
	unsigned long total = BITS_TO_LONGS(smd->ll.nr_blocks);
	int r = 0, free_blks = 0;

	if (!smd->free_map)
		return;

	spin_lock_init(&smd->free_map->lock);

	if (!total)
		return;

	smd->free_map->filter = vzalloc(DIV_ROUND_UP(total, (long)1 << FILTER_SHIFT) * sizeof(long));
	if (!smd->free_map->filter) {
		DMWARN("%s: allocation of free bloom filter for tier failed", __func__);
		return;
	}

	smd->free_map->map = vzalloc(total * sizeof(long));
	if (!smd->free_map->map) {
		DMWARN("%s: allocation of free full map for tier failed", __func__);
		vfree(smd->free_map->filter);
	}

	if (create)
		return;

	for (b = 0; !r; b = result + free_blks) {
		r = sm_ll_find_serial_free_blks(&smd->ll, b, smd->ll.nr_blocks, &result, &free_blks);
		if (r) {
			if (r != -ENOSPC)
				DMWARN("%s: reconstruct free bitmap failure", __func__);
			break;
		}

		bitmap_set(smd->free_map->map, (unsigned int)result, free_blks);
		bitmap_set(smd->free_map->filter, (unsigned int)result >> FILTER_SHIFT, 1);
		bitmap_set(smd->free_map->filter, 
			(unsigned int)(result + free_blks) >> FILTER_SHIFT, 1);
	}

	return;
}

struct dm_space_map *dm_sm_disk_create(struct dm_transaction_manager *tm,
				       dm_block_t nr_blocks, struct free_map *free_map)
{
	int r;
	struct sm_disk *smd;

	smd = kmalloc(sizeof(*smd), GFP_KERNEL);
	if (!smd)
		return ERR_PTR(-ENOMEM);

	smd->begin = 0;
	smd->free_map = free_map;
	smd->nr_allocated_this_transaction = 0;
	smd->bound_b = smd->bound_e = U64_MAX;
	memcpy(&smd->sm, &ops, sizeof(smd->sm));

	r = sm_ll_new_disk(&smd->ll, tm);
	if (r)
		goto bad;

	r = sm_ll_extend(&smd->ll, nr_blocks);
	if (r)
		goto bad;

	sm_allocate_free_map(smd, 1);

	r = sm_disk_commit(&smd->sm);
	if (r)
		goto bad;

	return &smd->sm;

bad:
	kfree(smd);
	return ERR_PTR(r);
}
EXPORT_SYMBOL_GPL(dm_sm_disk_create);

struct dm_space_map *dm_sm_disk_open(struct dm_transaction_manager *tm,
				     void *root_le, size_t len, struct free_map *free_map)
{
	int r;
	struct sm_disk *smd;

	smd = kmalloc(sizeof(*smd), GFP_KERNEL);
	if (!smd)
		return ERR_PTR(-ENOMEM);

	smd->begin = 0;
	smd->free_map = free_map;
	smd->nr_allocated_this_transaction = 0;
	smd->bound_b = smd->bound_e = U64_MAX;
	memcpy(&smd->sm, &ops, sizeof(smd->sm));

	r = sm_ll_open_disk(&smd->ll, tm, root_le, len);
	if (r)
		goto bad;

	sm_allocate_free_map(smd, 0);

	r = sm_disk_commit(&smd->sm);
	if (r)
		goto bad;

	return &smd->sm;

bad:
	kfree(smd);
	return ERR_PTR(r);
}
EXPORT_SYMBOL_GPL(dm_sm_disk_open);

/*----------------------------------------------------------------*/
