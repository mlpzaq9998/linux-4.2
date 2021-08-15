/*
 * Copyright (C) 2014-2015 QNAP, Inc.
 *
 * This file is released under the GPL.
 */

#ifndef DM_TIER_METADATA_H
#define DM_TIER_METADATA_H

#include "persistent-data/dm-block-manager.h"
#include "persistent-data/dm-space-map.h"
#include "persistent-data/dm-btree.h"
#include "pmd_hook.h"

#define TIER_BLK_SIZE 8192

#define FILTER_REVISE 14
#define FILTER_PACE 1
#define MAP_PACE 8
#define MAP_MASK ((1UL << MAP_PACE) - 1)
#define MAP_BLKS_PER_LONG (BITS_PER_LONG / MAP_PACE)
#define FLTR_TO_LONG ((1 << FILTER_REVISE) / MAP_BLKS_PER_LONG)

struct dm_tier_metadata;

struct dm_tier_lookup_result {
	dm_block_t block;
	unsigned tierid;
	unsigned reserve;
};

enum alloc_order {
	HOT_ALLOC = 0,
	NORMAL_ALLOC,
	COLD_ALLOC
};

int dm_tier_find_mapped_range(struct dm_tier_metadata *tmd,
	dm_block_t begin, dm_block_t end,
	dm_block_t *virt_begin, dm_block_t *virt_end,
	dm_block_t *data_begin, uint32_t *tid);
int dm_tier_find_block(struct dm_tier_metadata *tmd, dm_block_t block,
				int can_block, struct dm_tier_lookup_result *result);
int dm_tier_set_alloc_tier(struct dm_tier_metadata *tmd, unsigned long alloc_tier);
int dm_tier_get_alloc_tier(struct dm_tier_metadata *tmd, unsigned long *alloc_tier);
int dm_tier_find_unmapped_alloc_swap_and_blk(struct dm_tier_metadata *tmd,
	uint32_t tid, dm_block_t begin, dm_block_t end,
	dm_block_t *tier_begin, dm_block_t *tier_end);
int dm_tier_remove_swap_dec_range(struct dm_tier_metadata *tmd, 
	uint32_t tid, dm_block_t b, dm_block_t e);

int dm_tier_insert_block(struct dm_tier_metadata *tmd, 
			 dm_block_t block,
			 dm_block_t data_block,
			 uint32_t tierid);
int dm_tier_insert_block_reserve(struct dm_tier_metadata *tmd, 
				 dm_block_t block,
				 dm_block_t data_block,
				 uint32_t tierid,
				 uint32_t res);
int dm_tier_insert_block_free_swap(struct dm_tier_metadata *tmd,
				   dm_block_t block,
				   dm_block_t data_block,
				   unsigned int tierid,
				   struct dm_tier_lookup_result old);
int dm_tier_insert_block_check_retain(struct dm_tier_metadata *tmd,
				      dm_block_t block,
				      dm_block_t data_block,
				      unsigned int tierid,
				      struct dm_tier_lookup_result old);
int dm_tier_remove_block(struct dm_tier_metadata *tmd, dm_block_t block);

int dm_tier_alloc_block(struct dm_tier_metadata *tmd, 
			unsigned int tierid,
			dm_block_t *block);
int dm_tier_alloc_blk_remove_swap(struct dm_tier_metadata *tmd, 
				  unsigned int old_tierid,
				  unsigned int new_tierid,
				  dm_block_t *block);
int dm_tier_alloc_lower_block(struct dm_tier_metadata *tmd,
			      unsigned int *tierid,
			      unsigned int enable_map, 
			      dm_block_t *block);
int dm_tier_find_free_tier_and_alloc(struct dm_tier_metadata *tmd,
				     uint32_t *tierid,
				     enum alloc_order ao,
				     unsigned int enable_map,
				     dm_block_t *block);

int dm_tier_get_retain_free(struct dm_tier_metadata *tmd, 
			    unsigned int tierid, 
			    dm_block_t *retain_free);

int tier_mapping_walk(struct dm_tier_metadata *tmd,
	int (*fn)(void *context1, void *context2, void *context3, 
		dm_block_t block, struct dm_tier_lookup_result *result),
	void *context1, void *context2, void *context3);

void __tier_free_metadata(void *context);
int __tier_init_metadata(void *context, void **p);
int __tier_commit_metadata(void *context, struct thin_disk_superblock *disk_super);
void __tier_begin_transaction(void *context, struct thin_disk_superblock *disk_super);
bool __is_tier_changed(void *context);

void dm_tier_destory_metadata(void *context);
int dm_tier_open_metadata(void *context, struct pmd_hook *h, struct thin_disk_superblock *disk_super);
int dm_tier_format_metadata(void *context, struct pmd_hook *h);

int dm_tier_resize_data_dev(struct dm_tier_metadata *tmd, unsigned int tierid, dm_block_t new_count);
int dm_tier_get_free_block_count(struct dm_tier_metadata *tmd, 
				 unsigned int tierid,
				 dm_block_t *result);
int dm_tier_get_free_blk_real_cnt(struct dm_tier_metadata *tmd, 
				  unsigned int tierid,
				  dm_block_t *result);
int dm_tier_get_free_blk_cnt_range(struct dm_tier_metadata *tmd, 
				   unsigned int tierid,
				   dm_block_t begin, 
				   dm_block_t end,
				   dm_block_t *result);
int dm_tier_get_data_dev_size(struct dm_tier_metadata *tmd, 
			      unsigned int tierid,
			      dm_block_t *result);
int dm_tier_get_data_dev_real_size(struct dm_tier_metadata *tmd, 
				   unsigned int tierid,
				   dm_block_t *result);
int dm_tier_get_allocate_count(struct dm_tier_metadata *tmd, 
			       unsigned int tierid,
			       dm_block_t *result);

int dm_tier_get_swap_blkcnt(struct dm_tier_metadata *tmd,
			    unsigned int tierid, 
			    dm_block_t *blkcnt);
int dm_tier_set_swap_block(struct dm_tier_metadata *tmd, 
			   unsigned int tierid, 
			   dm_block_t block);
int dm_tier_alloc_swap_block(struct dm_tier_metadata *tmd, 
			     unsigned int tierid,
			     dm_block_t *result);
int dm_tier_free_swap_block(struct dm_tier_metadata *tmd, 
			    unsigned int tierid,
			    dm_block_t block);

int dm_tier_set_zombie_exist(struct dm_tier_metadata *tmd);
int dm_tier_get_zombie_exist(struct dm_tier_metadata *tmd, bool *result);

int dm_tier_get_swap_shortage(struct dm_tier_metadata *tmd, 
			      unsigned int tierid,
			      dm_block_t *shortage);

int dm_tier_set_boundary(struct dm_tier_metadata *tmd, 
			 unsigned int tierid,
			 dm_block_t b,
			 dm_block_t e);
int dm_tier_chk_and_clear_boundary(struct dm_tier_metadata *tmd);
int dm_tier_has_reserve(struct dm_tier_metadata *tmd, bool *result);
int dm_tier_on_reserve_tid(struct dm_tier_metadata *tmd,
			   struct dm_tier_lookup_result *blk,
			   bool *result);
int dm_tier_in_reserve(struct dm_tier_metadata *tmd,
		       struct dm_tier_lookup_result *blk,
		       bool *result);

int dm_tier_commit_metadata(struct dm_tier_metadata *tmd);

void __set_dinfo(unsigned long *map, dm_block_t block);
unsigned __get_dinfo(unsigned long *map, dm_block_t block);
int get_dinfo(struct dm_tier_metadata *tmd, dm_block_t block, unsigned *dinfo);

int check_dinfo(struct dm_tier_metadata *tmd,
		dm_block_t block,
		unsigned *dinfo);

int check_and_reset_filter(struct dm_tier_metadata *tmd, dm_block_t flt_idx);

int filter_search(struct dm_tier_metadata *tmd,
			    unsigned long size,
			    unsigned long offset,
			    dm_block_t *index);

int clone_map(struct dm_tier_metadata *tmd,
	      dm_block_t start,
	      unsigned size,
	      unsigned long **map);

int construct_map(struct dm_tier_metadata *tmd,
		  unsigned long *map,
		  dm_block_t block_num);

unsigned long map_search(unsigned long *map, unsigned long size, unsigned long offset);

#endif
