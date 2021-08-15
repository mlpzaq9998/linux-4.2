/*
 * Copyright (C) 2010-2011 Red Hat, Inc.
 *
 * This file is released under the GPL.
 */

#ifndef DM_THIN_METADATA_H
#define DM_THIN_METADATA_H

#include "persistent-data/dm-block-manager.h"
#include "persistent-data/dm-space-map.h"
#include "persistent-data/dm-space-map-metadata.h"

#include "persistent-data/dm-btree.h"
#ifdef QNAP_HAL
#include <qnap/hal_event.h>
#endif

/*----------------------------------------------------------------*/

/*
 * Thin metadata superblock flags.
 */
#define THIN_METADATA_NEEDS_CHECK_FLAG (1 << 0)

struct dm_pool_metadata;
struct dm_thin_device;

/*
 * Device identifier
 */
typedef uint64_t dm_thin_id;

/*
 * Reopens or creates a new, empty metadata volume.
 */
struct dm_pool_metadata *dm_pool_metadata_open(struct block_device *bdev,
					       sector_t data_block_size,
					       bool format_device, void *context);

int dm_pool_metadata_close(struct dm_pool_metadata *pmd);

/*
 * Compat feature flags.  Any incompat flags beyond the ones
 * specified below will prevent use of the thin metadata.
 */
#define THIN_FEATURE_SUPERBLOCK_BACKUP (1UL << 31)
#define THIN_FEATURE_FAST_BLOCK_CLONE  (1UL << 30)
#define THIN_FEATURE_COMPAT_SUPP	  0UL
#define THIN_FEATURE_COMPAT_RO_SUPP	  0UL
#define THIN_FEATURE_INCOMPAT_SUPP	  0UL

/*
 * Reserve space manuplate flag
 */
#define RES_CLONE_INC (1)
#define RES_CLONE_DEC (1 << 1)

/*
 * Data allocation flag
 */
#define ALLOC_NEW     0
#define ALLOC_SHARE   (1 << 1)

/*
 * Device creation/deletion.
 */
int dm_pool_create_thin(struct dm_pool_metadata *pmd, dm_thin_id dev);

/*
 * An internal clone.
 *
 * You can only clone a quiesced origin i.e. one that is either
 * suspended or not instanced at all.
 */
int dm_pool_create_clone(struct dm_pool_metadata *pmd,
                         dm_thin_id dev, dm_thin_id origin);

/*
 * An internal snapshot.
 *
 * You can only snapshot a quiesced origin i.e. one that is either
 * suspended or not instanced at all.
 */
int dm_pool_create_snap(struct dm_pool_metadata *pmd, dm_thin_id dev,
			dm_thin_id origin);

/*
 * Deletes a virtual device from the metadata.  It _is_ safe to call this
 * when that device is open.  Operations on that device will just start
 * failing.  You still need to call close() on the device.
 */
int dm_pool_delete_thin_device(struct dm_pool_metadata *pmd,
			       dm_thin_id dev);

/*
 * Clear a virtual device from the metadata. This aims to reduce time required
 * to delete a thin device.
 */
int dm_pool_clear_thin_device(struct dm_pool_metadata *pmd,
                              dm_thin_id dev);


/*
 * Commits _all_ metadata changes: device creation, deletion, mapping
 * updates.
 */
int dm_pool_commit_metadata(struct dm_pool_metadata *pmd);

/*
 * Discards all uncommitted changes.  Rereads the superblock, rolling back
 * to the last good transaction.  Thin devices remain open.
 * dm_thin_aborted_changes() tells you if they had uncommitted changes.
 *
 * If this call fails it's only useful to call dm_pool_metadata_close().
 * All other methods will fail with -EINVAL.
 */
int dm_pool_abort_metadata(struct dm_pool_metadata *pmd);

/*
 * Set/get userspace transaction id.
 */
int dm_pool_set_metadata_transaction_id(struct dm_pool_metadata *pmd,
					uint64_t current_id,
					uint64_t new_id);

int dm_pool_get_metadata_transaction_id(struct dm_pool_metadata *pmd,
					uint64_t *result);

/*
 * Hold/get root for userspace transaction.
 *
 * The metadata snapshot is a copy of the current superblock (minus the
 * space maps).  Userland can access the data structures for READ
 * operations only.  A small performance hit is incurred by providing this
 * copy of the metadata to userland due to extra copy-on-write operations
 * on the metadata nodes.  Release this as soon as you finish with it.
 */
int dm_pool_reserve_metadata_snap(struct dm_pool_metadata *pmd);
int dm_pool_release_metadata_snap(struct dm_pool_metadata *pmd);

int dm_pool_enable_block_clone(struct dm_pool_metadata *pmd);
int dm_pool_disable_block_clone(struct dm_pool_metadata *pmd);

int dm_pool_start_backup_sb(struct dm_pool_metadata *pmd);
int dm_pool_stop_backup_sb(struct dm_pool_metadata *pmd);

int dm_pool_get_metadata_snap(struct dm_pool_metadata *pmd,
			      dm_block_t *result);

int support_fast_block_clone(struct dm_pool_metadata *pmd);
/*
 * Actions on a single virtual device.
 */

/*
 * Opening the same device more than once will fail with -EBUSY.
 */
int dm_pool_open_thin_device(struct dm_pool_metadata *pmd, dm_thin_id dev,
			     struct dm_thin_device **td);

int dm_pool_close_thin_device(struct dm_thin_device *td);

dm_thin_id dm_thin_dev_id(struct dm_thin_device *td);

struct dm_thin_lookup_result {
	dm_block_t block;
	uint32_t time;
	bool zeroed: 1;
	bool shared: 1;
	bool cloned: 1;
};

int dm_thin_deploy(struct dm_thin_device *td, dm_block_t block, dm_block_t *result);

/*
 * Returns:
 *   -EWOULDBLOCK iff @can_issue_io is set and would issue IO
 *   -ENODATA iff that mapping is not present.
 *   0 success
 */
int dm_thin_find_block(struct dm_thin_device *td, dm_block_t block,
		       int can_issue_io, struct dm_thin_lookup_result *result);

int dm_thin_find_next_mapped_block(struct dm_thin_device *td, dm_block_t block,
					  dm_block_t *vblock,
					  struct dm_thin_lookup_result *result);
/*
 * Retrieve the next run of contiguously mapped blocks.  Useful for working
 * out where to break up IO.  Returns 0 on success, < 0 on error.
 */
int dm_thin_find_mapped_range(struct dm_thin_device *td,
			      dm_block_t begin, dm_block_t end,
			      dm_block_t *thin_begin, dm_block_t *thin_end,
			      dm_block_t *pool_begin, bool *maybe_shared);

/*
 * Obtain an unused block.
 */
int dm_thin_alloc_data_block(struct dm_thin_device *td, dm_block_t *result, int action);

/*
 * Insert or remove block.
 */
int dm_thin_insert_block(struct dm_thin_device *td, dm_block_t block,
						dm_block_t data_block, unsigned zeroed);
int dm_thin_insert_block_with_time(struct dm_thin_device *td, dm_block_t block,
                                   dm_block_t data_block, unsigned zeroed, uint32_t *time);

/*
 * If pool_block is given, reduce the clone counts of it
 */
int dm_thin_remove_block(struct dm_thin_device *td, dm_block_t block, dm_block_t *pblock);
int dm_thin_remove_range(struct dm_thin_device *td, dm_block_t begin, dm_block_t end, dm_block_t *pblock);

/*
 * Queries.
 */
bool dm_thin_changed_this_transaction(struct dm_thin_device *td);

bool dm_pool_changed_this_transaction(struct dm_pool_metadata *pmd);

bool dm_thin_aborted_changes(struct dm_thin_device *td);

int dm_thin_get_highest_mapped_block(struct dm_thin_device *td,
				     dm_block_t *highest_mapped);

int dm_thin_get_mapped_count(struct dm_thin_device *td, dm_block_t *result);

int dm_pool_get_free_block_count(struct dm_pool_metadata *pmd,
				 dm_block_t *result);
int dm_pool_get_raw_free_block_count(struct dm_pool_metadata *pmd,
				 dm_block_t *result);

int dm_pool_get_free_metadata_block_count(struct dm_pool_metadata *pmd,
					  dm_block_t *result);

int dm_pool_get_metadata_dev_size(struct dm_pool_metadata *pmd,
				  dm_block_t *result);

int dm_pool_get_data_dev_size(struct dm_pool_metadata *pmd, dm_block_t *result);

int dm_pool_block_is_used(struct dm_pool_metadata *pmd, dm_block_t b, bool *result);

/*
 * Returns -ENOSPC if the new size is too small and already allocated
 * blocks would be lost.
 */
int dm_pool_resize_data_dev(struct dm_pool_metadata *pmd, dm_block_t new_size);
int dm_pool_resize_metadata_dev(struct dm_pool_metadata *pmd, dm_block_t new_size);

/*
 * Flicks the underlying block manager into read only mode, so you know
 * that nothing is changing.
 */
void dm_pool_metadata_read_only(struct dm_pool_metadata *pmd);
void dm_pool_metadata_read_write(struct dm_pool_metadata *pmd);

int dm_pool_set_mapped_threshold(struct dm_pool_metadata *pmd,
                                 dm_block_t new_threshold);
int dm_pool_register_metadata_threshold(struct dm_pool_metadata *pmd,
					dm_block_t threshold,
					dm_sm_threshold_fn fn,
					void *context);

/*
 * Updates the superblock immediately.
 */
int dm_pool_metadata_set_needs_check(struct dm_pool_metadata *pmd);
bool dm_pool_metadata_needs_check(struct dm_pool_metadata *pmd);

/*
 * Issue any prefetches that may be useful.
 */
void dm_pool_issue_prefetches(struct dm_pool_metadata *pmd);

int dm_pool_support_superblock_backup(struct dm_pool_metadata *pmd);

dm_block_t get_metadata_dev_size_in_blocks(struct dm_pool_metadata *pmd, struct block_device *bdev);
void warn_if_metadata_device_too_big(struct dm_pool_metadata *pmd, struct block_device *bdev);

unsigned report_sb_backup_fail(struct dm_pool_metadata *pmd);
bool report_version_check_fail(struct dm_pool_metadata *pmd);
bool dm_thin_is_snapshot(struct dm_thin_device *td);

int dm_pool_get_snap_root(struct dm_pool_metadata *pmd, struct dm_thin_device *td, dm_block_t *root);

int dm_pool_clone_block(struct dm_pool_metadata *pmd,
                        struct dm_thin_lookup_result *src,
                        struct dm_thin_device *src_td, dm_block_t src_blk,
                        struct dm_thin_lookup_result *dst,
                        struct dm_thin_device *dst_td, dm_block_t dst_blk);
int dm_pool_get_origin_mapped_blocks(struct dm_pool_metadata *pmd, dm_block_t *b);
int dm_pool_snapshot_revert(struct dm_pool_metadata *pmd, dm_thin_id origin_id, dm_thin_id snap_id, dm_thin_id clone_id);

int dm_thin_set_preallocate(struct dm_thin_device *td, dm_block_t threshold);
void dm_thin_get_preallocate(struct dm_thin_device *td, dm_block_t *threshold);

int dm_pool_reserve_block(struct dm_pool_metadata *pmd, long long blocks);
bool dm_pool_space_reserve_status(struct dm_pool_metadata *pmd);
void dm_pool_space_reserve_disable(struct dm_pool_metadata *pmd);
void *dm_pool_metadata_private(struct dm_pool_metadata *pmd);

/*----------------------------------------------------------------*/

#endif
