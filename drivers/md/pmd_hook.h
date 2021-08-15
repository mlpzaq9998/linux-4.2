#ifndef DM_THIN_PMDHOOK_H
#define DM_THIN_PMDHOOK_H

#include "persistent-data/dm-transaction-manager.h"
#include "persistent-data/dm-space-map.h"

/* This should be plenty */
#define SPACE_MAP_ROOT_SIZE 40

/*
 * Little endian on-disk superblock and device details.
 */
struct thin_disk_superblock {
	__le32 csum;	/* Checksum of superblock except for this field. */
	__le32 flags;
	__le64 blocknr;	/* This block number, dm_block_t. */

	__u8 uuid[16];
	__le64 magic;
	__le32 version;
	__le32 time;

	__le64 trans_id;

	/*
	 * Root held by userspace transactions.
	 */
	__le64 held_root;

	// PATCH: TIER
	//__u8 tier_data_space_map_root[MAX_TIER_LEVEL][SPACE_MAP_ROOT_SIZE];

	__u8 data_space_map_root[SPACE_MAP_ROOT_SIZE];
	__u8 tier0_data_space_map_root[SPACE_MAP_ROOT_SIZE];
	__u8 tier1_data_space_map_root[SPACE_MAP_ROOT_SIZE];
	__le32 rescan_needed;
	__u8 padding1[4];

	__u8 metadata_space_map_root[SPACE_MAP_ROOT_SIZE];
	__u8 tier2_data_space_map_root[SPACE_MAP_ROOT_SIZE];
	__u8 padding2[48];

	/*
	 * 2-level btree mapping (dev_id, (dev block, time)) -> data block
	 */
	__le64 data_mapping_root;

	/*
	 * Device detail root mapping dev_id -> device_details
	 */
	__le64 device_details_root;

	__le32 data_block_size;		/* In 512-byte sectors. */

	__le32 metadata_block_size;	/* In 512-byte sectors. */
	__le64 metadata_nr_blocks;

	__le32 compat_flags;
	__le32 compat_ro_flags;
	__le32 incompat_flags;

	__le64 backup_id;
	__le64 reserved;

	/*
	 * Clone count root mapping pool block -> clone count
	 */
	__le64 clone_root;

	__le32 tier_num;
	__le64 pool_mapping_root;
	__le32 tier_block_size;
} __packed;

struct pmd_hook {
	bool *fail_io;
	int *need_commit;
	struct rw_semaphore *root_lock;
	struct dm_transaction_manager *tm;
	struct dm_transaction_manager *nb_tm;
	void *metadata;
	struct free_map *free_map;
	int (*commit)(void *metadata);
};

struct tier_c {
	void *tier;
	unsigned int tier_num;
	struct dm_dev **tier_dev;
	unsigned long tier_blk_size;
	unsigned int enable_map;
	uint8_t discard_passdown;
	bool bypass;
};

#endif
