#ifndef DM_TIER_H
#define DM_TIER_H

#include <linux/device-mapper.h>
#include <linux/dm-kcopyd.h>
#include <linux/delay.h>
#include <linux/kthread.h>
#include <linux/bitmap.h>
#include <linux/completion.h>

#include "persistent-data/dm-block-manager.h"
#include "dm-tier-metadata.h"
#include "dm-bio-prison.h"
#include "dm.h"

#define MAX_TIER_LEVEL 3

/*---- Move data type ----*/
#define MOVE_UP 0
#define MOVE_WITHIN 1
#define MOVE_DOWN 2

struct per_tier_stat {
	atomic_t move_up;
	atomic_t move_within;
	atomic_t move_down;
};

/*---- Anchor data type ----*/
#define ANCHOR_HOT_FINISH 0
#define ANCHOR_COLD_FINISH 1
#define ANCHOR_HOT_TOTAL 2
#define ANCHOR_COLD_TOTAL 3

struct anchor_stat {
	atomic_t hot_finish;
	atomic_t cold_finish;
	atomic_t hot_total;
	atomic_t cold_total;
};

struct dm_tier_new_mapping {
	struct list_head list;

	struct tier *tier;
	dm_block_t virt_block;
	struct dm_tier_lookup_result old;
	struct dm_tier_lookup_result new;
	struct dm_bio_prison_cell *cell;
	int err;

	bool discard;
	bool promote;
	bool demote;
	bool swap_reallot;
	bool demand;

	unsigned int generation;
};

struct dm_tier_trim_info {
	struct list_head list;

	struct tier *tier;
	uint32_t tid;
	dm_block_t tier_begin;
	dm_block_t tier_end;
};

struct dm_tier_endio_hook {
	struct tier *tier;
	struct dm_deferred_entry *tier_io_entry;
	struct dm_bio_prison_cell *cell;
};

struct hitcount_info {
	int index;
	int readcount;
	int writecount;
	struct list_head list;
};

int parse_tier_features(struct dm_arg_set *as, unsigned *argc, char *arg_name, struct dm_target *ti, void *context);
int parse_tier_settings(struct dm_arg_set *as, unsigned *argc, char *arg_name, struct dm_target *ti, void **context);

int maybe_resize_tier_data_dev(struct dm_target *ti, struct tier *tier, bool *need_commit);
void bind_tier_to_context(struct tier *tier, struct tier_c *tier_ctx);
void passdown_tier_discard(struct tier_c *tier_ctx);

int tier_ctr(struct dm_target *ti,
             struct kobject *pool_kobj,
             struct tier **tier,
             struct tier_c *tier_ctx,
             struct dm_tier_metadata *tmd,
             int created,
             uint32_t sectors_per_block,
             struct workqueue_struct *wq);
void tier_dtr(struct dm_target *ti, struct tier_c *tier_ctx);
void tier_ctx_dtr(struct dm_target *ti, struct tier_c *tier_ctx);

int tier_init(void);
void tier_exit(void);

int tier_bio_map(struct tier *tier, struct bio *bio);
int tier_endio(struct dm_target *ti, struct bio *bio, int err);

int tier_merge(struct tier_c *tc, struct dm_target *ti, struct bvec_merge_data *bvm,
		      struct bio_vec *biovec, int max_size);
int tier_iterate_devices(struct tier_c *tc, struct dm_target *ti,
				iterate_devices_callout_fn fn, void *data);
void tier_postsuspend(struct tier *tier);
void tier_resume(struct tier *tier);
void tier_io_hints(struct tier *tier, struct queue_limits *limits);

ssize_t show_auto_tiering_setting(struct tier *tier, char *buf);
ssize_t store_auto_tiering_setting(struct tier *tier, const char *buf, size_t count);
ssize_t show_tier_migration_status(struct tier *tier, char *buf);
ssize_t show_tier_statistics(struct tier *tier, char *buf);
ssize_t show_tier_info(struct tier *tier, char *buf);
ssize_t show_tier_algo(struct tier *tier, char *buf);
ssize_t store_tier_algo(struct tier *tier, const char *buf, size_t count);

int tier_is_congested(struct tier_c *tier_ctx, struct dm_target_callbacks *cb, int bdi_bits);
void emit_tier_flags(struct tier_c *tier_ctx, char *result,
		       unsigned *size, unsigned maxlen, unsigned *count);

int process_tier_mesg(struct dm_target *ti, unsigned argc, char **argv, struct tier *tier);

void wake_tier_worker(struct tier *tier);
#endif
