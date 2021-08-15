#ifndef DM_TIER_ALGO_H
#define DM_TIER_ALGO_H

#include "persistent-data/dm-block-manager.h"
#include <linux/types.h>
#include <linux/mutex.h>

#define TIER_ALGO_NAME_MAX 128
#define TIER_ALGO_VERSION_SIZE 3

#define PROFILE_POINT 100
#define MAX_TIER_LEVEL 3

/*
 * Singly-linked Tail queue declarations.
 */
#define	STAILQ_HEAD(name, type)						\
struct name {								\
	struct type *stqh_first;/* first element */			\
	struct type **stqh_last;/* addr of last next element */		\
}

#define	STAILQ_HEAD_INITIALIZER(head)					\
	{ NULL, &(head).stqh_first }

#define	STAILQ_ENTRY(type)						\
struct {								\
	struct type *stqe_next;	/* next element */			\
}

/*
 * Singly-linked Tail queue functions.
 */
#define	STAILQ_EMPTY(head)	((head)->stqh_first == NULL)

#define	STAILQ_FIRST(head)	((head)->stqh_first)

#define	STAILQ_FOREACH(var, head, field)				\
	for((var) = STAILQ_FIRST((head));				\
	   (var);							\
	   (var) = STAILQ_NEXT((var), field))

#define	STAILQ_INIT(head) do {						\
	STAILQ_FIRST((head)) = NULL;					\
	(head)->stqh_last = &STAILQ_FIRST((head));			\
} while (0)

#define	STAILQ_INSERT_AFTER(head, tqelm, elm, field) do {		\
	if ((STAILQ_NEXT((elm), field) = STAILQ_NEXT((tqelm), field)) == NULL)\
		(head)->stqh_last = &STAILQ_NEXT((elm), field);		\
	STAILQ_NEXT((tqelm), field) = (elm);				\
} while (0)

#define	STAILQ_INSERT_HEAD(head, elm, field) do {			\
	if ((STAILQ_NEXT((elm), field) = STAILQ_FIRST((head))) == NULL)	\
		(head)->stqh_last = &STAILQ_NEXT((elm), field);		\
	STAILQ_FIRST((head)) = (elm);					\
} while (0)

#define	STAILQ_INSERT_TAIL(head, elm, field) do {			\
	STAILQ_NEXT((elm), field) = NULL;				\
	STAILQ_LAST((head)) = (elm);					\
	(head)->stqh_last = &STAILQ_NEXT((elm), field);			\
} while (0)

#define	STAILQ_LAST(head)	(*(head)->stqh_last)

#define	STAILQ_NEXT(elm, field)	((elm)->field.stqe_next)

#define	STAILQ_REMOVE(head, elm, type, field) do {			\
	if (STAILQ_FIRST((head)) == (elm)) {				\
		STAILQ_REMOVE_HEAD(head, field);			\
	}								\
	else {								\
		struct type *curelm = STAILQ_FIRST((head));		\
		while (STAILQ_NEXT(curelm, field) != (elm))		\
			curelm = STAILQ_NEXT(curelm, field);		\
		if ((STAILQ_NEXT(curelm, field) =			\
		     STAILQ_NEXT(STAILQ_NEXT(curelm, field), field)) == NULL)\
			(head)->stqh_last = &STAILQ_NEXT((curelm), field);\
	}								\
} while (0)

#define	STAILQ_REMOVE_HEAD(head, field) do {				\
	if ((STAILQ_FIRST((head)) =					\
	     STAILQ_NEXT(STAILQ_FIRST((head)), field)) == NULL)		\
		(head)->stqh_last = &STAILQ_FIRST((head));		\
} while (0)

#define	STAILQ_REMOVE_HEAD_UNTIL(head, elm, field) do {			\
	if ((STAILQ_FIRST((head)) = STAILQ_NEXT((elm), field)) == NULL)	\
		(head)->stqh_last = &STAILQ_FIRST((head));		\
} while (0)

struct scorer {
	unsigned long *p;
	unsigned long gap;
	unsigned long counter;
	uint64_t *pscore;
};

struct score_profiler {
	unsigned long p_num;
	uint64_t score[PROFILE_POINT];
	uint64_t ssd_access;
};

struct per_block_info {
	uint32_t index;
	uint64_t score;
	STAILQ_ENTRY(per_block_info) next;
};

struct migration_stack {
	struct mutex lock;
	STAILQ_HEAD(, per_block_info) list;
};

struct cluster_set {
	struct mutex lock;
	uint64_t max_score;
	uint64_t min_score;
	uint64_t gap;
	STAILQ_HEAD(cluster, per_block_info) *clusters;
};

#define RESERVE_TIER_DISABLE -1

/*Tier Reserve Type*/
enum reserve_type {
	USAGE_CTRL = 0,
	DRIVE_OUT,
	__MAX_NR_RTYPE
};

static char * const rtype_str[__MAX_NR_RTYPE] = {
	"usage_ctrl",
	"drive_out"
};

/*
 * Only used to record user's configuration,
 * the "real" value of retain, adj_begin and end should be retrived from metadata
 * begin is for original setting, adj_begin is for tracking metadata
 */
struct reserve_ctrl {
	atomic_t type;
	int tierid;
	dm_block_t dev_size;
	atomic64_t retain;
	atomic64_t begin;
	atomic64_t end;
};

struct analyze_data {
	unsigned int tier_num;
	int total_migrate_block;
	unsigned long *block_to;
	unsigned long *block_from;
	unsigned long *anchormap;
	dm_block_t total_block_num;
	dm_block_t block_num[MAX_TIER_LEVEL];
	struct score_profiler sco_pf_org[MAX_TIER_LEVEL];
	struct score_profiler sco_pf_drun[MAX_TIER_LEVEL];
	bool dryrun;
	uint64_t tscore;
	bool below_avg_score;
	unsigned long flags;
	struct per_block_info *block_info;
	struct cluster_set set;
	struct migration_stack stack;
};

struct dm_tier_algo {
	/*
	 * Update/Clear read/write information in this function
	 */
	void (*update)(struct dm_tier_algo *a, dm_block_t b, struct bio *bio);
	void (*clear)(struct dm_tier_algo *a, dm_block_t b);

	/*
	 * Analyze statistic and produce block migration bitmap
	 */
	int (*analyze)(struct dm_tier_algo *a, struct analyze_data *data);

	/*
	 * Resize needed structure when pool expansion
	 */
	int (*resize)(struct dm_tier_algo *a, dm_block_t new_block_num);

	void *private;

	struct kobject kobj;
};

struct dm_tier_algo_type {
	struct list_head list;

	char name[TIER_ALGO_NAME_MAX];
	unsigned version[TIER_ALGO_VERSION_SIZE];

	struct module *owner;
	struct dm_tier_algo *(*create)(struct kobject *kobj);
};

int dm_tier_algo_register(struct dm_tier_algo_type *t);
void dm_tier_algo_unregister(struct dm_tier_algo_type *t);

#endif
