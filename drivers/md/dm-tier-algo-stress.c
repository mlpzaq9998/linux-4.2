#include "dm-tier-algo-sysfs.h"
#include "dm-tier-algo-utility.h"
#include <linux/device-mapper.h>
#include <linux/vmalloc.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/delay.h>

#define DM_MSG_PREFIX   "stress-algo"

struct stress {
	struct dm_tier_algo algo;
};

static struct stress *to_stress_algo(struct dm_tier_algo *a)
{
	return container_of(a, struct stress, algo);
}

static void dm_stress_kobj_release(struct kobject *kobj)
{
	struct dm_tier_algo *a = container_of(kobj, struct dm_tier_algo, kobj);
	struct stress *stress = to_stress_algo(a);

	kfree(stress);
}

static struct attribute *dm_attrs[] = {
	NULL,
};

static const struct sysfs_ops dm_sysfs_ops = {
	.show   = dm_attr_show,
	.store  = dm_attr_store,
};

static struct kobj_type dm_ktype = {
	.sysfs_ops      = &dm_sysfs_ops,
	.default_attrs  = dm_attrs,
	.release = dm_stress_kobj_release,
};

static void stress_update(struct dm_tier_algo *a, dm_block_t b, struct bio *bio)
{
	return;
}

static void stress_clear(struct dm_tier_algo *a, dm_block_t b)
{
	return;
}

static bool ifneed_migrate_down(struct stress *stress, struct analyze_data *data, dm_block_t block, uint32_t *tierid)
{
	if (*tierid >= data->tier_num - 1)
		return false;
	else if (*tierid == SSD_TIER_ID || !(block % 2))
		return find_next_tid(data, tierid) ? false : true;

	return false;
}

static bool ifneed_migrate_up(struct stress *stress, struct analyze_data *data, dm_block_t block, uint32_t *tierid)
{
	int target_tierid;
	/*
	 * Top level tier cannot be migrated up again
	 */
	if (*tierid == SSD_TIER_ID)
		return false;
	else if (*tierid == data->tier_num - 1 || block % 2) {
		for (target_tierid = *tierid - 1; target_tierid >= 0; target_tierid--) {
			if (!is_tier_disabled(data, (uint32_t)target_tierid))
				break;
		}

		*tierid = target_tierid < 0 ? *tierid : target_tierid;
		return target_tierid < 0 ? false : true;
	}

	return false;
}

static void profile_direction(struct dm_tier_algo *a, struct analyze_data *data, struct profile *profile)
{
	dm_block_t index = 0;
	unsigned long size = data->total_block_num;
	dm_block_t allocated[MAX_TIER_LEVEL] = {0};
	struct stress *stress = to_stress_algo(a);

	for (index = 0; index < size; index++) {
		bool migrate;
		uint32_t old_tierid, new_tierid;

		index = ta_find_next_allocated(data->block_from, size, index);
		if (index >= size)
			break;	

		old_tierid = new_tierid = ta_get_tierid(data->block_from, index);
		allocated[old_tierid]++;

		migrate = ifneed_migrate_down(stress, data, index, &new_tierid) ||
			  ifneed_migrate_up(stress, data, index, &new_tierid);
		if (migrate) {
			inc_tier_profile(profile, old_tierid, 
				old_tierid < new_tierid ? INTEND_DN : INTEND_UP, 1);
		}

		ta_store_tierid(data->block_to, index, new_tierid);
	}
	set_profile_free(profile, allocated);
}

static void create_score_list(struct analyze_data *data)
{
	dm_block_t index = 0;
	unsigned long size = data->total_block_num;

	for (index = 0; index < size; index++) {
		//uint32_t old_tierid, new_tierid;

		index = ta_find_next_allocated(data->block_from, size, index);
		if (index >= size)
			break;

		//FIXME: stress not support clustering
		/*
		old_tierid = ta_get_tierid(data->block_from, index);
		new_tierid = ta_get_tierid(data->block_to, index);

		if (old_tierid != new_tierid && !score_entry_create_and_queue(&data->score_list, 
			index, old_tierid, new_tierid, 0))
			DMERR("%s:%d, generate score entry for block %llu failed !!", __func__, __LINE__, index);
		*/
	}
}

static int stress_analyze(struct dm_tier_algo *a, struct analyze_data *data)
{
	struct profile *profile;

	profile = create_profile(data, 0);
	if (IS_ERR(profile)) {
		DMERR("No memory for profile !!");
		return PTR_ERR(profile);
	}

	data->total_migrate_block = 0;
	profile_direction(a, data, profile);
	simulate_profile(profile);
	regulate_block_to(data, profile);
	create_score_list(data);
	destroy_profile(profile);
	data->tscore = 1; /*in order to trigger migration*/

	return 0;
}

static int stress_resize(struct dm_tier_algo *a, dm_block_t new_block_num)
{
	return 0;
}

static void init_algo_functions(struct stress *stress)
{
	stress->algo.update = stress_update;
	stress->algo.clear = stress_clear;
	stress->algo.analyze = stress_analyze;
	stress->algo.resize = stress_resize;
}

static struct dm_tier_algo* stress_create(struct kobject *kobj)
{
	struct stress *stress;

	stress = kzalloc(sizeof(*stress), GFP_KERNEL);
	if (!stress) {
		DMERR("No memory for timeout algorithm private data");
		return NULL;
	}

	init_algo_functions(stress);

	if (kobject_init_and_add(&stress->algo.kobj, &dm_ktype,
	                         kobj, "%s", "stress"))
		goto bad_kobj;

	return &stress->algo;

bad_kobj:
	kfree(stress);

	return NULL;
}

static struct dm_tier_algo_type stress_algo_type = {
	.name = "stress",
	.version = {1, 0, 0},
	.owner = THIS_MODULE,
	.create = stress_create
};

static int __init stress_algo_register(void)
{
	return dm_tier_algo_register(&stress_algo_type);
}

static void __exit stress_algo_unregister(void)
{
	dm_tier_algo_unregister(&stress_algo_type);
}

module_init(stress_algo_register);
module_exit(stress_algo_unregister);

MODULE_AUTHOR("Webber Huang");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("TIER STRESS ALGORITHM");
MODULE_VERSION("1.0");
