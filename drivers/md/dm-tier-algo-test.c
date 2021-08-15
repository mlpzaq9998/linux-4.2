#include "dm-tier-algo.h"
#include <linux/module.h>
#include <linux/delay.h>

#define DM_MSG_PREFIX   "test-algo"

struct test {
	struct dm_tier_algo algo;
};

static void test_clear(struct dm_tier_algo *a, dm_block_t b)
{
	return;
}

static void test_update(struct dm_tier_algo *a, dm_block_t b, struct bio *bio)
{
	return;
}

static int test_analyze(struct dm_tier_algo *a, struct analyze_data *data)
{
	return 0;
}

static int test_resize(struct dm_tier_algo *a, dm_block_t new_block_num)
{
	return 0;
}

static void init_algo_functions(struct test *test)
{
	test->algo.update = test_update;
	test->algo.clear = test_clear;
	test->algo.analyze = test_analyze;
	test->algo.resize = test_resize;
}

static struct dm_tier_algo* test_create(struct kobject *kobj)
{
	struct test *test = kzalloc(sizeof(*test), GFP_KERNEL);

	if (!test)
		return ERR_PTR(-ENOMEM);

	init_algo_functions(test);

	return &test->algo;
}

static struct dm_tier_algo_type test_algo_type = {
	.name = "test",
	.version = {1, 0, 0},
	.owner = THIS_MODULE,
	.create = test_create
};

static int __init test_algo_register(void)
{
	return dm_tier_algo_register(&test_algo_type);
}

static void __exit test_algo_unregister(void)
{
	dm_tier_algo_unregister(&test_algo_type);
}

module_init(test_algo_register);
module_exit(test_algo_unregister);

MODULE_AUTHOR("Dennis Yang, Webber Huang");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("TIER TEST ALGORITHM");
MODULE_VERSION("1.0");
