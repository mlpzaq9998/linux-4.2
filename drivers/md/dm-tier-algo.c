#include "dm-tier-algo-internal.h"
#include "dm.h"
#include <linux/module.h>

#define DM_MSG_PREFIX  "tier-algo"

static DEFINE_SPINLOCK(tier_algo_list_lock);
static LIST_HEAD(tier_algo_list);

static struct dm_tier_algo_type *__find_algo(const char *name)
{
	struct dm_tier_algo_type *t;

	list_for_each_entry(t, &tier_algo_list, list) {
		if (!strcmp(t->name, name))
			return t;
	}

	return NULL;
}

static struct dm_tier_algo_type *__get_algo_once(const char *name)
{
	struct dm_tier_algo_type *t = __find_algo(name);

	if (t && !try_module_get(t->owner)) {
		DMWARN("couldn't get module %s_algo", name);
		t = ERR_PTR(-EINVAL);
	}

	return t;
}

static struct dm_tier_algo_type *get_algo_once(const char *name)
{
	struct dm_tier_algo_type *t;

	spin_lock(&tier_algo_list_lock);
	t = __get_algo_once(name);
	spin_unlock(&tier_algo_list_lock);

	return t;
}

static struct dm_tier_algo_type *get_algo(const char *name)
{
	struct dm_tier_algo_type *t;

	t = get_algo_once(name);
	if (IS_ERR(t))
		return NULL;

	if (t)
		return t;

	request_module("dm-tier-%s-algo", name);

	t = get_algo_once(name);
	if (IS_ERR(t))
		return NULL;

	return t;
}

static void put_algo(struct dm_tier_algo_type *t)
{
	module_put(t->owner);
}

int dm_tier_algo_register(struct dm_tier_algo_type *t)
{
	int r = 0;

	spin_lock(&tier_algo_list_lock);
	if (__find_algo(t->name)) {
		DMERR("%s: algorithm %s exists", __func__, t->name);
		r = -EEXIST;
	} else {
		list_add_tail(&t->list, &tier_algo_list);
		DMINFO("%s: algorithm %s registration success", __func__, t->name);
	}
	spin_unlock(&tier_algo_list_lock);

	return r;
}
EXPORT_SYMBOL_GPL(dm_tier_algo_register);

void dm_tier_algo_unregister(struct dm_tier_algo_type *t)
{
	spin_lock(&tier_algo_list_lock);
	list_del_init(&t->list);
	spin_unlock(&tier_algo_list_lock);
}
EXPORT_SYMBOL_GPL(dm_tier_algo_unregister);

struct dm_tier_algo *dm_tier_algo_create(const char *name, struct kobject *kobj)
{
	struct dm_tier_algo *a = NULL;
	struct dm_tier_algo_type *type;

	type = get_algo(name);
	if (!type) {
		DMWARN("unknown algorithm: %s", name);
		return ERR_PTR(-EINVAL);
	}

	a = type->create(kobj);
	if (!a) {
		put_algo(type);
		return ERR_PTR(-ENOMEM);
	}

	a->private = type;
	return a;
}
EXPORT_SYMBOL_GPL(dm_tier_algo_create);

char *dm_tier_algo_get_name(struct dm_tier_algo *a)
{
	struct dm_tier_algo_type *t = a->private;

	return t->name;
}
EXPORT_SYMBOL_GPL(dm_tier_algo_get_name);

void dm_tier_algo_get(struct dm_tier_algo *a)
{
	WARN_ON(IS_ERR_OR_NULL(get_algo_once(dm_tier_algo_get_name(a))));
	kobject_get(&a->kobj);
}
EXPORT_SYMBOL_GPL(dm_tier_algo_get);

void dm_tier_algo_put(struct dm_tier_algo *a)
{
	void *private;

	if (!a)
		return;
	
	private = a->private;
	kobject_put(&a->kobj);
	put_algo(private);
}
EXPORT_SYMBOL_GPL(dm_tier_algo_put);
