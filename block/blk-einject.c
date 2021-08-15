/*
 * Generic block device error injection 
 */
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/module.h>
#include <linux/bio.h>
#include <linux/blkdev.h>

#include "blk.h"

#define MAX_RANGE_INJ 16
#define EIJ_DELAYED INT_MIN;

static struct kmem_cache *eij_cache;

struct eij_io_delay {
	spinlock_t lock;
	struct bio_list list;
	struct delayed_work work;
} eij_delay;

struct eij_sysfs_entry {
	struct attribute attr;
	ssize_t (*show)(struct error_injector *, char *);
	ssize_t (*store)(struct error_injector *, const char *, size_t);
};

/*
 * An error injector range settings which targets for sector [start , end)
 */
struct eij_range {
	sector_t start;
	sector_t end;
	int error;
	int delay_msec;
	struct list_head list;
};

static bool eij_range_enable(struct eij_range *r)
{
	return r->end ? true : false;
}

static struct eij_range* eij_get_range_table(struct error_injector *eij)
{
	return (struct eij_range *)(eij->range_table);
}

static ssize_t eij_error_show(struct error_injector *eij, char *page)
{
	return sprintf(page, "%d\n", eij->error);
}

static ssize_t eij_error_store(struct error_injector *eij, 
							   const char *page, size_t length)
{
	int err;

	err = kstrtoint(page, 10, &eij->error);
	if (err || 
		eij->error > INT_MAX || 
		eij->error < INT_MIN)
		return -EINVAL;

	return length;
}

static ssize_t eij_delay_show(struct error_injector *eij, char *page)
{
	return sprintf(page, "%d\n", eij->delay_msec);
}

static ssize_t eij_delay_store(struct error_injector *eij, 
							   const char *page, size_t length)
{
	int err;

	err = kstrtouint(page, 10, &eij->delay_msec);
	if (err ||
		eij->delay_msec > UINT_MAX)
		return -EINVAL;

	if (eij->delay_msec % 100) {
		printk(KERN_ERR "error_injector: delay msec should be multiple of 100 msec");
		return -EINVAL;
	}

	return length;
}

static ssize_t eij_range_inject_show(struct error_injector *eij, char *page)
{
	int i;
	struct eij_range *r;

	for (i = 0; i < MAX_RANGE_INJ; i++) {
		r = eij_get_range_table(eij) + i;

		if (!eij_range_enable(r))
			break;

		sprintf(page + strlen(page), "%llu %llu %d %d\n", 
			(unsigned long long)r->start, (unsigned long long)r->end, r->error, r->delay_msec);		
	}

	if (!i)
		return sprintf(page, "NONE\n");

	return strlen(page);
}

enum param {
	P_START,
	P_END,
	P_ERROR,
	P_DELAY,
};

static ssize_t eij_range_inject_store(struct error_injector *eij,
								const char *page, size_t length)
{
	int i = 0, j, error, delay_msec;
	char *p, *buf;
	sector_t start, end;
	struct eij_range stage[MAX_RANGE_INJ];
	enum param param = P_START;

	buf = kzalloc(PAGE_SIZE, GFP_KERNEL);
	if (!buf)
		return -EIO;

	memcpy(buf, page, PAGE_SIZE);
	memset(stage, 0, sizeof(stage));

	do {
		for (param = P_START; param <= P_DELAY; param++) {
			while ((p = strsep(&buf, " \n")) && p && !*p);
			switch (param) {
			case P_START:
				if (!p)
					goto finish;
				
				if (kstrtoull(p, 10, (unsigned long long *)&start))
					goto err_out;

				break;
			case P_END:
				if (!p)
					goto err_out;

				if (kstrtoull(p, 10, (unsigned long long *)&end))
					goto err_out;

				break;
			case P_ERROR:
				if (!p)
					goto err_out;

				if (kstrtoint(p, 10, (int *)&error))
					goto err_out;
				break;
			case P_DELAY:
				if (!p)
					goto err_out;

				if (kstrtoint(p, 10, (int *)&delay_msec))
					goto err_out;
				break;
			default:
				printk(KERN_ERR "unrecognized parameter state\n");
				goto err_out;
			};
		}

		if (start >= end || 
			error > 0 || 
			delay_msec % 100 ||
			(!error && !delay_msec))
			goto err_out;

		for (j = 0; j < MAX_RANGE_INJ; j++) {
			if (!eij_range_enable(&stage[j]))
				break;

			/*
			 * Check if two range overlapped
			 */
			if (end > stage[j].start && stage[j].end > start)
				goto err_out;
		} 

		stage[i].start = start;
		stage[i].end = end;
		stage[i].error = error;
		stage[i].delay_msec = delay_msec;
		INIT_LIST_HEAD(&stage[i].list);
	} while (++i < MAX_RANGE_INJ);

finish:
	kfree(buf);
	memcpy(eij->range_table, stage, sizeof(stage));
	return length;

err_out:
	kfree(buf);
	printk(KERN_ERR "%s: error while parsing range setting %d", __func__, i);
	return -EIO;
}

static struct eij_sysfs_entry eij_error_entry = {
	.attr = {.name = "error_code", .mode = S_IRUGO | S_IWUSR},
	.show = eij_error_show,
	.store = eij_error_store,
};

static struct eij_sysfs_entry eij_delay_entry = {
	.attr = {.name = "delay_msec", .mode = S_IRUGO | S_IWUSR},
	.show = eij_delay_show,
	.store = eij_delay_store,
};

static struct eij_sysfs_entry eij_range_inject_entry = {
	.attr = {.name = "range_inject", .mode = S_IRUGO | S_IWUSR},
	.show = eij_range_inject_show,
	.store = eij_range_inject_store,
};

static struct attribute *default_attrs[] = {
	&eij_error_entry.attr,
	&eij_delay_entry.attr,
	&eij_range_inject_entry.attr,
	NULL,
};

static ssize_t eij_attr_show(struct kobject *kobj, struct attribute *attr, char *page)
{
	ssize_t ret;
	struct eij_sysfs_entry *entry = container_of(attr, struct eij_sysfs_entry, attr);
	struct error_injector *eij = container_of(kobj, struct error_injector, kobj);

	if (!entry->show)
		return -EIO;

	mutex_lock(&eij->lock);
	ret = entry->show(eij, page);
	mutex_unlock(&eij->lock);

	return ret;
}

static ssize_t eij_attr_store(struct kobject *kobj, struct attribute *attr, 
							  const char *page, size_t length)
{
	ssize_t ret;
	struct error_injector *eij = container_of(kobj, struct error_injector, kobj);
	struct eij_sysfs_entry *entry = container_of(attr, struct eij_sysfs_entry, attr);

	if (!entry->store)
		return -EIO;

	mutex_lock(&eij->lock);
	ret = entry->store(eij, page, length);
	mutex_unlock(&eij->lock);

	return ret;
}

static void blk_eij_release(struct kobject *kobj)
{
	struct error_injector *eij = container_of(kobj, struct error_injector, kobj);

	kfree(eij->range_table);
	kmem_cache_free(eij_cache, eij);
}

static const struct sysfs_ops eij_sysfs_ops = {
	.show	= eij_attr_show,
	.store	= eij_attr_store,
};

struct kobj_type blk_eij_ktype = {
	.sysfs_ops	= &eij_sysfs_ops,
	.default_attrs	= default_attrs,
	.release	= blk_eij_release,
};

static void __check_injection(struct error_injector *eij, 
							  sector_t dest, 
							  int *err, unsigned int *delay_msec)
{
	int i;

	*err = eij->error;
	*delay_msec = eij->delay_msec;

	if (*err || *delay_msec)
		return;

	/*
	 * Check if there is any range mapping
	 */
	for (i = 0; i < MAX_RANGE_INJ; i++) {
		struct eij_range *r = eij_get_range_table(eij) + i;

		if (r->start > dest || r->end <= dest)
			continue;

		*err = r->error;
		*delay_msec = r->delay_msec;

		return;
	}
}

bool blk_error_inject(struct bio *bio)
{
	int err;
	bool delayed;
	unsigned long flags;
	unsigned int delay_msec;
	struct error_injector *eij = bdev_get_injector(bio->bi_bdev);

	if (!eij)
		return false;

	mutex_lock(&eij->lock);
	__check_injection(eij, bio->bi_iter.bi_sector, &err, &delay_msec);
	mutex_unlock(&eij->lock);

	delayed = delay_msec && !bio->bi_delay_msec;

	if (err)
		bio_endio(bio, err);
	else if (delayed) {
		bio->bi_delay_msec = delay_msec;

		spin_lock_irqsave(&eij_delay.lock, flags);
		bio_list_add(&eij_delay.list, bio);
		spin_unlock_irqrestore(&eij_delay.lock, flags);
	}

	return (err || delayed);
}
EXPORT_SYMBOL(blk_error_inject);

struct error_injector* blk_einject_alloc(gfp_t gfp_mask, int node_id)
{
	struct error_injector *eij;

	eij = kmem_cache_alloc_node(eij_cache, gfp_mask | __GFP_ZERO, node_id);
	if (!eij)
		return NULL;

	kobject_init(&eij->kobj, &blk_eij_ktype);
	eij->error = 0;
	eij->delay_msec = 0;
	mutex_init(&eij->lock);

	eij->range_table = kzalloc(sizeof(struct eij_range) * MAX_RANGE_INJ, GFP_KERNEL);
	if (!eij->range_table) {
		kmem_cache_free(eij_cache, eij);
		return NULL;
	}

	memset(eij->range_table, 0, sizeof(struct eij_range) * MAX_RANGE_INJ);

	return eij;
}
EXPORT_SYMBOL(blk_einject_alloc);

int blk_register_einject(struct gendisk *disk)
{
	struct device *dev = disk_to_dev(disk);
	struct error_injector *eij = disk->eij;
	if (!eij)
		return 0;

	return kobject_add(&eij->kobj, kobject_get(&dev->kobj), "%s", "error_injector");
}
EXPORT_SYMBOL(blk_register_einject);

void blk_unregister_einject(struct gendisk *disk)
{
	if (!disk->eij)
		return;

	kobject_put(&disk_to_dev(disk)->kobj);
}
EXPORT_SYMBOL(blk_unregister_einject);

static void check_delay_bio(struct work_struct *ws)
{
	struct bio *bio;
	struct bio_list delay_list, requeue_list;
	unsigned long flags;

	bio_list_init(&delay_list);
	bio_list_init(&requeue_list);

	spin_lock_irqsave(&eij_delay.lock, flags);
	bio_list_merge(&delay_list, &eij_delay.list);
	bio_list_init(&eij_delay.list);
	spin_unlock_irqrestore(&eij_delay.lock, flags);

	while ((bio = bio_list_pop(&delay_list))) {
		bio->bi_delay_msec -= 100;
		if (!bio->bi_delay_msec) {
			bio->bi_delay_msec = EIJ_DELAYED;
			generic_make_request(bio);
		} else
			bio_list_add(&requeue_list, bio);
	}

	spin_lock_irqsave(&eij_delay.lock, flags);
	bio_list_merge(&eij_delay.list, &requeue_list);
	spin_unlock_irqrestore(&eij_delay.lock, flags);

	kblockd_schedule_delayed_work(&eij_delay.work, msecs_to_jiffies(100));
}

int __init blk_einject_init(void)
{
	eij_cache = kmem_cache_create("blkdev_error_injector",
				sizeof(struct error_injector), 0, SLAB_PANIC, NULL);
	if (!eij_cache)
		printk(KERN_ERR "fail to allocate eij_cache\n");

	bio_list_init(&eij_delay.list);
	spin_lock_init(&eij_delay.lock);
	INIT_DELAYED_WORK(&eij_delay.work, check_delay_bio);
	kblockd_schedule_delayed_work(&eij_delay.work, msecs_to_jiffies(100));
	
	return 0;
}
