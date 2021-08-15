/*******************************************************************************
 * Filename:  target_core_qlib.c
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 ****************************************************************************/

#include <linux/net.h>
#include <linux/delay.h>
#include <linux/string.h>
#include <linux/timer.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/kthread.h>
#include <linux/in.h>
#include <linux/cdrom.h>
#include <linux/module.h>
#include <linux/ratelimit.h>
#include <linux/vmalloc.h>
#include <linux/device-mapper.h>
#include <linux/blkdev.h>
#include <scsi/scsi.h>
#include <asm/unaligned.h>
#include "target/qnap_target_struct.h"
#include "target_core_qlib.h"

/**/
struct kmem_cache *iorec_cache = NULL;	/* io rec */

/* max # of bios to submit at a time, please refer the target_core_iblock.c */
#define BLOCK_MAX_BIO_PER_TASK		32

/**/
static void __qlib_bio_batch_end_io(struct bio *bio, int err);

static int  __qlib_submit_bio_wait(struct bio_list *bio_lists, u8 cmd);
static inline void __qlib_pop_put_bio(struct bio_list *biolist);
static inline void __qlib_free_io_rec_by_list(struct list_head *io_rec_list);
static inline sector_t __qlib_get_done_blks_by_list(struct list_head *io_rec_list);
static inline void __qlib_add_page_to_mybio(struct bio *bio, struct page *page,
	unsigned int len, unsigned int off);

static void __qlib_mybio_end_io(struct bio *bio, int err);
static struct bio *__qlib_get_one_mybio(struct ___bd *bd, void *priv, 
	sector_t block_lba, u32 sg_num);


/**/
bool qlib_thin_lun(
	struct qnap_se_dev_dr *dev_dr
	)
{
	if (!strncasecmp(dev_dr->dev_provision, "thin", 
			sizeof(dev_dr->dev_provision)))
		return true;
	return false;
}
EXPORT_SYMBOL(qlib_thin_lun);

int qlib_is_fio_blk_dev(
	struct qnap_se_dev_dr *dev_dr
	)
{
	if (dev_dr->dev_type == QNAP_DT_FIO_BLK)
		return 0;
	return -ENODEV;
}
EXPORT_SYMBOL(qlib_is_fio_blk_dev);

int qlib_is_ib_fbdisk_dev(
	struct qnap_se_dev_dr *dev_dr
	)
{
	if (dev_dr->dev_type == QNAP_DT_IBLK_FBDISK)
		return 0;
	return -ENODEV;
}

void qlib_make_naa_6h_hdr_old_style(
	unsigned char *buf
	)
{
	u8 off = 0;

	/* Start NAA IEEE Registered Extended Identifier/Designator */
	buf[off++] = (0x6 << 4);
	
	/* Use OpenFabrics IEEE Company ID: 00 14 05 */
	buf[off++] = 0x01;
	buf[off++] = 0x40;
	buf[off] = (0x5 << 4);
	return;
}

void qlib_make_naa_6h_hdr_new_style(
	unsigned char *buf
	)
{
	u8 off = 0;

	buf[off++] = (0x6 << 4)| 0x0e;
	
	/* Use QNAP IEEE Company ID: */
	buf[off++] = 0x84;
	buf[off++] = 0x3b;
	buf[off] = (0x6 << 4);
	return;
}

int qlib_get_naa_6h_code(
	void *se_dev,
	unsigned char *dev_naa_sign,
	unsigned char *buf,
	void (*lio_spc_parse_naa_6h)(void *, u8 *)
	)
{
	if (!se_dev || !dev_naa_sign || !buf || !lio_spc_parse_naa_6h)
		return -EINVAL;

	/* BUG 29894
	 * We have three dev_naa type: (1) legacy (2) 3.8.1 and
	 * (3) qnap. For compatible issue, we shall use old type method
	 * to create naa body when naa hdr is qnap (new style)
	 * or legacy (old style). For others, we go new style to create
	 * naa body
	 */

	/* spc4r37a, p758, table 604
	 * buf will point to byte0 of NAA IEEE Registered Extended Designator 
	 */
	if(!strcmp(dev_naa_sign, "qnap")) {
		pr_debug("%s: NAA with QNAP IEEE company ID.\n", __func__);
		qlib_make_naa_6h_hdr_new_style(buf);

	} else {
		pr_warn("%s: invalid dev_naa value, try use NAA with "
			"OpenFabrics IEEE company ID.\n", __func__);		     
		qlib_make_naa_6h_hdr_old_style(buf);
	}

	/* tricky code - spc_parse_naa_6h_vendor_specific() from LIO, 
	 * we need it ... 
	 */
	lio_spc_parse_naa_6h(se_dev, &buf[3]);
	return 0;
}

struct scatterlist *qlib_alloc_sg_list(
	u32 *data_size,
	u32 *sg_nent
	)
{
	struct page *page = NULL;
	struct scatterlist *sgl = NULL, *tmp_sgl = NULL;
	int nents, i, real_nents = 0;
	u32 alloc_size = 0, real_alloc_size = 0, tmp_alloc_size = 0, buf_size = 0;

	if (!data_size || !sg_nent)
		return NULL;

	tmp_alloc_size = alloc_size = 
		((*data_size >= MAX_SG_LISTS_ALLOC_SIZE) ? \
			MAX_SG_LISTS_ALLOC_SIZE : *data_size);

	nents = DIV_ROUND_UP(alloc_size, PAGE_SIZE);

	tmp_sgl = kzalloc(sizeof(struct scatterlist) * nents, GFP_KERNEL);
	if (!tmp_sgl)
		return NULL;

	/* prepare tmp sg lists */
	sg_init_table(tmp_sgl, nents);

	while (tmp_alloc_size) {
		page = alloc_page((GFP_KERNEL | __GFP_ZERO | __GFP_NOWARN));
		if (!page)
			break;

		buf_size = min_t(u32, tmp_alloc_size, PAGE_SIZE);
		sg_set_page(&tmp_sgl[real_nents++], page, buf_size, 0);
		tmp_alloc_size -= buf_size;
	}

	if (real_nents == nents) {
		*data_size = alloc_size;
		*sg_nent = nents;
		pr_debug("%s: done to alloc sg lists. alloc_size(0x%x), "
			"nents(0x%x)\n", __func__, alloc_size, nents);
		return tmp_sgl;
	}

	/* we may be fail to alloc page ... so to prepare real sg list again */
	sgl = kzalloc(sizeof(struct scatterlist) * real_nents, GFP_KERNEL);
	if (!sgl)
		goto out;

	sg_init_table(sgl, real_nents);

	for (i = 0; i < real_nents; i++) {
		sg_set_page(&sgl[i], sg_page(&tmp_sgl[i]), 
			tmp_sgl[i].length, tmp_sgl[i].offset);

		real_alloc_size += tmp_sgl[i].length;
	}

	kfree(tmp_sgl);

	pr_warn("%s: re-alloc sg lists. alloc_size(0x%x), "
		"real_nents(0x%x)\n", __func__, real_alloc_size, real_nents);

	*data_size = real_alloc_size;
	*sg_nent = real_nents;
	return sgl;

out:
	for (i = 0; i < real_nents; i++)
		__free_page(sg_page(&tmp_sgl[i]));

	kfree(tmp_sgl);
	return NULL;

}

void qlib_free_sg_list(
	struct scatterlist *sg_list,
	u32 sg_nent
	)
{
	int i = 0;

	if (!sg_list || !sg_nent)
		return;

	for (i = 0; i < sg_nent; i++)
		__free_page(sg_page(&sg_list[i]));

	kfree(sg_list);
	return;
}

void qlib_create_aligned_range_desc(
	struct ____align_desc_blk *desc,
	sector_t lba,
	sector_t nr_blks,
	u32 bs_order,
	u32 aligned_size
	)
{
	u32 aligned_size_order;
	u64 total_bytes, s_pos_bytes, e_pos_bytes;
	sector_t align_lba, align_blks;

	desc->body.lba = lba;
	desc->body.nr_blks = nr_blks;
	desc->bs_order = bs_order;
	desc->bytes_to_align = aligned_size;
	desc->is_aligned = false;

	pr_debug("%s: lba:0x%llx, nr_blks:0x%x, aligned_size:%d, "
		"bs_order:%d\n", __func__, (unsigned long long)lba,
		nr_blks, aligned_size, bs_order);

	total_bytes = (u64)(nr_blks << bs_order);
	if (total_bytes < (u64)aligned_size)
		return;

	aligned_size_order = ilog2(aligned_size);

	/* convert to byte unit first */
	s_pos_bytes = lba << bs_order;
	e_pos_bytes = s_pos_bytes + total_bytes - (1 << bs_order);

	pr_debug("%s: s_pos_bytes:0x%llx, e_pos_bytes:0x%llx, "
		"total_bytes:0x%llx\n", __func__, 
		(unsigned long long)s_pos_bytes, 
		(unsigned long long)e_pos_bytes, 
		(unsigned long long)total_bytes);

	/* get the new s_lba is aligned by aligned_size */
	s_pos_bytes =  
		(((s_pos_bytes + aligned_size - (1 << bs_order)) >> \
			aligned_size_order) << aligned_size_order);

	pr_debug("%s: new align s_pos_bytes:0x%llx\n", __func__,
		(unsigned long long)s_pos_bytes);
	
	if ((s_pos_bytes > e_pos_bytes)
	|| ((e_pos_bytes - s_pos_bytes + (1 << bs_order)) < (u64)aligned_size)
	)
		return;

	/* get how many bytes which is multiplied by aligned_size */
	total_bytes = 
		(((e_pos_bytes - s_pos_bytes + (1 << bs_order)) >> \
		aligned_size_order) << aligned_size_order);

	pr_debug("%s: new align total bytes:0x%llx\n", __func__, 
		(unsigned long long)total_bytes);
	
	/* convert to original unit finally. prepare the middle first then 
	 * is for head / tail
	 */
	desc->is_aligned = true;

	align_lba = (s_pos_bytes >> bs_order);
	align_blks = (total_bytes >> bs_order);

	if (align_lba == lba) {
		/* if we didn't align for head */
		desc->head_tail[0].lba = 0;
		desc->head_tail[0].nr_blks = 0;
	} else {
		desc->head_tail[0].lba = lba;
		desc->head_tail[0].nr_blks = (align_lba -1) - lba + 1;
	}

	desc->body.lba = align_lba;
	desc->body.nr_blks = align_blks;

	/* for tail */
	desc->head_tail[1].lba = desc->body.lba + desc->body.nr_blks; /* next lba */
	desc->head_tail[1].nr_blks = 
		nr_blks - desc->head_tail[0].nr_blks - desc->body.nr_blks;

	pr_debug("%s: (head) lba:0x%llx, blks:0x%llx\n", __func__, 
		(unsigned long long)desc->head_tail[0].lba, 
		desc->head_tail[0].nr_blks);
	pr_debug("%s: (body) lba:0x%llx, blks:0x%llx\n", __func__,
		(unsigned long long)desc->body.lba, desc->body.nr_blks);
	pr_debug("%s: (tail) lba:0x%llx, blks:0x%llx\n", __func__, 
		(unsigned long long)desc->head_tail[1].lba, 
		desc->head_tail[1].nr_blks);

	return;
}

int qlib_fileio_rw(
	struct __rw_task *task
	)
{
	struct __dev_info *dev_info = &task->dev_info;
	struct ___fd *__fd = &dev_info->fe_info.__dev.__fd;
	struct scatterlist *sg = NULL;
	struct iov_iter iter;
	struct bio_vec *bvec;

	sector_t dest_lba = task->lba;
	u64 len, tmp_total = 0, nr_bytes = task->nr_bytes;
	loff_t pos = 0, start = 0, end = 0;
	int ret = -EINVAL, i = 0, done_blks = 0, sync_ret;

	bvec = kcalloc(task->sg_nents, sizeof(struct bio_vec), GFP_KERNEL);
	if (!bvec) {
		pr_err("Unable to allocate qlib_fileio_rw iov[]\n");
		task->ret = -ENOMEM;
		return 0;
	}

	for_each_sg(task->sg_list, sg, task->sg_nents, i) {

		len = min_t(u64, nr_bytes, sg->length);
		bvec[i].bv_page = sg_page(sg);
		bvec[i].bv_offset = sg->offset;
		bvec[i].bv_len = len;

		tmp_total += len;
		nr_bytes -= len;
	}

	WARN_ON(nr_bytes);

	pos = ((u64)dest_lba << task->bs_order);

	iov_iter_bvec(&iter, ITER_BVEC, bvec, task->sg_nents, tmp_total);

	if (task->dir == DMA_TO_DEVICE)
		ret = vfs_iter_write(__fd->fd_file, &iter, &pos);
	else
		ret = vfs_iter_read(__fd->fd_file, &iter, &pos);

	if (ret <= 0)
		task->ret = -EIO;

	done_blks += (ret >> task->bs_order); 

	if (tmp_total != (u64)ret)
		task->ret = -EIO;

	if ((task->dir == DMA_TO_DEVICE) && (done_blks > 0)
	&& (dev_info->dev_attr & DEV_ATTR_SUPPORT_WRITE_CACHE)
	&& (dev_info->dev_attr & DEV_ATTR_SUPPORT_FUA_WRITE)
	)
	{
		start = (task->lba << task->bs_order);
		end = start + ((sector_t)done_blks << task->bs_order) - 1;
	
		sync_ret = vfs_fsync_range(__fd->fd_file, start, end, 1);
		if (sync_ret != 0) {
			task->ret = sync_ret;
			pr_err("[%s] write w/ FUA is failed: %d\n", 
				__func__, sync_ret);
		}
	}

	kfree(bvec);

	return done_blks;
}

int qlib_create_iorec_cache(void)
{
	iorec_cache = kmem_cache_create("iorec_cache",  
			sizeof(struct __io_rec), 
			__alignof__(struct __io_rec), 0, NULL);

	if (!iorec_cache)
		return -ENOMEM;

	return 0;
}

void qlib_destroy_iorec_cache(void)
{
	if (iorec_cache)
		kmem_cache_destroy(iorec_cache);
}

static void __qlib_bio_batch_end_io(struct bio *bio, int err)
{
	struct ____bio_batch *bb = bio->bi_private;

	if (err && (err != -EOPNOTSUPP)){
		clear_bit(BIO_UPTODATE, &bb->flags);
		if (err == -ENOSPC)
			bb->nospc_err = 1;
	}

	if (atomic_dec_and_test(&bb->done))
		complete(bb->wait);
	bio_put(bio);
}

void qlib_init_cb_data(
	struct __cb_data *data,
	void *p
	)
{
	data->wait = p;
	data->nospc_err= 0;
	atomic_set(&data->bio_count, 1);
	atomic_set(&data->bio_err_count, 0);
	return;
}

static int  __qlib_submit_bio_wait(
	struct bio_list *bio_lists,
	u8 cmd
	)
{
#define D4_TIME2WAIT  10

	DECLARE_COMPLETION_ONSTACK(wait);
	struct __io_rec *rec = NULL;
	struct __cb_data cb_data;
	struct bio *mybio = NULL;
	struct blk_plug plug;
	unsigned long t;

	if (!bio_lists)
		BUG_ON(1);

	t = msecs_to_jiffies(D4_TIME2WAIT * 1000);

	qlib_init_cb_data(&cb_data, &wait);

	blk_start_plug(&plug);
	while (1) {
		mybio = bio_list_pop(bio_lists);
		if (!mybio)
			break;

		rec = (struct __io_rec *)mybio->bi_private;

		pr_debug("%s: cmd(%d), bio lba(0x%llx), bio len(0x%llx), "
			"rec br_blks(0x%x)\n", __func__, cmd,
			(unsigned long long)mybio->bi_iter.bi_sector, 
			(unsigned long long)mybio->bi_iter.bi_size,
			rec->nr_blks);

		rec->cb_data = &cb_data;
		atomic_inc(&(cb_data.bio_count));
		submit_bio(cmd, mybio);
	}

	blk_finish_plug(&plug);

	if (!atomic_dec_and_test(&(cb_data.bio_count))) {
		while (wait_for_completion_timeout(&wait, t) == 0)
			pr_err("%s: wait bio to be done\n", __func__);
	}

	if (atomic_read(&cb_data.bio_err_count)) {
		if (cb_data.nospc_err)
			return -ENOSPC;
		else
			return -EIO;
	}
	return 0;
}

static inline void __qlib_pop_put_bio(
	struct bio_list *biolist
	)
{
	struct bio *bio = NULL;

	while ((bio = bio_list_pop(biolist)))
		bio_put(bio);
}

static inline void __qlib_free_io_rec_by_list(
	struct list_head *io_rec_list
	)
{
	struct __io_rec *rec = NULL, *tmp_rec = NULL;

	list_for_each_entry_safe(rec, tmp_rec, io_rec_list, node)
		kfree(rec);
}

static inline sector_t __qlib_get_done_blks_by_list(
	struct list_head *io_rec_list
	)
{
	struct __io_rec *rec;
	sector_t done = 0;
	
	list_for_each_entry(rec, io_rec_list, node){
		/* Only computed the transferred-done part. This shall
		 * match the __bio_end_io() function
		 */
		if (rec->transfer_done != 1)
			break;
		done += (sector_t)rec->nr_blks;
	}
	return done;
}

static inline void __qlib_add_page_to_mybio(
	struct bio *bio,
	struct page *page,
	unsigned int len,
	unsigned int off
	)
{
	bio->bi_io_vec[0].bv_page = page;
	bio->bi_io_vec[0].bv_len = len;
	bio->bi_io_vec[0].bv_offset = off;
	bio->bi_flags = 1 << BIO_UPTODATE;
	bio->bi_vcnt = 1;
	bio->bi_iter.bi_size = len;
	return;
}

static void __qlib_mybio_end_io(
	struct bio *bio,
	int err
	)
{
	struct __cb_data *p = NULL;
	struct __io_rec *rec = NULL;

	rec = (struct __io_rec *)bio->bi_private;
	p = rec->cb_data;

	if (!test_bit(BIO_UPTODATE, &bio->bi_flags) && !err)
		err = -EIO;

	rec->transfer_done = 1;
	if(err != 0){
		if (err == -ENOSPC)
			p->nospc_err = 1;

		rec->transfer_done = -1; // treat it as error
		atomic_inc(&p->bio_err_count);
		smp_mb__after_atomic();
	}

	bio_put(bio);

	if (atomic_dec_and_test(&p->bio_count))
		complete(p->wait);

	return;
}


static struct bio *__qlib_get_one_mybio(
	struct ___bd *bd,
	void *priv, 
	sector_t block_lba,
	u32 sg_num
	)
{
	struct bio *mybio = NULL;

	if (sg_num > BIO_MAX_PAGES)
		sg_num = BIO_MAX_PAGES;

	mybio = bio_alloc_bioset(GFP_NOIO, sg_num, bd->bio_set);
	if (!mybio){
		pr_err("%s: unable to allocate mybio\n", __func__);
		return NULL;
	}

	mybio->bi_bdev = bd->bd;
	mybio->bi_private = priv;
	mybio->bi_end_io = &__qlib_mybio_end_io;
	mybio->bi_iter.bi_sector = block_lba;

	pr_debug("%s - allocated bio: 0x%p, lba:0x%llx\n", __func__, 
		mybio, (unsigned long long)mybio->bi_iter.bi_sector);

	return mybio;
}


int qlib_blockio_rw(
	struct __rw_task *task
	)
{
	struct bio *mybio = NULL;
	struct __io_rec *rec = NULL;
	struct scatterlist *sg = NULL;
	struct bio_list bio_lists;
	struct list_head io_rec_list;
	struct __dev_info *dev_info = &task->dev_info;
	struct ___bd *bd = &dev_info->fe_info.__dev.__bd;
	sector_t bio_lba = 0;
	int i = 0, bio_cnt = 0, done_blks = 0, err;
	u32 dest_bs_order = dev_info->bs_order, sg_num = task->sg_nents;
	u64 len = 0, expected_bytes = 0;

	/* task lba may be 4096b, it shall be converted again for linux block layer (512b) */	
	bio_lba = ((task->lba << dest_bs_order) >> 9);
	expected_bytes = task->nr_bytes;

	if (task->dir == DMA_BIDIRECTIONAL || task->dir == DMA_NONE) {
		task->ret = -EINVAL;	
		return 0;
	}

	if (!task->nr_bytes || !sg_num) {
		task->ret = -EINVAL;	
		return 0;
	}

	rec = kmem_cache_zalloc(iorec_cache, GFP_KERNEL);
	if (!rec) {
		task->ret = -ENOMEM;
		return 0;
	}

	mybio = __qlib_get_one_mybio(bd, rec, bio_lba, sg_num);
	if (!mybio) {
		kmem_cache_free(iorec_cache, rec);
		task->ret = -ENOMEM;
		return 0;
	}

	/* prepare io rec for 1st bio, we still not insert sg page yet */
 	INIT_LIST_HEAD(&io_rec_list);
	INIT_LIST_HEAD(&rec->node);
	rec->cb_data = NULL;
	rec->nr_blks = 0;
	list_add_tail(&rec->node, &io_rec_list);

	bio_list_init(&bio_lists);
	bio_list_add(&bio_lists, mybio);
	bio_cnt = 1;

	for_each_sg(task->sg_list, sg, task->sg_nents, i) {

		len = min_t(u64, expected_bytes, sg->length);

		while (bio_add_page(mybio, sg_page(sg), len, sg->offset) != len)
		{
			/* 1st bio was fail to be inserted ... */
			if ((bio_list_size(&bio_lists) == 1) && (!rec->nr_blks))
				goto fail_put_bios;

			if (bio_cnt >= BLOCK_MAX_BIO_PER_TASK) {

				err = __qlib_submit_bio_wait(&bio_lists, 
					((task->dir == DMA_FROM_DEVICE) ? 0 : REQ_WRITE));
				
				/* after to submit, we will do ... */
				done_blks += __qlib_get_done_blks_by_list(&io_rec_list);
				
				__qlib_pop_put_bio(&bio_lists);
				__qlib_free_io_rec_by_list(&io_rec_list);	
				
				pr_debug("%s: done blks(0x%x)\n", __func__, done_blks);
				
				if (err < 0) {
					pr_warn("%s: done blks(0x%x), err:%d "
					"for (bio_cnt >= BLOCK_MAX_BIO_PER_TASK) "
					"case\n", __func__, done_blks, err);
					task->ret = err;
					return done_blks;
				}

				bio_cnt = 0;
			}

			/* prepare new bio */
			rec = kmem_cache_zalloc(iorec_cache, GFP_KERNEL);
			if (!rec)
				goto fail_put_bios;

			mybio = __qlib_get_one_mybio(bd, rec, bio_lba, sg_num);
			if (!mybio) {
				kmem_cache_free(iorec_cache, rec);
				goto fail_put_bios;
			}

			INIT_LIST_HEAD(&rec->node);
			rec->cb_data = NULL;
			rec->nr_blks = 0;
			list_add_tail(&rec->node, &io_rec_list);

			bio_list_add(&bio_lists, mybio);
			bio_cnt++;
		}

		bio_lba += len >> 9;

		/* this size is for real destination side */
		rec->nr_blks += (len >> dest_bs_order);
		expected_bytes -= len;
		sg_num--;
	}

	err = __qlib_submit_bio_wait(&bio_lists, 
		((task->dir == DMA_FROM_DEVICE) ? 0 : REQ_WRITE));

	/* after to submit, we will do ... */
	done_blks += __qlib_get_done_blks_by_list(&io_rec_list);
	
	__qlib_pop_put_bio(&bio_lists);
	__qlib_free_io_rec_by_list(&io_rec_list);

	pr_debug("%s: done blks(0x%x)\n", __func__, done_blks);

	WARN_ON(expected_bytes);

	if (err < 0) {
		pr_debug("%s: done blks(0x%x), err:%d\n", __func__, done_blks, err);
		task->ret = err;
	}

	return done_blks;


fail_put_bios:
	__qlib_pop_put_bio(&bio_lists);
	__qlib_free_io_rec_by_list(&io_rec_list);
	task->ret = -EIO;
	return 0;

}

/* unit for block is 512bytes here */
int qlib_blkdev_issue_special_discard(
	struct block_device *bdev, 
	sector_t lba,
	sector_t nr_blks, 
	gfp_t gfp_mask, 
	unsigned long flags
	)
{
#define MIN_REQ_SIZE	((4 << 20) >> 9)
	
	/* done_blks is 512b unit since this is block layer device */
	sector_t work_blks = 0;
	int ret = 0;

	while (nr_blks) {
		/* split req to 4mb at least one by one */
		work_blks = min_t (sector_t,  nr_blks, MIN_REQ_SIZE);

		pr_debug("%s: lba(0x%llx), nr_blks(0x%llx)\n", 
			__func__, (unsigned long long)lba, 
			(unsigned long long)nr_blks);

		ret = blkdev_issue_special_discard(
				bdev, lba, work_blks, gfp_mask);
		if (ret != 0)
			break;

		lba += work_blks;
		nr_blks -= work_blks;
	}

	return ret;

}

int qlib_fd_flush_and_truncate_cache(
	struct file *fd,
	sector_t lba,
	u32 nr_blks,
	u32 bs_order,
	bool truncate_cache,
	bool is_thin
	)
{
	struct inode *inode = NULL;
	struct address_space *mapping = NULL;
	loff_t first_page = 0, last_page = 0, start = 0, len = 0;
	loff_t first_page_offset = 0, last_page_offset = 0;
	int ret = 0;

	inode = fd->f_mapping->host;
	mapping = inode->i_mapping;

	start = (loff_t)(lba << bs_order);
	len = (loff_t)((loff_t)nr_blks << bs_order);

	first_page = (start) >> PAGE_CACHE_SHIFT;
	last_page = (start + len) >> PAGE_CACHE_SHIFT;
	first_page_offset = first_page	<< PAGE_CACHE_SHIFT;
	last_page_offset = (last_page << PAGE_CACHE_SHIFT) + \
			((PAGE_CACHE_SIZE - 1));

	pr_debug("%s: lba(0x%llx), nr_blks(0x%x), bs_order(0x%x), "
		"start(0x%llx), len(0x%llx), first_page(0x%llx), "
		"last_page(0x%llx), first_page_offset(0x%llx), "
		"last_page_offset(0x%llx)\n", __func__, 
		(unsigned long long)lba, (unsigned long long)nr_blks, bs_order,
		(unsigned long long)start, (unsigned long long)len,
		(unsigned long long)first_page, (unsigned long long)last_page,
		(unsigned long long)first_page_offset, 
		(unsigned long long)last_page_offset);

	if (mapping->nrpages 
	&& mapping_tagged(mapping, PAGECACHE_TAG_DIRTY))
	{
		ret = filemap_write_and_wait_range(mapping, 
			first_page_offset, last_page_offset);

		if (unlikely(ret)){
			pr_err("%s: fail from filemap_write_and_wait_range(), "
				"ret:%d\n", __func__, ret);
#ifdef SUPPORT_TP
			if (!is_thin)
				return ret;

			int err;

			if (ret != -ENOSPC) {
				err = qlib_fd_check_dm_thin_cond(fd);
				if (err == -ENOSPC)
					ret = err;
			}
#endif
			return ret;
		}
	}

	if (truncate_cache)
		truncate_pagecache_range(inode, first_page_offset, 
			last_page_offset);

	return 0;
}

int qlib_fd_vfs_fsync_range(
	struct file *fd,
	loff_t s,
	loff_t e,
	int data_sync,
	bool is_thin
	)
{
	struct inode *inode = fd->f_mapping->host;
	int ret, sync_ret;

	sync_ret = vfs_fsync_range(fd, s, e, data_sync);
	if (sync_ret == 0)
		return 0;

	/* if fail to sync, try check it is 
	 * 1. thin (or thick) 
	 * 2. or, it is (fd + blk) or (fd + file)
	 */
	if (!is_thin || (!S_ISBLK(inode->i_mode)))
		return sync_ret;

	/* if this is thin lun, now to ... */
	ret = qlib_fd_check_dm_thin_cond(fd);
	if (ret == -ENOSPC) {
		pr_warn("%s: space was full already\n", __func__);
		return ret;
	}

	return sync_ret;
}
EXPORT_SYMBOL(qlib_fd_vfs_fsync_range);

int qlib_fd_sync_cache_range(
	struct file *file,
	loff_t start_byte,
	loff_t end_byte	
	)
{
	int err_1, err_msg;

	err_msg = 1;
	err_1 = filemap_fdatawrite_range(
		file->f_mapping, start_byte, end_byte);

	if (unlikely(err_1 != 0))
		goto _err_;

	err_msg = 2;
	err_1 = filemap_fdatawait_range(
		file->f_mapping, start_byte, end_byte);

	if (unlikely(err_1 != 0))
		goto _err_;

	return 0;
_err_:
	pr_debug("%s: %s is failed: %d\n", __func__, 
		((err_msg == 1) ? "filemap_fdatawrite_range": \
		"filemap_fdatawait_range"), err_1);

	return err_1;
}
EXPORT_SYMBOL(qlib_fd_sync_cache_range);

/* this will call dm-thin cond to check whether to hit i/o threshold or not,
 * and then depend on result to sync cache after i/o was issued
 *
 * 0           - NOT need to check this i/o or not get nospc
 * -ENOSPC     - or, get nospc
 * others (<0) - or, get error from sync cache
 */
int qlib_fd_check_thin_io_get_nospc(
	struct qnap_se_dev_dr *dr,
	struct file *fd,
	u8 *cdb,
	loff_t start,
	loff_t len,
	bool do_sync
	)
{
	int ret, ret1;

	/* first time to check whether we goes to sync i/o condition or not */
	ret = qlib_fd_check_dm_thin_cond(fd);
	if (ret == 0 || ret == -EINVAL || ret == -ENODEV)
		return 0;

	/* if hit condition, force to report no space. we don't care the 
	 * io position was mapped or is new allocated
	 */ 
	if (qlib_hit_read_deletable(dr, cdb))
		return -ENOSPC;

	/* for some QNAP special io (i.e. fast-zero or fast-clone), we did sync
	 * cache already before to execute them. so, not need to sync cache again
	 */
	if (!do_sync)
		return ret;

	/* time to do sync i/o
	 * 1. hit the sync i/o threshold area
	 * 2. or, space is full BUT need to handle lba where
	 *    was mapped or not
	 */
	ret1 = qlib_fd_sync_cache_range(fd, start, (start + len));
	if (ret1 == 0)
		return 0;

	/* fail from sync cache -
	/* thin i/o may go somewhere (lba wasn't mapped to any block)
	 * or something wrong during normal sync-cache
	 */

	/* call again to make sure it is no space really or not */
	ret = qlib_fd_check_dm_thin_cond(fd);
	if (ret == -ENOSPC) {
		pr_debug("%s: space was full already\n",__func__);
		ret1 = ret;
	}

	return ret1;

}
EXPORT_SYMBOL(qlib_fd_check_thin_io_get_nospc);

/* 0: normal i/o (not hit sync i/o threshold)
 * 1: hit sync i/o threshold
 * - ENOSPC: pool space is full
 * - ENODEV: no such device
 * - others: other failure
 *
 * this call shal cowork with dm-thin layer and ONLY for block-based lun
 */
int qlib_fd_check_dm_thin_cond(
	struct file *file
	)
{
	struct inode *inode = NULL;
	struct request_queue *q = NULL; 
	int ret;

	if (!file)
		return -ENODEV;

	inode = file->f_mapping->host;
	if (!S_ISBLK(inode->i_mode))
		return -ENODEV;

	/* here is fio + block backend */
	if (!inode->i_bdev)
		return -ENODEV;

	q = bdev_get_queue(inode->i_bdev);
	if (!q)
		return -ENODEV; 

	/* check this function exists or not since it was declared by
	 * weak symbol in target_core_qlib.h
	 */
	if (!dm_thin_volume_is_full)
		return -EINVAL;

	return dm_thin_volume_is_full(rq_get_thin_hook(q));

}
EXPORT_SYMBOL(qlib_fd_check_dm_thin_cond);

bool qlib_hit_read_deletable(
	struct qnap_se_dev_dr *dev_dr,
	u8 *cdb
	)
{
	bool check = false;

	switch (cdb[0]) {
#if 0
	case SYNCHRONIZE_CACHE:
	case SYNCHRONIZE_CACHE_16:
#endif
	case WRITE_6:
	case WRITE_10:
	case WRITE_12:
	case WRITE_16:
	case WRITE_VERIFY:
	case XDWRITEREAD_10:
	case COMPARE_AND_WRITE:
	case UNMAP:
	case WRITE_SAME_16:
	case WRITE_SAME:
	case EXTENDED_COPY:
		check = true;
		break;
	case VARIABLE_LENGTH_CMD:
	{
		u16 service_action = get_unaligned_be16(&cdb[8]);
		switch (service_action) {
		case XDWRITEREAD_32:
		case WRITE_SAME_32:
			check = true;
		default:
			break;
		}
		break;		
	}
	default:
		break;
	}

	if (check && (atomic_read(&dev_dr->hit_read_deletable) == 1))
		return true;

	return false;
	
}




void qlib_se_cmd_dr_init(
	struct qnap_se_cmd_dr *cmd_dr
	)
{
	cmd_dr->cmd_t_state = 0;
}


