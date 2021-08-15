/*******************************************************************************
 * Filename:  target_core_qtransport.c
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
#include <asm/unaligned.h>
#include <net/sock.h>
#include <net/tcp.h>
#include <scsi/scsi_proto.h>
#include <scsi/scsi_common.h>
#include <linux/parser.h>

#include <target/target_core_base.h>
#include <target/target_core_fabric.h>
#include <target/target_core_backend.h>
#include "target_core_internal.h"
#include "target_core_iblock.h"
#include "target_core_file.h"
#include "target_core_pr.h"
#include "target_core_qlib.h"
#include "target_core_qtransport.h"
#include "target_core_qsbc.h"

#ifdef SUPPORT_FAST_BLOCK_CLONE
#include "target_core_qfbc.h"
#endif
#include "fbdisk.h"

#ifdef SUPPORT_TP
#if defined(QNAP_HAL)
#include <qnap/hal_event.h>
extern int send_hal_netlink(NETLINK_EVT *event);
#endif
#endif

#if defined(CONFIG_QTS_CEPH)
#include "target_core_rbd.h"
#endif

#ifdef SUPPORT_TPC_CMD
#include "target_core_qodx.h"
#endif
/* api provided by dm-thin layer */
extern int thin_get_dmtarget(char *name, struct dm_target **result);
extern int thin_get_data_status(struct dm_target *ti, 
	uint64_t *total_size, uint64_t *used_size);
extern int thin_set_dm_monitor(struct dm_target *ti,
	void *dev, void (*dm_monitor_fn)(void *dev, int));

extern int dm_thin_volume_is_full(void *data);

static inline struct iblock_dev *IBLOCK_DEV(struct se_device *dev)
{
	return container_of(dev, struct iblock_dev, dev);
}

static inline struct fd_dev *FD_DEV(struct se_device *dev)
{
	return container_of(dev, struct fd_dev, dev);
}

static void __qnap_bio_batch_end_io(struct bio *bio, int err)
{
	struct __bio_batch *bb = bio->bi_private;

	if (err && (err != -EOPNOTSUPP)){
		clear_bit(BIO_UPTODATE, &bb->flags);
		if (err == -ENOSPC)
			bb->nospc_err = 1;
	}

	if (atomic_dec_and_test(&bb->done))
		complete(bb->wait);
	bio_put(bio);
}

static void __qnap_do_mybio_end_io(
	struct bio *bio,
	int err
	)
{
	CB_DATA *p = NULL;
	IO_REC *rec = NULL;

	rec = (IO_REC *)bio->bi_private;
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

static inline void __qnap_do_init_cb_data(
	CB_DATA *data,
	void *p
	)
{
	data->wait = p;
	data->nospc_err= 0;
	atomic_set(&data->bio_count, 1);
	atomic_set(&data->bio_err_count, 0);
	return;
}


static inline void __qnap_do_free_io_rec_by_io_rec_list(
	struct list_head *io_rec_list
	)
{
	IO_REC *rec = NULL, *tmp_rec = NULL;

	list_for_each_entry_safe(rec, tmp_rec, io_rec_list, node)
		kfree(rec);
	return;
}


static void __qnap_do_pop_put_bio(
	struct bio_list *biolist
	)
{
	struct bio *bio = NULL;

	if (!biolist)
		return;

	while (1){
		bio = bio_list_pop(biolist);
		if (!bio)
			break;
		bio_put(bio);
	}
	return;
}

static sector_t __qnap_do_get_done_blks_by_io_rec_list(
	struct list_head *io_rec_list
	)
{
	IO_REC *rec;
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


static int  __qnap_do_submit_bio_wait(
	struct bio_list *bio_lists,
	u8 cmd,
	unsigned long timeout
	)
{
#define D4_T_S  10

	DECLARE_COMPLETION_ONSTACK(wait);
	IO_REC *rec = NULL;
	CB_DATA cb_data;
	unsigned long t;
	struct bio *mybio = NULL;
	struct blk_plug plug;

	if (bio_lists == NULL)
		BUG_ON(1);

	if (timeout)
		t = timeout;
	else
		t = msecs_to_jiffies(D4_T_S * 1000);

	__qnap_do_init_cb_data(&cb_data, &wait);

	blk_start_plug(&plug);
	while (1) {
		mybio = bio_list_pop(bio_lists);
		if (!mybio)
			break;

		rec = (IO_REC *)mybio->bi_private;
		rec->cb_data = &cb_data;
		atomic_inc(&(cb_data.bio_count));
		submit_bio(cmd, mybio);
	}

	blk_finish_plug(&plug);

	if (!atomic_dec_and_test(&(cb_data.bio_count))) {
		while (wait_for_completion_timeout(&wait, t) == 0)
			pr_err("wait bio to be done\n");
	}

	if (atomic_read(&cb_data.bio_err_count)) {
		if (cb_data.nospc_err)
			return -ENOSPC;
		else
			return -EIO;
	}
	return 0;
}


static struct bio *__qnap_do_get_one_mybio(
	GEN_RW_TASK *task,
	sector_t block_lba
	)
{
	struct iblock_dev *ib_dev = NULL; 
	struct bio *mybio = NULL;

	if (!task)
		return NULL;

	ib_dev = IBLOCK_DEV(task->se_dev);

	/* To limit to allocate one bio for this function */
	mybio = bio_alloc_bioset(GFP_NOIO, 1, ib_dev->ibd_bio_set);
	if (!mybio){
		pr_err("%s: unable to allocate mybio\n", __func__);
		return NULL;
	}

	mybio->bi_bdev = ib_dev->ibd_bd;
	mybio->bi_end_io = &__qnap_do_mybio_end_io;
	mybio->bi_iter.bi_sector = block_lba;

	pr_debug("%s - allocated bio: 0x%p, lba:0x%llx\n", __func__, 
		mybio, (unsigned long long)mybio->bi_iter.bi_sector);

	return mybio;
}

static int __qnap_transport_do_block_rw(
	GEN_RW_TASK *task,
	u8 cmd
	)
{
	struct iblock_dev *ib_dev = NULL;
	sector_t block_lba = 0, t_lba = 0;
	u32 i = 0, bs_order = 0, err = 0, done = 0;
	u64 expected_bcs = 0, len = 0;
	int code = -EINVAL, bio_cnt = 0;
	struct bio *mybio = NULL;	
	struct scatterlist *sg = NULL;
	struct bio_list bio_lists;
	struct list_head io_rec_list;
	IO_REC *rec = NULL;
	
	/* TODO: this code shall be smart ... */

	ib_dev = IBLOCK_DEV(task->se_dev);
	block_lba = t_lba = task->lba;
	bs_order = task->dev_bs_order;
	
	expected_bcs = ((sector_t)task->nr_blks << bs_order);
	if (!expected_bcs){
		task->ret_code = code;
		return 0;
	}

	code = 0;
	INIT_LIST_HEAD(&io_rec_list);
	bio_list_init(&bio_lists);
	
	/**/
	for_each_sg(task->sg_list, sg, task->sg_nents, i){
		if (!expected_bcs)
			break;
	
		/* Here will map one sg to one bio */
		rec = kzalloc(sizeof(IO_REC), GFP_KERNEL);
		if (!rec){
			if (!bio_list_size(&bio_lists)){
				pr_err("unable to allocate memory for io rec\n");
				err = 1;
				code = -ENOMEM;
				break;
			}
			goto _DO_SUBMIT_;
		}
		INIT_LIST_HEAD(&rec->node);

		/* task lba may be 4096b, shall be converted again for linux
		 * block layer (512b)
		 */	
		block_lba = ((block_lba << bs_order) >> 9);

		mybio = __qnap_do_get_one_mybio(task, block_lba);
		if (!mybio) {
			kfree(rec);
			if (!bio_list_size(&bio_lists)){
				code = -ENOMEM;
				err = 1;
				break;
			}
			goto _DO_SUBMIT_;
		}
	
		/* Set something for bio */
		len = min_t(u64, expected_bcs, sg->length);
		mybio->bi_io_vec[0].bv_page = sg_page(sg);
		mybio->bi_io_vec[0].bv_len = len;
		mybio->bi_io_vec[0].bv_offset = sg->offset;
		mybio->bi_flags = 1 << BIO_UPTODATE;
		mybio->bi_vcnt = 1;
		mybio->bi_iter.bi_size = len;

		mybio->bi_private = (void *)rec;
		rec->cb_data = NULL;
		rec->nr_blks = (len >> bs_order);
		rec->ib_dev = ib_dev;
		list_add_tail(&rec->node, &io_rec_list);	

		pr_debug("[%s] cmd:0x%x, sg->page:0x%p, sg->length:0x%x\n",
			__func__, cmd, sg_page(sg), sg->length);
	
		pr_debug("[%s] mybio:0x%p, task lba:0x%llx, "
			"bio block_lba:0x%llx, expected_bcs:0x%llx, "
			"real len:0x%llx \n", __func__, mybio,
			(unsigned long long)t_lba, (unsigned long long)block_lba, 
			(unsigned long long)expected_bcs, (unsigned long long)len);
	
		bio_list_add(&bio_lists, mybio);
		bio_cnt++;
	
		t_lba += (sector_t)(len >> bs_order);
		block_lba = t_lba;
		expected_bcs -= len;
	
		if ((bio_cnt < BLOCK_MAX_BIO_PER_TASK) && expected_bcs)
			continue;
	
_DO_SUBMIT_:
		err = __qnap_do_submit_bio_wait(&bio_lists, cmd, 0);
	
		/* after to submit, we will do ... */
		done += (u32)__qnap_do_get_done_blks_by_io_rec_list(&io_rec_list);
                __qnap_do_pop_put_bio(&bio_lists);
		__qnap_do_free_io_rec_by_io_rec_list(&io_rec_list);	
		pr_debug("[%s] done blks:0x%x\n", __func__, done);

		if (err){
			code = err;
			break;
		}

		/* To check if timeout happens after to submit */
		if (IS_TIMEOUT(task->timeout_jiffies)){
			task->is_timeout = 1;
			break;
		}
	
		INIT_LIST_HEAD(&io_rec_list);
		bio_list_init(&bio_lists);
		bio_cnt = 0;
	}
	
	task->ret_code = code;
	
	if (err || task->is_timeout){
		if (task->is_timeout)
			pr_err("[%s] jiffies > cmd expected-timeout value !!\n", 
				__func__);

		return -1;
	}
	return done;
}

static int __qnap_transport_do_vfs_rw(
	GEN_RW_TASK *task,
	VFS_RW vfs_rw_func   
	)
{
	struct se_device *se_dev = NULL;
	struct scatterlist *sg = NULL;
	struct fd_dev *f_dev = NULL;
	loff_t pos = 0;
	sector_t dest_lba = 0;
	u32 i = 0, done = 0;
	u64 expected_bcs = 0, len = 0;
	int ret = 0, code = -EINVAL;
	struct iovec iov;
	mm_segment_t old_fs;

	expected_bcs = ((u64)task->nr_blks << task->dev_bs_order);
	if (!expected_bcs){
		task->ret_code = code;
		return 0;
	}

	code = 0;
	dest_lba = task->lba;
	se_dev = task->se_dev;
	f_dev = qnap_transport_get_fd_dev(se_dev);

	/* Here, we do vfs_rw per sg at a time. The reason is we need to 
	 * computed the transfer bytes for the result of every i/o.
	 */
	for_each_sg(task->sg_list, sg, task->sg_nents, i) {
		if (!expected_bcs)
			break;

		/* To prepare iov. To care the expected transfer bytes may be
		 * more or less than the sg->length
		 */
		len = min_t(u64, expected_bcs, sg->length);
		iov.iov_len  = len;
		iov.iov_base = sg_virt(sg);

		pr_debug("%s - dir:0x%x, expected_bcs:0x%llx, sg->length:0x%x,"
			"iov_base:0x%p, iov_len:0x%llx\n", __func__, 
			task->dir, expected_bcs, sg->length,
			iov.iov_base, (u64)iov.iov_len);
	
		/**/
		pos = (dest_lba << task->dev_bs_order); 
		dest_lba += (len >> task->dev_bs_order);
		expected_bcs -= len;

		pr_debug("%s - dir:0x%x, pos:0x%llx, dest_lba:0x%llx\n",
			__func__, task->dir, pos, 
			(unsigned long long)dest_lba);
	
		if (IS_TIMEOUT(task->timeout_jiffies)){
			task->is_timeout = 1;
			break;
		}
	
		/* FIXED ME (need to be checked)
		 * (1)	Here is to use one vector only. The reason is we need 
		 *	to reoprt real data size we transfer from src to dest. 
		 * (2)	In the other words, we need to know which io vector was
		 *	error if we use multiple io vectors
		 */
		old_fs = get_fs();
		set_fs(get_ds());
		ret = vfs_rw_func(f_dev->fd_file, &iov, 1, &pos);
		set_fs(old_fs);

		if (ret <= 0){
			code = ret;
			break;
		} else{
			done += ((u32)ret >> task->dev_bs_order);
			pr_debug("%s - dir:0x%x, done blks:0x%x\n", 
				__func__, task->dir, done);
			if (ret != len){
				code = -EIO;
				break;
			}
		}
	}

	if (task->is_timeout)
		pr_err("%s - jiffies > cmd expected-timeout value!!\n",	__func__);

	if (ret <= 0)
		pr_err("%s - vfs_rw_func(dir:%d) returned %d\n", 
			__func__, task->dir, ret);
	else if (ret != len)
		pr_err("%s - vfs_rw_func(dir:%d) return size:0x%x != expected "
			"len:0x%llx\n", __func__, task->dir, ret, len);

	task->ret_code = code;
	return done;

}

/* BUG 29894: copy from target module in kernel 2.6.33.2 
 * This will be used to create NAA for old firmware. And,
 * it is also used for compatible upgrade case
 */
static unsigned char qnap_transport_asciihex_to_binaryhex(
	unsigned char val[2]
	)
{
	unsigned char result = 0;
	/*
	 * MSB
	 */
	if ((val[0] >= 'a') && (val[0] <= 'f'))
		result = ((val[0] - 'a' + 10) & 0xf) << 4;
	else
		if ((val[0] >= 'A') && (val[0] <= 'F'))
			result = ((val[0] - 'A' + 10) & 0xf) << 4;
		else /* digit */
			result = ((val[0] - '0') & 0xf) << 4;
	/*
	 * LSB
	 */
	if ((val[1] >= 'a') && (val[1] <= 'f'))
		result |= ((val[1] - 'a' + 10) & 0xf);
	else
		if ((val[1] >= 'A') && (val[1] <= 'F'))
			result |= ((val[1] - 'A' + 10) & 0xf);
		else /* digit */
			result |= ((val[1] - '0') & 0xf);

	return result;
}

void qnap_transport_make_naa_6h_hdr_old_style(
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
EXPORT_SYMBOL(qnap_transport_make_naa_6h_hdr_old_style);


void qnap_transport_make_naa_6h_body_old_style(	
	struct se_device *se_dev, 
	unsigned char *buf
	)
{
	u8 binary = 0, binary_new =0 , off= 0, i = 0;

	binary = qnap_transport_asciihex_to_binaryhex(
			&se_dev->t10_wwn.unit_serial[0]);

	buf[off++] |= (binary & 0xf0) >> 4;

	for (i = 0; i < 24; i += 2) {
	    binary_new = qnap_transport_asciihex_to_binaryhex(
	    		&se_dev->t10_wwn.unit_serial[i+2]);

	    buf[off] = (binary & 0x0f) << 4;
	    buf[off++] |= (binary_new & 0xf0) >> 4;
	    binary = binary_new;
	}
	return;
}
EXPORT_SYMBOL(qnap_transport_make_naa_6h_body_old_style);

void qnap_transport_make_naa_6h_hdr_new_style(
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
EXPORT_SYMBOL(qnap_transport_make_naa_6h_hdr_new_style);

void qnap_transport_get_naa_6h_code(
	struct se_device *se_dev, 
	unsigned char *buf
	)
{
	struct qnap_se_dev_dr *dr = &se_dev->dev_dr;

	/* BUG 29894
	 * We have three dev_naa type: (1) legacy (2) 3.8.1 and
	 * (3) qnap. For compatible issue, we shall use old type method
	 * to create naa body when naa hdr is qnap (new style)
	 * or legacy (old style). For others, we go new style to create
	 * naa body
	 */
	if(!strcmp(dr->dev_naa, "qnap")) {
		pr_debug("%s: NAA with QNAP IEEE company ID.\n", __func__);

		qnap_transport_make_naa_6h_hdr_new_style(buf);
	} else {
		pr_warn("%s: invalid dev_naa value, try use NAA with "
			"OpenFabrics IEEE company ID.\n", __func__);		     

		qnap_transport_make_naa_6h_hdr_old_style(buf);
	}

	spc_parse_naa_6h_vendor_specific(se_dev, &buf[3]);	
	return;
}
EXPORT_SYMBOL(qnap_transport_get_naa_6h_code);

struct iblock_dev *qnap_transport_get_iblock_dev(struct se_device *se_dev)
{
	return IBLOCK_DEV(se_dev);
}
EXPORT_SYMBOL(qnap_transport_get_iblock_dev);

struct fd_dev *qnap_transport_get_fd_dev(struct se_device *se_dev)
{
	return FD_DEV(se_dev);
}
EXPORT_SYMBOL(qnap_transport_get_fd_dev);

int qnap_transport_get_subsys_dev_type (
	struct se_device *se_dev,
	SUBSYSTEM_TYPE *type
	)
{
	int ret = 0;

	*type = MAX_SUBSYSTEM_TYPE;

	if(!strcmp(se_dev->transport->name, "iblock"))
		*type = SUBSYSTEM_BLOCK;
	else if(!strcmp(se_dev->transport->name, "fileio"))
		*type = SUBSYSTEM_FILE;
	else
		ret = -EINVAL;

	return ret;
}
EXPORT_SYMBOL(qnap_transport_get_subsys_dev_type);

int qnap_transport_config_dev_blk_sz(
	struct se_device *se_dev,
	u32 *blk_sz
	)
{
	struct qnap_se_dev_dr *dr = &se_dev->dev_dr;

	/* this code may overwrite the setting made by native code
	 * - dev->transport->configure_device(dev)
	 */

	if ((dr->dev_flags & QNAP_DF_USING_QLBS) && dr->dev_qlbs)
		*blk_sz = dr->dev_qlbs;
	return 0;
}
EXPORT_SYMBOL(qnap_transport_config_dev_blk_sz);

static int __qnap_transport_get_pool_sz_kb(
	struct se_device *se_dev
	)
{
	if (se_dev->dev_dr.fast_blk_clone) {
		/* case 
		 * -(a) new created pool only by 4.2 fw for block based lun 
		 */
		return POOL_BLK_SIZE_512_KB;
	} 

	/* case
	 * -(a) created pool by 4.1 fw for block based lun
	 *	or file based lun
	 * -(b) or, created pool by 4.1 fw then fw was upgraded to 4.2
	 *	for block based lun or file based lun
	 * -(c) or, new created pool only by 4.2 fw BUT
	 *	for file based lun
	 *
	 * actually, we don't care the pool blks for file based lun ...
	 */
	return POOL_BLK_SIZE_1024_KB;
}

int qnap_transport_config_blkio_dev(
	struct se_device *se_dev,
	u32 blk_sz
	)
{
	SUBSYSTEM_TYPE type;
	struct iblock_dev *ibd_dev = NULL;
	struct request_queue *q = NULL;
	int ret, bs_order = ilog2(blk_sz);


	/* this code may overwrite the setting made by native code
	 * - dev->transport->configure_device(dev)
	 */
	ret = qnap_transport_get_subsys_dev_type(se_dev, &type);
	if (ret != 0)
		return -EINVAL;

	if (type != SUBSYSTEM_BLOCK)
		return -EINVAL;

#ifdef SUPPORT_FAST_BLOCK_CLONE
	qnap_transport_setup_support_fbc(se_dev);
#endif

	/* This code will be called in dev->transport->configure_device(), and
	 * the dev_attrib.block_size still not be set here. The
	 * dev_attrib.block_size will be set after call configure_device().
	 * We force to set this here
	 */
	se_dev->dev_attrib.block_size = se_dev->dev_attrib.hw_block_size;

	ibd_dev = qnap_transport_get_iblock_dev(se_dev);
	q = bdev_get_queue(ibd_dev->ibd_bd);
	if (!q)
		return -EINVAL;

	/* iblock i/o */
	if (blk_queue_discard(q)) {
		/* re-configure the discard parameter */
		se_dev->dev_attrib.max_unmap_lba_count = 
			((MAX_UNMAP_MB_SIZE << 20) >> bs_order);

		se_dev->dev_attrib.max_unmap_block_desc_count =
			QIMAX_UNMAP_DESC_COUNT;

		/* This value shall be multiplied by 4KB. We overwrite it
		 * here instead of in lower layer driver
		 */
		se_dev->dev_attrib.unmap_granularity =
			(PAGE_SIZE >> bs_order);
	}
	se_dev->dev_attrib.max_bytes_per_io = (MAX_TRANSFER_LEN_MB << 20);
	se_dev->dev_attrib.hw_max_sectors = ((MAX_TRANSFER_LEN_MB << 20) >> bs_order);
	se_dev->dev_dr.pool_blk_kb = __qnap_transport_get_pool_sz_kb(se_dev);


	/* remember the capacity during to configure device */
	se_dev->dev_attrib.lun_blocks = se_dev->transport->get_blocks(se_dev);
	return 0;
}
EXPORT_SYMBOL(qnap_transport_config_blkio_dev);

int qnap_transport_config_fio_dev(
	struct se_device *se_dev,
	u32 blk_sz
	)
{
	struct fd_dev *fd_dev = qnap_transport_get_fd_dev(se_dev);
	SUBSYSTEM_TYPE type;
	struct file *file = NULL;
	struct inode *inode = NULL;
	struct request_queue *q = NULL;
	int ret, bs_order = ilog2(blk_sz);

	/* this code may overwrite the setting made by native code
	 * - dev->transport->configure_device(dev)
	 */
	ret = qnap_transport_get_subsys_dev_type(se_dev, &type);
	if (ret != 0)
		return -EINVAL;

	if (type != SUBSYSTEM_FILE)
		return -EINVAL;

	file = fd_dev->fd_file;
	inode = file->f_mapping->host;

#ifdef SUPPORT_FAST_BLOCK_CLONE
	qnap_transport_setup_support_fbc(se_dev);
#endif
	se_dev->dev_attrib.hw_queue_depth = FD_MAX_DEVICE_QUEUE_DEPTH;

	/* This code will be called in dev->transport->configure_device(), and
	 * the dev_attrib.block_size still not be set here. The
	 * dev_attrib.block_size will be set after call configure_device().
	 * We force to set this here
	 */
	se_dev->dev_attrib.block_size = se_dev->dev_attrib.hw_block_size;

	if (S_ISBLK(inode->i_mode)) {
		/* file i/o + block backend device */
		q = bdev_get_queue(inode->i_bdev);

		if (blk_queue_discard(q)) {
			se_dev->dev_attrib.max_unmap_lba_count = 
				((MAX_UNMAP_MB_SIZE << 20) >> bs_order);

			se_dev->dev_attrib.max_unmap_block_desc_count =
				QIMAX_UNMAP_DESC_COUNT;
		}

		/* TBD */
		se_dev->dev_attrib.max_bytes_per_io = (MAX_TRANSFER_LEN_MB << 20);
		se_dev->dev_attrib.hw_max_sectors = ((MAX_TRANSFER_LEN_MB << 20) >> bs_order);
		se_dev->dev_attrib.hw_queue_depth = q->nr_requests;

	} else {
		/* file i/o + file backend */

		se_dev->dev_attrib.max_unmap_lba_count = 
			((MAX_UNMAP_MB_SIZE << 20) >> bs_order);
		
		se_dev->dev_attrib.max_unmap_block_desc_count =
			QIMAX_UNMAP_DESC_COUNT;

		/* TBD */
		se_dev->dev_attrib.max_bytes_per_io = FD_MAX_BYTES;
		se_dev->dev_attrib.hw_max_sectors = FD_MAX_BYTES / fd_dev->fd_block_size;
		se_dev->dev_attrib.hw_queue_depth = FD_MAX_DEVICE_QUEUE_DEPTH;
	}

	se_dev->dev_dr.pool_blk_kb = __qnap_transport_get_pool_sz_kb(se_dev);

	/* remember the capacity during to configure device */
	se_dev->dev_attrib.lun_blocks = se_dev->transport->get_blocks(se_dev);
	return 0;
}
EXPORT_SYMBOL(qnap_transport_config_fio_dev);

int qnap_transport_check_is_thin_lun(
	struct se_device *se_dev
	)
{
	struct qnap_se_dev_dr *dr = &se_dev->dev_dr;
	
	if (!strncasecmp(dr->dev_provision, "thin", 
			sizeof(dr->dev_provision)))
		return 1;
	return 0;
}
EXPORT_SYMBOL(qnap_transport_check_is_thin_lun);

#ifdef QNAP_SHARE_JOURNAL
int qnap_transport_check_is_journal_support(struct se_device *dev)
{
	return dev->dev_bbu_journal;
}
EXPORT_SYMBOL(qnap_transport_check_is_journal_support);
#endif

int qnap_transport_buf_is_zero(
	unsigned char *buf,
	int len
	)
{
	int i;
	
	if (!buf || !len)
		return -EINVAL;
	
	for (i = 0; i < len; i++, buf++) {
		if (*buf != 0)
			return -EINVAL;
	}
	return 0;
}
EXPORT_SYMBOL(qnap_transport_buf_is_zero);

void qnap_transport_create_aligned_range_desc(
	void *range_desc,
	sector_t lba,
	sector_t nr_blks,
	u32 bs_order,
	u32 aligned_size
	)
{
	u32 aligned_size_order;
	u64 total_bytes, s_pos_bytes, e_pos_bytes;
	ALIGN_DESC_BLK *desc = (ALIGN_DESC_BLK *)range_desc;
	sector_t align_lba, align_blks;

	desc->m.lba = lba;
	desc->m.nr_blks = nr_blks;
	desc->bs_order = bs_order;
	desc->bytes_to_align = aligned_size;
	desc->aligned = 0;

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
	desc->aligned = 1;

	align_lba = (s_pos_bytes >> bs_order);
	align_blks = (total_bytes >> bs_order);

	if (align_lba == lba) {
		/* if we didn't align for head */
		desc->ht[0].lba = 0;
		desc->ht[0].nr_blks = 0;
	} else {
		desc->ht[0].lba = lba;
		desc->ht[0].nr_blks = (align_lba -1) - lba + 1;
	}

	desc->m.lba = align_lba;
	desc->m.nr_blks = align_blks;

	/* for tail */
	desc->ht[1].lba = desc->m.lba + desc->m.nr_blks; /* next lba */
	desc->ht[1].nr_blks = nr_blks - desc->ht[0].nr_blks - desc->m.nr_blks;

	pr_debug("%s: (h) lba:0x%llx, blks:0x%llx\n", __func__, 
		(unsigned long long)desc->ht[0].lba, desc->ht[0].nr_blks);
	pr_debug("%s: (m) lba:0x%llx, blks:0x%llx\n", __func__,
		(unsigned long long)desc->m.lba, desc->m.nr_blks);
	pr_debug("%s: (t) lba:0x%llx, blks:0x%llx\n", __func__, 
		(unsigned long long)desc->ht[1].lba, desc->ht[1].nr_blks);

	return;
}
EXPORT_SYMBOL(qnap_transport_create_aligned_range_desc);

int qnap_transport_alloc_sg_list(
	u64 *data_size,
	struct scatterlist **sg_list,
	u32 *sg_nent
	)
{
	u64 buf_size = 0, tmp_data_size = 0; 
	int alloc_size = MAX_IO_KB_PER_SG, nents = 0, i = 0, max_alloc = 0;
	struct scatterlist *sgl = NULL;
	struct page *page = NULL;
	struct list_head tmp_sg_data_list;

	typedef struct _tmp_sg_data{
	    struct list_head sg_node;
	    struct scatterlist *sg;
	} TMP_SG_DATA;

	TMP_SG_DATA *sg_data = NULL, *tmp_sg_data = NULL;

	if (!data_size)
		goto _INVAL_;

	if (*data_size == 0)
		goto _INVAL_;

	max_alloc = (D4_SG_LIST_IO_ALLOC_SIZE / alloc_size);
	tmp_data_size = *data_size;
	if (tmp_data_size > D4_SG_LIST_IO_ALLOC_SIZE)
		tmp_data_size = D4_SG_LIST_IO_ALLOC_SIZE;

	INIT_LIST_HEAD(&tmp_sg_data_list);

	/* To prepare the tmp sg list. Here will try to find how many sg
	 * we can allocate. Please note the allocation unit must be KB unit here
	 */
	while (tmp_data_size){
		buf_size = min_t(int, tmp_data_size, alloc_size);
		page = alloc_pages((GFP_KERNEL | __GFP_ZERO | __GFP_NOWARN), 
			get_order(buf_size));

		/* give the chance to re-allocate memory */
		if (!page){
			page = alloc_pages((GFP_KERNEL | __GFP_ZERO | __GFP_NOWARN), 
				get_order(buf_size));

			if (!page) {
				if (!list_empty(&tmp_sg_data_list))
					break;
				/* no memory really ... */
				return -ENOMEM;
			}
		}

		sgl = kzalloc(sizeof(struct scatterlist), GFP_KERNEL);
		sg_data = kzalloc(sizeof(TMP_SG_DATA), GFP_KERNEL);

		if (!sg_data || !sgl){
			if (page)
				__free_pages(page, get_order(buf_size));
			if (sgl)
				kfree(sgl);
			if (sg_data)
				kfree(sg_data);
			break;
		}

		sg_init_table(sgl, 1);
		sg_set_page(sgl, page, buf_size, 0);

		sg_data->sg = sgl;
		INIT_LIST_HEAD(&sg_data->sg_node);
		list_add_tail(&sg_data->sg_node, &tmp_sg_data_list);

		tmp_data_size -= buf_size;
		nents++;

		if (nents == max_alloc)
			break;

	}

	if (!nents)
		goto _OUT_MEM_;

	BUG_ON(list_empty(&tmp_sg_data_list));

	/**/
	sgl = kzalloc(sizeof(struct scatterlist) * nents, GFP_KERNEL);
	if (!sgl){
		list_for_each_entry_safe(sg_data, tmp_sg_data, 
			&tmp_sg_data_list, sg_node)
		{
			list_del_init(&sg_data->sg_node);
			__free_pages(sg_page(sg_data->sg), 
				get_order(sg_data->sg->length));
			kfree(sg_data->sg);
			kfree(sg_data);
		}
		goto _OUT_MEM_;
	}

	/* To prepare the real sg list */
	tmp_data_size = 0;
	sg_init_table(sgl, nents);

	list_for_each_entry_safe(sg_data, tmp_sg_data, 
		&tmp_sg_data_list, sg_node)
	{
		list_del_init(&sg_data->sg_node);
		tmp_data_size += sg_data->sg->length;
		sg_set_page(&sgl[i++], sg_page(sg_data->sg), 
			sg_data->sg->length, sg_data->sg->offset);

		/* remove the tmp data*/
		kfree(sg_data->sg);
		kfree(sg_data);
	}

	*data_size = tmp_data_size;
	*sg_list = sgl;
	*sg_nent = nents;
	return 0;

_INVAL_:
	pr_err("%s: invalid argument during to alloc sg list\n", __func__);
	return -EINVAL;

_OUT_MEM_:
	pr_err("%s: fail to alloc sg list\n", __func__);
	return -ENOMEM;
}
EXPORT_SYMBOL(qnap_transport_alloc_sg_list);

void qnap_transport_free_sg_list(
	struct scatterlist *sg_list,
	u32 sg_nent
	)
{
	int i = 0;

	if (!sg_list || !sg_nent)
		return;

	for (i = 0; i < sg_nent; i++)
		__free_pages(sg_page(&sg_list[i]), get_order(sg_list[i].length));

	kfree(sg_list);
	return;
}
EXPORT_SYMBOL(qnap_transport_free_sg_list);

int qnap_transport_do_f_rw(
	void *rw_task
	)
{
	struct se_device *se_dev = NULL;
	loff_t start = 0, end = 0, data_size = 0;
	struct fd_dev *f_dev = NULL;
	int ret = 0, sync_ret = 0;
	GEN_RW_TASK *task = NULL;

	/* Here refers the fd_do_task() */
	if (!rw_task)
		return -EINVAL;

	task = (GEN_RW_TASK *)rw_task;

	if ((!task->se_dev) 
	|| (task->dir == DMA_BIDIRECTIONAL)
	|| (task->dir == DMA_NONE)
	)
		return -EINVAL;

	se_dev = task->se_dev;

	if (task->dir == DMA_FROM_DEVICE)
		ret = __qnap_transport_do_vfs_rw(task, vfs_readv);
	else{
		ret = __qnap_transport_do_vfs_rw(task, vfs_writev);

		if ((ret > 0)
		&&  (target_check_fua(se_dev))
		&&  (task->task_flag & RW_TASK_FLAG_DO_FUA)
		)
		{
			f_dev = FD_DEV(se_dev);
			data_size = ((sector_t)task->nr_blks << task->dev_bs_order);
			start = ((sector_t)task->lba << task->dev_bs_order);
			end = start + data_size - 1;

			sync_ret = vfs_fsync_range(f_dev->fd_file, start, end, 1);
			if (sync_ret != 0)
				pr_err("[%s] write w/ FUA is failed: %d\n", 
					__func__, sync_ret);

		}
	}

	return ret;

}
EXPORT_SYMBOL(qnap_transport_do_f_rw);

int qnap_transport_do_b_rw(
	void *rw_task
	)
{
	GEN_RW_TASK *task = NULL;

	if (!rw_task)
		return 0;

	task = (GEN_RW_TASK *)rw_task;

	if ((!task->se_dev) || (task->dir == DMA_BIDIRECTIONAL)
	|| (task->dir == DMA_NONE)
	) 
	{
		task->ret_code = -EINVAL;
		return 0;
	}

	return __qnap_transport_do_block_rw(task, 
			((task->dir == DMA_FROM_DEVICE) ? 0 : REQ_WRITE));

}
EXPORT_SYMBOL(qnap_transport_do_b_rw);

int qnap_transport_loop_do_f_rw(
	struct se_device *se_dev,
	void *rw_task,
	u64 sg_io_alloc_bytes,
	sector_t lba,
	sector_t blks
	)
{
	GEN_RW_TASK *task = (GEN_RW_TASK *)rw_task;
	u32 tmp, bs_order = ilog2(se_dev->dev_attrib.block_size);
	int ret;

	do {
		/* TODO:
		 * we think the blks value shall not be larger than
		 * 0xffff_ffff ... 
		 */
		tmp = min_t(u32, (u32)blks, 
			((u32)sg_io_alloc_bytes >> bs_order));

		pr_debug("%s: lba:0x%llx, tmp:0x%x\n", __func__, 
			(unsigned long long)lba, tmp);
	
		qnap_transport_make_rw_task((void *)rw_task, se_dev, lba, tmp,
			msecs_to_jiffies(5*1000), 
			DMA_TO_DEVICE);
	
		ret = qnap_transport_do_f_rw((void *)rw_task);
	
		pr_debug("%s: after call transport_do_f_rw() ret:%d, "
			"is_timeout:%d, ret code:%d\n",
			__func__, ret, task->is_timeout, task->ret_code);
	
		if((ret <= 0) || task->is_timeout || task->ret_code != 0){
			ret = task->ret_code;
			if (task->is_timeout)
				ret = 1;
			break;
		}
		ret = 0;
		lba += tmp;
		blks -= tmp;
	} while (blks);

	return ret;
}
EXPORT_SYMBOL(qnap_transport_loop_do_f_rw);

void qnap_transport_make_rw_task(
	void *rw_task,
	struct se_device *se_dev,
	sector_t lba,
	u32 nr_blks,
	unsigned long timeout,
	enum dma_data_direction dir
	)
{
	GEN_RW_TASK *task = (GEN_RW_TASK *)rw_task;

	task->se_dev = se_dev;
	task->lba = lba;
	task->nr_blks = nr_blks;
	task->dev_bs_order = ilog2(se_dev->dev_attrib.block_size);
	task->dir = dir;
	task->timeout_jiffies = timeout;
	task->is_timeout = 0;
	task->ret_code = 0;
	return;
}
EXPORT_SYMBOL(qnap_transport_make_rw_task);

/* this function was referred from blkdev_issue_discard(), but something
 * is different about it will check the command was aborted or is releasing
 * from connection now
 */

int qnap_transport_blkdev_issue_discard(
	struct se_cmd *se_cmd,
	struct block_device *bdev, 
	sector_t sector,
	sector_t nr_sects, 
	gfp_t gfp_mask, 
	unsigned long flags
	)
{
#define MIN_REQ_SIZE	((8 << 20) >> 9)
	
	bool fio_blk_dev = false, iblock_fbdisk_dev = false;
	bool dropped_by_conn = false, dropped_by_tmr = false;
	char tmp_str[256];
	int __ret = 0, ret = 0;
	sector_t work_sects = 0;


	/* check backend type */
	__ret = qnap_transport_is_fio_blk_backend(se_cmd->se_dev);
	if (__ret != 0) {
		__ret = qnap_transport_is_iblock_fbdisk(se_cmd->se_dev);
		if (__ret == 0)
			iblock_fbdisk_dev = true;
	} else
		fio_blk_dev = true;


	while (nr_sects) {

		dropped_by_conn = test_bit(QNAP_CMD_T_RELEASE_FROM_CONN, 
			&se_cmd->cmd_dr.cmd_t_state);
		
		dropped_by_tmr = qnap_transport_is_dropped_by_tmr(se_cmd);

		/* treat the result to be pass for two conditions even if
		 * original result is bad
		 */
		if (dropped_by_tmr || dropped_by_conn) {

			memset(tmp_str, 0, sizeof(tmp_str));
			sprintf(tmp_str, "[iSCSI - %s]", 
				((fio_blk_dev == true) ? "block-based" : \
				((iblock_fbdisk_dev == true) ? "file-based": \
				"unknown")));
			
			if (dropped_by_tmr) {
				pr_info("%s done to abort discard io by "
					"TMR opcode: %d\n", tmp_str, se_cmd->tmf_code);
			}
	
			if (dropped_by_conn) {
				pr_info("%s done to drop scsi op:0x%x\n", 
					tmp_str, se_cmd->t_task_cdb[0]);
			}
			ret  = 0;
			break;
		}

		/* split req to 1mb at least one by one */
		work_sects = min_t (sector_t,  nr_sects, MIN_REQ_SIZE);

		ret = blkdev_issue_discard(bdev, sector, work_sects, gfp_mask, flags);
		if (ret !=0)
			break;

		sector += work_sects;
		nr_sects -= work_sects;
	}

	return ret;
}
EXPORT_SYMBOL(qnap_transport_blkdev_issue_discard);

int qnap_transport_is_fbdisk_dev(
	struct block_device *bd
	)
{
	/* here check bd again since we will get path for it from 
	 * iblock_configure_device(), it may be null when cgi try get 
	 * allocated attr from qnap_transport_get_thin_allocated()
	 * called by se_dev_show_allocated()
	 */
	if (!bd)
		return -ENODEV;

	/* we only handle the fbdisk dev currently */
	if (strncmp(bd->bd_disk->disk_name, "fbdisk", 6))
		return -ENODEV;
	return 0;
}
EXPORT_SYMBOL(qnap_transport_is_fbdisk_dev);

static void __dm_monitor_callback_fn(
	void *dev, 
	int dmstate
	)
{
	struct se_device *se_dev = dev;

	/* to prevent thin-lun and thin-pool both be removed */
	if (se_dev == NULL)
		return;
	
	if (dmstate == 1)
		se_dev->dev_attrib.gti = NULL;
	return;
}

int qnap_transport_get_dm_target_on_thin(
	struct se_device *se_dev
	)
{
	char lvname[FD_MAX_DEV_NAME];
	int ret;

	if (se_dev->udev_path[0] == 0x00) {
		pr_err("%s: udev_path is empty\n", __func__);
		return -ENODEV;
	}

	if (se_dev->dev_attrib.gti)
		return 0;

	memset(lvname, 0, sizeof(lvname));
	strcpy(lvname, se_dev->udev_path);

	/* try to get dm target and set the dm monitor */
	ret = thin_get_dmtarget(lvname, 
		(struct dm_target **)&se_dev->dev_attrib.gti);

	if (ret != 0)
		pr_warn("%s: fail to call thin_get_dmtarget()\n", __func__);
	return ret;

}
EXPORT_SYMBOL(qnap_transport_get_dm_target_on_thin);

	
int qnap_transport_set_dm_monitor_fn_on_thin(
	struct se_device *se_dev
	)
{
	if (!se_dev->dev_attrib.gti)
		return -EINVAL;

	thin_set_dm_monitor(
		(struct dm_target *)se_dev->dev_attrib.gti,
		se_dev, __dm_monitor_callback_fn);

	return 0;
}
EXPORT_SYMBOL(qnap_transport_set_dm_monitor_fn_on_thin);

int qnap_transport_free_dm_monitor_fn_on_thin(
	struct se_device *se_dev
	)
{
	if (!se_dev->dev_attrib.gti)
		return -EINVAL;

	thin_set_dm_monitor(
		(struct dm_target *)se_dev->dev_attrib.gti,
		NULL, NULL);

	return 0;
}
EXPORT_SYMBOL(qnap_transport_free_dm_monitor_fn_on_thin);

/* ts_bytes: total size bytes
 * us_blks: used size blks
 */
int qnap_transport_fbdisk_get_ts_bytes_and_us_blks(
	struct se_device *se_dev,
	loff_t *ts_bytes,
	loff_t *us_blks
	)
{
	struct iblock_dev *ib_dev = NULL;
	struct block_device *bd = NULL;
	struct fbdisk_device *fb_dev = NULL;
	struct fbdisk_file *fb_file = NULL;
	struct inode *inode = NULL;
	loff_t total_bytes = 0, used_blks = 0;
	SUBSYSTEM_TYPE type;
	int ret;
	u32 i;

	ret = qnap_transport_get_subsys_dev_type(se_dev, &type);
	if (ret != 0)
		return ret;

	if (type == SUBSYSTEM_FILE)
		return -EINVAL;

	ib_dev = qnap_transport_get_iblock_dev(se_dev);
	bd = ib_dev->ibd_bd;
	ret = qnap_transport_is_fbdisk_dev(bd);
	if (ret != 0)
		return -ENODEV;

	fb_dev = bd->bd_disk->private_data;

	for (i = 0; i < fb_dev->fb_file_num; i++) {
		fb_file = &fb_dev->fb_backing_files_ary[i];
		inode = fb_file->fb_backing_file->f_mapping->host;
		total_bytes += inode->i_size;
		/* unit is 512b */
		used_blks += inode->i_blocks;
	}

	*ts_bytes = total_bytes;
	*us_blks = used_blks;
	return 0;
}
EXPORT_SYMBOL(qnap_transport_fbdisk_get_ts_bytes_and_us_blks);

int qnap_transport_get_thin_data_status_on_thin(
	struct se_device *se_dev,
	u64 *total_512_sector,
	u64 *used_512_sector
	)
{
	u64 total = 0, used = 0;
	int ret;

	/* the unit of total_size and used_size is sector (512b) */
	ret = thin_get_data_status(se_dev->dev_attrib.gti, &total, &used);

	*total_512_sector = total;
	*used_512_sector = used;
	return ret;
}
EXPORT_SYMBOL(qnap_transport_get_thin_data_status_on_thin);

int qnap_transport_get_a_blks_and_u_blks_on_thin(
	struct se_device *se_dev,
	int bs_order,
	sector_t *avail_blks,
	sector_t *used_blks
	)
{
	struct iblock_dev *ibd = NULL;
	struct block_device *bd = NULL;
	loff_t ts_bytes = 0, used_512b_sectors = 0;
	u64 total_512b_sectors = 0;
	sector_t ts_blks, a_blks, u_blks;
	SUBSYSTEM_TYPE type;
	int ret;

	ret = qnap_transport_get_subsys_dev_type(se_dev, &type);
	if (ret != 0)
		return ret;

	if (type == SUBSYSTEM_FILE) {
		ret = qnap_transport_is_fio_blk_backend(se_dev);
		if (ret != 0)
			return ret;

		/* backend device is block dev */

		if (!se_dev->dev_attrib.gti)
			return -ENODEV;

		ret = qnap_transport_get_thin_data_status_on_thin(se_dev, 
			&total_512b_sectors, &used_512b_sectors);

		if (ret != 0)
			return ret;

		ts_blks = (((loff_t)total_512b_sectors << 9) >> bs_order);

	} else {
		ibd = qnap_transport_get_iblock_dev(se_dev);
		bd = ibd->ibd_bd;

		ret = qnap_transport_is_fbdisk_dev(bd);
		if (ret != 0)
			return -ENODEV;

		/* we are fbdisk dev and is file based lun */
		ret = qnap_transport_fbdisk_get_ts_bytes_and_us_blks(se_dev, 
			&ts_bytes, &used_512b_sectors);

		ts_blks = ts_bytes >> bs_order;
	}

	*used_blks = ((used_512b_sectors << 9) >> bs_order);
	*avail_blks = ts_blks - ((used_512b_sectors << 9) >> bs_order);

	pr_debug("%s: ts_blks:0x%llx, used_blks:0x%llx, avail_blks:0x%llx\n", 
		__func__, (unsigned long long)ts_blks, 
		(unsigned long long)(*used_blks),
		(unsigned long long)(*avail_blks));

	return 0;

}
EXPORT_SYMBOL(qnap_transport_get_a_blks_and_u_blks_on_thin);

int qnap_transport_get_ac_and_uc_on_thin(
	struct se_device *se_dev,
	u32 *ac,
	u32 *uc
	)
{
	sector_t avail_blks, used_blks;
	int ret, threshold_exp;

	*ac = 0, *uc = 0;

	ret = qnap_transport_get_a_blks_and_u_blks_on_thin(se_dev, 
		ilog2(se_dev->dev_attrib.lun_blocks), &avail_blks, &used_blks);

	if (ret != 0)
		return ret;

	threshold_exp = qnap_sbc_get_threshold_exp(se_dev);

	*ac = (u32)div_u64(avail_blks, (1 << threshold_exp));
	*uc = (u32)div_u64(used_blks, (1 << threshold_exp));
	return 0;
}
EXPORT_SYMBOL(qnap_transport_get_ac_and_uc_on_thin);


int qnap_transport_is_fio_blk_backend(
	struct se_device *se_dev
	)
{
	if (se_dev->dev_dr.dev_type == QNAP_DT_FIO_BLK)
		return 0;
	return -ENODEV;
}
EXPORT_SYMBOL(qnap_transport_is_fio_blk_backend);

int qnap_transport_check_capacity_changed(
	struct se_cmd *se_cmd
	)
{
	struct se_device *se_dev = se_cmd->se_dev;
	unsigned long long blocks = se_dev->transport->get_blocks(se_dev);
	unsigned long long old;

	/* dev_attrib.lun_blocks will be set during 
	 * 1. target_configure_device() or
	 * 2. when current capacity is not same as previous one during to
	 * handle any i/o
	 */
	if (se_dev->dev_attrib.lun_blocks != blocks) {
		/* update to new one */
		old = se_dev->dev_attrib.lun_blocks;
		se_dev->dev_attrib.lun_blocks = blocks;

		/* shall plus 1 cause of they are END LBA (0 based) */
		pr_warn("capacity size (new:0x%llx) is not same as "
			"previous one (old:0x%llx). send "
			"CAPACITY_DATA_HAS_CHANGED sense code\n",
			(unsigned long long)(blocks + 1), 
			(unsigned long long)(old + 1));
		return TCM_CAPACITY_DATA_HAS_CHANGED;
	}
	return 0;
}
EXPORT_SYMBOL(qnap_transport_check_capacity_changed);

void qnap_tmf_init_tmf_val(
	struct se_cmd *se_cmd
	)
{
	se_cmd->tmf_code = 0;
	se_cmd->tmf_resp_tas = 0;
	se_cmd->tmf_diff_it_nexus = 0;	
	spin_lock_init(&se_cmd->tmf_data_lock);
}
EXPORT_SYMBOL(qnap_tmf_init_tmf_val);

int qnap_tmf_check_same_it_nexus(
	int tmf_code,
	int tas,
	struct se_cmd *se_cmd,
	struct se_node_acl *tmr_nacl
	)
{
	se_cmd->tmf_code = tmf_code;
	se_cmd->tmf_diff_it_nexus = 0;
	se_cmd->tmf_resp_tas = 0;

	if (tmr_nacl && (tmr_nacl != se_cmd->se_sess->se_node_acl)){
		se_cmd->tmf_diff_it_nexus = 1;
		if (tas)
			se_cmd->tmf_resp_tas = 1;
	}

	pr_debug("TMF(0x%x) req comes from %s i_t_nexus\n", 
		tmf_code, ((se_cmd->tmf_diff_it_nexus)? "diff": "same"));

	return 0;
}
EXPORT_SYMBOL(qnap_tmf_check_same_it_nexus);

void qnap_tmf_tmr_abort_task(
	struct se_device *dev,
	struct se_tmr_req *tmr,
	struct se_session *se_sess)
{
	/* TODO: This call shall depend on your native code */
	struct se_node_acl *tmr_nacl = NULL;
	struct se_cmd *se_cmd = NULL;
	unsigned long flags;
	u64 ref_tag;

	spin_lock_irqsave(&se_sess->sess_cmd_lock, flags);
	list_for_each_entry(se_cmd, &se_sess->sess_cmd_list, se_cmd_list) {

		if (dev != se_cmd->se_dev)
			continue;

		/* skip task management functions, including tmr->task_cmd */
		if (se_cmd->se_cmd_flags & SCF_SCSI_TMR_CDB)
			continue;

		ref_tag = se_cmd->tag;

		if (tmr->ref_task_tag != ref_tag)
			continue;

		if (qnap_transport_is_dropped_by_tmr(se_cmd))
			continue;

		if (tmr->task_cmd && tmr->task_cmd->se_sess)
			tmr_nacl = tmr->task_cmd->se_sess->se_node_acl;

		printk("ABORT_TASK: Found referenced %s task_tag:0x%08x, "
			"cmdsn:0x%08x\n",
			se_cmd->se_tfo->get_fabric_name(), be32_to_cpu(ref_tag),
			se_cmd->se_tfo->get_cmdsn(se_cmd));

		/* we don't abort them right now ... */
		spin_lock(&se_cmd->tmf_data_lock);

		qnap_tmf_check_same_it_nexus(TMR_ABORT_TASK, 
			se_cmd->se_dev->dev_attrib.emulate_tas, 
			se_cmd, tmr_nacl);

		spin_unlock(&se_cmd->tmf_data_lock);

		qnap_transport_drop_bb_cmd(se_cmd, TMR_ABORT_TASK);
		qnap_transport_drop_fb_cmd(se_cmd, TMR_ABORT_TASK);

		se_cmd->se_tfo->set_clear_delay_remove(se_cmd, 1, 0);

		spin_unlock_irqrestore(&se_sess->sess_cmd_lock, flags);

		printk("ABORT_TASK: Sending TMR_FUNCTION_COMPLETE for "
			"ref_tag:0x%08x. "
			"Aborted task: itt:0x%08x, cmdsn:0x%08x, scsi op:0x%x\n", 
			be32_to_cpu(ref_tag), 
			be32_to_cpu(se_cmd->se_tfo->get_task_tag(se_cmd)),
			se_cmd->se_tfo->get_cmdsn(se_cmd), se_cmd->t_task_cdb[0]);

		tmr->response = TMR_FUNCTION_COMPLETE;
		return;
	}
	spin_unlock_irqrestore(&se_sess->sess_cmd_lock, flags);

out:
	printk("ABORT_TASK: Sending TMR_TASK_DOES_NOT_EXIST for "
		"ref_tag: 0x%08x\n",
		be32_to_cpu(tmr->ref_task_tag));

	tmr->response = TMR_TASK_DOES_NOT_EXIST;
	return;
}
EXPORT_SYMBOL(qnap_tmf_tmr_abort_task);

static int __qnap_tmf_check_cdb_and_preempt(
	struct list_head *list,
	struct se_cmd *cmd
	)
{
	/* here was refer the target_check_cdb_and_preempt(), 
	 * please take care it */
	struct t10_pr_registration *reg;

	if (!list)
		return 0;
	list_for_each_entry(reg, list, pr_reg_abort_list) {
		if (reg->pr_res_key == cmd->pr_res_key)
			return 0;
	}

	return 1;
}

void qnap_tmf_tmr_drain_state_list(
	struct se_device *dev,
	struct se_cmd *prout_cmd,
	struct se_node_acl *tmr_nacl,
	int tas,
	struct list_head *preempt_and_abort_list)
{
	/* TODO: This call shall depend on your native code */
	struct se_cmd *cmd, *next;
	unsigned long flags;

	/*
	 * Complete outstanding commands with TASK_ABORTED SAM status.
	 *
	 * This is following sam4r17, section 5.6 Aborting commands, Table 38
	 * for TMR LUN_RESET:
	 *
	 * a) "Yes" indicates that each command that is aborted on an I_T nexus
	 * other than the one that caused the SCSI device condition is
	 * completed with TASK ABORTED status, if the TAS bit is set to one in
	 * the Control mode page (see SPC-4). "No" indicates that no status is
	 * returned for aborted commands.
	 *
	 * d) If the logical unit reset is caused by a particular I_T nexus
	 * (e.g., by a LOGICAL UNIT RESET task management function), then "yes"
	 * (TASK_ABORTED status) applies.
	 *
	 * Otherwise (e.g., if triggered by a hard reset), "no"
	 * (no TASK_ABORTED SAM status) applies.
	 *
	 * Note that this seems to be independent of TAS (Task Aborted Status)
	 * in the Control Mode Page.
	 */
	spin_lock_irqsave(&dev->execute_task_lock, flags);
	list_for_each_entry_safe(cmd, next, &dev->state_list, state_list) {
		/*
		 * For PREEMPT_AND_ABORT usage, only process commands
		 * with a matching reservation key.
		 */
		if (__qnap_tmf_check_cdb_and_preempt(preempt_and_abort_list, cmd))
			continue;
		/*
		 * Not aborting PROUT PREEMPT_AND_ABORT CDB..
		 */
		if (prout_cmd == cmd)
			continue;

		if (qnap_transport_is_dropped_by_tmr(cmd))
			continue;

		spin_lock(&cmd->tmf_data_lock);
		qnap_tmf_check_same_it_nexus(TMR_LUN_RESET, tas, cmd, tmr_nacl);
		spin_unlock(&cmd->tmf_data_lock);

		qnap_transport_drop_bb_cmd(cmd, TMR_LUN_RESET);
		qnap_transport_drop_fb_cmd(cmd, TMR_LUN_RESET);

		cmd->se_tfo->set_clear_delay_remove(cmd, 1, 0);

	}
	spin_unlock_irqrestore(&dev->execute_task_lock, flags);

	return;
}
EXPORT_SYMBOL(qnap_tmf_tmr_drain_state_list);

int qnap_change_dev_size(
	struct se_device *se_dev
	)
{
	struct fd_dev *fd_dev = NULL;
	struct iblock_dev *ib_dev = NULL;
	struct block_device *bd = NULL;
	struct file *file = NULL;
	struct inode *inode = NULL;
	SUBSYSTEM_TYPE type;
	unsigned long long total_blks;
	int ret, bs_order = ilog2(se_dev->dev_attrib.block_size);

	ret =  qnap_transport_get_subsys_dev_type(se_dev, &type);
	if (ret != 0)
		return ret;

	if (type == SUBSYSTEM_FILE) {
		fd_dev = qnap_transport_get_fd_dev(se_dev);
		inode = fd_dev->fd_file->f_mapping->host;

		if (S_ISBLK(inode->i_mode))
			total_blks = (i_size_read(inode) >> bs_order);
		else
			total_blks = (fd_dev->fd_dev_size >> bs_order);

		pr_debug("FILEIO: Using size: %llu blks and block size: %d\n", 
			total_blks, (1 << bs_order));
	} else {
		ib_dev = qnap_transport_get_iblock_dev(se_dev);
		bd = ib_dev->ibd_bd;
		total_blks = (i_size_read(bd->bd_inode) >> bs_order);

		pr_debug("iBlock: Using size: %llu blks and block size: %d\n", 
			total_blks, (1 << bs_order));
	}

	return 0;
}
EXPORT_SYMBOL(qnap_change_dev_size);

void qnap_transport_enumerate_hba_for_deregister_session(
	struct se_session *se_sess
	)
{
	struct se_device *se_dev;

	mutex_lock(&g_device_mutex);

	list_for_each_entry(se_dev, &g_device_list, g_dev_node) {
		spin_lock(&se_dev->dev_reservation_lock);
		if (!se_dev->dev_reserved_node_acl) {
			spin_unlock(&se_dev->dev_reservation_lock);
			continue;
		}

		if (se_dev->dev_reserved_node_acl != se_sess->se_node_acl) {
			spin_unlock(&se_dev->dev_reservation_lock);
			continue;
		}

		se_dev->dev_reserved_node_acl = NULL;
		se_dev->dev_flags &= ~DRF_SPC2_RESERVATIONS;
		if (se_dev->dev_flags & DRF_SPC2_RESERVATIONS_WITH_ISID) {
			se_dev->dev_res_bin_isid = 0;
			se_dev->dev_flags &= ~DRF_SPC2_RESERVATIONS_WITH_ISID;
		}
		spin_unlock(&se_dev->dev_reservation_lock);
	}
	mutex_unlock(&g_device_mutex);
	return;
}

#ifdef SUPPORT_TP
extern int dm_thin_volume_is_full(void *data);

int qnap_transport_check_cmd_hit_thin_threshold(
	struct se_cmd *se_cmd
	)
{
	struct se_device *se_dev = se_cmd->se_dev;
	int bs_order = ilog2(se_dev->dev_attrib.block_size);
	loff_t ts_bytes = 0, us_blks = 0;
	sector_t a_blks, u_blks;
	uint64_t t_min,  dividend;
	int ret, reached = 0, under_threshold = 0;

	ret = qnap_transport_check_is_thin_lun(se_cmd->se_dev);
	if (ret != 1)
		return -ENODEV;

	/* we ONLY handle the write-direction command */
#if defined(QNAP_HAL)
	NETLINK_EVT hal_event;
	
	memset(&hal_event, 0, sizeof(NETLINK_EVT));
	hal_event.type = HAL_EVENT_ISCSI;
#endif
	
	ret = qnap_transport_get_a_blks_and_u_blks_on_thin(
		se_dev, bs_order, &a_blks, &u_blks);
	
	if (ret != 0)
		return ret;
	
	dividend = ((a_blks + u_blks) << bs_order);
	dividend = (dividend * se_dev->dev_attrib.tp_threshold_percent);
	t_min = div_u64(dividend, 100);
	
	if ((u_blks << bs_order) > t_min) {
		if (se_dev->dev_attrib.tp_threshold_hit == 0){
			se_dev->dev_attrib.tp_threshold_hit++;
			reached = 1;
		}
	} else{
		if (se_dev->dev_attrib.tp_threshold_hit != 0) {
			se_dev->dev_attrib.tp_threshold_hit = 0;
			check_lun_threshold_for_each_device(&under_threshold);
			/* under_threshold == 0, there are some LUN is still over threshold.
			   under_threshold == 0, all the LUN is under threshold. */
		}
	}	
	if (reached) {
#if defined(QNAP_HAL)	
		hal_event.arg.action = HIT_LUN_THRESHOLD;
		hal_event.arg.param.iscsi_lun.lun_index = 
			se_dev->dev_attrib.lun_index;
		hal_event.arg.param.iscsi_lun.tp_threshold = 
			se_dev->dev_attrib.tp_threshold_percent;

		/* unit: GB */
		hal_event.arg.param.iscsi_lun.tp_avail = 
			((a_blks << bs_order) >> 30);
		send_hal_netlink(&hal_event);
#endif
		return 0;
	} else if (under_threshold) {
#if defined(QNAP_HAL)	
		NETLINK_EVT hal_event;
		
		memset(&hal_event, 0, sizeof(NETLINK_EVT));
		hal_event.type = HAL_EVENT_ISCSI;

		hal_event.arg.action = UNDER_LUN_THRESHOLD;
		hal_event.arg.param.iscsi_lun.lun_index = 0;
		hal_event.arg.param.iscsi_lun.tp_threshold = 0;

		/* unit: GB */
		hal_event.arg.param.iscsi_lun.tp_avail = 
			((a_blks << bs_order) >> 30);

		/* call function if it exists since we declare it as weak symbol */
		if (send_hal_netlink)
			send_hal_netlink(&hal_event);
#endif
	}

	return -EPERM;
}
EXPORT_SYMBOL(qnap_transport_check_cmd_hit_thin_threshold);

static int __qnap_fbdisk_update_thin_allocated(
	struct se_device *se_dev
	)
{
	loff_t total_bytes = 0, used_blks = 0;
	int ret, order = 9;

	ret = qnap_transport_fbdisk_get_ts_bytes_and_us_blks(se_dev, 
		&total_bytes, &used_blks);

	if (ret != 0)
		return ret;

	/* the unit of used_blks is 512 bytes */
	se_dev->dev_attrib.allocated = (used_blks << 9);
	return 0;
}

int qnap_transport_get_thin_allocated(
	struct se_device *se_dev
	)
{
	struct iblock_dev *ibd = NULL;
	SUBSYSTEM_TYPE type;
	int ret;

	ret = qnap_transport_get_subsys_dev_type(se_dev, &type);
	if (ret != 0)
		return ret;

	if (type == SUBSYSTEM_FILE)
		return -ENODEV;

	if (!(se_dev->dev_flags & DF_CONFIGURED))
		return -ENODEV;

	/* currently, we support blk io + fbdisk block dev (file based lun) */
	ibd = qnap_transport_get_iblock_dev(se_dev);
	ret = qnap_transport_is_fbdisk_dev(ibd->ibd_bd);
	if (ret != 0)
		return -ENODEV;

	ret = __qnap_fbdisk_update_thin_allocated(se_dev);
	if (ret != 0)
		return ret;

	return 0;
}
#endif

#ifdef ISCSI_D4_INITIATOR
struct se_node_acl *qnap_tpg_get_initiator_node_acl(
	struct se_portal_group *tpg,
	unsigned char *initiatorname
	)
{
	struct se_node_acl *acl = NULL;

	// 2009/09/23 Nike Chen add for default initiator
	mutex_lock(&tpg->acl_node_mutex);

	list_for_each_entry(acl, &tpg->acl_node_list, acl_list) {
		if (!tpg->default_acl && !(strcmp(acl->initiatorname, 
			DEFAULT_INITIATOR))
			)
		{
			tpg->default_acl = acl;
			pr_debug("Get default acl %p for tpg %p.\n", 
				tpg->default_acl, tpg);
		}

		if (!tpg->default_acl && !(strcmp(acl->initiatorname,
			FC_DEFAULT_INITIATOR))
			)
		{
			tpg->default_acl = acl;
			pr_debug("Get FC default acl %p for tpg %p.\n",
				tpg->default_acl, tpg);
		}

		if (!strcasecmp(acl->initiatorname, initiatorname) &&
			!acl->dynamic_node_acl) 
		{
			mutex_unlock(&tpg->acl_node_mutex);
			return acl;
		}
	}

	mutex_unlock(&tpg->acl_node_mutex);
	return NULL;
}
EXPORT_SYMBOL(qnap_tpg_get_initiator_node_acl);

void qnap_tpg_copy_node_devs(
	struct se_node_acl *dest,
	struct se_node_acl *src,
	struct se_portal_group *tpg
	)
{
	u32 lun_access = 0;
	struct se_dev_entry *deve;
	struct se_lun *lun = NULL;

	rcu_read_lock();

	hlist_for_each_entry_rcu(deve, &src->lun_entry_hlist, link) {

		lun = rcu_dereference(deve->se_lun);
		if (!lun)
			continue;
	
		lun_access = (deve->lun_flags & TRANSPORT_LUNFLAGS_READ_WRITE) ?
			TRANSPORT_LUNFLAGS_READ_WRITE :
			TRANSPORT_LUNFLAGS_READ_ONLY;

		pr_debug("TARGET_CORE[%s]->TPG[%u]_LUN[%u] - Copying %s"
			" access for LUN\n", 
			tpg->se_tpg_tfo->get_fabric_name(),
			tpg->se_tpg_tfo->tpg_get_tag(tpg), 
			lun->unpacked_lun,
			(lun_access == TRANSPORT_LUNFLAGS_READ_WRITE) ?
			"READ-WRITE" : "READ-ONLY");

		rcu_read_unlock();

		/* unlock here since core_enable_device_list_for_node() will
		 * allocate memory and do lock ...
		 */
		core_enable_device_list_for_node(lun, NULL,
			lun->unpacked_lun, lun_access, dest, tpg);

		rcu_read_lock();
	}

	rcu_read_unlock();

	return;
}
EXPORT_SYMBOL(qnap_tpg_copy_node_devs);

/* 2019/06/12 Jonathan Ho: Only add the lun instead of all luns to dynamic acls. */
void qnap_tpg_add_node_to_devs_when_add_lun(
	struct se_portal_group *tpg,
	struct se_lun *lun
	)
{
	struct se_node_acl *acl = NULL;

	mutex_lock(&tpg->acl_node_mutex);
	list_for_each_entry(acl, &tpg->acl_node_list, acl_list) {
		// Benjamin 20120719: Note that acl->dynamic_node_acl should be
		// set in core_tpg_check_initiator_node_acl(), and no
		// NAF_DYNAMIC_NODE_ACL anymore.
		if (acl->dynamic_node_acl) {
			mutex_unlock(&tpg->acl_node_mutex);
			core_tpg_add_node_to_devs(acl, tpg, lun);
			mutex_lock(&tpg->acl_node_mutex);
		}
	}
	mutex_unlock(&tpg->acl_node_mutex);
	return;
}
EXPORT_SYMBOL(qnap_tpg_add_node_to_devs_when_add_lun);
#endif

void qnap_transport_config_zc_val(
	struct se_device *dev
	)
{
	/* zero-copy only supports on fio + blkdev configuration */
	if(!strcmp(dev->transport->name, "fileio")
	&& (qnap_transport_is_fio_blk_backend(dev) == 0)
	)
	{
		dev->dev_dr.dev_zc = 0;
		return;
	}
	/* other cases is 0 */
	dev->dev_dr.dev_zc = 0;
	return;
}
EXPORT_SYMBOL(qnap_transport_config_zc_val);

static void __qnap_init_zc_val(
	struct qnap_se_dev_dr *dr
	)
{
	spin_lock_init(&dr->dev_zc_lock);
	dr->dev_zc = 0;
}

static void __qnap_init_queue_obj(
	struct se_queue_obj *qobj
	)
{
	atomic_set(&qobj->queue_cnt, 0);
	INIT_LIST_HEAD(&qobj->qobj_list);
	init_waitqueue_head(&qobj->thread_wq);
	spin_lock_init(&qobj->queue_lock);
}

static void __qnap_init_wt_val(
	struct qnap_se_dev_dr *dr
	)
{
	spin_lock_init(&dr->dev_wt_lock);
	dr->dev_wt = 1;
	dr->process_thread = NULL;
	__qnap_init_queue_obj(&dr->dev_queue_obj);
}

void qnap_init_se_dev_dr(
	struct qnap_se_dev_dr *dr
	)
{
	memset(dr, 0, sizeof(struct qnap_se_dev_dr));

	__qnap_init_zc_val(dr);
	__qnap_init_wt_val(dr);
	dr->pool_blk_kb = 0;

#ifdef SUPPORT_FAST_BLOCK_CLONE
	dr->fast_blk_clone = 0;
	dr->fbc_control = 0;
	spin_lock_init(&dr->fbc_control_lock);
#endif
	atomic_set(&dr->hit_read_deletable, 0);
}


void qnap_transport_add_cmd_to_queue(
	struct se_cmd *cmd, 
	int t_state,
	bool at_head
	)
{
	struct se_device *dev = cmd->se_dev;
	struct se_queue_obj *qobj = &dev->dev_dr.dev_queue_obj;
	unsigned long flags;
	
	if (t_state) {
		spin_lock_irqsave(&cmd->t_state_lock, flags);
		cmd->t_state = t_state;
		cmd->transport_state |= CMD_T_ACTIVE;
		spin_unlock_irqrestore(&cmd->t_state_lock, flags);
	}
	
	spin_lock_irqsave(&qobj->queue_lock, flags);

	/* If the cmd is already on the list, remove it before we add it */
	if (!list_empty(&cmd->se_queue_node)) {
		list_del_init(&cmd->se_queue_node);
	}
	else
		atomic_inc(&qobj->queue_cnt);
	
	if (at_head)
		list_add(&cmd->se_queue_node, &qobj->qobj_list);
	else
		list_add_tail(&cmd->se_queue_node, &qobj->qobj_list);
	cmd->transport_state |= CMD_T_QUEUED;
	
	spin_unlock_irqrestore(&qobj->queue_lock, flags);
	wake_up_interruptible(&qobj->thread_wq);

}

void qnap_transport_remove_cmd_from_queue(
	struct se_cmd *cmd
	)
{
	struct se_queue_obj *qobj = &cmd->se_dev->dev_dr.dev_queue_obj;
	unsigned long flags;

	spin_lock_irqsave(&qobj->queue_lock, flags);
	if (!(cmd->transport_state & CMD_T_QUEUED)) {
		spin_unlock_irqrestore(&qobj->queue_lock, flags);
		return;
	}
	cmd->transport_state &= ~CMD_T_QUEUED;

	atomic_dec(&qobj->queue_cnt);
	list_del_init(&cmd->se_queue_node);
	spin_unlock_irqrestore(&qobj->queue_lock, flags);
}

struct se_cmd *qnap_transport_get_cmd_from_queue(
	struct se_queue_obj *qobj
	)
{
	struct se_cmd *cmd;
	unsigned long flags;

	spin_lock_irqsave(&qobj->queue_lock, flags);
	if (list_empty(&qobj->qobj_list)) {
		spin_unlock_irqrestore(&qobj->queue_lock, flags);
		return NULL;
	}
	cmd = list_first_entry(&qobj->qobj_list, struct se_cmd, se_queue_node);
	cmd->transport_state &= ~CMD_T_QUEUED;

	if (list_empty(&cmd->se_queue_node))
		WARN_ON(1);

	list_del_init(&cmd->se_queue_node);
	atomic_dec(&qobj->queue_cnt);
	spin_unlock_irqrestore(&qobj->queue_lock, flags);

	return cmd;

}

int qnap_transport_thread_cpu_setting(
		struct se_device *dev)
{
	cpumask_var_t cpumask;
	int cpu = 0;

	if (!(dev->dev_dr.se_dev_thread_cpumask == 0) && 
			!(dev->dev_dr.se_dev_thread_cpumask == 0xff)) {

		if (!zalloc_cpumask_var(&cpumask, GFP_KERNEL)) {
			pr_err("Unable to allocate conn->conn_cpumask\n");
		} else {
			for_each_online_cpu(cpu) {
				if ((1 <<cpu) & dev->dev_dr.se_dev_thread_cpumask) {
					cpumask_set_cpu(cpu, cpumask);
					pr_debug("%s: set cpu %d\n",__func__,cpu);
				}
			}
			set_cpus_allowed_ptr(current,cpumask);

			free_cpumask_var(cpumask);
			pr_debug("%s: set cpumask %u\n",__func__,
					dev->dev_dr.se_dev_thread_cpumask);
		}
	}

	return 0;

}

int qnap_transport_processing_thread(
	void *param
	)
{
	int ret;
	struct se_cmd *cmd;
	struct se_device *dev = param;
	
	set_user_nice(current, -20);
	
	qnap_transport_thread_cpu_setting(dev);
	while (!kthread_should_stop()) {
		ret = wait_event_interruptible(dev->dev_dr.dev_queue_obj.thread_wq,
				atomic_read(&dev->dev_dr.dev_queue_obj.queue_cnt) ||
				kthread_should_stop());
		if (ret < 0)
			goto out;
	
get_cmd:
		cmd = qnap_transport_get_cmd_from_queue(&dev->dev_dr.dev_queue_obj);
		if (!cmd)
			continue;
	
		if (dev->dev_dr.se_dev_thread_cpumask != cmd->dev_cpumask) {
			dev->dev_dr.se_dev_thread_cpumask = cmd->dev_cpumask;
			qnap_transport_thread_cpu_setting(dev);
		}
		switch (cmd->t_state) {
		case TRANSPORT_WORK_THREAD_PROCESS:
			target_execute_cmd(cmd);
			break;
		default:
			pr_err("Unknown t_state: %d, "
				"i_state: %d on SE LUN: %u\n",
				cmd->t_state,
				cmd->se_tfo->get_cmd_state(cmd),
				cmd->se_lun->unpacked_lun);
			BUG();
		}
	
		goto get_cmd;
	}
	
out:
	WARN_ON(!list_empty(&dev->dev_dr.dev_queue_obj.qobj_list));
	dev->dev_dr.process_thread = NULL;
	return 0;

}

void qnap_core_tmr_drain_cmd_list(
	struct se_device *dev,
	struct se_cmd *prout_cmd,
	struct se_node_acl *tmr_nacl,
	int tas,
	struct list_head *preempt_and_abort_list
	)
{
	struct se_queue_obj *qobj = &dev->dev_dr.dev_queue_obj;
	struct se_cmd *cmd, *tcmd;
	unsigned long flags;

	/*
	 * Release all commands remaining in the struct se_device cmd queue.
	 *
	 * This follows the same logic as above for the struct se_device
	 * struct se_task state list, where commands are returned with
	 * TASK_ABORTED status, if there is an outstanding $FABRIC_MOD
	 * reference, otherwise the struct se_cmd is released.
	 */
	spin_lock_irqsave(&qobj->queue_lock, flags);
	list_for_each_entry_safe(cmd, tcmd, &qobj->qobj_list, se_queue_node) {

		/*
		 * For PREEMPT_AND_ABORT usage, only process commands
		 * with a matching reservation key.
		 */
		if (__qnap_tmf_check_cdb_and_preempt(preempt_and_abort_list, cmd))
			continue;
		/*
		 * Not aborting PROUT PREEMPT_AND_ABORT CDB..
		 */
		if (prout_cmd == cmd)
			continue;

		if (qnap_transport_is_dropped_by_tmr(cmd))
			continue;

		spin_lock(&cmd->tmf_data_lock);
		qnap_tmf_check_same_it_nexus(TMR_LUN_RESET, tas, cmd, tmr_nacl);
		spin_unlock(&cmd->tmf_data_lock);
		cmd->se_tfo->set_clear_delay_remove(cmd, 1, 0);
	}

	spin_unlock_irqrestore(&qobj->queue_lock, flags);

}

int qnap_transport_exec_wt_cmd(
	struct se_cmd *se_cmd
	)
{
	spin_lock(&se_cmd->se_dev->dev_dr.dev_wt_lock);

	if ((se_cmd->se_dev->dev_dr.dev_wt == 1)
	&& se_cmd->se_dev->dev_dr.process_thread
	)
	{
		spin_unlock(&se_cmd->se_dev->dev_dr.dev_wt_lock);
		qnap_transport_add_cmd_to_queue(se_cmd,
			TRANSPORT_WORK_THREAD_PROCESS, false);
		return 0;
	}

	spin_unlock(&se_cmd->se_dev->dev_dr.dev_wt_lock);
	return -1;
}
EXPORT_SYMBOL(qnap_transport_exec_wt_cmd);

static void __qnap_target_exec_random_work(
	struct work_struct *work
	)
{
	int ret;
	struct se_cmd *se_cmd = 
		container_of(work, struct se_cmd, random_work);

	if (se_cmd->execute_cmd) {
		ret = se_cmd->execute_cmd(se_cmd);
		if (ret) {
			spin_lock_irq(&se_cmd->t_state_lock);
			se_cmd->transport_state &= ~(CMD_T_BUSY|CMD_T_SENT);
			spin_unlock_irq(&se_cmd->t_state_lock);
			transport_generic_request_failure(se_cmd, ret);
		}
	}
	return;
}

int qnap_target_exec_random_task(
	struct se_cmd *se_cmd
	)
{
	u32 len, bs_order;
	bool go_wq = false, is_gen_read = false;
	struct qnap_se_dev_dr *dr = &se_cmd->se_dev->dev_dr;
	
	if (!dr->random_wq)
		return -EPERM;

	if(strcmp(se_cmd->se_dev->transport->name, "fileio"))
		return -EPERM;

	if ((se_cmd->t_task_cdb[0] == READ_6) || (se_cmd->t_task_cdb[0] == READ_10)
	||  (se_cmd->t_task_cdb[0] == READ_12) || (se_cmd->t_task_cdb[0] == READ_16)
	)
		is_gen_read = true;

	if (is_gen_read == true) {

		bs_order = ilog2(se_cmd->se_dev->dev_attrib.block_size);
		len = (dr->prev_len >> bs_order);

		if(se_cmd->t_task_lba == (dr->prev_lba + len))
			go_wq = false;
		else
			go_wq = true;

		dr->prev_lba = se_cmd->t_task_lba;
		dr->prev_len = se_cmd->data_length;
		if (go_wq == true) {
			INIT_WORK(&se_cmd->random_work, 
				__qnap_target_exec_random_work);
			queue_work(dr->random_wq, &se_cmd->random_work);
			return 0;
		}
	}
	return -EPERM;
}
EXPORT_SYMBOL(qnap_target_exec_random_task);

#include <linux/time.h>
#include <linux/timex.h>
#include <linux/rtc.h>

void qnap_transport_print_local_time(void)
{
	struct timex txc;
	struct rtc_time tm;
	char time_buf[1024];

	memset(time_buf, 0, 1024);

	do_gettimeofday(&(txc.time));
	txc.time.tv_sec -= sys_tz.tz_minuteswest * 60;
	rtc_time_to_tm(txc.time.tv_sec, &tm);

	sprintf(time_buf, "%04d-%02d-%02d %02d:%02d:%02d"
		,tm.tm_year+1900
		,tm.tm_mon+1
		,tm.tm_mday
		,tm.tm_hour
		,tm.tm_min
		,tm.tm_sec);

	printk("[iSCSI UTC] time: %s\n", time_buf);
	return;
}
EXPORT_SYMBOL(qnap_transport_print_local_time);

int qnap_transport_is_iblock_fbdisk(
	struct se_device *se_dev
	)
{
	if (se_dev->dev_dr.dev_type == QNAP_DT_IBLK_FBDISK)
		return 0;
	return -ENODEV;
}
EXPORT_SYMBOL(qnap_transport_is_iblock_fbdisk);

static char * __qnap_get_drop_type_str(
	int type
	)
{
	char *str;

	/* refer from enum tcm_tmreq_table in target_core_base.h file 
	 * and it matches for rfc3720 spec
	 */
	switch(type) {
	case -1:
		str = "RELEASE CONN";
		break;
	case TMR_ABORT_TASK:
		str = "ABORT TASK";
		break;
	case TMR_ABORT_TASK_SET:
		str = "ABORT TASK SET";
		break;
	case TMR_CLEAR_ACA:
		str = "CLAER ACA";
		break;
	case TMR_CLEAR_TASK_SET:
		str = "CLAER TASK SET";
		break;
	case TMR_LUN_RESET:
		str = "LUN RESET";
		break;
	case TMR_TARGET_WARM_RESET:
		str = "TARGET WARM RESET";
		break;
	case TMR_TARGET_COLD_RESET:
		str = "TARGET COLD RESET";
		break;
	default:
		str = NULL;
		break;
	}

	return str;
}

/* this function will be called when
 *
 * 1. dev->execute_task_lock was hold with spin_xxx_irqxxx() for LUN RESET
 * 2. or, se_sess->sess_cmd_lock was hold with spin_xxx_irqxxx() for ABORT TASK
 * 3. or, conn->cmd_lock was hold with spin_xx_bh()
 */
int qnap_transport_drop_bb_cmd(
	struct se_cmd *se_cmd,
	int type
	)
{
	int ret;
	char *type_str;
	char tmp_str[256];
	struct __iov_obj *obj = NULL;

	/* we do this only for fio + block-backend configuration */
	ret = qnap_transport_is_fio_blk_backend(se_cmd->se_dev);
	if (ret != 0)
		return ret;

	type_str = __qnap_get_drop_type_str(type);
	if (!type_str)
		return -EINVAL;

	memset(tmp_str, 0, sizeof(tmp_str));

#ifdef SUPPORT_TPC_CMD
	qnap_odx_drop_cmd(se_cmd, type);
#endif

	if (type == -1) {
		set_bit(QNAP_CMD_T_RELEASE_FROM_CONN, &se_cmd->cmd_dr.cmd_t_state);
	} else {

		obj = &se_cmd->iov_obj;

		spin_lock(&obj->iov_rec_lock);

		/* if found se_cmd->iov_rec, it means cmd was issued
		 * in fd_do_rw() already but may not back
		 */
		if (obj->iov_rec) {
			struct iov_iter *iov = obj->iov_rec;
			u32 iov_len = obj->iov_len;
			sprintf(tmp_str, "iov:0x%p, len:0x%x", iov, iov_len);
			qnap_iscsi_iov_set_drop(iov);
		}
		spin_unlock(&obj->iov_rec_lock);
	}

	pr_info("[iSCSI (block-based)][%s] ip: %s, drop itt:0x%08x, "
		"scsi op:0x%x. %s\n", type_str,
		se_cmd->se_tfo->get_login_ip(se_cmd),
		be32_to_cpu(se_cmd->se_tfo->get_task_tag(se_cmd)), 
		se_cmd->t_task_cdb[0], tmp_str);

	return 0;

}
EXPORT_SYMBOL(qnap_transport_drop_bb_cmd);

int qnap_transport_drop_fb_cmd(
	struct se_cmd *se_cmd,
	int type
	)
{
	int ret, count = 0;
	struct fbdisk_device *fb = NULL;
	struct iblock_dev *ib_dev = NULL;
	struct bio_rec *brec, *tmp_brec;
	char *type_str;
	struct __bio_obj *obj = NULL;

	if (qnap_transport_is_iblock_fbdisk(se_cmd->se_dev) != 0)
		return -ENODEV;

	ib_dev = IBLOCK_DEV(se_cmd->se_dev);
	fb = ib_dev->ibd_bd->bd_disk->private_data;
	if (!fb)
		return -ENODEV;

	type_str = __qnap_get_drop_type_str(type);
	if (!type_str)
		return -EINVAL;

#ifdef SUPPORT_TPC_CMD
	qnap_odx_drop_cmd(se_cmd, type);
#endif

	/* try to drop all possible bio for iblock + block-backend */
	if (type == -1) {
		set_bit(QNAP_CMD_T_RELEASE_FROM_CONN, &se_cmd->cmd_dr.cmd_t_state);
	}

	obj = &se_cmd->bio_obj;

	/* take care this ..., caller hold lock with spin_xxx_bh() already */
	spin_lock(&obj->bio_rec_lists_lock);
	list_for_each_entry_safe(brec, tmp_brec, &obj->bio_rec_lists, node)
	{
		if (brec->bio) {
			count++;
			set_bit(BIO_ISCSI_DROP_BIO, &brec->bio->bi_iscsi_flags);

			pr_info("[iSCSI (file-based)][%s] ip: %s, "
				"drop itt:0x%08x, scsi op:0x%x, "
				"bio:0x%p, dev:%s\n", 
				type_str, se_cmd->se_tfo->get_login_ip(se_cmd),
				be32_to_cpu(se_cmd->se_tfo->get_task_tag(se_cmd)),
				se_cmd->t_task_cdb[0],
				brec->bio, fb->fb_device->bd_disk->disk_name);
		}
	}
	spin_unlock(&obj->bio_rec_lists_lock);

	if (count) {
		pr_debug("[iSCSI (file-based)] wake fb event for dev:%s\n",
			fb->fb_device->bd_disk->disk_name);
		wake_up_interruptible(&fb->fb_event);
	}
	return 0;

}
EXPORT_SYMBOL(qnap_transport_drop_fb_cmd);

static void qnap_transport_free_bio_rec(
	struct se_cmd *se_cmd,
	struct bio_rec *rec
	)
{
	if (qnap_transport_is_iblock_fbdisk(se_cmd->se_dev) != 0)
		return;

	if (se_cmd->se_dev->dev_dr.fb_bio_rec_kmem && rec)
		kmem_cache_free(se_cmd->se_dev->dev_dr.fb_bio_rec_kmem, rec);

	return;
}

int qnap_transport_alloc_bio_rec(
	struct se_cmd *se_cmd,
	struct bio *bio
	)
{
	struct bio_rec *brec = NULL;
	struct __bio_obj *obj = NULL;
	unsigned long flags;

	if (qnap_transport_is_iblock_fbdisk(se_cmd->se_dev) != 0)
		return -ENODEV;

	obj = &se_cmd->bio_obj;

	if (se_cmd->se_dev->dev_dr.fb_bio_rec_kmem) {
		brec = kmem_cache_zalloc(se_cmd->se_dev->dev_dr.fb_bio_rec_kmem, 
			GFP_KERNEL);
		if (brec) {
			INIT_LIST_HEAD(&brec->node);
			brec->bio = bio;
			brec->se_cmd = se_cmd;
			bio->bi_private = qnap_bi_private_set_brec_bit((void *)brec);

			spin_lock_irqsave(&obj->bio_rec_lists_lock, flags);
			list_add_tail(&brec->node, &obj->bio_rec_lists);
			atomic_inc(&obj->bio_rec_count);
			spin_unlock_irqrestore(&obj->bio_rec_lists_lock, flags);
			return 0;
		}
	}
	return -ENOMEM;
}
EXPORT_SYMBOL(qnap_transport_alloc_bio_rec);

int qnap_transport_free_bio_rec_lists(
	struct se_cmd *se_cmd
	)
{
	struct bio_rec *brec = NULL, *tmp_bio_rec = NULL;
	struct __bio_obj *obj = NULL;
	LIST_HEAD(__free_list);
	unsigned long flags;

	if (qnap_transport_is_iblock_fbdisk(se_cmd->se_dev) != 0)
		return -ENODEV;

	obj = &se_cmd->bio_obj;

	spin_lock_irqsave(&obj->bio_rec_lists_lock, flags);
	
	pr_debug("bio rec count:%d\n", atomic_read(&obj->bio_rec_count));	

	list_for_each_entry_safe(brec, tmp_bio_rec, &obj->bio_rec_lists, 
		node)
	{
		list_move_tail(&brec->node, &__free_list);
	}
	spin_unlock_irqrestore(&obj->bio_rec_lists_lock, flags);

	list_for_each_entry_safe(brec, tmp_bio_rec, &__free_list, node) {
		list_del_init(&brec->node);
		atomic_dec(&obj->bio_rec_count);
		qnap_transport_free_bio_rec(se_cmd, brec);
	}

	return 0;
}
EXPORT_SYMBOL(qnap_transport_free_bio_rec_lists);

void qnap_transport_create_fb_bio_rec_kmem(
	struct se_device *se_dev
	)
{
	char tmp_name[128];

	if (qnap_transport_is_iblock_fbdisk(se_dev) != 0)
		return;

	/* only for iblock + fbdisk device */
	sprintf(tmp_name, "fb_bio_rec_cache-%d", se_dev->dev_index);

	se_dev->dev_dr.fb_bio_rec_kmem = kmem_cache_create(tmp_name,
			sizeof(struct bio_rec), 
			__alignof__(struct bio_rec), 
			0, NULL);

	if (!se_dev->dev_dr.fb_bio_rec_kmem)
		pr_warn("fail to create fb_bio_rec_cache, idx: %d\n", 
			se_dev->dev_index);

	return;
}
EXPORT_SYMBOL(qnap_transport_create_fb_bio_rec_kmem);

void qnap_transport_destroy_fb_bio_rec_kmem(
	struct se_device *se_dev
	)
{
	if (qnap_transport_is_iblock_fbdisk(se_dev) != 0)
		return;

	if (se_dev->dev_dr.fb_bio_rec_kmem)
		kmem_cache_destroy(se_dev->dev_dr.fb_bio_rec_kmem);

	return;
}
EXPORT_SYMBOL(qnap_transport_destroy_fb_bio_rec_kmem);

void qnap_transport_set_bio_rec_null(
	struct se_cmd *se_cmd,
	struct bio_rec *brec
	)
{
	struct __bio_obj *obj = NULL;
	unsigned long flags;

	if (qnap_transport_is_iblock_fbdisk(se_cmd->se_dev) != 0)
		return;

	obj = &se_cmd->bio_obj;

	spin_lock_irqsave(&obj->bio_rec_lists_lock, flags);
	list_del_init(&brec->node);
	atomic_dec(&obj->bio_rec_count);
	spin_unlock_irqrestore(&obj->bio_rec_lists_lock, flags);

	qnap_transport_free_bio_rec(se_cmd, brec);

	return;
}
EXPORT_SYMBOL(qnap_transport_set_bio_rec_null);

void qnap_transport_init_bio_rec_val(
	struct se_cmd *se_cmd
	)
{
	struct __bio_obj *obj = NULL;

	obj = &se_cmd->bio_obj;

	spin_lock_init(&obj->bio_rec_lists_lock);
	INIT_LIST_HEAD(&obj->bio_rec_lists);
	atomic_set(&obj->bio_rec_count, 1);
	return;
}
EXPORT_SYMBOL(qnap_transport_init_bio_rec_val);

void qnap_transport_init_iov_rec_val(
	struct se_cmd *se_cmd
	)
{
	struct __iov_obj *obj = NULL;

	obj = &se_cmd->iov_obj;

	spin_lock_init(&obj->iov_rec_lock);
	obj->iov_rec = NULL;
	obj->iov_drop= false;
	obj->iov_len = 0;
	return;
}
EXPORT_SYMBOL(qnap_transport_init_iov_rec_val);

void qnap_transport_prepare_iov_rec(
	struct se_cmd *se_cmd,
	void *iter,
	u32 len
	)
{
	struct __iov_obj *obj = NULL;
	unsigned long flags;

	if (qnap_transport_is_fio_blk_backend(se_cmd->se_dev) != 0)
		return;

	obj = &se_cmd->iov_obj;

	spin_lock_irqsave(&obj->iov_rec_lock, flags);
	obj->iov_rec = (struct iov_iter *)iter;
	obj->iov_len = len;
	spin_unlock_irqrestore(&obj->iov_rec_lock, flags);
	return;
}
EXPORT_SYMBOL(qnap_transport_prepare_iov_rec);

void qnap_transport_set_iov_rec_null(
	struct se_cmd *se_cmd
	)
{
	struct __iov_obj *obj = NULL;
	unsigned long flags;

	if (qnap_transport_is_fio_blk_backend(se_cmd->se_dev) != 0)
		return;

	obj = &se_cmd->iov_obj;

	spin_lock_irqsave(&obj->iov_rec_lock, flags);
	obj->iov_rec = NULL;
	spin_unlock_irqrestore(&obj->iov_rec_lock, flags);
	return;
}
EXPORT_SYMBOL(qnap_transport_set_iov_rec_null);

void qnap_transport_set_iov_drop_val(
	struct se_cmd *se_cmd,
	bool val
	)
{
	struct __iov_obj *obj = NULL;

	if (qnap_transport_is_fio_blk_backend(se_cmd->se_dev) != 0)
		return;

	obj = &se_cmd->iov_obj;
	obj->iov_drop = val;
	return;
}
EXPORT_SYMBOL(qnap_transport_set_iov_drop_val);

int qnap_transport_get_iov_drop_val(
	struct se_cmd *se_cmd
	)
{
	struct __iov_obj *obj = NULL;

	if (qnap_transport_is_fio_blk_backend(se_cmd->se_dev) != 0)
		return -ENODEV;

	obj = &se_cmd->iov_obj;
	return ((obj->iov_drop) ? 1 : 0);
}
EXPORT_SYMBOL(qnap_transport_get_iov_drop_val);

sense_reason_t
qnap_transport_iblock_execute_write_same_direct(
	struct block_device *bdev, 
	struct se_cmd *cmd
	)
{
#define NORMAL_IO_TIMEOUT	5

	struct se_device *se_dev = cmd->se_dev;
	sector_t block_lba = cmd->t_task_lba, work_lba;
	sector_t total_sects = sbc_get_write_same_sectors(cmd), work_sects;
	struct scatterlist *sgl = NULL;
	struct scatterlist *ori_sg = &cmd->t_data_sg[0];
	u64 alloc_bytes = (1 << 20), total_bytes, work_bytes;
	u32 bs_order = ilog2(se_dev->dev_attrib.block_size), idx, total_copy;
	GEN_RW_TASK w_task;
	sense_reason_t s_ret = TCM_LOGICAL_UNIT_COMMUNICATION_FAILURE;
	void *tmp_buf = NULL;
	int ret;

	memset(&w_task, 0, sizeof(GEN_RW_TASK));

	ret = qnap_transport_alloc_sg_list(&alloc_bytes, &w_task.sg_list,
		&w_task.sg_nents);

	if (ret != 0){
		if (ret == -ENOMEM) {
			pr_err("%s: fail to alloc sg list\n", __func__);
			s_ret = TCM_OUT_OF_RESOURCES;
		}
		if (ret == -EINVAL)
			pr_err("%s: invalid argument during to alloc sg list\n", 
				__func__);
		return s_ret;
	}

	/* copy original sg data to our sg lists ... */
	sgl = w_task.sg_list;

	for (idx = 0; idx < w_task.sg_nents; idx++) {
		total_copy = sgl[idx].length;
		tmp_buf = kmap(sg_page(&sgl[idx])) + sgl[idx].offset;

		/* original sg data size (512b or 4096b) may <= PAGE_SIZE, 
		 * here will try fill full to our sg lists
		 */
		while (total_copy) {
			sg_copy_to_buffer(ori_sg, cmd->t_data_nents, 
				tmp_buf, (1 << bs_order));

			tmp_buf += (size_t)(1 << bs_order);
			total_copy -= (1 << bs_order);
		}
		kunmap(sg_page(&sgl[idx]));		
	}

	/* start to write data directly ... */
	total_bytes = ((u64)total_sects << bs_order);

	while (total_bytes) {
		work_bytes = min_t(u64, total_bytes, alloc_bytes);
		work_lba = (work_bytes >> bs_order);

		qnap_transport_make_rw_task((void *)&w_task, se_dev,
			block_lba, work_lba,
			msecs_to_jiffies(NORMAL_IO_TIMEOUT*1000), 
			DMA_TO_DEVICE);

		ret = qnap_transport_do_b_rw((void *)&w_task);

		if((ret <= 0) || w_task.is_timeout || w_task.ret_code != 0){
			if (w_task.ret_code == -ENOSPC) {
				pr_warn_ratelimited("%s: space was full "
					"already\n",__func__);
				s_ret = TCM_SPACE_ALLOCATION_FAILED_WRITE_PROTECT;
			} else
				s_ret = TCM_LOGICAL_UNIT_COMMUNICATION_FAILURE;

			goto _exit_;
		}
		block_lba += work_lba;
		total_bytes -= work_bytes;
	}

	s_ret = TCM_NO_SENSE;

_exit_:
	qnap_transport_free_sg_list(w_task.sg_list, w_task.sg_nents);

	if (s_ret == TCM_NO_SENSE)
		target_complete_cmd(cmd, GOOD);

	return s_ret;
}
EXPORT_SYMBOL(qnap_transport_iblock_execute_write_same_direct);

int qnap_set_fua(struct se_device *se_dev, bool set_fua)
{
	bool is_fio_blkdev;
	struct fd_dev *fd_dev = NULL;
	struct iblock_dev *ib_dev = NULL;
	struct request_queue *q = NULL;

	if (qnap_transport_is_fio_blk_backend(se_dev) == 0)
		is_fio_blkdev = true;
	else if (qnap_transport_is_iblock_fbdisk(se_dev) == 0)
		is_fio_blkdev = false;
	else
		return -ENODEV;

	if (is_fio_blkdev == false) {
		/* TODO: is it ok .....?? shall check this
		 * we didn't call blk_queue_flush() to setup REQ_FLUSH
		 * or REQ_FUA in queue flags in fbdisk code, but we
		 * still clear (or setup) them here ...
		 */
		ib_dev = qnap_transport_get_iblock_dev(se_dev);
		q = bdev_get_queue(ib_dev->ibd_bd);

		if (set_fua)
			q->flush_flags |= REQ_FUA;
		else
			q->flush_flags &= ~(REQ_FUA);
	}

	se_dev->dev_attrib.emulate_fua_write = (int)set_fua;
	return 0;
}
EXPORT_SYMBOL(qnap_set_fua);

int qnap_set_write_cache(struct se_device *se_dev, bool set_wc)
{
	bool is_fio_blkdev;
	struct fd_dev *fd_dev = NULL;
	struct iblock_dev *ib_dev = NULL;
	struct request_queue *q = NULL;

	if (qnap_transport_is_fio_blk_backend(se_dev) == 0)
		is_fio_blkdev = true;
	else if (qnap_transport_is_iblock_fbdisk(se_dev) == 0)
		is_fio_blkdev = false;
	else
		return -ENODEV;

	if (is_fio_blkdev == false) {
		/* TODO: is it ok .....?? shall check this
		 * we didn't call blk_queue_flush() to setup REQ_FLUSH
		 * or REQ_FUA in queue flags in fbdisk code, but we
		 * still clear (or setup) them here ...
		 */
		ib_dev = qnap_transport_get_iblock_dev(se_dev);
		q = bdev_get_queue(ib_dev->ibd_bd);

		if (set_wc)
			q->flush_flags |= REQ_FLUSH;
		else
			q->flush_flags &= ~(REQ_FLUSH);
	}

	se_dev->dev_attrib.emulate_write_cache = (int)set_wc;

	return 0;

}
EXPORT_SYMBOL(qnap_set_write_cache);

enum {
	aptpl_Opt_initiator_fabric, aptpl_Opt_initiator_node, 
	aptpl_Opt_initiator_sid, aptpl_Opt_sa_res_key, aptpl_Opt_res_holder, 
	aptpl_Opt_res_type, aptpl_Opt_res_scope, aptpl_Opt_res_all_tg_pt, 
	aptpl_Opt_mapped_lun, aptpl_Opt_target_fabric, aptpl_Opt_target_node, 
	aptpl_Opt_tpgt, aptpl_Opt_port_rtpi, aptpl_Opt_target_lun, 
	aptpl_Opt_pr_data_start, aptpl_Opt_pr_data_end, aptpl_Opt_err
};

static match_table_t tokens = {
	{aptpl_Opt_initiator_fabric, "initiator_fabric=%s"},
	{aptpl_Opt_initiator_node, "initiator_node=%s"},
	{aptpl_Opt_initiator_sid, "initiator_sid=%s"},
	{aptpl_Opt_sa_res_key, "sa_res_key=%s"},
	{aptpl_Opt_res_holder, "res_holder=%d"},
	{aptpl_Opt_res_type, "res_type=%d"},
	{aptpl_Opt_res_scope, "res_scope=%d"},
	{aptpl_Opt_res_all_tg_pt, "res_all_tg_pt=%d"},
	{aptpl_Opt_mapped_lun, "mapped_lun=%d"},
	{aptpl_Opt_target_fabric, "target_fabric=%s"},
	{aptpl_Opt_target_node, "target_node=%s"},
	{aptpl_Opt_tpgt, "tpgt=%d"},
	{aptpl_Opt_port_rtpi, "port_rtpi=%d"},
	{aptpl_Opt_target_lun, "target_lun=%d"},
	{aptpl_Opt_pr_data_start, "PR_REG_START: %d"},
	{aptpl_Opt_pr_data_end, "PR_REG_END: %d"},
	{aptpl_Opt_err, NULL}
};

int __qnap_scsi3_parse_aptpl_data(
	struct se_device *se_dev,
	char *data,
	struct node_info *s,
	struct node_info *d
	)
{
	unsigned char *i_fabric = NULL, *i_port = NULL, *isid = NULL;
	unsigned char *t_fabric = NULL, *t_port = NULL;
	char *ptr, *arg_p, *opts;
	substring_t args[MAX_OPT_ARGS];
	unsigned long long tmp_ll;
	u64 sa_res_key = 0;
	u32 mapped_lun = 0, target_lun = 0;
	int ret = -1, res_holder = 0, all_tg_pt = 0, arg, token;
	int token_start = 0, token_end = 0, found_match = 0;
	u16 port_rpti = 0, tpgt = 0;
	u8 type = 0, scope;

	while ((ptr = strsep(&data, ",\n")) != NULL) {
		if (!*ptr)
			continue;
	
		token = match_token(ptr, tokens, args);
		switch (token) {
		case aptpl_Opt_pr_data_end:
			ret = match_int(args, &arg);
			if (ret)
				goto out;
			token_end = 1;
			break;
		case aptpl_Opt_pr_data_start:
			ret = match_int(args, &arg);
			if (ret)
				goto out;
			token_start = 1;
			break;
		case aptpl_Opt_initiator_fabric:
			i_fabric = match_strdup(&args[0]);
			if (!i_fabric) {
				ret = -ENOMEM;
				goto out;
			}
			break;
		case aptpl_Opt_initiator_node:
			i_port = match_strdup(&args[0]);
			if (!i_port) {
				ret = -ENOMEM;
				goto out;
			}
			if (strlen(i_port) >= PR_APTPL_MAX_IPORT_LEN) {
				pr_err("APTPL metadata initiator_node="
					" exceeds PR_APTPL_MAX_IPORT_LEN: %d\n",
					PR_APTPL_MAX_IPORT_LEN);
				ret = -EINVAL;
				break;
			}
			break;
		case aptpl_Opt_initiator_sid:
			isid = match_strdup(&args[0]);
			if (!isid) {
				ret = -ENOMEM;
				goto out;
			}
			if (strlen(isid) >= PR_REG_ISID_LEN) {
				pr_err("APTPL metadata initiator_isid"
					"= exceeds PR_REG_ISID_LEN: %d\n",
					PR_REG_ISID_LEN);
				ret = -EINVAL;
				break;
			}
			break;
		case aptpl_Opt_sa_res_key:
			ret = kstrtoull(args->from, 0, &tmp_ll);
			if (ret < 0) {
				pr_err("kstrtoull() failed for sa_res_key=\n");
				goto out;
			}
			sa_res_key = (u64)tmp_ll;
			break;
		/*
		 * PR APTPL Metadata for Reservation
		 */
		case aptpl_Opt_res_holder:
			ret = match_int(args, &arg);
			if (ret)
				goto out;
			res_holder = arg;
			break;
		case aptpl_Opt_res_type:
			ret = match_int(args, &arg);
			if (ret)
				goto out;
			type = (u8)arg;
			break;
		case aptpl_Opt_res_scope:
			ret = match_int(args, &arg);
			if (ret)
				goto out;
			scope = (u8)arg;
			break;
		case aptpl_Opt_res_all_tg_pt:
			ret = match_int(args, &arg);
			if (ret)
				goto out;
			all_tg_pt = (int)arg;
			break;
		case aptpl_Opt_mapped_lun:
			ret = match_int(args, &arg);
			if (ret)
				goto out;
			mapped_lun = (u32)arg;
			break;
		/*
		 * PR APTPL Metadata for Target Port
		 */
		case aptpl_Opt_target_fabric:
			t_fabric = match_strdup(&args[0]);
			if (!t_fabric) {
				ret = -ENOMEM;
				goto out;
			}
			break;
		case aptpl_Opt_target_node:
			t_port = match_strdup(&args[0]);
			if (!t_port) {
				ret = -ENOMEM;
				goto out;
			}
			if (strlen(t_port) >= PR_APTPL_MAX_TPORT_LEN) {
				pr_err("APTPL metadata target_node="
					" exceeds PR_APTPL_MAX_TPORT_LEN: %d\n",
					PR_APTPL_MAX_TPORT_LEN);
				ret = -EINVAL;
				break;
			}
			break;
		case aptpl_Opt_tpgt:
			ret = match_int(args, &arg);
			if (ret)
				goto out;
			tpgt = (u16)arg;
			break;
		case aptpl_Opt_port_rtpi:
			ret = match_int(args, &arg);
			if (ret)
				goto out;
			port_rpti = (u16)arg;
			break;
		case aptpl_Opt_target_lun:
			ret = match_int(args, &arg);
			if (ret)
				goto out;
			target_lun = (u32)arg;
			break;
		default:
			break;
		}

		if (!token_start) {
			pr_info("%s: not found any information in APTPL "
				"metafile\n", __func__);
			ret = -ENOENT;
			goto out;
		}
	
		if (token_end && token_start) {
			if (!i_port || !t_port || !sa_res_key) {
				pr_err("Illegal parameters for APTPL registration\n");
				ret = -EINVAL;
				goto out;
			}
				
			if (res_holder && !(type)) {
				pr_err("Illegal PR type: 0x%02x for reservation"
						" holder\n", type);
				ret = -EINVAL;
				goto out;
			}
	
			if (!strcmp(s->i_port, i_port) &&
			(!strncmp(s->i_sid, isid, PR_REG_ISID_LEN)) &&
			(!strcmp(s->t_port, t_port)) &&
			(s->tpgt == tpgt) && (s->mapped_lun == mapped_lun) &&
			(s->target_lun == target_lun)
			)
			{
				pr_debug("\n==== source info ====\n");
				pr_debug("i_port: %s, i_sid: %s\n", 
					s->i_port, s->i_sid);
				pr_debug("t_port: %s, tpgt: %d, "
					"mapped_lun: %d, target_lun: %d\n", 
					s->t_port, s->tpgt, s->mapped_lun, 
					s->target_lun);
				pr_debug("\n");

				pr_debug("\n==== found match info ====\n");
				pr_debug("initiator: %s, initiator node: %s, "
					"initiator sid: %s, t_port: %s, "
					"tpgt: %d, target_lun: %d\n", 
					i_fabric, i_port, isid, t_port,
					tpgt, target_lun);
				pr_debug("res key: %llu, res holder: %d\n", 
					sa_res_key, res_holder);
				pr_debug("res type: %d, scope: %d, "
					"all_tg_pt: %d, port_rpti: %d\n", 
					type, scope, all_tg_pt, port_rpti);
				pr_debug("\n");

				memcpy(d->i_port, i_port, PR_APTPL_MAX_IPORT_LEN);
				memcpy(d->t_port, t_port, PR_APTPL_MAX_IPORT_LEN);
				memcpy(d->i_sid, isid, PR_REG_ISID_LEN);
				d->tpgt = tpgt;
				d->sa_res_key = sa_res_key;
				d->mapped_lun = mapped_lun;
				d->target_lun = target_lun;
				d->res_holder = res_holder;
				d->all_tg_pt = all_tg_pt;
				d->port_rpti = port_rpti;
				d->type = type;
				d->scope = scope;

				found_match = 1;
			}

			if (found_match)
				goto out;

			token_start = 0;
			token_end = 0;
		}

		if (i_fabric)
			kfree(i_fabric);

		if (i_port)
			kfree(i_port);

		if (isid)
			kfree(isid);

		if (t_fabric)
			kfree(t_fabric);

		if (t_port)
			kfree(t_port);
	
		i_fabric = NULL;
		i_port = NULL;
		isid = NULL;
		t_fabric = NULL;
		t_port = NULL;
	
	}
	
out:
	if (i_fabric)
		kfree(i_fabric);
	if (t_fabric)
		kfree(t_fabric);
	if (i_port)
		kfree(i_port);
	if (isid)
		kfree(isid);
	if (t_port)
		kfree(t_port);

	if (found_match)
		return 0;

	return -ENOENT;

}

int __qnap_scsi3_check_aptpl_metadata_file_exists(
	struct se_device *dev,
	struct file **fp
	)
{
	struct t10_wwn *wwn = &dev->t10_wwn;
	struct file *file;
	mm_segment_t old_fs;
	int flags = O_RDONLY;
	char path[512];

	/* check aptpl meta file path */
	if (strlen(&wwn->unit_serial[0]) >= 512) {
		pr_err("%s: WWN value for struct se_device does not fit"
			" into path buffer\n", __func__);
		return -EMSGSIZE;
	}

	memset(path, 0, 512);
	snprintf(path, 512, "/var/target/pr/aptpl_%s", &wwn->unit_serial[0]);

	file = filp_open(path, flags, 0600);
	if (IS_ERR(file)) {
		pr_debug("%s: filp_open(%s) for APTPL metadata"
			" failed\n", __func__, path);
		return PTR_ERR(file);
	}

	*fp = file;
	return 0;
}

int qnap_transport_check_aptpl_registration(
	struct se_session *se_sess,
	struct se_node_acl *nacl,
	struct se_portal_group *tpg
	)
{
	int i = 0;
	u32 lun_access = 0;
	struct se_lun *lun;
	struct se_dev_entry *deve;

	mutex_lock(&nacl->lun_entry_mutex);

	hlist_for_each_entry_rcu(deve, &nacl->lun_entry_hlist, link) {

		lun = rcu_dereference_check(deve->se_lun, 
			lockdep_is_held(&nacl->lun_entry_mutex));

		if (!lun)
			continue;
	
		lun_access = (deve->lun_flags & TRANSPORT_LUNFLAGS_READ_WRITE) ?
			TRANSPORT_LUNFLAGS_READ_WRITE :	
			TRANSPORT_LUNFLAGS_READ_ONLY;

		mutex_unlock(&nacl->lun_entry_mutex);

		qnap_transport_scsi3_check_aptpl_registration(
			lun->lun_se_dev, tpg, lun, 
			se_sess, nacl, lun->unpacked_lun
			);

		mutex_lock(&nacl->lun_entry_mutex);
	}
	mutex_unlock(&nacl->lun_entry_mutex);

	return 0;
}
EXPORT_SYMBOL(qnap_transport_check_aptpl_registration);

#ifdef CONFIG_MACH_QNAPTS
#ifdef ISCSI_MULTI_INIT_ACL
void *qnap_target_add_qnap_se_nacl(
	char *initiator_name,
	struct qnap_se_nacl_dr *dr
	)
{
	struct qnap_se_node_acl	*acl = NULL;

	acl = kzalloc(sizeof(struct qnap_se_node_acl), GFP_KERNEL);
	if (!acl) {
		pr_warn("%s: fail alloc mem for qnap_se_node_acl\n", __func__);
		return NULL;
	}

	INIT_LIST_HEAD(&acl->acl_node);
	memcpy(acl->initiatorname, initiator_name, strlen(initiator_name));

	spin_lock(&dr->acl_node_lock);
	list_add_tail(&acl->acl_node, &dr->acl_node_list);
	spin_unlock(&dr->acl_node_lock);

	pr_debug("%s: add qnap se nacl:0x%p, initiator name:%s\n", __func__,
		acl, acl->initiatorname);

	return (void *)acl;
}

void qnap_target_init_qnap_se_nacl(
	struct qnap_se_nacl_dr *dr
	)
{
	INIT_LIST_HEAD(&dr->acl_node_list);
	spin_lock_init(&dr->acl_node_lock);
}

void qnap_target_free_qnap_se_nacl(
	void *map,
	struct qnap_se_nacl_dr *dr
	)
{
	struct qnap_se_node_acl *nacl, *nacl_tmp;
	bool found = false;
	int count = 0;

	spin_lock(&dr->acl_node_lock);
	list_for_each_entry_safe(nacl, nacl_tmp, &dr->acl_node_list, acl_node) {
		if (map != nacl)
			continue;

		pr_debug("%s: found map:0x%p, del qnap se nacl:0x%p\n", 
			__func__, map, nacl);
		count++;
		found = true;
		list_del_init(&nacl->acl_node);
		kfree(nacl);
	}

	spin_unlock(&dr->acl_node_lock);

	if (found == false)
		pr_warn("%s: not found qnap nacl, need to check\n", __func__);

	if (count > 1)
		pr_warn("%s: count > 1, need to check\n", __func__);

	return;

}


void qnap_target_free_all_qnap_se_nacls(
	struct qnap_se_nacl_dr *dr
	)
{
	struct qnap_se_node_acl *nacl, *nacl_tmp;
	LIST_HEAD(node_list);

	spin_lock(&dr->acl_node_lock);
	list_splice_init(&dr->acl_node_list, &node_list);
	spin_unlock(&dr->acl_node_lock);

	list_for_each_entry_safe(nacl, nacl_tmp, &node_list, acl_node) {
		pr_debug("%s: del qnap se nacl:0x%p\n", __func__, nacl);
		list_del_init(&nacl->acl_node);
		kfree(nacl);
	}
	return;
}

#endif
#endif

bool qnap_transport_is_dropped_by_tmr(
	struct se_cmd *se_cmd
	)
{
	bool dropped = false;

	spin_lock(&se_cmd->tmf_data_lock);
	if (se_cmd->tmf_code == TMR_LUN_RESET 
	|| se_cmd->tmf_code == TMR_ABORT_TASK
	)
		dropped = true;
	
	spin_unlock(&se_cmd->tmf_data_lock);	
	return dropped;
}
EXPORT_SYMBOL(qnap_transport_is_dropped_by_tmr);

bool qnap_transport_create_sess_lio_cmd_cache(
	struct qnap_se_sess_dr *dr,
	int idx,
	size_t alloc_size,
	size_t align_size
	)
{
	char tmp[256];
	size_t real_size;

	real_size = ((alloc_size - 1 + align_size) / align_size) * align_size;

	sprintf(tmp, "lio_cmd_cache_%d", idx);

	dr->lio_cmd_cache = kmem_cache_create(tmp, real_size, align_size, 0, NULL);

	if (!dr->lio_cmd_cache) {
		pr_err("%s: Unable create sess_lio_cmd_cache\n", __func__);
		return false;
	}

	atomic_set(&dr->cmd_count, 0);
	pr_debug("%s: alloc_size:%d, align_size:%d\n", __func__, 
			alloc_size, align_size);

	return true;
}
EXPORT_SYMBOL(qnap_transport_create_sess_lio_cmd_cache);

void qnap_transport_destroy_sess_lio_cmd_cache(
	struct qnap_se_sess_dr *dr
	)
{
	if (dr->lio_cmd_cache) {
		pr_debug("%s: cmd count:%d\n", __func__, 
				atomic_read(&dr->cmd_count));
		kmem_cache_destroy(dr->lio_cmd_cache);
	}
}
EXPORT_SYMBOL(qnap_transport_destroy_sess_lio_cmd_cache);

void *qnap_transport_alloc_sess_lio_cmd(
	struct qnap_se_sess_dr *dr, 
	gfp_t gfp_mask
	)
{
	void *cmd = NULL;

	if (dr->lio_cmd_cache) {
		cmd = kmem_cache_zalloc(dr->lio_cmd_cache, gfp_mask);
		if (cmd) {
			pr_debug("alloc icmd from sess_lio_cmd_cache\n"); 	
			atomic_inc(&dr->cmd_count);
		} else
			pr_err("%s: fail alloc icmd from sess_lio_cmd_cache\n",
				__func__); 	
	}

	return cmd;
}
EXPORT_SYMBOL(qnap_transport_alloc_sess_lio_cmd);

void qnap_transport_free_sess_lio_cmd(
	struct qnap_se_sess_dr *dr, 
	void *p
	)
{
	if (dr->lio_cmd_cache) {
		kmem_cache_free(dr->lio_cmd_cache, p);
		atomic_dec(&dr->cmd_count);
	}
}
EXPORT_SYMBOL(qnap_transport_free_sess_lio_cmd);

int qnap_transport_spc_cmd_size_check(
	struct se_cmd *cmd
	)
{
	int ret = 1;
	struct se_device *se_dev = cmd->se_dev;
	u8 *cdb = cmd->t_task_cdb;
	u32 size;

	/* Some host testing tools will set the ExpectedDataTransferLength
	 * in iscsi header to non-zero but the parameter list length
	 * (or allocation length) is zero in scsi cdb. According to the
	 * SPC, either parameter list length or allocation length is
	 * zero, they are NOT error condition (indicates no data shall
	 * be transferred).
	 * Therefore, here will do filter this condition again
	 */
	switch(cdb[0]){
	case MAINTENANCE_IN:
	case MAINTENANCE_OUT:
		if (se_dev->transport->get_device_type(se_dev) != TYPE_ROM) {
			if (((cdb[1] & 0x1f) == MI_REPORT_TARGET_PGS)
			|| ((cdb[1] & 0x1f) == MO_SET_TARGET_PGS)
			) 
			{
				size = get_unaligned_be32(&cdb[6]);
				if (0 == size)
					ret = 0;
			}

		}
		break;
	case SERVICE_ACTION_IN_16:
		switch (cmd->t_task_cdb[1] & 0x1f) {
		case SAI_READ_CAPACITY_16:
			size = get_unaligned_be32(&cdb[10]);
			if (!size)
				ret = 0;
			break;
		default:
			break;
		}

		break;
	default:
		break;
	}


	if (ret == 0) {
		pr_warn("%s: allocation len or parameter list len is 0 "
			"for cdb:0x%x\n", __func__, cdb[0]);
	}

	return ret;
}

sense_reason_t qnap_transport_check_report_lun_changed(
	struct se_cmd *se_cmd
	)
{
	struct se_dev_entry *deve;
	struct se_session *sess = se_cmd->se_sess;
	struct se_node_acl *nacl;
	u32 lun_count = 0, i;
	
	/* how can I do ??? */
	if (!sess)
		return TCM_LOGICAL_UNIT_COMMUNICATION_FAILURE;
	
	if (!sess->sess_dr.sess_got_report_lun_cmd)
		return 0;

	nacl = sess->se_node_acl;
		
	rcu_read_lock();

	hlist_for_each_entry_rcu(deve, &nacl->lun_entry_hlist, link)
		lun_count++;

	rcu_read_unlock();

	if (atomic_read(&sess->sess_dr.sess_lun_count) != lun_count) {
		pr_warn("lun counts was changed. send REPORTED LUNS DATA "
				"HAS CHANGED sense code\n");
		/* reset it ... */
		sess->sess_dr.sess_got_report_lun_cmd = false;
		return TCM_REPORTED_LUNS_DATA_HAS_CHANGED;
	}
	return 0;
}

bool qnap_check_v_sup(struct se_device *dev)
{
	return dev->dev_attrib.emulate_v_sup > 0;
}

sense_reason_t qnap_transport_convert_rc_to_tcm_sense_reason( //29208
	RC rc
	)
{
	sense_reason_t ret;

	switch (rc) {
	case RC_GOOD:
		return TCM_NO_SENSE;
	case RC_UNKNOWN_SAM_OPCODE:
		return TCM_UNSUPPORTED_SCSI_OPCODE;
	case RC_REQ_TOO_MANY_SECTORS:
		return TCM_SECTOR_COUNT_TOO_MANY;
	case RC_INVALID_CDB_FIELD:
		return TCM_INVALID_CDB_FIELD;
	case RC_INVALID_PARAMETER_LIST:
		return TCM_INVALID_PARAMETER_LIST;
	case RC_UNKNOWN_MODE_PAGE:
		return TCM_UNKNOWN_MODE_PAGE;
	case RC_WRITE_PROTECTEDS:
		return TCM_WRITE_PROTECTED;
	case RC_RESERVATION_CONFLICT:
		return TCM_RESERVATION_CONFLICT;
	case RC_CHECK_CONDITION_NOT_READY:
		return TCM_CHECK_CONDITION_NOT_READY;
	case RC_CHECK_CONDITION_ABORTED_CMD:
		return TCM_CHECK_CONDITION_ABORT_CMD;
	case RC_CHECK_CONDITION_UA:
		return TCM_CHECK_CONDITION_UNIT_ATTENTION;
	case RC_LBA_OUT_OF_RANGE:
		return TCM_ADDRESS_OUT_OF_RANGE;
	case RC_MISCOMPARE_DURING_VERIFY_OP:
		return TCM_MISCOMPARE_VERIFY;
	case RC_PARAMETER_LIST_LEN_ERROR:
		return TCM_PARAMETER_LIST_LENGTH_ERROR;
	case RC_UNREACHABLE_COPY_TARGET:
		return TCM_UNREACHABLE_COPY_TARGET;
	case RC_3RD_PARTY_DEVICE_FAILURE:
		return TCM_3RD_PARTY_DEVICE_FAILURE;
	case RC_INCORRECT_COPY_TARGET_DEV_TYPE:
		return TCM_INCORRECT_COPY_TARGET_DEV_TYPE;
	case RC_TOO_MANY_TARGET_DESCRIPTORS:
		return TCM_TOO_MANY_TARGET_DESCRIPTORS;
	case RC_TOO_MANY_SEGMENT_DESCRIPTORS:
		return TCM_TOO_MANY_SEGMENT_DESCRIPTORS;
	case RC_ILLEGAL_REQ_DATA_OVERRUN_COPY_TARGET:
		return TCM_ILLEGAL_REQ_DATA_OVERRUN_COPY_TARGET;
	case RC_ILLEGAL_REQ_DATA_UNDERRUN_COPY_TARGET:
		return TCM_ILLEGAL_REQ_DATA_UNDERRUN_COPY_TARGET;
	case RC_COPY_ABORT_DATA_OVERRUN_COPY_TARGET:
		return TCM_COPY_ABORT_DATA_OVERRUN_COPY_TARGET;
	case RC_COPY_ABORT_DATA_UNDERRUN_COPY_TARGET:
		return TCM_COPY_ABORT_DATA_UNDERRUN_COPY_TARGET;
	case RC_INSUFFICIENT_RESOURCES:
		return TCM_INSUFFICIENT_RESOURCES;
	case RC_INSUFFICIENT_RESOURCES_TO_CREATE_ROD:
		return TCM_INSUFFICIENT_RESOURCES_TO_CREATE_ROD;
	case RC_INSUFFICIENT_RESOURCES_TO_CREATE_ROD_TOKEN:
		return TCM_INSUFFICIENT_RESOURCES_TO_CREATE_ROD_TOKEN;
	case RC_OPERATION_IN_PROGRESS:
		return TCM_OPERATION_IN_PROGRESS;
	case RC_INVALID_TOKEN_OP_AND_INVALID_TOKEN_LEN:
		return TCM_INVALID_TOKEN_OP_AND_INVALID_TOKEN_LEN;
	case RC_INVALID_TOKEN_OP_AND_CAUSE_NOT_REPORTABLE:
		return TCM_INVALID_TOKEN_OP_AND_CAUSE_NOT_REPORTABLE;
	case RC_INVALID_TOKEN_OP_AND_REMOTE_ROD_TOKEN_CREATION_NOT_SUPPORTED:
		return TCM_INVALID_TOKEN_OP_AND_REMOTE_ROD_TOKEN_CREATION_NOT_SUPPORTED;
	case RC_INVALID_TOKEN_OP_AND_REMOTE_ROD_TOKEN_USAGE_NOT_SUPPORTED:
		return TCM_INVALID_TOKEN_OP_AND_REMOTE_ROD_TOKEN_USAGE_NOT_SUPPORTED;
	case RC_INVALID_TOKEN_OP_AND_TOKEN_CANCELLED:
		return TCM_INVALID_TOKEN_OP_AND_TOKEN_CANCELLED;
	case RC_INVALID_TOKEN_OP_AND_TOKEN_CORRUPT:
		return TCM_INVALID_TOKEN_OP_AND_TOKEN_CORRUPT;
	case RC_INVALID_TOKEN_OP_AND_TOKEN_DELETED:
		return TCM_INVALID_TOKEN_OP_AND_TOKEN_DELETED;
	case RC_INVALID_TOKEN_OP_AND_TOKEN_EXPIRED:
		return TCM_INVALID_TOKEN_OP_AND_TOKEN_EXPIRED;
	case RC_INVALID_TOKEN_OP_AND_TOKEN_REVOKED:
		return TCM_INVALID_TOKEN_OP_AND_TOKEN_REVOKED;
	case RC_INVALID_TOKEN_OP_AND_TOKEN_UNKNOWN:
		return TCM_INVALID_TOKEN_OP_AND_TOKEN_UNKNOWN;
	case RC_INVALID_TOKEN_OP_AND_UNSUPPORTED_TOKEN_TYPE:
		return TCM_INVALID_TOKEN_OP_AND_UNSUPPORTED_TOKEN_TYPE;
	case RC_NO_SPACE_WRITE_PROTECT:
		return TCM_SPACE_ALLOCATION_FAILED_WRITE_PROTECT;
	case RC_OUT_OF_RESOURCES:
		return TCM_OUT_OF_RESOURCES;
	case RC_THIN_PROVISIONING_SOFT_THRESHOLD_REACHED:
		return TCM_THIN_PROVISIONING_SOFT_THRESHOLD_REACHED;
	case RC_CAPACITY_DATA_HAS_CHANGED:
		return TCM_CAPACITY_DATA_HAS_CHANGED;
	case RC_NON_EXISTENT_LUN:
		return TCM_NON_EXISTENT_LUN;
	case RC_REPORTED_LUNS_DATA_HAS_CHANGED:
		return TCM_REPORTED_LUNS_DATA_HAS_CHANGED;
	case RC_LOGICAL_UNIT_COMMUNICATION_FAILURE:
	default:
		ret = TCM_LOGICAL_UNIT_COMMUNICATION_FAILURE;
		break;
	}

	return ret;

}

int qnap_transport_create_devinfo(
	struct se_cmd *cmd, 
	struct __dev_info *dev_info
	)
{
	struct se_device *se_dev = cmd->se_dev;
	struct qnap_se_dev_dr *dr = &se_dev->dev_dr;
	struct se_portal_group *se_tpg;
	struct fd_dev *__fd_dev;
	struct iblock_dev *__ib_dev;
	struct __fe_info *fe_info = &dev_info->fe_info;

	if (!cmd->se_lun)
		return -ENODEV;

	if(!qlib_is_fio_blk_dev(dr) && (se_dev->transport->get_dev)) {
		__fd_dev = (struct fd_dev *)se_dev->transport->get_dev(se_dev);
		fe_info->__dev.__fd.fd_file = __fd_dev->fd_file;
	} 
	else if(!qlib_is_ib_fbdisk_dev(dr) && (se_dev->transport->get_dev)) {
		__ib_dev = (struct iblock_dev *)se_dev->transport->get_dev(se_dev);
		fe_info->__dev.__bd.bd = __ib_dev->ibd_bd;
		fe_info->__dev.__bd.bio_set = __ib_dev->ibd_bio_set;
	} else
		return -ENODEV;

	se_tpg = cmd->se_lun->lun_tpg;

	dev_info->fe_info.is_thin = qlib_thin_lun(dr);
	dev_info->fe_info.fe_type = se_dev->dev_dr.dev_type;
	dev_info->bs_order = ilog2(se_dev->dev_attrib.block_size);
	dev_info->dev_max_lba = se_dev->transport->get_blocks(se_dev);
	dev_info->sbc_dev_type = se_dev->transport->get_device_type(se_dev);

	/* Refer the target_emulate_evpd_83() to crete initiatior port
	 * identifier field value 
	 */
	dev_info->initiator_rtpi = cmd->se_lun->lun_rtpi;
	dev_info->initiator_prot_id = se_tpg->proto_id;

	dr = &se_dev->dev_dr;
	qlib_get_naa_6h_code((void *)se_dev, &dr->dev_naa[0], &dev_info->naa[0],
		spc_parse_naa_6h_vendor_specific);
		
	if (cmd->se_dev->dev_attrib.emulate_fua_write)
		dev_info->dev_attr |= DEV_ATTR_SUPPORT_FUA_WRITE;

	if (cmd->se_dev->dev_attrib.emulate_write_cache)
		dev_info->dev_attr |= DEV_ATTR_SUPPORT_WRITE_CACHE;

	if (dev_info->fe_info.is_thin == true) {

		if (cmd->se_dev->dev_attrib.emulate_tpu)
			dev_info->dev_attr |= DEV_ATTR_SUPPORT_UNMAP;

		/* TBD */
		if (cmd->se_dev->dev_attrib.emulate_tpws)
			dev_info->dev_attr |= DEV_ATTR_SUPPORT_WRITE_SAME;

		/* support read zero after unmap, it needs by windows certification testing */
		if (dev_info->dev_attr & 
				(DEV_ATTR_SUPPORT_UNMAP | DEV_ATTR_SUPPORT_WRITE_SAME))
			dev_info->dev_attr |= DEV_ATTR_SUPPORT_READ_ZERO_UNMAP;
	}

#ifdef SUPPORT_TPC_CMD
#ifdef SUPPORT_FAST_BLOCK_CLONE
	if (se_dev->dev_dr.fast_blk_clone)
		dev_info->dev_attr |= DEV_ATTR_SUPPORT_DM_FBC;

	if (se_dev->dev_dr.fbc_control)
		dev_info->dev_attr |= DEV_ATTR_SUPPORT_DEV_FBC;
#endif
#endif
	return 0;
}


