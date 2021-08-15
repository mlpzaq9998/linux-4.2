/*******************************************************************************
 * Filename:  target_core_qfbc.c
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


#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/list.h>
#include <scsi/scsi.h>
#include <scsi/scsi_cmnd.h>
#include <asm/unaligned.h>

#include <target/target_core_base.h>
#include <target/target_core_backend.h>
#include <target/target_core_fabric.h>

#include "target_core_iblock.h"
#include "target_core_file.h"
#include "target_core_xcopy.h"
#include <linux/fast_clone.h>
#include "target_core_qtransport.h"
#include "target_core_qfbc.h"
#ifdef SUPPORT_TPC_CMD
#include "target_core_qodx_lib.h"
#endif

static struct block_device *__qnap_fbc_get_blk_dev(struct se_device *se_dev);
static int __qnap_check_fbc_enabled(struct se_device *se_dev);
static inline void __qnap_fbc_create_fbc_obj(FC_OBJ *fc_obj, 
	struct se_device *s_se_dev, struct se_device *d_se_dev,
	sector_t s_lba, sector_t d_lba, u64 data_bytes);

static int __qnap_fbc_check_src_dest_lba_before_fbc(FC_OBJ *fc_obj);
static int __qnap_fbc_do_check_support_fbc(FC_OBJ *fc_obj, TBC_DESC_DATA *tbcd_data);
static int __qnap_fbc_do_fast_block_clone(FC_OBJ *fc_obj);
static int __qnap_fbc_do_b2b_xcopy_by_fbc(FC_OBJ *fc_obj, u64 *data_bytes);
static int __qnap_fbc_do_update_fbc_data_bytes(FC_OBJ *fc_obj, 
	TBC_DESC_DATA *tbcd_data, sector_t dest_lba, u64 *data_bytes);

static inline void __qnap_fbc_init_fccb_data(FCCB_DATA *fccb_data, 
	struct completion *io_wait);

static int __qnap_fbc_create_fast_clone_io_lists(struct list_head *io_lists, 
	CREATE_REC *create_rec);

static void __qnap_fbc_fast_clone_cb(int err, THIN_BLOCKCLONE_DESC *clone_desc);
static int __qnap_fbc_submit_fast_clone_io_lists_wait(
	struct list_head *io_lists);

static inline u32 __qnap_fbc_get_done_blks_by_fast_clone_io_lists(
	struct list_head *io_lists);

static inline void __qnap_fbc_free_fast_clone_io_lists(
	struct list_head *io_lists);

int qnap_transport_check_support_fbc(
	struct block_device *bd
	)
{
	THIN_BLOCKCLONE_DESC tbc_desc;
	unsigned long ret_bs = 0;
	sector_t s_lba, d_lba;
	u32 data_blks;
 
	if (!bd)
		return -EINVAL;
 
	/* quick check for file-based lun (fbdisk) */
	if (!strncmp(bd->bd_disk->disk_name, "fbdisk", 6)){
		pr_warn("not support fast clone on fbdisk dev\n");
		return -ENOTSUPP;
	}

	/* unit is 512b */
	data_blks = ((POOL_BLK_SIZE_512_KB << 10) >> 9);
	s_lba = 0;
	d_lba = s_lba + data_blks;

	tbc_desc.src_dev = bd;
	tbc_desc.dest_dev = bd;
	tbc_desc.src_block_addr = s_lba;
	tbc_desc.dest_block_addr = d_lba;
	tbc_desc.transfer_blocks = data_blks;

	if (thin_support_block_cloning(&tbc_desc, &ret_bs) != 0){
		pr_warn("not support fast clone on dev: %s\n",
			bd->bd_disk->disk_name);
		return -ENOTSUPP;
	}

	return 0;
}
EXPORT_SYMBOL(qnap_transport_check_support_fbc);
 
void qnap_transport_setup_support_fbc(
	struct se_device *se_dev
	)
{
	int ret;
	SUBSYSTEM_TYPE type;
	struct iblock_dev *ib_dev = NULL;
	struct fd_dev *fd_dev = NULL;
	struct file *file = NULL;
	struct block_device *bd = NULL;
	struct inode *inode = NULL;
 
	se_dev->dev_dr.fast_blk_clone = 0;
	ret = qnap_transport_get_subsys_dev_type(se_dev, &type);
	if (ret != 0)
		return;
	if (type == SUBSYSTEM_BLOCK) {

		/* here is for block i/o  */
		ib_dev = qnap_transport_get_iblock_dev(se_dev);
		bd =  ib_dev->ibd_bd;

		if (qnap_transport_check_support_fbc(bd) == 1){
			se_dev->dev_dr.fast_blk_clone = 1;
			se_dev->dev_dr.fbc_control = 1;
			pr_info("IBLOCK: support fast clone\n");
		} else
			pr_info("IBLOCK: not support fast clone\n");
	} else {
		/* here is for file i/o */
		fd_dev = qnap_transport_get_fd_dev(se_dev);
		file = fd_dev->fd_file;
		inode = file->f_mapping->host;

		if (S_ISBLK(inode->i_mode)) {
			if(qnap_transport_check_support_fbc(inode->i_bdev) == 0) 
			{
				se_dev->dev_dr.fast_blk_clone = 1;
				se_dev->dev_dr.fbc_control = 1;
				pr_info("FD: LIO(File I/O) + Block Backend: "
					"support fast clone\n");
			} else
				pr_info("FD: LIO(File I/O) + Block Backend: "
					"not support fast clone\n");
		} else
			pr_info("FD: LIO(File I/O) + File Backend: "
				"not support fast clone\n");
	}
	return;
 }
EXPORT_SYMBOL(qnap_transport_setup_support_fbc);

static inline void __qnap_fbc_init_fccb_data(
	FCCB_DATA *fccb_data, 
	struct completion *io_wait
	)
{
	fccb_data->io_wait = io_wait;
	fccb_data->nospc_err = 0;
	atomic_set(&fccb_data->io_done, 1);
	atomic_set(&fccb_data->io_err_count, 0);
	return;
}

static int __qnap_fbc_create_fast_clone_io_lists(
	struct list_head *io_lists, 
	CREATE_REC *create_rec
	)
{
	FCIO_REC *io_rec;
	u64 tmp_bytes, buf_size, tmp_total;
	sector_t s_lba, d_lba;

	if (!io_lists || !create_rec)
		BUG_ON(1);

	tmp_total = 0;
	tmp_bytes = create_rec->transfer_bytes;
	//pr_err("%s: tmp_bytes %d\n",__func__,tmp_bytes);
	s_lba = create_rec->s_lba;
	d_lba = create_rec->d_lba;

	while (tmp_bytes){
		buf_size= min_t (u64, tmp_bytes, MAX_FBC_IO);

		io_rec = kzalloc(sizeof(FCIO_REC), GFP_KERNEL);
		if (!io_rec)
			break;

		/* prepare io_rec */
		io_rec->desc.src_dev = create_rec->s_blkdev;
		io_rec->desc.dest_dev = create_rec->d_blkdev;

		/* 1. unit is 512b 
		 * 2. desc.private_data in each io_rec will be setup in
		 * __qnap_fbc_submit_fast_clone_io_lists_wait() before to
		 * issue fast-block-clone request
		 */
		io_rec->desc.src_block_addr = s_lba;
		io_rec->desc.dest_block_addr = d_lba;
		io_rec->desc.transfer_blocks = (buf_size >> 9);
		io_rec->io_done = 0;
		INIT_LIST_HEAD(&io_rec->io_node);

		/* put the io req to lists */
		list_add_tail(&io_rec->io_node, io_lists);

		s_lba += (buf_size >> 9);
		d_lba += (buf_size >> 9);

		tmp_total += buf_size;
		tmp_bytes -= buf_size;
	}

	if (list_empty(io_lists))
		return 1;

	/* if not create fully, to update transfer_bytes to REAL bytes */
	if (tmp_bytes)
		create_rec->transfer_bytes = tmp_total;

	return 0;
}

static void __qnap_fbc_fast_clone_cb(
	int err,
	THIN_BLOCKCLONE_DESC *clone_desc
	)
{
	FCIO_REC *rec = NULL;
	FCCB_DATA *cb = NULL;

	rec = container_of(clone_desc, FCIO_REC, desc);
	cb = (FCCB_DATA *)clone_desc->private_data;

	/**/
	rec->io_done = 1;
	if (err != 0){
		if (err != -EINVAL)
			pr_err("%s: err:%d\n", __func__, err);
		if (err == -ENOSPC)
			cb->nospc_err = 1;

		atomic_inc(&cb->io_err_count);
		smp_mb__after_atomic();
	}

	/* If there is any error which were set before, here will set to done 
	 * to -1 even if current status is w/o any error */
	if (atomic_read(&cb->io_err_count))
	    rec->io_done = -1;

	if (atomic_dec_and_test(&cb->io_done)){
		pr_debug("[fbc] all io was done, to compete them\n");
		complete(cb->io_wait);
	}
	return;
}

static int __qnap_fbc_submit_fast_clone_io_lists_wait(
	struct list_head *io_lists
	)
{
#define MAX_USEC_T	(1000)

	DECLARE_COMPLETION_ONSTACK(fast_io_wait);
	FCIO_REC *rec = NULL;
	unsigned long t0;
	int ret;
	u32 t1;
	FCCB_DATA cb;
	THIN_BLOCKCLONE_DESC *desc;

	__qnap_fbc_init_fccb_data(&cb, &fast_io_wait);
	t0 = jiffies;

	/* submit fast copy io */
	list_for_each_entry(rec, io_lists, io_node){
		pr_debug("[fbc] src_block_addr:0x%llx, dest_block_addr:0x%llx,"
			"transfer_blocks:0x%x\n",
			(unsigned long long)rec->desc.src_block_addr, 
			(unsigned long long)rec->desc.dest_block_addr,
			rec->desc.transfer_blocks
			);


		desc = &rec->desc;
		desc->private_data = &cb;
		atomic_inc(&cb.io_done);
		ret = thin_do_block_cloning(&rec->desc, 
			(void *)__qnap_fbc_fast_clone_cb);

		if (ret != 0){
			pr_warn("thin_do_block_cloning() return %d\n",ret);
			__qnap_fbc_fast_clone_cb(ret, &rec->desc);
		}
	}

	/* to wait the all io if possible */
	if (!atomic_dec_and_test(&cb.io_done)){
		while (wait_for_completion_timeout(&fast_io_wait, 
				msecs_to_jiffies(FAST_CLONE_TIMEOUT_SEC * 1000)
				) == 0)
			pr_info("[fbc] wait fast copy io to be done\n");
	}


	/* check and print the io time */
	t1 = jiffies_to_usecs(jiffies - t0);
	if (t1 > MAX_USEC_T)
		pr_debug("[fbc] diff time: %d (usec)\n", t1);

	if (atomic_read(&cb.io_err_count)){
		if (cb.nospc_err)
			return -ENOSPC;
		else
			return -EIO;
	}
	return 0;
}

static inline u32 __qnap_fbc_get_done_blks_by_fast_clone_io_lists(
	struct list_head *io_lists
	)
{
	FCIO_REC *rec = NULL;
	u32 done = 0;

	list_for_each_entry(rec, io_lists, io_node){
		if (rec->io_done == 1)
			done += rec->desc.transfer_blocks;
	}

	/* the return done blks unit is 512b */
	pr_debug("[fbc] in %s, done blks (512b):0x%x\n", __FUNCTION__, done);
	return done;
}

static inline void __qnap_fbc_free_fast_clone_io_lists(
	struct list_head *io_lists
	)
{
	FCIO_REC *rec = NULL, *tmp_rec = NULL;

	list_for_each_entry_safe(rec, tmp_rec, io_lists, io_node)
		kfree(rec);
	return;
} 


static struct block_device *__qnap_fbc_get_blk_dev(
	struct se_device *se_dev
	)
{
	struct fd_dev *fd_dev = NULL;
	struct inode *inode = NULL;
	struct iblock_dev *ibd = NULL;
	struct block_device *blk_dev = NULL;
	SUBSYSTEM_TYPE type;
	int ret;

	ret = qnap_transport_get_subsys_dev_type(se_dev, &type);
	if (ret != 0)
		return NULL;

	if (type == SUBSYSTEM_BLOCK){
		ibd = qnap_transport_get_iblock_dev(se_dev);
		blk_dev = ibd->ibd_bd;
	}
	else{
		fd_dev = qnap_transport_get_fd_dev(se_dev);
		inode = fd_dev->fd_file->f_mapping->host;
		if (S_ISBLK(inode->i_mode))
			blk_dev = inode->i_bdev;
		else
			return NULL;
	}
	return blk_dev;
}

static inline void __qnap_fbc_create_fbc_obj(
	FC_OBJ *fc_obj,
	struct se_device *s_se_dev,
	struct se_device *d_se_dev,
	sector_t s_lba,
	sector_t d_lba,
	u64 data_bytes
	)
{
	fc_obj->s_se_dev = s_se_dev;
	fc_obj->d_se_dev = d_se_dev;
	fc_obj->s_dev_bs = s_se_dev->dev_attrib.block_size;
	fc_obj->d_dev_bs = d_se_dev->dev_attrib.block_size;
	fc_obj->s_lba = s_lba;
	fc_obj->d_lba = d_lba;
	fc_obj->data_bytes = data_bytes;
	fc_obj->nospc_err = 0;
	return;
}

/* ret -  0: GOOD , 1: BAD */
static int __qnap_fbc_check_src_dest_lba_before_fbc(
	FC_OBJ *fc_obj
	)
{
	sector_t s_lba, d_lba;
	u32 ps_blks, s_bs_order, d_bs_order;

	/* FIXED ME
	 *
	 * now, the BOTH src, dest LBA shall be on alignment or non-alignment
	 * address before to do fast block clone
	 */

	/* convert to 512b unit first */
	ps_blks = ((POOL_BLK_SIZE_512_KB << 10) >> 9);
	s_bs_order = ilog2(fc_obj->s_dev_bs);
	d_bs_order = ilog2(fc_obj->d_dev_bs);
	s_lba = ((fc_obj->s_lba << s_bs_order) >> 9);
	d_lba = ((fc_obj->d_lba << d_bs_order) >> 9);

	if (((s_lba & (ps_blks -1)) && (d_lba & (ps_blks -1)))
	|| ((!(s_lba & (ps_blks -1))) && (!(d_lba & (ps_blks -1))))
	)
		return 0;

	pr_debug("[fbc] %s - ori src lba (512b unit) :0x%llx, "
		"ori dest lba (512b unit) :0x%llx. LBA address is bad !!\n",
		__func__, (unsigned long long)s_lba, (unsigned long long)d_lba);
#if 0
	printk("<0>[fbc] %s - ori src lba (512b unit) :0x%llx, "
		"ori dest lba (512b unit) :0x%llx. LBA address is bad !!\n", 
		__func__, (unsigned long long)s_lba, (unsigned long long)d_lba);
#endif
	return 1;
}

static int __qnap_fbc_do_check_support_fbc(
	FC_OBJ *fc_obj,
	TBC_DESC_DATA *tbcd_data
	)
{
	/* when code comes here, the src and dest address shall be all aligned
	 * or not all aligned (after to call __check_s_d_lba_before_fbc func)
	 */
	sector_t o_ss_lba, o_se_lba, o_ds_lba, o_de_lba;
	sector_t n_ss_lba, n_ds_lba;
	u32 data_blks, ps_blks = ((POOL_BLK_SIZE_512_KB << 10) >> 9);
	u32 s_bs_order, d_bs_order, ps_blk_order, diff_blks;
	unsigned long ret_bs = 0;
	int ret = -ENOTSUPP;

	/**/
	tbcd_data->do_fbc = 0;
	ps_blk_order = ilog2(ps_blks);
	s_bs_order = ilog2(fc_obj->s_dev_bs);
	d_bs_order = ilog2(fc_obj->d_dev_bs);

	if ((fc_obj->data_bytes >> 9) < ps_blks){
		pr_debug("[fbc] total data blks (512b unit):0x%llx "
			"< ps_blks (512b unit):0x%x\n",
			(unsigned long long)(fc_obj->data_bytes >> 9),
			ps_blks
			);
#if 0
		printk("<0>[fbc] total data blks (512b unit):0x%llx "
			"< ps_blks (512b unit):0x%x\n",
			(unsigned long long)(fc_obj->data_bytes >> 9),
			ps_blks
			);
#endif
		goto _EXIT_;
	}

	data_blks = (fc_obj->data_bytes >> 9);
	o_ss_lba = ((fc_obj->s_lba << s_bs_order) >> 9);
	o_se_lba = (o_ss_lba + data_blks - 1);
	o_ds_lba = ((fc_obj->d_lba << d_bs_order) >> 9);
	o_de_lba = (o_ds_lba + data_blks - 1);

	/* both src and dest shall be aligned by dm-thin block size 512kB first */
	if ((o_ss_lba & (ps_blks -1)) && (o_ds_lba & (ps_blks -1)))
		goto _EXIT_;

	pr_debug("[fbc] === ori data ===\n");
	pr_debug("[fbc] o_ss_lba (512b unit):0x%llx\n", (unsigned long long)o_ss_lba);
	pr_debug("[fbc] o_se_lba (512b unit):0x%llx\n", (unsigned long long)o_se_lba);
	pr_debug("[fbc] o_ds_lba (512b unit):0x%llx\n", (unsigned long long)o_ds_lba);
	pr_debug("[fbc] o_de_lba (512b unit):0x%llx\n", (unsigned long long)o_de_lba);
	pr_debug("[fbc] data blks (512b unit):0x%x\n", data_blks);

	/* to convert to 512b unit first and run 1st round to get
	 * alignment address of SRC */
	n_ss_lba =  (((o_ss_lba + ps_blks - 1) >> ps_blk_order) \
		<< ps_blk_order);
	diff_blks = n_ss_lba - o_ss_lba;
	n_ds_lba = o_ds_lba + diff_blks;

	if (n_ds_lba & (ps_blks -1)){
		pr_debug("[fbc] new address doesn't aligned by 0x%x, "
			"new src:0x%llx, new dest:0x%llx, to skip fbc...\n",
			ps_blks, (unsigned long long)n_ss_lba, 
			(unsigned long long)n_ds_lba
			);
#if 0
		printk("<0>[fbc] new address doesn't aligned by 0x%x, "
			"new src:0x%llx, new dest:0x%llx, to skip fbc...\n",
			ps_blks, (unsigned long long)n_ss_lba, 
			(unsigned long long)n_ds_lba
			);
#endif
		goto _EXIT_;
	}

	/* final chance to check new data blks is multipled by ps_blks or not */
	data_blks = (o_se_lba - n_ss_lba + 1);
	if (data_blks < ps_blks){
		pr_debug("[fbc] the blks between o_se_lba and n_ss_lba is small"
			"then ps_blks\n");
#if 0
		printk("<0>[fbc] the blks between o_se_lba and n_ss_lba is small"
			"then ps_blks\n");
#endif
		goto _EXIT_;
	}else if (data_blks & (ps_blks -1))
		data_blks = ((data_blks >> ps_blk_order) << ps_blk_order);

	/* now to ask whether we can do fast block clone or not */
	tbcd_data->tbc_desc.src_dev = __qnap_fbc_get_blk_dev(fc_obj->s_se_dev);
	tbcd_data->tbc_desc.dest_dev = __qnap_fbc_get_blk_dev(fc_obj->d_se_dev);
	tbcd_data->tbc_desc.src_block_addr = n_ss_lba;
	tbcd_data->tbc_desc.dest_block_addr = n_ds_lba;
	tbcd_data->tbc_desc.transfer_blocks = data_blks;
	tbcd_data->tbc_desc.private_data = NULL;

	if (!tbcd_data->tbc_desc.src_dev || !tbcd_data->tbc_desc.dest_dev){
		pr_debug("[fbc] not found block device for src or dest\n");
#if 0
		printk("<0>[fbc] not found block device for src or dest\n");
#endif
		ret = -ENODEV;
		goto _EXIT_;
	}

	pr_debug("[fbc] === new data ===\n");
	pr_debug("[fbc] n_ss_lba (512b unit):0x%llx\n", (unsigned long long)n_ss_lba);
	pr_debug("[fbc] n_ds_lba (512b unit):0x%llx\n", (unsigned long long)n_ds_lba);
	pr_debug("[fbc] new data blks (512b unit):0x%x\n", data_blks);

	/* now to ask whether we can do fast block clone or not */
	if (thin_support_block_cloning(&tbcd_data->tbc_desc, &ret_bs) != 0){
		pr_debug("fail to call thin_support_block_cloning(), "
			"ret_bs:0x%lx\n", (unsigned long)ret_bs);
#if 0
		printk("<0>fail to call thin_support_block_cloning(), "
			"ret_bs:0x%lx\n", (unsigned long)ret_bs);
#endif
		goto _EXIT_;
	}

	if (ret_bs != POOL_BLK_SIZE_512_KB)
		pr_debug("warning: ret_bs != POOL_BLK_SIZE_KB\n");

	tbcd_data->do_fbc = 1;

	/* convert to original unit */
	tbcd_data->h_d_lba = fc_obj->d_lba;

	tbcd_data->d_align_lba = ((n_ds_lba << 9) >> d_bs_order);
	tbcd_data->data_bytes = ((u64)data_blks << 9);

	tbcd_data->t_d_lba = (tbcd_data->d_align_lba + \
		(tbcd_data->data_bytes >> d_bs_order));

	pr_debug("[fbc] === tcbd data ===\n");
	pr_debug("[fbc] h_d_lba:0x%llx\n", (unsigned long long)tbcd_data->h_d_lba);
	pr_debug("[fbc] d_align_lba:0x%llx\n", (unsigned long long)tbcd_data->d_align_lba);
	pr_debug("[fbc] data_bytes:0x%llx\n", (unsigned long long)tbcd_data->data_bytes);
	pr_debug("[fbc] t_d_lba:0x%llx\n", (unsigned long long)tbcd_data->t_d_lba);
	ret = 0;

_EXIT_:
	if (ret != 0){
		pr_debug("[fbc] %s - ret: %d\n", __func__, ret);
#if 0
		printk("<0>[fbc] %s - ret: %d\n", __func__, ret);
#endif
	}
	return ret;
}

static int __qnap_fbc_do_fast_block_clone(
	FC_OBJ *fc_obj
	)
{
	struct se_device *s_sdev = NULL, *d_sdev = NULL;
	struct fd_dev *s_fd_dev = NULL, *d_fd_dev = NULL;
	struct inode *s_inode = NULL, *d_inode = NULL;
	struct list_head io_lists;
	int ret, ret1, done_blks = 0, curr_done_blks_512 = 0;
	CREATE_REC create_rec;
	u32 s_bs_order, d_bs_order;
	sector_t s_lba = fc_obj->s_lba, d_lba = fc_obj->d_lba;

	/* the data_bytes range will be in 
	 * 0 ~ (OPTIMAL_TRANSFER_SIZE_IN_BYTES - 1) */
	u64 data_bytes = fc_obj->data_bytes;

	s_sdev = fc_obj->s_se_dev;
	d_sdev = fc_obj->d_se_dev;	
	s_fd_dev = s_sdev->transport->get_dev(s_sdev);
	d_fd_dev = d_sdev->transport->get_dev(d_sdev);
	s_inode = s_fd_dev->fd_file->f_mapping->host;
	d_inode = d_fd_dev->fd_file->f_mapping->host;
	s_bs_order = ilog2(fc_obj->s_dev_bs);
	d_bs_order = ilog2(fc_obj->d_dev_bs);

_EXEC_AGAIN:

	/* To flush and drop the cache data for src / dest first since we will
	 * ask block layer to do fast block clone
	 */
	ret1 = qlib_fd_flush_and_truncate_cache(s_fd_dev->fd_file, s_lba, 
			(data_bytes >> s_bs_order), s_bs_order, true, 
			qlib_thin_lun(&s_sdev->dev_dr));

	ret = qlib_fd_flush_and_truncate_cache(d_fd_dev->fd_file, d_lba, 
			(data_bytes >> d_bs_order), d_bs_order, true, 
			qlib_thin_lun(&d_sdev->dev_dr));

	if (ret != 0 || ret1 != 0){

		pr_warn("[fbc] fail to flush / drop cache for %s area. "
			"done_blks: %d\n",
			(((ret != 0 && ret1 != 0)) ? "src/dest" : \
			((ret1 != 0) ? "src": "dest")), done_blks
			);
#ifdef SUPPORT_TP
		if (ret == -ENOSPC || ret1 == -ENOSPC) {
			fc_obj->nospc_err = 1;
		}
#endif
		return done_blks;
	}

	INIT_LIST_HEAD(&io_lists);
	create_rec.s_blkdev = s_inode->i_bdev;
	create_rec.d_blkdev = d_inode->i_bdev;

	/* prepare the fbc io, to conver to 512b unit first */
	create_rec.s_lba = ((s_lba << s_bs_order) >> 9);
	create_rec.d_lba = ((d_lba << d_bs_order) >> 9);
	create_rec.transfer_bytes = data_bytes;

	/* After to create io lists, the create_rec.transfer_bytes may NOT
	 * the same as data_bytes  */
	ret =__qnap_fbc_create_fast_clone_io_lists(&io_lists, &create_rec);
	if (ret != 0)
		return 0;

	ret = __qnap_fbc_submit_fast_clone_io_lists_wait(&io_lists);

	/* After to submit io, the done_blks (unit is 512b) may 
	 * NOT the same as (create_rec.transfer_bytes >> 9) */
	curr_done_blks_512 = __qnap_fbc_get_done_blks_by_fast_clone_io_lists(&io_lists);
	done_blks += ((curr_done_blks_512 << 9) >> d_bs_order);
	__qnap_fbc_free_fast_clone_io_lists(&io_lists);


	/* (ret != 0) contains the case about cb_data.io_err_count is not zero */
	if ((ret != 0) || ((curr_done_blks_512 << 9) != create_rec.transfer_bytes)){
		if (ret == -ENOSPC)
			fc_obj->nospc_err = 1;

		pr_debug("[fbc] fail to call "
			"__submit_fast_clone_io_lists_wait(). done_blks:%d\n",
			done_blks);
		return done_blks;
	}

	s_lba += (sector_t)done_blks;
	d_lba += (sector_t)done_blks;

	if (create_rec.transfer_bytes != data_bytes){
		data_bytes -= create_rec.transfer_bytes;
		goto _EXEC_AGAIN;
	}
	return done_blks;
}


static int __qnap_fbc_do_b2b_xcopy_by_fbc(
	FC_OBJ *fc_obj,
	u64 *data_bytes
	)
{
	int w_done_blks, ret;
	u64 e_bytes = *data_bytes;

	w_done_blks = __qnap_fbc_do_fast_block_clone(fc_obj);

	if ((e_bytes >> ilog2(fc_obj->d_dev_bs)) != (u64)w_done_blks){
		pr_debug("[fbc] b2b xcopy - w_done_blks != expected write blks\n");

		if (fc_obj->nospc_err) {
			pr_err("[fbc] b2b xcopy - space was full\n");
			ret = TCM_SPACE_ALLOCATION_FAILED_WRITE_PROTECT;
		} else
			ret = TCM_3RD_PARTY_DEVICE_FAILURE;

		return ret;
	}
	return 0;
}

static int __qnap_fbc_do_update_fbc_data_bytes(
	FC_OBJ *fc_obj,
	TBC_DESC_DATA *tbcd_data, 
	sector_t dest_lba,
	u64 *data_bytes
	)
{
	int ret = 0;
	u32 d_bs_order;

	if (!tbcd_data->do_fbc){
#if 0
		printk("<0>[fbc] !tbcd_data->do_fbc\n");
#endif
		return ret;
	}

	d_bs_order = ilog2(fc_obj->d_dev_bs);

	if (dest_lba == tbcd_data->d_align_lba){
		*data_bytes = tbcd_data->data_bytes;
		ret = 1;
	}
	else{
		/* case for normal IO. only handle the case about
		 * "dest_lba < tbcd_data.d_align_lba"
		 */
		if (dest_lba < tbcd_data->d_align_lba)
			*data_bytes = ((tbcd_data->d_align_lba - dest_lba) \
				<< d_bs_order); 
	}

	pr_debug("[fbc] %s - ret:%d, dest:0x%llx, d_align_lba:0x%llx, "
		"real data bytes:0x%llx\n", __func__, ret,
		(unsigned long long)dest_lba,
		(unsigned long long)tbcd_data->d_align_lba,
		(unsigned long long)*data_bytes
		);
	return ret;
}


static int __qnap_check_fbc_enabled(
	struct se_device *se_dev
	)
{
	spin_lock(&se_dev->dev_dr.fbc_control_lock);
	if (!se_dev->dev_dr.fbc_control) {
		spin_unlock(&se_dev->dev_dr.fbc_control_lock);
		return -ENOTSUPP;
	}
	spin_unlock(&se_dev->dev_dr.fbc_control_lock);
	return 0;
}

int qnap_fbc_do_fast_block_clone(
	struct xcopy_op *xop
	)
{
	int is_create = 0, do_fbc = 0, ret = -1, fbc_enabled;
	/* TODO, shall check dc bit ? */
	u64 length = ((u64)xop->nolb * xop->src_dev->dev_attrib.block_size);
	FC_OBJ fc_obj;
	TBC_DESC_DATA tbc_desc_data;

	/* check iSCSI support FBC or not */
	if (!xop->src_dev->dev_dr.fast_blk_clone || !xop->dst_dev->dev_dr.fast_blk_clone)
		return ret; 

	/* check FBC was enabled by SRC or DEST */
	fbc_enabled = __qnap_check_fbc_enabled(xop->src_dev);
	if (fbc_enabled != 0)
		return ret;

	fbc_enabled = __qnap_check_fbc_enabled(xop->dst_dev);
	if (fbc_enabled != 0)
		return ret;

	if (!is_create){
		__qnap_fbc_create_fbc_obj(&fc_obj, xop->src_dev, 
			xop->dst_dev, xop->src_lba, xop->dst_lba, length);

		if (__qnap_fbc_check_src_dest_lba_before_fbc(&fc_obj) == 0){
			if (__qnap_fbc_do_check_support_fbc(&fc_obj, 
				&tbc_desc_data) == 0){
				do_fbc = __qnap_fbc_do_update_fbc_data_bytes(
						&fc_obj, &tbc_desc_data,
						xop->dst_lba, &length);
			}
		}
		is_create = 1;
	}
#if 0
	else{
		/* go further step since we created already */
		do_fbc = __qnap_fbc_do_update_fbc_data_bytes(
				&fc_obj, &tbc_desc_data,
				xop->dst_lba, &length);
	}
#endif
	if (do_fbc){
		/* now, the s_lba, d_lba and e_bytes were aligned already */
		__qnap_fbc_create_fbc_obj(&fc_obj, xop->src_dev, xop->dst_dev,
			 xop->src_lba, xop->dst_lba, length);
		ret = __qnap_fbc_do_b2b_xcopy_by_fbc(&fc_obj, &length);
	}

	return ret;
}
EXPORT_SYMBOL(qnap_fbc_do_fast_block_clone);

#ifdef SUPPORT_TPC_CMD
static int __qnap_fbc_do_odx_by_fbc(
	struct wut_io_data *io_data,
	FC_OBJ *fc_obj,
	u64 *data_bytes
	)
{
	int w_done_blks, ret = 0;
	u64 e_bytes = *data_bytes;

	w_done_blks = __qnap_fbc_do_fast_block_clone(fc_obj);

	__odx_lock_update_tc_cmd_transfer_count(io_data->tc_p, (sector_t)w_done_blks);

	if ((e_bytes >> ilog2(fc_obj->d_dev_bs)) != (u64)w_done_blks){
		pr_warn("[fbc] odx - w_done_blks != expected write blks\n");

		if (fc_obj->nospc_err) {
			pr_err("[fbc] odx: space was full\n");
			io_data->rc = RC_NO_SPACE_WRITE_PROTECT;
			ret = -ENOSPC;
		} else {
			io_data->rc = RC_3RD_PARTY_DEVICE_FAILURE;
			ret = -EINVAL;
		}
		return ret;
	}

	io_data->rc = RC_GOOD;
	return 0;
}

int qnap_do_fast_block_clone_odx(
	struct wut_io_data *io_data
	)
{
	struct blk_range_data *br = NULL;
	int do_fbc = 0, ret = -1;
	u64 length = 0;
	sector_t src_lba, dest_lba, br_off;
	TBC_DESC_DATA tbc_desc_data;
	FC_OBJ fc_obj;

	/* here we checked the dm-thin or iscsi layer supports for 
	 * fast block cloning from __odx_wut_io() already
	 */
	br = __odx_get_br_loc_by_rod_off(io_data->s_token, 
		io_data->s_rod_off_bytes, &br_off);

	if (!br) {
		io_data->rc = RC_UNREACHABLE_COPY_TARGET;
		return -EINVAL;
	}

	src_lba = br->lba + br_off;
	dest_lba = io_data->dest_lba;
	length = io_data->nr_bytes;

	__qnap_fbc_create_fbc_obj(&fc_obj, io_data->s_token->se_dev, 
		io_data->d_token->se_dev, src_lba, dest_lba, length);

	ret = __qnap_fbc_do_check_support_fbc(&fc_obj, &tbc_desc_data);
	if (ret != 0) {
		/* go normal path */
		io_data->rc = RC_GOOD;
		return ret;
	}

	do_fbc = __qnap_fbc_do_update_fbc_data_bytes(&fc_obj, &tbc_desc_data,
			dest_lba, &length);

	if (!do_fbc) {
		/* go normal path */
		io_data->rc = RC_GOOD;
		return -1;
	}

	/* now, the s_lba, d_lba and e_bytes were aligned already */
	__qnap_fbc_create_fbc_obj(&fc_obj, io_data->s_token->se_dev, 
		io_data->d_token->se_dev, src_lba, dest_lba, length);

	ret = __qnap_fbc_do_odx_by_fbc(io_data, &fc_obj, &length);

	return ret;
}
#endif




