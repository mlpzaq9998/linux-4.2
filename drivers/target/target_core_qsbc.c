/*******************************************************************************
 * Filename:  target_core_qsbc.c
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
#include <asm/unaligned.h>
#include <net/sock.h>
#include <net/tcp.h>
#include <scsi/scsi_proto.h>
#include <scsi/scsi_common.h>

#include <target/target_core_base.h>
#include <target/target_core_fabric.h>
#include <target/target_core_backend.h>
#include "target_core_iblock.h"
#include "target_core_file.h"
#include "target_core_pr.h"
#include "target_core_qtransport.h"
#include "target_core_qsbc.h"
#include "target_core_qspc.h"
#include "fbdisk.h"

extern int thin_get_sectors_per_block(char *name, uint32_t *result);
extern int thin_get_lba_status(char *name, uint64_t index, uint64_t len, uint8_t *result);

#ifdef SUPPORT_TP
static void __qnap_sbc_build_provisioning_group_desc(struct se_device *se_dev, 
	u8 *buf);
#endif

static sense_reason_t __qnap_sbc_iblock_fast_zero(
	struct se_cmd *se_cmd
	)
{
	struct se_device *se_dev = se_cmd->se_dev;
	struct iblock_dev *ibd = se_dev->transport->get_dev(se_dev);
	struct block_device *bd = ibd->ibd_bd;
	sector_t sectors = sbc_get_write_same_sectors(se_cmd);
	sector_t block_lba = se_cmd->t_task_lba;
	u32 bs_order = ilog2(se_dev->dev_attrib.block_size);
	sector_t tmp_lba, tmp_range;
	int ret;

	/* The sector unit is 512 in block i/o layer of kernel, 
	 * so need to transfer it again */
	tmp_lba = ((block_lba << bs_order) >> 9);
	tmp_range = ((sectors << bs_order) >> 9);

	ret = qlib_blkdev_issue_special_discard(bd, tmp_lba, 
		tmp_range, GFP_KERNEL, 0);

	if (ret != 0) {
		pr_warn("%s: fail to call "
			"blkdev_issue_special_discard, ret: %d\n",
			__func__, ret);
#ifdef SUPPORT_TP
		if (ret == -ENOSPC) {
			pr_warn("%s: space was full\n", __func__);
			return TCM_SPACE_ALLOCATION_FAILED_WRITE_PROTECT;
		}
#endif
		return TCM_LOGICAL_UNIT_COMMUNICATION_FAILURE;
	}

	return TCM_NO_SENSE;
}


static int __qnap_sbc_fd_fast_zero(
	struct se_cmd *se_cmd
	)
{
	struct se_device *se_dev = se_cmd->se_dev;
	struct fd_dev *fd_dev = se_dev->transport->get_dev(se_dev);
	struct file *fd = fd_dev->fd_file;
	struct inode *inode = fd->f_mapping->host;	
	sector_t sectors = sbc_get_write_same_sectors(se_cmd);
	sector_t block_lba = se_cmd->t_task_lba;
	u32 bs_order = ilog2(se_dev->dev_attrib.block_size);

	ALIGN_DESC_BLK desc;
	GEN_RW_TASK w_task;
	int ret, i;
	u64 alloc_bytes = (1 << 20); /* default to allocate 1mb data */
	u32 aligned_size = (se_dev->dev_dr.pool_blk_kb << 10);

	if (!S_ISBLK(inode->i_mode)) {
		pr_err("%s: not support fast-zero in file backend dev\n");
		return TCM_UNSUPPORTED_SCSI_OPCODE;
	}

	qnap_transport_create_aligned_range_desc((void *)&desc, block_lba, 
		sectors, bs_order, aligned_size);

	memset((void *)&w_task, 0, sizeof(GEN_RW_TASK));

	ret = qnap_transport_alloc_sg_list(&alloc_bytes, &w_task.sg_list, 
			&w_task.sg_nents);

	if (ret != 0) {
		if (ret == -ENOMEM)
			return TCM_OUT_OF_RESOURCES;

		return TCM_LOGICAL_UNIT_COMMUNICATION_FAILURE;
	}

	if (!desc.aligned) {
		ret = qnap_transport_loop_do_f_rw(se_dev, 
			(void *)&w_task, alloc_bytes, desc.m.lba, desc.m.nr_blks);
		if (ret == 0)
			ret = TCM_NO_SENSE;
		else {
#ifdef SUPPORT_TP
			if (qlib_thin_lun(&se_dev->dev_dr) && (ret == -ENOSPC))
			{
				pr_warn_ratelimited("%s: space was full for "
					"(!desc.is_aligned) case\n", __func__);
				ret = TCM_SPACE_ALLOCATION_FAILED_WRITE_PROTECT;
				goto _EXIT_;
			}
#endif
			ret = TCM_LOGICAL_UNIT_COMMUNICATION_FAILURE;
		}
		goto _EXIT_;
	} 

	/* case for we have alignd block at least
	 * we do fast zero first to avoid if there is no any avaiable blk now
	 * but need to write data to new blk
	 *
	 *
	 * (0) |--------------|--ws range---|-----| (max lba)
	 *
	 *     |----------------------| (physical max)
	 */

	/* step1: flush and truncate page first */
	ret = qlib_fd_flush_and_truncate_cache(fd, desc.m.lba, desc.m.nr_blks,
		bs_order, true, qlib_thin_lun(&se_dev->dev_dr));

	if (ret != 0) {
#ifdef SUPPORT_TP
		if (qlib_thin_lun(&se_dev->dev_dr) && (ret == -ENOSPC)) {
			pr_warn_ratelimited("%s: space was full after "
				"flush / truncate cache\n", __func__);
			ret = TCM_SPACE_ALLOCATION_FAILED_WRITE_PROTECT;
			goto _EXIT_;
		}
#endif
		ret = TCM_LOGICAL_UNIT_COMMUNICATION_FAILURE;
		goto _EXIT_;
	}

	/* step2: do fast zero here
	 * try conver the (lba,nolb) again cause of the block size
	 * for linux block layer is 512b but upper lun block size may
	 * be 4096b ... */
	block_lba = ((desc.m.lba << bs_order) >> 9);
	sectors = ((desc.m.nr_blks << bs_order) >> 9);

	pr_debug("special discard lba:0x%llx\n", (unsigned long long)desc.m.lba);
	pr_debug("speacial blks:0x%llx\n", (unsigned long long)desc.m.nr_blks);

	ret = qlib_blkdev_issue_special_discard(inode->i_bdev, block_lba, 
		sectors, GFP_KERNEL, 0);

	if (ret != 0) {
#ifdef SUPPORT_TP
		if (qlib_thin_lun(&se_dev->dev_dr)) {
			/* try check real status again ... */
			int __ret;

			__ret = qlib_fd_check_thin_io_get_nospc(&se_dev->dev_dr, 
				fd, se_cmd->t_task_cdb,	(desc.m.lba << bs_order), 
				(desc.m.nr_blks << bs_order), false);

			if (__ret == -ENOSPC) {
				pr_warn_ratelimited("%s: space was full\n", __func__);
				ret = TCM_SPACE_ALLOCATION_FAILED_WRITE_PROTECT;
				goto _EXIT_;
			}
		}	
#endif
		pr_warn_ratelimited("%s: fail to call blkdev_issue_special_discard, "
			"ret: %d\n", __func__, ret);

		ret = TCM_LOGICAL_UNIT_COMMUNICATION_FAILURE;
		goto _EXIT_;
	}

	/* step3: handle the non-aligned part */
	for (i = 0; i < MAX_ALIGN_DESC_HT_BLK; i++) {
		if (!desc.ht[i].nr_blks)
			continue;

		pr_debug("ht[%d], lba:0x%llx, blks:0x%llx\n",
			i, (unsigned long long)desc.ht[i].lba, 
			(unsigned long long)desc.ht[i].nr_blks);

		ret = qnap_transport_loop_do_f_rw(se_dev, (void *)&w_task, 
				alloc_bytes, desc.ht[i].lba, desc.ht[i].nr_blks);

		if (ret != 0) {
#ifdef SUPPORT_TP
			if (qlib_thin_lun(&se_dev->dev_dr) && (ret == -ENOSPC)) {
				pr_warn_ratelimited("%s: space was full for "
					"aligned case\n", __func__);
				ret = TCM_SPACE_ALLOCATION_FAILED_WRITE_PROTECT;
				goto _EXIT_;
			}
#endif
			ret = TCM_LOGICAL_UNIT_COMMUNICATION_FAILURE;
			goto _EXIT_;
		}
	}

	ret = TCM_NO_SENSE;
_EXIT_:
	qnap_transport_free_sg_list(w_task.sg_list, w_task.sg_nents);
	return ret;
}


sense_reason_t qnap_sbc_write_same_fast_zero(
	struct se_cmd *se_cmd
	)
{
	int ret;
	SUBSYSTEM_TYPE type;

	ret = qnap_transport_get_subsys_dev_type(se_cmd->se_dev, &type);
	if (ret != 0)
		return TCM_LOGICAL_UNIT_COMMUNICATION_FAILURE;

	if (type == SUBSYSTEM_FILE)
		return __qnap_sbc_fd_fast_zero(se_cmd);
	else if (type == SUBSYSTEM_BLOCK)
		return __qnap_sbc_iblock_fast_zero(se_cmd);

	return TCM_LOGICAL_UNIT_COMMUNICATION_FAILURE; 	 
 }
 EXPORT_SYMBOL(qnap_sbc_write_same_fast_zero);

#ifdef SUPPORT_TP
void *__qnap_get_fbdisk_file(
	void *fb_dev, 
	sector_t lba, 
	u32 *index
	)
{
	u32 i = 0;
	struct fbdisk_device *fbd = (struct fbdisk_device *)fb_dev; 
	struct fbdisk_file *fb_file = NULL;

	if ((fbd == NULL) ||(index == NULL))
		return NULL;

	for (i = 0; i < (fbd->fb_file_num); i++){
		fb_file = &fbd->fb_backing_files_ary[i];
		if ((lba >= fb_file->fb_start_byte) && (lba <= fb_file->fb_end_byte))
			break;
	}

	if (fb_file)
		*index = i;

	return (void *)fb_file;
}

static int __qnap_get_file_map(
	u32 blk_size,
	struct inode *inode,
	sector_t lba, 
	u32 *desc_count, 
	u8 *desc_buf
	)
{
/* for regular file, we get 1mb (1 ^ 20) len for each lba descriptor */
#define SIZE_ORDER	20

	struct fiemap_extent *file_ext = NULL;
	struct fiemap_extent_info file_info;
	u32 count = *desc_count, nr_blks, total_blks = 0;
	u32 idx = 0, fe_idx = 0, real_count = 0, bs_order = ilog2(blk_size);
	loff_t pos, len, tmp_len;
	sector_t curr_lba;
	int ret, is_not_map, found_map = 0;
	LBA_STATUS_DESC *lba_stats_desc = (LBA_STATUS_DESC *)desc_buf;

	if (!inode->i_op->fiemap){
		ret = -EOPNOTSUPP;
		goto _EXIT_;
	}

	pos = ((loff_t)lba << bs_order);
	tmp_len = len = ((loff_t)count << SIZE_ORDER);

	pr_debug("%s: (before call fiemap_check_ranges) pos:0x%llx, "
		"len:0x%llx\n", __func__, (unsigned long long)pos,
		(unsigned long long)len);

	/* please refer the fiemap_check_ranges() */
	ret = fiemap_check_ranges(inode->i_sb, pos, len, &tmp_len);
	if (ret != 0)
		goto _EXIT_;

	len = tmp_len;

	/* The final count / len may be smaller than original ones
	 * so to calculate them again */
	count = (len >> SIZE_ORDER);
	len = ((loff_t)count << SIZE_ORDER);

	pr_debug("%s, (after call fiemap_check_ranges) pos:0x%llx, "
		"count:0x%llx, len:0x%llx\n", __func__, 
		(unsigned long long)pos, (unsigned long long)count,
		(unsigned long long)len);

	file_ext = kzalloc((count * sizeof(struct fiemap_extent)), 
			GFP_KERNEL);
	if (!file_ext){
		ret = -ENOMEM;
		goto _EXIT_;
	}

	file_info.fi_flags = FIEMAP_FLAG_SYNC;;
	file_info.fi_extents_max = count;
	file_info.fi_extents_mapped = 0;
	file_info.fi_extents_start = file_ext;

	if (file_info.fi_flags & FIEMAP_FLAG_SYNC)
		filemap_write_and_wait(inode->i_mapping);

	ret = inode->i_op->fiemap(inode, &file_info, pos, len);
	if (ret != 0) {
		pr_err("%s: fail exec to i_op->fiemap, ret:%d\n", __func__, ret);
		goto _EXIT_;		
	}

	if (unlikely(!file_info.fi_extents_mapped)){
		pr_debug("%s: not found any mapped extent\n", __func__);
		goto _NOT_FOUND_MAP_;
	}

	pr_debug("%s: mapped extent count:%d\n", __func__, 
		file_info.fi_extents_mapped);

	/* (1) the lba status desc count may be larger than fi_extents_mapped
	 * (2) we need to take care the gap (deallocated) case
	 *
	 * i.e:
	 * If want to get status of lba:0x123 (off:0x24600) but the mapping was
	 * started from lba:0x180 (off:0x30000). Hence, the lba status 
	 * descriptor will be
	 *
	 * desc[0] - 0x123 ~ 0x17f (deallocated)
	 * desc[1] - 0x180 ~ 0xYYY (mapped)
	 *
	 * (3) if possible, we may prepare one descriptor at the tail
	 */
	idx = 0;
	real_count = 0;

	for (fe_idx = 0; fe_idx < file_info.fi_extents_mapped; fe_idx++){

		pr_debug("idx:%d, file_ext_idx:%d\n",idx, fe_idx);
		pr_debug("file_info.fe_logical:0x%llx\n", 
			(unsigned long long)file_ext[fe_idx].fe_logical);
		pr_debug("file_info.fe_physical:0x%llx\n", 
			(unsigned long long)file_ext[fe_idx].fe_physical);
		pr_debug("file_info.fe_length:0x%llx\n", 
			(unsigned long long)file_ext[fe_idx].fe_length);
		pr_debug("file_info.fe_flags:0x%x\n", file_ext[fe_idx].fe_flags);

		if (likely(file_ext[fe_idx].fe_logical == pos))
			found_map = 1;
		else {
			/* the fs block size is 4kb, so the pos may not be 
			 * aligned by fe_logical value. Just for 1st ext info
			 * i.e.
			 * pos: 0x896c00
			 * fe_logical: 0x896000
			 */
			if (fe_idx == 0)
				found_map = 1;
			else
				found_map = 0;
		}

_PREPARE_:
		if (found_map){
			found_map = 0;
			is_not_map = 0;
			curr_lba = (file_ext[fe_idx].fe_logical >> bs_order);
			nr_blks = (file_ext[fe_idx].fe_length >> bs_order);
	
			/* next pos */
			pos = file_ext[fe_idx].fe_logical + \
					file_ext[fe_idx].fe_length;
		} else {
			found_map = 1;
			is_not_map = 1;
			curr_lba = (pos >> bs_order);
			nr_blks = ((file_ext[fe_idx].fe_logical - pos) >> bs_order);
	
			/* next pos */
			pos = file_ext[fe_idx].fe_logical;
		}
	
		put_unaligned_be64((u64)curr_lba, &lba_stats_desc[idx].lba[0]);
		put_unaligned_be32(nr_blks, &lba_stats_desc[idx].nr_blks[0]);
		lba_stats_desc[idx].provisioning_status |= is_not_map;
	
		total_blks += nr_blks;
		real_count++;
	
		if (real_count == count)
			break;

		if (found_map){
			/* go to next desc pos */
			idx++;
			goto _PREPARE_;
		}

		/* go to next desc pos */
		idx++;
	
		/* current extent may NOT be last one ... */
		if (file_ext[fe_idx].fe_flags & FIEMAP_EXTENT_LAST)
			break;

		/* break the loop if next map ext info is invalid ... */
		if (file_ext[fe_idx + 1].fe_length == 0)
			break;
	
	}

_NOT_FOUND_MAP_:
	if (!real_count){
		/* if not found any map, to report status to all deallocated */
		idx = 0;
		real_count = 1;
		curr_lba = lba;
		nr_blks = ((count << SIZE_ORDER) >> bs_order);

		put_unaligned_be64((u64)curr_lba, &lba_stats_desc[idx].lba[0]);
		put_unaligned_be32(nr_blks, &lba_stats_desc[idx].nr_blks[0]);
		lba_stats_desc[idx].provisioning_status |= 0x1;
	}

	pr_debug("%s: real_count:%d\n", __func__, real_count);

	*desc_count = real_count;
	ret = 0;

_EXIT_:
	if (file_ext)
		kfree(file_ext);

	return ret;

}

static sense_reason_t __qnap_sbc_get_lba_status_pre_check(
	struct se_cmd *se_cmd
	)
{	
	/* minimun value should be 24 = (16 bytes descriptor + 8 bytes) */
	if (get_unaligned_be32(&se_cmd->t_task_cdb[10]) < 24 )	
		return TCM_PARAMETER_LIST_LENGTH_ERROR;

	if (get_unaligned_be64(&se_cmd->t_task_cdb[2]) >
		se_cmd->se_dev->transport->get_blocks(se_cmd->se_dev))	
		return TCM_ADDRESS_OUT_OF_RANGE;

	return TCM_NO_SENSE;
}

static sense_reason_t __qnap_sbc_fd_file_backend_get_lba_status(
	struct se_cmd *se_cmd
	)
{
	return TCM_LOGICAL_UNIT_COMMUNICATION_FAILURE;
}

static sense_reason_t __qnap_sbc_fd_blk_backend_get_lba_status(
	struct se_cmd *se_cmd
	)
{
	struct se_device *se_dev = se_cmd->se_dev;
	struct fd_dev *fd_dev = qnap_transport_get_fd_dev(se_dev);
	struct file *file = fd_dev->fd_file;
	struct inode *inode = file->f_mapping->host;
	struct address_space *mapping = inode->i_mapping;
	u8 *pro_status = NULL, *buf = NULL;
	char lvname[256];
	u32 nr_blks, sector_per_dm_block, off = 8;
	u32 bs_order = ilog2(se_dev->dev_attrib.block_size);
	sector_t start_lba, lba_512b;
	u64 l_index, len;
	u32 para_data_length, desc_count, idx;
	loff_t first_page = 0, last_page = 0, p_start = 0, p_len = 0;
	loff_t first_page_off = 0, last_page_off = 0;
	sense_reason_t reason;
	int ret;

	start_lba = get_unaligned_be64(&se_cmd->t_task_cdb[2]);
	para_data_length = get_unaligned_be32(&se_cmd->t_task_cdb[10]);
	desc_count = ((para_data_length - 8) >> 4);

	if (!S_ISBLK(inode->i_mode)){
		reason = TCM_LOGICAL_UNIT_COMMUNICATION_FAILURE;
		goto _EXIT_;
	}

	/* for block-based lun, se_dev_udev_path will store the
	 * lv dev name which maps to iscsi lun
	 */		
	if (!strcmp(se_dev->udev_path, "")) {
		reason = TCM_INVALID_PARAMETER_LIST;
		goto _EXIT_;
	}
	strcpy(lvname, se_dev->udev_path);

	buf = transport_kmap_data_sg(se_cmd);
	if (!buf) {
		reason = TCM_INVALID_PARAMETER_LIST;
		goto _EXIT_;
	}

	pro_status = kzalloc(desc_count, GFP_KERNEL);
	if (!pro_status) {
		reason = TCM_OUT_OF_RESOURCES;
		goto _EXIT_;
	}

	/* get how many blocks (512b) per one dm thin data block */
	ret = thin_get_sectors_per_block(lvname, &sector_per_dm_block);
	if (ret != 0){
		pr_err("fail to call thin_get_sectors_per_block\n");
		reason = TCM_INVALID_PARAMETER_LIST;
		goto _EXIT_;
	}
	pr_debug("sector_per_dm_block (512b):%d\n", sector_per_dm_block);

	/* to flush cache first */
	p_start = (loff_t)(start_lba << bs_order);
	p_len	= (loff_t)(((loff_t)sector_per_dm_block << 9) *desc_count);

	first_page = (p_start >> PAGE_CACHE_SHIFT);
	last_page = ((p_start + p_len - 1) >> PAGE_CACHE_SHIFT);
	first_page_off = first_page << PAGE_CACHE_SHIFT;
	last_page_off = (last_page << PAGE_CACHE_SHIFT) + (PAGE_CACHE_SIZE - 1);

	pr_debug("p_start:0x%llx, p_len:0x%llx, first_page:0x%llx, "
		"last_page:0x%llx, first_page_off:0x%llx, "
		"last_page_off:0x%llx\n", (unsigned long long)p_start, 
		(unsigned long long)p_len, (unsigned long long)first_page, 
		(unsigned long long)last_page, 
		(unsigned long long)first_page_off, 
		(unsigned long long)last_page_off);

	if (mapping->nrpages && mapping_tagged(mapping, PAGECACHE_TAG_DIRTY)){
		ret = filemap_write_and_wait_range(mapping, 
			first_page_off, last_page_off);
		if (unlikely(ret)) {
			pr_err("%s: fail to exec "
				"filemap_write_and_wait_range(), ret:%d\n", 
				__func__, ret);
		}
	}
	/* everything to use 512b unit for linux block layer, we also need to
	 * consider the case about 4KB logical block size 
	 */
	lba_512b = ((start_lba << bs_order) >> 9);
	l_index = div_u64((u64)lba_512b, sector_per_dm_block);
	nr_blks = ((sector_per_dm_block << 9) >> bs_order);

	pr_debug("lba_512b:0x%llx, l_index:0x%llx, nr_blks:0x%llx\n",
		(unsigned long long)lba_512b, (unsigned long long)l_index,
		(unsigned long long)nr_blks);

	ret = thin_get_lba_status(lvname, l_index, desc_count, pro_status);
	if (ret != 0){
		pr_err("fail to call thin_get_lba_status\n");
		reason = TCM_INVALID_PARAMETER_LIST;
		goto _EXIT_;
	}

	for (idx = 0; idx < desc_count; idx++){
		/* STARTING LOGICAL BLOCK ADDRESS (use original lba value) */
		buf[off + 0] = (start_lba >> 56) & 0xff;
		buf[off + 1] = (start_lba >> 48) & 0xff;
		buf[off + 2] = (start_lba >> 40) & 0xff;
		buf[off + 3] = (start_lba >> 32) & 0xff;
		buf[off + 4] = (start_lba >> 24) & 0xff;
		buf[off + 5] = (start_lba >> 16) & 0xff;
		buf[off + 6] = (start_lba >> 8) & 0xff;
		buf[off + 7] = start_lba & 0xff;
		off += 8;

		/* NUMBER OF LOGICAL BLOCKS */
		buf[off + 0] = (nr_blks >> 24) & 0xff;
		buf[off + 1] = (nr_blks >> 16) & 0xff;
		buf[off + 2] = (nr_blks >> 8) & 0xff;
		buf[off + 3] = nr_blks & 0xff;
		off += 4;

		/* PROVISIONING STATUS 
		 * pro_status: 0->mapped, 1->unmapped
		 */
		buf[off] = pro_status[idx];
		off += 4;

		start_lba  += nr_blks;
	}

	/* to update PARAMETER DATA LENGTH finally */
	len = ((desc_count << 4) + 4);
	buf[0] = (len >> 24) & 0xff;
	buf[1] = (len >> 16) & 0xff;
	buf[2] = (len >> 8) & 0xff;
	buf[3] = len & 0xff;

	reason = TCM_NO_SENSE;

_EXIT_:
	if (pro_status)
		kfree(pro_status);

	if (buf)
		transport_kunmap_data_sg(se_cmd);
	
	if (reason == TCM_NO_SENSE)
		target_complete_cmd(se_cmd, GOOD);

	return reason;

}

static sense_reason_t __qnap_sbc_fd_get_lba_status(
	struct se_cmd *se_cmd
	)
{
	struct se_device *se_dev = se_cmd->se_dev;
	struct fd_dev *fd_dev = qnap_transport_get_fd_dev(se_dev);
	struct file *file = fd_dev->fd_file;
	struct inode *inode = file->f_mapping->host;
	sense_reason_t reason;

	reason = __qnap_sbc_get_lba_status_pre_check(se_cmd);
	if (reason != TCM_NO_SENSE)
		return reason;

	if (S_ISBLK(inode->i_mode))
		return __qnap_sbc_fd_blk_backend_get_lba_status(se_cmd);

	return __qnap_sbc_fd_file_backend_get_lba_status(se_cmd);

}

static sense_reason_t __qnap_sbc_iblock_get_lba_status(
	struct se_cmd *se_cmd
	)
{
#define	MAX_DESC_COUNTS		64

	struct se_device *se_dev = se_cmd->se_dev;
	struct iblock_dev *ibd = qnap_transport_get_iblock_dev(se_dev);
	struct block_device *bd = ibd->ibd_bd;
	struct fbdisk_device *fb_dev = NULL;
	struct fbdisk_file *fb_file = NULL;
	unsigned char *buf = NULL;
	LBA_STATUS_DESC *desc = NULL;
	sector_t start_lba;
	u32 para_data_length, desc_count, idx;
	sense_reason_t reason;
	int ret;

	/* currently, we only handle fbdisk device */
	if (qnap_transport_is_fbdisk_dev(bd) != 0)
		return TCM_LOGICAL_UNIT_COMMUNICATION_FAILURE;

	buf = transport_kmap_data_sg(se_cmd);
	if (!buf) {
		reason = TCM_INVALID_PARAMETER_LIST;
		goto EXIT;
	}

	start_lba = get_unaligned_be64(&se_cmd->t_task_cdb[2]);
	para_data_length = get_unaligned_be32(&se_cmd->t_task_cdb[10]);
	desc_count = ((para_data_length - 8) >> 4);

	/* In order to reduce the memory allocation failure, we try limit
	 * the descriptor count here. It's ok
	 * sbc3r35j, p114
	 * In response to a GET LBA STATUS command, the device serer may
	 * send less data to Data-In buffer than is specified by allocation len
	 */
	if (desc_count > MAX_DESC_COUNTS)
		desc_count = MAX_DESC_COUNTS;

	/* TODO
	 * it shall be better to use ioctl to get lba map status directly
	 * than to use this function 
	 */
	fb_dev = (struct fbdisk_device *)bd->bd_disk->private_data;
	fb_file = (struct fbdisk_file *)__qnap_get_fbdisk_file(
			(void *)fb_dev, start_lba, &idx);

	if (!fb_file){
		reason = TCM_LOGICAL_UNIT_COMMUNICATION_FAILURE;
		goto EXIT;
	}

	desc = kzalloc((desc_count * sizeof(LBA_STATUS_DESC)), GFP_KERNEL);
	if (!desc){
		reason = TCM_OUT_OF_RESOURCES;
		goto EXIT;
	}

	/* return code for transport_get_file_lba_map_status will be following lists
	 * 0,
	 * or -ENODEV,
	 * or -EOPNOTSUPP,
	 * or -EFBIG,
	 * or -ENOMEM,
	 * or others return from inode->i_op->fiemap
	 */
	ret = blkdev_issue_flush(bd, GFP_KERNEL, NULL);
	if (unlikely(ret))
		pr_err("%s: fail to exec blkdev_issue_flush, ret:%d\n", 
			__func__, ret);


	ret = __qnap_get_file_map(se_dev->dev_attrib.block_size, 
		fb_file->fb_backing_file->f_mapping->host, start_lba, 
		&desc_count, (u8 *)desc
		);

	if (ret != 0) {
		if (ret == -ENODEV || ret == -EOPNOTSUPP)
			reason = TCM_UNSUPPORTED_SCSI_OPCODE;
		else if (ret == -ENOMEM)
			reason = TCM_OUT_OF_RESOURCES;
		else if (ret == -EFBIG)
			reason = TCM_INVALID_CDB_FIELD;
		else
			reason = TCM_INVALID_PARAMETER_LIST;
	} else {
		/* update the lba status descriptor */
		memcpy(&buf[8], (u8 *)desc,
			(desc_count* sizeof(LBA_STATUS_DESC)));

		/* to update PARAMETER DATA LENGTH finally */
		desc_count = ((desc_count << 4) + 4);
		put_unaligned_be32(desc_count, &buf[0]);
	}

	if (ret == 0)
		reason = TCM_NO_SENSE;
EXIT:
	if (desc)
		kfree(desc);

	if (buf)
		transport_kunmap_data_sg(se_cmd);
	
	if (reason == TCM_NO_SENSE)
		target_complete_cmd(se_cmd, GOOD);

	return reason;
}

sense_reason_t qnap_sbc_get_lba_status(
	struct se_cmd *se_cmd
	)
{
	int ret;
	SUBSYSTEM_TYPE type;
	sense_reason_t reason;

	reason = __qnap_sbc_get_lba_status_pre_check(se_cmd);
	if (reason != TCM_NO_SENSE)
		return reason;

	ret = qnap_transport_get_subsys_dev_type(se_cmd->se_dev, &type);
	if (ret != 0)
		return TCM_LOGICAL_UNIT_COMMUNICATION_FAILURE;

	if (type == SUBSYSTEM_FILE)
		return __qnap_sbc_fd_get_lba_status(se_cmd);
	else if (type == SUBSYSTEM_BLOCK)
		return __qnap_sbc_iblock_get_lba_status(se_cmd);

	return TCM_LOGICAL_UNIT_COMMUNICATION_FAILURE; 	 

}
EXPORT_SYMBOL(qnap_sbc_get_lba_status);
#endif

static sense_reason_t __qnap_sbc_fd_blk_backend_unmap(
	struct se_cmd *se_cmd,
	sector_t lba, 
	sector_t nolb
	)
{
	struct se_device *se_dev = se_cmd->se_dev;
	struct fd_dev *fd_dev = qnap_transport_get_fd_dev(se_cmd->se_dev);
	struct file *file = fd_dev->fd_file;
	struct inode *inode = file->f_mapping->host;
	struct block_device *bd = NULL;
	u32 bs_order = ilog2(se_dev->dev_attrib.block_size);
	u64 alloc_bytes = D4_SG_LIST_IO_ALLOC_SIZE;
	u32 i, aligned_size = (se_dev->dev_dr.pool_blk_kb << 10);
	ALIGN_DESC_BLK desc;
	GEN_RW_TASK w_task;
	int ret;

	/* not handle this case */
	if (!S_ISBLK(inode->i_mode))
		return TCM_LOGICAL_UNIT_COMMUNICATION_FAILURE;

	bd = inode->i_bdev;

	qnap_transport_create_aligned_range_desc((void *)&desc, lba, nolb, 
		bs_order, aligned_size);

	memset((void *)&w_task, 0, sizeof(GEN_RW_TASK));

	ret = qnap_transport_alloc_sg_list(&alloc_bytes, &w_task.sg_list, 
			&w_task.sg_nents);

	if (ret != 0) {
		if (ret == -ENOMEM)
			return TCM_OUT_OF_RESOURCES;
		return TCM_LOGICAL_UNIT_COMMUNICATION_FAILURE;
	}

	/* we didn't get any aligned range */
	if (!desc.aligned) {
		ret = qnap_transport_loop_do_f_rw(se_cmd->se_dev, 
			(void *)&w_task, alloc_bytes, desc.m.lba, desc.m.nr_blks);
		if (ret == 0)
			ret = TCM_NO_SENSE;
		else {
#ifdef SUPPORT_TP
			if (ret == -ENOSPC) {
				pr_warn("%s: space was full for "
					"(!desc.is_aligned) case\n", __func__);
				ret = TCM_SPACE_ALLOCATION_FAILED_WRITE_PROTECT;
				goto _EXIT_;
			}
#endif
			ret = TCM_LOGICAL_UNIT_COMMUNICATION_FAILURE;
		}
		goto _EXIT_;
	} 

	/* we did get aligned range at least
	 * we do unmap first to avoid if there is no any avaiable blk now
 	 * but need to write data to new blk
	 *
	 *
	 * (0) |--------------|--unmap range---|-----| (max lba)
	 *
	 *     |----------------------| (physical max)
	 */

	/* step1: flush and truncate page first */
	ret = qlib_fd_flush_and_truncate_cache(file, desc.m.lba, desc.m.nr_blks,
		bs_order, true, qlib_thin_lun(&se_dev->dev_dr));

	if (ret != 0) {
#ifdef SUPPORT_TP
		if (ret == -ENOSPC) {
			pr_warn("%s: space was full after "
				"flush / truncate cache\n", __func__);
			ret = TCM_SPACE_ALLOCATION_FAILED_WRITE_PROTECT;
			goto _EXIT_;
		}
#endif
		ret = TCM_LOGICAL_UNIT_COMMUNICATION_FAILURE;
		goto _EXIT_;
	}

	/* step2: do unmap here for aligned range
	 * try conver the (lba,nolb) again cause of the block size
	 * for linux block layer is 512b but upper lun block size may
	 * be 4096b ... */
	lba = ((desc.m.lba << bs_order) >> 9);
	nolb = ((desc.m.nr_blks << bs_order) >> 9);

	pr_debug("%s: discard lba:0x%llx, discard blks:0x%llx\n", 
		__func__, (unsigned long long)desc.m.lba,
		(unsigned long long)desc.m.nr_blks);

	ret = qnap_transport_blkdev_issue_discard(se_cmd, bd, lba, 
			nolb, GFP_KERNEL, 0);

	if (ret != 0) {
		pr_warn("%s: fail from qnap_transport_blkdev_issue_discard, "
			"ret: %d\n", __func__, ret);
		ret = TCM_LOGICAL_UNIT_COMMUNICATION_FAILURE;
		goto _EXIT_;
	}

	if (test_bit(QNAP_CMD_T_RELEASE_FROM_CONN, &se_cmd->cmd_dr.cmd_t_state)
		|| qnap_transport_is_dropped_by_tmr(se_cmd)
	)
	{
		ret = TCM_NO_SENSE;
		goto _EXIT_;
	}

	/* step3: handle the non-aligned part */
	for (i = 0; i < MAX_ALIGN_DESC_HT_BLK; i++) {
		if (!desc.ht[i].nr_blks)
			continue;

		pr_debug("ht[%d], lba:0x%llx, blks:0x%llx\n",
			i, (unsigned long long)desc.ht[i].lba, 
			(unsigned long long)desc.ht[i].nr_blks);

		ret = qnap_transport_loop_do_f_rw(se_cmd->se_dev, (void *)&w_task, 
				alloc_bytes, desc.ht[i].lba, desc.ht[i].nr_blks);

		if (ret != 0) {
#ifdef SUPPORT_TP
			if (ret == -ENOSPC) {
				pr_warn("%s: space was full for aligned case\n",
					__func__);
				ret = TCM_SPACE_ALLOCATION_FAILED_WRITE_PROTECT;
				goto _EXIT_;
			}
#endif
			ret = TCM_LOGICAL_UNIT_COMMUNICATION_FAILURE;
			goto _EXIT_;
		}
	}

	ret = TCM_NO_SENSE;
_EXIT_:
	qnap_transport_free_sg_list(w_task.sg_list, w_task.sg_nents);
	return ret;
}

static sense_reason_t __qnap_sbc_iblock_blk_backend_unmap(
	struct se_cmd *se_cmd,
	sector_t lba, 
	sector_t nolb
	)
{
	struct iblock_dev *ibd = qnap_transport_get_iblock_dev(se_cmd->se_dev);
	struct block_device *bd = ibd->ibd_bd;

	int ret;
	u32 bs_order = ilog2(se_cmd->se_dev->dev_attrib.block_size);

	/* The kernel block layer is 512b unit, so to convert 
	 * the lba, nolb again if now is 4KB sector size */
	lba = ((lba << bs_order) >> 9);
	nolb = ((nolb << bs_order) >> 9);

	ret = qnap_transport_blkdev_issue_discard(se_cmd, bd, lba, 
			nolb, GFP_KERNEL, 0);
	if (ret < 0) {
		pr_err("%s: fail from qnap_transport_blkdev_issue_discard(), "
			"ret: %d\n", __func__, ret);


		if (ret == -ENOMEM)
			return TCM_OUT_OF_RESOURCES;

#ifdef SUPPORT_TP
		if (ret == -ENOSPC) {
			pr_warn("%s: space was full\n", __func__);
			return TCM_SPACE_ALLOCATION_FAILED_WRITE_PROTECT;
		}
#endif
		return TCM_LOGICAL_UNIT_COMMUNICATION_FAILURE;
	}

	return TCM_NO_SENSE;
}

sense_reason_t qnap_sbc_unmap(
	struct se_cmd *se_cmd,
	sector_t lba, 
	sector_t nolb
	)
{
	int ret;
	SUBSYSTEM_TYPE type;
	sense_reason_t reason;

	ret = qnap_transport_get_subsys_dev_type(se_cmd->se_dev, &type);
	if (ret != 0)
		return TCM_LOGICAL_UNIT_COMMUNICATION_FAILURE;

	if (type == SUBSYSTEM_FILE)
		return __qnap_sbc_fd_blk_backend_unmap(se_cmd, lba, nolb);
	else if (type == SUBSYSTEM_BLOCK)
		return __qnap_sbc_iblock_blk_backend_unmap(se_cmd, lba, nolb);

	return TCM_LOGICAL_UNIT_COMMUNICATION_FAILURE; 	 

}
EXPORT_SYMBOL(qnap_sbc_unmap);

unsigned int qnap_sbc_get_io_min(
	struct se_device *se_dev
	)
{
	/* for OPTIMAL TRANSFER LENGTH GRANULARITY in vpd 0xb0 */
	int bs_order = ilog2(se_dev->dev_attrib.block_size);

	/* hard coding to set 1MB */
	return ((MAX_TRANSFER_LEN_MB << 20) >> bs_order);
}
EXPORT_SYMBOL(qnap_sbc_get_io_min);

unsigned int qnap_sbc_get_io_opt(
	struct se_device *se_dev
	)
{
	/* for OPTIMAL TRANSFER LENGTH in vpd 0xb0 */
	int bs_order = ilog2(se_dev->dev_attrib.block_size);

	/* hard coding to set 1MB */
	return ((MAX_TRANSFER_LEN_MB << 20) >> bs_order);
}
EXPORT_SYMBOL(qnap_sbc_get_io_opt);

int qnap_sbc_get_threshold_exp(
	struct se_device *se_dev
	)
{
	/* we need this call cause of the lun capacity may be changed by expansion */
	unsigned long long tmp;
	unsigned long long total_blocks = 
		se_dev->transport->get_blocks(se_dev) + 1;
	int exp;

	if (total_blocks > 0x00000000ffffffffULL) {
		tmp = (total_blocks >> 32);
		exp = ilog2(tmp) + 1;
	}
	else {
		/* sbc3r35j, p289 
		 * THRESHOLD_EXPONENT shall be larger than 0, 0 means
		 * the logical unit doesn't support logical block provisioning
		 * threshold
		 */
		exp = 1;
	}

	return exp;
}
EXPORT_SYMBOL(qnap_sbc_get_threshold_exp);

#ifdef SUPPORT_TP
static void __qnap_sbc_build_provisioning_group_desc(
	struct se_device *se_dev,
	u8 *buf
	)
{
	struct qnap_se_dev_dr *dr = &se_dev->dev_dr;

	/* 1. pg_desc information starts from offset 8 of vpd 0xb2 
	 * 2. buf location was pointed to offset 8 already
	 */
	buf[0] |= 0x01;	// CODE SET == Binary
	buf[1] |= 0x00;	// ASSOCIATION == addressed logical unit: 0)b
	buf[1] |= 0x03;	// Identifier/Designator type == NAA identifier
	buf[3] = 0x10;	// Identifier/Designator length

	/* here the off = 4 and header len is 4 bytes
	 * (end location is byte7[bit7-4] ) 
	 */
	if(!strcmp(dr->dev_naa, "qnap"))
		qnap_transport_make_naa_6h_hdr_new_style(&buf[4]);
	else
		qnap_transport_make_naa_6h_hdr_old_style(&buf[4]);		

	/* start from byte7 again */
	spc_parse_naa_6h_vendor_specific(se_dev, &buf[7]);
	return;
}


int qnap_sbc_config_tp_on_evpd_b2(
	struct se_device *se_dev,
	unsigned char *buf
	)
{
	if (se_dev->dev_attrib.emulate_tpu 
	|| se_dev->dev_attrib.emulate_tpws
	)
	{
		if (qnap_transport_check_is_thin_lun(se_dev) != 1)
			return -ENODEV;

		/* only do this when it is thin lun */
		put_unaligned_be16(4 + PROVISIONING_GROUP_DESC_LEN, &buf[2]);
	
		/* The THRESHOLD EXPONENT field indicates the threshold set
		 * size in LBAs as a power of 2 (i.e., the threshold set size
		 * is equal to 2(threshold exponent)).
		 *
		 * The RESOURCE COUNT filed (unit is threshold set size = 
		 * 2 ^ THRESHOLD EXPONENT nr blks) in Logical Block Provisioning
		 * log page is 32bit only, so we need to adjust
		 * THRESHOLD EXPONENT field to suitable value
		 */
		buf[4] = (unsigned char)qnap_sbc_get_threshold_exp(se_dev);
		buf[5] |= 0x1;
	
		/*
		 * A TPU bit set to one indicates that the device server
		 * supports the UNMAP command (see 5.25). A TPU bit set
		 * to zero indicates that the device server does not
		 * support the UNMAP command.
		 */
		if (se_dev->dev_attrib.emulate_tpu != 0)
			buf[5] |= 0x80;
	
		/*
		 * A TPWS bit set to one indicates that the device server
		 * supports the use of the WRITE SAME (16) command (see 5.42)
		 * to unmap LBAs. A TPWS bit set to zero indicates that the
		 * device server does not support the use of the
		 * WRITE SAME (16) command to unmap LBAs.
		 */
		if (se_dev->dev_attrib.emulate_tpws != 0)
			buf[5] |= 0x40;
	
		/* LBPRZ bit should be the same setting as LBPRZ bit in
		 * Read Capacity 16 */
		buf[5] |= 0x04;
		buf[6] |= VPD_B2h_PROVISION_TYPE_TP;
	
		/*
		 * FIXED ME
		 *
		 * Here to report the PROVISIONING GROUP DESCRIPTOR
		 * information. The PROVISIONING GROUP DESCRIPTOR field
		 * contains a designation descriptor for the LBA
		 * mapping resources used by logical unit.
		 *
		 * The ASSOCIATION field should be set to 00b
		 * The DESIGNATOR TYPE field should be 01h
		 * (T10 vendor ID based) or 03h (NAA)
		 *
		 * NOTE: 
		 * This code depends on target_emulate_evpd_83(), 
		 * please take care it...
		 */
	
		/* SBC3R31, page 279 */ 		
		__qnap_sbc_build_provisioning_group_desc(se_dev, &buf[8]);
		return 0;
	}

	return -ENODEV;
}

int qnap_sbc_modesense_lbp(
	struct se_cmd *se_cmd, 
	u8 pc, 
	unsigned char *p
	)
{
	struct se_device *se_dev = se_cmd->se_dev;
	THRESHOLD_DESC_FORMAT *desc = NULL;
	unsigned long long total_blocks = 
		(se_dev->transport->get_blocks(se_dev) + 1);
	u16 off = 16, len = 0;
	u64 dividend;
	u32 threshold_count, threshold_exp;

	if ((se_cmd->data_length == 0) || (off > (u16)se_cmd->data_length))
		return 0;

	if (!se_dev->dev_attrib.tp_threshold_percent)
		return 0;

	dividend = (total_blocks * se_dev->dev_attrib.tp_threshold_percent);
	dividend = div_u64(dividend, 100);

	threshold_exp = qnap_sbc_get_threshold_exp(se_dev);
	threshold_count = (u32)div_u64(dividend, (1 << threshold_exp));

	p[0] = (0x1c | 0x40); /* set SPF bit (bit 6) to 1 */
	p[1] = 0x02;

	/* No changeable values for now */
	if (pc == 1)
		goto out;

	/* FIXED ME !! 
	 * set the SITUA (single initiator threshold unit attention) bit
	 */
	p[4] = 0x01;

	desc = (THRESHOLD_DESC_FORMAT *)&p[off];
	desc->threshold_arming = THRESHOLD_ARM_INC;
	desc->threshold_type = THRESHOLD_TYPE_SOFTWARE;
	desc->enabled = 1;

	/* should be less than 0100h */
	desc->threshold_resource = LBP_LOG_PARAMS_USED_LBA_MAP_RES_COUNT;

	desc->threshold_count[0] = (threshold_count >> 24) & 0xff;
	desc->threshold_count[1] = (threshold_count >> 16) & 0xff;
	desc->threshold_count[2] = (threshold_count >> 8) & 0xff;
	desc->threshold_count[3] = threshold_count  & 0xff;

out:
	len = (sizeof(THRESHOLD_DESC_FORMAT) + 12);
	put_unaligned_be16(len, &p[2]);
	return (4 + len);
}

#endif

