/*******************************************************************************
 * Filename:  target_core_iblock.c
 *
 * This file contains the Storage Engine  <-> Linux BlockIO transport
 * specific functions.
 *
 * (c) Copyright 2003-2013 Datera, Inc.
 *
 * Nicholas A. Bellinger <nab@kernel.org>
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
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 ******************************************************************************/

#include <linux/string.h>
#include <linux/parser.h>
#include <linux/timer.h>
#include <linux/fs.h>
#include <linux/blkdev.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/bio.h>
#include <linux/genhd.h>
#include <linux/file.h>
#include <linux/module.h>
#include <scsi/scsi_proto.h>
#include <asm/unaligned.h>
#include <target/target_core_base.h>
#include <target/target_core_backend.h>
#include <target/target_core_fabric.h>
#include "target_core_iblock.h"

#ifdef CONFIG_MACH_QNAPTS
#include "target_core_qtransport.h"
#include "target_core_qsbc.h"

static void __qnap_target_iblock_execute_sync_cache_work(struct work_struct *work);
static sense_reason_t qnap_target_iblock_execute_sync_cache(struct se_cmd *cmd);
#endif

#define IBLOCK_MAX_BIO_PER_TASK	 32	/* max # of bios to submit at a time */
#define IBLOCK_BIO_POOL_SIZE	128

#ifdef QNAP_SHARE_JOURNAL
extern int init_blkdev_journal(char *blkdev_name, char *lun_uuid);
extern int release_blkdev_journal(char *blkdev_name);
extern int blkdev_set_aops(struct block_device *bdev, unsigned long enable);
#endif

#ifdef CONFIG_MACH_QNAPTS 
static int blockio_cpumask=0xff;

extern int check_lun_threshold_for_each_device(void *data);
#endif

static inline struct iblock_dev *IBLOCK_DEV(struct se_device *dev)
{
	return container_of(dev, struct iblock_dev, dev);
}

#if defined(CONFIG_MACH_QNAPTS) && defined(CONFIG_QTS_CEPH)
struct request_queue *ibock_se_device_to_q(struct se_device *dev)
{
	struct iblock_dev *ib_dev = IBLOCK_DEV(dev);
	return bdev_get_queue(ib_dev->ibd_bd);
}
EXPORT_SYMBOL(ibock_se_device_to_q);
#endif

static int iblock_attach_hba(struct se_hba *hba, u32 host_id)
{
	pr_debug("CORE_HBA[%d] - TCM iBlock HBA Driver %s on"
		" Generic Target Core Stack %s\n", hba->hba_id,
		IBLOCK_VERSION, TARGET_CORE_VERSION);
	return 0;
}

static void iblock_detach_hba(struct se_hba *hba)
{
}

static struct se_device *iblock_alloc_device(struct se_hba *hba, const char *name)
{
	struct iblock_dev *ib_dev = NULL;

	ib_dev = kzalloc(sizeof(struct iblock_dev), GFP_KERNEL);
	if (!ib_dev) {
		pr_err("Unable to allocate struct iblock_dev\n");
		return NULL;
	}

	pr_debug( "IBLOCK: Allocated ib_dev for %s\n", name);

	return &ib_dev->dev;
}

static int iblock_configure_device(struct se_device *dev)
{
	struct iblock_dev *ib_dev = IBLOCK_DEV(dev);
	struct request_queue *q;
	struct block_device *bd = NULL;
	struct blk_integrity *bi;
	fmode_t mode;
	int ret = -ENOMEM;

	if (!(ib_dev->ibd_flags & IBDF_HAS_UDEV_PATH)) {
		pr_err("Missing udev_path= parameters for IBLOCK\n");
		return -EINVAL;
	}

	ib_dev->ibd_bio_set = bioset_create(IBLOCK_BIO_POOL_SIZE, 0);
	if (!ib_dev->ibd_bio_set) {
		pr_err("IBLOCK: Unable to create bioset\n");
		goto out;
	}

	pr_debug( "IBLOCK: Claiming struct block_device: %s\n",
			ib_dev->ibd_udev_path);

	mode = FMODE_READ|FMODE_EXCL;
	if (!ib_dev->ibd_readonly)
		mode |= FMODE_WRITE;

#ifdef CONFIG_MACH_QNAPTS

	/* snapshot lun cannot map into iSCSI target */
	fmode_t mode_all, tmp_mode;

	bd = lookup_bdev(ib_dev->ibd_udev_path);
	if (IS_ERR(bd)) {
		ret = PTR_ERR(bd);
		pr_err("IBLOCK: Fail to lookup block device by %s, "
			"PTR_ERR = %d.\n", ib_dev->ibd_udev_path, ret);
		goto out_free_bioset;
	}

	mode_all = (FMODE_WRITE|FMODE_READ|FMODE_EXCL);
	ret = blkdev_get(bd, mode_all, ib_dev);
	if (ret) {
		pr_err("IBLOCK: Fail to get block device, ret = %d.\n", ret);
		goto out_free_bioset;
	}

	/* reset the ib_dev->ibd_readonly */
	if (bdev_read_only(bd)) {
		/* if block device policy is read-only, to reset the
		 * ibd_readonly even if it is not read only
		 */
		tmp_mode = 0;
		ib_dev->ibd_readonly = 1;
	}
	else {
		/* not reset the ibd_readonly even if block device policy
		 * is not read-only. just keep what it is
		 */
		tmp_mode = FMODE_WRITE;
	}
	
	tmp_mode |= (FMODE_READ|FMODE_EXCL);

	pr_debug("IBLOCK: Succeed to lookup block device by %s "
		"with mode 0x%x\n", ib_dev->ibd_udev_path, mode);

	/* remember do this if you called blkdev_get() already */
	blkdev_put(bd, mode_all);
	mode = tmp_mode; 
#endif

	bd = blkdev_get_by_path(ib_dev->ibd_udev_path, mode, ib_dev);
	if (IS_ERR(bd)) {
		ret = PTR_ERR(bd);
		goto out_free_bioset;
	}
	ib_dev->ibd_bd = bd;

	q = bdev_get_queue(bd);

	dev->dev_attrib.hw_block_size = bdev_logical_block_size(bd);
#ifdef CONFIG_MACH_QNAPTS

	dev->dev_dr.se_dev_thread_cpumask = blockio_cpumask;

	/* check need to overwrite block size or not (i.e. 4kb sector size lun) */
	qnap_transport_config_dev_blk_sz(dev, &dev->dev_attrib.hw_block_size);

	if (!qnap_transport_is_fbdisk_dev(bd))
		dev->dev_dr.dev_type = QNAP_DT_IBLK_FBDISK;
	else
		dev->dev_dr.dev_type = QNAP_DT_IBLK_BLK;
#endif

	dev->dev_attrib.hw_max_sectors = queue_max_hw_sectors(q);
	dev->dev_attrib.hw_queue_depth = q->nr_requests;

	/*
	 * Check if the underlying struct block_device request_queue supports
	 * the QUEUE_FLAG_DISCARD bit for UNMAP/WRITE_SAME in SCSI + TRIM
	 * in ATA and we need to set TPE=1
	 */
	if (blk_queue_discard(q)) {
		dev->dev_attrib.max_unmap_lba_count =
				q->limits.max_discard_sectors;

		/*
		 * Currently hardcoded to 1 in Linux/SCSI code..
		 */
		dev->dev_attrib.max_unmap_block_desc_count = 1;
		dev->dev_attrib.unmap_granularity =
				q->limits.discard_granularity >> 9;
		dev->dev_attrib.unmap_granularity_alignment =
				q->limits.discard_alignment;

		pr_debug("IBLOCK: BLOCK Discard support available,"
				" disabled by default\n");
	}
	/*
	 * Enable write same emulation for IBLOCK and use 0xFFFF as
	 * the smaller WRITE_SAME(10) only has a two-byte block count.
	 */
	dev->dev_attrib.max_write_same_len = 0xFFFF;

	if (blk_queue_nonrot(q))
		dev->dev_attrib.is_nonrot = 1;

#ifdef CONFIG_MACH_QNAPTS
	qnap_transport_config_zc_val(dev);

	/* depend on case to overwrite the setting ... */
	qnap_transport_config_blkio_dev(dev, dev->dev_attrib.hw_block_size);
#endif

	bi = bdev_get_integrity(bd);
	if (bi) {
		struct bio_set *bs = ib_dev->ibd_bio_set;

		if (!strcmp(bi->name, "T10-DIF-TYPE3-IP") ||
		    !strcmp(bi->name, "T10-DIF-TYPE1-IP")) {
			pr_err("IBLOCK export of blk_integrity: %s not"
			       " supported\n", bi->name);
			ret = -ENOSYS;
			goto out_blkdev_put;
		}

		if (!strcmp(bi->name, "T10-DIF-TYPE3-CRC")) {
			dev->dev_attrib.pi_prot_type = TARGET_DIF_TYPE3_PROT;
		} else if (!strcmp(bi->name, "T10-DIF-TYPE1-CRC")) {
			dev->dev_attrib.pi_prot_type = TARGET_DIF_TYPE1_PROT;
		}

		if (dev->dev_attrib.pi_prot_type) {
			if (bioset_integrity_create(bs, IBLOCK_BIO_POOL_SIZE) < 0) {
				pr_err("Unable to allocate bioset for PI\n");
				ret = -ENOMEM;
				goto out_blkdev_put;
			}
			pr_debug("IBLOCK setup BIP bs->bio_integrity_pool: %p\n",
				 bs->bio_integrity_pool);
		}
		dev->dev_attrib.hw_pi_prot_type = dev->dev_attrib.pi_prot_type;
	}

	return 0;

out_blkdev_put:
	blkdev_put(ib_dev->ibd_bd, FMODE_WRITE|FMODE_READ|FMODE_EXCL);
out_free_bioset:
	bioset_free(ib_dev->ibd_bio_set);
	ib_dev->ibd_bio_set = NULL;
out:
	return ret;
}

static void iblock_dev_call_rcu(struct rcu_head *p)
{
	struct se_device *dev = container_of(p, struct se_device, rcu_head);
	struct iblock_dev *ib_dev = IBLOCK_DEV(dev);

	kfree(ib_dev);
}

static void iblock_free_device(struct se_device *dev)
{
	struct iblock_dev *ib_dev = IBLOCK_DEV(dev);
#ifdef CONFIG_MACH_QNAPTS
	int under_threshold = 0;
#endif
#ifdef QNAP_SHARE_JOURNAL
	int err = 0;

	if (ib_dev->ibd_flags & IBDF_HAS_JOURNAL_SUPPORT) {
		pr_info("[BLKJBD] disable journal support when release.\n");
		err = release_blkdev_journal(ib_dev->ibd_udev_path);
		if (err) {
			pr_info("[BLKJBD] %s: release_blkdev_journal failed.\n",
				__func__);
			ib_dev->ibd_flags |= IBDF_HAS_JOURNAL_SUPPORT;
		}
	}
#endif

	if (ib_dev->ibd_bd != NULL)
		blkdev_put(ib_dev->ibd_bd, FMODE_WRITE|FMODE_READ|FMODE_EXCL);
	if (ib_dev->ibd_bio_set != NULL)
		bioset_free(ib_dev->ibd_bio_set);

#ifdef CONFIG_MACH_QNAPTS
	dev->dev_attrib.tp_threshold_hit = 0;
	check_lun_threshold_for_each_device(&under_threshold);

	if (under_threshold) {
#if defined(QNAP_HAL)	
		NETLINK_EVT hal_event;

		memset(&hal_event, 0, sizeof(NETLINK_EVT));
		hal_event.type = HAL_EVENT_ISCSI;

		hal_event.arg.action = UNDER_LUN_THRESHOLD;
		hal_event.arg.param.iscsi_lun.lun_index = 0;
		hal_event.arg.param.iscsi_lun.tp_threshold = 0;

		/* unit: GB */
		hal_event.arg.param.iscsi_lun.tp_avail = 0;

		/* call function if it exists since we declare it as weak symbol */
		if (send_hal_netlink)
			send_hal_netlink(&hal_event);
	}
#endif
#endif

	call_rcu(&dev->rcu_head, iblock_dev_call_rcu);
}

static unsigned long long iblock_emulate_read_cap_with_block_size(
	struct se_device *dev,
	struct block_device *bd,
	struct request_queue *q)
{
	unsigned long long blocks_long = (div_u64(i_size_read(bd->bd_inode),
					bdev_logical_block_size(bd)) - 1);
	u32 block_size = bdev_logical_block_size(bd);

	if (block_size == dev->dev_attrib.block_size)
		return blocks_long;

	switch (block_size) {
	case 4096:
		switch (dev->dev_attrib.block_size) {
		case 2048:
			blocks_long <<= 1;
			break;
		case 1024:
			blocks_long <<= 2;
			break;
		case 512:
			blocks_long <<= 3;
		default:
			break;
		}
		break;
	case 2048:
		switch (dev->dev_attrib.block_size) {
		case 4096:
			blocks_long >>= 1;
			break;
		case 1024:
			blocks_long <<= 1;
			break;
		case 512:
			blocks_long <<= 2;
			break;
		default:
			break;
		}
		break;
	case 1024:
		switch (dev->dev_attrib.block_size) {
		case 4096:
			blocks_long >>= 2;
			break;
		case 2048:
			blocks_long >>= 1;
			break;
		case 512:
			blocks_long <<= 1;
			break;
		default:
			break;
		}
		break;
	case 512:
		switch (dev->dev_attrib.block_size) {
		case 4096:
			blocks_long >>= 3;
			break;
		case 2048:
			blocks_long >>= 2;
			break;
		case 1024:
			blocks_long >>= 1;
			break;
		default:
			break;
		}
		break;
	default:
		break;
	}

	return blocks_long;
}

static void iblock_complete_cmd(struct se_cmd *cmd)
{
	struct iblock_req *ibr = cmd->priv;
	u8 status;

	if (!atomic_dec_and_test(&ibr->pending))
		return;

	if (atomic_read(&ibr->ib_bio_err_cnt))
		status = SAM_STAT_CHECK_CONDITION;
	else
		status = SAM_STAT_GOOD;

#ifdef CONFIG_MACH_QNAPTS
#ifdef SUPPORT_TP
	/* overwrite this if need to report UA */
	if (cmd->work_io_err == TCM_THIN_PROVISIONING_SOFT_THRESHOLD_REACHED)
		status = SAM_STAT_CHECK_CONDITION;
#endif
#endif

	target_complete_cmd(cmd, status);
	kfree(ibr);
}

static void iblock_bio_done(struct bio *bio, int err)
{
	struct se_cmd *cmd = bio->bi_private;

#ifdef CONFIG_MACH_QNAPTS // take care this
	struct bio_rec *brec = NULL;

	if (qnap_bi_private_is_brec(bio->bi_private)) {
		brec = (struct bio_rec *)qnap_bi_private_clear_brec_bit(bio->bi_private);
		cmd = brec->se_cmd;
		qnap_transport_set_bio_rec_null(cmd, brec);		
	}
#endif
	struct iblock_req *ibr = cmd->priv;

	/*
	 * Set -EIO if !BIO_UPTODATE and the passed is still err=0
	 */
	if (!test_bit(BIO_UPTODATE, &bio->bi_flags) && !err)
		err = -EIO;

	if (err != 0) {
		pr_err("test_bit(BIO_UPTODATE) failed for bio: %p,"
			" err: %d\n", bio, err);

#ifdef CONFIG_MACH_QNAPTS
#ifdef SUPPORT_TP
		if (err == -ENOSPC)
			cmd->work_io_err = TCM_SPACE_ALLOCATION_FAILED_WRITE_PROTECT;
#endif
#endif
		/*
		 * Bump the ib_bio_err_cnt and release bio.
		 */
		atomic_inc(&ibr->ib_bio_err_cnt);
		smp_mb__after_atomic();
	}

	bio_put(bio);

#ifdef CONFIG_MACH_QNAPTS
#ifdef SUPPORT_TP
	if (!atomic_read(&ibr->ib_bio_err_cnt)) {
		if (qnap_transport_check_cmd_hit_thin_threshold(cmd) == 0)
			cmd->work_io_err = TCM_THIN_PROVISIONING_SOFT_THRESHOLD_REACHED;
	}
#endif
#endif
	iblock_complete_cmd(cmd);
}

static struct bio *
iblock_get_bio(struct se_cmd *cmd, sector_t lba, u32 sg_num)
{
	struct iblock_dev *ib_dev = IBLOCK_DEV(cmd->se_dev);
	struct bio *bio;

	/*
	 * Only allocate as many vector entries as the bio code allows us to,
	 * we'll loop later on until we have handled the whole request.
	 */
	if (sg_num > BIO_MAX_PAGES)
		sg_num = BIO_MAX_PAGES;

	bio = bio_alloc_bioset(GFP_NOIO, sg_num, ib_dev->ibd_bio_set);
	if (!bio) {
		pr_err("Unable to allocate memory for bio\n");
		return NULL;
	}

	bio->bi_bdev = ib_dev->ibd_bd;
	bio->bi_private = cmd;
	bio->bi_end_io = &iblock_bio_done;
	bio->bi_iter.bi_sector = lba;

	return bio;
}

static void iblock_submit_bios(struct bio_list *list, int rw)
{
	struct blk_plug plug;
	struct bio *bio;

	blk_start_plug(&plug);
	while ((bio = bio_list_pop(list)))
		submit_bio(rw, bio);
	blk_finish_plug(&plug);
}

static void iblock_end_io_flush(struct bio *bio, int err)
{
	struct se_cmd *cmd = bio->bi_private;

	if (err)
		pr_err("IBLOCK: cache flush failed: %d\n", err);

	if (cmd) {
		if (err)
			target_complete_cmd(cmd, SAM_STAT_CHECK_CONDITION);
		else
			target_complete_cmd(cmd, SAM_STAT_GOOD);
	}

	bio_put(bio);
}

/*
 * Implement SYCHRONIZE CACHE.  Note that we can't handle lba ranges and must
 * always flush the whole cache.
 */
static sense_reason_t
iblock_execute_sync_cache(struct se_cmd *cmd)
{
	struct iblock_dev *ib_dev = IBLOCK_DEV(cmd->se_dev);
	int immed = (cmd->t_task_cdb[1] & 0x2);
	struct bio *bio;

	/*
	 * If the Immediate bit is set, queue up the GOOD response
	 * for this SYNCHRONIZE_CACHE op.
	 */
	if (immed)
		target_complete_cmd(cmd, SAM_STAT_GOOD);

	bio = bio_alloc(GFP_KERNEL, 0);
	bio->bi_end_io = iblock_end_io_flush;
	bio->bi_bdev = ib_dev->ibd_bd;
	if (!immed)
		bio->bi_private = cmd;
	submit_bio(WRITE_FLUSH, bio);
	return 0;
}

static sense_reason_t
iblock_execute_unmap(struct se_cmd *cmd, sector_t lba, sector_t nolb)
{
	struct block_device *bdev = IBLOCK_DEV(cmd->se_dev)->ibd_bd;
	int ret;

#ifdef CONFIG_MACH_QNAPTS
	/* force to go this way */
	return qnap_sbc_unmap(cmd, lba, nolb);
#endif

	ret = blkdev_issue_discard(bdev, lba, nolb, GFP_KERNEL, 0);
	if (ret < 0) {
		pr_err("blkdev_issue_discard() failed: %d\n", ret);
		return TCM_LOGICAL_UNIT_COMMUNICATION_FAILURE;
	}

	return 0;
}

static sense_reason_t
iblock_execute_write_same(struct se_cmd *cmd)
{
	struct iblock_req *ibr;
	struct scatterlist *sg;
	struct bio *bio;
	struct bio_list list;
	sector_t block_lba = cmd->t_task_lba;
	sector_t sectors = sbc_get_write_same_sectors(cmd);

	if (cmd->prot_op) {
		pr_err("WRITE_SAME: Protection information with IBLOCK"
		       " backends not supported\n");
		return TCM_LOGICAL_UNIT_COMMUNICATION_FAILURE;
	}
	sg = &cmd->t_data_sg[0];

	if (cmd->t_data_nents > 1 ||
	    sg->length != cmd->se_dev->dev_attrib.block_size) {
		pr_err("WRITE_SAME: Illegal SGL t_data_nents: %u length: %u"
			" block_size: %u\n", cmd->t_data_nents, sg->length,
			cmd->se_dev->dev_attrib.block_size);
		return TCM_INVALID_CDB_FIELD;
	}

#ifdef CONFIG_MACH_QNAPTS
	struct block_device *bdev = IBLOCK_DEV(cmd->se_dev)->ibd_bd;
	
	/* 1. we force go this way 
	 * 2. new kernel will call blkdev_issue_write_same(), but its behavior
	 *    is still to write data sector by sector.
	 * 3. this new call is to prepare buf as PAGE_SIZE, and base on PAGE_SIZE
	 *    to write data
	 */
	return qnap_transport_iblock_execute_write_same_direct(bdev, cmd);
#endif

	ibr = kzalloc(sizeof(struct iblock_req), GFP_KERNEL);
	if (!ibr)
		goto fail;
	cmd->priv = ibr;

	bio = iblock_get_bio(cmd, block_lba, 1);
	if (!bio)
		goto fail_free_ibr;

	bio_list_init(&list);
	bio_list_add(&list, bio);

	atomic_set(&ibr->pending, 1);

	while (sectors) {
		while (bio_add_page(bio, sg_page(sg), sg->length, sg->offset)
				!= sg->length) {

			bio = iblock_get_bio(cmd, block_lba, 1);
			if (!bio)
				goto fail_put_bios;

			atomic_inc(&ibr->pending);
			bio_list_add(&list, bio);
		}

		/* Always in 512 byte units for Linux/Block */
		block_lba += sg->length >> IBLOCK_LBA_SHIFT;
		sectors -= 1;
	}

	iblock_submit_bios(&list, WRITE);
	return 0;

fail_put_bios:
	while ((bio = bio_list_pop(&list)))
		bio_put(bio);
fail_free_ibr:
	kfree(ibr);
fail:
	return TCM_LOGICAL_UNIT_COMMUNICATION_FAILURE;
}

enum {
	Opt_udev_path, Opt_readonly, Opt_force, Opt_err
};

static match_table_t tokens = {
	{Opt_udev_path, "udev_path=%s"},
	{Opt_readonly, "readonly=%d"},
	{Opt_force, "force=%d"},
	{Opt_err, NULL}
};

static ssize_t iblock_set_configfs_dev_params(struct se_device *dev,
		const char *page, ssize_t count)
{
	struct iblock_dev *ib_dev = IBLOCK_DEV(dev);
	char *orig, *ptr, *arg_p, *opts;
	substring_t args[MAX_OPT_ARGS];
	int ret = 0, token;
	unsigned long tmp_readonly;

	opts = kstrdup(page, GFP_KERNEL);
	if (!opts)
		return -ENOMEM;

	orig = opts;

	while ((ptr = strsep(&opts, ",\n")) != NULL) {
		if (!*ptr)
			continue;

		token = match_token(ptr, tokens, args);
		switch (token) {
		case Opt_udev_path:
			if (ib_dev->ibd_bd) {
				pr_err("Unable to set udev_path= while"
					" ib_dev->ibd_bd exists\n");
				ret = -EEXIST;
				goto out;
			}
			if (match_strlcpy(ib_dev->ibd_udev_path, &args[0],
				SE_UDEV_PATH_LEN) == 0) {
				ret = -EINVAL;
				break;
			}
			pr_debug("IBLOCK: Referencing UDEV path: %s\n",
					ib_dev->ibd_udev_path);
			ib_dev->ibd_flags |= IBDF_HAS_UDEV_PATH;
			break;
		case Opt_readonly:
			arg_p = match_strdup(&args[0]);
			if (!arg_p) {
				ret = -ENOMEM;
				break;
			}
			ret = kstrtoul(arg_p, 0, &tmp_readonly);
			kfree(arg_p);
			if (ret < 0) {
				pr_err("kstrtoul() failed for"
						" readonly=\n");
				goto out;
			}
			ib_dev->ibd_readonly = tmp_readonly;
			pr_debug("IBLOCK: readonly: %d\n", ib_dev->ibd_readonly);
			break;
		case Opt_force:
			break;
		default:
			break;
		}
	}

out:
	kfree(orig);
	return (!ret) ? count : ret;
}

static ssize_t iblock_show_configfs_dev_params(struct se_device *dev, char *b)
{
	struct iblock_dev *ib_dev = IBLOCK_DEV(dev);
	struct block_device *bd = ib_dev->ibd_bd;
	char buf[BDEVNAME_SIZE];
	ssize_t bl = 0;

	if (bd)
		bl += sprintf(b + bl, "iBlock device: %s",
				bdevname(bd, buf));
	if (ib_dev->ibd_flags & IBDF_HAS_UDEV_PATH)
		bl += sprintf(b + bl, "  UDEV PATH: %s",
				ib_dev->ibd_udev_path);
	bl += sprintf(b + bl, "  readonly: %d\n", ib_dev->ibd_readonly);

	bl += sprintf(b + bl, "        ");
	if (bd) {
		bl += sprintf(b + bl, "Major: %d Minor: %d  %s\n",
			MAJOR(bd->bd_dev), MINOR(bd->bd_dev), (!bd->bd_contains) ?
			"" : (bd->bd_holder == ib_dev) ?
			"CLAIMED: IBLOCK" : "CLAIMED: OS");
	} else {
		bl += sprintf(b + bl, "Major: 0 Minor: 0\n");
	}

	return bl;
}

static int
iblock_alloc_bip(struct se_cmd *cmd, struct bio *bio)
{
	struct se_device *dev = cmd->se_dev;
	struct blk_integrity *bi;
	struct bio_integrity_payload *bip;
	struct iblock_dev *ib_dev = IBLOCK_DEV(dev);
	struct scatterlist *sg;
	int i, rc;

	bi = bdev_get_integrity(ib_dev->ibd_bd);
	if (!bi) {
		pr_err("Unable to locate bio_integrity\n");
		return -ENODEV;
	}

	bip = bio_integrity_alloc(bio, GFP_NOIO, cmd->t_prot_nents);
	if (!bip) {
		pr_err("Unable to allocate bio_integrity_payload\n");
		return -ENOMEM;
	}

	bip->bip_iter.bi_size = (cmd->data_length / dev->dev_attrib.block_size) *
			 dev->prot_length;
	bip->bip_iter.bi_sector = bio->bi_iter.bi_sector;

	pr_debug("IBLOCK BIP Size: %u Sector: %llu\n", bip->bip_iter.bi_size,
		 (unsigned long long)bip->bip_iter.bi_sector);

	for_each_sg(cmd->t_prot_sg, sg, cmd->t_prot_nents, i) {

		rc = bio_integrity_add_page(bio, sg_page(sg), sg->length,
					    sg->offset);
		if (rc != sg->length) {
			pr_err("bio_integrity_add_page() failed; %d\n", rc);
			return -ENOMEM;
		}

		pr_debug("Added bio integrity page: %p length: %d offset; %d\n",
			 sg_page(sg), sg->length, sg->offset);
	}

	return 0;
}

static sense_reason_t
iblock_execute_rw(struct se_cmd *cmd, struct scatterlist *sgl, u32 sgl_nents,
		  enum dma_data_direction data_direction)
{
	struct se_device *dev = cmd->se_dev;
	struct iblock_req *ibr;
	struct bio *bio, *bio_start;
	struct bio_list list;
	struct scatterlist *sg;
	u32 sg_num = sgl_nents;
	sector_t block_lba;
	unsigned bio_cnt;
	int rw = 0;
	int i;

	if (data_direction == DMA_TO_DEVICE) {
		struct iblock_dev *ib_dev = IBLOCK_DEV(dev);
		struct request_queue *q = bdev_get_queue(ib_dev->ibd_bd);
		/*
		 * Force writethrough using WRITE_FUA if a volatile write cache
		 * is not enabled, or if initiator set the Force Unit Access bit.
		 */
		if (q->flush_flags & REQ_FUA) {
			if (cmd->se_cmd_flags & SCF_FUA)
				rw = WRITE_FUA;
#ifndef CONFIG_MACH_QNAPTS
			else if (!(q->flush_flags & REQ_FLUSH))
				rw = WRITE_FUA;
#endif
			else
				rw = WRITE;
		} else {
			rw = WRITE;
		}
	} else {
		rw = READ;
	}

	/*
	 * Convert the blocksize advertised to the initiator to the 512 byte
	 * units unconditionally used by the Linux block layer.
	 */
	if (dev->dev_attrib.block_size == 4096)
		block_lba = (cmd->t_task_lba << 3);
	else if (dev->dev_attrib.block_size == 2048)
		block_lba = (cmd->t_task_lba << 2);
	else if (dev->dev_attrib.block_size == 1024)
		block_lba = (cmd->t_task_lba << 1);
	else if (dev->dev_attrib.block_size == 512)
		block_lba = cmd->t_task_lba;
	else {
		pr_err("Unsupported SCSI -> BLOCK LBA conversion:"
				" %u\n", dev->dev_attrib.block_size);
		return TCM_LOGICAL_UNIT_COMMUNICATION_FAILURE;
	}

	ibr = kzalloc(sizeof(struct iblock_req), GFP_KERNEL);
	if (!ibr)
		goto fail;
	cmd->priv = ibr;

	if (!sgl_nents) {
		atomic_set(&ibr->pending, 1);
		iblock_complete_cmd(cmd);
		return 0;
	}

	bio = iblock_get_bio(cmd, block_lba, sgl_nents);
	if (!bio)
		goto fail_free_ibr;

	bio_start = bio;
	bio_list_init(&list);
	bio_list_add(&list, bio);

	atomic_set(&ibr->pending, 2);
	bio_cnt = 1;

#ifdef CONFIG_MACH_QNAPTS
	qnap_transport_alloc_bio_rec(cmd, bio);
#endif	

	for_each_sg(sgl, sg, sgl_nents, i) {
		/*
		 * XXX: if the length the device accepts is shorter than the
		 *	length of the S/G list entry this will cause and
		 *	endless loop.  Better hope no driver uses huge pages.
		 */
		while (bio_add_page(bio, sg_page(sg), sg->length, sg->offset)
				!= sg->length) {
			if (bio_cnt >= IBLOCK_MAX_BIO_PER_TASK) {
				iblock_submit_bios(&list, rw);
				bio_cnt = 0;
			}

			bio = iblock_get_bio(cmd, block_lba, sg_num);
			if (!bio)
				goto fail_put_bios;

			atomic_inc(&ibr->pending);
			bio_list_add(&list, bio);
			bio_cnt++;
#ifdef CONFIG_MACH_QNAPTS
			qnap_transport_alloc_bio_rec(cmd, bio);
#endif
		}

		/* Always in 512 byte units for Linux/Block */
		block_lba += sg->length >> IBLOCK_LBA_SHIFT;
		sg_num--;
	}

	if (cmd->prot_type && dev->dev_attrib.pi_prot_type) {
		int rc = iblock_alloc_bip(cmd, bio_start);
		if (rc)
			goto fail_put_bios;
	}

	iblock_submit_bios(&list, rw);
	iblock_complete_cmd(cmd);
	return 0;

fail_put_bios:
	while ((bio = bio_list_pop(&list)))
		bio_put(bio);
fail_free_ibr:
	kfree(ibr);
fail:
	return TCM_LOGICAL_UNIT_COMMUNICATION_FAILURE;
}

static sector_t iblock_get_blocks(struct se_device *dev)
{
	struct iblock_dev *ib_dev = IBLOCK_DEV(dev);
	struct block_device *bd = ib_dev->ibd_bd;
	struct request_queue *q = bdev_get_queue(bd);

	return iblock_emulate_read_cap_with_block_size(dev, bd, q);
}

static sector_t iblock_get_alignment_offset_lbas(struct se_device *dev)
{
	struct iblock_dev *ib_dev = IBLOCK_DEV(dev);
	struct block_device *bd = ib_dev->ibd_bd;
	int ret;

	ret = bdev_alignment_offset(bd);
	if (ret == -1)
		return 0;

	/* convert offset-bytes to offset-lbas */
	return ret / bdev_logical_block_size(bd);
}

static unsigned int iblock_get_lbppbe(struct se_device *dev)
{
	struct iblock_dev *ib_dev = IBLOCK_DEV(dev);
	struct block_device *bd = ib_dev->ibd_bd;
	int logs_per_phys = bdev_physical_block_size(bd) / bdev_logical_block_size(bd);

	return ilog2(logs_per_phys);
}

static unsigned int iblock_get_io_min(struct se_device *dev)
{
	struct iblock_dev *ib_dev = IBLOCK_DEV(dev);
	struct block_device *bd = ib_dev->ibd_bd;

#ifdef CONFIG_MACH_QNAPTS
	/* force to go this way */
	return qnap_sbc_get_io_min(dev);
#endif
	return bdev_io_min(bd);
}

#ifdef CONFIG_MACH_QNAPTS
static void __qnap_target_iblock_execute_sync_cache_work(
	struct work_struct *work
	)
{
	int ret;
	struct se_cmd *cmd = container_of(work, struct se_cmd, sync_cache_work);

	ret = iblock_execute_sync_cache(cmd);

	if (ret) {
		spin_lock_irq(&cmd->t_state_lock);
		cmd->transport_state &= ~(CMD_T_BUSY|CMD_T_SENT);
		spin_unlock_irq(&cmd->t_state_lock);
		transport_generic_request_failure(cmd, ret);
	}
	return;
}

static sense_reason_t qnap_target_iblock_execute_sync_cache(
	struct se_cmd *cmd
	)
{
	if (cmd->se_dev->dev_dr.sync_cache_wq) {
		INIT_WORK(&cmd->sync_cache_work,
			__qnap_target_iblock_execute_sync_cache_work);
		queue_work(cmd->se_dev->dev_dr.sync_cache_wq,  &cmd->sync_cache_work);
		return 0;
	}

	return iblock_execute_sync_cache(cmd);
}

static void *qnap_get_ib_dev(
	struct se_device *se_dev
	)
{
	return (void *)IBLOCK_DEV(se_dev);
}

#endif

static unsigned int iblock_get_io_opt(struct se_device *dev)
{
	struct iblock_dev *ib_dev = IBLOCK_DEV(dev);
	struct block_device *bd = ib_dev->ibd_bd;

#ifdef CONFIG_MACH_QNAPTS
	/* force to go this way */
	return qnap_sbc_get_io_opt(dev);
#endif
	return bdev_io_opt(bd);
}

static struct sbc_ops iblock_sbc_ops = {
	.execute_rw		= iblock_execute_rw,
	.execute_sync_cache	= iblock_execute_sync_cache,
	.execute_write_same	= iblock_execute_write_same,
	.execute_unmap		= iblock_execute_unmap,
#ifdef CONFIG_MACH_QNAPTS
	.execute_qnap_sync_cache = qnap_target_iblock_execute_sync_cache,
#endif
};

static sense_reason_t
iblock_parse_cdb(struct se_cmd *cmd)
{
	return sbc_parse_cdb(cmd, &iblock_sbc_ops);
}

static bool iblock_get_write_cache(struct se_device *dev)
{
	struct iblock_dev *ib_dev = IBLOCK_DEV(dev);
	struct block_device *bd = ib_dev->ibd_bd;
	struct request_queue *q = bdev_get_queue(bd);

	return q->flush_flags & REQ_FLUSH;
}

#ifdef QNAP_SHARE_JOURNAL
static int iblock_set_journal_support(struct se_device *dev,
				      unsigned long enable)
{
	struct iblock_dev *ibd = IBLOCK_DEV(dev);
	struct block_device *bd = ibd->ibd_bd;
	int err = 0;

	if (enable) {
		pr_info("[BLKJBD] enable journal for file-based LUN\n");
		err = init_blkdev_journal(ibd->ibd_udev_path,
					  dev->t10_wwn.unit_serial);
		if (err) {
			pr_info("[BLKJBD] %s: init_blkdev_journal failed\n",
				__func__);
		} else {
			ibd->ibd_flags |= IBDF_HAS_JOURNAL_SUPPORT;
			blkdev_set_aops(bd, 1);
		}
	} else {
		pr_info("[BLKJBD] disable journal support\n");
		blkdev_set_aops(bd, 0);
		ibd->ibd_flags &= ~IBDF_HAS_JOURNAL_SUPPORT;
		err = release_blkdev_journal(ibd->ibd_udev_path);
		if (err) {
			pr_info("[BLKJBD] %s: release_blkdev_journal failed\n",
				__func__);
			ibd->ibd_flags |= IBDF_HAS_JOURNAL_SUPPORT;
		}
	}

	return err;
}
#endif

static const struct target_backend_ops iblock_ops = {
	.name			= "iblock",
#ifdef CONFIG_MACH_QNAPTS
	.inquiry_prod		= "iSCSI Storage",
#else
	.inquiry_prod		= "IBLOCK",
#endif
	.inquiry_rev		= IBLOCK_VERSION,
	.owner			= THIS_MODULE,
	.attach_hba		= iblock_attach_hba,
	.detach_hba		= iblock_detach_hba,
	.alloc_device		= iblock_alloc_device,
	.configure_device	= iblock_configure_device,
	.free_device		= iblock_free_device,
	.parse_cdb		= iblock_parse_cdb,
	.set_configfs_dev_params = iblock_set_configfs_dev_params,
	.show_configfs_dev_params = iblock_show_configfs_dev_params,
	.get_device_type	= sbc_get_device_type,
	.get_blocks		= iblock_get_blocks,
#ifdef CONFIG_MACH_QNAPTS
	.change_dev_size	= qnap_change_dev_size,
	.set_write_cache	= qnap_set_write_cache,
	.set_fua		= qnap_set_fua,
	.get_dev		= qnap_get_ib_dev,
#endif
	.get_alignment_offset_lbas = iblock_get_alignment_offset_lbas,
	.get_lbppbe		= iblock_get_lbppbe,
	.get_io_min		= iblock_get_io_min,
	.get_io_opt		= iblock_get_io_opt,
	.get_write_cache	= iblock_get_write_cache,
	.tb_dev_attrib_attrs	= sbc_attrib_attrs,
#ifdef QNAP_SHARE_JOURNAL
	.set_journal_support	= iblock_set_journal_support,
#endif
};

static int __init iblock_module_init(void)
{
	return transport_backend_register(&iblock_ops);
}

static void __exit iblock_module_exit(void)
{
	target_backend_unregister(&iblock_ops);
}

MODULE_DESCRIPTION("TCM IBLOCK subsystem plugin");
MODULE_AUTHOR("nab@Linux-iSCSI.org");
MODULE_LICENSE("GPL");

#if defined(CONFIG_MACH_QNAPTS)
module_param(blockio_cpumask, int, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
MODULE_PARM_DESC(blockio_cpumask, "BLOCKIO thread binding CPU");
#endif

module_init(iblock_module_init);
module_exit(iblock_module_exit);
