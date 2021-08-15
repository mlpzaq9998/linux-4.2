/*******************************************************************************
 * Filename:  target_core_qodx.c
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

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/net.h>
#include <linux/delay.h>
#include <linux/string.h>
#include <linux/timer.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/kthread.h>
#include <linux/in.h>
#include <linux/vmalloc.h>
#include <linux/blkdev.h>
#include <asm/unaligned.h>
#include <target/qnap_target_struct.h>
#include "target_core_qlib.h"
#include "target_core_qodx_lib.h"
#include "target_core_qodx_scsi.h"

/**/
extern struct rod_type_table gRodTypeTable[];

/**/
struct kmem_cache *token512b_cache = NULL;
struct kmem_cache *odx_token_data_cache = NULL;
struct kmem_cache *odx_br_cache = NULL;
struct kmem_cache *odx_tpg_data_cache = NULL;
struct kmem_cache *odx_cmd_data_cache = NULL;

/**/
static int __odx_loop_blkio_fastzero(struct block_device *bd, sector_t lba,
	sector_t nr_blks, gfp_t gfp_mask, unsigned long flags, sector_t *done_blks);

static void __odx_create_ext_rod_token_data(struct tpc_token_data *token, u8 *buffer);
static u32 __odx_create_target_dev_desc(struct tpc_token_data *token, u8 *buffer);
static void __odx_create_512b_rod_token_after_byte128(struct odx_work_request *odx_wr,
	struct tpc_token_data *token, struct rod_token_512b *token_512b);

static void __odx_create_dev_type_specific_data(struct tpc_token_data *token,
	u8 *dev_type_data);

static void __odx_create_byte64_95(struct tpc_token_data *token, u8 *buffer);
static void __odx_create_id_cscd_desc(struct tpc_token_data *token, 
	struct id_cscd_desc *data);

/**/
u64 odx_get_total_sg_len(
	struct sg_io_data *sg_io
	)
{
	u64 len = 0;
	int i;

	for (i = 0; i < MAX_SG_IO_DATA_COUNT; i++) {
		if (!sg_io[i].data_sg)
			break;
		len += sg_io[i].data_len;
	}

	return len;
}

static void __odx_create_ext_rod_token_data(
	struct tpc_token_data *token,
	u8 *buffer
	)
{
	struct ext_rod_token_data *ext_data = NULL;
	struct __reg_data *data = &token->reg_data;

	ext_data = (struct ext_rod_token_data *)buffer;

	/* information for source side */
	ext_data->cmd_id_lo = data->cmd_id_lo;
	ext_data->cmd_id_hi = data->cmd_id_hi;
	ext_data->tpg_id_lo = data->tpg_id_lo;
	ext_data->tpg_id_hi = data->tpg_id_hi;
	ext_data->initiator_id_lo = data->initiator_id_lo;
	ext_data->initiator_id_hi = data->initiator_id_hi;
}

static u32 __odx_create_target_dev_desc(
	struct tpc_token_data *token,
	u8 *buffer
	)
{
	struct __dev_info *info = &token->reg_data.dev_info;
	u32 off = 0, len = 0;

	/* SPC4R36, page 251
	 *
	 * The TARGET DEVICE DESCRIPTOR field contains desigination
	 * descriptor for the SCSI target device that contains the 
	 * logical unit indicated by the descriptor in CREATOR LOGICAL
	 * UNIT DESCRIPTOR field. The designation descriptor shall have
	 * the ASSOCIATION field set to 10b (i.e. SCSI target device) 
	 * and the DESIGNATOR TYPE field set to 
	 *
	 * a) 2h (EUI-64-based)
	 * b) 3h (NAA) or
	 * c) 8h (SCSI name string)
	 */
	buffer[off] = (info->initiator_prot_id << 4);
	buffer[off++] |= 0x3;	/* CODE SET = UTF-8 */
	buffer[off] = 0x80;	/* Set PIV=1 */
	buffer[off] |= 0x20;	/* Set ASSOCIATION == SCSI target device: 10b */
	buffer[off++] |= 0x3;	/* DESIGNATOR TYPE = NAA */
	off++;			/* Skip over Reserved */
	buffer[off++] = NAA_LEN;

	/* use NAA format , we put md5 id for (target name + tpgt) */

	/* create header */
	buffer[off++] = info->naa[0];
	buffer[off++] = info->naa[1];
	buffer[off++] = info->naa[2];
	/* clear byte0~ byte3 */
	buffer[off] = (info->naa[3] & 0xf0);
	buffer[off] |= 0x0a;
	off++;

	/* FIXED ME: create body, we only have 12 bytes for body */
	*(u32 *)&buffer[off] = (u32)(token->reg_data.tpg_id_lo >> 32);
	off += 4;
	*(u64 *)&buffer[off] = token->reg_data.tpg_id_hi;

	len = ROD_TARGET_DEV_DESC_LEN;
	return len;
}

static void __odx_create_512b_rod_token_after_byte128(
	struct odx_work_request *odx_wr,
	struct tpc_token_data *token,
	struct rod_token_512b *token_512b
	)
{
	/* FIXED ME !!
	 * Go to position of byte 128 and we should consider the remain token
	 * size before to build those data where starts from byte 128.
	 */

	/* byte 128 ~ byte t (target device descriptor) */
	__odx_create_target_dev_desc(token, token_512b->target_dev_desc);


	/* byte (t+1) ~ byte n (extended rod token data) */
	__odx_create_ext_rod_token_data(token, token_512b->ext_rod_token);

	return;
}

static void __odx_create_dev_type_specific_data(
	struct tpc_token_data *token,
	u8 *dev_type_data
	)
{
	struct __dev_info *info = &token->reg_data.dev_info;
	u32 blk_size = (1 << info->bs_order);

	memset(dev_type_data, 0, 32);

	dev_type_data[0] = ((blk_size >> 24) & 0xff);
	dev_type_data[1] = ((blk_size >> 16) & 0xff);
	dev_type_data[2] = ((blk_size >> 8) & 0xff);
	dev_type_data[3] = (blk_size & 0xff);

	/*
	 * Set Thin Provisioning Enable bit following sbc3r22 in section
	 * READ CAPACITY (16) byte 14 if emulate_tpu or emulate_tpws is enabled.
	 */
	if (info->dev_attr & (DEV_ATTR_SUPPORT_UNMAP | DEV_ATTR_SUPPORT_WRITE_SAME))
		dev_type_data[6] = 0x80;

#if defined(CONFIG_MACH_QNAPTS) && defined(SUPPORT_TP)
	if (info->dev_attr & DEV_ATTR_SUPPORT_READ_ZERO_UNMAP)
		dev_type_data[6] |= 0x40;
#endif
	return;
}

static void __odx_create_byte64_95(
	struct tpc_token_data *token,
	u8 *buffer
	)
{
	return;
}

static void __odx_create_id_cscd_desc(
	struct tpc_token_data *token,
	struct id_cscd_desc *data
	)
{
	struct __dev_info *info = &token->reg_data.dev_info;

	data->GenCSCDHdr.DescTypeCode = ID_DESC;
	data->GenCSCDHdr.DevType = info->sbc_dev_type;

	/* this will be ignored in ID CSCD desc, SPC4R36, page 288 */
	data->GenCSCDHdr.LuIdType = 0;

	/* Refer the target_emulate_evpd_83() to crete initiatior port
	 * identifier field value 
	 */
	put_unaligned_be16(info->initiator_rtpi, 
		&data->InitiatorPortIdentifier[0]);

	data->CodeSet = 0x1; // binary
	data->DesignatorType = 0x3; // NAA identifier
	data->Assoc = 0x0; // addressed logical unit

	/* We build the 16 bytes for DESIGNATOR data only, 
	 * length shall be <= 20 for ID CSCD descriptor format
	 */
	data->DesignatorLen = 0x10;

	memcpy(&data->Designator[0], &info->naa[0], NAA_LEN);

	data->DevTypeSpecificParam.BlockDevTypes.DiskBlkLen[0] = 
		(u8)((1 << info->bs_order) >> 16);

	data->DevTypeSpecificParam.BlockDevTypes.DiskBlkLen[1] = 
		(u8)((1 << info->bs_order) >> 8);

	data->DevTypeSpecificParam.BlockDevTypes.DiskBlkLen[2] = 
		(u8)(1 << info->bs_order);
	return;

}

static void __odx_create_cm_rod_token_id_in_rod_token(
	struct tpc_token_data *token,
	u8 *buffer
	)
{
	/* SPC4R36, page 249
	 *
	 * The COPY MANAGER ROD TOKEN IDENTIFIER field contains a value that 
	 * differentiates this ROD token from all other valid ROD token created
	 * by and known to a specific copy manager. No two ROD tokens knwon to
	 * a specific copy manager shall have the same value in this field.
	 */
	put_unaligned_be64((u64)token->create_time, &buffer[0]);
	return;
}

void __odx_build_512b_token_data(
	struct odx_work_request *odx_wr,
	struct tpc_token_data *token
	)
{
	struct rod_token_512b *token_512b = NULL;
	u32 rod_type = 0;
	u8 bs_order = odx_wr->reg_data.dev_info.bs_order;

	/* NOTE:
	 * The token type (byte 0 ~ byte 3) and token size (byte 6 ~ byte 7)
	 * had been updated in __alloc_rod_token() already 
	 */
	token_512b = (struct rod_token_512b *)token->token;

	/* byte 8 ~ byte 15 (copy manager rod token identifier) */
	__odx_create_cm_rod_token_id_in_rod_token(token,
		&token_512b->gen_data.cm_rod_token_id[0]);

	/* byte 16 ~ byte 47 (creator logical unit descriptor, 
	 * SPC4R36, page 249) 
	 */
	__odx_create_id_cscd_desc(token, 
		(struct id_cscd_desc *)&token_512b->gen_data.cr_lu_desc[0]);

	/* byte 48 ~ byte 63 (16 bytes)(number of bytes represented) */
	/* FIXED ME !! we shall take care the case about 64bit x 32bit. */
	put_unaligned_be64((token->transfer_count << bs_order), 
		&token_512b->gen_data.nr_represented_bytes[0]);

	/* byte 64 ~ byte 95 (rod token type specific data) */
	rod_type = get_unaligned_be32(&token_512b->gen_data.type[0]);
	if (rod_type == ROD_TYPE_SPECIFICED_BY_ROD_TOKEN){
		__odx_create_byte64_95(token, 
			&token_512b->gen_data.byte64_95.rod_token_specific_data[0]
			);
	}

	/* byte 96 ~ byte 127,
	 *
	 * device type specific data is specified by the command standard for
	 * the peripheral device type indicated by the CREATOR LOGICAL UNIT
	 * DESCRIPTOR (e.g. for peripheral device type 00h, see SBC-3) */
	__odx_create_dev_type_specific_data(token, 
		&token_512b->gen_data.dev_type_data[0]);

	__odx_create_512b_rod_token_after_byte128(odx_wr, token, token_512b);
	return;
}

int __odx_check_valid_supported_rod_type(
	u32 rod_type
	)
{
	u8 index = 0;
	int ret = -EINVAL;

	for (index = 0;; index++){
		if (gRodTypeTable[index].end_table == 1)
			break;
		if (gRodTypeTable[index].rod_type == rod_type){
			ret = 0;
			break;
	        }
	}
	return ret;
}

int __odx_check_max_lba_in_desc_list(
	struct blk_dev_range_desc *s,
	sector_t max_lba,
	u16 counts
	)
{
	u16 index0 = 0;
	sector_t lba = 0;

	for (index0 = 0; index0 < counts ; index0++){
		lba = (sector_t)(get_unaligned_be64(&s->lba[0]) + \
				(u64)get_unaligned_be32(&s->nr_blks[0]) - 1);

		if (lba > max_lba)
			return -EINVAL;

		s = (struct blk_dev_range_desc *)((u8*)s + \
			sizeof(struct blk_dev_range_desc));
	}

	return 0;
}

int __odx_check_overlap_lba_in_desc_list(
	struct blk_dev_range_desc *s,
	u16 counts
	)
{
	u16 index0 = 0, index1 = 0;
	sector_t lba = 0, lba_s = 0, lba_r = 0;

	for (index0 = 0; index0 < counts; index0++){
		if (get_unaligned_be32(&s[index0].nr_blks[0]) == 0)
			continue;

		lba = (sector_t)(get_unaligned_be64(&s[index0].lba[0]));

		for (index1 = 0; index1 < counts; index1++){
			if ((get_unaligned_be32(&s[index1].nr_blks[0]) == 0)
			|| (index0 == index1)
			)
				continue;

			lba_s = (sector_t)get_unaligned_be64(&s[index1].lba[0]);
			lba_r = (sector_t)get_unaligned_be32(&s[index1].nr_blks[0]);

			if ((lba >= lba_s) && (lba < (lba_s + lba_r)))
				return -EINVAL;
		}
	}

	return 0;
}


int __odx_check_same_lba_in_desc_list(
	struct blk_dev_range_desc *s,
	u16 counts
	)
{
	u16 index0 = 0, index1 = 0;
	sector_t lba = 0;

	for (index0 = 0; index0 < counts; index0++){
		if (get_unaligned_be32(&s[index0].nr_blks[0]) == 0)
			continue;

		lba = (sector_t)(get_unaligned_be64(&s[index0].lba[0]));

		for (index1 = 0; index1 < counts; index1++){
			if ((get_unaligned_be32(&s[index1].nr_blks[0]) == 0)
			|| (index0 == index1)
			)
				continue;

			if (lba == (sector_t)get_unaligned_be64(&s[index1].lba[0]))
				return -EINVAL;
		}
	}

	return 0;
}

int __odx_is_duplicated_token_then_delete(
	struct tpc_tpg_data *tpg_p,
	u64 cmd_id_hi, 
	u64 cmd_id_lo, 
	u64 initiator_id_hi, 
	u64 initiator_id_lo
	)
{
	struct tpc_token_data *d_token_p = NULL;
	int count = 0;

	d_token_p = odx_rb_token_get(tpg_p, cmd_id_hi, cmd_id_lo, 
			initiator_id_hi, initiator_id_lo, false);

	if (d_token_p) {
		/* To discard related data. SPC4R36 , page 428 */
		pr_warn("warning: found matched token (list id:0x%x, "
			"op_sac:0x%x), to discard token first ...\n", 
			d_token_p->reg_data.list_id, d_token_p->reg_data.sac);

		/* if token status is O_TOKEN_ALIVE, set to O_TOKEN_CANCELLED */
		__odx_cmpxchg_token_status(d_token_p, O_TOKEN_ALIVE, O_TOKEN_CANCELLED);

		do {
			count = odx_rb_token_put(d_token_p);
			if (count == 1)
				break;

			pr_warn("%s: token refcount not 1, it is still using "
				"by someone, wait next chance\n", __func__);
			cpu_relax();
		} while (1);

		/* we don't delete token here due to timer will conver this.
		 * and, token won't be picked up since it was cancelled
		 */
	}

	return 0;
}

static void __odx_token512b_free(void *p)
{
	if (p)
		kmem_cache_free(token512b_cache, p);
}

static struct rod_token_512b *__odx_token512b_alloc(
	u32 token_type,
	u32 token_size
	)
{
	struct rod_token_512b *token512b = NULL;

	/* SBC3R31, page 89
	 *
	 * The block device zero ROD token represents the use data in which
	 * all bits are set to zero and protection information, if any, is set to 
	 * 0xFFFF_FFFF_FFFF_FFFFULL. In response to a RECEIVE ROD TOKEN INFORMATION
	 * command in which the list identifier field specifies a POPULATE TOKEN
	 * command, the copy manager may or may NOT return a ROD token that is
	 * the block device zero ROD token.
	 *
	 * Therefore, we don't support to build the block device zero ROD token
	 * here.
	 */


	/* windows ODX use 512b token so only check this */
	if ((token_type == ROD_TYPE_BLK_DEV_ZERO)
	|| (token_size != ROD_TOKEN_MIN_SIZE)
	)
		return NULL;
	
	if (__odx_check_valid_supported_rod_type(token_type) != 0)
		return NULL;
	
	if (token_type != ROD_TYPE_PIT_COPY_D4)
		return NULL;

	token512b = kmem_cache_zalloc(token512b_cache, GFP_KERNEL);
	if (!token512b)
		return NULL;

	put_unaligned_be32(token_type, &token512b->gen_data.type[0]);
	put_unaligned_be16((token_size - 8), &token512b->gen_data.token_len[0]);

	return token512b;
}

void __odx_token_data_free(struct tpc_token_data *p)
{
	if (p) {
		if (p->token)
			__odx_token512b_free(p->token);

		kmem_cache_free(odx_token_data_cache, p);
	}
}

struct tpc_token_data *__odx_token_data_alloc(
	struct odx_work_request *odx_wr,
	struct __reg_data *data
	)
{
	struct tpc_token_data *p = NULL;
	struct rod_token_512b *token512b_p = NULL;	

	token512b_p = __odx_token512b_alloc(ROD_TYPE_PIT_COPY_D4, 
			ROD_TOKEN_MIN_SIZE);

	if (!token512b_p)
		return NULL;

	/* SBC3R31, page 89
	 *
	 * The block device zero ROD token represents the use data in which
	 * all bits are set to zero and protection information, if any, is set to 
	 * 0xFFFF_FFFF_FFFF_FFFFULL. In response to a RECEIVE ROD TOKEN INFORMATION
	 * command in which the list identifier field specifies a POPULATE TOKEN
	 * command, the copy manager may or may NOT return a ROD token that is
	 * the block device zero ROD token.
	 *
	 * Therefore, we don't support to build the block device zero ROD token
	 * here.
	 */
	p = kmem_cache_zalloc(odx_token_data_cache, GFP_KERNEL);
	if (!p) {
		__odx_token512b_free(token512b_p);
		return NULL;
	}

	RB_CLEAR_NODE(&p->node);
	INIT_LIST_HEAD(&p->del_node);
	INIT_LIST_HEAD(&p->br_list);
	spin_lock_init(&p->br_list_lock);
	spin_lock_init(&p->transfer_count_lock);
	atomic_set(&p->ref_count, 1);
        init_timer(&p->timer);

#ifdef SUPPORT_TPC_CMD
	p->se_dev = odx_wr->se_dev;
#endif
	p->tpg_p = odx_wr->tpg_p;
	__odx_update_token_status(p, O_TOKEN_NOT_ALLOCATED_AND_NOT_ALIVE);
	p->cp_op_status = OP_COMPLETED_WO_ERR;
	p->completion_status = SAM_STAT_GOOD;
	p->token = token512b_p;

	memcpy(&p->reg_data, data, sizeof(struct __reg_data));
	return p;
}


void __odx_set_obj_op_counter(
	struct tpc_token_data *token
	)
{
	/* TBD: need to check */
	if ((token->completion_status == SAM_STAT_GOOD)
	|| (token->completion_status == SAM_STAT_CONDITION_MET)
	|| (token->completion_status == SAM_STAT_CHECK_CONDITION)
	)
		token->op_counter = 1;
	else
		token->op_counter = 0;

	return;
}

int __odx_set_obj_completion_status(
	struct tpc_token_data *token
	)
{
	/* FIXED ME !!
	 * The completion_status shall be reserved if the cp_op_status is 
	 * 0x10, 0x11, 0x12 
	 */
	
	if ((token->cp_op_status == OP_IN_PROGRESS_WITHIN_FG_OR_BG_UNKNOWN)
	||  (token->cp_op_status == OP_IN_PROGRESS_WITHIN_FG)
	||  (token->cp_op_status == OP_IN_PROGRESS_WITHIN_BG)
	)
		return -EINVAL;

	/* TODO: need to check in the future */
	if ((token->cp_op_status == OP_COMPLETED_W_ERR)
	||  (token->cp_op_status == OP_COMPLETED_WO_ERR_WITH_ROD_TOKEN_USAGE)
	||  (token->cp_op_status == OP_COMPLETED_WO_ERR_BUT_WITH_RESIDUAL_DATA)
	)
		token->completion_status = SAM_STAT_CHECK_CONDITION;
	else if (token->cp_op_status == OP_COMPLETED_WO_ERR)
		token->completion_status = SAM_STAT_GOOD;
	else if (token->cp_op_status == OP_TERMINATED)
		token->completion_status = SAM_STAT_TASK_ABORTED;
	else
		return -EINVAL;

	return 0;		
}


static void __odx_free_token_timer(
	unsigned long arg
	)
{
	/* spc4r37a p 268
	 *
	 * If any of the conditions described in this subclause cause a ROD token 
	 * to become invalid, then the copy manager shall maintain a record of 
	 * them for reporting purposes (see 5.16.6.5.2.3) for at least the 
	 * lifetime of the ROD token established at the time the ROD token was 
	 * created, and should maintain the record for twice the lifetime of the
	 * ROD token.
	 */

	struct tpc_token_data *token = (struct tpc_token_data *)arg;
	struct tpc_tpg_data *tpg_p = token->tpg_p;
	LIST_HEAD(tmp_data_list);
	int next_time_out = token->token_timeout;

	/* the token may be O_TOKEN_ALIVE, O_TOKEN_CANCELLED or O_TOKEN_EXPIRED */
	__odx_cmpxchg_token_status(token, O_TOKEN_ALIVE, O_TOKEN_EXPIRED);

	if (token->next_delete || (atomic_read(&token->status) == O_TOKEN_CANCELLED)) {

		if (atomic_read(&token->ref_count) == 1) {

			pr_debug("%s: rb erase token (id:0x%x, sac:0x%x), status: %d\n", 
				__func__, token->reg_data.list_id, token->reg_data.sac, 
				atomic_read(&token->status));

			spin_lock(&tpg_p->token_root_lock);
			rb_erase(&token->node, &tpg_p->token_root);
			RB_CLEAR_NODE(&token->node);
			spin_unlock(&tpg_p->token_root_lock);

			spin_lock(&token->br_list_lock);
			list_splice_tail_init(&token->br_list, &tmp_data_list);
			spin_unlock(&token->br_list_lock);

			__odx_free_br_lists(&tmp_data_list);
			__odx_token_data_free(token);
			return;
		}

		/* If somebody is still using this token, to init timer again and
		 * wait next chance to release this token. But, since this token status
		 * was changed, it won't be used by newbody
		 */
		pr_debug("%s: token (id:0x%x, sac:0x%x) refcount not 1, status: %d. "
			"resetup timer handler\n", __func__, token->reg_data.list_id, 
			token->reg_data.sac, atomic_read(&token->status));

		next_time_out = 5;

	}

	token->next_delete = true;

	/* to init the timer again */
	init_timer(&token->timer);
	token->timer.expires = (jiffies + \
		msecs_to_jiffies(next_time_out * 1000));
	token->timer.data = (unsigned long)token;
	token->timer.function = __odx_free_token_timer;
	add_timer(&token->timer);
	return;

}

void __odx_setup_token_timer(
	struct tpc_token_data *token,
	u32 timeout
	)
{
	unsigned long token_timeout = 0;

	if (timeout > MAX_INACTIVITY_TIMEOUT)
		timeout = MAX_INACTIVITY_TIMEOUT;

	if (timeout == 0)
		token_timeout = jiffies + \
			msecs_to_jiffies(D4_INACTIVITY_TIMEOUT * 1000);
	else
		token_timeout = jiffies + msecs_to_jiffies(timeout * 1000);

	token->timer.expires	= token_timeout;
	token->timer.data	= (unsigned long )token;
	token->timer.function	= __odx_free_token_timer;
	add_timer(&token->timer);
	return;
}

struct blk_range_data *__odx_alloc_br(void)
{
	struct blk_range_data *br = NULL;

	br = kmem_cache_alloc(odx_br_cache, GFP_KERNEL);
	if (!br)
		return NULL;

	INIT_LIST_HEAD(&br->br_node);
	br->curr_status = R_STATUS_NOT_USED;
	br->next_status = R_STATUS_NOT_USED;
	return br;
}

void __odx_free_br_lists(
	struct list_head *data_list
	)
{
	struct blk_range_data *br = NULL, *tmp_br = NULL;

	list_for_each_entry_safe(br, tmp_br, data_list, br_node) {
		pr_debug("free br (0x%p)\n", br);
		kmem_cache_free(odx_br_cache, br);
	}
}

void __odx_free_token_lists(
	struct list_head *data_list
	)
{
	struct tpc_token_data *token_p = NULL, *tmp_token_p = NULL;

	list_for_each_entry_safe(token_p, tmp_token_p, data_list, del_node) {

		if (token_p->timer.entry.pprev)
			del_timer_sync(&token_p->timer);

		if (token_p->token)
			kmem_cache_free(token512b_cache, token_p->token);

		__odx_free_br_lists(&token_p->br_list);

		kmem_cache_free(odx_token_data_cache, token_p);
	}
}

sector_t __odx_lock_get_nr_blks_by_s_token(
	struct tpc_token_data *s_token_p
	)
{
	struct blk_range_data *br = NULL;
	sector_t total = 0;

	spin_lock_bh(&s_token_p->br_list_lock);

	list_for_each_entry(br, &s_token_p->br_list, br_node)
		total += (sector_t)br->nr_blks;

	spin_unlock_bh(&s_token_p->br_list_lock);
	return total;
}

int __odx_wut_check_rod_off_before_wut_io(
	struct tpc_token_data *s_token_p,
	struct tpc_token_data *d_token_p,
	sector_t src_nr_blks,
	sector_t dest_nr_blks,
	u64 off_to_rod,
	RC *rc
	)
{
	u64 off_bytes_to_rod = 0, src_nr_bytes = 0, dest_nr_bytes = 0;
	u32 src_bs_order = s_token_p->reg_data.dev_info.bs_order;
	u32 dest_bs_order = d_token_p->reg_data.dev_info.bs_order;

	/* convert to byte count unit first */
	off_bytes_to_rod = off_to_rod << dest_bs_order;
	src_nr_bytes = (u64)src_nr_blks << src_bs_order;
	dest_nr_bytes = (u64)dest_nr_blks << dest_bs_order;

	if (off_bytes_to_rod >= src_nr_bytes) {
		pr_err("value of offset-into-ROD (0x%llx) is larger than "
			"total blks(0x%llx) of src token (id:0x%x), "
			"src bs_order:0x%x, dest bs_order:0x%x\n",
			(unsigned long long)off_bytes_to_rod,
			(unsigned long long)src_nr_bytes, 
			s_token_p->reg_data.list_id,
			src_bs_order, dest_bs_order);

		*rc = RC_INVALID_PARAMETER_LIST;
		return -EINVAL;
	}

	
	/* SBCR31, page 209
	 *
	 * If the numberof bytes of user data represented by the sum of the 
	 * contents of the NUMBER OF LOGICAL BLOCKS fields in all of the 
	 * complete block device range descriptors is larger than the number of
	 * bytes in the data represented by the ROD token minus the computed 
	 * byte offset into the ROD (i.e. the total requested length of the 
	 * transfer exceeds the length of the data avaiable in the data 
	 * represented by the ROD token), then the copy manager
	 * shall :
	 *
	 * (1) transfer as many whole logical blocks; and
	 *
	 * (2) if any portion of a logical block that is written by the copy
	 *     manager corresponds offsets into the ROD at or beyond the length
	 *     of the data represented by the ROD token, write that portion of
	 *     the logical block with user data with all bits set to zero
	 *
	 * But, for this case, offload scsi compliance test in HCK in windows want
	 * the device server terminated with CHECK CONDITION and set the ASC, 
	 * ASCQ to ILLEGAL REQUEST and COPY TARGET DEVICE DATA UNDERRUN.
	 *
	 * p.s. We need to check this again !!
	 */

	if (dest_nr_bytes > (src_nr_bytes - off_bytes_to_rod)){
		pr_err("total bytes (0x%llx) of dest token (id:0x%x) "
			"is larger than avaiable ROD data (bytes:0x%llx, "
			"offset:0x%llx), src bs_order:0x%x, dest bs_order:0x%x\n",
			(unsigned long long)dest_nr_bytes,
			d_token_p->reg_data.list_id,
			(unsigned long long)src_nr_bytes, 
			(unsigned long long)off_bytes_to_rod, 
			src_bs_order, dest_bs_order);

		*rc = RC_ILLEGAL_REQ_DATA_UNDERRUN_COPY_TARGET;
		return -EINVAL;
	}

	*rc = RC_GOOD;
	return 0;

}

int __odx_wut_get_src_tpg_p_and_token_p(
	struct rod_token_512b *s_token512b_p,
	struct tpc_tpg_data **s_tpg_p,
	struct tpc_token_data **s_token_p,
	struct tpc_token_data *d_token_p,
	RC *rc
	)
{
	struct ext_rod_token_data *ext_rtd = NULL;
	struct tpc_tpg_data *tpg_p = NULL;
	struct tpc_token_data *token_p = NULL;
	int ret;
	RC tmp_rc;
	u8 src_token_id[0];
	struct __dev_info *dev_info;

	/* here will try get src information from token data passed from dest */

	ext_rtd = (struct ext_rod_token_data *)&s_token512b_p->ext_rod_token[0];

	tpg_p = odx_rb_tpg_get(ext_rtd->tpg_id_hi, ext_rtd->tpg_id_lo);
	if (!tpg_p) {
		*rc = RC_3RD_PARTY_DEVICE_FAILURE;
		return -ENODEV;
	}

	token_p = odx_rb_token_get(tpg_p, ext_rtd->cmd_id_hi, ext_rtd->cmd_id_lo, 
			ext_rtd->initiator_id_hi, ext_rtd->initiator_id_lo, false);

	if (!token_p) {
		pr_debug("warning: src token may be expired\n");
		*rc = RC_INVALID_TOKEN_OP_AND_TOKEN_EXPIRED;
		return -ENODEV;
	}

	/* even we know where this command comes from (i.e. comes from which
	 * initiator (IQN + ISID), goes to which iscsi target (IQN + TPGT) and,
	 * its command list id), we still need to check it is VALID or INVALID
	 */
	put_unaligned_be64(*(u64 *)&s_token512b_p->gen_data.cm_rod_token_id[0], 
		&src_token_id[0]);

	dev_info = &token_p->reg_data.dev_info;

	if (token_p->create_time != *(u64 *)&src_token_id[0]
	|| memcmp(&dev_info->naa[0], &s_token512b_p->gen_data.cr_lu_desc[8], NAA_LEN)
	)
	{
		pr_err("found token record but information of token id and "
			"lun desc NOT match with incoming token\n");

		odx_rb_token_put(token_p);
		odx_rb_tpg_put(tpg_p);
		*rc = RC_INVALID_TOKEN_OP_AND_CAUSE_NOT_REPORTABLE;
		return -ENODEV;
	}

	*s_tpg_p = tpg_p;
	*s_token_p = token_p;

	/* Found src token, but need to check the i_t nexus of then whether
	 * they are the same or not
	 */
	if ((ext_rtd->tpg_id_lo != d_token_p->reg_data.tpg_id_lo)
	|| (ext_rtd->tpg_id_hi != d_token_p->reg_data.tpg_id_hi)
	|| (ext_rtd->initiator_id_lo != d_token_p->reg_data.initiator_id_lo)
	|| (ext_rtd->initiator_id_hi != d_token_p->reg_data.initiator_id_hi)
	)
		pr_debug("i_t nexus of src token and dest token "
			"are NOT the same, but still force run ODX\n");

	*rc = RC_GOOD;
	return 0;
}

void __odx_build_token_sense_data(
	struct tpc_token_data *token,
	RC rc,
	u8 asc,
	u8 ascq
	)
{
	u8 *buffer = NULL;
	u8 offset= 0;

	pr_debug("token(0x%p), list id:0x%x, asc:0x%x, ascq:0x%x, rc:%d\n", 
		token, token->reg_data.list_id, asc, ascq, rc);

	buffer = &token->sense_data[0];
	memset(buffer, 0, ROD_SENSE_DATA_LEN);

	/* Here refer the transport_send_check_condition_and_sense() and only
	 * handle error code about the 3rd-party copy command that originated
	 * the copy operation.
	 */
	switch(rc){
	case RC_NON_EXISTENT_LUN:
		buffer[offset] = 0x70;
		buffer[offset+SPC_ADD_SENSE_LEN_OFFSET] = 10;
		buffer[offset+SPC_SENSE_KEY_OFFSET] = ILLEGAL_REQUEST;
		buffer[offset+SPC_ASC_KEY_OFFSET] = 0x25;
		break;

	case RC_UNKNOWN_SAM_OPCODE:
	case RC_REQ_TOO_MANY_SECTORS:
		buffer[offset] = 0x70;
		buffer[offset+SPC_ADD_SENSE_LEN_OFFSET] = 10;
		buffer[offset+SPC_SENSE_KEY_OFFSET] = ILLEGAL_REQUEST;
		buffer[offset+SPC_ASC_KEY_OFFSET] = 0x20;
		break;
	case RC_CHECK_CONDITION_NOT_READY:
		buffer[offset] = 0x70;
		buffer[offset+SPC_ADD_SENSE_LEN_OFFSET] = 10;
		buffer[offset+SPC_SENSE_KEY_OFFSET] = NOT_READY;
		buffer[offset+SPC_ASC_KEY_OFFSET] = asc;
		buffer[offset+SPC_ASCQ_KEY_OFFSET] = ascq;
		break;
	case RC_CHECK_CONDITION_ABORTED_CMD:
		buffer[offset] = 0x70;
		buffer[offset+SPC_ADD_SENSE_LEN_OFFSET] = 10;
		buffer[offset+SPC_SENSE_KEY_OFFSET] = ABORTED_COMMAND;
		buffer[offset+SPC_ASC_KEY_OFFSET] = 0x29;
		buffer[offset+SPC_ASCQ_KEY_OFFSET] = 0x03;
		break;
	case RC_INVALID_CDB_FIELD:
		buffer[offset]                          = 0x70;
		buffer[offset+SPC_ADD_SENSE_LEN_OFFSET] = 10;
		buffer[offset+SPC_SENSE_KEY_OFFSET]     = ILLEGAL_REQUEST;
		buffer[offset+SPC_ASC_KEY_OFFSET]       = 0x24;
		break;
	case RC_INVALID_PARAMETER_LIST:
		buffer[offset]                          = 0x70;
		buffer[offset+SPC_ADD_SENSE_LEN_OFFSET] = 10;
		buffer[offset+SPC_SENSE_KEY_OFFSET]     = ILLEGAL_REQUEST;
		buffer[offset+SPC_ASC_KEY_OFFSET]       = 0x26;
		break;
	case RC_WRITE_PROTECTEDS:
		buffer[offset]                          = 0x70;
		buffer[offset+SPC_ADD_SENSE_LEN_OFFSET] = 10;
		buffer[offset+SPC_SENSE_KEY_OFFSET]     = DATA_PROTECT;
		buffer[offset+SPC_ASC_KEY_OFFSET]       = 0x27;
		break;
	case RC_LBA_OUT_OF_RANGE:
		buffer[offset]                          = 0x70;
		buffer[offset+SPC_ADD_SENSE_LEN_OFFSET] = 10;
		buffer[offset+SPC_SENSE_KEY_OFFSET]     = ILLEGAL_REQUEST;
		buffer[offset+SPC_ASC_KEY_OFFSET]       = 0x21;
		buffer[offset+SPC_ASCQ_KEY_OFFSET]      = 0x00;
		break;
	case RC_PARAMETER_LIST_LEN_ERROR:
		buffer[offset]                          = 0x70;
		buffer[offset+SPC_ADD_SENSE_LEN_OFFSET] = 10;
		buffer[offset+SPC_SENSE_KEY_OFFSET]     = ILLEGAL_REQUEST;
		buffer[offset+SPC_ASC_KEY_OFFSET]       = 0x1A;
		buffer[offset+SPC_ASCQ_KEY_OFFSET]      = 0x00;
		break;
	case RC_UNREACHABLE_COPY_TARGET:
		buffer[offset]                          = 0x70;
		buffer[offset+SPC_ADD_SENSE_LEN_OFFSET] = 10;
		buffer[offset+SPC_SENSE_KEY_OFFSET]     = COPY_ABORTED;
		buffer[offset+SPC_ASC_KEY_OFFSET]       = 0x08;
		buffer[offset+SPC_ASCQ_KEY_OFFSET]      = 0x04;
		break;
	case RC_3RD_PARTY_DEVICE_FAILURE:
		buffer[offset]                          = 0x70;
		buffer[offset+SPC_ADD_SENSE_LEN_OFFSET] = 10;
		buffer[offset+SPC_SENSE_KEY_OFFSET]     = COPY_ABORTED;
		buffer[offset+SPC_ASC_KEY_OFFSET]       = 0x0D;
		buffer[offset+SPC_ASCQ_KEY_OFFSET]      = 0x01;
		break;
	case RC_INCORRECT_COPY_TARGET_DEV_TYPE:
		buffer[offset]                          = 0x70;
		buffer[offset+SPC_ADD_SENSE_LEN_OFFSET] = 10;
		buffer[offset+SPC_SENSE_KEY_OFFSET]     = COPY_ABORTED;
		buffer[offset+SPC_ASC_KEY_OFFSET]       = 0x0D;
		buffer[offset+SPC_ASCQ_KEY_OFFSET]      = 0x03;
		break;
	case RC_TOO_MANY_TARGET_DESCRIPTORS:
		buffer[offset]                          = 0x70;
		buffer[offset+SPC_ADD_SENSE_LEN_OFFSET] = 10;
		buffer[offset+SPC_SENSE_KEY_OFFSET]     = ILLEGAL_REQUEST;
		buffer[offset+SPC_ASC_KEY_OFFSET]       = 0x26;
		buffer[offset+SPC_ASCQ_KEY_OFFSET]      = 0x06;
		break;
	case RC_TOO_MANY_SEGMENT_DESCRIPTORS:
		buffer[offset]                          = 0x70;
		buffer[offset+SPC_ADD_SENSE_LEN_OFFSET] = 10;
		buffer[offset+SPC_SENSE_KEY_OFFSET]     = ILLEGAL_REQUEST;
		buffer[offset+SPC_ASC_KEY_OFFSET]       = 0x26;
		buffer[offset+SPC_ASCQ_KEY_OFFSET]      = 0x08;
		break;
	case RC_ILLEGAL_REQ_DATA_OVERRUN_COPY_TARGET:
		buffer[offset]                          = 0x70;
		buffer[offset+SPC_ADD_SENSE_LEN_OFFSET] = 10;
		buffer[offset+SPC_SENSE_KEY_OFFSET]     = ILLEGAL_REQUEST;
		buffer[offset+SPC_ASC_KEY_OFFSET]       = 0x0D;
		buffer[offset+SPC_ASCQ_KEY_OFFSET]      = 0x05;
		break;
	case RC_ILLEGAL_REQ_DATA_UNDERRUN_COPY_TARGET:
    		buffer[offset]                          = 0x70;
		buffer[offset]                          |= 0x80;

	        /* Information field shall be zero */
		buffer[offset+3] = 0;
		buffer[offset+SPC_ADD_SENSE_LEN_OFFSET] = 10;
		buffer[offset+SPC_SENSE_KEY_OFFSET]     = ILLEGAL_REQUEST;
		buffer[offset+SPC_ASC_KEY_OFFSET]       = 0x0D;
		buffer[offset+SPC_ASCQ_KEY_OFFSET]      = 0x04;
		break;
	case RC_COPY_ABORT_DATA_OVERRUN_COPY_TARGET:
		buffer[offset]                          = 0x70;
		buffer[offset+SPC_ADD_SENSE_LEN_OFFSET] = 10;
		buffer[offset+SPC_SENSE_KEY_OFFSET]     = COPY_ABORTED;
		buffer[offset+SPC_ASC_KEY_OFFSET]       = 0x0D;
		buffer[offset+SPC_ASCQ_KEY_OFFSET]      = 0x05;
		break;
	case RC_COPY_ABORT_DATA_UNDERRUN_COPY_TARGET:
		buffer[offset]                          = 0x70;
		buffer[offset]                          |= 0x80;
		put_unaligned_be32((u64)token->transfer_count, &buffer[offset+3]);
		buffer[offset+SPC_ADD_SENSE_LEN_OFFSET] = 10;
		buffer[offset+SPC_SENSE_KEY_OFFSET]     = COPY_ABORTED;
		buffer[offset+SPC_ASC_KEY_OFFSET]       = 0x0D;
		buffer[offset+SPC_ASCQ_KEY_OFFSET]      = 0x04;
		break;
	case RC_INSUFFICIENT_RESOURCES:
		buffer[offset]                          = 0x70;
		buffer[offset+SPC_ADD_SENSE_LEN_OFFSET] = 10;
		buffer[offset+SPC_SENSE_KEY_OFFSET]     = ILLEGAL_REQUEST;
		buffer[offset+SPC_ASC_KEY_OFFSET]       = 0x55;
		buffer[offset+SPC_ASCQ_KEY_OFFSET]      = 0x03;
		break;
	case RC_INSUFFICIENT_RESOURCES_TO_CREATE_ROD:
		buffer[offset]                          = 0x70;
		buffer[offset+SPC_ADD_SENSE_LEN_OFFSET] = 10;
		buffer[offset+SPC_SENSE_KEY_OFFSET]     = ILLEGAL_REQUEST;
		buffer[offset+SPC_ASC_KEY_OFFSET]       = 0x55;
		buffer[offset+SPC_ASCQ_KEY_OFFSET]      = 0x0C;
		break;
	case RC_INSUFFICIENT_RESOURCES_TO_CREATE_ROD_TOKEN:
		buffer[offset]                          = 0x70;
		buffer[offset+SPC_ADD_SENSE_LEN_OFFSET] = 10;
		buffer[offset+SPC_SENSE_KEY_OFFSET]     = ILLEGAL_REQUEST;
		buffer[offset+SPC_ASC_KEY_OFFSET]       = 0x55;
		buffer[offset+SPC_ASCQ_KEY_OFFSET]      = 0x0D;
		break;
	case RC_OPERATION_IN_PROGRESS:
		buffer[offset]                          = 0x70;
		buffer[offset+SPC_ADD_SENSE_LEN_OFFSET] = 10;
		buffer[offset+SPC_SENSE_KEY_OFFSET]     = ILLEGAL_REQUEST;
		buffer[offset+SPC_ASC_KEY_OFFSET]       = 0x00;
		buffer[offset+SPC_ASCQ_KEY_OFFSET]      = 0x16;
		break;
	case RC_INVALID_TOKEN_OP_AND_INVALID_TOKEN_LEN:
		buffer[offset]                          = 0x70;
		buffer[offset+SPC_ADD_SENSE_LEN_OFFSET] = 10;
		buffer[offset+SPC_SENSE_KEY_OFFSET]     = ILLEGAL_REQUEST;
		buffer[offset+SPC_ASC_KEY_OFFSET]       = 0x23;
		buffer[offset+SPC_ASCQ_KEY_OFFSET]      = 0x0A;
		break;
	case RC_INVALID_TOKEN_OP_AND_CAUSE_NOT_REPORTABLE:
		buffer[offset]                          = 0x70;
		buffer[offset+SPC_ADD_SENSE_LEN_OFFSET] = 10;
		buffer[offset+SPC_SENSE_KEY_OFFSET]     = ILLEGAL_REQUEST;
		buffer[offset+SPC_ASC_KEY_OFFSET]       = 0x23;
		buffer[offset+SPC_ASCQ_KEY_OFFSET]      = 0x00;
		break;
	case RC_INVALID_TOKEN_OP_AND_REMOTE_ROD_TOKEN_CREATION_NOT_SUPPORTED:
		buffer[offset]                          = 0x70;
		buffer[offset+SPC_ADD_SENSE_LEN_OFFSET] = 10;
		buffer[offset+SPC_SENSE_KEY_OFFSET]     = ILLEGAL_REQUEST;
		buffer[offset+SPC_ASC_KEY_OFFSET]       = 0x23;
		buffer[offset+SPC_ASCQ_KEY_OFFSET]      = 0x03;
		break;
	case RC_INVALID_TOKEN_OP_AND_REMOTE_ROD_TOKEN_USAGE_NOT_SUPPORTED:
		buffer[offset]                          = 0x70;
		buffer[offset+SPC_ADD_SENSE_LEN_OFFSET] = 10;
		buffer[offset+SPC_SENSE_KEY_OFFSET]     = ILLEGAL_REQUEST;
		buffer[offset+SPC_ASC_KEY_OFFSET]       = 0x23;
		buffer[offset+SPC_ASCQ_KEY_OFFSET]      = 0x02;
		break;
	case RC_INVALID_TOKEN_OP_AND_TOKEN_CANCELLED:
		buffer[offset]                          = 0x70;
		buffer[offset+SPC_ADD_SENSE_LEN_OFFSET] = 10;
		buffer[offset+SPC_SENSE_KEY_OFFSET]     = ILLEGAL_REQUEST;
		buffer[offset+SPC_ASC_KEY_OFFSET]       = 0x23;
		buffer[offset+SPC_ASCQ_KEY_OFFSET]      = 0x08;
		break;
	case RC_INVALID_TOKEN_OP_AND_TOKEN_CORRUPT:
		buffer[offset]                          = 0x70;
		buffer[offset+SPC_ADD_SENSE_LEN_OFFSET] = 10;
		buffer[offset+SPC_SENSE_KEY_OFFSET]     = ILLEGAL_REQUEST;
		buffer[offset+SPC_ASC_KEY_OFFSET]       = 0x23;
		buffer[offset+SPC_ASCQ_KEY_OFFSET]      = 0x05;
		break;
	case RC_INVALID_TOKEN_OP_AND_TOKEN_DELETED:
		buffer[offset]                          = 0x70;
		buffer[offset+SPC_ADD_SENSE_LEN_OFFSET] = 10;
		buffer[offset+SPC_SENSE_KEY_OFFSET]     = ILLEGAL_REQUEST;
		buffer[offset+SPC_ASC_KEY_OFFSET]       = 0x23;
		buffer[offset+SPC_ASCQ_KEY_OFFSET]      = 0x09;
		break;
	case RC_INVALID_TOKEN_OP_AND_TOKEN_EXPIRED:
		buffer[offset]                          = 0x70;
		buffer[offset+SPC_ADD_SENSE_LEN_OFFSET] = 10;
		buffer[offset+SPC_SENSE_KEY_OFFSET]     = ILLEGAL_REQUEST;
		buffer[offset+SPC_ASC_KEY_OFFSET]       = 0x23;
		buffer[offset+SPC_ASCQ_KEY_OFFSET]      = 0x07;
		break;
	case RC_INVALID_TOKEN_OP_AND_TOKEN_REVOKED:
		buffer[offset] = 0x70;
		buffer[offset+SPC_ADD_SENSE_LEN_OFFSET] = 10;
		buffer[offset+SPC_SENSE_KEY_OFFSET] = ILLEGAL_REQUEST;
		buffer[offset+SPC_ASC_KEY_OFFSET] = 0x23;
		buffer[offset+SPC_ASCQ_KEY_OFFSET] = 0x06;
		break;
	case RC_INVALID_TOKEN_OP_AND_TOKEN_UNKNOWN:
		buffer[offset]                          = 0x70;
		buffer[offset+SPC_ADD_SENSE_LEN_OFFSET] = 10;
		buffer[offset+SPC_SENSE_KEY_OFFSET]     = ILLEGAL_REQUEST;
		buffer[offset+SPC_ASC_KEY_OFFSET]       = 0x23;
		buffer[offset+SPC_ASCQ_KEY_OFFSET]      = 0x04;
		break;
	case RC_INVALID_TOKEN_OP_AND_UNSUPPORTED_TOKEN_TYPE:
		buffer[offset]                          = 0x70;
		buffer[offset+SPC_ADD_SENSE_LEN_OFFSET] = 10;
		buffer[offset+SPC_SENSE_KEY_OFFSET]     = ILLEGAL_REQUEST;
		buffer[offset+SPC_ASC_KEY_OFFSET]       = 0x23;
		buffer[offset+SPC_ASCQ_KEY_OFFSET]      = 0x01;
		break;
	case RC_NO_SPACE_WRITE_PROTECT:
		/* CURRENT ERROR */
		buffer[offset]				= 0x70;
		buffer[offset+SPC_ADD_SENSE_LEN_OFFSET] = 10;

		/* DATA_PROTECT */
		buffer[offset+SPC_SENSE_KEY_OFFSET]	= DATA_PROTECT;
		buffer[offset+SPC_ASC_KEY_OFFSET]	= 0x27;
		buffer[offset+SPC_ASCQ_KEY_OFFSET]	= 0x07;
		break;
	case RC_LOGICAL_UNIT_COMMUNICATION_FAILURE:
	default:
		buffer[offset]                          = 0x70;
		buffer[offset+SPC_ADD_SENSE_LEN_OFFSET] = 10;
		buffer[offset+SPC_SENSE_KEY_OFFSET]     = ILLEGAL_REQUEST;
		buffer[offset+SPC_ASC_KEY_OFFSET]       = 0x80;
		break;
	}

	return;
}

struct blk_range_data * __odx_get_br_loc_by_rod_off(
	struct tpc_token_data *s_token,
	u64 off_bytes_to_rod,
	sector_t *br_off
	)
{
	struct blk_range_data *br = NULL;
	bool found = false;
	u64 tmp_off = 0, bytes = 0;
	u32 s_bs_order = s_token->reg_data.dev_info.bs_order;

	pr_debug("off_bytes_to_rod:0x%llx\n", (unsigned long long)off_bytes_to_rod);

	tmp_off = off_bytes_to_rod;

	spin_lock_bh(&s_token->br_list_lock);

	list_for_each_entry(br, &s_token->br_list, br_node){   
		bytes = ((u64)br->nr_blks << s_bs_order);
		if (off_bytes_to_rod >= bytes){     
			off_bytes_to_rod -= bytes;	    
			pr_debug("off_bytes_to_rod:0x%llx, bytes:0x%llx, "
				"go next br\n",  
				(unsigned long long)off_bytes_to_rod,
				(unsigned long long)bytes);
			continue;
		}

		if (br->curr_status == R_STATUS_TRUNCATE_USED){
			pr_debug("found br data but status is "
				"TRUNCATED_USED\n");
			break;
		}

		/* Found the block range we want */
		pr_debug("found br. lba:0x%llx, nr_blks:0x%x, "
			"off:0x%llx (blks), curr_status:0x%x, "
			"next_status:0x%x\n", 
			(unsigned long long)br->lba, br->nr_blks,
			(unsigned long long)(off_bytes_to_rod >> s_bs_order),
			br->curr_status, br->next_status);

		/* To set the curr_status to be R_STATUS_TRANSFER_USED and
		 * next_status to be R_STATUS_NOT_USED. Actually, we will reset
		 * curr_status from next_status after this command was finished
		 * completely */
		br->curr_status = R_STATUS_TRANSFER_USED;
		br->next_status = R_STATUS_NOT_USED;
		*br_off = ((sector_t)off_bytes_to_rod >> s_bs_order);
		found = true;
		break;
	}
	spin_unlock_bh(&s_token->br_list_lock);

	if (!found)
		return NULL;

	return br;
}

int __odx_fileio_fastzero(
	struct __rw_task *task
	)
{
	/* the lba sent by host won't be aligned by linux dm-thin block size,
	 * so we need to split them to un-aligned part and aligned part
	 */
	struct __dev_info *dev_info = &task->dev_info;
	struct file *fd = dev_info->fe_info.__dev.__fd.fd_file;
	struct inode *inode = fd->f_mapping->host;
	struct ____align_desc_blk desc;
	sector_t lba, nr_blks, done_blks = 0, tmp_done_blks = 0;
	u64 nr_bytes;
	int ret = -EINVAL, idx;
	struct __rw_task tmp_task;

	if (task->dir == DMA_BIDIRECTIONAL || task->dir == DMA_NONE
	|| task->dir == DMA_FROM_DEVICE || !task->nr_bytes
	)
	{
		task->ret = -EINVAL;
		return 0;
	}

	/* we want fio + block device ... */
	if (!S_ISBLK(inode->i_mode)) {
		task->ret = -ENODEV;
		return 0;
	}

	lba = task->lba;
	nr_blks = (task->nr_bytes >> dev_info->bs_order);

	qlib_create_aligned_range_desc(&desc, lba, nr_blks, 
		dev_info->bs_order, ALIGNED_SIZE_BYTES);

	if (!desc.is_aligned) {
		/* we shall have one aligned desc when go this code ... */
		WARN_ON(true);
		task->ret = -EINVAL;
		return 0;
	}

	/* Found anyone of aligned part, try do fast zero. Due to this is
	 * fd configuration but to call block layer api, we need flush cache
	 * data then to truncate them first
	 */ 

	/* step1: flush and truncate page first */
	ret = qlib_fd_flush_and_truncate_cache(fd, lba, nr_blks, 
		dev_info->bs_order, true, dev_info->fe_info.is_thin);

	if (ret != 0) {
		task->ret = ret;
		return 0;
	}

	/* step2: do fast zero (they are 512b unit ..) */
	lba = ((desc.body.lba << dev_info->bs_order) >> 9);
	nr_blks = ((desc.body.nr_blks << dev_info->bs_order) >> 9);
	pr_debug("fast zero: lba(0x%llx), blks(0x%llx)\n", 
		(unsigned long long)desc.body.lba,
		(unsigned long long)desc.body.nr_blks);

	ret = __odx_loop_blkio_fastzero(inode->i_bdev, lba, nr_blks, 
		GFP_KERNEL, 0, &tmp_done_blks);

	done_blks += ((tmp_done_blks << 9) >> dev_info->bs_order);

	if (ret != 0)
		goto exit;

	/* step3: handle the non-aligned part */
	for (idx = 0; idx < 2; idx++) {
		if (!desc.head_tail[idx].nr_blks)
			continue;
	
		pr_debug("head_tail[%d], lba:0x%llx, blks:0x%llx\n",
			idx, (unsigned long long)desc.head_tail[idx].lba, 
			(unsigned long long)desc.head_tail[idx].nr_blks);

		nr_bytes = (desc.head_tail[idx].nr_blks << dev_info->bs_order);

		/* this condition shall never be true due to non-aligned part 
		 * size will be smaller than ALIGNED_SIZE_BYTES ...
		 */
		WARN_ON((nr_bytes > MAX_SG_LISTS_ALLOC_SIZE));

		memcpy(&tmp_task.dev_info, dev_info, sizeof(struct __dev_info));
		tmp_task.sg_list = task->sg_list;
		tmp_task.sg_nents = task->sg_nents;
		tmp_task.nr_bytes = nr_bytes;
		tmp_task.lba = desc.head_tail[idx].lba;
		tmp_task.bs_order = dev_info->bs_order;
		tmp_task.dir = DMA_TO_DEVICE;
		tmp_task.ret = 0;

		tmp_done_blks = qlib_fileio_rw(&tmp_task);
		done_blks += tmp_done_blks;

		if (tmp_task.ret != 0) {
			ret = tmp_task.ret;			
			if (ret == -ENOSPC) {
				pr_warn("%s: space was full for aligned case\n",
					__func__);
#warning "warning"
//				ret = TCM_SPACE_ALLOCATION_FAILED_WRITE_PROTECT;
			}
			goto exit;
		}

	}

exit:
	task->ret = ret;

	return (int)done_blks;
}

static int __odx_loop_blkio_fastzero(
	struct block_device *bd,
	sector_t lba,
	sector_t nr_blks,
	gfp_t gfp_mask, 
	unsigned long flags,
	sector_t *done_blks
	)
{
	sector_t work_blks = 0, __done_blks = 0;
	int ret;

	while (nr_blks) {

		work_blks = min_t(u64, nr_blks, 
			(OPTIMAL_TRANSFER_SIZE_IN_BYTES >> 9));

		ret = qlib_blkdev_issue_special_discard(bd, lba, work_blks, 
			GFP_KERNEL, 0);

		if (ret != 0) {
			pr_warn("fail from special disacrd operation. "
				"ret(%d), task_lba(0x%llx), work_blks(0x%llx), "
				"total done(0x%llx)\n",	ret,
				(unsigned long long)lba,
				(unsigned long long)work_blks,
				(unsigned long long)__done_blks);
			break;
		}

		__done_blks += work_blks;
		lba += work_blks;
		nr_blks -= work_blks;
	}

	*done_blks = __done_blks;
	return ret;
}

int __odx_blkio_fastzero(
	struct __rw_task *task
	)
{
	struct __dev_info *dev_info = &task->dev_info;
	struct block_device *bd = dev_info->fe_info.__dev.__bd.bd;
	sector_t task_lba = 0, done_blks = 0;
	sector_t expected_blks = 0;
	u32 dest_bs_order;
	int ret = -EINVAL;

	if (task->dir == DMA_BIDIRECTIONAL || task->dir == DMA_NONE
	|| task->dir == DMA_FROM_DEVICE || !task->nr_bytes
	)
	{
		task->ret = -EINVAL;	
		return 0;
	}

	dest_bs_order = dev_info->bs_order;

	/* convert to 512b unit for linux block layer */
	task_lba = ((task->lba << dest_bs_order) >> 9);
	expected_blks = (task->nr_bytes >> 9);

	ret = __odx_loop_blkio_fastzero(bd, task_lba, expected_blks, 
			GFP_KERNEL, 0, &done_blks);

	task->ret = ret;
	return (int)done_blks;

}

static int __odx_wuzt_io_before(
	struct __dev_info *info
	)
{
	struct inode *inode = NULL;
	struct block_device *bd = NULL;
	struct request_queue *q = NULL;
	struct file *f = NULL;

	if (info->fe_info.fe_type == QNAP_DT_FIO_BLK) {
		f = info->fe_info.__dev.__fd.fd_file;
		inode = f->f_mapping->host;

		if (!S_ISBLK(inode->i_mode))
			return -ENODEV;

		bd = inode->i_bdev;

	} else if (info->fe_info.fe_type == QNAP_DT_IBLK_FBDISK) {
		bd = info->fe_info.__dev.__bd.bd;
	} else
		return -ENODEV;

	/* try check block layer supports discard operation or not */
	q = bdev_get_queue(bd);
	if (!blk_queue_discard(q)){
		pr_warn("blk layer not support discard operation\n");
		return -ENODEV;
	}

	if (blk_queue_secdiscard(q)){
		pr_warn("unsupported secure-discard operation\n");
		return -ENODEV;
	}

	if (!q->limits.max_discard_sectors){
		pr_warn("max_discard_sectors of blk dev is zero\n");
		return -ENODEV;
	}

	return 0;
}

static int __odx_wuzrt_rw_io(
	struct wut_io_data *io_data,
	sector_t lba, 
	u64 *nr_bytes,
	bool *go_normal_io
	)
{
	struct tpc_token_data *d_token = io_data->d_token;
	struct __dev_info *d_dev_info = &d_token->reg_data.dev_info;
	struct __rw_task task;
	struct ____align_desc_blk desc;
	int done_blks;

	/* for write using zero ROD token operation, we use first sg only */
	task.sg_list = io_data->sg_io[0].data_sg;
	task.sg_nents = io_data->sg_io[0].data_sg_nents;
	task.nr_bytes = *nr_bytes;
	task.lba = lba;
	task.ret = 0;
	*go_normal_io = false;

	pr_debug("%s: lba(0x%llx), expected bytes(0x%llx)\n", __func__, 
		(unsigned long long)lba, (unsigned long long)*nr_bytes);

	task.bs_order = d_dev_info->bs_order;
	task.dir = DMA_TO_DEVICE;
	memcpy(&task.dev_info, d_dev_info, sizeof(struct __dev_info));

	/* check front-end type for our device */
	if (task.dev_info.fe_info.fe_type == QNAP_DT_FIO_BLK) {

		memset(&desc, 0, sizeof(struct ____align_desc_blk));

		/* We will check whether our working range needs to
		 * be aligned or not. The lba sent by host may not be
		 * aligned by dm-thin block size. If found one of desc
		 * contains aligned informatin, we go fast-zero path
		 */
		qlib_create_aligned_range_desc(&desc, task.lba, 
			(task.nr_bytes >> task.dev_info.bs_order), 
			task.dev_info.bs_order, ALIGNED_SIZE_BYTES);

		/* only do fast-zero if found any aligned block */
		if (!desc.is_aligned) {
			*go_normal_io = true;
			return -ENOTSUPP;
		}

		done_blks = __odx_fileio_fastzero(&task);

	}
	else if (task.dev_info.fe_info.fe_type == QNAP_DT_IBLK_FBDISK) {
		done_blks = __odx_blkio_fastzero(&task);
	}
	else {
		pr_warn("unsupported fe_type(%d)\n", 
				task.dev_info.fe_info.fe_type);

		done_blks = 0;
		task.ret = -ENODEV;
		return -ENODEV;
	}

	/* update final result */
	*nr_bytes = (u64)done_blks << task.bs_order;

	if (*nr_bytes != task.nr_bytes)
		pr_warn("%s: expected bytes(0x%llx) not same as done_bytes(0x%llx)\n",  
			__func__, (unsigned long long)task.nr_bytes, 
			(unsigned long long)*nr_bytes);

	if (task.ret != 0)
		pr_warn("%s: task.ret(%d)\n", __func__, task.ret);

	return task.ret;

}

/**
 * __odx_wut_rw_io - execute R/W io for WUT command
 * @io_data:    pointer to io structure for WUT
 * @lba:        start lba to write or read
 * @nr_bytes:   For input parameter, it is expected nr bytes to write to or
 *              read from.
 *              For output parameter, it will be upadted to nr bytes to write
 *              to or read from.
 * @is_write:   flag indicates this is write or read
 *
 * Return:
 *     Return value (task->ret) is execution result for read or write
 **/
static int ____odx_wut_rw_io(
	struct wut_io_data *io_data,
	int sg_idx,
	sector_t lba, 
	u64 *nr_bytes,
	bool is_write
	)
{
	struct tpc_token_data *s_token = io_data->s_token;
	struct tpc_token_data *d_token = io_data->d_token;
	struct __dev_info *s_dev_info = &s_token->reg_data.dev_info;
	struct __dev_info *d_dev_info = &d_token->reg_data.dev_info;
	struct __rw_task task;
	int done_blks;

	task.sg_list = io_data->sg_io[sg_idx].data_sg;
	task.sg_nents = io_data->sg_io[sg_idx].data_sg_nents; 

	/* task.nr_bytes will be smaller than or equal to sg_io[sg_idx].data_len */
	task.nr_bytes = *nr_bytes;
	task.lba = lba;
	task.ret = 0;

	WARN_ON((task.nr_bytes > io_data->sg_io[sg_idx].data_len));

	pr_debug("%s: write(%d), lba(0x%llx), expected bytes(0x%llx)\n", 
		__func__, is_write, (unsigned long long)lba, 
		(unsigned long long)*nr_bytes);

	if (is_write) {
		task.bs_order = d_dev_info->bs_order;
		task.dir = DMA_TO_DEVICE;
		memcpy(&task.dev_info, d_dev_info, sizeof(struct __dev_info));
	} else {
		task.bs_order = s_dev_info->bs_order;
		task.dir = DMA_FROM_DEVICE;
		memcpy(&task.dev_info, s_dev_info, sizeof(struct __dev_info));
	}

	/* check front-end type for our device */
	if (task.dev_info.fe_info.fe_type == QNAP_DT_FIO_BLK) {

		done_blks = qlib_fileio_rw(&task);
	} else if (task.dev_info.fe_info.fe_type == QNAP_DT_IBLK_FBDISK) {

		done_blks = qlib_blockio_rw(&task);
	} else {
		pr_warn("unsupported fe_type(%d)\n", 
				task.dev_info.fe_info.fe_type);

		done_blks = 0;
		task.ret = -ENODEV;
		return task.ret;
	}

	/* update final result */
	*nr_bytes = (u64)done_blks << task.bs_order;

	if (*nr_bytes != task.nr_bytes)
		pr_warn("%s expected bytes(0x%llx) not same as "
			"%s done_bytes(0x%llx)\n",  
			((is_write)? "write" : "read"),
			(unsigned long long)task.nr_bytes, 
			((is_write)? "write" : "read"),
			(unsigned long long)*nr_bytes);

	if (task.ret != 0)
		pr_warn("%s: task.ret(%d)\n", __func__, task.ret);

	return task.ret;
}

static void __odx_wut_rw_io_work(
	struct work_struct *work
	)
{
	struct __cb_data *p = NULL;
	u64 ori_nr_bytes;
	int ret;

	struct wut_io_work_data *work_data = 
		container_of(work, struct wut_io_work_data, wut_io_work);

	p = work_data->cb_data;
	ori_nr_bytes = work_data->nr_bytes;

	ret = ____odx_wut_rw_io(work_data->io_data, work_data->sg_idx, 
		work_data->start_lba, &work_data->nr_bytes, work_data->is_write);

	/* only treat it is OK for this case ... */
	if ((ori_nr_bytes == work_data->nr_bytes && !ret)) {
		work_data->transfer_done = true;
		goto exit;
	}

	if (ori_nr_bytes != work_data->nr_bytes) {
		pr_warn("wq idx:%d, %s expected bytes(0x%llx) not same as "
			"%s done_bytes(0x%llx), ret:%d\n",  
			work_data->sg_idx,
			((work_data->is_write)? "write" : "read"),
			(unsigned long long)ori_nr_bytes, 
			((work_data->is_write)? "write" : "read"),
			(unsigned long long)work_data->nr_bytes, ret);
	}

	if ((ret != 0) && (ret == -ENOSPC))
		p->nospc_err = 1;

	work_data->transfer_done = false;
	atomic_inc(&p->bio_err_count);
	smp_mb__after_atomic();

exit:
	if (atomic_dec_and_test(&p->bio_count))
		complete(p->wait);

}

static int __odx_wut_rw_io(
	struct wut_io_data *io_data,
	sector_t lba, 
	u64 *nr_bytes,
	bool is_write,
	bool go_wq
	)
{
	DECLARE_COMPLETION_ONSTACK(wait);
	struct tpc_token_data *token = NULL;
	struct __dev_info *dev_info = NULL;
	struct wut_io_work_data *work_data = NULL, *tmp_work_data = NULL;
	struct sg_io_data *sg_io = NULL;
	struct __cb_data cb_data;
	struct list_head io_lists;
	sector_t start_lba = lba;
	u64 done_bytes = 0, tmp_bytes;
	int i, ret = 0;

	token = ((is_write) ? io_data->d_token : io_data->s_token);
	dev_info = &token->reg_data.dev_info;

	/* use first sg if no any dev_wq */
	if (!go_wq)
		return ____odx_wut_rw_io(io_data, 0, lba, nr_bytes, is_write);

	/* === here is wq way === */
	tmp_bytes = *nr_bytes; 
	INIT_LIST_HEAD(&io_lists);
	qlib_init_cb_data(&cb_data, &wait);	

	for (i = 0; i < MAX_SG_IO_DATA_COUNT; i++) {
		sg_io = &io_data->sg_io[i];

		/* 1st sg shall not be null ... */
		if (!sg_io->data_sg)
			break;

		work_data = kzalloc(sizeof(struct wut_io_work_data), GFP_KERNEL);
		if (!work_data)
			break;

		/* prepare sg for each one */
		INIT_LIST_HEAD(&work_data->node);
		work_data->io_data = io_data;
		work_data->cb_data = &cb_data;
		work_data->is_write = is_write;
		work_data->sg_idx = i;
		work_data->start_lba = start_lba;
		work_data->nr_bytes = ((tmp_bytes >= sg_io->data_len) ? \
						sg_io->data_len : tmp_bytes);

		work_data->transfer_done = false;
		INIT_WORK(&work_data->wut_io_work, __odx_wut_rw_io_work);

		atomic_inc(&(cb_data.bio_count));
		list_add_tail(&work_data->node, &io_lists);

		/* convert to suitable lba unit for src or dest */
		start_lba += (work_data->nr_bytes >> dev_info->bs_order);

		tmp_bytes -= work_data->nr_bytes;
		if (!tmp_bytes)
			break;

	}

	WARN_ON(tmp_bytes);

	/* submit wq io */
	list_for_each_entry(work_data, &io_lists, node)
		queue_work(io_data->odx_wq, &work_data->wut_io_work);

	/* to wait all tasks to be completed */
	if (!atomic_dec_and_test(&(cb_data.bio_count))) {
		while (wait_for_completion_timeout(&wait, 
				msecs_to_jiffies(3 * 1000)) == 0)
			pr_debug("%s: wait odx wut-io wq to be done\n", __func__);
	}

	/* get real done bytes here */
	list_for_each_entry(work_data, &io_lists, node) {
		/* break if found anyone is false */
		if (work_data->transfer_done == false)
			break;
		done_bytes += work_data->nr_bytes;
	}

	/* free all buffer */
	list_for_each_entry_safe(work_data, tmp_work_data, &io_lists, node) {
		list_del_init(&work_data->node);
		kfree(work_data);
	}

	if (atomic_read(&cb_data.bio_err_count)) {
		if (cb_data.nospc_err)
			ret = -ENOSPC;
		else
			ret = -EIO;
	}

	*nr_bytes = done_bytes;
	return ret;

}

static int __odx_loop_wuzrt_io(
	struct wut_io_data *io_data,
	bool is_thin,
	bool go_wq
	)
{
	struct tpc_token_data *d_token;
	u32 dest_bs_order;
	u64 tmp_wbytes = io_data->nr_bytes, e_bytes, done_bytes, total_sg_lens = 0;
	sector_t dest_lba = io_data->dest_lba;
	int ret = 0, cmd_abort = 0;
	bool go_normal_io;
	RC rc;

	d_token = io_data->d_token;
	dest_bs_order = d_token->reg_data.dev_info.bs_order;

	while (tmp_wbytes){

		e_bytes = tmp_wbytes;
		done_bytes = 0;

		if (__odx_cmd_was_asked_drop(io_data->tc_p)) {
			io_data->rc = RC_GOOD;
			cmd_abort = 1;
			goto check_1;
		}

		if (is_thin) {
			/* if thin dev, we will write all blks via special api */
			done_bytes = e_bytes;

			ret = __odx_wuzrt_rw_io(io_data, dest_lba, &done_bytes, 
					&go_normal_io);

			if (!go_normal_io)
				goto check_0;

			/* fall-through if need to go normal io path */
		} 

		/* again to check exceeds total sg data len */
		if (!go_wq)
			total_sg_lens = io_data->sg_io[0].data_len;
		else
			total_sg_lens = odx_get_total_sg_len(&io_data->sg_io[0]);

		done_bytes = e_bytes = ((e_bytes >= total_sg_lens) ? \
						total_sg_lens : e_bytes);

		/* ===== write to destination ===== */
		ret = __odx_wut_rw_io(io_data, dest_lba, &done_bytes, true, go_wq);

check_0:
		if (ret < 0) {
			if (ret == -ENOSPC)
				io_data->rc = RC_NO_SPACE_WRITE_PROTECT;
			else
				io_data->rc = RC_3RD_PARTY_DEVICE_FAILURE;
			goto check_1;
		}

		if (e_bytes != done_bytes) {
			io_data->rc = RC_3RD_PARTY_DEVICE_FAILURE;
			ret = -EIO;
		}

check_1:
		if (io_data->rc != RC_NO_SPACE_WRITE_PROTECT)
			__odx_lock_update_tc_cmd_transfer_count(io_data->tc_p, 
				((sector_t)done_bytes >> dest_bs_order));

		if (ret || cmd_abort)
			break;

		dest_lba += ((sector_t)done_bytes >> dest_bs_order);
		tmp_wbytes -= done_bytes;
	}


	if (!tmp_wbytes) {
		io_data->rc = RC_GOOD;
		ret = 0;
	}

	return ret;


}

static int __odx_loop_wut_io(
	struct wut_io_data *io_data,
	bool is_thin,
	bool go_wq
	)
{
	struct tpc_token_data *s_token, *d_token;
	u32 src_bs_order, dest_bs_order;
	u64 tmp_wbytes = io_data->nr_bytes, tmp, e_bytes, done_bytes;
	sector_t src_lba, dest_lba = io_data->dest_lba;
	u64 off_bytes_to_rod = io_data->s_rod_off_bytes, total_sg_lens = 0;
	sector_t br_off;
	struct blk_range_data *br;
	int ret = 0, cmd_abort = 0;
	RC rc;

	s_token = io_data->s_token;
	d_token = io_data->d_token;
	src_bs_order = s_token->reg_data.dev_info.bs_order;
	dest_bs_order = d_token->reg_data.dev_info.bs_order;

	while (tmp_wbytes){

		done_bytes = 0;

		/* To get the br location by rod offset for src side */
		br = __odx_get_br_loc_by_rod_off(s_token, 
			off_bytes_to_rod, &br_off);

		if (!br) {
			pr_warn("%s: not found br\n", __func__);
			io_data->rc = RC_UNREACHABLE_COPY_TARGET;
			ret = -EINVAL;
			goto err;
		}

		src_lba = br->lba + br_off;

		/* To check source token is invalid or not before to
		 * read. If the source token is invalid, here won't
		 * update any data for src token, what we will do is
		 * to udpate dest token only 
		 */
		ret = __odx_is_token_invalid(s_token, &rc);
		if (ret != 0) {
			pr_debug("s_token (id:0x%x, sac:0x%x) is invalid, rc:%d\n", 
				s_token->reg_data.list_id, s_token->reg_data.sac, rc);
			io_data->rc = rc;
			goto err;
		}

		if (__odx_cmd_was_asked_drop(io_data->tc_p)) {
			io_data->rc = RC_GOOD;
			cmd_abort = 1;
			goto err;
		}

		/* To check whether the write range execeeds the 
		 * (br->nr_blks - br_off) or not
		 */
		tmp = ((u64)(br->nr_blks - br_off) << src_bs_order);

		e_bytes = ((tmp_wbytes >= tmp) ? tmp : tmp_wbytes);

		/* again to check exceeds sg data len 
		 * for wq case, we us all sg. for non-wq case, use one only
		 */
		if (go_wq)
			total_sg_lens = odx_get_total_sg_len(&io_data->sg_io[0]);
		else
			total_sg_lens = io_data->sg_io[0].data_len;

		e_bytes = ((e_bytes >= total_sg_lens) ? total_sg_lens : e_bytes);

		done_bytes = e_bytes;

		/* ===== read from source first ===== */
		ret = __odx_wut_rw_io(io_data, src_lba, &done_bytes, false, go_wq);
		if (ret < 0) {
			io_data->rc = RC_3RD_PARTY_DEVICE_FAILURE;
			goto err;
		}

		/* if can't read completely, we still need to write ... */
		if (e_bytes != done_bytes)
			e_bytes = done_bytes;

		/* ===== write to destination ===== */
		ret = __odx_wut_rw_io(io_data, dest_lba, &done_bytes, true, go_wq);
		if (ret < 0) {
			if (ret == -ENOSPC)
				io_data->rc = RC_NO_SPACE_WRITE_PROTECT;
			else
				io_data->rc = RC_3RD_PARTY_DEVICE_FAILURE;
			goto err;
		}

		if (e_bytes != done_bytes) {
			io_data->rc = RC_3RD_PARTY_DEVICE_FAILURE;
			ret = -EIO;
		}

err:
		if (io_data->rc != RC_NO_SPACE_WRITE_PROTECT)
			__odx_lock_update_tc_cmd_transfer_count(io_data->tc_p, 
				((sector_t)done_bytes >> dest_bs_order));

		if (ret || cmd_abort)
			break;

		off_bytes_to_rod += done_bytes;
		dest_lba += ((sector_t)done_bytes >> dest_bs_order);
		tmp_wbytes -= done_bytes;
	}


	if (!tmp_wbytes) {
		io_data->rc = RC_GOOD;
		ret = 0;
	}

	return ret;

}

static bool __odx_check_run_wq(
	struct odx_work_request *odx_wr,
	u32 src_type,
	u32 dest_type,
	bool run_wuzrt
	)
{
	bool run_wq = false;

	if (!odx_wr->odx_wq)
		return run_wq;

	if (run_wuzrt) {
		if (dest_type == QNAP_DT_FIO_BLK)
			run_wq = true;
	} else {
		/* check to run wq or not, if src and dest are block based lun, 
		 * we go wq way 
		 */
		if ((src_type == QNAP_DT_FIO_BLK) && (dest_type == QNAP_DT_FIO_BLK))
			run_wq = true;
	}

	return run_wq;

}

int __odx_wut_io(
	struct odx_work_request *odx_wr,
	struct tpc_token_data *s_token_p,
	struct tpc_token_data *d_token_p,
	bool run_wuzrt
	)
{
	struct write_by_token_param *p = 
		(struct write_by_token_param *)odx_wr->buff;

	struct blk_dev_range_desc *s = NULL;
	struct __dev_info *info = &odx_wr->reg_data.dev_info;
	u32 dest_bs_order = info->bs_order;
	sector_t d_nr_blks = 0, dest_lba = 0;
	u32 dest_w_nr_blks = 0;
	u16 desc_counts = 0, idx = 0;
	u64 w_nr_bytes = 0, off_bytes_to_rod = 0;
	struct wut_io_data io_data;
	int ret = -EINVAL;
	bool go_wq = false, cmd_abort = false;
	struct __dev_info *src_dev_info, *dest_dev_info;
#ifdef SUPPORT_FAST_BLOCK_CLONE
	bool src_support_fbc = false, dest_support_fbc = false;
#endif

	/* check something if device is thin type and run_wuzrt is true */
	if (run_wuzrt && info->fe_info.is_thin) {
		ret = __odx_wuzt_io_before(info);
		if (ret != 0) {
			odx_wr->rc = RC_3RD_PARTY_DEVICE_FAILURE;
			return ret;
		}
	}

	dest_dev_info = &d_token_p->reg_data.dev_info;	

	if (!run_wuzrt) {
		src_dev_info = &s_token_p->reg_data.dev_info;

#ifdef SUPPORT_FAST_BLOCK_CLONE
		/* here, we safe to use d_token_p since its reg_data was
		 * created from odx_core_wut() already
		 */
		src_support_fbc = SUPPORT_FBC(src_dev_info->dev_attr, 
			(DEV_ATTR_SUPPORT_DM_FBC | DEV_ATTR_SUPPORT_DEV_FBC));
		dest_support_fbc = SUPPORT_FBC(dest_dev_info->dev_attr, 
			(DEV_ATTR_SUPPORT_DM_FBC | DEV_ATTR_SUPPORT_DEV_FBC));
#endif
		go_wq = __odx_check_run_wq(odx_wr, src_dev_info->fe_info.fe_type,
				dest_dev_info->fe_info.fe_type, run_wuzrt);

	} else {
		go_wq = __odx_check_run_wq(odx_wr, 0,
				dest_dev_info->fe_info.fe_type, run_wuzrt);
	}

	/* The block dev range desc length shall be a multiple of 16 */
	s = (struct blk_dev_range_desc *)((u8 *)p + \
		sizeof(struct write_by_token_param));

	desc_counts = __odx_get_desc_counts(
			get_unaligned_be16(&p->blkdev_range_desc_len[0]));

	d_nr_blks = __odx_get_total_nr_blks_by_desc(s, desc_counts);

	off_bytes_to_rod = 
		(get_unaligned_be64(&p->off_into_rod[0]) << dest_bs_order);
	
	for (idx = 0; idx < desc_counts; idx++){
	
		if (get_unaligned_be32(&s[idx].nr_blks[0]) == 0)
			continue;
	
		dest_lba = get_unaligned_be64(&s[idx].lba[0]);
		dest_w_nr_blks = get_unaligned_be32(&s[idx].nr_blks[0]);
		w_nr_bytes = (u64)dest_w_nr_blks << dest_bs_order;

		pr_debug("idx(0x%x), dest lba(0x%llx), nr_blks(0x%llx)\n",
			idx, (unsigned long long)dest_lba, 
			(unsigned long long)dest_w_nr_blks);

		memset(&io_data, 0, sizeof(struct wut_io_data));

		io_data.nr_bytes = w_nr_bytes;
		io_data.s_rod_off_bytes = off_bytes_to_rod;
		io_data.dest_lba = dest_lba;
		io_data.dest_bs_order = dest_bs_order;

		memcpy(&io_data.sg_io[0], &odx_wr->sg_io[0], 
			(sizeof(struct sg_io_data) * MAX_SG_IO_DATA_COUNT));

		io_data.odx_wq = odx_wr->odx_wq;
		io_data.rc = RC_GOOD;
		io_data.s_token = s_token_p;
		io_data.d_token = d_token_p;	
		io_data.tc_p = odx_wr->tc_p;

		/* break loop if can't complete one full descriptor */
		if (run_wuzrt)
			ret = __odx_loop_wuzrt_io(&io_data, info->fe_info.is_thin, go_wq);
		else {

#ifdef SUPPORT_FAST_BLOCK_CLONE
			if (src_support_fbc && dest_support_fbc) {
				ret = qnap_do_fast_block_clone_odx(&io_data);

				if (((io_data.rc == RC_GOOD) && (ret == 0))
					|| ((io_data.rc != RC_GOOD) && (ret != 0))
				) 
					goto next;

				/* go normal path if (rc = RC_GOOD && ret != 0) 
				 * and, we still go wq way
				 */
			}
#endif
			ret = __odx_loop_wut_io(&io_data, info->fe_info.is_thin, go_wq);
		}
next:

		cmd_abort = __odx_cmd_was_asked_drop(odx_wr->tc_p); 

		if (ret || cmd_abort) {
			if (cmd_abort) {
				pr_warn("odx cmd (list id:0x%x) "
				"was asked to drop\n", odx_wr->tc_p->reg_data.list_id);
			}

			odx_wr->rc = io_data.rc;			
			break;
		}
		off_bytes_to_rod += w_nr_bytes;
	}

	return ret;

}

int odx_alloc_cache_res(void)
{

	odx_tpg_data_cache = kmem_cache_create("odx_tpg_data_cache", 
			sizeof(struct tpc_tpg_data),
			__alignof__(struct tpc_tpg_data), 0, NULL);

	if (!odx_tpg_data_cache) {
		pr_err("unable to create odx_tpg_data_cache\n");
		goto _exit_;
	}

	odx_cmd_data_cache = kmem_cache_create("odx_cmd_data_cache", 
			sizeof(struct tpc_cmd_data),
			__alignof__(struct tpc_cmd_data), 0, NULL);

	if (!odx_cmd_data_cache) {
		pr_err("unable to create odx_cmd_data_cache\n");
		goto _exit_;
	}

	odx_token_data_cache = kmem_cache_create("odx_token_data_cache", 
			sizeof(struct tpc_token_data),
			__alignof__(struct tpc_token_data), 0, NULL);

	if (!odx_token_data_cache) {
		pr_err("unable to create odx_token_data_cache\n");
		goto _exit_;
	}

	token512b_cache = kmem_cache_create("token512b_cache",
			sizeof(struct rod_token_512b),
			__alignof__(struct rod_token_512b), 0, NULL);

	if (!token512b_cache) {
		pr_err("unable to create token512b_cache\n");
		goto _exit_;
	}


	odx_br_cache = kmem_cache_create("odx_br_cache",
		sizeof(struct blk_range_data),
		__alignof__(struct blk_range_data), 0, NULL);

	if (!odx_br_cache) {
		pr_err("unable to create odx_br_cache\n");
		goto _exit_;
	}

	return 0;

_exit_:
	odx_free_cache_res();

	return -ENOMEM;

}

void odx_free_cache_res(void)
{
	if (odx_tpg_data_cache)
		kmem_cache_destroy(odx_tpg_data_cache);

	if (odx_cmd_data_cache)
		kmem_cache_destroy(odx_cmd_data_cache);

	if (odx_token_data_cache)
		kmem_cache_destroy(odx_token_data_cache);

	if (token512b_cache)
		kmem_cache_destroy(token512b_cache);

	if (odx_br_cache)
		kmem_cache_destroy(odx_br_cache);
}

struct workqueue_struct *odx_alloc_wut_io_wq(
	char *name,
	int idx
	)
{
	return alloc_workqueue("QNAPodx_%s%d",
			(WQ_HIGHPRI |WQ_SYSFS | WQ_MEM_RECLAIM | WQ_UNBOUND), 0, 
			name, idx);
}

void odx_destroy_wut_io_wq(
	struct workqueue_struct *wq
	)
{
	if (wq) {
		flush_workqueue(wq);
		destroy_workqueue(wq);
	}
}

void odx_alloc_sg_lists(
	struct odx_work_request *req,
	bool use_wq
	)
{
	struct sg_io_data *sg_io = &req->sg_io[0];
	int i;

	sg_io[0].data_len = MAX_ODX_WR_DATA_LEN;
	sg_io[0].data_sg = qlib_alloc_sg_list(&sg_io[0].data_len, 
				&sg_io[0].data_sg_nents);

	if (!use_wq)
		return;

	for (i = 1; i < MAX_SG_IO_DATA_COUNT; i++) {
		sg_io[i].data_len = MAX_ODX_WR_DATA_LEN;
		sg_io[i].data_sg = qlib_alloc_sg_list(&sg_io[i].data_len, 
					&sg_io[i].data_sg_nents);

		if (!sg_io[i].data_sg)
			break;
	}

}

void odx_free_sg_lists(
	struct odx_work_request *req
	)
{
	struct sg_io_data *sg_io = &req->sg_io[0];
	int i;

	for (i = 0; i < MAX_SG_IO_DATA_COUNT; i++) {
		if (sg_io[i].data_sg)
			qlib_free_sg_list(sg_io[i].data_sg, sg_io[i].data_sg_nents);
	}
}


