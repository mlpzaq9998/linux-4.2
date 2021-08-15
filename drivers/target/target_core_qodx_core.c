/*******************************************************************************
 * Filename:  target_core_qodx_core.c
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
#include "target_core_qlib.h"
#include "target_core_qodx_lib.h"

/**/
static int __odx_core_rrti_s2_update_by_token(
	struct tpc_token_data *token,
	void *buff,
	bool attached_rod_token,
	u32 alloc_len
	)
{
	struct rod_token_info_param *param = (struct rod_token_info_param *)buff;
	u8 *p = NULL;
	int d4_sense_len = 0;

	if (alloc_len == 0)
		return -EINVAL;

	/* FIXED ME !! */
	if ((token->cp_op_status == OP_COMPLETED_WO_ERR)
	||  (token->cp_op_status == OP_COMPLETED_W_ERR)
	||  (token->cp_op_status == OP_COMPLETED_WO_ERR_WITH_ROD_TOKEN_USAGE)
	||  (token->cp_op_status == OP_COMPLETED_WO_ERR_BUT_WITH_RESIDUAL_DATA)
	||  (token->cp_op_status == OP_TERMINATED)
	)
	{
		/* alloc_len had been limited to __odx_get_min_rrti_param_len() */
		d4_sense_len = alloc_len - (ROD_TOKEN_MIN_SIZE + 2) - 4 - 32;

		param->res_to_sac = (u8)token->reg_data.sac;    
		param->cp_op_status = token->cp_op_status;
		put_unaligned_be16(token->op_counter, &param->op_counter[0]);
		put_unaligned_be32(0xfffffffe, 
			&param->estimated_status_update_delay[0]);

		param->extcp_completion_status = token->completion_status;

		if (token->cp_op_status  == OP_TERMINATED)
			param->sense_data_len_field = param->sense_data_len = 0;
		else {
			param->sense_data_len = 
				min_t(int, ROD_SENSE_DATA_LEN, d4_sense_len);

			param->sense_data_len_field = param->sense_data_len;
		}

		param->transfer_count_units = UNIT_NA;

		put_unaligned_be16(token->segs_processed, &param->seg_processed[0]);
		put_unaligned_be64(token->transfer_count, &param->transfer_count[0]);

		/* go to sense data field */
		p = (u8*)((size_t)param + sizeof(struct rod_token_info_param));
		if ((param->sense_data_len_field != 0)
		&& (param->sense_data_len != 0)
		)
		{
  			/* To update the sense data to parameter buffer */
			memcpy(p, &token->sense_data[0], param->sense_data_len);

			/* go to rod token descriptor length field */
			p = (u8*)((size_t)p + param->sense_data_len);
			put_unaligned_be32(0, &p[0]);

			/* SPC4R36, page 431 */
			if ((token->cp_op_status == OP_COMPLETED_WO_ERR)
			||  (token->cp_op_status == OP_COMPLETED_WO_ERR_WITH_ROD_TOKEN_USAGE)
			)
			{
				if ((attached_rod_token == 1) && (token->token))
				{
					/* To set the rod token descriptor 
					 * length if cp_op_status is w/o 
					 * any error */
					put_unaligned_be32(
						(ROD_TOKEN_MIN_SIZE + 2), &p[0]);

					/* SPC4R36, page 431 
					 * If the response to service action 
					 * field is not 0x0 or 0x1, the 
					 * ID FOR CREATING ROD CSCD DESCRIPTOR 
					 * field shall be reserved.
					 */
					memcpy(&p[4 + 2], token->token, 
						ROD_TOKEN_MIN_SIZE);
				}
			}
		}

		put_unaligned_be32((alloc_len - 4), 
			&param->avaiable_data_len[0]);
		return 0;
	}

	/* The code shall NEVER come here !! */
	WARN_ON(1);

	return -EINVAL;
}

static int __odx_core_rrti_s1_update_by_tc_data(
	struct tpc_cmd_data *data,
	void *buff,
	T_CMD_STATUS status
	)
{
	struct rod_token_info_param *param = (struct rod_token_info_param *)buff;

	/* If call this function to build the RECEIVE ROD TOKEN INFORMATION
	 * parameter data, it means the command matched with list id in
	 * RECEIVE ROD TOKEN INFORMATION is still processing now ...
	 */

	if ((status == T_CMD_IS_STARTING_IN_FG)
 	||  (status == T_CMD_IS_STARTING_IN_BG)
 	||  (status == T_CMD_WAS_ABORTED)
 	)
 	{
		param->res_to_sac = (u8)data->reg_data.sac;

		/* SPC4R36, page 424 */
		if (status == T_CMD_IS_STARTING_IN_FG)
			param->cp_op_status = OP_IN_PROGRESS_WITHIN_FG;
		else if (status == T_CMD_IS_STARTING_IN_BG)
			param->cp_op_status = OP_IN_PROGRESS_WITHIN_BG;
		else
			param->cp_op_status = OP_TERMINATED;

		/* FIXED ME !! 
		 * All data set below shall be checked again
		 */

		put_unaligned_be16(data->op_counter, &param->op_counter[0]);
		put_unaligned_be32(ESTIMATE_STATUS_UPDATE_DELAY, 
			&param->estimated_status_update_delay[0]);

		if (param->cp_op_status == OP_TERMINATED)
			put_unaligned_be32(0xfffffffe, 
				&param->estimated_status_update_delay[0]);

		/* the extcp_completion_status field ONLY be set if
		 * cp_op_status is 0x01,0x02,0x03,0x04 or 0x60
		 */
		if (param->cp_op_status == OP_TERMINATED)
			param->extcp_completion_status = SAM_STAT_TASK_ABORTED;

		param->sense_data_len_field = param->sense_data_len = 0x0;

		/* SPC4R36, page 425 */
		param->transfer_count_units = UNIT_NA;

		spin_lock(&data->transfer_count_lock);
		put_unaligned_be64(data->transfer_count, &param->transfer_count[0]);
		spin_unlock(&data->transfer_count_lock);

		put_unaligned_be16(data->segs_processed, &param->seg_processed[0]);

		/* SPC4R36, page 430 (or SBC3R31, page 155) */
		put_unaligned_be32((32-4), &param->avaiable_data_len[0]);
		return 0;

	}

	WARN_ON(1);
	return -EINVAL;

}



static int __odx_core_rrti_s2(
	struct odx_work_request *odx_wr
	)
{
	struct tpc_token_data *token_p = NULL;
	int ret = 0, count = 0;
	u8 *cdb = odx_wr->cdb;
	u32 alloc_len_in_cdb = get_unaligned_be32(&cdb[10]);

	token_p = odx_rb_token_get(odx_wr->tpg_p, odx_wr->reg_data.cmd_id_hi,
			odx_wr->reg_data.cmd_id_lo, 
			odx_wr->reg_data.initiator_id_hi,
			odx_wr->reg_data.initiator_id_lo,
			true
			);
	if (!token_p) {	
		pr_warn("RRTI s2: not found token\n");
		odx_wr->rc = RC_INVALID_CDB_FIELD;
		return -ENODEV;
	}

	if (alloc_len_in_cdb == 0){
		/* FIXED ME !! 
		 * SPC4R36, page 428
		 *
		 * b)
		 * if a RECEIVE ROD TOKEN INFORMATION command
		 * has been received on the same I_T nexus with
		 * a matching list id with the ALLOCATION LENGTH
		 * field set to zero
		 */
		pr_warn("RRTI s2: warning, discard token (list id:0x%x, "
			"sac:0x%x) when alloc_len_in_cdb is zero ... \n", 
			token_p->reg_data.list_id, token_p->reg_data.sac);

		/* delete token */
		__odx_cmpxchg_token_status(token_p, O_TOKEN_ALIVE, O_TOKEN_CANCELLED);

		do {
			count = odx_rb_token_put(token_p);
			if (count == 1)
				break;

			pr_warn("RRTI s2: token refcount not 1, it is still using "
				"by someone, wait next chance\n");
			cpu_relax();
		} while (1);

		/* we don't delete token here due to timer will conver this.
		 * and, token won't be picked up since it was cancelled
		 */
		odx_wr->rc = RC_INVALID_TOKEN_OP_AND_TOKEN_DELETED;
		return -EINVAL;

	}

	/* Since found the token already, here to check the status
	 * of obj and token before to prepare the parameter
	 * data for RECEIVE ROD TOKEN INFORMATION command
	 */
	ret = __odx_is_token_invalid(token_p, &odx_wr->rc);
	if (ret == -ENODEV) {
		pr_warn("RRTI s2: warning token (list id:0x%x, sac:0x%x) "
			"was NOT alive, rc:%d\n", token_p->reg_data.list_id, 
			token_p->reg_data.sac, odx_wr->rc);

		/* even token was invalid, we still copy data to client for
		 * reporting purpose
		 */
	}

	ret = __odx_core_rrti_s2_update_by_token(token_p, odx_wr->buff, true, 
		       alloc_len_in_cdb);

	if (ret != 0){
		odx_wr->rc = RC_INVALID_PARAMETER_LIST;
		ret = -EINVAL;
	} else
		odx_wr->rc = RC_GOOD;

	odx_rb_token_put(token_p);
	return ret;
}

static int __odx_core_rrti_s1(
	struct odx_work_request *odx_wr
	)
{
	T_CMD_STATUS status = MAX_T_CMD_STATUS;
	struct tpc_cmd_data *tc_p;
	int ret = 0;

	/* list id in RRTI will be used to track previous ODX cmd (PT or WUT), 
	 * so following steps will try to get (everything was setup from caller 
	 * already) and here to skip to check sac (reaosn is we need get same 
	 * list id)
	 */
	tc_p = odx_rb_cmd_get(odx_wr->tpg_p, &odx_wr->reg_data, false, true);
	if (!tc_p) {
		/* if can't get command, the cmd may be completed, we will try
		 * to search from token tree again
		 */
		pr_debug("odx (list id:0x%x) not found in RRTI phase 1, " 
			"it may be completed, go RRTI phase 2\n", 
			odx_wr->reg_data.list_id);
			
		odx_wr->rc = RC_GOOD;
		return -ENODEV;
	}	

	status = __odx_get_tc_data_status(tc_p);

	if (T_CMD_IS_NOT_START(status)){
		/* FIXED ME 
		 * If we found the matched list id in tracking list
		 * and matched command is not working now, then to
		 * report error
		 */
		pr_warn("odx (list id:0x%x, sac:0x%x) not "
			"start work yet\n", tc_p->reg_data.list_id, 
			tc_p->reg_data.sac);

		odx_wr->rc = RC_INVALID_PARAMETER_LIST;
		ret = -EINVAL;
	}
	else if (T_CMD_IS_START_FG(status) || T_CMD_IS_START_BG(status)
		|| T_CMD_WAS_ABORT(status) // <-- FIXED ME !!!!
	)
	{
		/* if cmd is still in processing or has been aborted */
		pr_warn("odx (list id:0x%x, sac:0x%x) is in "
			"process now\n", tc_p->reg_data.list_id, 
			tc_p->reg_data.sac);

		ret = __odx_core_rrti_s1_update_by_tc_data(tc_p, odx_wr->buff, 
				status);

		if (ret != 0)
			odx_wr->rc = RC_INVALID_PARAMETER_LIST;
		else
			odx_wr->rc = RC_GOOD;
	}
	else if (T_CMD_WAS_COMPLETED_W_ERR(status)
	|| T_CMD_WAS_COMPLETED_WO_ERR(status)
	)
	{
		/* if cmd was completed, to break loop of step 1 then
		 * go to step 2
		 */
		pr_debug("odx (list id:0x%x, sac:0x%x) was "
			"completed, go RRTI phase 2\n", 
			tc_p->reg_data.list_id, tc_p->reg_data.sac);

		odx_wr->rc = RC_GOOD;
		ret = -ENODEV;
	}
	else {
		pr_warn("odx (list id:0x%x, sac:0x%x) is unknown status\n", 
			tc_p->reg_data.list_id, tc_p->reg_data.sac);

		odx_wr->rc = RC_INVALID_PARAMETER_LIST;
		ret = -EINVAL;
	}

	odx_rb_cmd_put(tc_p);

	return ret;
}

static int __odx_core_pt_io(
	struct odx_work_request *odx_wr, 
	struct tpc_token_data *token_p
	)
{
	LIST_HEAD(br_list);
	struct populate_token_param *param = 
		(struct populate_token_param *)odx_wr->buff;

	struct blk_range_data *br = NULL;
	struct blk_dev_range_desc *start = NULL;
	u8 bs_order = odx_wr->reg_data.dev_info.bs_order;
	u16 desc_counts = 0, index = 0;
	u32 alloc_nr_blks = 0, tmp_nr_blks = 0, opt_nr_blks = 0;
	sector_t lba = 0;

	start = (struct blk_dev_range_desc *)((u8*)param + \
			sizeof(struct populate_token_param));

	desc_counts = __odx_get_desc_counts(get_unaligned_be16(
			&param->blkdev_range_desc_len[0]));

	opt_nr_blks = (OPTIMAL_TRANSFER_SIZE_IN_BYTES >> bs_order);
	
	/**/
	for (index = 0; index < desc_counts; index++){
	
		/* (SBC3R31, p130)
		 *
		 * If the NUMBER_OF_LOGICAL_BLOCKS field is set to zero, then
		 * the copy manager should perform no operation for this block
		 * device range descriptor. This condition shall not be
		 * considered an error.
		 */
		if (get_unaligned_be32(&start[index].nr_blks[0]) == 0)
			continue;
	
		/* To split the blocks to small chunks */
		lba = get_unaligned_be64(&start[index].lba[0]);
		alloc_nr_blks = get_unaligned_be32(&start[index].nr_blks[0]);

		while (alloc_nr_blks){

			tmp_nr_blks = min_t(u32, alloc_nr_blks, opt_nr_blks);

			br = __odx_alloc_br();
			if (!br) {
				__odx_free_br_lists(&br_list);
				INIT_LIST_HEAD(&br_list);
				odx_wr->rc = RC_INSUFFICIENT_RESOURCES_TO_CREATE_ROD_TOKEN;
				return -ENOMEM;
			}

			br->lba = lba;
			br->nr_blks = tmp_nr_blks;

			lba += (sector_t)tmp_nr_blks;
			alloc_nr_blks -= tmp_nr_blks;

			__odx_lock_update_tc_cmd_transfer_count(odx_wr->tc_p, 
					(sector_t)br->nr_blks);

			pr_debug("br(0x%p) lba(0x%llx), nr_blks(0x%x)\n",
				br, (unsigned long long)lba, 
				tmp_nr_blks);

			list_add_tail(&br->br_node, &br_list);

		}
	}

	list_splice_tail_init(&br_list, &token_p->br_list);

	odx_wr->rc = RC_GOOD;
	return 0;
}

int odx_core_before_pt(
	struct odx_work_request *odx_wr,
	bool *go_pt
	)
{
	struct populate_token_param *p = (struct populate_token_param *)odx_wr->buff;
	struct blk_dev_range_desc *s = NULL;
	struct __reg_data *reg_data = &odx_wr->reg_data;
	u8 bs_order = reg_data->dev_info.bs_order;
	u16 desc_counts = 0;
	sector_t all_nr_blks = 0;
	u32 rod_type;

	*go_pt = false;
 
	 s = (struct blk_dev_range_desc *)((u8*)p + \
		 sizeof(struct populate_token_param));

	 /* The block dev range desc length shall be a multiple of 16 */
	 desc_counts = __odx_get_desc_counts(get_unaligned_be16(
		 &p->blkdev_range_desc_len[0]));

	if (p->rtv){
		/* we don't support to create BLOCK ZERO ROD TOKEN */
		rod_type = get_unaligned_be32(&p->rod_type[0]);
 
		if(__odx_check_valid_supported_rod_type(rod_type)
		|| (rod_type == ROD_TYPE_BLK_DEV_ZERO)
		)
		{
			pr_err("unsupported token type:0x%x "
				"in PT parameter data (id:0x%x, sac:0x%x)\n", 
				rod_type, reg_data->list_id, reg_data->sac);
 
			odx_wr->rc = RC_INVALID_PARAMETER_LIST;
			return -EINVAL;
		}
	}

	if ((get_unaligned_be16(&p->token_data_len[0]) < 0x1e)
	||  (get_unaligned_be16(&p->blkdev_range_desc_len[0]) < 0x10)
	)
	{
		pr_err("token data length or blk dev range desc "
			"length is not enough (id:0x%x, sac:0x%x)\n", 
			reg_data->list_id, reg_data->sac);
 
		odx_wr->rc = RC_INVALID_PARAMETER_LIST;
		return -EINVAL;
	}
 
	if (__odx_check_same_lba_in_desc_list(s, desc_counts) != 0){
		pr_err("found same LBA in blk dev range "
			"descriptor (id:0x%x, sac:0x%x)\n", reg_data->list_id, 
			reg_data->sac);
 
		odx_wr->rc = RC_INVALID_PARAMETER_LIST;
		return -EINVAL;
	}
 
	if (__odx_check_overlap_lba_in_desc_list(s, desc_counts) != 0){
		pr_err("found overlapped LBA in blk dev range "
			"descriptor (id:0x%x, sac:0x%x)\n", reg_data->list_id, 
			reg_data->sac);
 
		odx_wr->rc = RC_INVALID_PARAMETER_LIST;
		return -EINVAL;
	}
 
	if (__odx_check_max_lba_in_desc_list(s, reg_data->dev_info.dev_max_lba,
			desc_counts) != 0){
		pr_err("found LBA in blk dev range descriptor execeeds "
			"the max LBA of device (id:0x%x, sac:0x%x)\n", 
			reg_data->list_id, reg_data->sac);
 
		odx_wr->rc = RC_LBA_OUT_OF_RANGE;
		return -EINVAL;
	}
 
 
	/* b). To check timeout value */
	if (get_unaligned_be32(&p->inactivity_timeout[0]) > MAX_INACTIVITY_TIMEOUT) {
		pr_err("timeout value is larger than max-timeout "
			"value (id:0x%x, sac:0x%x)\n", reg_data->list_id, 
			reg_data->sac);
 
		odx_wr->rc = RC_INVALID_PARAMETER_LIST;
		return -EINVAL;
	}
 
	if (desc_counts > __odx_get_max_supported_blk_dev_range()){
		pr_err("blk dev range descriptor length exceeds "
			"the max value (id:0x%x, sac:0x%x)\n", 
			reg_data->list_id, reg_data->sac);
 
		odx_wr->rc = RC_TOO_MANY_SEGMENT_DESCRIPTORS;
		return -EINVAL;
	}

	all_nr_blks = __odx_get_total_nr_blks_by_desc(s, desc_counts);
 
	/* SBC3R31, page 209 (FIXED ME !!)
	 *
	 * d). To check the total sum of the NUMBER OF LOGICAL BLOCKS fields in all 
	 *	of the complete block device range descriptors is larger than the
	 *	max bytes in block ROD value in the BLOCK ROD device type specific 
	 *	features descriptor in the ROD token features third-party copy
	 *	descriptors in the third-party copy vpd page or not
	 *
	 * FIXED ME !!
	 *
	 * This setting shall be checked with __build_blkdev_rod_limits_desc()
	 * and __build_rod_token_feature() again
	 */
	if (all_nr_blks > (MAX_TRANSFER_SIZE_IN_BYTES >> bs_order)){
		pr_err("sum of contents in blk dev range descriptor "
			"length exceeds the max value (id:0x%x, sac:0x%x)\n", 
			reg_data->list_id, reg_data->sac);
 
		odx_wr->rc = RC_INVALID_PARAMETER_LIST;
		return -EINVAL;
	}

	/*
	 * If the NUMBER_OF_LOGICAL_BLOCKS field is set to zero, then
	 * the copy manager should perform no operation for this block
	 * device range descriptor. This condition shall not be considered
	 * an error
	 */
	if (all_nr_blks)
		*go_pt = true;

	odx_wr->rc = RC_GOOD;
	return 0;
 
}

int odx_core_pt(
	struct odx_work_request *odx_wr
	)
{
	struct populate_token_param *param = 
		(struct populate_token_param *)odx_wr->buff;

	struct tpc_token_data *token_p = NULL;
	int ret;

	/* 
	 * Check whether there is any token which was matchedwith list id in
	 * current passing cmd.
	 *
	 * c) If another a 3rd party command that originates a copy operation
	 *    is received on the same I_T nexus and the list id matches the
	 *    list id associated with the ROD token,then the ROD token shall be
	 *    discard.
	 */
	__odx_is_duplicated_token_then_delete(
		odx_wr->tpg_p, 
		odx_wr->reg_data.cmd_id_hi, 
		odx_wr->reg_data.cmd_id_lo,
		odx_wr->reg_data.initiator_id_hi, 
		odx_wr->reg_data.initiator_id_lo
		);	

	/* create new token data and prepare reg_data */
	token_p = __odx_token_data_alloc(odx_wr, &odx_wr->reg_data);
	if (!token_p) {
		odx_wr->rc = RC_INSUFFICIENT_RESOURCES_TO_CREATE_ROD;
		return -ENOMEM;
	}

	/* start process pt operation */
	__odx_update_tc_data_status(odx_wr->tc_p, T_CMD_IS_STARTING_IN_FG);

	/* main code for Pupulate Token */
	ret = __odx_core_pt_io(odx_wr, token_p);
	if (ret != 0) {
		__odx_token_data_free(token_p);
		__odx_update_tc_data_status(odx_wr->tc_p, T_CMD_COMPLETED_W_ERR);
		return ret;
	}

	/**/ 
	__odx_update_tc_data_status(odx_wr->tc_p, T_CMD_COMPLETED_WO_ERR);
	token_p->cp_op_status = OP_COMPLETED_WO_ERR;

	__odx_set_obj_completion_status(token_p);
	__odx_set_obj_op_counter(token_p);

	token_p->segs_processed = odx_wr->tc_p->segs_processed = 0;
	token_p->transfer_count = __odx_lock_get_tc_cmd_transfer_count(odx_wr->tc_p);
	token_p->create_time = get_jiffies_64();

	/* it is tricky to report transfer count even if we don't need do
	 * any I/O for PT
	 */
	odx_wr->transfer_counts = token_p->transfer_count;

	__odx_build_512b_token_data(odx_wr, token_p);
	__odx_update_token_status(token_p, O_TOKEN_ALIVE);

	/* add new token into tree */
	odx_rb_token_add(odx_wr->tpg_p, token_p);

	/* fire timer */
	token_p->token_timeout = get_unaligned_be32(&param->inactivity_timeout[0]);
	__odx_setup_token_timer(token_p, token_p->token_timeout);
	return 0;

}

int odx_core_before_wut(
	struct odx_work_request *odx_wr,
	bool *go_wut
	)
{
	struct write_by_token_param *p = 
		(struct write_by_token_param *)odx_wr->buff;
	struct blk_dev_range_desc *s = NULL;
	struct rod_token *token = NULL;
	u8 *cdb = odx_wr->cdb;
	u8 bs_order = odx_wr->reg_data.dev_info.bs_order;
	u16 desc_counts = 0;
	sector_t all_nr_blks = 0;

	*go_wut = false;

	s = (struct blk_dev_range_desc *)((u8 *)p + \
		sizeof(struct write_by_token_param));

	/* The block dev range desc length shall be a multiple of 16 */
	desc_counts = __odx_get_desc_counts(
		get_unaligned_be16(&p->blkdev_range_desc_len[0]));

	if (get_unaligned_be32(&cdb[10]) < 552){
		pr_err("allocation len is smaller than 552 bytes "
			"(id:0x%x, sac:0x%x)\n", 
			odx_wr->reg_data.list_id, odx_wr->reg_data.sac);

		odx_wr->rc = RC_INVALID_PARAMETER_LIST;
		return -EINVAL;
	}

	if (get_unaligned_be16(&p->token_data_len[0]) < 550){
		pr_err("avaiable data len in param is smaller than "
			"550 bytes (id:0x%x, sac:0x%x)\n", 
			odx_wr->reg_data.list_id, odx_wr->reg_data.sac);

		odx_wr->rc = RC_INVALID_PARAMETER_LIST;
		return -EINVAL;
	}

	if (get_unaligned_be16(&p->blkdev_range_desc_len[0]) < 0x10){
		pr_err("blk dev range desc length is not enougth "
			"(id:0x%x, sac:0x%x)\n", odx_wr->reg_data.list_id, 
			odx_wr->reg_data.sac);

		odx_wr->rc = RC_INVALID_PARAMETER_LIST;
		return -EINVAL;
	}

	token = (struct rod_token*)&p->rod_token[0];
	if (get_unaligned_be16(&token->token_len[0]) != 0x1f8 ){
		pr_err("token length is NOT 0x1f8 bytes (id:0x%x, sac:0x%x)\n", 
			odx_wr->reg_data.list_id, odx_wr->reg_data.sac);

		odx_wr->rc = RC_INVALID_TOKEN_OP_AND_INVALID_TOKEN_LEN;
		return -EINVAL;
	}

	if (__odx_check_valid_supported_rod_type(
		get_unaligned_be32(&token->type[0])) != 0)
	{
		pr_err("unsupported token type (id:0x%x, sac:0x%x)\n", 
			odx_wr->reg_data.list_id, odx_wr->reg_data.sac);

		odx_wr->rc = RC_INVALID_TOKEN_OP_AND_UNSUPPORTED_TOKEN_TYPE;
		return -EINVAL;
	}

	if (__odx_check_same_lba_in_desc_list(s, desc_counts) != 0){
		pr_err("found same LBA in blk dev range descriptor "
			"(id:0x%x, sac:0x%x)\n", 
			odx_wr->reg_data.list_id, odx_wr->reg_data.sac);

		odx_wr->rc = RC_INVALID_PARAMETER_LIST;
		return -EINVAL;
	}

	if (__odx_check_overlap_lba_in_desc_list(s, desc_counts) != 0){
		pr_err("found overlapped LBA in blk dev range "
			"descriptor (id:0x%x, sac:0x%x)\n", 
			odx_wr->reg_data.list_id, odx_wr->reg_data.sac);

		odx_wr->rc = RC_INVALID_PARAMETER_LIST;
		return -EINVAL;
	}

	if (__odx_check_max_lba_in_desc_list(s, 
		odx_wr->reg_data.dev_info.dev_max_lba, desc_counts) != 0){

		pr_err("found LBA in blk dev range descriptor execeeds "
			"the max LBA of device (id:0x%x, sac:0x%x)\n", 
			odx_wr->reg_data.list_id, odx_wr->reg_data.sac);

		odx_wr->rc = RC_LBA_OUT_OF_RANGE;
		return -EINVAL;
	}

	if (desc_counts > __odx_get_max_supported_blk_dev_range()){
		pr_err("error !! blk dev range descriptor length exceeds "
			"the max value (id:0x%x, sac:0x%x)\n", 
			odx_wr->reg_data.list_id, odx_wr->reg_data.sac);

		odx_wr->rc = RC_TOO_MANY_SEGMENT_DESCRIPTORS;
		return -EINVAL;
	}

	all_nr_blks = __odx_get_total_nr_blks_by_desc(s, desc_counts);

	/* SBC3R31, page 209 (FIXED ME !!)
	 *
	 * d). To check the total sum of the NUMBER OF LOGICAL BLOCKS fields in all 
	 *     of the complete block device range descriptors is larger than the
	 *     max bytes in block ROD value in the BLOCK ROD device type specific 
	 *     features descriptor in the ROD token features third-party copy
	 *     descriptors in the third-party copy vpd page or not
	 *
	 * FIXED ME !!
	 *
	 * This setting shall be checked with __build_blkdev_rod_limits_desc()
	 * and __build_rod_token_feature() again
	*/

	if (all_nr_blks > (MAX_TRANSFER_SIZE_IN_BYTES >> bs_order)){
		pr_err("error !! sum of contents in blk dev range descriptor "
			"length exceeds the max value (id:0x%x, sac:0x%x)\n", 
			odx_wr->reg_data.list_id, odx_wr->reg_data.sac);

		odx_wr->rc = RC_INVALID_PARAMETER_LIST;
		return -EINVAL;
	}

	/*
	 * If the NUMBER_OF_LOGICAL_BLOCKS field is set to zero, then
	 * the copy manager should perform no operation for this block
	 * device range descriptor. This condition shall not be considered
	 * an error
	 */
	if (all_nr_blks)
		*go_wut = true;

	odx_wr->rc = RC_GOOD;
	return 0;

}

int odx_core_wut(
	struct odx_work_request *odx_wr
	)
{
	sector_t d_nr_blks = 0, s_nr_blks = 0, transfer_blks;
	u64 off_to_rod = 0;
	u16 desc_counts = 0;
	u32 tmp;
	int ret = 0;
	struct write_by_token_param *p = NULL;
	struct blk_dev_range_desc *s = NULL;
	struct tpc_tpg_data *s_tpg_p = NULL;
	struct tpc_token_data *d_token_p = NULL, *s_token_p = NULL;
	struct rod_token_512b *tmp_s_token512b_p = NULL;
	struct __reg_data *reg_data = &odx_wr->reg_data;
	T_CMD_STATUS curr_tc_status = OP_COMPLETED_W_ERR;
	bool run_wuzrt = false; /* Write Using Zero ROD Token */

	/* The block dev range desc length shall be a multiple of 16 */
	p = (struct write_by_token_param *)odx_wr->buff;
	
	s = (struct blk_dev_range_desc *)((u8*)p + \
			sizeof(struct write_by_token_param));
	
	desc_counts = __odx_get_desc_counts(
			get_unaligned_be16(&p->blkdev_range_desc_len[0]));
	
	d_nr_blks = __odx_get_total_nr_blks_by_desc(s, desc_counts);

	tmp_s_token512b_p = (struct rod_token_512b *)&p->rod_token[0];


	/* check what kind of WUT we want to run ... */
	tmp = get_unaligned_be32(&tmp_s_token512b_p->gen_data.type[0]);
	if (tmp == ROD_TYPE_BLK_DEV_ZERO) 
		run_wuzrt = true;
	
	/* 
	 * Check whether there is any token which was matched with list id in
	 * current passing cmd.
	 *
	 * c) If another a 3rd party command that originates a copy operation 
	 *    is received on the same I_T nexus and the list id matches the
	 *    list id associated with the ROD token,then the ROD token shall
	 *    be discard.
	 */
	__odx_is_duplicated_token_then_delete(odx_wr->tpg_p, 
		reg_data->cmd_id_hi, reg_data->cmd_id_lo,
		reg_data->initiator_id_hi, reg_data->initiator_id_lo
		);

	/* create new one and copy reg data */
	d_token_p = __odx_token_data_alloc(odx_wr, reg_data);
	if (!d_token_p) {
		odx_wr->rc = RC_INSUFFICIENT_RESOURCES_TO_CREATE_ROD;
		return -ENOMEM;
	}

	if (run_wuzrt == false) {
	
		/* if it is Write Using Zero ROD Token, try get token / tpg
		 * data of source from token tree 
		 */
		ret = __odx_wut_get_src_tpg_p_and_token_p(tmp_s_token512b_p, 
			&s_tpg_p, &s_token_p, d_token_p, &odx_wr->rc);

		if (ret != 0) {
			if (s_token_p)
				odx_rb_token_put(s_token_p);
			if (s_tpg_p)
				odx_rb_tpg_put(s_tpg_p);

			__odx_token_data_free(d_token_p);
			/* we setup RC to odx_wr->rc already */
			return ret;
		}

		d_token_p->token_timeout = s_token_p->token_timeout;

		/* Before to do WUT, let's investigate some conditions again */	
		s_nr_blks = __odx_lock_get_nr_blks_by_s_token(s_token_p);
		off_to_rod = get_unaligned_be64(&p->off_into_rod[0]);

		ret = __odx_wut_check_rod_off_before_wut_io(s_token_p, d_token_p, 
				s_nr_blks, d_nr_blks, off_to_rod, &odx_wr->rc);

		if(ret != 0) {
			odx_rb_token_put(s_token_p);
			odx_rb_tpg_put(s_tpg_p);
			__odx_token_data_free(d_token_p);
			/* we setup RC to odx_wr->rc already */
			return ret;
		}
	}

	__odx_update_tc_data_status(odx_wr->tc_p, T_CMD_IS_STARTING_IN_FG);

	/* ===== main code to do WUT I/O ===== */
	__odx_wut_io(odx_wr, s_token_p, d_token_p, run_wuzrt);

	transfer_blks = __odx_lock_get_tc_cmd_transfer_count(odx_wr->tc_p);
	pr_debug("transfer_blks:0x%llx\n", (unsigned long long)transfer_blks);

	/* please refer the sbc3r31, page 88 */
	if (d_nr_blks == transfer_blks) {
		curr_tc_status = T_CMD_COMPLETED_WO_ERR;
		d_token_p->cp_op_status = OP_COMPLETED_WO_ERR;
	} 
	else if (__odx_cmd_was_asked_drop(odx_wr->tc_p)) {
		curr_tc_status = T_CMD_WAS_ABORTED;
		d_token_p->cp_op_status = OP_TERMINATED;
		odx_wr->rc = RC_GOOD;
	}
	else {
		if (p->immed)
			d_token_p->completion_status = SAM_STAT_CHECK_CONDITION;
	
		if (odx_wr->rc == RC_NO_SPACE_WRITE_PROTECT) {
			/* treat it as copy-error if hit no sapce event */
			d_token_p->cp_op_status = OP_COMPLETED_W_ERR;
		} else {
			d_token_p->cp_op_status = OP_COMPLETED_WO_ERR_WITH_ROD_TOKEN_USAGE;

			if (transfer_blks) {
				pr_debug(
				"COPY_ABORT_DATA_UNDERRUN_COPY_TARGET: "
				"list id:0x%x, d_nr_blks:0x%llx, "
				"transfer_blks:0x%llx,\n", reg_data->list_id,
				(unsigned long long)d_nr_blks,
				(unsigned long long)transfer_blks);

				odx_wr->rc = RC_COPY_ABORT_DATA_UNDERRUN_COPY_TARGET;
			}else {
				pr_debug(
				"ILLEGAL_REQ_DATA_UNDERRUN_COPY_TARGET: "
				"list id:0x%x, d_nr_blks:0x%llx, "
				"transfer_blks:0x%llx,\n", reg_data->list_id,
				(unsigned long long)d_nr_blks,
				(unsigned long long)transfer_blks);

				odx_wr->rc = RC_ILLEGAL_REQ_DATA_UNDERRUN_COPY_TARGET;
			}
		}
	}

	__odx_set_obj_completion_status(d_token_p);
	__odx_set_obj_op_counter(d_token_p);

	d_token_p->segs_processed = odx_wr->tc_p->segs_processed = 0;
	d_token_p->create_time = get_jiffies_64();

	/* update final transfer count */	
	odx_wr->transfer_counts = d_token_p->transfer_count = transfer_blks;

	ret = 0;

	if (d_token_p->cp_op_status != OP_COMPLETED_WO_ERR){
		curr_tc_status = T_CMD_COMPLETED_W_ERR;
		ret = -EINVAL;
		__odx_build_token_sense_data(d_token_p, odx_wr->rc, 0, 0);
	}

	__odx_update_tc_data_status(odx_wr->tc_p, curr_tc_status);
	__odx_update_token_status(d_token_p, O_TOKEN_ALIVE);	

	/* put src tpg / token, for wuzrt case, they are null */
	if (s_token_p)
		odx_rb_token_put(s_token_p);

	if (s_tpg_p)
		odx_rb_tpg_put(s_tpg_p);

	/* add new token into tree */
	odx_rb_token_add(odx_wr->tpg_p, d_token_p);

	/* fire timer */
	__odx_setup_token_timer(d_token_p, d_token_p->token_timeout);
	return ret;

}

int odx_core_rrti(
	struct odx_work_request *odx_wr
	)
{
	int ret;

	ret = __odx_core_rrti_s1(odx_wr);
	if ((ret == -ENODEV) && (odx_wr->rc == RC_GOOD))
		ret = __odx_core_rrti_s2(odx_wr);
	
	return ret;
}

