/*******************************************************************************
 * Filename:  target_core_qodx_vpd.c
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
#include "target/qnap_target_struct.h"
#include "target_core_qlib.h"
#include "target_core_qodx_lib.h"
#include "target_core_qodx_scsi.h"

/** 
 * @brief  CSCD supported table
 */
CSCD_DESC_TYPE_CODE gCscdSupportedTable[] ={
	/* The type code should be ordered here */
	ID_DESC,
	MAX_CSCD_DESC_TYPE_CODE, // end of table
};

/** 
 * @brief  SEGMENT supported table
 */
SEG_DESC_TYPE_CODE gSegSupportedTable[] = {
	/* The type code should be ordered here */
	COPY_BLK_TO_BLK,
	MAX_SEG_DESC_TYPE_CODE, // end of table
};

struct rod_type_table gRodTypeTable[] = {
	/* {<type>, <end table>, <token out>, <token in>, <internal token>, <prefenence>} */
 
#if (SUPPORT_NONZERO_ROD_TYPE == 1)
	{ ROD_TYPE_PIT_COPY_D4  , 0, 1, 1, 0, 0 },  /* point in time copy - default */   
	{ ROD_TYPE_BLK_DEV_ZERO , 0, 0, 1, 0, 0 },  /* block device zero ROD token */
#endif
	/* end of table */
	{ 0xffffffff , 1,  0, 0, 0, 0 },
 };
 
#if 0
 /** 
  * @brief  Table for supported CSCD IDs other than 0000h to 07fffh
  */
 CSCD_ID_TABLE gSupportedCSCDIdsTable[] = {
#if (SUPPORT_CSCD_ID_F800 == 1)
	 /*
	  * The CSCD ID 0xf800 shall be supported in the Supported CSCD IDs 
	  * third-party copy descriptor if
	  *
	  * (1) the ROD CSCD descriptor is supported and
	  * (2) any ROD type descriptor contains:
	  *	a) a non-zero value in the ROD type field and
	  *	b) the TOKEN_IN bit is set to one
	  */
	 { 0xf800, false },
#endif
	 { 0x0000, true  }, // end of table
 };
#endif

 static int __odx_vpd_get_total_blkdev_rod_limits_desc_len(u16 *len);
 static int __odx_vpd_build_blkdev_rod_limits_desc(struct __dev_info *dev_info,
	 TPC_DESC_TYPE_CODE desc_code, u8 *desc_ptr);
 
 static int __odx_vpd_get_total_gen_copy_op_len(u16 *len);
 static int __odx_vpd_build_gen_copy_op(struct __dev_info *dev_info, 
	 TPC_DESC_TYPE_CODE desc_code, u8 *desc_ptr);
 
 static int __odx_vpd_get_total_supported_descs_len(u16 *len);
 static int __odx_vpd_build_supported_descs(struct __dev_info *dev_info,
	 TPC_DESC_TYPE_CODE desc_code, u8 *desc_ptr);

 /** 
  * @brief  Function pointer table to build each 3rd party copy descriptor data
  */
 struct build_tpc_desc gTpcDescTable[] = {
	 {   
	 TPC_DESC_BLOCK_DEV_ROD_LIMITS, 
	 __odx_vpd_get_total_blkdev_rod_limits_desc_len,
	 __odx_vpd_build_blkdev_rod_limits_desc 
	 },
 
#if 0
	 /* This function is mandatory (SPC4R36, page 769) */
	 {	 
	 TPC_DESC_SUPPORTED_CMDS , 
	 __get_total_supported_cmds_len ,
	 __build_supported_cmds 
	 },
#endif
 
 
#if 0 // mark this cause of no way to verify this
     /*
      * This function shall be mandatory if the EXTENDED COPY (LID4) or
      * EXTENDED COPY (LID1) command is supported (SPC4R36, page 769)
      */
     {	 
	 TPC_DESC_PARAMETER_DATA , 
	 __get_total_params_len ,
	 __build_params 
     },  
#endif
     /*
      * This function shall be mandatory if the EXTENDED COPY (LID4) or
      * EXTENDED COPY (LID1) command is supported (SPC4R36, page 769)
      */
     {	 
	 TPC_DESC_SUPPORTED_DESCS , 
	 __odx_vpd_get_total_supported_descs_len ,
	 __odx_vpd_build_supported_descs 
     },
 
#if 0
     /*
      * This function shall be mandatory if the EXTENDED COPY (LID4) or
      * EXTENDED COPY (LID1) command is supported (SPC4R36, page 769)
      */
     {	 
	 TPC_DESC_SUPPORTED_CSCD_IDS , 
	 __get_total_supported_cscd_ids_len ,
	 __build_supported_cscd_ids 
     },
#endif
 
#if (SUPPORT_ROD_TOKEN_DESC_IN_TPC_VPD == 1)
	 /* This function shall be mandatory if the extended copy command
	  * ROD CSCD descriptor is supported (SPC4R36, page 769)
	  */
	 {   
	 /* Currently, we only support the information for block device */
	 TPC_DESC_ROD_TOKEN_FEATURES , 
	 __get_total_rod_token_feature_len ,
	 __build_rod_token_feature 
	 },
#endif
 
#if 0 // mark this cause of no way to verify this
     /*
      * This function shall be mandatory if the extended copy command ROD CSCD
      * descriptor is supported (SPC4R36, page 769)
      */
     {	 
	 TPC_DESC_SUPPORTED_ROD , 
	 __get_total_supported_rod_len ,
	 __build_supported_rod 
     },
#endif
 
	 /* This function is mandatory (SPC4R36, page 769) */
	 {   
	 TPC_DESC_GENERAL_COPY_OP ,
	 __odx_vpd_get_total_gen_copy_op_len ,
	 __odx_vpd_build_gen_copy_op 
	 },
 
#if 0 // mark this cause of no way to verify this
     {
	 TPC_DESC_STREAM_COPY_OP ,
	 __get_total_stream_copy_op_len ,
	 __build_stream_copy_op  
     },
 
     /*
      * This function shall be mandatory if the RECEIVE COPY DATA (LID4) or
      * RECEIVE COPY DATA (LID1) command is supported (SPC4R36, page 769)
      */
     {	 
	 TPC_DESC_HOLD_DATA , 
	 __get_total_hold_data_len ,
	 __build_hold_data 
     },
#endif
 
	 {   
	 MAX_TPC_DESC_TYPE , 
	 NULL ,
	 NULL
	 },
 };

static u16 __odx_vpd_fill_supported_desc_type_codes(
	u8 *p
	)
{
	u16 Count = 0, Index = 0;

	/* 
	 * SPC4R36, page 773,
	 *
	 * The unique supported value in each byte shall appear in the list in
	 * ascending numerical order
	 */
	for (Index = 0;; Index++){
		if (gSegSupportedTable[Index] == MAX_SEG_DESC_TYPE_CODE)
			break;
		p[Count++] = gSegSupportedTable[Index];
	}

	for (Index = 0;; Index++){
		if (gCscdSupportedTable[Index] == MAX_CSCD_DESC_TYPE_CODE)
			break;
		p[Count++] = gCscdSupportedTable[Index];
	}
	return Count;
}

#if 0

static u16 __get_rod_type_desc_len(void)
{
	u16 total_len = 0;
	u8 index = 0;

	for (index = 0 ;; index++){
		if (gRodTypeTable[index].end_table == 1)
			break;
		total_len += ROD_TYPE_DESC_LEN;
	}
	return total_len;
}

#endif

static int __odx_vpd_get_total_blkdev_rod_limits_desc_len(
	u16 *len
	)
{
	*len = BLK_DEV_ROD_TOKEN_LIMIT_DESC_LEN;
	return 0;
}

static int __odx_vpd_get_total_gen_copy_op_len(
	u16 *len
	)
{
	*len = 0;
	return 0;
}

#if 0
static int __get_total_params_len(
	u16 *len
	)
{
	*len = 0; /* report zero length if not found any supported value */
	return 0;
}
#endif

static int __odx_vpd_get_total_supported_descs_len(
	u16 *len
	)
{
	u16 total_len = 0, pad_len = 0;

	total_len = __tpc_get_max_supported_cscd_desc_count();
	total_len += __tpc_get_max_supported_seg_desc_count();
	
	if ((total_len + 5) & (0x03)){
		/* Caculate the pad length */
		pad_len = (((((total_len+ 5) + 4) >> 2) << 2) - (total_len+ 5));
		total_len += pad_len;
	}

	*len = (total_len + 5);
	return 0;
}

#if 0
static int __get_total_supported_cscd_ids_len(
	u16 *len
	)
{
	u16 total_len = 0, pad_len = 0;
	u8 index = 0;

	for (index = 0;; index++){
		if(gSupportedCSCDIdsTable[index].IsEndTable == true)
			break;
	}

	total_len  = (u16)index;

	if ((total_len + 6) & (0x03)){
		/* Caculate the pad length */
		pad_len = (((((total_len+ 6) + 4) >> 2) << 2) - (total_len+ 6));
		total_len += pad_len;
	}

	*len = (total_len + 6);
	return 0;
}

static int __get_total_supported_rod_len(
	u16 *len
	)
{
	u16 total_len = 0, pad_len = 0;

	total_len = __get_rod_type_desc_len();

	if ((total_len + 8) & (0x03)){
		/* Caculate the pad length */
		pad_len = (((((total_len + 8) + 4) >> 2) << 2) - (total_len + 8));
		total_len += pad_len;
	}

	*len = (total_len + 8); // (ROD_TYPE_DESC_LEN + 8)
	return 0;
}

static int __get_total_stream_copy_op_len(
	u16 *len
	)
{
	*len = 0;
	return 0;
}

static int __get_total_hold_data_len(
	u16 *len
	)
{
	*len = 0;
	return 0;
}


#if (SUPPORT_ROD_TOKEN_DESC_IN_TPC_VPD == 1)

static u16 __get_rod_dev_type_sepcific_desc_len()
{
    return ROD_DEV_TYPE_SPECIFIC_DESC_LEN;
}

static int __get_total_rod_token_feature_len(
	u16 *len
	)
{
	u16 total_len = 0, pad_len = 0;

	total_len = __get_rod_dev_type_sepcific_desc_len();

	if ((total_len + 48) & (0x03)){
		/* caculate the pad length */
		pad_len = (((((total_len + 48) + 4) >> 2) << 2) - (total_len + 48));
		total_len += pad_len;
	}

	*len = (total_len + 48);
	return 0;
}

static int __build_rod_token_feature(
	void *work_data,
	TPC_DESC_TYPE_CODE desc_code, 
	u8 *desc_ptr
	)
{
	struct tpc_work_data *wd = (struct tpc_work_data *)work_data;
	u8 bs_order = wd->dev_info.bs_order;
	u16 len = ROD_DEV_TYPE_SPECIFIC_DESC_LEN, pad_len = 0;
	ROD_DEV_TYPE_SPECIFIC_DESC *p = NULL;
	
	COMPILE_ASSERT(sizeof(ROD_DEV_TYPE_SPECIFIC_DESC) == \
		ROD_DEV_TYPE_SPECIFIC_DESC_LEN);

	put_unaligned_be16((u16)desc_code, &desc_ptr[0]);
	put_unaligned_be32(D4_INACTIVITY_TIMEOUT, &desc_ptr[16]);
	put_unaligned_be32(MAX_INACTIVITY_TIMEOUT, &desc_ptr[20]);
	put_unaligned_be32(MAX_INACTIVITY_TIMEOUT, &desc_ptr[24]);
	put_unaligned_be16(len, &desc_ptr[46]);

	/*
	 * FIXED ME !! FIXED ME !!
	 * The remote_tokens filed indicates the level of support the copy
	 * manager provides for ROD tokens that are NOT created by the copy
	 * manager that is processing the copy operation
	 */
#if (R_TOKENS_CODE_6 == 1)
	desc_ptr[4] |= 6;
#elif (R_TOKENS_CODE_4 == 1)
	desc_ptr[4] |= 4;
#elif (R_TOKENS_CODE_0 == 1)
	desc_ptr[4] |= 0;
#else
#error what are you doing !!??
#endif

	/* 
	 * FIXED ME !!
	 * start to build the block rod device type specific feature descriptor
	 * and these values shall be changed in the future ...
	 */
	p = (ROD_DEV_TYPE_SPECIFIC_DESC *)&desc_ptr[48];
	p->u8DevType = wd->dev_info.type;
	p->u8DescFormat = 0;
	put_unaligned_be16(0x002c, &p->u8DescLen[0]);
	put_unaligned_be16(
		(OPTIMAL_BLK_ROD_LEN_GRANULARITY_IN_BYTES >> bs_order), 
		&p->u8Byte4_7[2]
		);

	put_unaligned_be64(MAX_TRANSFER_SIZE_IN_BYTES, &p->u8Byte8_15[0]);
	put_unaligned_be64(MAX_TRANSFER_SIZE_IN_BYTES, &p->u8Byte16_23[0]);

	/* FIXED ME !! SPC4R36, page 779
	 * The SEGMENT means a single segment descriptor or single block device
	 * range descriptor
	 */
	put_unaligned_be64(OPTIMAL_TRANSFER_SIZE_IN_BYTES, &p->u8Byte24_47[0]);
	put_unaligned_be64(OPTIMAL_TRANSFER_SIZE_IN_BYTES, &p->u8Byte24_47[8]);

	/* The length should be a multiple of four */
	if ((len + 48) & (0x03)){
		/* Caculate the pad length */
		pad_len = (((((len + 48) + 4) >> 2) << 2) - (len + 48));
		len += pad_len;
	}

	put_unaligned_be16((u16)(len + 44), &p[2]);
	return 0;

}
#endif
#endif


/**/
static int __odx_vpd_build_blkdev_rod_limits_desc(
	struct __dev_info *dev_info,
	TPC_DESC_TYPE_CODE desc_code,
	u8 *desc_ptr
	)
{
	u32 bs_order = dev_info->bs_order;

	put_unaligned_be16(desc_code, &desc_ptr[0]);
	put_unaligned_be16(0x0020, &desc_ptr[2]);
	put_unaligned_be16(__odx_get_max_supported_blk_dev_range(), &desc_ptr[10]);
	put_unaligned_be32(MAX_INACTIVITY_TIMEOUT, &desc_ptr[12]);
	put_unaligned_be32(D4_INACTIVITY_TIMEOUT, &desc_ptr[16]);

	/*
	 * SBC3-R31, page-282
	 *
	 * MAX TOKEN TRANSFER SIZE indicates the max size in blocks that may be
	 * specified by the sum of the NUMBER OF LOGICAL BLOCKS fileds in all block
	 * device range descriptors of the POPULATE TOKEN command or 
	 * WRITE USING TOKEN command
	 *
	 * a). If the MAX BYTES IN BLOCK ROD field in block ROD device type feature
	 *     descriptor was reported, the MAX TOKEN TRANSFER SIZE fiedl shall be
	 *     set to MAX BYTES IN BLOCK ROD field.
	 *
	 * b). If the OPTIMAL BYTES IN BLOCK ROD TRANSFER field in block ROD device
	 *     type feature descriptor was reported, the OPTIMAL TRANSFER COUNT field 
	 *     shall be set to OPTIMAL BYTES IN BLOCK ROD TRANSFER field.
	 *
	 */

	/* set the max transfer size and optimal transfer size */
	put_unaligned_be64((MAX_TRANSFER_SIZE_IN_BYTES >> bs_order), &desc_ptr[20]);
	put_unaligned_be64((MAX_TRANSFER_SIZE_IN_BYTES >> bs_order), &desc_ptr[28]);

	return 0;
}

static int __odx_vpd_build_gen_copy_op(
	struct __dev_info *dev_info,
	TPC_DESC_TYPE_CODE desc_code, 
	u8 *desc_ptr
	)
{
	put_unaligned_be16((u16)desc_code, &desc_ptr[0]);
	put_unaligned_be16(0x0020, &desc_ptr[2]);

	/* FIXED ME !! 
	 * These settings shall be for EXTENDED COPY (LID4) command, this needs
	 * to be checked (But, we don't have any product support it ...).
	 */ 

	/* Concurrent Copies - 
	 *
	 * Max number of 3rd-party copy commands that are supported for concurrent
	 * processing by the copy manager
	 */
	put_unaligned_be32(0x1, &desc_ptr[4]);	// total concurrent copies

	/* Max Identified Concurrent Copies - 
	 *
	 * Max number of 3rd-party copy commands that are not an EXTENDED COPY
	 * command with LIST ID USAGE (6.4.3.2) set to 11b that are supported for 
	 * concurrent processing by the copy manager
	 */
	put_unaligned_be32(0x1, &desc_ptr[8]);	// max identified concurrent copies

	/* max segment length */
	put_unaligned_be32(OPTIMAL_TRANSFER_SIZE_IN_BYTES, &desc_ptr[12]);
	desc_ptr[16] = 22;	// data segment granularity (log 2) (2 ^ 22 = 4MB)
	desc_ptr[17] = 0x0;	// inline data granularity (log 2)
	return 0;
}

#if 0
static int __build_params(
	void *work_data,
	TPC_DESC_TYPE_CODE desc_code, 
	u8 *desc_ptr
	)
{
	u16 CscdDescCount = 0, SegDescCount = 0;

	CscdDescCount = __tpc_get_max_supported_cscd_desc_count();
	if (CscdDescCount == 0)
		return 1;

	SegDescCount = __tpc_get_max_supported_seg_desc_count();
	if (SegDescCount == 0)
		return 1;

	put_unaligned_be16((u16)desc_code, &desc_ptr[0]);
	put_unaligned_be16(0x001c, &desc_ptr[2]);
	put_unaligned_be16(CscdDescCount, &desc_ptr[8]);
	put_unaligned_be16(SegDescCount, &desc_ptr[10]);
	put_unaligned_be32(__tpc_get_total_supported_desc_len(), &desc_ptr[12]);
	put_unaligned_be32(0x0, &desc_ptr[16]);
	return 0;
}
#endif

static int __odx_vpd_build_supported_descs(
	struct __dev_info *dev_info,
	TPC_DESC_TYPE_CODE desc_code, 
	u8 *desc_ptr
	)
{
	u16 Len = 0, PadLen = 0;

	put_unaligned_be16((u16)desc_code, &desc_ptr[0]);
	Len = __odx_vpd_fill_supported_desc_type_codes(&desc_ptr[5]);
	desc_ptr[4] = (u8)Len;

	/* The length of supported third-party descriptor should be a multiple of four */
	if ((Len + 5) & (0x03)){
		/* Caculate the pad length */
		PadLen = (((((Len+ 5) + 4) >> 2) << 2) - (Len+ 5));
		/* u16Len is length for supported descriptor list plus pad length */
		Len += PadLen;
	}

	/* one byte for supported descriptor list length field */
	put_unaligned_be16((u16)(Len+1), &desc_ptr[2]);
	return 0;
}

#if 0
static int __build_supported_cscd_ids(
	void *work_data,
	TPC_DESC_TYPE_CODE desc_code, 
	u8 *desc_ptr
	)
{
	u16 Len = 0, PadLen = 0;

	put_unaligned_be16((u16)desc_code, &desc_ptr[0]);
	put_unaligned_be16((u16)Len, &desc_ptr[4]);

	/* The length of supported third-party descriptor should be a multiple of four */
	if ((Len + 6) & (0x03)){
		/* Caculate the pad length */
		PadLen = (((((Len+ 6) + 4) >> 2) << 2) - (Len+ 6));
		 /* u16Len is length for supported descriptor list plus pad length */		
		Len += PadLen;
	}

	/* two bytes for supported CSCD IDs list length field */
	put_unaligned_be16((u16)(Len + 2), &desc_ptr[2]);
	return 0;
}


static int __build_supported_rod(
	void *work_data,
	TPC_DESC_TYPE_CODE desc_code, 
	u8 *desc_ptr
	)
{
	u16 Len = 0, PadLen = 0, Index = 0;
	ROD_TYPE_DESC *pDesc = NULL;
	u8 *p = NULL;

	put_unaligned_be16((u16)desc_code, &desc_ptr[0]);

	/* start to build the ROD type descriptor lists data */
	p = &desc_ptr[8];

	for (Index = 0;; Index++){
		if (gRodTypeTable[Index].end_table == 1)
			break;

		pDesc = (ROD_TYPE_DESC *)p;

		put_unaligned_be32(gRodTypeTable[Index].rod_type, 
			&pDesc->u8RodType[0]);

		pDesc->u8TokenOut = (u8)gRodTypeTable[Index].token_out;
		pDesc->u8TokenIn = (u8)gRodTypeTable[Index].token_in;
		pDesc->u8EcpyInt = (u8)gRodTypeTable[Index].ecpy_int_bit;

		pDesc->u16PreferenceIndication = 
			(u16)gRodTypeTable[Index].preference_indication;

		Len += ROD_TYPE_DESC_LEN;
		p += ROD_TYPE_DESC_LEN;
	}

	put_unaligned_be16(Len, &desc_ptr[6]);

	/* The length should be a multiple of four */
	if ((Len + 8) & (0x03)){
		/* Caculate the pad length */
		PadLen = (((((Len + 8) + 4) >> 2) << 2) - (Len + 8));
		Len += PadLen;
	}

	put_unaligned_be16((u16)(Len + 4), &desc_ptr[2]);
	return 0;
}

static int __build_stream_copy_op(
	void *work_data,
	TPC_DESC_TYPE_CODE desc_code, 
	u8 *desc_ptr
	)
{
	/* we are not support stream copy operation */
	return 0;
}

static int __build_hold_data(
	void *work_data,
	TPC_DESC_TYPE_CODE desc_code, 
	u8 *desc_ptr
	)
{
	return 0;
}

#endif
/**/

 static u16 __odx_vpd_caculate_all_desc_len(
	 struct odx_work_request *odx_wr
	 )
 {
	 u8 *cdb = odx_wr->cdb;
	 u16 total_len = 0, curr_len = 0, idx, tmp;
	 int ret;
 
	 /* subtract 4 bytes first and remain bytes is for 
	  * 3rd-party copy descriptor lists data 
	  */
	 tmp = get_unaligned_be16(&cdb[3]) - 4;
 
	 for (idx = 0;; idx++) {
		 if ((gTpcDescTable[idx].desc_code == MAX_TPC_DESC_TYPE)
		 && (gTpcDescTable[idx].get_desc_len == NULL)
		 )
			 break;
 
		 curr_len = 0;
		 ret = gTpcDescTable[idx].get_desc_len(&curr_len);
		 if (ret != 0) {
			 /* break function if fail to get desc len ... */
			 odx_wr->rc = RC_INVALID_CDB_FIELD;
			 return 0;
		 }
 
		 total_len += curr_len;
	 }
 
	 pr_debug("%s: total len:0x%x\n", __func__, total_len);
 
	 if (total_len > tmp) {
		 pr_warn("%s: total of desc len of vpd 0x8f: 0x%x execeeds "
			 "the ALLOCATION_LENGTH field: 0x%x\n", __func__, 
			 total_len, get_unaligned_be16(&cdb[3]));
 
		 odx_wr->rc = RC_INVALID_CDB_FIELD;
		 return 0;
	 }
 
	 return total_len;
 }

 static int __odx_vpd_build_all_desc_data(
	 struct odx_work_request *odx_wr
	 )
 {
	 u8 *buffer = (u8 *)odx_wr->buff;
	 u8 *desc_ptr = &buffer[4];	 /* first third-party copy descriptor */
	 u16 total_len = 0, curr_len, idx;
	 int ret;
 
	 for (idx = 0 ;; idx++) {
		 if ((gTpcDescTable[idx].desc_code == MAX_TPC_DESC_TYPE)
		 && (gTpcDescTable[idx].build_desc == NULL)
		 )
			 break;
 
		 /*
		  * We did some error-checking in __odx_vpd_caculate_all_desc_len() 
		  * already. So here to get length of descriptor directly.
		  * If the value is zero, not build the descriptor table.
		  */
		 curr_len = 0;
		 gTpcDescTable[idx].get_desc_len(&curr_len);
 
		 if(curr_len == 0)
			 continue;
 
		 ret = gTpcDescTable[idx].build_desc(&odx_wr->reg_data.dev_info, 
				 gTpcDescTable[idx].desc_code, desc_ptr);
 
		 if (ret != 0) {
			 pr_err("%s: fail to build desc data. idx: %d\n", 
				 __func__, idx);
			 odx_wr->rc = RC_INVALID_CDB_FIELD;
			 return -EINVAL;
		 }
 
		 total_len += curr_len;
		 desc_ptr += (size_t)curr_len;
 
		 pr_debug("%s: idx:0x%x, tpc_ptr:0x%p, curr_len:0x%x\n",
			 __func__, idx, desc_ptr, curr_len);
	 }
 
 
	 put_unaligned_be16(total_len, &buffer[2]);
	 odx_wr->rc = RC_GOOD;
	 return 0;
 
 }

 int odx_emulate_evpd_8f(
	 struct odx_work_request *odx_wr
	 )
 {
	 u8 *cdb = odx_wr->cdb, *buffer = (u8 *)odx_wr->buff;
	 u16 total_len = 0;
	 int ret;
 
	 /* For the offload scsicompliance (LOGO) test in HCK, the allocation
	  * len will be 0x1000 but the iscsi initiator only will give 0xff length.
	  * Actually, the 0xff size is too small to return suitable data for
	  * third-party copy command vpd 0x8f
	  */ 
	 pr_debug("%s: allocation len: 0x%x in vpd 0x8f\n", 
		 __func__, get_unaligned_be16(&cdb[3]));
 
	 /* SPC4R36, page 767 */
	 if (get_unaligned_be16(&cdb[3]) < 4) {
		 odx_wr->rc = RC_INVALID_CDB_FIELD;
		 return -EINVAL;
	 }
 
	 /* (1) To caculate the total length we will build ... */
	 total_len = __odx_vpd_caculate_all_desc_len(odx_wr);
	 if (odx_wr->rc != RC_GOOD)
		 return -EINVAL;
 
	 /* (2) To start to build the data ... */
	 ret = __odx_vpd_build_all_desc_data(odx_wr);
 
	 buffer[0] = odx_wr->reg_data.dev_info.sbc_dev_type;
 
	 return ret;
 }
 

