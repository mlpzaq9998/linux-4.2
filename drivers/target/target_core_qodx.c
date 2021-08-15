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
#include <target/target_core_base.h>
#include <target/target_core_backend.h>
#include <target/target_core_fabric.h>
#include "target_core_file.h"
#include "target_core_iblock.h"
#include "target_core_pr.h" /* used for spc_parse_naa_6h_vendor_specific() */

#include "target_core_qtransport.h"
#include "target_core_qlib.h"
#include "target_core_qodx_lib.h"
 

/* Only use get_unaligned_be24() if reading p - 1 is allowed. */
static inline uint32_t __get_unaligned_be24(const uint8_t *const p)
{
	return get_unaligned_be32(p - 1) & 0xffffffU;
}

/**/
static int __qnap_odx_create_initiator_id(
	struct se_cmd *se_cmd, 
	u64 *id_hi,
	u64 *id_lo
	)
{
	struct se_portal_group *se_tpg = NULL;
	struct crypto_hash *tfm;
	struct hash_desc desc;
	struct scatterlist sg;
	unsigned char md5_digest[MD5_SIGNATURE_SIZE];
	u8 initiator_name[256];
	u8 isid[PR_REG_ISID_LEN];
	int ret = -EINVAL;
	
	if (!se_cmd->se_lun)
		return -ENODEV;
	
	if (!se_cmd->se_tfo->sess_get_initiator_sid
	)
		return -EINVAL;
	
	memset(isid, 0, sizeof(isid));
	se_cmd->se_tfo->sess_get_initiator_sid(se_cmd->se_sess, isid,
			PR_REG_ISID_LEN);
	
	memset(initiator_name, 0, sizeof(initiator_name));	

	memcpy(initiator_name, se_cmd->se_tfo->get_initiator_name(se_cmd), 
			min(sizeof(initiator_name), 
			strlen(se_cmd->se_tfo->get_initiator_name(se_cmd)))
			);

	tfm = crypto_alloc_hash("md5", 0, CRYPTO_ALG_ASYNC);
	if (IS_ERR(tfm)) {
		pr_err("Unable to allocate struct crypto_hash\n");
		goto out;
	}
	
	desc.tfm = tfm;
	desc.flags = 0;
		
	ret = crypto_hash_init(&desc);
	if (ret < 0) {
		pr_err("crypto_hash_init() failed\n");
		crypto_free_hash(tfm);
		goto out;
	}
	
	sg_init_one(&sg, &initiator_name[0], strlen(initiator_name));
	ret = crypto_hash_update(&desc, &sg, strlen(initiator_name));
	if (ret < 0) {
		pr_err("crypto_hash_update() failed for initiator name\n");
		crypto_free_hash(tfm);
		goto out;
	}
	
	sg_init_one(&sg, &isid[0], strlen(isid));
	ret = crypto_hash_update(&desc, &sg, strlen(isid));
	if (ret < 0) {
		pr_err("crypto_hash_update() failed for isid\n");
		crypto_free_hash(tfm);
		goto out;
	}
	
	ret = crypto_hash_final(&desc, md5_digest);
	if (ret < 0) {
		pr_err("crypto_hash_final() failed for md5 digest for "
			"initiator name + isid\n");
		crypto_free_hash(tfm);
		goto out;
	}

	*id_hi = *(u64 *)&md5_digest[0];
	*id_lo = *(u64 *)&md5_digest[8];
	
	crypto_free_hash(tfm);
	ret = 0;
out:
	return ret;

}

static int __qnap_odx_create_tpg_id(
	struct se_portal_group *se_tpg,
	u64 *id_hi,
	u64 *id_lo
	)
{
	struct crypto_hash *tfm;
	struct hash_desc desc;
	struct scatterlist sg;
	unsigned char md5_digest[MD5_SIGNATURE_SIZE];
	u8 target_name[256];
	u16 pg_tag = 0;
	int ret = -EINVAL;

	*id_hi = 0;
	*id_lo = 0;
	
	if (!se_tpg->se_tpg_tfo->tpg_get_tag
	|| !se_tpg->se_tpg_tfo->tpg_get_wwn
	)
		return -EINVAL;
	
	pg_tag = se_tpg->se_tpg_tfo->tpg_get_tag(se_tpg);
	
	memset(target_name, 0, sizeof(target_name));
	memcpy(target_name, se_tpg->se_tpg_tfo->tpg_get_wwn(se_tpg), 
			min(sizeof(target_name), 
			strlen(se_tpg->se_tpg_tfo->tpg_get_wwn(se_tpg)))
			);
	
	tfm = crypto_alloc_hash("md5", 0, CRYPTO_ALG_ASYNC);
	if (IS_ERR(tfm)) {
		pr_err("Unable to allocate struct crypto_hash\n");
		goto out;
	}
	
	desc.tfm = tfm;
	desc.flags = 0;
		
	ret = crypto_hash_init(&desc);
	if (ret < 0) {
		pr_err("crypto_hash_init() failed\n");
		crypto_free_hash(tfm);
		goto out;
	}
	
	sg_init_one(&sg, &target_name[0], strlen(target_name));
	ret = crypto_hash_update(&desc, &sg, strlen(target_name));
	if (ret < 0) {
		pr_err("crypto_hash_update() failed for target name\n");
		crypto_free_hash(tfm);
		goto out;
	}
		
	sg_init_one(&sg, &pg_tag, sizeof(u16));
	ret = crypto_hash_update(&desc, &sg, sizeof(u16));
	if (ret < 0) {
		pr_err("crypto_hash_update() failed for pg tag id\n");
		crypto_free_hash(tfm);
		goto out;
	}
	
	ret = crypto_hash_final(&desc, md5_digest);
	if (ret < 0) {
		pr_err("crypto_hash_final() failed for md5 digest for "
			"pg tag + target name\n");
		crypto_free_hash(tfm);
		goto out;
	}
	
	*id_lo = *(u64 *)&md5_digest[0];
	*id_hi = *(u64 *)&md5_digest[8];
	
	crypto_free_hash(tfm);
	ret = 0;
out:
	return ret;

}

static int __qnap_odx_create_cmd_id(
	struct se_cmd *se_cmd, 
	u64 *id_hi,
	u64 *id_lo,
	u32 list_id
	)
{
	struct se_portal_group *se_tpg = NULL;
	struct crypto_hash *tfm;
	struct hash_desc desc;
	struct scatterlist sg;
	unsigned char md5_digest[MD5_SIGNATURE_SIZE];
	int ret = -EINVAL;
		
	if (!se_cmd->se_lun)
		return -ENODEV;
		
	tfm = crypto_alloc_hash("md5", 0, CRYPTO_ALG_ASYNC);
	if (IS_ERR(tfm)) {
		pr_err("Unable to allocate struct crypto_hash\n");
		goto out;
	}
		
	desc.tfm = tfm;
	desc.flags = 0;
			
	ret = crypto_hash_init(&desc);
	if (ret < 0) {
		pr_err("crypto_hash_init() failed\n");
		crypto_free_hash(tfm);
		goto out;
	}
		
	sg_init_one(&sg, &list_id, sizeof(u32));
	ret = crypto_hash_update(&desc, &sg, sizeof(u32));
	if (ret < 0) {
		pr_err("crypto_hash_update() failed for list id\n");
		crypto_free_hash(tfm);
		goto out;
	}

	ret = crypto_hash_final(&desc, md5_digest);
	if (ret < 0) {
		pr_err("crypto_hash_final() failed for md5 digest for "
			"list id + sac\n");
		crypto_free_hash(tfm);
		goto out;
	}
		
	*id_lo = *(u64 *)&md5_digest[0];
	*id_hi = *(u64 *)&md5_digest[8];
		
	crypto_free_hash(tfm);
	ret = 0;
out:
	return ret;

}


int qnap_odx_tpg_add_and_get(
	struct se_portal_group *se_tpg
	)
{
	int ret;

	ret = __qnap_odx_create_tpg_id(se_tpg, &se_tpg->odx_dr.tpg_id_hi, 
			&se_tpg->odx_dr.tpg_id_lo);

	if (ret != 0)
		return ret;

	se_tpg->odx_dr.odx_tpg = odx_rb_tpg_add_and_get(
			se_tpg->odx_dr.tpg_id_hi, se_tpg->odx_dr.tpg_id_lo);

	if (!se_tpg->odx_dr.odx_tpg) {
		pr_warn("fail to get odx_tpg\n");
		return -ENODEV;
	}

	pr_debug("odx_tpg:0x%p, id(hi):0x%llx, id(lo):0x%llx\n", 
		se_tpg->odx_dr.odx_tpg, 
		(unsigned long long)se_tpg->odx_dr.tpg_id_hi,
		(unsigned long long)se_tpg->odx_dr.tpg_id_lo);

	return 0;


}

void qnap_odx_tpg_del(
	struct se_portal_group *se_tpg
	)
{
	int count;

	if (se_tpg->odx_dr.odx_tpg) {

		do {
			count = odx_rb_tpg_put(se_tpg->odx_dr.odx_tpg);
			WARN_ON(count < 0);
		
			if (count == 1)
				break;

			pr_debug("%s: count(%d)\n", __func__, count);
			cpu_relax();
		} while(1);

		odx_rb_tpg_del(se_tpg->odx_dr.odx_tpg);
	}
}

static void qnap_odx_cmd_put_and_del(
	struct se_cmd *se_cmd,
	struct tpc_cmd_data *tc_p
	)
{
	struct se_portal_group *se_tpg = NULL;
	int count;

	if (se_cmd->odx_dr.is_odx_cmd && tc_p) {

		se_tpg = se_cmd->se_sess->se_tpg;

		do {
			count = odx_rb_cmd_put(tc_p);
			WARN_ON(count < 0);

			if (count == 1)
				break;

			pr_debug("%s: count(%d)\n", __func__, count);
			cpu_relax();
		} while(1);

		odx_rb_cmd_del(se_tpg->odx_dr.odx_tpg, tc_p);
	}
}

void qnap_odx_cmd_free(struct se_cmd *se_cmd)
{
	struct tpc_cmd_data *tc_p = NULL;


	if (se_cmd->odx_dr.is_odx_cmd && se_cmd->odx_dr.odx_cmd) {
		tc_p = (struct tpc_cmd_data *)se_cmd->odx_dr.odx_cmd;
		se_cmd->odx_dr.odx_cmd = NULL;
		qnap_odx_cmd_put_and_del(se_cmd, tc_p);
		odx_rb_cmd_free(tc_p);
	}
}

void qnap_odx_se_cmd_init(struct se_cmd *se_cmd)
{
	se_cmd->odx_dr.is_odx_cmd = false;
	se_cmd->odx_dr.cmd_id_lo = 0;
	se_cmd->odx_dr.cmd_id_hi = 0;
	se_cmd->odx_dr.tpg_id_lo = 0;
	se_cmd->odx_dr.tpg_id_hi = 0;
	se_cmd->odx_dr.initiator_id_lo = 0;
	se_cmd->odx_dr.initiator_id_hi = 0;
	se_cmd->odx_dr.list_id = 0;
	se_cmd->odx_dr.sac = 0;
	atomic_set(&se_cmd->odx_dr.odx_cmd_count, 1);
	atomic_set(&se_cmd->odx_dr.odx_tpg_count, 1);
}

/**/
sense_reason_t qnap_odx_emulate_evpd_8f(
	struct se_cmd *se_cmd, 
	unsigned char *buffer
	)
{

	/* please refer spc_emulate_inquiry(), buffer always points to buf[0] */
	struct odx_work_request odx_wr;
	struct __dev_info dev_info;

	memset(&dev_info, 0, sizeof(struct __dev_info));

	if (qnap_transport_create_devinfo(se_cmd, &dev_info) != 0)
		return TCM_LOGICAL_UNIT_COMMUNICATION_FAILURE;

	memset(&odx_wr, 0, sizeof(struct odx_work_request));
	
	/* create odx request and only pick something we need ... */
	odx_wr.cdb = se_cmd->t_task_cdb;
	odx_wr.buff = buffer;
	odx_wr.rc = RC_GOOD;
	memcpy(&odx_wr.reg_data.dev_info, &dev_info, sizeof(struct __dev_info));

	odx_emulate_evpd_8f(&odx_wr);

	/* convert RC to TCM_xxx */
	return qnap_transport_convert_rc_to_tcm_sense_reason(odx_wr.rc);
}

sense_reason_t qnap_odx_wut(
	struct se_cmd *se_cmd
	)
{
	struct se_device *se_dev = se_cmd->se_dev;
	u8 *cdb = se_cmd->t_task_cdb;
	struct odx_work_request odx_wr;
	struct tpc_tpg_data *tpg_p = NULL;
	struct tpc_cmd_data *tc_p = NULL;
	struct __reg_data tmp_reg_data;
	void *p = NULL;
	sector_t all_nr_blks = 0;
	sense_reason_t ret;
	bool go_wut;

	if (!se_cmd->odx_dr.is_odx_cmd)
		return TCM_UNSUPPORTED_SCSI_OPCODE;
	
	/* if length is zero, means no data shall be sent, not treat it as error */
	if(get_unaligned_be32(&cdb[10]) == 0) {
		target_complete_cmd(se_cmd, SAM_STAT_GOOD);
		return TCM_NO_SENSE;
	}

	/* prepare sg list since we need i/o for WUT */
	memset(&odx_wr, 0, sizeof(struct odx_work_request));

	odx_alloc_sg_lists(&odx_wr, ((se_dev->dev_dr.odx_wq) ? true : false));

	/* we need one at least */
	if (!odx_wr.sg_io[0].data_sg) {
		ret = TCM_INSUFFICIENT_RESOURCES;
		goto _out;
	}

	p = transport_kmap_data_sg(se_cmd);
	if (!p) {
		ret = TCM_INSUFFICIENT_RESOURCES;
		goto _out;
	}

	/* following to get tpg_p and tc_p again ... */
	tpg_p = odx_rb_tpg_get(se_cmd->odx_dr.tpg_id_hi, 
			se_cmd->odx_dr.tpg_id_lo);
	if (!tpg_p) {
		ret = TCM_3RD_PARTY_DEVICE_FAILURE;
		goto _out;
	}

	if (tpg_p != se_cmd->odx_dr.odx_tpg) {
		BUG_ON(1);
		odx_rb_tpg_put(tpg_p);
		ret = TCM_3RD_PARTY_DEVICE_FAILURE;
		goto _out;	
	}

	tmp_reg_data.initiator_id_hi = se_cmd->odx_dr.initiator_id_hi;
	tmp_reg_data.initiator_id_lo = se_cmd->odx_dr.initiator_id_lo;
	tmp_reg_data.tpg_id_hi = se_cmd->odx_dr.tpg_id_hi;
	tmp_reg_data.tpg_id_lo = se_cmd->odx_dr.tpg_id_lo;
	tmp_reg_data.cmd_id_hi = se_cmd->odx_dr.cmd_id_hi;
	tmp_reg_data.cmd_id_lo = se_cmd->odx_dr.cmd_id_lo;
	tmp_reg_data.list_id = se_cmd->odx_dr.list_id;
	tmp_reg_data.sac = se_cmd->odx_dr.sac;
	tmp_reg_data.cmd_type = se_cmd->odx_dr.cmd_type;

	tc_p = odx_rb_cmd_get(tpg_p, &tmp_reg_data, false, false);
	if (!tc_p) {
		odx_rb_tpg_put(tpg_p);
		ret = TCM_3RD_PARTY_DEVICE_FAILURE;
		goto _out;
	}	

	if (tc_p != se_cmd->odx_dr.odx_cmd) {
		BUG_ON(1);
		odx_rb_cmd_put(tc_p);
		odx_rb_tpg_put(tpg_p);	
		ret = TCM_3RD_PARTY_DEVICE_FAILURE;
		goto _out;	
	}

	/* create odx request */
	odx_wr.cdb = se_cmd->t_task_cdb;
	odx_wr.odx_wq = se_dev->dev_dr.odx_wq;
	odx_wr.buff = p;
	odx_wr.tpg_p = tpg_p;
	odx_wr.tc_p = tc_p;
#ifdef SUPPORT_TPC_CMD
	odx_wr.se_dev = (void *)se_cmd->se_dev;
#endif	
	odx_wr.rc = RC_GOOD;
	memcpy(&odx_wr.reg_data, &tc_p->reg_data, sizeof(struct __reg_data));

	/* filter something first */
	if (odx_core_before_wut(&odx_wr, &go_wut) == 0) {
		if (go_wut)
			odx_core_wut(&odx_wr);
	}

	/* report transfer count here */
	se_cmd->odx_dr.transfer_counts = odx_wr.transfer_counts;

	odx_rb_cmd_put(tc_p);
	odx_rb_tpg_put(tpg_p);	

	/* convert RC to TCM_xxx */
	ret = qnap_transport_convert_rc_to_tcm_sense_reason(odx_wr.rc);

_out:
	if (p)
		transport_kunmap_data_sg(se_cmd);

	odx_free_sg_lists(&odx_wr);

	if (ret == TCM_NO_SENSE)
		target_complete_cmd(se_cmd, SAM_STAT_GOOD);

	return ret;

}

sense_reason_t qnap_odx_pt(
	struct se_cmd *se_cmd
	)
{
	struct se_device *se_dev = se_cmd->se_dev;
	u8 *cdb = se_cmd->t_task_cdb;
	sector_t all_nr_blks = 0;
	void *p = NULL;
	struct tpc_tpg_data *tpg_p = NULL;
	struct tpc_cmd_data *tc_p = NULL;
	struct odx_work_request odx_wr;
	struct __reg_data tmp_reg_data;
	sense_reason_t ret;
	bool go_pt;

	if (!se_cmd->odx_dr.is_odx_cmd)
		return TCM_UNSUPPORTED_SCSI_OPCODE;

	/* if length is zero, means no data shall be sent, not treat it as error */
	if(get_unaligned_be32(&cdb[10]) == 0) {
		target_complete_cmd(se_cmd, SAM_STAT_GOOD);
		return TCM_NO_SENSE;
	}

	memset(&odx_wr, 0, sizeof(struct odx_work_request));

	/* we do NOT need to any io for PT command so not set data_sg_nents,
	 * data_len and data_sg here
	 */	
	p = transport_kmap_data_sg(se_cmd);
	if (!p) {
		ret = TCM_INSUFFICIENT_RESOURCES;
		goto _out;
	}

	/* following to get tpg_p and tc_p again ... */
	tpg_p = odx_rb_tpg_get(se_cmd->odx_dr.tpg_id_hi, se_cmd->odx_dr.tpg_id_lo);
	if (!tpg_p) {
		ret = TCM_3RD_PARTY_DEVICE_FAILURE;
		goto _out;
	}

	if (tpg_p != se_cmd->odx_dr.odx_tpg) {
		WARN_ON(1);
		odx_rb_tpg_put(tpg_p);
		ret = TCM_3RD_PARTY_DEVICE_FAILURE;
		goto _out;	
	}

	tmp_reg_data.initiator_id_hi = se_cmd->odx_dr.initiator_id_hi;
	tmp_reg_data.initiator_id_lo = se_cmd->odx_dr.initiator_id_lo;
	tmp_reg_data.tpg_id_hi = se_cmd->odx_dr.tpg_id_hi;
	tmp_reg_data.tpg_id_lo = se_cmd->odx_dr.tpg_id_lo;
	tmp_reg_data.cmd_id_hi = se_cmd->odx_dr.cmd_id_hi;
	tmp_reg_data.cmd_id_lo = se_cmd->odx_dr.cmd_id_lo;
	tmp_reg_data.list_id = se_cmd->odx_dr.list_id;
	tmp_reg_data.sac = se_cmd->odx_dr.sac;
	tmp_reg_data.cmd_type = se_cmd->odx_dr.cmd_type;

	tc_p = odx_rb_cmd_get(tpg_p, &tmp_reg_data, false, false);
	if (!tc_p) {
		odx_rb_tpg_put(tpg_p);
		ret = TCM_3RD_PARTY_DEVICE_FAILURE;
		goto _out;
	}	

	if (tc_p != se_cmd->odx_dr.odx_cmd) {
		WARN_ON(1);
		odx_rb_cmd_put(tc_p);
		odx_rb_tpg_put(tpg_p);
		ret = TCM_3RD_PARTY_DEVICE_FAILURE;
		goto _out;	
	}

	/* create odx request */
	odx_wr.cdb = se_cmd->t_task_cdb;
	odx_wr.odx_wq = se_dev->dev_dr.odx_wq;
	odx_wr.buff = p;
	odx_wr.tpg_p = tpg_p;
	odx_wr.tc_p = tc_p;
#ifdef SUPPORT_TPC_CMD
	odx_wr.se_dev = (void *)se_cmd->se_dev;
#endif	
	odx_wr.rc = RC_GOOD;
	memcpy(&odx_wr.reg_data, &tc_p->reg_data, sizeof(struct __reg_data));

	/* filter something first */
	if (odx_core_before_pt(&odx_wr, &go_pt) == 0) {
		if (go_pt)
			odx_core_pt(&odx_wr);
	}

	odx_rb_cmd_put(tc_p);
	odx_rb_tpg_put(tpg_p);

	/* report transfer count here */
	se_cmd->odx_dr.transfer_counts = odx_wr.transfer_counts;

	/* convert RC to TCM_xxx */
	ret = qnap_transport_convert_rc_to_tcm_sense_reason(odx_wr.rc);

_out:
	if (p)
		transport_kunmap_data_sg(se_cmd);

	if (ret == TCM_NO_SENSE)
		target_complete_cmd(se_cmd, SAM_STAT_GOOD);

	return ret;

}

sense_reason_t qnap_odx_rrti(
	struct se_cmd *se_cmd
	)
{
	struct tpc_tpg_data *tpg_p = NULL;
	u8 *cdb = se_cmd->t_task_cdb;
	struct odx_work_request odx_wr;
	void *p = NULL;
	int ret;

	if (!se_cmd->odx_dr.is_odx_cmd)
		return TCM_UNSUPPORTED_SCSI_OPCODE;

	/*
	 * SPC4R36, page 428
	 *
	 * The copy manager shall discard the parameter data for the created
	 * ROD tokens:
	 *
	 * a) after all ROD tokens created by a specific copy operation have
	 *    been transferred without errors to the application client
	 * b) if a RECEIVE ROD TOKEN INFORMATION command has been received on
	 *    the same I_T nexus with a matching list id with the
	 *    ALLOCATION LENGTH field set to zero
	 * c) if another a 3rd party command that originates a copy operation
	 *    is received on the same I_T nexus and the list id matches the
	 *    list id associated with the ROD tokens
	 * d) if the copy manager detects a LU reset conditionor I_T nexus loss
	 *    condition or
	 * e) if the copy manager requires the resources used to preserve the
	 *    data
	 *
	 */
	if (get_unaligned_be32(&cdb[10]) < __odx_get_min_rrti_param_len()) {
		pr_err("allocation length:0x%x < min RRTI param len\n", 
			get_unaligned_be32(&cdb[10]));
		return TCM_PARAMETER_LIST_LENGTH_ERROR;
	}

	p = transport_kmap_data_sg(se_cmd);
	if (!p)
		return TCM_INSUFFICIENT_RESOURCES;

	tpg_p = odx_rb_tpg_get(se_cmd->odx_dr.tpg_id_hi, se_cmd->odx_dr.tpg_id_lo);
	if (!tpg_p) {
		transport_kunmap_data_sg(se_cmd);
		return TCM_3RD_PARTY_DEVICE_FAILURE;
	}

	if (tpg_p != se_cmd->odx_dr.odx_tpg) {
		WARN_ON(1);
		odx_rb_tpg_put(tpg_p);
		transport_kunmap_data_sg(se_cmd);
		return TCM_3RD_PARTY_DEVICE_FAILURE;
	}

	/* create odx request */
	odx_wr.cdb = cdb;
	odx_wr.buff = p;
	odx_wr.tpg_p = tpg_p;
	odx_wr.tc_p = NULL;
	odx_wr.rc = RC_GOOD;
	odx_wr.reg_data.initiator_id_hi = se_cmd->odx_dr.initiator_id_hi;
	odx_wr.reg_data.initiator_id_lo = se_cmd->odx_dr.initiator_id_lo;
	odx_wr.reg_data.tpg_id_hi = se_cmd->odx_dr.tpg_id_hi;
	odx_wr.reg_data.tpg_id_lo = se_cmd->odx_dr.tpg_id_lo;
	odx_wr.reg_data.cmd_id_hi = se_cmd->odx_dr.cmd_id_hi;
	odx_wr.reg_data.cmd_id_lo = se_cmd->odx_dr.cmd_id_lo;
	odx_wr.reg_data.list_id = se_cmd->odx_dr.list_id;
	odx_wr.reg_data.sac = se_cmd->odx_dr.sac;

	/* list id in RRTI will be used to track previous ODX cmd (PT or WUT), 
	 * so set cmd type to CP_OP here due to either CP_OP or MONITOR_OP will
	 * be in cmd rb tree
	 */
	odx_wr.reg_data.cmd_type = ODX_CP_OP;	

	ret = odx_core_rrti(&odx_wr);

	odx_rb_tpg_put(tpg_p);

	transport_kunmap_data_sg(se_cmd);

	if (ret != 0)
		return qnap_transport_convert_rc_to_tcm_sense_reason(odx_wr.rc);

	target_complete_cmd(se_cmd, SAM_STAT_GOOD);
	return TCM_NO_SENSE;


}


/*
 * @fn int qnap_odx_is_in_progress(struct se_cmd *se_cmd)
 *
 * @brief To check whether the same 3rd-party ODX copy command is in progress
 *        or not
 * @note
 * @param[in] cmd
 * @retval: 0       - 3rd-party ODX copy cmd is in progress
 * @retval: 1       - 3rd-party ODX copy cmd is not in progress
 * @retval: -EINVAL - not 3rd-party ODX copy command or other err after call
 *                    this function
 */
int qnap_odx_is_in_progress(
	struct se_cmd *se_cmd
	)
{
	u8 *cdb = &se_cmd->t_task_cdb[0];
	struct se_portal_group *se_tpg = NULL;
	struct tpc_cmd_data *tc_p = NULL;
	struct __reg_data reg_data;
	u32 list_id;
	int ret;

	if (!se_cmd->se_lun)
		return -EINVAL;

	se_tpg = se_cmd->se_lun->lun_tpg;
	if (!se_tpg->odx_dr.odx_tpg)
		return -EINVAL;

	if ((__odx_is_odx_opcode(cdb) == false)
		|| (__odx_get_list_id_by_cdb(cdb, &list_id) != 0)
	)
		return -EINVAL;

	/* create md5 from necessary information */
	ret = __qnap_odx_create_cmd_id(se_cmd, &reg_data.cmd_id_hi,
			&reg_data.cmd_id_lo, list_id);
	if (ret != 0)
		return -EINVAL;

	ret = __qnap_odx_create_initiator_id(se_cmd, &reg_data.initiator_id_hi,
			&reg_data.initiator_id_lo);
	if (ret != 0)
		return -EINVAL;

	reg_data.tpg_id_lo = se_tpg->odx_dr.tpg_id_lo;
	reg_data.tpg_id_hi = se_tpg->odx_dr.tpg_id_hi;
	reg_data.list_id = list_id;
	reg_data.sac = (cdb[1] & 0x1f);

	if (IS_TPC_SCSI_OP(cdb[0]) && IS_TPC_SCSI_RRTI_OP(cdb[1]))
		reg_data.cmd_type = ODX_MONITOR_OP;
	else
		reg_data.cmd_type = ODX_CP_OP;

	ret = qnap_transport_create_devinfo(se_cmd, &reg_data.dev_info);
	if (ret != 0)
		return -EINVAL;

	/* now to check current odx cmd exists in tree or not */
	tc_p = odx_rb_cmd_get(se_tpg->odx_dr.odx_tpg, &reg_data, 
			false, false);
	if (tc_p) {
		/* if found it, the cmd is in progress */
		pr_warn("odx is in progress. list_id(0x%x), sac(0x%x)\n", 
			tc_p->reg_data.list_id, tc_p->reg_data.sac);

		odx_rb_cmd_put(tc_p);
		return 0;
	}

	/* try add new cmd reocrd if not find it */
	se_cmd->odx_dr.odx_cmd = odx_rb_cmd_add_and_get(se_tpg->odx_dr.odx_tpg, 
		&reg_data);

	if (!se_cmd->odx_dr.odx_cmd)
		return -EINVAL;

	se_cmd->odx_dr.is_odx_cmd = true;
	se_cmd->odx_dr.cmd_type = reg_data.cmd_type;
	se_cmd->odx_dr.odx_tpg = se_tpg->odx_dr.odx_tpg;
	se_cmd->odx_dr.cmd_id_lo = reg_data.cmd_id_lo;
	se_cmd->odx_dr.cmd_id_hi = reg_data.cmd_id_hi;
	se_cmd->odx_dr.tpg_id_hi = reg_data.tpg_id_hi;
	se_cmd->odx_dr.tpg_id_lo = reg_data.tpg_id_lo;
	se_cmd->odx_dr.initiator_id_hi = reg_data.initiator_id_hi;
	se_cmd->odx_dr.initiator_id_lo = reg_data.initiator_id_lo;
	se_cmd->odx_dr.list_id = reg_data.list_id;
	se_cmd->odx_dr.sac = reg_data.sac;

	pr_debug("%s: op(0x%x), list_id(0x%x), sac(0x%x), type:%d, tpg_p(0x%p), "
		"odx_p(0x%p), cmd id(hi):0x%llx, cmd id(lo):0x%llx, "
		"initiator id(hi):0x%llx, initiator id(lo):0x%llx\n",
		__func__, cdb[0], list_id, (cdb[1] & 0x1f), se_cmd->odx_dr.cmd_type, 
		se_cmd->odx_dr.odx_tpg, se_cmd->odx_dr.odx_cmd, 
		(unsigned long long)reg_data.cmd_id_hi,
		(unsigned long long)reg_data.cmd_id_lo,
		(unsigned long long)reg_data.initiator_id_hi,
		(unsigned long long)reg_data.initiator_id_lo);

	return 1;
}

static void __qnap_odx_ask_to_drop(
	struct se_cmd *se_cmd,
	int type
	)
{
	struct tpc_cmd_data *tp_data = NULL;

	if (!se_cmd->odx_dr.is_odx_cmd)
		return;

	if (!se_cmd->odx_dr.odx_cmd)
		return;

	tp_data = (struct tpc_cmd_data *)se_cmd->odx_dr.odx_cmd;


	switch(type) {
	case -1:
		/* RELEASE CONN */
		atomic_set(&tp_data->cmd_asked, CMD_ASKED_BY_RELEASE_CONN);
		break;
	case TMR_ABORT_TASK:
		atomic_set(&tp_data->cmd_asked, CMD_ASKED_BY_ABORT_TASK);
		break;
	case TMR_ABORT_TASK_SET:
		atomic_set(&tp_data->cmd_asked, CMD_ASKED_BY_ABORT_TASK_SET);
		break;
	case TMR_CLEAR_ACA:
		atomic_set(&tp_data->cmd_asked, CMD_ASKED_BY_CLEAR_ACA);
		break;
	case TMR_CLEAR_TASK_SET:
		atomic_set(&tp_data->cmd_asked, CMD_ASKED_BY_CLEAR_TASK_SET);
		break;
	case TMR_LUN_RESET:
		atomic_set(&tp_data->cmd_asked, CMD_ASKED_BY_LUN_RESET);
		break;
	case TMR_TARGET_WARM_RESET:
		atomic_set(&tp_data->cmd_asked, CMD_ASKED_BY_TARGET_WARM_RESET);
		break;
	case TMR_TARGET_COLD_RESET:
		atomic_set(&tp_data->cmd_asked, CMD_ASKED_BY_TARGET_COLD_RESET);
		break;
	default:
		break;
	}

	return;
}

void qnap_odx_drop_cmd(
	struct se_cmd *se_cmd,
	int type
	)
{
	__qnap_odx_ask_to_drop(se_cmd, type);
}

struct lba_len_desc_data {
	u8	*start_desc;
	u16	desc_count;
	u8	cdb0;
	u8	cdb1;
};

struct lba_len_data {
	sector_t lba;
	u32 nr_blks;
};


/* 1   : format in not in (generic) write dir cmd 
 * 0   : format is what we want
 * < 0 : other error
 */
static int __qnap_odx_parse_write_blk_desc_cmd_data(
	struct se_cmd *se_cmd,
	void *desc_data
	)
{
	u8 *cdb = se_cmd->t_task_cdb;
	struct lba_len_desc_data *ll_desc_data = (struct lba_len_desc_data *)desc_data;
	u8 *p = NULL;
	int ret = 0;

	/* we will do kunmap data sg outside if to parse format successfully */
	if((p = (u8 *)transport_kmap_data_sg(se_cmd)) == NULL)
	    return -ENOMEM;
	
	switch(cdb[0]){
	case UNMAP:
		ll_desc_data->start_desc = (u8 *)(p + 8);
		ll_desc_data->desc_count = 
				__odx_get_desc_counts(get_unaligned_be16(&p[2]));

		if (!ll_desc_data->desc_count)
			ret = 1;
		break;
	default:
		ret = 1;
		break;
	}

	/* if parse format successfully, we don't */
	if (ret && p)
	     transport_kunmap_data_sg(se_cmd);

	return ret;

}


/* 1   : format in not in (generic) write dir cmd 
 * 0   : format is what we want
 * < 0 : other error
 */
static int __qnap_odx_parse_write_dir_cmd_data(
	struct se_cmd *se_cmd,
	void *desc_data
	)
{
	u8 *cdb = se_cmd->t_task_cdb;
	struct lba_len_data *desc = (struct lba_len_data *)desc_data;
	u16 sac = 0;
	int ret = 0;


	switch(cdb[0]){
	case WRITE_6:
		desc->nr_blks = (u32)(cdb[4] ? : 256);
		desc->lba = (sector_t)(__get_unaligned_be24(&cdb[1]) & 0x1fffff);
		break;

	case XDWRITEREAD_10:
	case WRITE_VERIFY:
	case WRITE_10:
		desc->nr_blks = (u32)get_unaligned_be16(&cdb[7]);
		desc->lba = (sector_t)get_unaligned_be32(&cdb[2]);
	        break;

	case WRITE_VERIFY_12:
	case WRITE_12:
		desc->nr_blks = (u32)get_unaligned_be32(&cdb[6]);
		desc->lba = (sector_t)get_unaligned_be32(&cdb[2]);
		break;

//	case WRITE_VERIFY_16:
 	case WRITE_16:
		desc->nr_blks = (u32)get_unaligned_be32(&cdb[10]);
		desc->lba = (sector_t)get_unaligned_be64(&cdb[2]);
		break;

	case WRITE_SAME:
		desc->nr_blks = (u32)get_unaligned_be16(&cdb[7]);
		desc->lba = get_unaligned_be32(&cdb[2]);
		break;

	case WRITE_SAME_16:
		desc->nr_blks = (u32)get_unaligned_be32(&cdb[10]);
		desc->lba = get_unaligned_be64(&cdb[2]);
		break;

	case COMPARE_AND_WRITE:
		desc->nr_blks = (u32)cdb[13];
		desc->lba = get_unaligned_be64(&cdb[2]);
		break;

	case VARIABLE_LENGTH_CMD:
		sac = get_unaligned_be16(&cdb[8]);
		switch (sac) {
		case XDWRITEREAD_32:
			desc->nr_blks = (u32)get_unaligned_be32(&cdb[28]);	
			/* For VARIABLE_LENGTH_CDB w/ 32 byte extended CDBs */
			desc->lba = (sector_t)get_unaligned_be64(&cdb[12]);
			break;
		case WRITE_SAME_32:
			desc->nr_blks = (u32)get_unaligned_be32(&cdb[28]);
			desc->lba = get_unaligned_be64(&cdb[12]);
			break;
		default:
			pr_warn("warning, %s - VARIABLE_LENGTH_CMD service "
				"action 0x%04x not supported\n", __func__, sac);
			ret = 1;
			break;
		}
		break;
	default:
		ret = 1;
		break;
	}

	return ret;

}


/* 0	  : cancel token successfully or not need to cancel token 
 *	    even the parsing format is correct
 * others : parsing forma is not we want ot other errors
 */
static int __qnap_odx_is_to_cancel_token(
	struct se_cmd *se_cmd,
	int (*qnap_parse_cmd_data)(struct se_cmd *, void *)
	)
{
	struct se_device *se_dev = se_cmd->se_dev;
	struct se_portal_group *se_tpg = NULL;
	struct tpc_tpg_data *tpg_p = NULL;
	struct blk_dev_range_desc *start_desc = NULL;
	struct blk_dev_range_desc tmp_range_desc;
	struct lba_len_desc_data ll_desc_data;
	struct lba_len_data ll_data;
	struct __dev_info dev_info;
	bool parse_blk_desc = false;
	u16 desc_idx = 0;
	int ret;	

	if ((se_cmd->data_direction != DMA_TO_DEVICE) || !se_cmd->se_lun 
		|| !se_cmd->se_lun->lun_tpg
	)
		return -EINVAL;

	ret = qnap_transport_create_devinfo(se_cmd, &dev_info);
	if (ret != 0)
		return -EINVAL;

	if (qnap_parse_cmd_data != __qnap_odx_parse_write_dir_cmd_data) {
		parse_blk_desc = true;		
		ret = qnap_parse_cmd_data(se_cmd, (void *)&ll_desc_data);
	} else
		ret = qnap_parse_cmd_data(se_cmd, (void *)&ll_data);


	/* 1   : format is not hwat we want
	 * 0   : format is what we want
	 * < 0 : other error
	 */
	if (ret)
		return ret;

	/* no any data to be transfered if len is zero */
	if (!parse_blk_desc && !ll_data.nr_blks)
		return 0;
	else if (parse_blk_desc && !ll_desc_data.desc_count)
		return 0;

	if (!parse_blk_desc) {
		put_unaligned_be64(ll_data.lba, &tmp_range_desc.lba[0]);
		put_unaligned_be32(ll_data.nr_blks, &tmp_range_desc.nr_blks[0]);
		ll_desc_data.desc_count = 1;
		ll_desc_data.start_desc = (u8 *)&tmp_range_desc;
	}

	ll_desc_data.cdb0 = se_cmd->t_task_cdb[0];
	ll_desc_data.cdb1 = se_cmd->t_task_cdb[1];

	/* start to check each token range [lba, nr_blks] with passing command */
	se_tpg = se_cmd->se_lun->lun_tpg;
	tpg_p = odx_rb_tpg_get(se_tpg->odx_dr.tpg_id_hi, se_tpg->odx_dr.tpg_id_lo);

	if (tpg_p) {	
		start_desc = (struct blk_dev_range_desc *)ll_desc_data.start_desc;
		
		for (desc_idx = 0; desc_idx < ll_desc_data.desc_count; desc_idx++){
			if (get_unaligned_be32(&start_desc[desc_idx].nr_blks[0]) == 0)
				continue;
		
			odx_rb_parse_conflict_token_range(tpg_p, &dev_info, 
				&start_desc[desc_idx], desc_idx, 
				ll_desc_data.cdb0, ll_desc_data.cdb1);
		}
		odx_rb_tpg_put(tpg_p);
	}

	/* take care we do kmap in __qnap_odx_parse_write_blk_desc_cmd_data already */
	if (parse_blk_desc && ll_desc_data.desc_count)
		transport_kunmap_data_sg(se_cmd);

	return 0;
}

void qnap_odx_is_to_cancel_token(
	struct se_cmd *se_cmd
	)
{
	int ret;

	ret = __qnap_odx_is_to_cancel_token(se_cmd, 
		__qnap_odx_parse_write_dir_cmd_data);

	if (ret) {
		__qnap_odx_is_to_cancel_token(se_cmd, 
			__qnap_odx_parse_write_blk_desc_cmd_data);
	}
}



