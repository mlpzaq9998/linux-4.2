/*******************************************************************************
 * Filename:  target_core_qspc.c
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
#include "target_core_internal.h"
#include "target_core_qtransport.h"
#include "target_core_qspc.h"
#include "iscsi/iscsi_target_qlog.h"
#include "target_core_ua.h"

/* log sense command function table */
static int __qnap_spc_logsense_lbp(struct se_cmd *cmd, u8 *buf);

LOGSENSE_FUNC_TABLE g_logsense_table[] ={
#ifdef SUPPORT_TP
    {0xc, 0x0, __qnap_spc_logsense_lbp, 0x0},
#endif
    {0x0, 0x0, NULL, 0x1},
};

static int __qnap_spc_modeselect_caching(struct se_cmd *se_cmd, u8 sp, u8 *p);

static struct {
	uint8_t		page;
	uint8_t		subpage;
	int		(*emulate)(struct se_cmd *, u8, unsigned char *);
} modeselect_handlers[] = {
	{ .page = 0x08, .subpage = 0x00, .emulate = __qnap_spc_modeselect_caching },
};


#ifdef SUPPORT_TP
static int __qnap_spc_logsense_lbp(
	struct se_cmd *se_cmd, 
	u8 *buf
	)
{
	LBP_LOG_PARAMETER_FORMAT *format = NULL;
	u16 off = 4, len = 0;
	u32 avail = 0, used = 0;
	struct se_device *se_dev = se_cmd->se_dev;
	int ret = 0, tmp_len = 4;

	/* currently, we support
	 * (1) Available LBA Mapping Resource count log parameter
	 * (2) and, Used LBA Mapping Resource count log parameter
	 */
	len = (2 * sizeof(LBP_LOG_PARAMETER_FORMAT));

	/* sbc3r35j, page 244
	 * Logical Block Provisioning log page Header (4-bytes) 
	 */
	buf[0] = (0x0c | 0x80); /* set= SPF bit (bit 6) to 0, DS bit (bit 7) to 1 */
	buf[1] = 0x00;

	if (se_cmd->data_length < (4 + len))
		ret = -EINVAL;

	if (qnap_transport_get_ac_and_uc_on_thin(se_dev, &avail, &used) != 0) {
		pr_warn("%s: fail to get avail/used res count\n", __func__);
		ret = -EINVAL;
	}

	if (ret == -EINVAL) {
		/* only return 4 bytes if got any error */
		put_unaligned_be16(tmp_len, &buf[2]);	    
		return tmp_len;
	}
	
	/* Available LBA Mapping Resource count log parameter format */
	format = (LBP_LOG_PARAMETER_FORMAT *)&buf[off];
	format->parameter_code[0] = (0x0001 >> 8) & 0xff;
	format->parameter_code[1] = 0x0001 & 0xff;
	format->du = 0;
	format->tsd = 1;
	format->etc = 0;
	format->tmc = 0;
	format->format_and_linking = 3;
	format->parameter_length = 0x8;
	format->resource_count[0] = (avail >> 24 ) & 0xff;
	format->resource_count[1] = (avail >> 16 ) & 0xff;
	format->resource_count[2] = (avail >> 8 ) & 0xff;
	format->resource_count[3] = avail  & 0xff;

	/* set to 10b to indicate the RESOURCE COUNT field may or may not be
	 * dedicated to any logical unit including the addressed logical unit.
	 * Usage of resources on other logical units may impact the resource count
	 */
	format->scope = 2;

	/* Used LBA Mapping Resource count log parameter */
	off += 12;
	format  = (LBP_LOG_PARAMETER_FORMAT *)&buf[off];
	format->parameter_code[0] = (0x0002 >> 8) & 0xff;
	format->parameter_code[1] = 0x0002 & 0xff;
	format->du = 0;
	format->tsd = 1;
	format->etc = 0;
	format->tmc = 0;
	format->format_and_linking = 3;
	format->parameter_length = 0x8;
	format->resource_count[0] = (used >> 24 ) & 0xff;
	format->resource_count[1] = (used >> 16 ) & 0xff;
	format->resource_count[2] = (used >> 8 ) & 0xff;
	format->resource_count[3] = used	& 0xff;

	/* set to 01b to indicate the RESOURCE COUNT field is dedicated to the
	 * logical unit. Usage of resources on other logical units does not
	 * impact the resource count
	 */
	format->scope = 1;
	
	put_unaligned_be16(len, &buf[2]);
		    
	return (4 + len);

}
#endif

sense_reason_t qnap_spc_logsense(
	struct se_cmd *se_cmd
	)
{
	u8 *rbuf = NULL, *data_buf = NULL;
	u8 pagecode, sub_pagecode;
	int length = 0, i;
	sense_reason_t reason;

	pagecode = (se_cmd->t_task_cdb[2] & 0x3f);
	sub_pagecode = se_cmd->t_task_cdb[3];

	if (!se_cmd->data_length){
		target_complete_cmd(se_cmd, GOOD);
		return TCM_NO_SENSE;
	}

	/* spc4r37a , p373
	 * sp bit (save parameters bit) set to one specifies that device server
	 * shall perform the specified LOG SENSE command and save all log
	 * parameters as saveavle by DS bit to a nonvolatile, vendor specific
	 * location.
	 * If sp bit set to one and LU doesn't implement saveing log parameters,
	 * the device shall terminate the command with CHECK CONDITION status 
	 * with the sense key set to ILLEGAL REQUEST, and the additinal sense
	 * code set to INVALID FIELD IN CDB
	 */
	if (se_cmd->t_task_cdb[1] & 0x1) {
		reason = TCM_INVALID_CDB_FIELD;
		goto _exit_;
	}

	/* at least, we need 4 bytes even not report any log parameter */
	if (se_cmd->data_length < 4){
		reason = TCM_INVALID_CDB_FIELD;
 		goto _exit_;
	}

	rbuf = transport_kmap_data_sg(se_cmd);
	if (!rbuf){
		reason = TCM_OUT_OF_RESOURCES;
		goto _exit_;
	}

	data_buf = kmalloc(se_cmd->data_length, GFP_KERNEL);
	if (!data_buf){
		reason = TCM_OUT_OF_RESOURCES;
		goto _exit_;
	}

	/* spec4r37a, page374
	 * If the log page specified by the page code and subpage code
	 * combination is reserved or not implemented, then the device server
	 * shall terminate the command with CHECK CONDITION status with the
	 * sense key set to ILLEGAL REQUEST, and the additinal sense code set
	 * to INVALID FIELD IN CDB
	 */
	reason = TCM_INVALID_CDB_FIELD;

	memset(data_buf, 0, se_cmd->data_length);

	for (i = 0; i < ARRAY_SIZE(g_logsense_table); i++){
		if ((g_logsense_table[i].end != 0x1) 
		&& (g_logsense_table[i].logsense_func != NULL)
		&& (g_logsense_table[i].page_code == pagecode)
		&& (g_logsense_table[i].sub_page_code == sub_pagecode)
		)
		{
			length = g_logsense_table[i].logsense_func(se_cmd, 
				&data_buf[0]);

			if (length != 0){
				reason = TCM_NO_SENSE;
				memcpy(rbuf, data_buf, length);
				target_complete_cmd_with_length(se_cmd, 
					GOOD, length);
			}
			break;
		}
	}

_exit_:
	if (data_buf)
		kfree(data_buf);

	if (rbuf)
		transport_kunmap_data_sg(se_cmd);

	return reason;
}
EXPORT_SYMBOL(qnap_spc_logsense);

int qnap_transport_notify_ua_to_other_it_nexus(
	struct se_cmd *se_cmd,
	u8 asc, 
	u8 ascq	
	)
{
	unsigned long flags;
	struct se_session *se_sess;
	struct se_portal_group *se_tpg;
	struct se_node_acl *se_acl;
	struct se_dev_entry *se_deve;
	unsigned char isid_buf[PR_REG_ISID_LEN];

	if (!se_cmd->se_sess)
		return -EINVAL;

	se_sess = se_cmd->se_sess;
	if (!se_sess->se_tpg)
		return -EINVAL;

	se_tpg = se_sess->se_tpg;

	mutex_lock(&se_tpg->acl_node_mutex);
	list_for_each_entry(se_acl, &se_tpg->acl_node_list, acl_list) {

		spin_lock_irqsave(&se_acl->nacl_sess_lock, flags);

		if (!strncasecmp(se_acl->initiatorname, DEFAULT_INITIATOR, 
			sizeof(DEFAULT_INITIATOR)))
		{
			spin_unlock_irqrestore(&se_acl->nacl_sess_lock, flags);
			continue;		
		}

		if (!strncasecmp(se_acl->initiatorname, FC_DEFAULT_INITIATOR,
			sizeof(FC_DEFAULT_INITIATOR)))
		{
			spin_unlock_irqrestore(&se_acl->nacl_sess_lock, flags);
			continue;
		}

		if (!se_acl->nacl_sess) {
			spin_unlock_irqrestore(&se_acl->nacl_sess_lock, flags);
			continue;
		}

		/* skip it_nexus received the mode select command */
		if (se_sess == se_acl->nacl_sess) {
			pr_debug("found sess as cmd issuer, skip it..., "
				"node:%s, isid:%s\n", 
				se_acl->initiatorname, isid_buf);

			spin_unlock_irqrestore(&se_acl->nacl_sess_lock, flags);
			continue;
		}

		mutex_lock(&se_acl->lun_entry_mutex);
		se_deve = target_nacl_find_deve(se_acl, se_cmd->se_lun->unpacked_lun);
		if (!se_deve) {
			mutex_unlock(&se_acl->lun_entry_mutex);
			spin_unlock_irqrestore(&se_acl->nacl_sess_lock, flags);
			continue;
		}

		if (!(se_deve->lun_flags & TRANSPORT_LUNFLAGS_READ_WRITE)) {
			mutex_unlock(&se_acl->lun_entry_mutex);
			spin_unlock_irqrestore(&se_acl->nacl_sess_lock, flags);
			continue;
		}

		mutex_unlock(&se_acl->lun_entry_mutex);
		spin_unlock_irqrestore(&se_acl->nacl_sess_lock, flags);
		mutex_unlock(&se_tpg->acl_node_mutex);


		if (se_tpg->se_tpg_tfo->sess_get_initiator_sid != NULL) {
			memset(&isid_buf[0], 0, PR_REG_ISID_LEN);
			se_tpg->se_tpg_tfo->sess_get_initiator_sid(
				se_acl->nacl_sess, &isid_buf[0], PR_REG_ISID_LEN);
		}


		/* find the it_nexus we want ... */
		pr_info("alloc UA (asc:0x%x, ascq:0x%x) for lun:0x%x, "
			"on node:%s, isid:%s\n", asc, ascq, 
			se_deve->mapped_lun, se_acl->initiatorname, isid_buf);

		core_scsi3_ua_allocate(se_deve, asc, ascq);

		mutex_lock(&se_tpg->acl_node_mutex);
	}
	mutex_unlock(&se_tpg->acl_node_mutex);
	return 0;
}

static int __qnap_spc_modeselect_caching(
	struct se_cmd *se_cmd, 
	u8 sp,
	u8 *p
	)
{
	int wce, invalid = 0, i, ret = 0;
	struct fd_dev *fd_dev = NULL;

	struct se_device *se_dev = se_cmd->se_dev;
	struct iblock_dev *ib_dev = NULL;
	bool is_fio_blkdev;

	if (qnap_transport_is_fio_blk_backend(se_dev) == 0)
		is_fio_blkdev = true;
	else if (qnap_transport_is_iblock_fbdisk(se_dev) == 0)
		is_fio_blkdev = false;
	else
		ret = -ENODEV;

	if (!se_dev->transport->set_write_cache || !se_dev->transport->set_fua)
		ret = -ENODEV;

	if (ret == -ENODEV) {
		pr_warn("not support mode select - caching mode page\n");
		return ret;
	}

	if (p[1] != 0x12)
		return -EINVAL;

	wce = ((p[2] & 0x4) ? 1: 0);

	if (target_check_wce(se_dev) == (bool)wce)
		return 0;

	/* Do not support changing WCE while V_SUP is 0 */
	if(!qnap_check_v_sup(se_dev))
		return -EINVAL;

	/* TBD: 
	 * hmmm ... here will do something checking , actually, we don't want 
	 * to update others except the wce bit (it shall depend on the answer
	 * from mode sense command for caching modepage)
	 */
	for (i = 3; i < 20; i++) {
		if (i != 12) {
			if (p[i] != 0x0)
				invalid = 1;
		} else {
			if (p[i] != 0x20)
				invalid = 1;
		}
		if (invalid)
			break;
	}

	if (invalid) {
		pr_err("mode page data contents not same as answer from"
			" mode sense - caching mode page\n");
		return -EINVAL;
	}

	if ((target_check_wce(se_dev) == true) && (wce == 0)) {
		/* we shall flush cache here if wce bit becomes from 1 to 0 
		 * sbc3r35j, p265
		 */
		if (is_fio_blkdev == true) {
			fd_dev = qnap_transport_get_fd_dev(se_dev);
			ret = vfs_fsync_range(fd_dev->fd_file, 0, LLONG_MAX, 1);
		} else {
			ib_dev = qnap_transport_get_iblock_dev(se_dev);
			ret = blkdev_issue_flush(ib_dev->ibd_bd, GFP_KERNEL, NULL);
		}

		if (ret != 0)
			pr_warn("fail to flush when WCE bit becomes "
				"from 1 to 0, ret: %d\n", ret);
	}

	se_dev->transport->set_write_cache(se_dev, (bool)wce);

	pr_debug("done to %s WCE bit\n", ((wce == 1) ? "enable": "disable"));

	/* ack MODE PARAMETERS CHANGED via UA to other I_T nexuses */
	qnap_transport_notify_ua_to_other_it_nexus(se_cmd, 0x2A,
		ASCQ_2AH_MODE_PARAMETERS_CHANGED);

	return 0;
}

sense_reason_t qnap_spc_emulate_modeselect(
	struct se_cmd *se_cmd
	)
{
	struct se_device *se_dev = se_cmd->se_dev;
	char *cdb = se_cmd->t_task_cdb;
	bool ten = cdb[0] == MODE_SELECT_10;
	int off, dev_type, llba_bit, blk_desc_len;
	u8 page, subpage;
	unsigned char *buf, *mode_pdata;
	int length;
	sense_reason_t s_ret = TCM_LOGICAL_UNIT_COMMUNICATION_FAILURE;
	int i, ret;

	if (!se_cmd->data_length) {
		target_complete_cmd(se_cmd, GOOD);
		return TCM_NO_SENSE;
	}

	/* PF (page format)
	 * 0 - all parameters after the block descriptors are vendor specific
	 * 1 - all parameters after header and block descriptors are structured
	 *     as pages of related parameters
	 */
	if (!(cdb[1] & 0x10))
		return TCM_INVALID_CDB_FIELD;

	buf = transport_kmap_data_sg(se_cmd);
	if (!buf)
		return TCM_OUT_OF_RESOURCES;

	/* spc4r37a, sectio 7.5.4 mode parameter list format */
	if (ten) {
		dev_type = buf[2];
		llba_bit = (buf[4] & 1);
		blk_desc_len = get_unaligned_be16(&buf[6]);
	} else {
		dev_type = buf[1];
		llba_bit = 0;
		blk_desc_len = buf[3];
	}

	/* 1. for MODE SELECT command, the MODE_DATA_LENGTH shall be reserved 
	 * 2. check the medium type (shall be 00h for sbc)
	 * 3. for device-specific parameter (WP bit and DPOFUA bit shall be
	 *    ignored and reserved for MODE SELECT command)
	 */
	if ((se_dev->transport->get_device_type(se_dev) != TYPE_DISK)
	|| (dev_type != TYPE_DISK)
	)
	{
		pr_err("%s: medium type is not correct\n", __func__);
		transport_kunmap_data_sg(se_cmd);
		return TCM_INVALID_PARAMETER_LIST;
	}

	/* TBD: if block descriptor length is 0, it is not error condition */
	if (blk_desc_len){
		/* we do not support to change any value reported in block descriptor. 
		 * So to ignore it
		 */
	} 

	if (ten)
		mode_pdata = &buf[8 + blk_desc_len];
	else
		mode_pdata = &buf[4 + blk_desc_len];

	/* spc4r37a, section 7.5.7 */
	page = mode_pdata[0] & 0x3f;
	subpage = mode_pdata[0] & 0x40 ? mode_pdata[1] : 0;

	for (i = 0; i < ARRAY_SIZE(modeselect_handlers); i++) {
		if (modeselect_handlers[i].page == page &&
		    modeselect_handlers[i].subpage == subpage) {
			ret = modeselect_handlers[i].emulate(se_cmd, 
				(cdb[1] & 0x01), mode_pdata);

			if (ret == -EINVAL)
				s_ret = TCM_INVALID_PARAMETER_LIST;

			goto out;
		}
	}

	ret = -EINVAL;
	s_ret = TCM_UNKNOWN_MODE_PAGE;

out:
	transport_kunmap_data_sg(se_cmd);

	if (!ret) {
		s_ret = TCM_NO_SENSE;
		target_complete_cmd(se_cmd, GOOD);
	}

	return s_ret;
}
EXPORT_SYMBOL(qnap_spc_emulate_modeselect);

int qnap_spc_modesense_caching(
	struct se_cmd *se_cmd, 
	u8 pc, 
	u8 *p
	)
{
	int ret = qnap_transport_is_fio_blk_backend(se_cmd->se_dev);

	p[0] = 0x08;
	p[1] = 0x12;

	/* PC (page controal)
	 * 1 - changeable value
	 */
	if (pc == 1) {
		/* WCE can be set on fio + blk_backend only, to return mask */
		if (ret == 0)
			p[2] = 0x04;
		goto out;
	}

	if (target_check_wce(se_cmd->se_dev))
		p[2] = 0x04; /* Write Cache Enable */
	p[12] = 0x20; /* Disabled Read Ahead */
out:
	return 20;

}


