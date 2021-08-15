/*******************************************************************************
 * Filename:  iscsi_target_qtransport.c
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
#include <linux/string.h>
#include <linux/kthread.h>
#include <linux/crypto.h>
#include <linux/completion.h>
#include <linux/module.h>
#include <linux/vmalloc.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/list.h>
#include <linux/backing-dev.h>
#include <asm/unaligned.h>

#include <target/target_core_base.h>
#include <target/target_core_backend.h>
#include <target/target_core_fabric.h>
#include <target/iscsi/iscsi_target_core.h>
#include "iscsi_target_parameters.h"
#include "iscsi_target_datain_values.h"
#include "iscsi_target_util.h"
#include <target/iscsi/iscsi_transport.h>

#include "../target_core_iblock.h"
#include "../target_core_file.h"
#include "iscsi_target_qlog.h"

#include "iscsi_target_qtransport.h"
#include "iscsi_target_qconfigfs.h"
#include "../target_core_qtransport.h"

#ifdef CONFIG_MACH_QNAPTS

struct nl_func *nl_func_p = NULL;

void qnap_nl_create_func_table(void)
{
	/* TBD: anything is good to get functon table ??? */
	if (!nl_func_p)
		nl_func_p = (struct nl_func *)qnap_nl_get_nl_func();
}

void qnap_nl_send_post_log(
	int conn_type,
	int log_type,
	struct iscsi_session *sess,
	char *ip
)
{
	struct iscsi_portal_group *tpg = NULL;
	char *target_iqn = NULL;

	if (!nl_func_p)
		return;

	tpg = (struct iscsi_portal_group *)(sess)->tpg;
	target_iqn = (tpg && tpg->tpg_tiqn && strlen(tpg->tpg_tiqn->tiqn) > 0) \
		? (char *)tpg->tpg_tiqn->tiqn : "Discovery Session";

	if (LOGIN_OK == conn_type) {
		struct timeval cur_time;
		do_gettimeofday(&cur_time);
		sess->login_time = cur_time.tv_sec;
	}

	nl_func_p->nl_post_log_send(conn_type, log_type, 
		sess->sess_ops->InitiatorName, target_iqn, ip);

}

void qnap_nl_rt_conf_update(
	int conn_type,
	int log_type,
	char *key,
	char *val
)
{
	if (!nl_func_p)
		return;

	nl_func_p->nl_rt_conf_update(conn_type, log_type, key, val);
}

#ifdef QNAP_KERNEL_STORAGE_V2
struct workqueue_struct *acl_notify_info_wq = NULL;
struct kmem_cache *acl_notify_info_cache = NULL;

void qnap_create_acl_notify_info_wq(void)
{
	acl_notify_info_wq = alloc_workqueue("acl_notify_info_wq",
			(WQ_HIGHPRI | WQ_MEM_RECLAIM | WQ_UNBOUND), 0);
	if (!acl_notify_info_wq)
		pr_warn("%s: fail to create acl_notify_info_wq\n", __func__);
	return;
}

void qnap_destroy_acl_notify_info_wq(void)
{
	if (acl_notify_info_wq) {
		flush_workqueue(acl_notify_info_wq);
		destroy_workqueue(acl_notify_info_wq);
	}
	return;
}

void qnap_create_acl_notify_info_cache(void)
{
	acl_notify_info_cache = kmem_cache_create("acl_notify_info_cache",
			sizeof(struct notify_data),
			__alignof__(struct notify_data), 0, NULL);

	if (!acl_notify_info_cache)
		pr_warn("%s: fail to create acl_notify_info_cache\n", __func__);
	return;
}

void qnap_destroy_acl_notify_info_cache(void)
{
	if (acl_notify_info_cache)
		kmem_cache_destroy(acl_notify_info_cache);
	return;
}

int qnap_target_nacl_update_show_info(
       struct notify_data *n_data
       )
{
       struct file *fd = NULL;
       mm_segment_t fs;
       struct iovec iov[1];
       int ret = 0;

       fd = filp_open(n_data->path, 
               O_CREAT | O_WRONLY | O_APPEND , S_IRWXU);
       if (IS_ERR (fd))
               return -EINVAL;
       
       memset(iov, 0, sizeof(struct iovec));
       iov[0].iov_base = &n_data->data[0];
       iov[0].iov_len = n_data->data_size;

       fs = get_fs();
       set_fs(get_ds());
       ret = vfs_writev(fd, &iov[0], 1, &fd->f_pos);
       set_fs(fs);

       if(ret < 0)
               pr_err("%s: vfs_writev error!!\n", __func__);

       filp_close(fd, NULL);
       return ((ret < 0) ? ret : 0);

}

static void __qnap_target_acl_notify_info_work(
	struct work_struct *work
	)
{
	struct notify_data *data = 
		container_of(work, struct notify_data, work);

	struct se_node_acl *se_nacl = data->se_nacl;

	qnap_target_nacl_update_show_info(data);

	vfree(data->data);

	qnap_free_acl_notify_info_cache(data);

	/* to indicate we finished to write acl info data */
	spin_lock(&se_nacl->acl_read_info_lock);
	atomic_dec_mb(&se_nacl->acl_read_info);
	spin_unlock(&se_nacl->acl_read_info_lock);
	return;
}


static void __qnap_target_nacl_show_info_null_work(
	struct work_struct *work
	)
{
	struct notify_data *data = 
		container_of(work, struct notify_data, work);

	struct se_node_acl *se_nacl = data->se_nacl;

	qnap_free_acl_notify_info_cache(data);

	/* to indicate we finished to write acl info data */
	spin_lock(&se_nacl->acl_read_info_lock);
	atomic_dec_mb(&se_nacl->acl_read_info);
	spin_unlock(&se_nacl->acl_read_info_lock);
	return;
}

int qnap_put_acl_notify_info_work(
	struct notify_data *data
	)
{
	if (acl_notify_info_wq) {
		INIT_WORK(&data->work, __qnap_target_acl_notify_info_work);
		queue_work(acl_notify_info_wq, &data->work);
		return 0;
	}
	return -ENODEV;
}

int qnap_put_acl_notify_info_null_work(
	struct notify_data *data
	)
{
	if (acl_notify_info_wq) {
		INIT_WORK(&data->work, __qnap_target_nacl_show_info_null_work);
		queue_work(acl_notify_info_wq, &data->work);
		return 0;
	}
	return -ENODEV;

}
#endif

static unsigned char __decode_base64_digit(
	char base64
	)
{
	switch (base64) {
	case '=':
		return 64;
	case '/':
		return 63;
	case '+':
		return 62;
	default:
		if ((base64 >= 'A') && (base64 <= 'Z'))
			return base64 - 'A';
		else if ((base64 >= 'a') && (base64 <= 'z'))
			return 26 + (base64 - 'a');
		else if ((base64 >= '0') && (base64 <= '9'))
			return 52 + (base64 - '0');
		else
			return -1;
	}
}

static void __decode_base64_string(
	char *string, 
	unsigned char *intnum, 
	int int_len
	)
{
	int len;
	int count;
	int intptr;
	unsigned char num[4];
	int octets;

	if ((string == NULL) || (intnum == NULL))
		return;
	len = strlen(string);
	if (len == 0)
		return;

	if ((len % 4) != 0)
		return;

	count = 0;
	intptr = 0;
	while (count < len - 4) {
		num[0] = __decode_base64_digit(string[count]);
		num[1] = __decode_base64_digit(string[count + 1]);
		num[2] = __decode_base64_digit(string[count + 2]);
		num[3] = __decode_base64_digit(string[count + 3]);
		if ((num[0] == 65) || (num[1] == 65) 
		|| (num[2] == 65) || (num[3] == 65)
		)
			return;

		count += 4;
		octets =
		    (num[0] << 18) | (num[1] << 12) | (num[2] << 6) | num[3];
		intnum[intptr] = (octets & 0xFF0000) >> 16;
		intnum[intptr + 1] = (octets & 0x00FF00) >> 8;
		intnum[intptr + 2] = octets & 0x0000FF;
		intptr += 3;
	}
	num[0] = __decode_base64_digit(string[count]);
	num[1] = __decode_base64_digit(string[count + 1]);
	num[2] = __decode_base64_digit(string[count + 2]);
	num[3] = __decode_base64_digit(string[count + 3]);
	if ((num[0] == 64) || (num[1] == 64)) {
		intnum[intptr + 1] = '\0';
		return;
	}
	if (num[2] == 64) {
		if (num[3] != 64) {
			intnum[intptr + 1] = '\0';
			return;
		}
		intnum[intptr] = (num[0] << 2) | (num[1] >> 4);
		intnum[intptr + 1] = '\0';
	} else if (num[3] == 64) {
		intnum[intptr] = (num[0] << 2) | (num[1] >> 4);
		intnum[intptr + 1] = (num[1] << 4) | (num[2] >> 2);
		intnum[intptr + 2] = '\0';
	} else {
		octets =
		    (num[0] << 18) | (num[1] << 12) | (num[2] << 6) | num[3];
		intnum[intptr] = (octets & 0xFF0000) >> 16;
		intnum[intptr + 1] = (octets & 0x00FF00) >> 8;
		intnum[intptr + 2] = octets & 0x0000FF;
		intnum[intptr + 3] = '\0';
	}
}

void qnap_iscsit_chap_base64_to_hex(
	unsigned char *dst, 
	unsigned char *src, 
	int len
	)
{
	__decode_base64_string(src, dst, len);
}

void __qnap_iscsit_tmf_clear_dealy_remove(
	struct iscsi_cmd *cmd
	)
{
	if (cmd->cmd_flags & ICF_DELAYED_REMOVE)
		cmd->cmd_flags &= ~ICF_DELAYED_REMOVE;	
	return;
}

void qnap_iscsit_tmf_clear_dealy_remove(
	struct iscsi_cmd *cmd
	)
{
	spin_lock_bh(&cmd->istate_lock);
	__qnap_iscsit_tmf_clear_dealy_remove(cmd);
	spin_unlock_bh(&cmd->istate_lock);
	return;
}

int qnap_iscsit_tmf_handle_send_response(
	struct iscsi_cmd *cmd, 
	struct iscsi_conn *conn,
	int *ret_code
	)
{
	int resp_tas = cmd->se_cmd.tmf_resp_tas;
	struct se_cmd *se_cmd = &cmd->se_cmd;
	bool is_thin = false;
	int type_ret;
	SUBSYSTEM_TYPE *type;

	if (qnap_transport_check_is_thin_lun(se_cmd->se_dev) == 1)
		is_thin = true;

	type_ret = qnap_transport_get_subsys_dev_type(se_cmd->se_dev, &type);

	printk_ratelimited(KERN_WARNING "[RESP] "
		"iscsi cmd(ITT:0x%08x), cmdsn:0x%08x "
		"from ip:%s to lun:0x%x. "
		"filebased:%s, thin:%s. cmd dropped by "
		"TMF request(op:0x%x) from %s i_t nexus. resp TAS:0x%x\n",
		be32_to_cpu(cmd->init_task_tag), cmd->cmd_sn,
		((cmd->conn) ? cmd->conn->login_ip : "null"), 
		se_cmd->orig_fe_lun, 
		((type_ret != 0) ? "unknown" : \
		((type == SUBSYSTEM_BLOCK) ? "yes" : "no")),
		((is_thin == true) ? "yes": "no"),
		se_cmd->tmf_code, 
		((se_cmd->tmf_diff_it_nexus == 1) ? "diff": "same"),
		se_cmd->tmf_resp_tas);

	/* exit if we need to resp the TAS bit for response pdu */
	if (resp_tas)
		return resp_tas;

	iscsit_increment_maxcmdsn(cmd, conn->sess);

	/* check this is last dataout or not */
	spin_lock_bh(&cmd->istate_lock);
	if (cmd->cmd_flags & ICF_GOT_LAST_DATAOUT){
		pr_debug("[RESP]: cmd(ITT:0x%8x), "
		"cmd_flags:0x%x, clear ICF_DELAYED_REMOVE\n",
		be32_to_cpu(cmd->init_task_tag), cmd->cmd_flags,
		cmd->se_cmd.tmf_resp_tas);

		__qnap_iscsit_tmf_clear_dealy_remove(cmd);
	}
	spin_unlock_bh(&cmd->istate_lock);

	*ret_code = 2;
	return 0;

}

void qnap_iscsit_tmf_handle_send_datain(
	struct iscsi_cmd *cmd, 
	struct iscsi_conn *conn,
	struct iscsi_datain_req *dr,
	int *end_of_datain_req,
	int tas
	)
{
	struct se_cmd *se_cmd = &cmd->se_cmd;
	bool is_thin = false;
	int type_ret;
	SUBSYSTEM_TYPE *type;

	if (qnap_transport_check_is_thin_lun(se_cmd->se_dev) == 1)
		is_thin = true;

	type_ret = qnap_transport_get_subsys_dev_type(se_cmd->se_dev, &type);

	if (tas == 1 || dr->dr_complete) {
		printk_ratelimited(KERN_WARNING "[DATA-IN] "
			"iscsi cmd(ITT:0x%08x), cmdsn:0x%08x, "
			"from ip:%s to lun:0x%x. filebased:%s, thin:%s. "
			"cmd dropped by TMR (op:0x%x) "
			"from %s i_t nexus. resp TAS:0x%x\n",
			be32_to_cpu(cmd->init_task_tag), cmd->cmd_sn,
			((cmd->conn) ? cmd->conn->login_ip : "null"), 
			se_cmd->orig_fe_lun, 
			((type_ret != 0) ? "unknown" : \
			((type == SUBSYSTEM_BLOCK) ? "yes" : "no")),
			((is_thin == true) ? "yes": "no"),
			se_cmd->tmf_code, 
			((se_cmd->tmf_diff_it_nexus == 1) ? "diff": "same"),
			se_cmd->tmf_resp_tas);
	}

	if (tas == 1) {
		/* if session of aborted object is different with 
		 * task management function, skip to send all data-in
		 */
		iscsit_free_all_datain_reqs(cmd);

		if (se_cmd->se_cmd_flags & SCF_TRANSPORT_TASK_SENSE)
			se_cmd->se_cmd_flags &= ~SCF_TRANSPORT_TASK_SENSE;

		if (!(se_cmd->scsi_status & SAM_STAT_TASK_ABORTED))
			se_cmd->scsi_status |= SAM_STAT_TASK_ABORTED;

		spin_lock_bh(&cmd->istate_lock);
		cmd->i_state = ISTATE_SEND_STATUS;
		spin_unlock_bh(&cmd->istate_lock);

		*end_of_datain_req = 2;
		return;
	}


	if (!dr->dr_complete) {
		*end_of_datain_req = 0;
		return;
	}

	/* update eodr and free necessary datain req */
	*end_of_datain_req = (cmd->se_cmd.se_cmd_flags & \
		SCF_TRANSPORT_TASK_SENSE) ? 2 : 1;

	iscsit_free_datain_req(cmd, dr);
	iscsit_increment_maxcmdsn(cmd, conn->sess);

	spin_lock_bh(&cmd->istate_lock);	
	pr_debug("[DATA-IN] cmd(ITT:0x%08x), cmd_flags:0x%x, "
		"TAS resp:0x%x, to clear ICF_DELAYED_REMOVE\n",
		be32_to_cpu(cmd->init_task_tag), cmd->cmd_flags,
		cmd->se_cmd.tmf_resp_tas);

	__qnap_iscsit_tmf_clear_dealy_remove(cmd);
	spin_unlock_bh(&cmd->istate_lock);
	return;
}

int qnap_lio_tmf_set_clear_delay_remove(
	struct se_cmd *se_cmd, 
	int opt, 
	int lock
	)
{
	struct iscsi_cmd *cmd = container_of(se_cmd, struct iscsi_cmd, se_cmd);

	if ((opt == 0 || opt == 1) && (lock == 0 || lock == 1)){

		if (lock)
			spin_lock_bh(&cmd->istate_lock);

		pr_debug("%s: %s ICF_DELAYED_REMOVE for cmd(ITT:0x%08x)\n",
			__func__, ((opt) ? "set" : "clear"), 
			be32_to_cpu(cmd->init_task_tag));

		if (opt)
			cmd->cmd_flags |= ICF_DELAYED_REMOVE;
		else
			cmd->cmd_flags &= ~ICF_DELAYED_REMOVE;

		if (lock)
			spin_unlock_bh(&cmd->istate_lock);
	}
	return 0;
}

int qnap_iscsit_check_received_cmdsn(
	struct iscsi_session *sess, 
	u32 cmdsn
	)
{
	/* this code was referred from iscsit_check_received_cmdsn() */
	int ret;

	/*
	 * This is the proper method of checking received CmdSN against
	 * ExpCmdSN and MaxCmdSN values, as well as accounting for out
	 * or order CmdSNs due to multiple connection sessions and/or
	 * CRC failures.
	 */
	if (iscsi_sna_gt(cmdsn, sess->max_cmd_sn)) {
		pr_debug("Received CmdSN: 0x%08x is greater than"
		       " MaxCmdSN: 0x%08x, ignoring.\n", cmdsn,
		       sess->max_cmd_sn);

		ret = CMDSN_MAXCMDSN_OVERRUN;
	}
	else if (cmdsn == sess->exp_cmd_sn)
		ret = CMDSN_NORMAL_OPERATION;
	else if (iscsi_sna_gt(cmdsn, sess->exp_cmd_sn)) {
		/* mc/s may come here */
		pr_debug("Received CmdSN: 0x%08x is greater"
		      " than ExpCmdSN: 0x%08x, not acknowledging.\n",
		      cmdsn, sess->exp_cmd_sn);

		ret = CMDSN_HIGHER_THAN_EXP;
	} else {
		pr_debug("Received CmdSN: 0x%08x is less than"
		       " ExpCmdSN: 0x%08x, ignoring.\n", cmdsn,
		       sess->exp_cmd_sn);

		ret = CMDSN_LOWER_THAN_EXP;
	}
	return ret;
}


#ifdef SUPPORT_ISCSI_ZERO_COPY

static int  __qnap_iscsit_zc_exec_write_end(
	struct file *file,
	int page_idx,
	int page_allocated,
	struct RECV_FILE_CONTROL_BLOCK *rv_cb
	)
{
	struct address_space *mapping = file->f_mapping;
	int ret, idx = page_idx;

	for (idx = 0; idx < page_allocated; idx++){
		kunmap(rv_cb[idx].rv_page);
		ret = mapping->a_ops->write_end(file, mapping, 
			rv_cb[idx].rv_pos, rv_cb[idx].rv_count, 
			rv_cb[idx].rv_count, rv_cb[idx].rv_page, 
			rv_cb[idx].rv_fsdata);
	}
	return ret;
}

static ssize_t __qnap_iscsit_zc_splice(
	struct file *file, 
	struct socket *sock,
	loff_t __user *ppos,
	size_t count
	)
{
	struct address_space *mapping = file->f_mapping;
	struct inode *inode = mapping->host;
	loff_t pos = *ppos;
	int count_tmp, err = 0, cPagesAllocated = 0;
	int count2 = (count / PAGE_SIZE)+1, ret;
	struct RECV_FILE_CONTROL_BLOCK rv_cb[count2 + 1];
	struct kvec iov[count2 + 1];
	struct msghdr msg;
	long rcvtimeo;
	struct blk_plug plug;

	mutex_lock(&inode->i_mutex);

	blk_start_plug(&plug);

	/* We can write back this queue in page reclaim */
	current->backing_dev_info = inode_to_bdi(inode);

	err = file_remove_privs(file);
	if (err)
		goto done;

	err = file_update_time(file); 
	if (err)
		goto done;

	count_tmp = count;

	do {
		unsigned long bytes;	/* Bytes to write to page */
		unsigned long offset;	/* Offset into pagecache page */
		struct page *pageP;
		void *fsdata;
	
		offset = (pos & (PAGE_CACHE_SIZE - 1));
		bytes = PAGE_CACHE_SIZE - offset;
		if (bytes > count_tmp)
			bytes = count_tmp;
	
		ret = mapping->a_ops->write_begin(file, mapping, pos, 
			bytes, AOP_FLAG_UNINTERRUPTIBLE,&pageP,&fsdata);
	
		if (unlikely(ret)){
			err = ret;
			__qnap_iscsit_zc_exec_write_end(file, 0, 
				cPagesAllocated, &rv_cb[0]);
			goto done;
		}
		rv_cb[cPagesAllocated].rv_page = pageP;
		rv_cb[cPagesAllocated].rv_pos = pos;
		rv_cb[cPagesAllocated].rv_count = bytes;
		rv_cb[cPagesAllocated].rv_fsdata = fsdata;
		iov[cPagesAllocated].iov_base = kmap(pageP) + offset;
		iov[cPagesAllocated].iov_len = bytes;
		cPagesAllocated++;
		count_tmp -= bytes;
		pos += bytes;
	} while (count_tmp);

	/* IOV is ready, receive the date from socket now */
	msg.msg_name = NULL;
	msg.msg_namelen = 0;
	msg.msg_control = NULL;
	msg.msg_controllen = 0;
	msg.msg_flags = MSG_KERNSPACE;
	rcvtimeo = sock->sk->sk_rcvtimeo;    
	sock->sk->sk_rcvtimeo = 3 * HZ;
	
	ret = kernel_recvmsg(sock, &msg, &iov[0], cPagesAllocated, 
		count, MSG_WAITALL | MSG_NOCATCHSIGNAL);
	sock->sk->sk_rcvtimeo = rcvtimeo;


	if (unlikely(ret < 0)){
		err = ret;
		__qnap_iscsit_zc_exec_write_end(file, 0, 
			cPagesAllocated, &rv_cb[0]);
		goto done;
	} else {
		err = 0;
		pos = pos - count + ret;
		count = ret;
	}

	__qnap_iscsit_zc_exec_write_end(file, 0, cPagesAllocated, &rv_cb[0]);
	balance_dirty_pages_ratelimited(mapping);
done:
	current->backing_dev_info = NULL;

	blk_finish_plug(&plug);
	mutex_unlock(&inode->i_mutex);

	if (err) {
		printk("%s: err:0x%x\n",__func__, err);
		return err;
	}
	return count;
}

ssize_t qnap_iscsit_zc_splice(
	struct se_cmd *se_cmd,
	struct socket *sock,
	u32 hdr_off,
	u32 size
	)
{
	struct fd_dev *fd_dev = qnap_transport_get_fd_dev(se_cmd->se_dev);
	struct file *file = fd_dev->fd_file;
	struct address_space *mapping = file->f_mapping;
	struct inode *inode = mapping->host;
	int bs_order = ilog2(se_cmd->se_dev->dev_attrib.block_size);
	loff_t pos = 0;

	/* do zc splice on fio + block backend only now */
	if (!S_ISBLK(inode->i_mode))
		return -ENODEV;

	pos = (loff_t)hdr_off;
	pos += ((loff_t)se_cmd->t_task_lba << bs_order);
	return __qnap_iscsit_zc_splice(file, sock, &pos, (size_t)size);
}

int qnap_iscsit_zc_splice_work_on_scsi_op(
	struct se_cmd *se_cmd
	)
{
	int zc_val = 0;

	/* zero-copy only supports on fio + blkdev configuration */
	if(!strcmp(se_cmd->se_dev->transport->name, "fileio")
	&& (qnap_transport_is_fio_blk_backend(se_cmd->se_dev) == 0)
	)
	{
		if ((se_cmd->t_task_cdb[0] == WRITE_6)
		||  (se_cmd->t_task_cdb[0] == WRITE_10)
		||  (se_cmd->t_task_cdb[0] == WRITE_12)
		||  (se_cmd->t_task_cdb[0] == WRITE_16)
		||  ((se_cmd->t_task_cdb[0] == VARIABLE_LENGTH_CMD)
			&& (get_unaligned_be16(&se_cmd->t_task_cdb[8]) == WRITE_32)))
		{
			spin_lock(&se_cmd->se_dev->dev_dr.dev_zc_lock);
			zc_val = se_cmd->se_dev->dev_dr.dev_zc;
			spin_unlock(&se_cmd->se_dev->dev_dr.dev_zc_lock);

			/* no ... */
			if (zc_val == 0)
				return 0;
		
			/* yes ... */
			return 1;
		}
	}

	/* no ... */
	return 0;
}

int qnap_iscsit_check_do_zc_splice(
	struct se_cmd *se_cmd
	)
{
	int ret, zc_ret = 1;
	struct se_device *se_dev = se_cmd->se_dev;

	if(!strcmp(se_dev->transport->name, "fileio")
	&& (qnap_transport_is_fio_blk_backend(se_dev) == 0)
	&& (se_cmd->digest_zero_copy_skip == false)
	)
	{
#ifdef SUPPORT_TP
		/* still go zc if not thin lun */
		if(qnap_transport_check_is_thin_lun(se_dev) != 1) {
			zc_ret = 0;
			goto _exit_;
		}

		/* 0: normal i/o (not hit sync i/o threshold)
		 * 1: hit sync i/o threshold
		 * -ENOSPC: pool space is full
		 * -EINVAL: wrong parameter to call function
		 * -ENODEV: no such device
		 */
		struct fd_dev *fd_dev = se_dev->transport->get_dev(se_dev);

		ret = qlib_fd_check_dm_thin_cond(fd_dev->fd_file);
		if ((ret == -ENOSPC) || (ret == 1)) {
			pr_debug("%s: convert to sync i/o. ret: %d\n", 
				__func__, ret);

			/* not go zc splice ... */
			goto _exit_;
		}
#endif
		/* go zc splice */
		zc_ret = 0;
	}

_exit_:

	/* not go zc splice ... */
	if (zc_ret == 1)
		se_cmd->digest_zero_copy_skip = true;

	return zc_ret;
}

#endif

#ifdef SUPPORT_SINGLE_INIT_LOGIN
/* Jonathan Ho, 20140416,  one target can be logged in from only one initiator IQN */
int qnap_iscsit_search_tiqn_for_initiator(
	struct iscsi_tiqn *tiqn,
	char *InitiatorName)
{
	struct iscsi_portal_group *tpg = NULL;
	struct se_portal_group *se_tpg = NULL;
	struct se_node_acl *acl = NULL;
	struct se_session *se_sess = NULL;
	struct iscsi_session *sess = NULL;
	struct iscsi_sess_ops *sess_ops = NULL;
	struct qnap_se_nacl_dr *dr = NULL;
	struct qnap_se_node_acl *qnap_nacl = NULL;

	pr_debug("search Target: %s for Initiator IQN: %s\n", tiqn->tiqn, InitiatorName);
	spin_lock(&tiqn->tiqn_tpg_lock);
	list_for_each_entry(tpg, &tiqn->tiqn_tpg_list, tpg_list) {
		pr_debug("get Target Portal Group Tag: %hu\n", tpg->tpgt);
		spin_lock(&tpg->tpg_state_lock);
		if (tpg->tpg_state == TPG_STATE_FREE) {
			spin_unlock(&tpg->tpg_state_lock);
			continue;
		}
		spin_unlock(&tpg->tpg_state_lock);

		se_tpg = &tpg->tpg_se_tpg;
		dr = &se_tpg->se_nacl_dr;

		spin_lock(&dr->acl_node_lock);
		list_for_each_entry(qnap_nacl, &dr->acl_node_list, acl_node) {
			if (!strcmp(qnap_nacl->initiatorname, DEFAULT_INITIATOR))
				continue;

			if (!strcmp(qnap_nacl->initiatorname, FC_DEFAULT_INITIATOR))
				continue;

			if (strcmp(InitiatorName, qnap_nacl->initiatorname)) {
				pr_debug("get different, i_buf:%s, "
					"nacl initiator name: %s\n", 
					InitiatorName, qnap_nacl->initiatorname);
			
				/* make sure to unlock all spin lock before return */
				spin_unlock(&dr->acl_node_lock);
				spin_unlock(&tiqn->tiqn_tpg_lock);
				return -1;
			} else
				pr_debug("get same IQN: %s\n", qnap_nacl->initiatorname);
		}
		spin_unlock(&dr->acl_node_lock);
	}
	spin_unlock(&tiqn->tiqn_tpg_lock);
	return 0;
}
#endif

#ifdef QNAP_KERNEL_STORAGE_V2

#define TMP_TGT_INFO_FILE_PAT	"/tmp/%s/%s/target_info"

static int __qnap_check_tmp_tgt_info_file(
	struct se_node_acl *se_nacl,
   	struct se_portal_group *se_tpg,
   	struct notify_data *n_data
	)
{
	struct se_wwn *wwn = NULL;
	struct file *fd = NULL;

	if (!se_nacl || !se_tpg)
		return -EINVAL;

	wwn = se_tpg->se_tpg_wwn;
	snprintf(n_data->path, sizeof(n_data->path), TMP_TGT_INFO_FILE_PAT, 
		wwn->wwn_group.cg_item.ci_name,se_nacl->initiatorname);

	fd = filp_open(n_data->path, O_CREAT | O_WRONLY | O_TRUNC , S_IRWXU);
	if (!IS_ERR(fd)) {
		filp_close(fd, NULL);
		return 0;
	}

	pr_err("%s: path error:%s \n", __func__, n_data->path);
	return -EINVAL;

}

static ssize_t __qnap_update_tmp_tgt_info_buf_s1(
	struct iscsi_session *sess,
	char *buf,
	ssize_t read_bytes
	)
{
	struct iscsi_sess_ops *sess_ops = sess->sess_ops;

	read_bytes += sprintf(buf + read_bytes, "SID,%u,%hu,"
		"%d,", sess->sid, sess->tsih, atomic_read(&sess->nconn));

	read_bytes += sprintf(buf + read_bytes, "%s,",
		(sess_ops->SessionType) ? "Discovery" : "Normal");

	read_bytes += sprintf(buf + read_bytes, 
		"%hu,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u\n",
		sess_ops->TargetPortalGroupTag, sess_ops->InitialR2T, 
		sess_ops->ImmediateData, sess_ops->MaxOutstandingR2T, 
		sess_ops->FirstBurstLength, sess_ops->MaxBurstLength,
		sess_ops->DataSequenceInOrder, sess_ops->DataPDUInOrder,
		sess_ops->ErrorRecoveryLevel, sess_ops->MaxConnections,
		sess_ops->DefaultTime2Wait, sess_ops->DefaultTime2Retain
		);

	return read_bytes;
}

static ssize_t __qnap_update_tmp_tgt_info_buf_s2(
	struct iscsi_session *sess,
	struct iscsi_conn *conn,
	char *buf,
	ssize_t read_bytes,
	int first_conn
	)
{
	struct iscsi_sess_ops *sess_ops = sess->sess_ops;

	if (!first_conn) {
		read_bytes += sprintf(buf + read_bytes, "IQN,%s,%s,%lld\n", 
			sess_ops->InitiatorName, conn->login_ip, 
			sess->login_time);
	} else
		read_bytes += sprintf(buf + read_bytes, 
			"!,%s\n",conn->login_ip);

	return read_bytes;
}

#endif

#ifdef ISCSI_D4_INITIATOR
ssize_t qnap_lio_nacl_show_info(
	struct se_node_acl *se_nacl,
	char *page
	)
{
	struct iscsi_session *sess;
	struct iscsi_conn *conn;
	struct se_session *se_sess, *tmp_se_sess;
   	struct se_portal_group *se_tpg = NULL;
	struct se_node_acl *acl;
	struct iscsi_sess_ops *sess_ops;
	ssize_t rb = 0;
	bool is_default_initiator;

#ifdef QNAP_KERNEL_STORAGE_V2
	int first_conn, go_next;
	struct notify_data *n_data = NULL;

	/* TODO (shall be smart here ...)
	 * size for one target_info file per session (one conn) is about 115
	 * bytes now, we consider case about there are many sessions (conns)
	 * connect to one target ... hope the buffer is enough
	 */
#define DATA_SIZE	(8 * PAGE_SIZE)

#else /* !QNAP_KERNEL_STORAGE_V2 */

	char *tmp_page = NULL, *old_page = NULL;
	ssize_t old_rb = 0;
	int buf_result = 0;

#endif

	if (se_nacl)
		se_tpg = se_nacl->se_tpg;
	else {
		pr_err("%s:can't get the se_tpg\n", __func__);
		return rb;
	}

	if (se_tpg) {

		if (!strcmp(se_nacl->initiatorname, DEFAULT_INITIATOR))
			is_default_initiator = true;
		else if (!strcmp(se_nacl->initiatorname, FC_DEFAULT_INITIATOR))
			is_default_initiator = true;
		else
			is_default_initiator = false;

#ifdef QNAP_KERNEL_STORAGE_V2

		n_data = qnap_alloc_acl_notify_info_cache();
		if (!n_data) {
			pr_warn("%s: fail to alloc mem from "
				"acl_notify_info_cache\n", __func__);
			return rb;
		}

		n_data->se_nacl = se_nacl;

		spin_lock(&se_nacl->acl_read_info_lock);
		if (atomic_read(&se_nacl->acl_read_info) != 0) {
			spin_unlock(&se_nacl->acl_read_info_lock);
			pr_debug("%s: previuos reading is not finished, "
				"to exit\n", __func__);

			qnap_free_acl_notify_info_cache(n_data);
			return rb;
		}

		/* indicate we will read it now ... */
		atomic_inc_mb(&se_nacl->acl_read_info);
		spin_unlock(&se_nacl->acl_read_info_lock);

		spin_lock(&se_nacl->acl_drop_node_lock);
		if (atomic_read(&se_nacl->acl_drop_node) == 1){
			spin_unlock(&se_nacl->acl_drop_node_lock);
			pr_debug("%s: someone starts to drop acl data now, "
				"to exit now\n", __func__);

			if (qnap_put_acl_notify_info_null_work(n_data) == 0)
				return rb;
			goto _exit_;
		}
		spin_unlock(&se_nacl->acl_drop_node_lock);

		if (__qnap_check_tmp_tgt_info_file(se_nacl, se_tpg, 
				n_data) != 0) {
			if (qnap_put_acl_notify_info_null_work(n_data) == 0)
				return rb;
			goto _exit_;
		}

		n_data->data = NULL;
		n_data->data = vmalloc(DATA_SIZE);
		if (!n_data->data) {
			if (qnap_put_acl_notify_info_null_work(n_data) == 0)
				return rb;
			goto _exit_;
		}

#else /* !QNAP_KERNEL_STORAGE_V2 */

		/* since read of configfs only can carry PAGE_SIZE data, 
		 * we setup tmp buffer size to be (PAGE_SIZE * 2) first
		 */
		tmp_page = kzalloc((PAGE_SIZE * 2), GFP_KERNEL);
		if (!tmp_page)
			return rb;

		/* save original page address and use new one first */
		old_page = page;
		page = tmp_page;
#endif
		mutex_lock(&se_tpg->acl_node_mutex);
		list_for_each_entry(acl, &se_tpg->acl_node_list, acl_list) {

			spin_lock_bh(&acl->nacl_sess_lock);

			/* Since we will get EVERY acl node in this tpg, we
			 * also need check whether passing se_nacl equals to 
			 * acl node from tpg or not. But, this condition shall
			 * be skipped for default initiator.
			 * This shall cowork with solution of bugzilla 79317
			 */
			if ((se_nacl != acl) && (is_default_initiator == false)) {
				spin_unlock_bh(&acl->nacl_sess_lock);
				continue;
			}

			/* please refer __transport_register_session()
			 * so we safe do this 
			 */
			if (!acl->nacl_sess) {
				spin_unlock_bh(&acl->nacl_sess_lock);
				continue;
			}

			/* get each sess from acl node */
			list_for_each_entry_safe(se_sess, tmp_se_sess, 
					&acl->acl_sess_list, sess_acl_list) 

			{
				sess = (struct iscsi_session *)se_sess->fabric_sess_ptr;
				sess_ops = sess->sess_ops;

				spin_lock(&sess->conn_lock);
				if (sess->sess_release) {
					spin_unlock(&sess->conn_lock);
					continue;
				}

#ifdef QNAP_KERNEL_STORAGE_V2
				rb = __qnap_update_tmp_tgt_info_buf_s1(sess, 
					n_data->data, rb);

				/* force to go this way */
				goto _show_conn_;
#endif
				/* Benjamin 20121214 add for showing the
				 * smi-s session parameters. 
				 */
				rb += sprintf(page+rb, "Session ID=%u,TSIH=%hu,"
					"CurrentConnections=%d,", sess->sid, 
					sess->tsih, atomic_read(&sess->nconn));
			
				rb += sprintf(page+rb, "SessionType=%s,",
					(sess_ops->SessionType) ? 
					"Discovery" : "Normal");
			
				rb += sprintf(page+rb, 
					TARGETPORTALGROUPTAG"=%hu,"INITIALR2T"=%u,"
					IMMEDIATEDATA"=%u,"MAXOUTSTANDINGR2T"=%u,"
					FIRSTBURSTLENGTH"=%u,"MAXBURSTLENGTH"=%u,"
					DATASEQUENCEINORDER"=%u,"DATAPDUINORDER"=%u,"
					ERRORRECOVERYLEVEL"=%u,"MAXCONNECTIONS"=%u,"
					DEFAULTTIME2WAIT"=%u,"DEFAULTTIME2RETAIN"=%u\n",
					sess_ops->TargetPortalGroupTag, sess_ops->InitialR2T, 
					sess_ops->ImmediateData, sess_ops->MaxOutstandingR2T, 
					sess_ops->FirstBurstLength, sess_ops->MaxBurstLength,
					sess_ops->DataSequenceInOrder, 
					sess_ops->DataPDUInOrder, sess_ops->ErrorRecoveryLevel, 
					sess_ops->MaxConnections, sess_ops->DefaultTime2Wait, 
					sess_ops->DefaultTime2Retain);

				// show the first connection only
#ifdef QNAP_KERNEL_STORAGE_V2
_show_conn_:
				first_conn = 0;
#endif
				list_for_each_entry(conn, &sess->sess_conn_list, 
					conn_list) 
				{
					if (conn) {
#ifdef QNAP_KERNEL_STORAGE_V2
						rb = __qnap_update_tmp_tgt_info_buf_s2(
							sess, conn, n_data->data, 
							rb, first_conn);

						if (!first_conn)
							first_conn = 1;

						/* force to go this way */
						continue;
#endif
						rb += sprintf(page + rb, 
						"InitiatorName=%s,IP=%s,Login=%lld\n",
						sess_ops->InitiatorName, 
						conn->login_ip, sess->login_time);
					}
				}
				spin_unlock(&sess->conn_lock);
			}
			spin_unlock_bh(&acl->nacl_sess_lock);

#ifndef QNAP_KERNEL_STORAGE_V2
			/* Benjamin 20130315 for BUG 31457: fill_read_buffer()
			 * in configfs can only read one page. 
			 * If exceeds, BUG_ON! 
			 */
			if (rb > PAGE_SIZE) {
				buf_result = -ENOMEM;
				break;
			} else
				old_rb = rb;
#endif
		}
		mutex_unlock(&se_tpg->acl_node_mutex);

#ifdef QNAP_KERNEL_STORAGE_V2
		if (rb) {
			n_data->data_size = rb;

			/* if someone is removing tree now, we put the work to
			 * workqueue
			 */
			spin_lock(&se_nacl->acl_drop_node_lock);
			if (atomic_read(&se_nacl->acl_drop_node) == 1){
				spin_unlock(&se_nacl->acl_drop_node_lock);

				if (qnap_put_acl_notify_info_work(n_data) == 0)
					return 0;	
			}
			spin_unlock(&se_nacl->acl_drop_node_lock);

			/* if nobody is removing tree or fail to put wq, 
			 * try normal path 
			 */
			qnap_target_nacl_update_show_info(n_data);
		} 

		vfree(n_data->data);

		if (rb == 0) {
			if (qnap_put_acl_notify_info_null_work(n_data) == 0)
				return 0;
		}
_exit_:
		qnap_free_acl_notify_info_cache(n_data);
	
		spin_lock(&se_nacl->acl_read_info_lock);
		atomic_dec_mb(&se_nacl->acl_read_info);
		spin_unlock(&se_nacl->acl_read_info_lock);
		rb = 0;

#else /* !QNAP_KERNEL_STORAGE_V2 */

		/* restore original page address */
		page = old_page;

		if (!buf_result)
			memcpy(page, tmp_page, old_rb);
		else {
			if (old_rb) {
				memcpy(page, tmp_page, old_rb);
				pr_warn("%s: nacl info exceeds PAGE_SIZE, "
					"stop to get remain info\n", __func__);			
			} else
				pr_err("%s: fail to get nacl info at "
					"1st round ( > PAGE_SIZE )\n", __func__);
		}

		rb = old_rb;
		kfree(tmp_page);
#endif
	}
	return rb;
}

static void __qnap_iscsit_copy_node_attribues(
	struct iscsi_node_acl *dest_acl, 
	struct iscsi_node_acl *src_acl
	)
{
	struct iscsi_node_attrib *src_a = &src_acl->node_attrib;
	struct iscsi_node_attrib *dest_a = &dest_acl->node_attrib;
	struct iscsi_node_auth *src_auth = &src_acl->node_auth;
	struct iscsi_node_auth *dest_auth = &dest_acl->node_auth;
	
	dest_a->dataout_timeout = src_a->dataout_timeout;
	dest_a->dataout_timeout_retries = src_a->dataout_timeout_retries;
	dest_a->nopin_timeout = src_a->nopin_timeout;
	dest_a->nopin_response_timeout = src_a->nopin_response_timeout;
	dest_a->random_datain_pdu_offsets = src_a->random_datain_pdu_offsets;
	dest_a->random_datain_seq_offsets = src_a->random_datain_seq_offsets;
	dest_a->random_r2t_offsets = src_a->random_r2t_offsets;
	dest_a->default_erl = src_a->default_erl;
	
	// should copy the auth parameters as well
	// struct config_group	   auth_attrib_group;
	dest_auth->naf_flags = src_auth->naf_flags;
	dest_auth->authenticate_target = src_auth->authenticate_target;
	strcpy(dest_auth->userid, src_auth->userid);
	//printk("Nike src_auth = %p, copy userid = %s.\n", src_auth, dest_auth->userid);
	strcpy(dest_auth->password, src_auth->password);
	//printk("Nike copy password = %s.\n", dest_auth->password);
	strcpy(dest_auth->userid_mutual, src_auth->userid_mutual);
	//printk("Nike copy userid_mutual = %s.\n", dest_auth->userid_mutual);
	strcpy(dest_auth->password_mutual, src_auth->password_mutual);
	//printk("Nike copy password_mutual = %s.\n", dest_auth->password_mutual);
	return;
}


void qnap_lio_copy_node_attributes(
	struct se_node_acl *dest, 
	struct se_node_acl *src
	)
{
	struct iscsi_node_acl *dest_acl = 
		container_of(dest, struct iscsi_node_acl, se_node_acl);

	struct iscsi_node_acl *src_acl = 
		container_of(src, struct iscsi_node_acl, se_node_acl);
    
	dest_acl->node_attrib.nacl = dest_acl;
	__qnap_iscsit_copy_node_attribues(dest_acl, src_acl);
	return;
}
#endif

int qnap_iscsi_lio_drop_cmd_from_lun_acl(
	struct se_lun *se_lun
	)
{
	/* this function only will be used on case about if 
	 * someone will delete se_lun (se_dev) from lun_acl 
	 * even the target is still online
	 */
	LIST_HEAD(free_cmd_list);
	struct se_node_acl *se_nacl;
	struct se_session *se_sess;
	struct se_portal_group *se_tpg;
	struct se_cmd *se_cmd;
	struct iscsi_session *i_sess;
	struct iscsi_conn *i_conn;
	struct iscsi_cmd *i_cmd, *i_cmd_p;
	
	if (!se_lun->lun_tpg)
		return -EINVAL;
	
	se_tpg = se_lun->lun_tpg;

	/* find out all conns per sess on the tpg for this lun .... */
	mutex_lock(&se_tpg->acl_node_mutex);

	list_for_each_entry(se_nacl, &se_tpg->acl_node_list, acl_list) {

		spin_lock_bh(&se_nacl->nacl_sess_lock);
		se_sess = se_nacl->nacl_sess;
		if (!se_sess) {
			spin_unlock_bh(&se_nacl->nacl_sess_lock);
			continue;
		}
	
		i_sess = (struct iscsi_session *)se_sess->fabric_sess_ptr;

		/* check all conns per sess */
		spin_lock(&i_sess->conn_lock);
		list_for_each_entry(i_conn, &i_sess->sess_conn_list, conn_list) {

			/* take care use list_for_each_entry_safe() since we 
			 * will use list_move_tail() later
			 */
			spin_lock(&i_conn->cmd_lock);
			list_for_each_entry_safe(i_cmd, i_cmd_p, &i_conn->conn_cmd_list, 
				i_conn_node) 
			{
				if (i_cmd->iscsi_opcode != ISCSI_OP_SCSI_CMD)
					continue;

				se_cmd = &i_cmd->se_cmd;
				if (se_lun->lun_se_dev != se_cmd->se_dev)
					continue;

				/* if backend se_dev for se_lun matches
				 * the cmd->se_cmd.se_dev, try drop cmds
				 */		
				pr_debug("%s: found i_cmd:0x%p,se_cmd:0x%p, "
					"se_dev:0x%p\n", __func__, i_cmd, 
					se_cmd, se_cmd->se_dev);

				qnap_transport_drop_fb_cmd(se_cmd, -1);
				qnap_transport_drop_bb_cmd(se_cmd, -1);

				list_move_tail(&i_cmd->i_conn_node, &free_cmd_list);
			}
			spin_unlock(&i_conn->cmd_lock);
		}
		spin_unlock(&i_sess->conn_lock);
		spin_unlock_bh(&se_nacl->nacl_sess_lock);
	}
	mutex_unlock(&se_tpg->acl_node_mutex);
	

	list_for_each_entry_safe(i_cmd, i_cmd_p, &free_cmd_list, i_conn_node) {
		list_del_init(&i_cmd->i_conn_node);
		iscsit_free_cmd(i_cmd, false);
	}

	return 0;
}



#ifdef ISCSI_MULTI_INIT_ACL
int qnap_iscsit_get_matched_initiator_count(
	struct iscsi_tiqn *tiqn,
	char *initiator_name
	)
{
	/* take care this call due to tiqn_lock needs be locked before call this */

	int tmp_acl_count = 0;
	struct iscsi_portal_group *tpg = NULL;
	struct qnap_se_nacl_dr *dr = NULL;
	struct qnap_se_node_acl *tmp_acl = NULL;
	
	spin_lock(&tiqn->tiqn_tpg_lock);
	list_for_each_entry(tpg, &tiqn->tiqn_tpg_list, tpg_list) {

		dr = &tpg->tpg_se_tpg.se_nacl_dr;

		spin_lock(&dr->acl_node_lock);
		list_for_each_entry(tmp_acl, &dr->acl_node_list, acl_node) {
			if (!(strcmp(tmp_acl->initiatorname, DEFAULT_INITIATOR))
			|| !(strcmp(tmp_acl->initiatorname, FC_DEFAULT_INITIATOR))
			|| !(strcasecmp(tmp_acl->initiatorname, initiator_name))
			)
				tmp_acl_count++;
		}
		spin_unlock(&dr->acl_node_lock);
	}
	spin_unlock(&tiqn->tiqn_tpg_lock);

	return tmp_acl_count;
}


#endif

int qnap_iscsit_find_cmd_count_from_itt (
	struct iscsi_conn *conn,
	itt_t init_task_tag
	)
{
	struct iscsi_cmd *cmd;
	int cmd_count = 0;
	
	spin_lock_bh(&conn->cmd_lock);
	list_for_each_entry(cmd, &conn->conn_cmd_list, i_conn_node) {
		if (cmd->init_task_tag == init_task_tag) {
			pr_debug("%s: itt:0x%08x, cmdsn:0x%08x\n", __func__,
				be32_to_cpu(cmd->init_task_tag), cmd->cmd_sn);
			cmd_count++;
		}
	}
	spin_unlock_bh(&conn->cmd_lock);

	if (cmd_count > 1)
		pr_debug("%s: duplicated cmd count: %d\n", __func__, cmd_count);
	
	return cmd_count;
}

struct iscsi_cmd *qnap_iscsit_find_cmd_from_itt(
	struct iscsi_conn *conn,
	struct iscsi_tm *tm_hdr
	)
{
	struct iscsi_cmd *cmd;

	spin_lock_bh(&conn->cmd_lock);
	list_for_each_entry(cmd, &conn->conn_cmd_list, i_conn_node) {

		if (cmd->init_task_tag != tm_hdr->rtt)
			continue;

		spin_unlock_bh(&conn->cmd_lock);

		/* 1. only pick the cmd which was not be aborted 
		 * 2. host shall not abort any cmd which was aborted already
		 */
		if (qnap_transport_is_dropped_by_tmr(&cmd->se_cmd) != true)
			return cmd;

		pr_warn("%s: skip to pick cmd(itt:0x%08x, cmdsn:0x%08x) "
			"which was aborted already\n", __func__, 
			be32_to_cpu(cmd->init_task_tag), cmd->cmd_sn);

		spin_lock_bh(&conn->cmd_lock);
	}
	spin_unlock_bh(&conn->cmd_lock);

	return NULL;
}

/* 1. sess->conn_lock shall be lock before to call this 
 * 2. this call ONLY be used in iscsit_free_session() , iscsit_stop_session()
 */
int qnap_iscsit_stop_connection_by_sess(
	struct iscsi_session *sess
	)
{
	u16 conn_count = 0;
	struct iscsi_conn *conn = NULL, *conn_tmp = NULL;
	bool go_sleep = false;

	conn_count = atomic_read(&sess->nconn);
	list_for_each_entry(conn, &sess->sess_conn_list, conn_list) {
		if (conn_count--)
			iscsit_inc_conn_usage_count(conn);
	}
	
	conn_count = atomic_read(&sess->nconn);
	list_for_each_entry_safe(conn, conn_tmp, &sess->sess_conn_list, conn_list) {
		if (conn_count--) {
			iscsit_cause_connection_reinstatement(conn, 0);

			spin_lock_bh(&conn->state_lock);
			if (atomic_read(&conn->conn_reinstatement_not_sleep))
				go_sleep = true;
			spin_unlock_bh(&conn->state_lock);

			if (go_sleep) {
				spin_unlock_bh(&sess->conn_lock);
				iscsit_cause_connection_reinstatement(conn, 1);
				spin_lock_bh(&sess->conn_lock);
			}
		}
	}
	
	conn_count = atomic_read(&sess->nconn);
	list_for_each_entry(conn, &sess->sess_conn_list, conn_list) {
		if (conn_count--)
			iscsit_dec_conn_usage_count(conn);
	}

	return 0;
}



#endif


