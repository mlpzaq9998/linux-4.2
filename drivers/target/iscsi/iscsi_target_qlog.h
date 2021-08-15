/**
 * $Header: /home/cvsroot/NasX86/Kernel/linux-3.12.6/drivers/target/iscsi/iscsi_target_log.h,v 1.1 2014/04/22 09:14:31 adamhsu Exp $
 *
 * Copyright (c) 2009, 2010 QNAP SYSTEMS, INC.
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
 * @brief	iscsi target log function declaration.
 * @author	Nike Chen
 * @date	2009/11/23
 *
 * $Id: iscsi_target_log.h,v 1.1 2014/04/22 09:14:31 adamhsu Exp $
 */

#ifndef _ISCSI_TARGET_LOG
#define _ISCSI_TARGET_LOG

#define MAX_IP_SIZE             64
#define MAX_LOG_IQN_SIZE        256

/* TBD: 256 is min value cause of we need to consider length of SN ... */
#define RT_CONF_UPDATE_BUF_SIZE	256

/* take care the structure size of _iscsi_conn_log, we will receive buffer
 * from iscsi_logd, and the buffer size is 4KB now for one iov
 */
typedef struct _iscsi_conn_log
{
	// Extract following constants from naslog.h
	enum {
		LOGIN_FAIL = 9,
		LOGIN_OK,
		LOGOUT,
		ISCSI_RT_CONF_UPDATE = 0x2000,
	} conn_type;

	enum {
		LOG_INFO = 0,
		LOG_WARN,
		LOG_ERROR,

	/* rt conf op starts from 0x2000 ~ 0x20ff, 256 shall be enough */
		ISCSI_RT_CONF_UPDATE_WCE = 0x2000,
		ISCSI_RT_CONF_UPDATE_FUA = 0x20ff,
	} log_type;

	union {
		struct msg_rt_conf_update_data {
			/* we may use SN to be a key so take care the buf size */
			char key[RT_CONF_UPDATE_BUF_SIZE];
			char val[RT_CONF_UPDATE_BUF_SIZE];
		} rt_conf_update_data;

		struct msg_post_log_data {
			char target_iqn[MAX_LOG_IQN_SIZE];
			char init_iqn[MAX_LOG_IQN_SIZE];
			char init_ip[MAX_IP_SIZE];
		} post_log_data;
	} u;

} iscsi_conn_log;

struct nl_func {
	int (*nl_post_log_send)(int, int, char *, char *, char *);
	int (*nl_rt_conf_update)(int, int, char *, char *);
};

#define IS_RT_CONF_UPDATE_OP(op) \
	((op >= ISCSI_RT_CONF_UPDATE_WCE) && (op <= ISCSI_RT_CONF_UPDATE_FUA))

void *qnap_nl_get_nl_func(void);

#endif

