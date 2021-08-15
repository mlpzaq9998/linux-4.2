/*
 *  Copyright (c) 2009 QNAP Systems, Inc. All Rights Reserved.
 */
#ifndef _LINUX_FNOTIFY_H_
#define _LINUX_FNOTIFY_H_


typedef struct _T_INODE_INFO_ {
	uint64_t			i_size;
	uint32_t			i_mtsec;
	uint32_t			i_mtnsec;
	uint32_t			i_mode;
	uint32_t			i_uid_val;
	uint32_t			i_gid_val;
	uint32_t			i_padding;
} T_INODE_INFO;

#ifdef CONFIG_QND_FNOTIFY_MODULE
#define	FN_CHMOD		0x00000001
#define	FN_CHOWN		0x00000002
#define	FN_MKDIR		0x00000004
#define	FN_RMDIR		0x00000008
#define	FN_UNLINK		0x00000010
#define	FN_SYMLINK		0x00000020
#define	FN_LINK			0x00000040
#define	FN_RENAME		0x00000080
#define	FN_OPEN			0x00000100
#define	FN_CLOSE		0x00000200
#define	FN_READ			0x00000400
#define	FN_WRITE		0x00000800
#define	FN_TRUNCATE		0x00001000
#define	FN_CHTIME		0x00002000
#define	FN_XATTR		0x00004000

#define	MARG_0			0
#define	MARG_1xI32		0x14
#define	MARG_2xI32		0x24
#define	MARG_3xI32		0x34
#define	MARG_4xI32		0x44
#define	MARG_1xI64		0x18
#define	MARG_2xI64		0x28

#define ARG_PADDING		0

#define QNAP_FN_GET_INODE_INFO(inode, i_info)\
	do {\
		if ((inode)) {\
			(i_info)->i_size = (uint64_t)(inode)->i_size;\
			(i_info)->i_mtsec = (uint32_t)(inode)->i_mtime.tv_sec;\
			(i_info)->i_mtnsec =\
				(uint32_t)(inode)->i_mtime.tv_nsec;\
			(i_info)->i_mode = (uint32_t)(inode)->i_mode;\
			(i_info)->i_uid_val = (uint32_t)(inode)->i_uid.val;\
			(i_info)->i_gid_val = (uint32_t)(inode)->i_gid.val;\
			(i_info)->i_padding = 0;\
		} \
	} while (0)

extern uint32_t  qnap_g_file_notify_mask;
#define QNAP_FN_GET_NOTIFY_MASK() qnap_g_file_notify_mask
#define QNAP_FN_IS_NOTIFY(event) ((event) & QNAP_FN_GET_NOTIFY_MASK())
#define QNAP_FN_GET_MODE(mode) (0x1FF & (mode))

extern void (*qnap_sys_file_notify)(int idcode, int margs,
		const struct path *ppath, const char *pstname,
		int cbname, T_INODE_INFO *i_info, int64_t iarg1,
		int64_t iarg2, uint32_t iarg3, uint32_t iarg4);
extern void (*qnap_sys_files_notify)(int idcode, const struct path *ppath1,
		const char *pstname1, int cbname1, const struct path *ppath2,
		const char *pstname2, int cbname2,
		T_INODE_INFO *i_info_old, T_INODE_INFO *i_info_new);

#ifdef	_LINUX_NFSD_NFSFH_H
extern void (*qnap_nfs_file_notify)(int idcode, int nbargs,
		struct svc_fh *ptsffile, const char *pszname,
		int cbname, T_INODE_INFO *i_info, int64_t iarg1,
		int64_t iarg2, uint32_t iarg3, uint32_t iarg4);
extern void (*qnap_nfs_files_notify)(int idcode,
		struct svc_fh *ptsfold, const char *psznold,
		int cbnold, struct svc_fh *ptsfnew,
		const char *psznnew, int cbnnew,
		T_INODE_INFO *i_info_old, T_INODE_INFO *i_info_new);
#endif
#else
#define QNAP_FN_GET_INODE_INFO(inode, i_info)
#endif /* if define CONFIG_QND_FNOTIFY_MODULE */
#endif
