#ifndef ISCSI_TARGET_QCONFIGFS_H
#define ISCSI_TARGET_QCONFIGFS_H

#ifdef CONFIG_MACH_QNAPTS
#ifdef SUPPORT_SINGLE_INIT_LOGIN

#define QNAP_ISCSI_STAT_TGT_ATTR(_name, _mode)		\
struct iscsi_stat_tgt_attr_attribute			\
			iscsi_stat_tgt_attr_##_name =	\
	__CONFIGFS_EATTR(_name, _mode,			\
	iscsi_stat_tgt_attr_show_attr_##_name,		\
	iscsi_stat_tgt_attr_store_attr_##_name);


ssize_t iscsi_stat_tgt_attr_show_attr_cluster_enable(
	struct iscsi_wwn_stat_grps *igrps, char *page);

ssize_t iscsi_stat_tgt_attr_store_attr_cluster_enable(
	struct iscsi_wwn_stat_grps *igrps, const char *page, size_t count);
#endif
#endif

#endif
