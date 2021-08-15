#ifndef TARGET_CORE_QCONFIGFS_H
#define TARGET_CORE_QCONFIGFS_H


/* this structure shall matches for 
 * struct configfs_attribute *target_core_dev_attrs[] in native code 
 */
struct __target_core_configfs_attribute {
	struct configfs_attribute attr;
	ssize_t (*show)(void *, char *);
	ssize_t (*store)(void *, const char *, size_t);
};

extern struct __target_core_configfs_attribute target_core_attr_dev_provision;
extern struct __target_core_configfs_attribute target_core_attr_dev_naa_vendor;
extern struct __target_core_configfs_attribute target_core_attr_dev_naa_code;
extern struct __target_core_configfs_attribute target_core_attr_dev_qlbs;
extern struct __target_core_configfs_attribute target_core_attr_dev_wt;
extern struct __target_core_configfs_attribute target_core_attr_dev_zc;
extern struct __target_core_configfs_attribute target_core_attr_dev_read_deletable;


#ifdef SUPPORT_FAST_BLOCK_CLONE
extern struct __target_core_configfs_attribute target_core_attr_dev_qfbc;
extern struct __target_core_configfs_attribute target_core_attr_dev_qfbc_enable;
#endif

#ifdef QNAP_SHARE_JOURNAL
extern struct __target_core_configfs_attribute target_core_attr_dev_bbu_journal;
ssize_t target_core_show_dev_bbu_journal(void *p, char *page);
ssize_t target_core_store_dev_bbu_journal(void *p, const char *page,
					  size_t count);
#endif

ssize_t target_core_show_dev_provision(void *p, char *page);
ssize_t target_core_store_dev_provision(void *p, const char *page, size_t count);

ssize_t target_core_show_dev_naa_vendor(void *p, char *page);
ssize_t target_core_store_dev_naa_vendor(void *p, const char *page, size_t count);

ssize_t target_core_show_dev_naa_str(void *p, char *page);

ssize_t target_core_show_dev_qlbs(void *p, char *page);
ssize_t target_core_store_dev_qlbs(void *p, const char *page, size_t count);
ssize_t target_core_store_dev_wt_enable(void *p, const char *page, size_t count);

#ifdef SUPPORT_FAST_BLOCK_CLONE
ssize_t target_core_show_dev_qfbc(void *p, char *page);
ssize_t target_core_store_dev_qfbc_enable(void *p, const char *page, size_t count);
#endif

int se_dev_set_emulate_v_sup(struct se_dev_attrib *da, unsigned long flag);
ssize_t se_dev_show_emulate_v_sup(struct se_dev_attrib *da, char *page);
int se_dev_set_emulate_fua_write(struct se_dev_attrib *dev_attrib, unsigned long flag);
ssize_t se_dev_show_emulate_fua_write(struct se_dev_attrib *dev_attrib, char *page);

ssize_t se_dev_show_lun_index(struct se_dev_attrib *dev_attrib, char *page);
int se_dev_set_lun_index(struct se_dev_attrib *dev_attrib, unsigned long flag);

#ifdef SUPPORT_TP
ssize_t se_dev_show_allocated(struct se_dev_attrib *dev_attrib, char *page);
ssize_t se_dev_show_tp_threshold_enable(struct se_dev_attrib *dev_attrib, 
	char *page);

int se_dev_set_tp_threshold_enable(struct se_dev_attrib *dev_attrib, 
	unsigned long flag);

ssize_t se_dev_show_tp_threshold_percent(struct se_dev_attrib *dev_attrib, 
	char *page);

int se_dev_set_tp_threshold_percent(struct se_dev_attrib *dev_attrib, 
	unsigned long flag);
#endif

/* For QNAP list of target backend device attributes as defined by
 * struct se_dev_attrib
 */
#define DEF_TB_QNAP_DEV_ATTRIB_SHOW(_name)				\
static ssize_t show_##_name(struct se_dev_attrib *da, char *page)	\
{									\
	return se_dev_show_##_name(da, page);				\
}									\

#define DEF_TB_QNAP_DEV_ATTRIB_STORE(_name)				\
static ssize_t store_##_name(struct se_dev_attrib *da, const char *page,\
		size_t count)						\
{									\
	unsigned long val;						\
	int ret;							\
									\
	ret = kstrtoul(page, 0, &val);					\
	if (ret < 0) {							\
		pr_err("fail to call kstrtoul(), ret:%d\n", ret);	\
		return ret;						\
	}								\
	ret = se_dev_set_##_name(da, val);				\
	return (!ret) ? count : -EINVAL;				\
}									\


#define DEF_TB_QNAP_ATTRIBS(__backend, __name)	\
	DEF_TB_QNAP_DEV_ATTRIB_SHOW(__name);		\
	DEF_TB_QNAP_DEV_ATTRIB_STORE(__name);	\
	TB_DEV_ATTR(__backend, __name, S_IRUGO | S_IWUSR);

#define DEF_TB_QNAP_ATTRIBS_RO(__backend, __name)	\
	DEF_TB_QNAP_DEV_ATTRIB_SHOW(__name);		\
	TB_DEV_ATTR_RO(__backend, __name);


#endif
