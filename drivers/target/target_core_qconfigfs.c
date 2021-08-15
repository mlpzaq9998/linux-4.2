/*******************************************************************************
 * Filename:  target_core_qconfigfs.c
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
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <generated/utsrelease.h>
#include <linux/utsname.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/blkdev.h>
#include <linux/namei.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/delay.h>
#include <linux/unistd.h>
#include <linux/string.h>
#include <linux/parser.h>
#include <linux/syscalls.h>
#include <linux/configfs.h>
#include <linux/spinlock.h>
#include <linux/kernel.h>
#include <asm/unaligned.h>

#include <target/target_core_base.h>
#include <target/target_core_backend.h>
#include <target/target_core_fabric.h>
#include <target/target_core_fabric_configfs.h>
#include <target/configfs_macros.h>
#include "target_core_qconfigfs.h"
#include "target_core_qtransport.h"
#include "target_core_iblock.h"

int se_dev_set_emulate_v_sup(
	struct se_dev_attrib *da,
	unsigned long flag
	)
{
	da->emulate_v_sup = ((flag > 0) ? 1 : 0);

	/* Set WCE to 0 while changing V_SUP */
	if (da->da_dev->transport->set_write_cache)
		da->da_dev->transport->set_write_cache(da->da_dev, false);
	else
		da->emulate_write_cache = 0;

	pr_debug("dev[%p]: SE Device V_SUP_EMULATION flag: %d\n",
			da->da_dev, da->emulate_v_sup);
	return 0;
}

ssize_t se_dev_show_emulate_v_sup(
	struct se_dev_attrib *da,
	char *page
	)
{
	return snprintf(page, PAGE_SIZE, "%u\n", da->emulate_v_sup);
}

int se_dev_set_emulate_fua_write(
	struct se_dev_attrib *da,
	unsigned long flag
	)
{
	bool is_fio_blkdev;
	struct se_device *se_dev = da->da_dev;
	struct iblock_dev *ib_dev = NULL;
	struct request_queue *q = NULL;

	da->emulate_fua_write = ((flag > 0) ? 1 : 0);

	if (qnap_transport_is_fio_blk_backend(se_dev) == 0)
		is_fio_blkdev = true;
	else if (qnap_transport_is_iblock_fbdisk(se_dev) == 0)
		is_fio_blkdev = false;
	else
		return -ENODEV;

	if (is_fio_blkdev == false) {
		/* TODO: is it ok .....?? shall check this
		 * we didn't call blk_queue_flush() to setup REQ_FLUSH
		 * or REQ_FUA in queue flags in fbdisk code, but we
		 * still clear (or setup) them here ...
		 */
		ib_dev = qnap_transport_get_iblock_dev(se_dev);
		q = bdev_get_queue(ib_dev->ibd_bd);

		if (da->emulate_fua_write)
			q->flush_flags |= REQ_FUA;
		else
			q->flush_flags &= ~(REQ_FUA);
	}

	pr_debug("dev[%p]: SE Device FUA_WRITE_EMULATION flag: %d\n",
			da->da_dev, da->emulate_fua_write);
	return 0;
}

ssize_t se_dev_show_emulate_fua_write(
	struct se_dev_attrib *da,
	char *page
	)
{
	return snprintf(page, PAGE_SIZE, "%u\n", da->emulate_fua_write);
}

ssize_t se_dev_show_lun_index(
	struct se_dev_attrib *dev_attrib, 
	char *page
	)
{
	return snprintf(page, PAGE_SIZE, "%u\n", dev_attrib->lun_index);
}

int se_dev_set_lun_index(
	struct se_dev_attrib *dev_attrib, 
	unsigned long flag
	)
{
	if (flag > 255)
		return -EINVAL;

	dev_attrib->lun_index = flag;
	return 0;
}


#ifdef SUPPORT_TP
ssize_t se_dev_show_allocated(
	struct se_dev_attrib *dev_attrib, 
	char *page
	)
{
	struct se_device *se_dev;
	int ret;

	if (!dev_attrib->da_dev)
		return -ENODEV;

	se_dev = dev_attrib->da_dev;
	ret = qnap_transport_get_thin_allocated(se_dev);
	if (ret != 0)
		return ret;

	return snprintf(page, PAGE_SIZE, "%llu\n", dev_attrib->allocated);
}
/* for threshold notification */
ssize_t se_dev_show_tp_threshold_enable(
	struct se_dev_attrib *dev_attrib, 
	char *page
	)
{
	return snprintf(page, PAGE_SIZE, "%u\n", 
			dev_attrib->tp_threshold_enable);
}

int se_dev_set_tp_threshold_enable(
	struct se_dev_attrib *dev_attrib, 
	unsigned long flag
	)
{
	if ((flag != 0) && (flag != 1))
		return -EINVAL;

	/*
	 * We expect this value to be non-zero when generic Block Layer
	 * Discard supported is detected iblock_create_virtdevice().
	 */
	if (flag && !dev_attrib->tp_threshold_percent) {
		pr_err("TP threshold enable not supported\n");
		return -ENOSYS;
	}

	dev_attrib->tp_threshold_enable = flag;
	return 0;
}

ssize_t se_dev_show_tp_threshold_percent(
	struct se_dev_attrib *dev_attrib, 
	char *page
	)
{
	return snprintf(page, PAGE_SIZE, "%u\n", 
			dev_attrib->tp_threshold_percent);
}

int se_dev_set_tp_threshold_percent(
	struct se_dev_attrib *dev_attrib, 
	unsigned long flag
	)
{
	if (flag > 100)
		return -EINVAL;

	dev_attrib->tp_threshold_percent = flag;
	return 0;
}
#endif

#ifdef SUPPORT_FAST_BLOCK_CLONE
ssize_t target_core_show_dev_qfbc(void *p, char *page)
{
	struct se_device *dev = p;

	return snprintf(page, PAGE_SIZE, "%d\n", dev->dev_dr.fast_blk_clone);
}

ssize_t target_core_show_dev_qfbc_enable(
	void *p, 
	char *page
	)
{
	struct se_device *dev = p;

	return snprintf(page, PAGE_SIZE, "%d\n", dev->dev_dr.fbc_control);
}

ssize_t target_core_store_dev_qfbc_enable(
	void *p,
	const char *page,
	size_t count
	)
{
	struct se_device *dev = p;
	unsigned long val = 0;
	int ret = 0;
	
	ret = kstrtoul(page, 0, &val);
	if (ret < 0) {
		pr_err("%s: kstrtoul() failed with  ret: %d\n", __func__, ret);
		return -EINVAL;
	}

	if ((val != 0) && (val != 1)) {
		pr_err("%s: dev[%p]: Illegal value: %lu. Must be 0 or 1\n", 
			__func__, dev, val);
		return -EINVAL;
	}

	if (!dev->dev_dr.fast_blk_clone)
		return -EINVAL;

	spin_lock(&dev->dev_dr.fbc_control_lock);
	dev->dev_dr.fbc_control = (int)val;
	spin_unlock(&dev->dev_dr.fbc_control_lock);

	return count;

}
#endif

ssize_t target_core_show_dev_provision(void *p, char *page)
{
	struct se_device *dev = p;
	struct qnap_se_dev_dr *dr = &dev->dev_dr;

	if (!(dr->dev_flags & QNAP_DF_USING_PROVISION))
		return 0;

	return snprintf(page, PAGE_SIZE, "%s\n", dr->dev_provision);
}

ssize_t target_core_store_dev_provision(
	void *p,
	const char *page,
	size_t count)
{
	struct se_device *dev = p;
	struct qnap_se_dev_dr *dr = &dev->dev_dr;
	struct se_hba *hba = dev->se_hba;
	ssize_t read_bytes;
	unsigned char dev_provision_str[QNAP_SE_DEV_PROVISION_LEN];

	if (count > (QNAP_SE_DEV_PROVISION_LEN - 1)) {
		pr_err("provision count: %d exceeds "
			"QNAP_SE_DEV_PROVISION_LEN - 1: %u\n", (int)count,
			QNAP_SE_DEV_PROVISION_LEN - 1);
		return -EINVAL;
	}

	if (dr->dev_attr_write_once_flag & QNAP_DEV_ATTR_PROVISION_WRITE_ONCE) {
		pr_err("se_dev_provision was set already. can't update again.\n");
		return -EINVAL;
	}

	memset(dev_provision_str, 0, sizeof(dev_provision_str));
	read_bytes = snprintf(&dev_provision_str[0], QNAP_SE_DEV_PROVISION_LEN,
			"%s", page);
	if (!read_bytes){
		pr_err("cat't format dev_provision_str string\n");
		return -EINVAL;
	}

	if (dev_provision_str[read_bytes - 1] == '\n')
		dev_provision_str[read_bytes - 1] = '\0';

	/* check the dev provision string format */
	if (strncasecmp(dev_provision_str, "thin", sizeof(dev_provision_str)) 
	&& strncasecmp(dev_provision_str, "thick", sizeof(dev_provision_str))
	)
	{
		pr_err("neither thick nor thin for dev_provision string\n");
		return -EINVAL;
	}

	read_bytes = snprintf(&dr->dev_provision[0], QNAP_SE_DEV_PROVISION_LEN,
			"%s", page);
	if (!read_bytes)
		return -EINVAL;
	if (dr->dev_provision[read_bytes - 1] == '\n')
		dr->dev_provision[read_bytes - 1] = '\0';

	dr->dev_flags |= QNAP_DF_USING_PROVISION;
	dr->dev_attr_write_once_flag |= QNAP_DEV_ATTR_PROVISION_WRITE_ONCE;

	pr_debug("Target_Core_ConfigFS: %s/%s set provision: %s\n",
		config_item_name(&hba->hba_group.cg_item),
		config_item_name(&dev->dev_group.cg_item),
		dr->dev_provision);

	return read_bytes;
}

ssize_t target_core_store_dev_naa_vendor(
	void *p,
	const char *page,
	size_t count)
{
	struct se_device *dev = p;
	struct qnap_se_dev_dr *dr = &dev->dev_dr;
	struct se_hba *hba = dev->se_hba;
	ssize_t read_bytes;

	if (count > (QNAP_SE_DEV_NAA_LEN - 1)) {
		pr_err("naa count: %d exceeds SE_DEV_NAA_LEN-1: %u\n", 
			(int)count, QNAP_SE_DEV_NAA_LEN - 1);
		return -EINVAL;
	}

	read_bytes = snprintf(&dr->dev_naa[0], QNAP_SE_DEV_NAA_LEN,
			"%s", page);
	if (!read_bytes)
		return -EINVAL;

	if (dr->dev_naa[read_bytes - 1] == '\n')
		dr->dev_naa[read_bytes - 1] = '\0';

	if (dr->dev_attr_write_once_flag & QNAP_DEV_ATTR_NAA_WRITE_ONCE) {
		pr_err("naa was setup already. Can't update again.\n");
		return -EINVAL;
	}

	dr->dev_attr_write_once_flag |= QNAP_DEV_ATTR_NAA_WRITE_ONCE;
	dr->dev_flags |= QNAP_DF_USING_NAA;

	pr_debug("Target_Core_ConfigFS: %s/%s set naa: %s\n",
		config_item_name(&hba->hba_group.cg_item),
		config_item_name(&dev->dev_group.cg_item),
		dr->dev_naa);

	return read_bytes;
}


ssize_t target_core_show_dev_naa_vendor(void *p, char *page)
{
	struct se_device *dev = p;
	struct qnap_se_dev_dr *dr = &dev->dev_dr;

	if (!(dr->dev_flags & QNAP_DF_USING_NAA))
		return 0;

	return snprintf(page, PAGE_SIZE, "%s\n", dr->dev_naa);
}

ssize_t target_core_show_dev_naa_code(void *p, char *page)
{
	struct se_device *dev = p;
	struct qnap_se_dev_dr *dr = &dev->dev_dr;

	u8 hex[] = {'0', '1', '2', '3', '4', '5', '6', '7',
		'8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
	int i;
	u8 tmp_buf[QNAP_SE_DEV_NAA_LEN + 1], naa_buf[QNAP_SE_DEV_NAA_LEN + 1], c;

	if (!(dr->dev_flags & QNAP_DF_USING_NAA))
		return 0;

	memset(tmp_buf, 0, sizeof(tmp_buf));
	memset(naa_buf, 0, sizeof(naa_buf));

	qnap_transport_get_naa_6h_code(dev, tmp_buf);
	
	for (i = 0; i < 16; i++) {
		c = tmp_buf[i];
		naa_buf[i*2 + 0] = hex[c >> 4];
		naa_buf[i*2 + 1] = hex[c & 0xf];
	}
	return snprintf(page, PAGE_SIZE, "%s\n", naa_buf);
}


/* adamhsu 2013/06/07 - Support to set the logical block size from NAS GUI.
 *
 * Cause of the attribute item information in attrib folder are still not be set
 * before to enable the LU, we need to put this information into another attribute
 * item.
 */
ssize_t target_core_show_dev_qlbs(
	void *p, 
	char *page
	)
{
	struct se_device *dev = p;
	struct qnap_se_dev_dr *dr = &dev->dev_dr;
	ssize_t rb;

	if (!(dr->dev_flags & QNAP_DF_USING_QLBS))
		return 0;

	rb = snprintf(page, PAGE_SIZE, "%llu\n", (u64)dr->dev_qlbs);
	return rb;
}

ssize_t target_core_store_dev_qlbs(
	void *p,
	const char *page,
	size_t count
	)
{
	struct se_device *dev = p;
	struct qnap_se_dev_dr *dr = &dev->dev_dr;
	struct se_hba *hba = dev->se_hba;
	unsigned long val = 0;
	int ret = 0;

	ret = kstrtoul(page, 0, &val);
	if (ret < 0) {
		pr_err("%s: kstrtoul() failed with  ret: %d\n", __func__, ret);
		return -EINVAL;
	}

	if ((val != 512) && (val != 4096)) {
		pr_err("%s: dev[%p]: Illegal value for block_device: %lu"
			" for se sub device, must be 512, or 4096\n", __func__, 
			dev, val);
		return -EINVAL;
	}

	if (dr->dev_attr_write_once_flag & QNAP_DEV_ATTR_QLBS_WRITE_ONCE) {
		pr_err("qlbs was setup already. Can't update again.\n");
		return -EINVAL;
	}

	dr->dev_attr_write_once_flag |= QNAP_DEV_ATTR_QLBS_WRITE_ONCE;
	dr->dev_flags |= QNAP_DF_USING_QLBS;
	dr->dev_qlbs = val;

	pr_debug("Target_Core_ConfigFS: dev[%p], %s/%s set qlbs: %u\n",
		dev, config_item_name(&hba->hba_group.cg_item), 
		config_item_name(&dev->dev_group.cg_item),
		dr->dev_qlbs
		);

	return count;
}

static int __core_get_dev_zc(
	struct se_device *se_dev
	)
{
	int val;

	spin_lock(&se_dev->dev_dr.dev_zc_lock);
	val = se_dev->dev_dr.dev_zc;
	spin_unlock(&se_dev->dev_dr.dev_zc_lock);
	return val;
}

static void __core_store_dev_zc(
	struct se_device *se_dev,
	int val
	)
{
	spin_lock(&se_dev->dev_dr.dev_zc_lock);
	se_dev->dev_dr.dev_zc = val;
	spin_unlock(&se_dev->dev_dr.dev_zc_lock);
}

static int __core_get_dev_wt(
	struct se_device *se_dev
	)
{
	int val;

	spin_lock(&se_dev->dev_dr.dev_wt_lock);
	val = se_dev->dev_dr.dev_wt;
	spin_unlock(&se_dev->dev_dr.dev_wt_lock);
	return val;
}

static void __core_store_dev_wt(
	struct se_device *se_dev,
	int val
	)
{
	spin_lock(&se_dev->dev_dr.dev_wt_lock);
	se_dev->dev_dr.dev_wt = val;
	spin_unlock(&se_dev->dev_dr.dev_wt_lock);
}

ssize_t target_core_show_dev_wt(
	void *p, 
	char *page
	)
{
	struct se_device *dev = p;
	ssize_t rb;
	int val;

	spin_lock(&dev->dev_dr.dev_wt_lock);
	val = dev->dev_dr.dev_wt;
	spin_unlock(&dev->dev_dr.dev_wt_lock);

	rb = snprintf(page, PAGE_SIZE, "%llu\n", (u64)val);
	return rb;
}

ssize_t target_core_show_dev_zc(
	void *p, 
	char *page
	)
{
	struct se_device *dev = p;
	ssize_t rb;
	int val;

	spin_lock(&dev->dev_dr.dev_zc_lock);
	val = dev->dev_dr.dev_zc;
	spin_unlock(&dev->dev_dr.dev_zc_lock);

	rb = snprintf(page, PAGE_SIZE, "%llu\n", (u64)val);
	return rb;

}

ssize_t target_core_store_dev_wt(
	void *p,
	const char *page,
	size_t count
	)
{
	struct se_device *dev = p;
	unsigned long wt_val = 0;
	int ret = 0, zc_val = 0;

	ret = kstrtoul(page, 0, &wt_val);
	if (ret < 0) {
		pr_err("%s: kstrtoul() failed with  ret: %d\n", __func__, ret);
		return -EINVAL;
	}

	if ((wt_val != 0) && (wt_val != 1)) {
		pr_err("%s: dev[%p]: Illegal value. Must be 0 or 1\n", 
			__func__, dev);
		return -EINVAL;
	}

	zc_val = __core_get_dev_zc(dev);

	if ((wt_val == 1) && (zc_val == 1)) {
		pr_warn("dev[%p]: Invalid option. zc = 1 "
			"when to set wt = 1\n", dev);
		return -EINVAL;
	} 

	__core_store_dev_wt(dev, (int)wt_val);

	pr_info("dev[%p]: %s dev write thread\n", 
		dev, ((wt_val == 1) ? "enable": "disable"));

	return count;
}

ssize_t target_core_store_dev_zc(
	void *p,
	const char *page,
	size_t count
	)
{
	struct se_device *dev = p;
	unsigned long zc_val = 0;
	int ret = 0, wt_val = 0;

	ret = kstrtoul(page, 0, &zc_val);
	if (ret < 0) {
		pr_err("%s: kstrtoul() failed with  ret: %d\n", __func__, ret);
		return -EINVAL;
	}

	if ((zc_val != 0) && (zc_val != 1)) {
		pr_err("%s: dev[%p]: Illegal value. Must be 0 or 1\n", 
			__func__, dev);
		return -EINVAL;
	}

	wt_val = __core_get_dev_wt(dev);

	/* zero-copy only supports on fio + blkdev configuration */
	if(!strcmp(dev->transport->name, "fileio")
	&& (qnap_transport_is_fio_blk_backend(dev) == 0)
	)
	{
		if ((zc_val == 1) && (wt_val == 1)) {
			pr_warn("dev[%p]: Invalid option. wt = 1 "
				"when to set zc = 1\n", dev);
			return -EINVAL;			
		} 

		__core_store_dev_zc(dev, (int)zc_val);

		pr_info("dev[%p]: %s dev zero copy\n", 
			dev, ((zc_val == 1) ? "enable": "disable"));

		return count;
	}

	pr_warn("dev[%p]: dev not support zero copy\n", dev);
	return count;
}

ssize_t target_core_show_dev_read_deletable(
	void *p, 
	char *page
	)
{
	struct se_device *dev = p;
	ssize_t rb;
	int val;

	val = atomic_read(&dev->dev_dr.hit_read_deletable);
	rb = snprintf(page, PAGE_SIZE, "%llu\n", (u64)val);
	return rb;
}

ssize_t target_core_store_dev_read_deletable(
	void *p,
	const char *page,
	size_t count
	)
{
	struct se_device *dev = p;
	unsigned long val = 0;
	int ret = 0;
	char *naa_buf = NULL;

	ret = kstrtoul(page, 0, &val);
	if (ret < 0) {
		pr_err("%s: kstrtoul() failed with  ret: %d\n", __func__, ret);
		return -EINVAL;
	}

	if ((val != 0) && (val != 1)) {
		pr_err("%s: Illegal value. Must be 0 or 1\n", __func__);
		return -EINVAL;
	}

	naa_buf = kzalloc(PAGE_SIZE, GFP_KERNEL);
	if (!naa_buf)
		return -ENOMEM;

	atomic_set(&dev->dev_dr.hit_read_deletable, (int)val);

	/* buffer size passed to target_core_show_dev_naa_code() must be PAGE_SIZE */
	target_core_show_dev_naa_code(dev, naa_buf);

	if (naa_buf[strlen(naa_buf) - 1] == '\n')
		naa_buf[strlen(naa_buf) - 1] = 0x00;

	pr_info("dev[naa:%s] read_deletable status was %s\n", naa_buf, 
			((val == 1) ? "set": "clear"));

	kfree(naa_buf);
	return count;
}

#ifdef QNAP_SHARE_JOURNAL
/* @fn int target_core_show_dev_bbu_journal (void *p, char *page)
 *
 * @brief
 * @note
 * @param[in] p
 * @param[in] page
 * @retval
 */
ssize_t target_core_show_dev_bbu_journal(void *p, char *page)
{
	struct se_device *dev = p;
	ssize_t rb;

	if (!(dev->dev_flags & DF_USING_BBUJOURNAL))
		return 0;
	rb = snprintf(page, PAGE_SIZE, "%llu\n", (u64)dev->dev_bbu_journal);
	return rb;
}
/*
 * @fn int target_core_store_dev_bbu_journal(void *p, char *page, size_t count)
 *
 * @brief
 * @note
 * @param[in] p
 * @param[in] page
 * @param[in] count
 * @retval
 */
ssize_t target_core_store_dev_bbu_journal(void *p, const char *page,
						 size_t count) {
	struct se_device *dev = p;
	struct target_backend_ops *t = dev->transport;
	unsigned long enable = 0;
	int ret = 0;
	u32 last_status;

	ret = kstrtoul(page, 0, &enable);
	if (ret < 0) {
		pr_err("kstrtoul() failed with ret: %d\n", ret);
		return -EINVAL;
	}

	if ((enable != 0) && (enable != 1)) {
		pr_err("dev[%p]: Illegal value for block_device: %lu"
		  " for se sub device, set 0 to disable journal support;"
		  " set 1 to enable journal support\n",
		  dev, enable);
		return -EINVAL;
	}

	dev->dev_flags |= DF_USING_BBUJOURNAL;

	if (!(!enable && dev->dev_bbu_journal)
			&& !(enable && !dev->dev_bbu_journal)) {
		return count;
	}

	last_status = dev->dev_bbu_journal;
	dev->dev_bbu_journal = enable;

	if (t && t->set_journal_support) {
		ret = t->set_journal_support(dev, enable);
		if (ret) {
			dev->dev_bbu_journal = last_status;
			return -EINVAL;
		}
		pr_debug("Target_Core_ConfigFS: se_sub_dev[%p], "
			 "%s configure journal support: %u\n",
			 dev,
			 config_item_name(&dev->dev_group.cg_item),
			 dev->dev_bbu_journal);
	}

	return count;
}

struct __target_core_configfs_attribute target_core_attr_dev_bbu_journal =
{
	.attr	= { .ca_owner = THIS_MODULE,
		    .ca_name = "bbu_journal",
		    .ca_mode = S_IRUGO | S_IWUSR},
	.show	= target_core_show_dev_bbu_journal,
	.store	= target_core_store_dev_bbu_journal,
};

#endif


struct __target_core_configfs_attribute target_core_attr_dev_provision = {
	.attr	= { .ca_owner = THIS_MODULE,
		    .ca_name = "provision",
		    .ca_mode =  S_IRUGO | S_IWUSR },
	.show	= target_core_show_dev_provision,
	.store	= target_core_store_dev_provision,
};

struct __target_core_configfs_attribute target_core_attr_dev_naa_vendor = {
	.attr	= { .ca_owner = THIS_MODULE,
		    .ca_name = "naa",
		    .ca_mode =  S_IRUGO | S_IWUSR },
	.show	= target_core_show_dev_naa_vendor,
	.store	= target_core_store_dev_naa_vendor,
};

struct __target_core_configfs_attribute target_core_attr_dev_naa_code = {
	.attr	= { .ca_owner = THIS_MODULE,
		    .ca_name = "naa_code",
		    .ca_mode =  S_IRUGO | S_IWUSR },
	.show	= target_core_show_dev_naa_code,
};


struct __target_core_configfs_attribute target_core_attr_dev_qlbs = {
	.attr	= { .ca_owner = THIS_MODULE,
		    .ca_name = "qlbs",
		    .ca_mode =  S_IRUGO | S_IWUSR },
	.show	= target_core_show_dev_qlbs,
	.store	= target_core_store_dev_qlbs,
};

#ifdef SUPPORT_FAST_BLOCK_CLONE
/* information to know whether the lun supports fbc (fast block cloning)
 * from pool or not
 */
struct __target_core_configfs_attribute target_core_attr_dev_qfbc = {
	.attr	= { .ca_owner = THIS_MODULE,
		    .ca_name = "qfbc_supported",
		    .ca_mode =  S_IRUGO | S_IWUSR },
	.show	= target_core_show_dev_qfbc,
};

/* switch to enable / disable the fbc (fast block cloning) for lun by manual */
struct __target_core_configfs_attribute target_core_attr_dev_qfbc_enable = {
	.attr	= { .ca_owner = THIS_MODULE,
		    .ca_name = "qfbc_enable",
		    .ca_mode =  S_IRUGO | S_IWUSR },
	.store	= target_core_store_dev_qfbc_enable,
	.show	= target_core_show_dev_qfbc_enable,
};
#endif


/* switch to enable / disable the wt (write processing thread) for lun by manual
 *
 * (zc,wt)
 * (0,0) Disable zc and wt. This goes original native desing in rx
 * (0,1) Disable zc but Enable wt. All iscsi writes goes to write processing thread
 * (1,0) Enable zc but Disable wt. All general iscsi writes executed by splice in rx
 * (1,1) Invalid option
 */
struct __target_core_configfs_attribute target_core_attr_dev_wt = {
	.attr	= { .ca_owner = THIS_MODULE,
		    .ca_name = "wt",
		    .ca_mode =  S_IRUGO | S_IWUSR },
	.show	= target_core_show_dev_wt,
	.store	= target_core_store_dev_wt,
};

/* switch to enable / disable the zc (zero copy) for lun by manual */
struct __target_core_configfs_attribute target_core_attr_dev_zc = {
	.attr	= { .ca_owner = THIS_MODULE,
		    .ca_name = "zc",
		    .ca_mode =  S_IRUGO | S_IWUSR },
	.show	= target_core_show_dev_zc,
	.store	= target_core_store_dev_zc,
};

struct __target_core_configfs_attribute target_core_attr_dev_read_deletable = {
	.attr	= { .ca_owner = THIS_MODULE,
		    .ca_name = "read_delete",
		    .ca_mode =  S_IRUGO | S_IWUSR },
	.show	= target_core_show_dev_read_deletable,
	.store	= target_core_store_dev_read_deletable,
};



