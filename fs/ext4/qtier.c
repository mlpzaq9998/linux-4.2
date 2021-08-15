#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/qtier.h>
#include "ext4.h"
#include "ext4_jbd2.h"
#include "xattr.h"
#include "qtier.h"


static char * const qtier_xattrs[__MAX_NR_QTIER_XATTRS + 1] = {
	"0",
	"h",
	"c",
	"hot_anchor",
	"cold_anchor",
	"io_aware",
};

static int qtier_bio_flags[__MAX_NR_QTIER_XATTRS + 1] = {
	0,
	REQ_HOTDATA,
	REQ_COLDDATA,
	REQ_ANCHOR_HOT,
	REQ_ANCHOR_COLD,
	REQ_IO_AWARE,
};

static enum QTIER_TEMPER __xattr_search(const void *value, size_t size)
{
	enum QTIER_TEMPER t;

	for (t = QTIER_NORMALDATA; t < __MAX_NR_QTIER_XATTRS; t++) {
		if (size == strlen(qtier_xattrs[t]) &&
	        !strncmp(value, qtier_xattrs[t], size))
			break;
	}

	return t;
}

int qtier_xattr_check(const char *name, const void *value, size_t size)
{
	/* workaround for overlayfs  */
	/*
	kuid_t root_uid;

	root_uid = make_kuid(current_user_ns(), 0);
	if (!uid_eq(current_fsuid(), root_uid))
		return -EPERM;
	*/

	if (value && __xattr_search(value, size) < __MAX_NR_QTIER_XATTRS)
		return 0;

	/* remove qtier extended attribute*/
	if (!value && size == 0)
		return 0;

	return -EINVAL;
}

int ext4_check_data_temper(struct inode *inode)
{
	int r = 0, size;
	void *value = NULL;
	enum QTIER_TEMPER t = QTIER_NORMALDATA;

	if (!test_opt(inode->i_sb, XATTR_USER))
		goto ret;

	size = ext4_xattr_get(inode, EXT4_XATTR_INDEX_USER,
			QTIER_XATTR, NULL, 0);

	if (size <= 0)
		goto ret;

	value = kmalloc(size, GFP_KERNEL);
	if (!value) {
		pr_err_ratelimited("%s: no memory, return normal anyway.", __func__);
		goto ret;
	}

	r = ext4_xattr_get(inode,
					   EXT4_XATTR_INDEX_USER, QTIER_XATTR, value, size);
	if (r < 0)
		goto out;

	t = __xattr_search(value, size);
	if (t >= __MAX_NR_QTIER_XATTRS)
		t = QTIER_NORMALDATA;
out:
	kfree(value);
ret:
	return qtier_bio_flags[t];
}

int
ext4_init_qtier(handle_t *handle, struct inode *inode, struct inode *dir)
{
	int retval = 0;
	void *value = NULL;

	if (!test_opt(inode->i_sb, XATTR_USER) ||
		!test_opt(dir->i_sb, XATTR_USER))
		return 0;

	if (!S_ISREG(inode->i_mode) && !S_ISDIR(inode->i_mode))
		return 0;

	retval = ext4_xattr_get(dir, EXT4_XATTR_INDEX_USER,
		QTIER_XATTR, NULL, 0);
	if (retval > 0) {
		value = kmalloc(retval, GFP_KERNEL);
		if (!value)
			return -ENOMEM;

		retval = ext4_xattr_get(dir, EXT4_XATTR_INDEX_USER,
			QTIER_XATTR, value, retval);
		if (retval <= 0) {
			kfree(value);
			return 0;
		}
	} else
		return 0;

	retval = ext4_xattr_set(inode, EXT4_XATTR_INDEX_USER,
		QTIER_XATTR, value, retval, 0);

	kfree(value);

	return retval;
}
