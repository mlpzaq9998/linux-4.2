/*
 * linux/fs/ext4/xattr_user.c
 * Handler for extended user attributes.
 *
 * Copyright (C) 2001 by Andreas Gruenbacher, <a.gruenbacher@computer.org>
 */

#include <linux/string.h>
#include <linux/fs.h>
#include "ext4_jbd2.h"
#include "ext4.h"
#include "xattr.h"
#include "qtier.h"

static bool
ext4_xattr_user_list(struct dentry *dentry)
{
	return test_opt(dentry->d_sb, XATTR_USER);
}

static int
ext4_xattr_user_get(struct dentry *dentry, const char *name,
		    void *buffer, size_t size, int type)
{
	if (strcmp(name, "") == 0)
		return -EINVAL;
	if (!test_opt(dentry->d_sb, XATTR_USER))
		return -EOPNOTSUPP;
	return ext4_xattr_get(d_inode(dentry), EXT4_XATTR_INDEX_USER,
			      name, buffer, size);
}

static int
ext4_xattr_user_set(struct dentry *dentry, const char *name,
		    const void *value, size_t size, int flags, int type)
{
	int r;
	kuid_t root_uid;

	if (strcmp(name, "") == 0)
		return -EINVAL;

	if (strlen(name) == strlen(QTIER_XATTR) &&
	    !strncmp(name, QTIER_XATTR, strlen(QTIER_XATTR))) {
		r = qtier_xattr_check(name, value, size);
		if (r)
			return r;
	}

	if (!test_opt(dentry->d_sb, XATTR_USER))
		return -EOPNOTSUPP;
		
	return ext4_xattr_set(d_inode(dentry), EXT4_XATTR_INDEX_USER,
			      name, value, size, flags);
}

const struct xattr_handler ext4_xattr_user_handler = {
	.prefix	= XATTR_USER_PREFIX,
	.list	= ext4_xattr_user_list,
	.get	= ext4_xattr_user_get,
	.set	= ext4_xattr_user_set,
};
