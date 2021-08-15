/*
 * linux/fs/ext3/xattr_user.c
 * Handler for extended user attributes.
 *
 * Copyright (C) 2001 by Andreas Gruenbacher, <a.gruenbacher@computer.org>
 */

#include "ext3.h"
#include "xattr.h"

static bool
ext3_xattr_user_list(struct dentry *dentry)
{
	return test_opt(dentry->d_sb, XATTR_USER);
}

static int
ext3_xattr_user_get(struct dentry *dentry, const char *name, void *buffer,
		size_t size, int type)
{
	if (strcmp(name, "") == 0)
		return -EINVAL;
	if (!test_opt(dentry->d_sb, XATTR_USER))
		return -EOPNOTSUPP;
	return ext3_xattr_get(d_inode(dentry), EXT3_XATTR_INDEX_USER,
			      name, buffer, size);
}

static int
ext3_xattr_user_set(struct dentry *dentry, const char *name,
		const void *value, size_t size, int flags, int type)
{
	if (strcmp(name, "") == 0)
		return -EINVAL;
	if (!test_opt(dentry->d_sb, XATTR_USER))
		return -EOPNOTSUPP;
	return ext3_xattr_set(d_inode(dentry), EXT3_XATTR_INDEX_USER,
			      name, value, size, flags);
}

const struct xattr_handler ext3_xattr_user_handler = {
	.prefix	= XATTR_USER_PREFIX,
	.list	= ext3_xattr_user_list,
	.get	= ext3_xattr_user_get,
	.set	= ext3_xattr_user_set,
};
