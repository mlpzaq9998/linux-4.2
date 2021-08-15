/*
 * linux/fs/ext2/xattr_trusted.c
 * Handler for trusted extended attributes.
 *
 * Copyright (C) 2003 by Andreas Gruenbacher, <a.gruenbacher@computer.org>
 */

#include "ext2.h"
#include "xattr.h"

static bool
ext2_xattr_trusted_list(struct dentry *dentry)
{
	return capable(CAP_SYS_ADMIN);
}

static int
ext2_xattr_trusted_get(struct dentry *dentry, const char *name,
		void *buffer, size_t size, int type)
{
	if (strcmp(name, "") == 0)
		return -EINVAL;
	return ext2_xattr_get(d_inode(dentry), EXT2_XATTR_INDEX_TRUSTED, name,
			      buffer, size);
}

static int
ext2_xattr_trusted_set(struct dentry *dentry, const char *name,
		const void *value, size_t size, int flags, int type)
{
	if (strcmp(name, "") == 0)
		return -EINVAL;
	return ext2_xattr_set(d_inode(dentry), EXT2_XATTR_INDEX_TRUSTED, name,
			      value, size, flags);
}

const struct xattr_handler ext2_xattr_trusted_handler = {
	.prefix	= XATTR_TRUSTED_PREFIX,
	.list	= ext2_xattr_trusted_list,
	.get	= ext2_xattr_trusted_get,
	.set	= ext2_xattr_trusted_set,
};
