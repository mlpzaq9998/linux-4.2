#ifndef _FS_CEPH_TYPES_H
#define _FS_CEPH_TYPES_H

/* needed before including ceph_fs.h */
#include <linux/in.h>
#include <linux/types.h>
#include <linux/fcntl.h>
#include <linux/string.h>

#include <linux/ceph/ceph_fs.h>
#include <linux/ceph/ceph_frag.h>
#include <linux/ceph/ceph_hash.h>

/*
 * Identify inodes by both their ino AND snapshot id (a u64).
 */
struct ceph_vino {
	u64 ino;
	u64 snap;
};


/* context for the caps reservation mechanism */
struct ceph_cap_reservation {
	int count;
};

struct ceph_quota_info {
	u64 max_bytes;
	u64 max_files;
};

#endif
