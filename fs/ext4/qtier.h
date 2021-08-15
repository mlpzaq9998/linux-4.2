#ifndef __FS_EXT4_QTIER_H
#define __FS_EXT4_QTIER_H

#include <linux/qtier.h>

extern int ext4_check_data_temper(struct inode *inode);
extern int ext4_init_qtier(handle_t *handle, struct inode *inode, struct inode *dir);

#endif  /* __FS_EXT4_QTIER_H */
