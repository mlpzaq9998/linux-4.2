#ifndef __QTIER_H
#define __QTIER_H

#define QTIER_XATTR		"qtier"

enum QTIER_TEMPER {
    	QTIER_NORMALDATA,
    	QTIER_HOTDATA,
    	QTIER_COLDDATA,
    	QTIER_HOT_ANCHOR,
    	QTIER_COLD_ANCHOR,
    	QTIER_IO_AWARE,
	__MAX_NR_QTIER_XATTRS
};

int qtier_xattr_check(const char *name, const void *value, size_t size);

#endif /* __QTIER_H */
