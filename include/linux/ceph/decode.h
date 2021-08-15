#ifndef __CEPH_DECODE_H
#define __CEPH_DECODE_H

#include <linux/err.h>
#include <linux/bug.h>
#include <linux/time.h>
#include <asm/unaligned.h>

#include <linux/ceph/types.h>

/*
 * in all cases,
 *   void **p     pointer to position pointer
 *   void *end    pointer to end of buffer (last byte + 1)
 */

static inline u64 ceph_decode_64(void **p)
{
	u64 v = get_unaligned_le64(*p);
	*p += sizeof(u64);
	return v;
}
static inline u32 ceph_decode_32(void **p)
{
	u32 v = get_unaligned_le32(*p);
	*p += sizeof(u32);
	return v;
}
static inline u16 ceph_decode_16(void **p)
{
	u16 v = get_unaligned_le16(*p);
	*p += sizeof(u16);
	return v;
}
static inline u8 ceph_decode_8(void **p)
{
	u8 v = *(u8 *)*p;
	(*p)++;
	return v;
}
static inline void ceph_decode_copy(void **p, void *pv, size_t n)
{
	memcpy(pv, *p, n);
	*p += n;
}

/*
 * bounds check input.
 */
static inline int ceph_has_room(void **p, void *end, size_t n)
{
	return end >= *p && n <= end - *p;
}

#define ceph_decode_need(p, end, n, bad)			\
	do {							\
		if (!likely(ceph_has_room(p, end, n)))		\
			goto bad;				\
	} while (0)

#define ceph_decode_64_safe(p, end, v, bad)			\
	do {							\
		ceph_decode_need(p, end, sizeof(u64), bad);	\
		v = ceph_decode_64(p);				\
	} while (0)
#define ceph_decode_32_safe(p, end, v, bad)			\
	do {							\
		ceph_decode_need(p, end, sizeof(u32), bad);	\
		v = ceph_decode_32(p);				\
	} while (0)
#define ceph_decode_16_safe(p, end, v, bad)			\
	do {							\
		ceph_decode_need(p, end, sizeof(u16), bad);	\
		v = ceph_decode_16(p);				\
	} while (0)
#define ceph_decode_8_safe(p, end, v, bad)			\
	do {							\
		ceph_decode_need(p, end, sizeof(u8), bad);	\
		v = ceph_decode_8(p);				\
	} while (0)

#define ceph_decode_copy_safe(p, end, pv, n, bad)		\
	do {							\
		ceph_decode_need(p, end, n, bad);		\
		ceph_decode_copy(p, pv, n);			\
	} while (0)

/*
 * Allocate a buffer big enough to hold the wire-encoded string, and
 * decode the string into it.  The resulting string will always be
 * terminated with '\0'.  If successful, *p will be advanced
 * past the decoded data.  Also, if lenp is not a null pointer, the
 * length (not including the terminating '\0') will be recorded in
 * *lenp.  Note that a zero-length string is a valid return value.
 *
 * Returns a pointer to the newly-allocated string buffer, or a
 * pointer-coded errno if an error occurs.  Neither *p nor *lenp
 * will have been updated if an error is returned.
 *
 * There are two possible failures:
 *   - converting the string would require accessing memory at or
 *     beyond the "end" pointer provided (-ERANGE)
 *   - memory could not be allocated for the result (-ENOMEM)
 */
static inline char *ceph_extract_encoded_string(void **p, void *end,
						size_t *lenp, gfp_t gfp)
{
	u32 len;
	void *sp = *p;
	char *buf;

	ceph_decode_32_safe(&sp, end, len, bad);
	if (!ceph_has_room(&sp, end, len))
		goto bad;

	buf = kmalloc(len + 1, gfp);
	if (!buf)
		return ERR_PTR(-ENOMEM);

	if (len)
		memcpy(buf, sp, len);
	buf[len] = '\0';

	*p = (char *) *p + sizeof (u32) + len;
	if (lenp)
		*lenp = (size_t) len;

	return buf;

bad:
	return ERR_PTR(-ERANGE);
}

/*
 * struct ceph_timespec <-> struct timespec
 */
static inline void ceph_decode_timespec(struct timespec *ts,
					const struct ceph_timespec *tv)
{
	ts->tv_sec = (__kernel_time_t)le32_to_cpu(tv->tv_sec);
	ts->tv_nsec = (long)le32_to_cpu(tv->tv_nsec);
}
static inline void ceph_encode_timespec(struct ceph_timespec *tv,
					const struct timespec *ts)
{
	tv->tv_sec = cpu_to_le32((u32)ts->tv_sec);
	tv->tv_nsec = cpu_to_le32((u32)ts->tv_nsec);
}

/*
 * sockaddr_storage <-> ceph_sockaddr
 */
static inline void ceph_encode_addr(struct ceph_entity_addr *a)
{
	__be16 ss_family = htons(a->in_addr.ss_family);
	a->in_addr.ss_family = *(__u16 *)&ss_family;
}
static inline void ceph_decode_addr(struct ceph_entity_addr *a)
{
	__be16 ss_family = *(__be16 *)&a->in_addr.ss_family;
	a->in_addr.ss_family = ntohs(ss_family);
	WARN_ON(a->in_addr.ss_family == 512);
}

/*
 * encoders
 */
static inline void ceph_encode_64(void **p, u64 v)
{
	put_unaligned_le64(v, (__le64 *)*p);
	*p += sizeof(u64);
}
static inline void ceph_encode_32(void **p, u32 v)
{
	put_unaligned_le32(v, (__le32 *)*p);
	*p += sizeof(u32);
}
static inline void ceph_encode_16(void **p, u16 v)
{
	put_unaligned_le16(v, (__le16 *)*p);
	*p += sizeof(u16);
}
static inline void ceph_encode_8(void **p, u8 v)
{
	*(u8 *)*p = v;
	(*p)++;
}
static inline void ceph_encode_copy(void **p, const void *s, int len)
{
	memcpy(*p, s, len);
	*p += len;
}

/*
 * filepath, string encoders
 */
static inline void ceph_encode_filepath(void **p, void *end,
					u64 ino, const char *path)
{
	u32 len = path ? strlen(path) : 0;
	BUG_ON(*p + 1 + sizeof(ino) + sizeof(len) + len > end);
	ceph_encode_8(p, 1);
	ceph_encode_64(p, ino);
	ceph_encode_32(p, len);
	if (len)
		memcpy(*p, path, len);
	*p += len;
}

static inline void ceph_encode_string(void **p, void *end,
				      const char *s, u32 len)
{
	BUG_ON(*p + sizeof(len) + len > end);
	ceph_encode_32(p, len);
	if (len)
		memcpy(*p, s, len);
	*p += len;
}

#if defined(CONFIG_MACH_QNAPTS) && defined(CONFIG_QTS_CEPH)
/*
 * version and length starting block encoders/decoders
 */

/* current code version (u8) + compat code version (u8) + len of struct (u32) */
#define CEPH_ENCODING_START_BLK_LEN 6

/**
 * ceph_start_encoding - start encoding block
 * @p: buffer to encode data in
 * @curr_ver: current (code) version of the encoding
 * @compat_ver: oldest code version that can decode it
 * @len: length of data that will be encoded in buffer
 */
static inline void ceph_start_encoding(void **p, u8 curr_ver, u8 compat_ver,
				       u32 len)
{
	ceph_encode_8(p, curr_ver);
	ceph_encode_8(p, compat_ver);
	ceph_encode_32(p, len);
}

/**
 * ceph_start_decoding_compat - decode block with legacy support for older schemes
 * @p: buffer to decode
 * @end: end of decode buffer
 * @curr_ver: current version of the encoding that the code supports/encode
 * @compat_ver: oldest version that includes a __u8 compat version field
 * @len_ver: oldest version that includes a __u32 length wrapper
 * @len: buffer to return len of data in buffer
 */
static inline int ceph_start_decoding_compat(void **p, void *end, u8 curr_ver,
					     u8 compat_ver, u8 len_ver, u32 *len)
{
	u8 struct_ver, struct_compat;

	ceph_decode_8_safe(p, end, struct_ver, fail);
	if (struct_ver >= curr_ver) {
		ceph_decode_8_safe(p, end, struct_compat, fail);
		if (curr_ver < struct_compat)
			return -EINVAL;
	}

	if (struct_ver >= len_ver) {
		ceph_decode_32_safe(p, end, *len, fail);
	} else {
		*len = 0;
	}

	return 0;
fail:
	return -ERANGE;
}

/**
 * ceph_start_decoding - start a decoding block
 * @p: buffer to decode
 * @end: end of buffer
 * @curr_ver: current version of the encoding that the code supports/encode
 * @len: buffer to return len of data in buffer
 */
static inline int ceph_start_decoding(void **p, void *end, u8 curr_ver,
				      u32 *len)
{
	u8 struct_ver, struct_compat;

	ceph_decode_8_safe(p, end, struct_ver, fail);
	ceph_decode_8_safe(p, end, struct_compat, fail);

	if (curr_ver < struct_compat)
		return -EINVAL;

	ceph_decode_32_safe(p, end, *len, fail);
	return 0;
fail:
	return -ERANGE;
}
#endif

#define ceph_encode_need(p, end, n, bad)			\
	do {							\
		if (!likely(ceph_has_room(p, end, n)))		\
			goto bad;				\
	} while (0)

#define ceph_encode_64_safe(p, end, v, bad)			\
	do {							\
		ceph_encode_need(p, end, sizeof(u64), bad);	\
		ceph_encode_64(p, v);				\
	} while (0)
#define ceph_encode_32_safe(p, end, v, bad)			\
	do {							\
		ceph_encode_need(p, end, sizeof(u32), bad);	\
		ceph_encode_32(p, v);				\
	} while (0)
#define ceph_encode_16_safe(p, end, v, bad)			\
	do {							\
		ceph_encode_need(p, end, sizeof(u16), bad);	\
		ceph_encode_16(p, v);				\
	} while (0)
#define ceph_encode_8_safe(p, end, v, bad)			\
	do {							\
		ceph_encode_need(p, end, sizeof(u8), bad);	\
		ceph_encode_8(p, v);				\
	} while (0)

#define ceph_encode_copy_safe(p, end, pv, n, bad)		\
	do {							\
		ceph_encode_need(p, end, n, bad);		\
		ceph_encode_copy(p, pv, n);			\
	} while (0)
#define ceph_encode_string_safe(p, end, s, n, bad)		\
	do {							\
		ceph_encode_need(p, end, n, bad);		\
		ceph_encode_string(p, end, s, n);		\
	} while (0)


#endif
