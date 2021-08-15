/*
 * "splice": joining two ropes together by interweaving their strands.
 *
 * This is the "extended pipe" functionality, where a pipe is used as
 * an arbitrary in-memory buffer. Think of a pipe as a small kernel
 * buffer that you can use to transfer data from one end to the other.
 *
 * The traditional unix read/write is extended with a "splice()" operation
 * that transfers data buffers to or from a pipe buffer.
 *
 * Named by Larry McVoy, original implementation from Linus, extended by
 * Jens to support splicing to files, network, direct splicing, etc and
 * fixing lots of bugs.
 *
 * Copyright (C) 2005-2006 Jens Axboe <axboe@kernel.dk>
 * Copyright (C) 2005-2006 Linus Torvalds <torvalds@osdl.org>
 * Copyright (C) 2006 Ingo Molnar <mingo@elte.hu>
 *
 */

#include <linux/fast_clone.h>
#include <linux/wait.h>

#include <linux/fs.h>
#include <linux/file.h>
#include <linux/pagemap.h>
#include <linux/splice.h>
#include <linux/memcontrol.h>
#include <linux/mm_inline.h>
#include <linux/swap.h>
#include <linux/writeback.h>
#include <linux/export.h>
#include <linux/syscalls.h>
#include <linux/uio.h>
#include <linux/security.h>
#include <linux/gfp.h>
#include <linux/socket.h>
#include <linux/compat.h>
#include <linux/falloc.h>
#include <linux/fiemap.h>
#include <linux/delay.h>
#include <linux/statfs.h>
#include "internal.h"

/* Patched by QNAP to support Fnotify*/
#include <linux/fnotify.h>

/* Patched by QNAP for enhancing performance */
#include <net/sock.h>
#include <linux/backing-dev.h>
#define vfs_check_frozen(sb, level) \
	wait_event((sb)->s_writers.wait_unfrozen,\
		((sb)->s_writers.frozen < (level)))

#define NUM_ENTRY_PER_CPU 8

static mempool_t *rcv_pools = NULL;
static mempool_t *kvec_pools = NULL;

/*
 * Attempt to steal a page from a pipe buffer. This should perhaps go into
 * a vm helper function, it's already simplified quite a bit by the
 * addition of remove_mapping(). If success is returned, the caller may
 * attempt to reuse this page for another destination.
 */
static int page_cache_pipe_buf_steal(struct pipe_inode_info *pipe,
				     struct pipe_buffer *buf)
{
	struct page *page = buf->page;
	struct address_space *mapping;

	lock_page(page);

	mapping = page_mapping(page);
	if (mapping) {
		WARN_ON(!PageUptodate(page));

		/*
		 * At least for ext2 with nobh option, we need to wait on
		 * writeback completing on this page, since we'll remove it
		 * from the pagecache.  Otherwise truncate wont wait on the
		 * page, allowing the disk blocks to be reused by someone else
		 * before we actually wrote our data to them. fs corruption
		 * ensues.
		 */
		wait_on_page_writeback(page);

		if (page_has_private(page) &&
		    !try_to_release_page(page, GFP_KERNEL))
			goto out_unlock;

		/*
		 * If we succeeded in removing the mapping, set LRU flag
		 * and return good.
		 */
		if (remove_mapping(mapping, page)) {
			buf->flags |= PIPE_BUF_FLAG_LRU;
			return 0;
		}
	}

	/*
	 * Raced with truncate or failed to remove page from current
	 * address space, unlock and return failure.
	 */
out_unlock:
	unlock_page(page);
	return 1;
}

static void page_cache_pipe_buf_release(struct pipe_inode_info *pipe,
					struct pipe_buffer *buf)
{
	page_cache_release(buf->page);
	buf->flags &= ~PIPE_BUF_FLAG_LRU;
}

/*
 * Check whether the contents of buf is OK to access. Since the content
 * is a page cache page, IO may be in flight.
 */
static int page_cache_pipe_buf_confirm(struct pipe_inode_info *pipe,
				       struct pipe_buffer *buf)
{
	struct page *page = buf->page;
	int err;

	if (!PageUptodate(page)) {
		lock_page(page);

		/*
		 * Page got truncated/unhashed. This will cause a 0-byte
		 * splice, if this is the first page.
		 */
		if (!page->mapping) {
			err = -ENODATA;
			goto error;
		}

		/*
		 * Uh oh, read-error from disk.
		 */
		if (!PageUptodate(page)) {
			err = -EIO;
			goto error;
		}

		/*
		 * Page is ok afterall, we are done.
		 */
		unlock_page(page);
	}

	return 0;
error:
	unlock_page(page);
	return err;
}

const struct pipe_buf_operations page_cache_pipe_buf_ops = {
	.can_merge = 0,
	.confirm = page_cache_pipe_buf_confirm,
	.release = page_cache_pipe_buf_release,
	.steal = page_cache_pipe_buf_steal,
	.get = generic_pipe_buf_get,
};

static int user_page_pipe_buf_steal(struct pipe_inode_info *pipe,
				    struct pipe_buffer *buf)
{
	if (!(buf->flags & PIPE_BUF_FLAG_GIFT))
		return 1;

	buf->flags |= PIPE_BUF_FLAG_LRU;
	return generic_pipe_buf_steal(pipe, buf);
}

static const struct pipe_buf_operations user_page_pipe_buf_ops = {
	.can_merge = 0,
	.confirm = generic_pipe_buf_confirm,
	.release = page_cache_pipe_buf_release,
	.steal = user_page_pipe_buf_steal,
	.get = generic_pipe_buf_get,
};

static void wakeup_pipe_readers(struct pipe_inode_info *pipe)
{
	smp_mb();
	if (waitqueue_active(&pipe->wait))
		wake_up_interruptible(&pipe->wait);
	kill_fasync(&pipe->fasync_readers, SIGIO, POLL_IN);
}

/**
 * splice_to_pipe - fill passed data into a pipe
 * @pipe:	pipe to fill
 * @spd:	data to fill
 *
 * Description:
 *    @spd contains a map of pages and len/offset tuples, along with
 *    the struct pipe_buf_operations associated with these pages. This
 *    function will link that data to the pipe.
 *
 */
ssize_t splice_to_pipe(struct pipe_inode_info *pipe,
		       struct splice_pipe_desc *spd)
{
	unsigned int spd_pages = spd->nr_pages;
	int ret, do_wakeup, page_nr;

	if (!spd_pages)
		return 0;

	ret = 0;
	do_wakeup = 0;
	page_nr = 0;

	pipe_lock(pipe);

	for (;;) {
		if (!pipe->readers) {
			send_sig(SIGPIPE, current, 0);
			if (!ret)
				ret = -EPIPE;
			break;
		}

		if (pipe->nrbufs < pipe->buffers) {
			int newbuf = (pipe->curbuf + pipe->nrbufs) & (pipe->buffers - 1);
			struct pipe_buffer *buf = pipe->bufs + newbuf;

			buf->page = spd->pages[page_nr];
			buf->offset = spd->partial[page_nr].offset;
			buf->len = spd->partial[page_nr].len;
			buf->private = spd->partial[page_nr].private;
			buf->ops = spd->ops;
			if (spd->flags & SPLICE_F_GIFT)
				buf->flags |= PIPE_BUF_FLAG_GIFT;

			pipe->nrbufs++;
			page_nr++;
			ret += buf->len;

			if (pipe->files)
				do_wakeup = 1;

			if (!--spd->nr_pages)
				break;
			if (pipe->nrbufs < pipe->buffers)
				continue;

			break;
		}

		if (spd->flags & SPLICE_F_NONBLOCK) {
			if (!ret)
				ret = -EAGAIN;
			break;
		}

		if (signal_pending(current)) {
			if (!ret)
				ret = -ERESTARTSYS;
			break;
		}

		if (do_wakeup) {
			smp_mb();
			if (waitqueue_active(&pipe->wait))
				wake_up_interruptible_sync(&pipe->wait);
			kill_fasync(&pipe->fasync_readers, SIGIO, POLL_IN);
			do_wakeup = 0;
		}

		pipe->waiting_writers++;
		pipe_wait(pipe);
		pipe->waiting_writers--;
	}

	pipe_unlock(pipe);

	if (do_wakeup)
		wakeup_pipe_readers(pipe);

	while (page_nr < spd_pages)
		spd->spd_release(spd, page_nr++);

	return ret;
}
EXPORT_SYMBOL_GPL(splice_to_pipe);

void spd_release_page(struct splice_pipe_desc *spd, unsigned int i)
{
	page_cache_release(spd->pages[i]);
}

/*
 * Check if we need to grow the arrays holding pages and partial page
 * descriptions.
 */
int splice_grow_spd(const struct pipe_inode_info *pipe, struct splice_pipe_desc *spd)
{
	unsigned int buffers = ACCESS_ONCE(pipe->buffers);

	spd->nr_pages_max = buffers;
	if (buffers <= PIPE_DEF_BUFFERS)
		return 0;

	spd->pages = kmalloc(buffers * sizeof(struct page *), GFP_KERNEL);
	spd->partial = kmalloc(buffers * sizeof(struct partial_page), GFP_KERNEL);

	if (spd->pages && spd->partial)
		return 0;

	kfree(spd->pages);
	kfree(spd->partial);
	return -ENOMEM;
}

void splice_shrink_spd(struct splice_pipe_desc *spd)
{
	if (spd->nr_pages_max <= PIPE_DEF_BUFFERS)
		return;

	kfree(spd->pages);
	kfree(spd->partial);
}

static int
__generic_file_splice_read(struct file *in, loff_t *ppos,
			   struct pipe_inode_info *pipe, size_t len,
			   unsigned int flags)
{
	struct address_space *mapping = in->f_mapping;
	unsigned int loff, nr_pages, req_pages;
	struct page *pages[PIPE_DEF_BUFFERS];
	struct partial_page partial[PIPE_DEF_BUFFERS];
	struct page *page;
	pgoff_t index, end_index;
	loff_t isize;
	int error, page_nr;
	struct splice_pipe_desc spd = {
		.pages = pages,
		.partial = partial,
		.nr_pages_max = PIPE_DEF_BUFFERS,
		.flags = flags,
		.ops = &page_cache_pipe_buf_ops,
		.spd_release = spd_release_page,
	};

	if (splice_grow_spd(pipe, &spd))
		return -ENOMEM;

	index = *ppos >> PAGE_CACHE_SHIFT;
	loff = *ppos & ~PAGE_CACHE_MASK;
	req_pages = (len + loff + PAGE_CACHE_SIZE - 1) >> PAGE_CACHE_SHIFT;
	nr_pages = min(req_pages, spd.nr_pages_max);

	/*
	 * Lookup the (hopefully) full range of pages we need.
	 */
	spd.nr_pages = find_get_pages_contig(mapping, index, nr_pages, spd.pages);
	index += spd.nr_pages;

	/*
	 * If find_get_pages_contig() returned fewer pages than we needed,
	 * readahead/allocate the rest and fill in the holes.
	 */
	if (spd.nr_pages < nr_pages)
		page_cache_sync_readahead(mapping, &in->f_ra, in,
				index, req_pages - spd.nr_pages);

	error = 0;
	while (spd.nr_pages < nr_pages) {
		/*
		 * Page could be there, find_get_pages_contig() breaks on
		 * the first hole.
		 */
		page = find_get_page(mapping, index);
		if (!page) {
			/*
			 * page didn't exist, allocate one.
			 */
			page = page_cache_alloc_cold(mapping);
			if (!page)
				break;

			error = add_to_page_cache_lru(page, mapping, index,
					GFP_KERNEL & mapping_gfp_mask(mapping));
			if (unlikely(error)) {
				page_cache_release(page);
				if (error == -EEXIST)
					continue;
				break;
			}
			/*
			 * add_to_page_cache() locks the page, unlock it
			 * to avoid convoluting the logic below even more.
			 */
			unlock_page(page);
		}

		spd.pages[spd.nr_pages++] = page;
		index++;
	}

	/*
	 * Now loop over the map and see if we need to start IO on any
	 * pages, fill in the partial map, etc.
	 */
	index = *ppos >> PAGE_CACHE_SHIFT;
	nr_pages = spd.nr_pages;
	spd.nr_pages = 0;
	for (page_nr = 0; page_nr < nr_pages; page_nr++) {
		unsigned int this_len;

		if (!len)
			break;

		/*
		 * this_len is the max we'll use from this page
		 */
		this_len = min_t(unsigned long, len, PAGE_CACHE_SIZE - loff);
		page = spd.pages[page_nr];

		if (PageReadahead(page))
			page_cache_async_readahead(mapping, &in->f_ra, in,
					page, index, req_pages - page_nr);

		/*
		 * If the page isn't uptodate, we may need to start io on it
		 */
		if (!PageUptodate(page)) {
			lock_page(page);

			/*
			 * Page was truncated, or invalidated by the
			 * filesystem.  Redo the find/create, but this time the
			 * page is kept locked, so there's no chance of another
			 * race with truncate/invalidate.
			 */
			if (!page->mapping) {
				unlock_page(page);
				page = find_or_create_page(mapping, index,
						mapping_gfp_mask(mapping));

				if (!page) {
					error = -ENOMEM;
					break;
				}
				page_cache_release(spd.pages[page_nr]);
				spd.pages[page_nr] = page;
			}
			/*
			 * page was already under io and is now done, great
			 */
			if (PageUptodate(page)) {
				unlock_page(page);
				goto fill_it;
			}

			/*
			 * need to read in the page
			 */
			error = mapping->a_ops->readpage(in, page);
			if (unlikely(error)) {
				/*
				 * We really should re-lookup the page here,
				 * but it complicates things a lot. Instead
				 * lets just do what we already stored, and
				 * we'll get it the next time we are called.
				 */
				if (error == AOP_TRUNCATED_PAGE)
					error = 0;

				break;
			}
		}
fill_it:
		/*
		 * i_size must be checked after PageUptodate.
		 */
		isize = i_size_read(mapping->host);
		end_index = (isize - 1) >> PAGE_CACHE_SHIFT;
		if (unlikely(!isize || index > end_index))
			break;

		/*
		 * if this is the last page, see if we need to shrink
		 * the length and stop
		 */
		if (end_index == index) {
			unsigned int plen;

			/*
			 * max good bytes in this page
			 */
			plen = ((isize - 1) & ~PAGE_CACHE_MASK) + 1;
			if (plen <= loff)
				break;

			/*
			 * force quit after adding this page
			 */
			this_len = min(this_len, plen - loff);
			len = this_len;
		}

		spd.partial[page_nr].offset = loff;
		spd.partial[page_nr].len = this_len;
		len -= this_len;
		loff = 0;
		spd.nr_pages++;
		index++;
	}

	/*
	 * Release any pages at the end, if we quit early. 'page_nr' is how far
	 * we got, 'nr_pages' is how many pages are in the map.
	 */
	while (page_nr < nr_pages)
		page_cache_release(spd.pages[page_nr++]);
	in->f_ra.prev_pos = (loff_t)index << PAGE_CACHE_SHIFT;

	if (spd.nr_pages)
		error = splice_to_pipe(pipe, &spd);

	splice_shrink_spd(&spd);
	return error;
}

/**
 * generic_file_splice_read - splice data from file to a pipe
 * @in:		file to splice from
 * @ppos:	position in @in
 * @pipe:	pipe to splice to
 * @len:	number of bytes to splice
 * @flags:	splice modifier flags
 *
 * Description:
 *    Will read pages from given file and fill them into a pipe. Can be
 *    used as long as the address_space operations for the source implements
 *    a readpage() hook.
 *
 */
ssize_t generic_file_splice_read(struct file *in, loff_t *ppos,
				 struct pipe_inode_info *pipe, size_t len,
				 unsigned int flags)
{
	loff_t isize, left;
	int ret;

	if (IS_DAX(in->f_mapping->host))
		return default_file_splice_read(in, ppos, pipe, len, flags);

	isize = i_size_read(in->f_mapping->host);
	if (unlikely(*ppos >= isize))
		return 0;

	left = isize - *ppos;
	if (unlikely(left < len))
		len = left;

	ret = __generic_file_splice_read(in, ppos, pipe, len, flags);
	if (ret > 0) {
		*ppos += ret;
		file_accessed(in);
	}

	return ret;
}
EXPORT_SYMBOL(generic_file_splice_read);

static const struct pipe_buf_operations default_pipe_buf_ops = {
	.can_merge = 0,
	.confirm = generic_pipe_buf_confirm,
	.release = generic_pipe_buf_release,
	.steal = generic_pipe_buf_steal,
	.get = generic_pipe_buf_get,
};

static int generic_pipe_buf_nosteal(struct pipe_inode_info *pipe,
				    struct pipe_buffer *buf)
{
	return 1;
}

/* Pipe buffer operations for a socket and similar. */
const struct pipe_buf_operations nosteal_pipe_buf_ops = {
	.can_merge = 0,
	.confirm = generic_pipe_buf_confirm,
	.release = generic_pipe_buf_release,
	.steal = generic_pipe_buf_nosteal,
	.get = generic_pipe_buf_get,
};
EXPORT_SYMBOL(nosteal_pipe_buf_ops);

static ssize_t kernel_readv(struct file *file, const struct iovec *vec,
			    unsigned long vlen, loff_t offset)
{
	mm_segment_t old_fs;
	loff_t pos = offset;
	ssize_t res;

	old_fs = get_fs();
	set_fs(get_ds());
	/* The cast to a user pointer is valid due to the set_fs() */
	res = vfs_readv(file, (const struct iovec __user *)vec, vlen, &pos);
	set_fs(old_fs);

	return res;
}

ssize_t kernel_write(struct file *file, const char *buf, size_t count,
			    loff_t pos)
{
	mm_segment_t old_fs;
	ssize_t res;

	old_fs = get_fs();
	set_fs(get_ds());
	/* The cast to a user pointer is valid due to the set_fs() */
	res = vfs_write(file, (__force const char __user *)buf, count, &pos);
	set_fs(old_fs);

	return res;
}
EXPORT_SYMBOL(kernel_write);

#ifdef QNAP_DEDUPE
ssize_t QNAP_default_splice_from_zero(loff_t *ppos,
				 struct pipe_inode_info *pipe, size_t len,
				 unsigned int flags)
{
	unsigned int nr_pages;
	unsigned int nr_freed;
	size_t offset;
	struct page *pages[PIPE_DEF_BUFFERS];
	struct partial_page partial[PIPE_DEF_BUFFERS];
	struct iovec *vec, __vec[PIPE_DEF_BUFFERS];
	ssize_t res;
	size_t this_len;
	int error;
	int i;

	struct splice_pipe_desc spd = {
		.pages = pages,
		.partial = partial,
		.nr_pages_max = PIPE_DEF_BUFFERS,
		.flags = flags,
		.ops = &default_pipe_buf_ops,
		.spd_release = spd_release_page,
	};

	if (splice_grow_spd(pipe, &spd))
		return -ENOMEM;

	res = -ENOMEM;
	vec = __vec;
	if (spd.nr_pages_max > PIPE_DEF_BUFFERS) {
		vec = kmalloc_array(spd.nr_pages_max, sizeof(struct iovec),
				GFP_KERNEL);
		if (!vec)
			goto shrink_ret;
	}

	offset = *ppos & ~PAGE_CACHE_MASK;
	nr_pages = (len + offset + PAGE_CACHE_SIZE - 1) >> PAGE_CACHE_SHIFT;

	for (i = 0; i < nr_pages && i < spd.nr_pages_max && len; i++) {
		struct page *page;

		page = alloc_page(GFP_KERNEL | __GFP_ZERO);
		error = -ENOMEM;
		if (!page)
			goto err;

		this_len = min_t(size_t, len, PAGE_CACHE_SIZE - offset);
		vec[i].iov_len = this_len;
		spd.pages[i] = page;
		spd.nr_pages++;
		len -= this_len;
		offset = 0;
	}

	nr_freed = 0;
	for (i = 0; i < spd.nr_pages; i++) {
		this_len = min_t(size_t, vec[i].iov_len, res);
		spd.partial[i].offset = 0;
		spd.partial[i].len = this_len;
		if (!this_len) {
			__free_page(spd.pages[i]);
			spd.pages[i] = NULL;
			nr_freed++;
		}
		res -= this_len;
	}
	spd.nr_pages -= nr_freed;

	res = splice_to_pipe(pipe, &spd);
	if (res > 0)
		*ppos += res;

shrink_ret:
	if (vec != __vec)
		kfree(vec);
	splice_shrink_spd(&spd);
	return res;

err:
	for (i = 0; i < spd.nr_pages; i++)
		__free_page(spd.pages[i]);

	res = error;
	goto shrink_ret;
}
EXPORT_SYMBOL(QNAP_default_splice_from_zero);
#endif

ssize_t default_file_splice_read(struct file *in, loff_t *ppos,
				 struct pipe_inode_info *pipe, size_t len,
				 unsigned int flags)
{
	unsigned int nr_pages;
	unsigned int nr_freed;
	size_t offset;
	struct page *pages[PIPE_DEF_BUFFERS];
	struct partial_page partial[PIPE_DEF_BUFFERS];
	struct iovec *vec, __vec[PIPE_DEF_BUFFERS];
	ssize_t res;
	size_t this_len;
	int error;
	int i;
	struct splice_pipe_desc spd = {
		.pages = pages,
		.partial = partial,
		.nr_pages_max = PIPE_DEF_BUFFERS,
		.flags = flags,
		.ops = &default_pipe_buf_ops,
		.spd_release = spd_release_page,
	};

	if (splice_grow_spd(pipe, &spd))
		return -ENOMEM;

	res = -ENOMEM;
	vec = __vec;
	if (spd.nr_pages_max > PIPE_DEF_BUFFERS) {
		vec = kmalloc(spd.nr_pages_max * sizeof(struct iovec), GFP_KERNEL);
		if (!vec)
			goto shrink_ret;
	}

	offset = *ppos & ~PAGE_CACHE_MASK;
	nr_pages = (len + offset + PAGE_CACHE_SIZE - 1) >> PAGE_CACHE_SHIFT;

	for (i = 0; i < nr_pages && i < spd.nr_pages_max && len; i++) {
		struct page *page;

		page = alloc_page(GFP_USER);
		error = -ENOMEM;
		if (!page)
			goto err;

		this_len = min_t(size_t, len, PAGE_CACHE_SIZE - offset);
		vec[i].iov_base = (void __user *) page_address(page);
		vec[i].iov_len = this_len;
		spd.pages[i] = page;
		spd.nr_pages++;
		len -= this_len;
		offset = 0;
	}

	res = kernel_readv(in, vec, spd.nr_pages, *ppos);
	if (res < 0) {
		error = res;
		goto err;
	}

	error = 0;
	if (!res)
		goto err;

	nr_freed = 0;
	for (i = 0; i < spd.nr_pages; i++) {
		this_len = min_t(size_t, vec[i].iov_len, res);
		spd.partial[i].offset = 0;
		spd.partial[i].len = this_len;
		if (!this_len) {
			__free_page(spd.pages[i]);
			spd.pages[i] = NULL;
			nr_freed++;
		}
		res -= this_len;
	}
	spd.nr_pages -= nr_freed;

	res = splice_to_pipe(pipe, &spd);
	if (res > 0)
		*ppos += res;

shrink_ret:
	if (vec != __vec)
		kfree(vec);
	splice_shrink_spd(&spd);
	return res;

err:
	for (i = 0; i < spd.nr_pages; i++)
		__free_page(spd.pages[i]);

	res = error;
	goto shrink_ret;
}
EXPORT_SYMBOL(default_file_splice_read);

/*
 * Send 'sd->len' bytes to socket from 'sd->file' at position 'sd->pos'
 * using sendpage(). Return the number of bytes sent.
 */
static int pipe_to_sendpage(struct pipe_inode_info *pipe,
			    struct pipe_buffer *buf, struct splice_desc *sd)
{
	struct file *file = sd->u.file;
	loff_t pos = sd->pos;
	int more;

	if (!likely(file->f_op->sendpage))
		return -EINVAL;

	more = (sd->flags & SPLICE_F_MORE) ? MSG_MORE : 0;

	if (sd->len < sd->total_len && pipe->nrbufs > 1)
		more |= MSG_SENDPAGE_NOTLAST;

	return file->f_op->sendpage(file, buf->page, buf->offset,
				    sd->len, &pos, more);
}

static void wakeup_pipe_writers(struct pipe_inode_info *pipe)
{
	smp_mb();
	if (waitqueue_active(&pipe->wait))
		wake_up_interruptible(&pipe->wait);
	kill_fasync(&pipe->fasync_writers, SIGIO, POLL_OUT);
}

/**
 * splice_from_pipe_feed - feed available data from a pipe to a file
 * @pipe:	pipe to splice from
 * @sd:		information to @actor
 * @actor:	handler that splices the data
 *
 * Description:
 *    This function loops over the pipe and calls @actor to do the
 *    actual moving of a single struct pipe_buffer to the desired
 *    destination.  It returns when there's no more buffers left in
 *    the pipe or if the requested number of bytes (@sd->total_len)
 *    have been copied.  It returns a positive number (one) if the
 *    pipe needs to be filled with more data, zero if the required
 *    number of bytes have been copied and -errno on error.
 *
 *    This, together with splice_from_pipe_{begin,end,next}, may be
 *    used to implement the functionality of __splice_from_pipe() when
 *    locking is required around copying the pipe buffers to the
 *    destination.
 */
static int splice_from_pipe_feed(struct pipe_inode_info *pipe, struct splice_desc *sd,
			  splice_actor *actor)
{
	int ret;

	while (pipe->nrbufs) {
		struct pipe_buffer *buf = pipe->bufs + pipe->curbuf;
		const struct pipe_buf_operations *ops = buf->ops;

		sd->len = buf->len;
		if (sd->len > sd->total_len)
			sd->len = sd->total_len;

		ret = buf->ops->confirm(pipe, buf);
		if (unlikely(ret)) {
			if (ret == -ENODATA)
				ret = 0;
			return ret;
		}

		ret = actor(pipe, buf, sd);
		if (ret <= 0)
			return ret;

		buf->offset += ret;
		buf->len -= ret;

		sd->num_spliced += ret;
		sd->len -= ret;
		sd->pos += ret;
		sd->total_len -= ret;

		if (!buf->len) {
			buf->ops = NULL;
			ops->release(pipe, buf);
			pipe->curbuf = (pipe->curbuf + 1) & (pipe->buffers - 1);
			pipe->nrbufs--;
			if (pipe->files)
				sd->need_wakeup = true;
		}

		if (!sd->total_len)
			return 0;
	}

	return 1;
}

/**
 * splice_from_pipe_next - wait for some data to splice from
 * @pipe:	pipe to splice from
 * @sd:		information about the splice operation
 *
 * Description:
 *    This function will wait for some data and return a positive
 *    value (one) if pipe buffers are available.  It will return zero
 *    or -errno if no more data needs to be spliced.
 */
static int splice_from_pipe_next(struct pipe_inode_info *pipe, struct splice_desc *sd)
{
	while (!pipe->nrbufs) {
		if (!pipe->writers)
			return 0;

		if (!pipe->waiting_writers && sd->num_spliced)
			return 0;

		if (sd->flags & SPLICE_F_NONBLOCK)
			return -EAGAIN;

		if (signal_pending(current))
			return -ERESTARTSYS;

		if (sd->need_wakeup) {
			wakeup_pipe_writers(pipe);
			sd->need_wakeup = false;
		}

		pipe_wait(pipe);
	}

	return 1;
}

/**
 * splice_from_pipe_begin - start splicing from pipe
 * @sd:		information about the splice operation
 *
 * Description:
 *    This function should be called before a loop containing
 *    splice_from_pipe_next() and splice_from_pipe_feed() to
 *    initialize the necessary fields of @sd.
 */
static void splice_from_pipe_begin(struct splice_desc *sd)
{
	sd->num_spliced = 0;
	sd->need_wakeup = false;
}

/**
 * splice_from_pipe_end - finish splicing from pipe
 * @pipe:	pipe to splice from
 * @sd:		information about the splice operation
 *
 * Description:
 *    This function will wake up pipe writers if necessary.  It should
 *    be called after a loop containing splice_from_pipe_next() and
 *    splice_from_pipe_feed().
 */
static void splice_from_pipe_end(struct pipe_inode_info *pipe, struct splice_desc *sd)
{
	if (sd->need_wakeup)
		wakeup_pipe_writers(pipe);
}

/**
 * __splice_from_pipe - splice data from a pipe to given actor
 * @pipe:	pipe to splice from
 * @sd:		information to @actor
 * @actor:	handler that splices the data
 *
 * Description:
 *    This function does little more than loop over the pipe and call
 *    @actor to do the actual moving of a single struct pipe_buffer to
 *    the desired destination. See pipe_to_file, pipe_to_sendpage, or
 *    pipe_to_user.
 *
 */
ssize_t __splice_from_pipe(struct pipe_inode_info *pipe, struct splice_desc *sd,
			   splice_actor *actor)
{
	int ret;

	splice_from_pipe_begin(sd);
	do {
		ret = splice_from_pipe_next(pipe, sd);
		if (ret > 0)
			ret = splice_from_pipe_feed(pipe, sd, actor);
	} while (ret > 0);
	splice_from_pipe_end(pipe, sd);

	return sd->num_spliced ? sd->num_spliced : ret;
}
EXPORT_SYMBOL(__splice_from_pipe);

/**
 * splice_from_pipe - splice data from a pipe to a file
 * @pipe:	pipe to splice from
 * @out:	file to splice to
 * @ppos:	position in @out
 * @len:	how many bytes to splice
 * @flags:	splice modifier flags
 * @actor:	handler that splices the data
 *
 * Description:
 *    See __splice_from_pipe. This function locks the pipe inode,
 *    otherwise it's identical to __splice_from_pipe().
 *
 */
ssize_t splice_from_pipe(struct pipe_inode_info *pipe, struct file *out,
			 loff_t *ppos, size_t len, unsigned int flags,
			 splice_actor *actor)
{
	ssize_t ret;
	struct splice_desc sd = {
		.total_len = len,
		.flags = flags,
		.pos = *ppos,
		.u.file = out,
	};

	pipe_lock(pipe);
	ret = __splice_from_pipe(pipe, &sd, actor);
	pipe_unlock(pipe);

	return ret;
}

/**
 * iter_file_splice_write - splice data from a pipe to a file
 * @pipe:	pipe info
 * @out:	file to write to
 * @ppos:	position in @out
 * @len:	number of bytes to splice
 * @flags:	splice modifier flags
 *
 * Description:
 *    Will either move or copy pages (determined by @flags options) from
 *    the given pipe inode to the given file.
 *    This one is ->write_iter-based.
 *
 */
ssize_t
iter_file_splice_write(struct pipe_inode_info *pipe, struct file *out,
			  loff_t *ppos, size_t len, unsigned int flags)
{
	struct splice_desc sd = {
		.total_len = len,
		.flags = flags,
		.pos = *ppos,
		.u.file = out,
	};
	int nbufs = pipe->buffers;
	struct bio_vec *array = kcalloc(nbufs, sizeof(struct bio_vec),
					GFP_KERNEL);
	ssize_t ret;

	if (unlikely(!array))
		return -ENOMEM;

	pipe_lock(pipe);

	splice_from_pipe_begin(&sd);
	while (sd.total_len) {
		struct iov_iter from;
		size_t left;
		int n, idx;

		ret = splice_from_pipe_next(pipe, &sd);
		if (ret <= 0)
			break;

		if (unlikely(nbufs < pipe->buffers)) {
			kfree(array);
			nbufs = pipe->buffers;
			array = kcalloc(nbufs, sizeof(struct bio_vec),
					GFP_KERNEL);
			if (!array) {
				ret = -ENOMEM;
				break;
			}
		}

		/* build the vector */
		left = sd.total_len;
		for (n = 0, idx = pipe->curbuf; left && n < pipe->nrbufs; n++, idx++) {
			struct pipe_buffer *buf = pipe->bufs + idx;
			size_t this_len = buf->len;

			if (this_len > left)
				this_len = left;

			if (idx == pipe->buffers - 1)
				idx = -1;

			ret = buf->ops->confirm(pipe, buf);
			if (unlikely(ret)) {
				if (ret == -ENODATA)
					ret = 0;
				goto done;
			}

			array[n].bv_page = buf->page;
			array[n].bv_len = this_len;
			array[n].bv_offset = buf->offset;
			left -= this_len;
		}

		iov_iter_bvec(&from, ITER_BVEC | WRITE, array, n,
			      sd.total_len - left);
		ret = vfs_iter_write(out, &from, &sd.pos);
		if (ret <= 0)
			break;

		sd.num_spliced += ret;
		sd.total_len -= ret;
		*ppos = sd.pos;

		/* dismiss the fully eaten buffers, adjust the partial one */
		while (ret) {
			struct pipe_buffer *buf = pipe->bufs + pipe->curbuf;
			if (ret >= buf->len) {
				const struct pipe_buf_operations *ops = buf->ops;
				ret -= buf->len;
				buf->len = 0;
				buf->ops = NULL;
				ops->release(pipe, buf);
				pipe->curbuf = (pipe->curbuf + 1) & (pipe->buffers - 1);
				pipe->nrbufs--;
				if (pipe->files)
					sd.need_wakeup = true;
			} else {
				buf->offset += ret;
				buf->len -= ret;
				ret = 0;
			}
		}
	}
done:
	kfree(array);
	splice_from_pipe_end(pipe, &sd);

	pipe_unlock(pipe);

	if (sd.num_spliced)
		ret = sd.num_spliced;

	return ret;
}

EXPORT_SYMBOL(iter_file_splice_write);

static int write_pipe_buf(struct pipe_inode_info *pipe, struct pipe_buffer *buf,
			  struct splice_desc *sd)
{
	int ret;
	void *data;
	loff_t tmp = sd->pos;

	data = kmap(buf->page);
	ret = __kernel_write(sd->u.file, data + buf->offset, sd->len, &tmp);
	kunmap(buf->page);

	return ret;
}

static ssize_t default_file_splice_write(struct pipe_inode_info *pipe,
					 struct file *out, loff_t *ppos,
					 size_t len, unsigned int flags)
{
	ssize_t ret;

	ret = splice_from_pipe(pipe, out, ppos, len, flags, write_pipe_buf);
	if (ret > 0)
		*ppos += ret;

	return ret;
}

/**
 * generic_splice_sendpage - splice data from a pipe to a socket
 * @pipe:	pipe to splice from
 * @out:	socket to write to
 * @ppos:	position in @out
 * @len:	number of bytes to splice
 * @flags:	splice modifier flags
 *
 * Description:
 *    Will send @len bytes from the pipe to a network socket. No data copying
 *    is involved.
 *
 */
ssize_t generic_splice_sendpage(struct pipe_inode_info *pipe, struct file *out,
				loff_t *ppos, size_t len, unsigned int flags)
{
	return splice_from_pipe(pipe, out, ppos, len, flags, pipe_to_sendpage);
}

EXPORT_SYMBOL(generic_splice_sendpage);

/*
 * Attempt to initiate a splice from pipe to file.
 */
static long do_splice_from(struct pipe_inode_info *pipe, struct file *out,
			   loff_t *ppos, size_t len, unsigned int flags)
{
	ssize_t (*splice_write)(struct pipe_inode_info *, struct file *,
				loff_t *, size_t, unsigned int);

	if (out->f_op->splice_write)
		splice_write = out->f_op->splice_write;
	else
		splice_write = default_file_splice_write;

	return splice_write(pipe, out, ppos, len, flags);
}

static void qnap_fnotify_write_notify(struct path *path, T_INODE_INFO *i_info,
		long ret, loff_t offset)
{
#ifdef QNAP_FNOTIFY
	if (QNAP_FN_IS_NOTIFY(FN_WRITE))
		qnap_sys_file_notify(FN_WRITE, MARG_2xI64, path, NULL, 0,
			i_info, ret, offset-ret, ARG_PADDING, ARG_PADDING);
#endif
}

/* Patched by QNAP for enhancing performance */
typedef struct RECV_FILE_CONTROL_BLOCK {
	struct page *rv_page;
	loff_t rv_pos;
	size_t  rv_count;
	void *rv_fsdata;
} RCV_FILE_CB;

/* Patched by QNAP for enhancing performance */
static int qnap_mapping_write_end_all(struct file *file,
		struct address_space *mapping, RCV_FILE_CB *cb, int num_pages)
{
	int i = 0;
	int ret = 0;

	for (i = 0; i < num_pages; i++) {
		kunmap(cb[i].rv_page);
		ret = mapping->a_ops->write_end(file, mapping, cb[i].rv_pos,
			cb[i].rv_count, cb[i].rv_count, cb[i].rv_page,
			cb[i].rv_fsdata);
	}
	return ret;
}

static void qnap_setup_rvcb(RCV_FILE_CB *rv_cb, struct page *pageP, loff_t pos,
		unsigned long bytes, void *fsdata)
{
	rv_cb->rv_page = pageP;
	rv_cb->rv_pos = pos;
	rv_cb->rv_count = bytes;
	rv_cb->rv_fsdata = fsdata;
}

static void qnap_setup_iov(struct kvec *iov, struct page *pageP,
		unsigned long offset, unsigned long bytes)
{
	iov->iov_base = kmap(pageP) + offset;
	iov->iov_len = bytes;
}

/* Check the write region of the file */
static int qnap_file_write_check(struct file *file, loff_t *pos, size_t *count)
{
	int err = 0;
	struct kiocb kiocb;
	struct iov_iter iter;

	init_sync_kiocb(&kiocb, file);
	kiocb.ki_pos = *pos;
	iov_iter_init(&iter, WRITE, NULL, 1, *count);

	err = generic_write_checks(&kiocb, &iter);
	/* update pos and count after write check */
	*pos = kiocb.ki_pos;
	*count = iov_iter_count(&iter);

	return err;
}

/* The part is mostly derived from generic_write_iter() */
static int qnap_splice_to_file_prepare(struct file *file, loff_t *pos,
		size_t *count, RCV_FILE_CB *rv_cb, struct kvec *iov,
		int *pageAllocated)
{
	int err = 0, ret;
	int count_tmp;
	struct address_space *mapping = file->f_mapping;
	struct inode *inode = mapping->host;

	*pageAllocated = 0;
	vfs_check_frozen(inode->i_sb, SB_FREEZE_WRITE);

	err = qnap_file_write_check(file, pos, count);
	if (err < 0 || *count == 0)
		goto done;
	/* We can write back this queue in page reclaim */
	current->backing_dev_info = inode_to_bdi(inode);
	err = file_remove_privs(file);
	if (err)
		goto done;
	err = file_update_time(file);
	if (err)
		goto done;

	count_tmp = *count;
	do {
		unsigned long bytes;    /* Bytes to write to page */
		unsigned long offset;   /* Offset into pagecache page */
		struct page *pageP;
		void *fsdata;

		offset = (*pos & (PAGE_CACHE_SIZE - 1));
		bytes = PAGE_CACHE_SIZE - offset;
		if (bytes > count_tmp)
			bytes = count_tmp;

		ret = mapping->a_ops->write_begin(file, mapping, *pos, bytes,
				AOP_FLAG_UNINTERRUPTIBLE | AOP_FLAG_NOFS,
				&pageP, &fsdata);
		if (unlikely(ret)) {
			err = ret;
			/* -ENOSPC:No space left on device maybe happen */
			ret = qnap_mapping_write_end_all(file, mapping, rv_cb,
					*pageAllocated);
			goto done;
		}
		qnap_setup_rvcb(&rv_cb[*pageAllocated], pageP, *pos, bytes, fsdata);
		qnap_setup_iov(&iov[*pageAllocated], pageP, offset, bytes);

		*pageAllocated = *pageAllocated + 1;
		count_tmp -= bytes;
		*pos += bytes;
	} while (count_tmp);

done:
	return err;
}

static int qnap_is_fs_almost_full(struct file* file)
{
#define FULL_THRESHOLD (1024 * 1024 * 1024) /* 1GB */
	int err;
	struct kstatfs statfs_buf;

	err = vfs_statfs(&file->f_path, &statfs_buf);
	if (err)
		return 0;
	if (statfs_buf.f_bsize * statfs_buf.f_bavail < FULL_THRESHOLD)
		return 1;

	return 0;
}

/* Patched by QNAP for enhancing performance */
static ssize_t qnap_do_splice_from_socket(struct file *file,
		struct socket *sock, loff_t __user *ppos, size_t count)
{
	struct address_space *mapping;
	struct inode *inode;
	loff_t pos;
	int err = 0;
	int cPagesAllocated = 0;
	RCV_FILE_CB *rv_cb = NULL;
	struct kvec *iov = NULL;
	struct msghdr msg;
	long rcvtimeo;
	int ret;
	T_INODE_INFO  i_info;

	if (!file)
		return -EBADF;

	mapping = file->f_mapping;
	inode = mapping->host;

	if (S_ISFIFO(inode->i_mode))
		return -EINTR;
	if (copy_from_user(&pos, ppos, sizeof(loff_t)))
		return -EFAULT;
	if (count > MAX_PAGES_PER_RECVFILE * PAGE_SIZE)
		return -EINVAL;
	if (qnap_is_fs_almost_full(file))
		return -EINTR;

	mutex_lock(&inode->i_mutex);

	rv_cb = (RCV_FILE_CB *) qnap_mempool_alloc(rcv_pools);
	iov = (struct kvec *) qnap_mempool_alloc(kvec_pools);
	if (!rv_cb | !iov) {
		err = -ENOMEM;
		goto done;
	}

	err = qnap_splice_to_file_prepare(file, &pos, &count, rv_cb, iov,
			&cPagesAllocated);
	if (err || count == 0)
		goto done;

	/* IOV is ready, receive the date from socket now */
	memset(&msg, 0, sizeof(msg));
	msg.msg_flags = MSG_KERNSPACE;
	rcvtimeo = sock->sk->sk_rcvtimeo;
	sock->sk->sk_rcvtimeo = 3 * HZ;
	ret = kernel_recvmsg(sock, &msg, iov, cPagesAllocated, count,
			MSG_WAITALL | MSG_NOCATCHSIGNAL);
	sock->sk->sk_rcvtimeo = rcvtimeo;

	if (file && file->f_path.dentry)
		QNAP_FN_GET_INODE_INFO(file->f_path.dentry->d_inode, &i_info);

	if (unlikely(ret < 0)) {
		err = ret;
		ret = qnap_mapping_write_end_all(file, mapping, rv_cb,
				cPagesAllocated);
		goto done;
	} else {
		err = 0;
		pos = pos - count + ret;
		count = ret;
	}

	ret = qnap_mapping_write_end_all(file, mapping, rv_cb, cPagesAllocated);
	balance_dirty_pages_ratelimited(mapping);
	ret = copy_to_user(ppos, &pos, sizeof(loff_t));
	qnap_fnotify_write_notify(&file->f_path, &i_info, (long) count, pos);
done:
	current->backing_dev_info = NULL;
	mutex_unlock(&inode->i_mutex);
	if (rv_cb)
		qnap_mempool_free((void *) rv_cb, rcv_pools);
	if (iov)
		qnap_mempool_free((void *) iov, kvec_pools);
	if (err)
		return err;
	else
		return count;
}

#ifdef QNAP_DEDUPE
ssize_t QNAP_splice_write_from_socket(struct file *file,
		struct socket *sock, loff_t __user *ppos, size_t count)
{
	return qnap_do_splice_from_socket(file, sock, ppos, count);
}
EXPORT_SYMBOL(QNAP_splice_write_from_socket);
#endif

/*
 * Attempt to initiate a splice from a file to a pipe.
 */
static long do_splice_to(struct file *in, loff_t *ppos,
			 struct pipe_inode_info *pipe, size_t len,
			 unsigned int flags)
{
	ssize_t (*splice_read)(struct file *, loff_t *,
			       struct pipe_inode_info *, size_t, unsigned int);
	int ret;

	if (unlikely(!(in->f_mode & FMODE_READ)))
		return -EBADF;

	ret = rw_verify_area(READ, in, ppos, len);
	if (unlikely(ret < 0))
		return ret;

	if (in->f_op->splice_read)
		splice_read = in->f_op->splice_read;
	else
		splice_read = default_file_splice_read;

	return splice_read(in, ppos, pipe, len, flags);
}

#ifdef QNAP_DEDUPE
long QNAP_do_splice_to(struct file *in, loff_t *ppos,
		struct pipe_inode_info *pipe, size_t len, unsigned int flags)
{
	return do_splice_to(in, ppos, pipe, len, flags);
}
EXPORT_SYMBOL(QNAP_do_splice_to);
#endif

/**
 * splice_direct_to_actor - splices data directly between two non-pipes
 * @in:		file to splice from
 * @sd:		actor information on where to splice to
 * @actor:	handles the data splicing
 *
 * Description:
 *    This is a special case helper to splice directly between two
 *    points, without requiring an explicit pipe. Internally an allocated
 *    pipe is cached in the process, and reused during the lifetime of
 *    that process.
 *
 */
ssize_t splice_direct_to_actor(struct file *in, struct splice_desc *sd,
			       splice_direct_actor *actor)
{
	struct pipe_inode_info *pipe;
	long ret, bytes;
	umode_t i_mode;
	size_t len;
	int i, flags, more;

	/*
	 * We require the input being a regular file, as we don't want to
	 * randomly drop data for eg socket -> socket splicing. Use the
	 * piped splicing for that!
	 */
	i_mode = file_inode(in)->i_mode;
	if (unlikely(!S_ISREG(i_mode) && !S_ISBLK(i_mode)))
		return -EINVAL;

	/*
	 * neither in nor out is a pipe, setup an internal pipe attached to
	 * 'out' and transfer the wanted data from 'in' to 'out' through that
	 */
	pipe = current->splice_pipe;
	if (unlikely(!pipe)) {
		pipe = alloc_pipe_info();
		if (!pipe)
			return -ENOMEM;

		/*
		 * We don't have an immediate reader, but we'll read the stuff
		 * out of the pipe right after the splice_to_pipe(). So set
		 * PIPE_READERS appropriately.
		 */
		pipe->readers = 1;

		current->splice_pipe = pipe;
	}

	/*
	 * Do the splice.
	 */
	ret = 0;
	bytes = 0;
	len = sd->total_len;
	flags = sd->flags;

	/*
	 * Don't block on output, we have to drain the direct pipe.
	 */
	sd->flags &= ~SPLICE_F_NONBLOCK;
	more = sd->flags & SPLICE_F_MORE;

	while (len) {
		size_t read_len;
		loff_t pos = sd->pos, prev_pos = pos;

		ret = do_splice_to(in, &pos, pipe, len, flags);
		if (unlikely(ret <= 0))
			goto out_release;

		read_len = ret;
		sd->total_len = read_len;

		/*
		 * If more data is pending, set SPLICE_F_MORE
		 * If this is the last data and SPLICE_F_MORE was not set
		 * initially, clears it.
		 */
		if (read_len < len)
			sd->flags |= SPLICE_F_MORE;
		else if (!more)
			sd->flags &= ~SPLICE_F_MORE;
		/*
		 * NOTE: nonblocking mode only applies to the input. We
		 * must not do the output in nonblocking mode as then we
		 * could get stuck data in the internal pipe:
		 */
		ret = actor(pipe, sd);
		if (unlikely(ret <= 0)) {
			sd->pos = prev_pos;
			goto out_release;
		}

		bytes += ret;
		len -= ret;
		sd->pos = pos;

		if (ret < read_len) {
			sd->pos = prev_pos + ret;
			goto out_release;
		}
	}

done:
	pipe->nrbufs = pipe->curbuf = 0;
	file_accessed(in);
	return bytes;

out_release:
	/*
	 * If we did an incomplete transfer we must release
	 * the pipe buffers in question:
	 */
	for (i = 0; i < pipe->buffers; i++) {
		struct pipe_buffer *buf = pipe->bufs + i;

		if (buf->ops) {
			buf->ops->release(pipe, buf);
			buf->ops = NULL;
		}
	}

	if (!bytes)
		bytes = ret;

	goto done;
}
EXPORT_SYMBOL(splice_direct_to_actor);

static int direct_splice_actor(struct pipe_inode_info *pipe,
			       struct splice_desc *sd)
{
	struct file *file = sd->u.file;

	return do_splice_from(pipe, file, sd->opos, sd->total_len,
			      sd->flags);
}

static inline size_t align_floor(size_t pos)
{
	return pos & ~((size_t)THIN_BLOCK_BYTES - 1);
}

static size_t unaligned(size_t pos)
{
	return pos - align_floor(pos);
}

static inline size_t align_ceil(size_t pos)
{
	size_t tail = unaligned(pos);

	return tail ? pos + THIN_BLOCK_BYTES - tail : pos;
}

struct thin_clone_job {
	atomic_t error;
	struct completion finish;
};

static void thin_clone_cb(int err_code, THIN_BLOCKCLONE_DESC *desc)
{
	struct thin_clone_job *cjob = desc->private_data;

	complete(&cjob->finish);
	if (err_code)
		atomic_set(&cjob->error, 1);
}

#define SECTOR_SHIFT 9

static int get_extents_info(struct file *in, struct fiemap_extent_info *fieinfo, u64 start, u64 len)
{
	int error;
	struct inode *inode = file_inode(in);
	struct fiemap_extent *map;
	size_t map_shift;

	error = fiemap_check_ranges(inode->i_sb, start, len, &len);
	if (error)
		return error;

	if (fieinfo->fi_flags & FIEMAP_FLAG_SYNC)
		filemap_write_and_wait(inode->i_mapping);

	error = inode->i_op->fiemap(inode, fieinfo, start, len);
	if (error < 0)
		return error;

	map = fieinfo->kfi_extents_start;
	map_shift = max(start, map->fe_logical) - map->fe_logical;

	/* Patch the extent if if does not fit our sendfile request */
	map->fe_logical += map_shift;
	map->fe_physical += map_shift;
	map->fe_length -= map_shift;

	return error;
}

static ssize_t do_thin_clone(struct file *in, u64 in_poff, struct file *out,
                             loff_t out_loff, size_t len, size_t *not_aligned)
{
	long fallocb;
	int ret, mode = FALLOC_FL_NO_HIDE_STALE;
	unsigned long block_size = THIN_BLOCK_BYTES;
	THIN_BLOCKCLONE_DESC desc;
	struct thin_clone_job cjob;
	struct fiemap_extent map;
	struct fiemap_extent_info einfo = {0, };

	atomic_set(&cjob.error, 0);
	init_completion(&cjob.finish);

	fallocb = out->f_op->fallocate(out, mode, out_loff, len);
	if (fallocb <= 0) {
		pr_err("%s: fallocate failed, err_code = %ld\n", __func__, fallocb);
		return fallocb ? fallocb : -EINVAL;
	}

	fallocb <<= file_inode(out)->i_blkbits;

	einfo.fi_extents_max = 1;
	einfo.kfi_extents_start = &map;
	einfo.fi_flags = FIEMAP_FLAG_SYNC | FIEMAP_FLAG_KERNEL;
	memset(&map, 0, sizeof(struct fiemap_extent));
	ret = get_extents_info(out, &einfo, out_loff, fallocb);
	if (ret < 0) {
		pr_err("%s: get extents info failed, err: %d\n", __func__, ret);
		return -EINVAL;
	}

	/*
	 * FIXME: this should never happen, only precaution
	 */
	if (map.fe_length != fallocb)
		return -EINVAL;

	/*
	 * There are three conditions which we cannot do fast block cloning
	 * 1. target extent unaligned to thin block
	 * 2. aligned extent length is 0 (This could be a subset to the first condition)
	 * 3. target extent allows no clone
	 */
	if (unaligned(map.fe_physical) ||
		!align_floor(map.fe_length) ||
		map.fe_flags & FIEMAP_EXTENT_NO_CLONE) {
		*not_aligned = align_ceil(map.fe_length);
		return 0;
	}

	/* for unaligned tail of extent, we direct splice it */
	*not_aligned = align_ceil(unaligned(map.fe_length));

	/* Construct THIN_BLOCKCLONE_DESC descriptor */
	desc.src_dev = file_inode(in)->i_sb->s_bdev;
	desc.src_block_addr = in_poff >> SECTOR_SHIFT;
	desc.dest_dev = file_inode(out)->i_sb->s_bdev;
	desc.dest_block_addr = map.fe_physical >> SECTOR_SHIFT;
	desc.transfer_blocks = align_floor(map.fe_length) >> SECTOR_SHIFT;
	desc.private_data = &cjob;

	//pr_err("%s: issue clone from block %llu -> %llu : %llu\n", __func__, desc.src_block_addr, desc.dest_block_addr, desc.transfer_blocks);
	if (thin_support_block_cloning(&desc, &block_size))
		return -EINVAL;

	if (thin_do_block_cloning(&desc, thin_clone_cb))
		return -EINVAL;

	wait_for_completion(&cjob.finish);

	return atomic_read(&cjob.error) ? -EIO : align_floor(map.fe_length);
}

static inline bool support_fiemap(struct file *in)
{
	struct inode *inode = file_inode(in);

	return (!inode->i_op->fiemap) ? false : true;
}

/**
 * do_splice_direct - splices data directly between two files
 * @in:		file to splice from
 * @ppos:	input file offset
 * @out:	file to splice to
 * @opos:	output file offset
 * @len:	number of bytes to splice
 * @flags:	splice modifier flags
 *
 * Description:
 *    For use by do_sendfile(). splice can easily emulate sendfile, but
 *    doing it in the application would incur an extra system call
 *    (splice in + splice out, as compared to just sendfile()). So this helper
 *    can splice directly through a process-private pipe.
 *
 */
long do_splice_direct(struct file *in, loff_t *ppos, struct file *out,
		      loff_t *opos, size_t len, unsigned int flags)
{
	struct splice_desc sd = {
		.len		= len,
		.total_len	= len,
		.flags		= flags,
		.pos		= *ppos,
		.u.file		= out,
		.opos		= opos,
	};
	long ret;

	if (unlikely(!(out->f_mode & FMODE_WRITE)))
		return -EBADF;

	if (unlikely(out->f_flags & O_APPEND))
		return -EINVAL;

	ret = rw_verify_area(WRITE, out, opos, len);
	if (unlikely(ret < 0))
		return ret;

	ret = splice_direct_to_actor(in, &sd, direct_splice_actor);
	if (ret > 0)
		*ppos = sd.pos;

	return ret;
}
EXPORT_SYMBOL(do_splice_direct);

long do_splice_clone(struct file *in, loff_t *ppos, struct file *out,
                     loff_t *opos, size_t len, unsigned int flags)
{
	long ret;
	ssize_t shift = *opos - *ppos;
	struct fiemap_extent_info einfo;
	loff_t start = *ppos, end = *ppos + len, in_size = i_size_read(in->f_inode);
	size_t bypass;

	if (!out->f_op->fallocate || !support_fiemap(in) || start >= in_size)
		return do_splice_direct(in, ppos, out, opos, len, flags);

	if (unlikely(!(out->f_mode & FMODE_WRITE)))
		return -EBADF;

	if (unlikely(out->f_flags & O_APPEND))
		return -EINVAL;

	ret = rw_verify_area(WRITE, out, opos, len);
	if (unlikely(ret < 0))
		return ret;

	einfo.fi_flags = FIEMAP_FLAG_SYNC | FIEMAP_FLAG_KERNEL;
	einfo.fi_extents_max = 10;
	einfo.kfi_extents_start = kmalloc(einfo.fi_extents_max * sizeof(struct fiemap_extent), GFP_KERNEL);
	if (!einfo.kfi_extents_start)
		return do_splice_direct(in, ppos, out, opos, len, flags);

	while (*ppos < end)	{
		int i;
		size_t to_be_done;
		struct fiemap_extent *map;

		/* First, let's get the extent info of target file */
		einfo.fi_extents_mapped = 0;
		memset(einfo.kfi_extents_start, 0, einfo.fi_extents_max * sizeof(struct fiemap_extent));
		ret = get_extents_info(in, &einfo, *ppos, len - (*ppos - start));
		if (ret < 0) {
			kfree(einfo.kfi_extents_start);
			return do_splice_direct(in, ppos, out, opos, len - (*ppos - start), flags);
		}

		/* FAST CASE: This is a hole */
		if (!einfo.fi_extents_mapped) {
			/* We never go beyond input file size */
			*ppos = min((loff_t)(start + len), in_size);
			*opos = *ppos + shift;
			return *ppos - start;
		}

		/* Deal with each extents */
		for (i = 0; i < einfo.fi_extents_mapped; i++) {
			map = einfo.kfi_extents_start + i;

			/* align input and output file's pointer to appropriate position */
			*ppos = map->fe_logical;
			*opos = *ppos + shift;
			to_be_done = min(map->fe_length, (__u64)(end - *ppos));

			if (to_be_done < THIN_BLOCK_BYTES ||
				map->fe_flags & FIEMAP_EXTENT_NO_CLONE)
				goto fallback;

			if (map->fe_flags & FIEMAP_EXTENT_UNWRITTEN) {
				/* normal fallocate, will always make it up to to_be_done */
				ret = out->f_op->fallocate(out, 0, *opos, to_be_done);
				if (!ret) {
					*ppos += to_be_done;
					*opos += to_be_done;
					ret = to_be_done;
					continue;
				} else {
					pr_err("%s: fallocate failed for copying unwritten extents, err: %lx\n", __func__, ret);
					goto fallback;
				}
			}

			bypass = unaligned(map->fe_physical) ?
					 THIN_BLOCK_BYTES - unaligned(map->fe_physical) : 0;

			while (to_be_done - bypass >= THIN_BLOCK_BYTES) {
				/*
				 * Fallback to splice_direct for the front part of this
				 * extent which does not align to thin block size.
				 */
				if (bypass) {
					ret = do_splice_direct(in, ppos, out, opos, bypass, flags);
					if (ret > 0 && ret == bypass)
						to_be_done -= ret;
					else {
						pr_err("%s: direct splice failed\n", __func__);
						goto err_out;
					}
				}

				ret = do_thin_clone(in, map->fe_physical + (*ppos - map->fe_logical),
				                    out, *opos, align_floor(to_be_done), &bypass);
				if (ret >= 0) {
					*ppos += ret;
					*opos += ret;
					to_be_done -= ret;
				} else {
					//printk(KERN_ERR "Cannot do thin fast cloning, fallback to direct splicing, ret: %ld\n", ret);
					break;
				}
			}
fallback:
			/* Fall back to direct splicing */
			if (to_be_done) {
				ret = do_splice_direct(in, ppos, out, opos, to_be_done, flags);
				if (ret > 0 && ret == to_be_done)
					continue;
				else {
					printk(KERN_ERR "%s: direct splice return error, ret: %ld\n", __func__, ret);
					goto err_out;
				}
			}
		}
	}
err_out:
	kfree(einfo.kfi_extents_start);
	return ret <= 0 ? ret : *ppos - start;
}

static int splice_pipe_to_pipe(struct pipe_inode_info *ipipe,
                               struct pipe_inode_info *opipe,
			       size_t len, unsigned int flags);

static void qnap_fnotify_read_notify(struct path *path, T_INODE_INFO *i_info,
		long ret, loff_t offset)
{
#ifdef CONFIG_QND_FNOTIFY_MODULE
	if (QNAP_FN_IS_NOTIFY(FN_READ))
		qnap_sys_file_notify(FN_READ, MARG_2xI64, path, NULL, 0,
			i_info, ret, offset-ret, ARG_PADDING, ARG_PADDING);
#endif
}

/*
 * Determine where to splice to/from.
 */
static long do_splice(struct file *in, loff_t __user *off_in,
		      struct file *out, loff_t __user *off_out,
		      size_t len, unsigned int flags)
{
	struct pipe_inode_info *ipipe;
	struct pipe_inode_info *opipe;
	loff_t offset;
	long ret;
	T_INODE_INFO i_info;

	ipipe = get_pipe_info(in);
	opipe = get_pipe_info(out);

	if (ipipe && opipe) {
		if (off_in || off_out)
			return -ESPIPE;

		if (!(in->f_mode & FMODE_READ))
			return -EBADF;

		if (!(out->f_mode & FMODE_WRITE))
			return -EBADF;

		/* Splicing to self would be fun, but... */
		if (ipipe == opipe)
			return -EINVAL;

		return splice_pipe_to_pipe(ipipe, opipe, len, flags);
	}

	if (ipipe) {
		if (off_in)
			return -ESPIPE;
		if (off_out) {
			if (!(out->f_mode & FMODE_PWRITE))
				return -EINVAL;
			if (copy_from_user(&offset, off_out, sizeof(loff_t)))
				return -EFAULT;
		} else {
			offset = out->f_pos;
		}

		if (unlikely(!(out->f_mode & FMODE_WRITE)))
			return -EBADF;

		if (unlikely(out->f_flags & O_APPEND))
			return -EINVAL;

		ret = rw_verify_area(WRITE, out, &offset, len);
		if (unlikely(ret < 0))
			return ret;

		if (out && out->f_path.dentry)
			QNAP_FN_GET_INODE_INFO(out->f_path.dentry->d_inode,
					&i_info);
		file_start_write(out);
		ret = do_splice_from(ipipe, out, &offset, len, flags);
		file_end_write(out);
		if ((ret > 0) && out)
			qnap_fnotify_write_notify(&out->f_path, &i_info, len,
					offset);

		if (!off_out)
			out->f_pos = offset;
		else if (copy_to_user(off_out, &offset, sizeof(loff_t)))
			ret = -EFAULT;

		return ret;
	}

	if (opipe) {
		if (off_out)
			return -ESPIPE;
		if (off_in) {
			if (!(in->f_mode & FMODE_PREAD))
				return -EINVAL;
			if (copy_from_user(&offset, off_in, sizeof(loff_t)))
				return -EFAULT;
		} else {
			offset = in->f_pos;
		}

		if (in && in->f_path.dentry)
			QNAP_FN_GET_INODE_INFO(in->f_path.dentry->d_inode,
					&i_info);
		ret = do_splice_to(in, &offset, opipe, len, flags);
		if ((ret > 0) && in)
			qnap_fnotify_read_notify(&in->f_path, &i_info, len,
					offset);
		if (!off_in)
			in->f_pos = offset;
		else if (copy_to_user(off_in, &offset, sizeof(loff_t)))
			ret = -EFAULT;

		return ret;
	}

	return -EINVAL;
}

/*
 * Map an iov into an array of pages and offset/length tupples. With the
 * partial_page structure, we can map several non-contiguous ranges into
 * our ones pages[] map instead of splitting that operation into pieces.
 * Could easily be exported as a generic helper for other users, in which
 * case one would probably want to add a 'max_nr_pages' parameter as well.
 */
static int get_iovec_page_array(const struct iovec __user *iov,
				unsigned int nr_vecs, struct page **pages,
				struct partial_page *partial, bool aligned,
				unsigned int pipe_buffers)
{
	int buffers = 0, error = 0;

	while (nr_vecs) {
		unsigned long off, npages;
		struct iovec entry;
		void __user *base;
		size_t len;
		int i;

		error = -EFAULT;
		if (copy_from_user(&entry, iov, sizeof(entry)))
			break;

		base = entry.iov_base;
		len = entry.iov_len;

		/*
		 * Sanity check this iovec. 0 read succeeds.
		 */
		error = 0;
		if (unlikely(!len))
			break;
		error = -EFAULT;
		if (!access_ok(VERIFY_READ, base, len))
			break;

		/*
		 * Get this base offset and number of pages, then map
		 * in the user pages.
		 */
		off = (unsigned long) base & ~PAGE_MASK;

		/*
		 * If asked for alignment, the offset must be zero and the
		 * length a multiple of the PAGE_SIZE.
		 */
		error = -EINVAL;
		if (aligned && (off || len & ~PAGE_MASK))
			break;

		npages = (off + len + PAGE_SIZE - 1) >> PAGE_SHIFT;
		if (npages > pipe_buffers - buffers)
			npages = pipe_buffers - buffers;

		error = get_user_pages_fast((unsigned long)base, npages,
					0, &pages[buffers]);

		if (unlikely(error <= 0))
			break;

		/*
		 * Fill this contiguous range into the partial page map.
		 */
		for (i = 0; i < error; i++) {
			const int plen = min_t(size_t, len, PAGE_SIZE - off);

			partial[buffers].offset = off;
			partial[buffers].len = plen;

			off = 0;
			len -= plen;
			buffers++;
		}

		/*
		 * We didn't complete this iov, stop here since it probably
		 * means we have to move some of this into a pipe to
		 * be able to continue.
		 */
		if (len)
			break;

		/*
		 * Don't continue if we mapped fewer pages than we asked for,
		 * or if we mapped the max number of pages that we have
		 * room for.
		 */
		if (error < npages || buffers == pipe_buffers)
			break;

		nr_vecs--;
		iov++;
	}

	if (buffers)
		return buffers;

	return error;
}

static int pipe_to_user(struct pipe_inode_info *pipe, struct pipe_buffer *buf,
			struct splice_desc *sd)
{
	int n = copy_page_to_iter(buf->page, buf->offset, sd->len, sd->u.data);
	return n == sd->len ? n : -EFAULT;
}

/*
 * For lack of a better implementation, implement vmsplice() to userspace
 * as a simple copy of the pipes pages to the user iov.
 */
static long vmsplice_to_user(struct file *file, const struct iovec __user *uiov,
			     unsigned long nr_segs, unsigned int flags)
{
	struct pipe_inode_info *pipe;
	struct splice_desc sd;
	long ret;
	struct iovec iovstack[UIO_FASTIOV];
	struct iovec *iov = iovstack;
	struct iov_iter iter;

	pipe = get_pipe_info(file);
	if (!pipe)
		return -EBADF;

	ret = import_iovec(READ, uiov, nr_segs,
			   ARRAY_SIZE(iovstack), &iov, &iter);
	if (ret < 0)
		return ret;

	sd.total_len = iov_iter_count(&iter);
	sd.len = 0;
	sd.flags = flags;
	sd.u.data = &iter;
	sd.pos = 0;

	if (sd.total_len) {
		pipe_lock(pipe);
		ret = __splice_from_pipe(pipe, &sd, pipe_to_user);
		pipe_unlock(pipe);
	}

	kfree(iov);
	return ret;
}

/*
 * vmsplice splices a user address range into a pipe. It can be thought of
 * as splice-from-memory, where the regular splice is splice-from-file (or
 * to file). In both cases the output is a pipe, naturally.
 */
static long vmsplice_to_pipe(struct file *file, const struct iovec __user *iov,
			     unsigned long nr_segs, unsigned int flags)
{
	struct pipe_inode_info *pipe;
	struct page *pages[PIPE_DEF_BUFFERS];
	struct partial_page partial[PIPE_DEF_BUFFERS];
	struct splice_pipe_desc spd = {
		.pages = pages,
		.partial = partial,
		.nr_pages_max = PIPE_DEF_BUFFERS,
		.flags = flags,
		.ops = &user_page_pipe_buf_ops,
		.spd_release = spd_release_page,
	};
	long ret;

	pipe = get_pipe_info(file);
	if (!pipe)
		return -EBADF;

	if (splice_grow_spd(pipe, &spd))
		return -ENOMEM;

	spd.nr_pages = get_iovec_page_array(iov, nr_segs, spd.pages,
					    spd.partial, false,
					    spd.nr_pages_max);
	if (spd.nr_pages <= 0)
		ret = spd.nr_pages;
	else
		ret = splice_to_pipe(pipe, &spd);

	splice_shrink_spd(&spd);
	return ret;
}

/*
 * Note that vmsplice only really supports true splicing _from_ user memory
 * to a pipe, not the other way around. Splicing from user memory is a simple
 * operation that can be supported without any funky alignment restrictions
 * or nasty vm tricks. We simply map in the user memory and fill them into
 * a pipe. The reverse isn't quite as easy, though. There are two possible
 * solutions for that:
 *
 *	- memcpy() the data internally, at which point we might as well just
 *	  do a regular read() on the buffer anyway.
 *	- Lots of nasty vm tricks, that are neither fast nor flexible (it
 *	  has restriction limitations on both ends of the pipe).
 *
 * Currently we punt and implement it as a normal copy, see pipe_to_user().
 *
 */
SYSCALL_DEFINE4(vmsplice, int, fd, const struct iovec __user *, iov,
		unsigned long, nr_segs, unsigned int, flags)
{
	struct fd f;
	long error;

	if (unlikely(nr_segs > UIO_MAXIOV))
		return -EINVAL;
	else if (unlikely(!nr_segs))
		return 0;

	error = -EBADF;
	f = fdget(fd);
	if (f.file) {
		if (f.file->f_mode & FMODE_WRITE)
			error = vmsplice_to_pipe(f.file, iov, nr_segs, flags);
		else if (f.file->f_mode & FMODE_READ)
			error = vmsplice_to_user(f.file, iov, nr_segs, flags);

		fdput(f);
	}

	return error;
}

#ifdef CONFIG_COMPAT
COMPAT_SYSCALL_DEFINE4(vmsplice, int, fd, const struct compat_iovec __user *, iov32,
		    unsigned int, nr_segs, unsigned int, flags)
{
	unsigned i;
	struct iovec __user *iov;
	if (nr_segs > UIO_MAXIOV)
		return -EINVAL;
	iov = compat_alloc_user_space(nr_segs * sizeof(struct iovec));
	for (i = 0; i < nr_segs; i++) {
		struct compat_iovec v;
		if (get_user(v.iov_base, &iov32[i].iov_base) ||
		    get_user(v.iov_len, &iov32[i].iov_len) ||
		    put_user(compat_ptr(v.iov_base), &iov[i].iov_base) ||
		    put_user(v.iov_len, &iov[i].iov_len))
			return -EFAULT;
	}
	return sys_vmsplice(fd, iov, nr_segs, flags);
}
#endif

/* Patched by QNAP for enhancing performance */
static long qnap_splice(int fd_in, int fd_out, loff_t __user *off_out,
		size_t len, long err, bool *back_to_linux_route)
{
	long error = err;
	struct socket *sock = NULL;
	struct fd out;

	/* check fd_in is socket fd */
	sock = sockfd_lookup(fd_in, (int *) &error);
	if (sock) {
		*back_to_linux_route = false;
		if (!sock->sk)
			goto no_socket;

		out = fdget(fd_out);
		if (!out.file)
			goto done;

		if (!(out.file->f_mode & FMODE_WRITE))
			goto done;
#ifdef QNAP_DEDUPE
		if (out.file->f_op && out.file->f_op->splice_write_from_socket)
			error = out.file->f_op->splice_write_from_socket(
					out.file, sock, off_out, len);
		else
			error = qnap_do_splice_from_socket(out.file, sock,
					off_out, len);
#else
		error = qnap_do_splice_from_socket(out.file, sock,
				off_out, len);
#endif
		if (error == -EINTR)
			*back_to_linux_route = true;
done:
		if (out.file)
			fdput(out);
no_socket:
		fput(sock->file);
	}
	return error;
}

SYSCALL_DEFINE6(splice, int, fd_in, loff_t __user *, off_in,
		int, fd_out, loff_t __user *, off_out,
		size_t, len, unsigned int, flags)
{
	struct fd in, out;
	long error;
	bool back_to_linux_route = true;

	if (unlikely(!len))
		return 0;

	error = -EBADF;
	/* Patched by QNAP for enhancing performance */
	error = qnap_splice(fd_in, fd_out, off_out, len, error,
				&back_to_linux_route);
	if (!back_to_linux_route)
		return error;

	in = fdget(fd_in);
	if (in.file) {
		if (in.file->f_mode & FMODE_READ) {
			out = fdget(fd_out);
			if (out.file) {
				if (out.file->f_mode & FMODE_WRITE)
					error = do_splice(in.file, off_in,
							  out.file, off_out,
							  len, flags);
				fdput(out);
			}
		}
		fdput(in);
	}
	return error;
}

/*
 * Make sure there's data to read. Wait for input if we can, otherwise
 * return an appropriate error.
 */
static int ipipe_prep(struct pipe_inode_info *pipe, unsigned int flags)
{
	int ret;

	/*
	 * Check ->nrbufs without the inode lock first. This function
	 * is speculative anyways, so missing one is ok.
	 */
	if (pipe->nrbufs)
		return 0;

	ret = 0;
	pipe_lock(pipe);

	while (!pipe->nrbufs) {
		if (signal_pending(current)) {
			ret = -ERESTARTSYS;
			break;
		}
		if (!pipe->writers)
			break;
		if (!pipe->waiting_writers) {
			if (flags & SPLICE_F_NONBLOCK) {
				ret = -EAGAIN;
				break;
			}
		}
		pipe_wait(pipe);
	}

	pipe_unlock(pipe);
	return ret;
}

/*
 * Make sure there's writeable room. Wait for room if we can, otherwise
 * return an appropriate error.
 */
static int opipe_prep(struct pipe_inode_info *pipe, unsigned int flags)
{
	int ret;

	/*
	 * Check ->nrbufs without the inode lock first. This function
	 * is speculative anyways, so missing one is ok.
	 */
	if (pipe->nrbufs < pipe->buffers)
		return 0;

	ret = 0;
	pipe_lock(pipe);

	while (pipe->nrbufs >= pipe->buffers) {
		if (!pipe->readers) {
			send_sig(SIGPIPE, current, 0);
			ret = -EPIPE;
			break;
		}
		if (flags & SPLICE_F_NONBLOCK) {
			ret = -EAGAIN;
			break;
		}
		if (signal_pending(current)) {
			ret = -ERESTARTSYS;
			break;
		}
		pipe->waiting_writers++;
		pipe_wait(pipe);
		pipe->waiting_writers--;
	}

	pipe_unlock(pipe);
	return ret;
}

/*
 * Splice contents of ipipe to opipe.
 */
static int splice_pipe_to_pipe(struct pipe_inode_info *ipipe,
			       struct pipe_inode_info *opipe,
			       size_t len, unsigned int flags)
{
	struct pipe_buffer *ibuf, *obuf;
	int ret = 0, nbuf;
	bool input_wakeup = false;


retry:
	ret = ipipe_prep(ipipe, flags);
	if (ret)
		return ret;

	ret = opipe_prep(opipe, flags);
	if (ret)
		return ret;

	/*
	 * Potential ABBA deadlock, work around it by ordering lock
	 * grabbing by pipe info address. Otherwise two different processes
	 * could deadlock (one doing tee from A -> B, the other from B -> A).
	 */
	pipe_double_lock(ipipe, opipe);

	do {
		if (!opipe->readers) {
			send_sig(SIGPIPE, current, 0);
			if (!ret)
				ret = -EPIPE;
			break;
		}

		if (!ipipe->nrbufs && !ipipe->writers)
			break;

		/*
		 * Cannot make any progress, because either the input
		 * pipe is empty or the output pipe is full.
		 */
		if (!ipipe->nrbufs || opipe->nrbufs >= opipe->buffers) {
			/* Already processed some buffers, break */
			if (ret)
				break;

			if (flags & SPLICE_F_NONBLOCK) {
				ret = -EAGAIN;
				break;
			}

			/*
			 * We raced with another reader/writer and haven't
			 * managed to process any buffers.  A zero return
			 * value means EOF, so retry instead.
			 */
			pipe_unlock(ipipe);
			pipe_unlock(opipe);
			goto retry;
		}

		ibuf = ipipe->bufs + ipipe->curbuf;
		nbuf = (opipe->curbuf + opipe->nrbufs) & (opipe->buffers - 1);
		obuf = opipe->bufs + nbuf;

		if (len >= ibuf->len) {
			/*
			 * Simply move the whole buffer from ipipe to opipe
			 */
			*obuf = *ibuf;
			ibuf->ops = NULL;
			opipe->nrbufs++;
			ipipe->curbuf = (ipipe->curbuf + 1) & (ipipe->buffers - 1);
			ipipe->nrbufs--;
			input_wakeup = true;
		} else {
			/*
			 * Get a reference to this pipe buffer,
			 * so we can copy the contents over.
			 */
			ibuf->ops->get(ipipe, ibuf);
			*obuf = *ibuf;

			/*
			 * Don't inherit the gift flag, we need to
			 * prevent multiple steals of this page.
			 */
			obuf->flags &= ~PIPE_BUF_FLAG_GIFT;

			obuf->len = len;
			opipe->nrbufs++;
			ibuf->offset += obuf->len;
			ibuf->len -= obuf->len;
		}
		ret += obuf->len;
		len -= obuf->len;
	} while (len);

	pipe_unlock(ipipe);
	pipe_unlock(opipe);

	/*
	 * If we put data in the output pipe, wakeup any potential readers.
	 */
	if (ret > 0)
		wakeup_pipe_readers(opipe);

	if (input_wakeup)
		wakeup_pipe_writers(ipipe);

	return ret;
}

/*
 * Link contents of ipipe to opipe.
 */
static int link_pipe(struct pipe_inode_info *ipipe,
		     struct pipe_inode_info *opipe,
		     size_t len, unsigned int flags)
{
	struct pipe_buffer *ibuf, *obuf;
	int ret = 0, i = 0, nbuf;

	/*
	 * Potential ABBA deadlock, work around it by ordering lock
	 * grabbing by pipe info address. Otherwise two different processes
	 * could deadlock (one doing tee from A -> B, the other from B -> A).
	 */
	pipe_double_lock(ipipe, opipe);

	do {
		if (!opipe->readers) {
			send_sig(SIGPIPE, current, 0);
			if (!ret)
				ret = -EPIPE;
			break;
		}

		/*
		 * If we have iterated all input buffers or ran out of
		 * output room, break.
		 */
		if (i >= ipipe->nrbufs || opipe->nrbufs >= opipe->buffers)
			break;

		ibuf = ipipe->bufs + ((ipipe->curbuf + i) & (ipipe->buffers-1));
		nbuf = (opipe->curbuf + opipe->nrbufs) & (opipe->buffers - 1);

		/*
		 * Get a reference to this pipe buffer,
		 * so we can copy the contents over.
		 */
		ibuf->ops->get(ipipe, ibuf);

		obuf = opipe->bufs + nbuf;
		*obuf = *ibuf;

		/*
		 * Don't inherit the gift flag, we need to
		 * prevent multiple steals of this page.
		 */
		obuf->flags &= ~PIPE_BUF_FLAG_GIFT;

		if (obuf->len > len)
			obuf->len = len;

		opipe->nrbufs++;
		ret += obuf->len;
		len -= obuf->len;
		i++;
	} while (len);

	/*
	 * return EAGAIN if we have the potential of some data in the
	 * future, otherwise just return 0
	 */
	if (!ret && ipipe->waiting_writers && (flags & SPLICE_F_NONBLOCK))
		ret = -EAGAIN;

	pipe_unlock(ipipe);
	pipe_unlock(opipe);

	/*
	 * If we put data in the output pipe, wakeup any potential readers.
	 */
	if (ret > 0)
		wakeup_pipe_readers(opipe);

	return ret;
}

/*
 * This is a tee(1) implementation that works on pipes. It doesn't copy
 * any data, it simply references the 'in' pages on the 'out' pipe.
 * The 'flags' used are the SPLICE_F_* variants, currently the only
 * applicable one is SPLICE_F_NONBLOCK.
 */
static long do_tee(struct file *in, struct file *out, size_t len,
		   unsigned int flags)
{
	struct pipe_inode_info *ipipe = get_pipe_info(in);
	struct pipe_inode_info *opipe = get_pipe_info(out);
	int ret = -EINVAL;

	/*
	 * Duplicate the contents of ipipe to opipe without actually
	 * copying the data.
	 */
	if (ipipe && opipe && ipipe != opipe) {
		/*
		 * Keep going, unless we encounter an error. The ipipe/opipe
		 * ordering doesn't really matter.
		 */
		ret = ipipe_prep(ipipe, flags);
		if (!ret) {
			ret = opipe_prep(opipe, flags);
			if (!ret)
				ret = link_pipe(ipipe, opipe, len, flags);
		}
	}

	return ret;
}

SYSCALL_DEFINE4(tee, int, fdin, int, fdout, size_t, len, unsigned int, flags)
{
	struct fd in;
	int error;

	if (unlikely(!len))
		return 0;

	error = -EBADF;
	in = fdget(fdin);
	if (in.file) {
		if (in.file->f_mode & FMODE_READ) {
			struct fd out = fdget(fdout);
			if (out.file) {
				if (out.file->f_mode & FMODE_WRITE)
					error = do_tee(in.file, out.file,
							len, flags);
				fdput(out);
			}
		}
 		fdput(in);
 	}

	return error;
}

static int __init qnap_init_splice_pools(void)
{
	rcv_pools = mempool_create(NUM_ENTRY_PER_CPU * num_possible_cpus(),
			mempool_kmalloc, mempool_kfree,
			(void *) (sizeof(RCV_FILE_CB) * (MAX_PAGES_PER_RECVFILE + 1)));
	kvec_pools = mempool_create(NUM_ENTRY_PER_CPU * num_possible_cpus(),
			mempool_kmalloc, mempool_kfree,
			(void *) (sizeof(struct kvec) * (MAX_PAGES_PER_RECVFILE + 1)));

	if (!rcv_pools | !kvec_pools) {
		printk("Cannot allocate mempool for splice\n");
		return -ENOMEM;
	}

	return 0;
}

fs_initcall(qnap_init_splice_pools);
