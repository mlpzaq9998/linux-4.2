#ifndef TARGET_CORE_QFBC_H
#define TARGET_CORE_QFBC_H

#include <linux/fast_clone.h>

#define MAX_FBC_IO      	(64*1024*1024)	/* size per one FBC i/o */
#define FAST_CLONE_TIMEOUT_SEC  4


typedef struct __fast_clone_io_cb_data{
	atomic_t io_done;
	atomic_t io_err_count;
	struct completion *io_wait;

	/* used on thin provisioning case */
	int nospc_err;
} FCCB_DATA;

typedef struct __create_record{
	struct block_device *s_blkdev;
	struct block_device *d_blkdev;
	sector_t s_lba;
	sector_t d_lba;
	u64 transfer_bytes;
} CREATE_REC;

typedef struct __fast_clone_io_rec{
	struct list_head io_node;
	THIN_BLOCKCLONE_DESC desc;

	/* 0: init value , 1: io done w/o error , -1: io done with any error */
	int io_done;
} FCIO_REC;

typedef struct _fast_clone_obj{
	struct se_device	*s_se_dev;
	struct se_device	*d_se_dev;
	sector_t	s_lba;
	sector_t	d_lba;
	u32		s_dev_bs;
	u32		d_dev_bs;
	u64		data_bytes;
	int		nospc_err;
} FC_OBJ;

typedef struct __tbc_desc_data{
	THIN_BLOCKCLONE_DESC tbc_desc;

	/* the unit for lba data bytes listed below is original unit */
	sector_t h_d_lba;	/* head */
	sector_t t_d_lba;	/* tail */

	/* align area */
	sector_t d_align_lba;
	u64 data_bytes;		/* shall be multiple by pool block size */
	int do_fbc;
} TBC_DESC_DATA;

int qnap_transport_check_support_fbc(struct block_device *bd);
void qnap_transport_setup_support_fbc(struct se_device *se_dev);
int qnap_fbc_do_fast_block_clone(struct xcopy_op *xop);


#endif
