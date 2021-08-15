#ifndef __RBD_H
#define __RBD_H

enum rbd_notify_op {
	RBD_NOTIFY_OP_ACQUIRED_LOCK	= 0,
	RBD_NOTIFY_OP_RELEASED_LOCK	= 1,
	RBD_NOTIFY_OP_REQUEST_LOCK	= 2,
	RBD_NOTIFY_OP_HEADER_UPDATE	= 3,
	RBD_NOTIFY_OP_ASYNC_PROGRESS	= 4,
	RBD_NOTIFY_OP_ASYNC_COMPLETE	= 5,
	RBD_NOTIFY_OP_FLATTEN		= 6,
	RBD_NOTIFY_OP_RESIZE		= 7,
	RBD_NOTIFY_OP_SNAP_CREATE	= 8,
	RBD_NOTIFY_OP_SCSI_PR_UPDATE	= 9,
	RBD_NOTIFY_OP_SCSI_LUN_RESET	= 10,
};

struct rbd_device;

/* rbd.c helpers */
void rbd_warn(struct rbd_device *rbd_dev, const char *fmt, ...);
extern int rbd_obj_notify_scsi_event_sync(struct rbd_device *rbd_dev, u32 event,
					  u32 notify_timeout);
int rbd_obj_notify_ack_sync(struct rbd_device *rbd_dev, u64 notify_id);
extern int rbd_attach_tcm_dev(struct rbd_device *rbd_dev, void *data);
extern int rbd_detach_tcm_dev(struct rbd_device *rbd_dev);

#if defined(CONFIG_TCM_IBLOCK) || defined(CONFIG_TCM_IBLOCK_MODULE)

extern void rbd_tcm_reset_notify_handle(void *data, u64 notify_id);
extern int rbd_tcm_register(void);
extern void rbd_tcm_unregister(void);

#else

void rbd_tcm_reset_notify_handle(void *data, u64 notify_id)
{
}

int rbd_tcm_register(void)
{
	return 0;
}

void rbd_tcm_unregister(void)
{
}

#endif /* CONFIG_TARGET_CORE */

#endif /* __RBD_TYPE_H */
