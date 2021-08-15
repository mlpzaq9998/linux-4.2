#include "md.h"

#if defined(CONFIG_MACH_QNAPTS) && defined(QNAP_HAL)
#include <qnap/hal_event.h>
extern int send_hal_netlink(NETLINK_EVT *event);
#endif

void
qnap_send_raid_hal_event(unsigned int action,
			struct mddev *mddev,
			char *pd_scsi_name,
			char *pd_scsi_spare_name,
	unsigned long long pd_repair_sector);

void
qnap_send_badblock_hal_event(unsigned int action,
			struct md_rdev *rdev,
			sector_t sector,
			int len,
			unsigned int count);
