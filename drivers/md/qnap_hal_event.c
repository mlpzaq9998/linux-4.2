#include "qnap_hal_event.h"

#if defined(CONFIG_MACH_QNAPTS) && defined(QNAP_HAL)

static char *qnap_get_hal_event_action_string(unsigned int action)
{
	switch (action) {

	case REPAIR_RAID_READ_ERROR:
		return "REPAIR_RAID_READ_ERROR";
	case SET_RAID_PD_ERROR:
		return "SET_RAID_PD_ERROR";
	case SET_RAID_RO:
		return "SET_RAID_RO";
	case RESYNCING_START:
		return "RESYNCING_START";
	case RESYNCING_SKIP:
		return "RESYNCING_SKIP";
	case RESYNCING_COMPLETE:
		return "RESYNCING_COMPLETE";
	case REBUILDING_START:
		return "REBUILDING_START";
	case REBUILDING_SKIP:
		return "REBUILDING_SKIP";
	case REBUILDING_COMPLETE:
		return "REBUILDING_COMPLETE";
	case RESHAPING_START:
		return "RESHAPING_START";
	case RESHAPING_SKIP:
		return "RESHAPING_SKIP";
	case RESHAPING_COMPLETE:
		return "RESHAPING_COMPLETE";
	case HOTREPLACING_START:
		return "HOTREPLACING_START";
	case HOTREPLACING_SKIP:
		return "HOTREPLACING_SKIP";
	case HOTREPLACING_COMPLETE:
		return "HOTREPLACING_COMPLETE";
	case RAID_PD_HOTREPLACED:
		return "RAID_PD_HOTREPLACED";
	case BAD_BLOCK_ERROR_DETECT:
		return "BAD_BLOCK_ERROR_DETECT";
	case BAD_BLOCK_ERROR_STRIPE:
		return "BAD_BLOCK_ERROR_STRIPE";
	default:
		return "NULL";
	}
}

void
qnap_send_raid_hal_event(unsigned int action,
			struct mddev *mddev,
			char *pd_scsi_name,
			char *pd_scsi_spare_name,
		unsigned long long pd_repair_sector)
{
	NETLINK_EVT hal_event;
	struct __netlink_raid_cb *nl_raid;
	int ret;

	memset(&hal_event, 0, sizeof(NETLINK_EVT));
	hal_event.type = HAL_EVENT_RAID;

	pr_info("md/raid:%s: report qnap hal event: type = HAL_EVENT_RAID, action = %s\n",
		mdname(mddev), qnap_get_hal_event_action_string(action));

	nl_raid = &(hal_event.arg.param.netlink_raid);

	switch (action) {

	case REPAIR_RAID_READ_ERROR:
	case SET_RAID_PD_ERROR:
	case SET_RAID_RO:
	case RESYNCING_START:
	case RESYNCING_SKIP:
	case RESYNCING_COMPLETE:
	case REBUILDING_START:
	case REBUILDING_SKIP:
	case REBUILDING_COMPLETE:
	case RESHAPING_START:
	case RESHAPING_SKIP:
	case RESHAPING_COMPLETE:
	case HOTREPLACING_START:
	case HOTREPLACING_SKIP:
	case HOTREPLACING_COMPLETE:
	case RAID_PD_HOTREPLACED:

		hal_event.arg.action = action;

		ret = kstrtoint(mdname(mddev) + strlen("md"), 0, &nl_raid->raid_id);
		if (ret)
			return;

		snprintf(nl_raid->pd_scsi_name,
			sizeof(nl_raid->pd_scsi_name),
			"/dev/%s", pd_scsi_name);

		snprintf(nl_raid->pd_scsi_spare_name,
			sizeof(nl_raid->pd_scsi_spare_name),
			"/dev/%s", pd_scsi_spare_name);

		nl_raid->pd_repair_sector = pd_repair_sector;

		pr_info("md/raid:%s: report qnap hal event: raid_id=%d, pd_name=%s, spare=%s, pd_repair_sector=%llu\n",
			mdname(mddev), nl_raid->raid_id, nl_raid->pd_scsi_name,
			nl_raid->pd_scsi_spare_name, nl_raid->pd_repair_sector);

		send_hal_netlink(&hal_event);
	break;

	default:
		pr_err("md/raid:%s: Unknown qnap_raid_hal_event action id=%u\n",
			mdname(mddev), action);
		return;
	}

}

void
qnap_send_badblock_hal_event(unsigned int action,
			struct md_rdev *rdev,
			sector_t sector,
			int len,
			unsigned int count)
{
	NETLINK_EVT hal_event;
	char devname[BDEVNAME_SIZE];
	struct mddev *mddev;
	struct __badblock *bb;
	int ret;

	if (!rdev)
		return;

	mddev = rdev->mddev;
	bdevname(rdev->bdev->bd_contains, devname);
	memset(&hal_event, 0, sizeof(NETLINK_EVT));

	pr_info("md/raid:%s: report qnap hal event: type = HAL_EVENT_RAID, action = %s\n",
		mdname(mddev), qnap_get_hal_event_action_string(action));

	bb = &(hal_event.arg.param.badblock);

	switch (action) {

	case BAD_BLOCK_ERROR_DETECT:
	case BAD_BLOCK_ERROR_STRIPE:

		hal_event.type = HAL_EVENT_RAID;
		hal_event.arg.action = action;
		ret = kstrtoint(mdname(mddev) + strlen("md"), 0, &bb->raid_id);
		if (ret)
			return;

		snprintf(bb->pd_scsi_name, sizeof(bb->pd_scsi_name),
			"/dev/%s", devname);
		bb->first_bad = sector;
		bb->bad_sectors = len;
		bb->count = count;

		pr_info("md/raid:%s: report qnap hal event: pd_name=%s, sector=%llu, len=%llu, count=%u\n",
			mdname(mddev), bb->pd_scsi_name, bb->first_bad,
			bb->bad_sectors, bb->count);

		break;

	default:
		pr_err("md/raid:%s: Unknown qnap_badblock_hal_event action id:%u\n",
				mdname(mddev), action);
		return;
	}

	send_hal_netlink(&hal_event);
}

#else

void
qnap_send_raid_hal_event(unsigned int action,
			struct mddev *mddev,
			char *pd_scsi_name,
			char *pd_scsi_spare_name,
	unsigned long long pd_repair_sector){}

void
qnap_send_badblock_hal_event(unsigned int action,
			struct md_rdev *rdev,
			sector_t sector,
			int len,
			unsigned int count){}
#endif
