/*******************************************************************************
 * Filename:  iscsi_target_qconfigfs.c
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 ****************************************************************************/
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/list.h>
#include <asm/unaligned.h>

#include <target/target_core_base.h>
#include <target/target_core_backend.h>
#include <target/target_core_fabric.h>
#include <target/iscsi/iscsi_target_core.h>

#if 0
#include "iscsi_target_core.h"
#include "iscsi_target_erl0.h"
#include "iscsi_target_login.h"
#include "iscsi_target_nodeattrib.h"
#include "iscsi_target_tpg.h"
#include "iscsi_target_util.h"
#include "iscsi_target.h"
#include "iscsi_target_parameters.h"
#endif

#include "iscsi_target_qtransport.h"
#include "iscsi_target_qconfigfs.h"


#ifdef CONFIG_MACH_QNAPTS
#ifdef SUPPORT_SINGLE_INIT_LOGIN
/* Jonathan Ho, 20140416,  one target can be logged in from only one initiator IQN */
ssize_t iscsi_stat_tgt_attr_show_attr_cluster_enable(
	struct iscsi_wwn_stat_grps *igrps, char *page)
{
	struct iscsi_tiqn *tiqn = container_of(igrps,
				struct iscsi_tiqn, tiqn_stat_grps);

	return snprintf(page, PAGE_SIZE, "%d\n", tiqn->cluster_enable ? 1 : 0);
}

ssize_t iscsi_stat_tgt_attr_store_attr_cluster_enable(
	struct iscsi_wwn_stat_grps *igrps, const char *page, size_t count)
{
	struct iscsi_tiqn *tiqn = container_of(igrps,
				struct iscsi_tiqn, tiqn_stat_grps);
	char *endptr;
	u32 val;

	val = simple_strtoul(page, &endptr, 0);
	if (val == 0)
		tiqn->cluster_enable = 0;
	else
		tiqn->cluster_enable = 1;

	return count;
}
#endif
#endif


