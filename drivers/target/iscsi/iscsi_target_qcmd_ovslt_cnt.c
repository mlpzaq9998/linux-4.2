/*******************************************************************************
 * This file contains a stress test features to the iSCSI Target Core Driver.
 *
 * (c) Copyright 2016 QNAP, Inc.
 *
 * Author: WilliamChang <williamchang@qnap.com>
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
 ******************************************************************************/

#include <linux/init.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/configfs.h>
#include <linux/jiffies.h>
#include <linux/delay.h>
#include <linux/random.h>
#include <linux/time.h>
#include <linux/timer.h>
#include <linux/timex.h>
#include <linux/rtc.h>

#include "iscsi_target_qcmd_ovslt_cnt.h"

struct config_group *g_iscsi_cmd_ovslt_cnt_group = NULL;
struct iscsi_cmd_ovslt_cnt_module *g_ovslt_module;

extern void __QNAP_ovslt_mod_get_enable(
  unsigned long (*ovslt_mod_set_func_get_enable)(void));
extern void __QNAP_ovslt_mod_statistics(int (*ovslt_mod_set_func_statistics)
								(unsigned char *cmd_opcode,
								  unsigned long cmd_trasprt_begin_time,
								  unsigned long cmd_trasprt_end_time,
								  struct timex cmd_txc));

static inline struct config_item *to_item(struct list_head *entry)
{
	return container_of(entry, struct config_item, ci_entry);
}

struct iscsi_cmd_ovslt_cnt_group {
	struct config_group group;
	struct iscsi_cmd_ovslt_cnt_cmd cmd_item;
	struct iscsi_cmd_ovslt_cnt_latency latency_item;
};

static inline struct iscsi_cmd_ovslt_cnt_group *to_iscsi_cmd_ovslt_cnt_group(struct config_item *item)
{
	return item ? container_of(to_config_group(item), struct iscsi_cmd_ovslt_cnt_group, group) : NULL;
}

static void init_all_var(void)
{
	int i = 0;

	g_ovslt_module->enable = 0;
	g_ovslt_module->cmd_timeslot_setting = 0;
	g_ovslt_module->cmd_cnt = 0;
	for (i = 0 ; i < MAX_CMD_INFO_SIZE ; i++)
	{
		g_ovslt_module->cmd_info[i].cmd_opcode = 0;
		g_ovslt_module->cmd_info[i].cmd_total_elapsed_time = 0;
		g_ovslt_module->cmd_info[i].cmd_sbc_elapsed_time = 0;
		g_ovslt_module->cmd_info[i].cmd_spc_elapsed_time = 0;
	}
	strcpy(g_ovslt_module->latency_info[READ_6_IDX].cmd_name, "READ_6");
	strcpy(g_ovslt_module->latency_info[READ_10_IDX].cmd_name, "READ_10");
	strcpy(g_ovslt_module->latency_info[READ_12_IDX].cmd_name, "READ_12");
	strcpy(g_ovslt_module->latency_info[READ_16_IDX].cmd_name, "READ_16");
	strcpy(g_ovslt_module->latency_info[READ_32_IDX].cmd_name, "READ_32");
	strcpy(g_ovslt_module->latency_info[WRITE_6_IDX].cmd_name, "WRITE_6");
	strcpy(g_ovslt_module->latency_info[WRITE_10_IDX].cmd_name, "WRITE_10");
	strcpy(g_ovslt_module->latency_info[WRITE_12_IDX].cmd_name, "WRITE_12");
	strcpy(g_ovslt_module->latency_info[WRITE_16_IDX].cmd_name, "WRITE_16");
	strcpy(g_ovslt_module->latency_info[WRITE_32_IDX].cmd_name, "WRITE_32");
	strcpy(g_ovslt_module->latency_info[UNMAP_IDX].cmd_name, "UNMAP");
	strcpy(g_ovslt_module->latency_info[WRITE_SAME_IDX].cmd_name, "WRITE_SAME");
	strcpy(g_ovslt_module->latency_info[WRITE_SAME_16_IDX].cmd_name, "WRITE_SAME_16");
	strcpy(g_ovslt_module->latency_info[WRITE_SAME_32_IDX].cmd_name, "WRITE_SAME_32");
	g_ovslt_module->latency_info[READ_6_IDX].cmd_opcode = READ_6;
	g_ovslt_module->latency_info[READ_10_IDX].cmd_opcode = READ_10;
	g_ovslt_module->latency_info[READ_12_IDX].cmd_opcode = READ_12;
	g_ovslt_module->latency_info[READ_16_IDX].cmd_opcode = READ_16;
	g_ovslt_module->latency_info[READ_32_IDX].cmd_opcode = READ_32;
	g_ovslt_module->latency_info[WRITE_6_IDX].cmd_opcode = WRITE_6;
	g_ovslt_module->latency_info[WRITE_10_IDX].cmd_opcode = WRITE_10;
	g_ovslt_module->latency_info[WRITE_12_IDX].cmd_opcode = WRITE_12;
	g_ovslt_module->latency_info[WRITE_16_IDX].cmd_opcode = WRITE_16;
	g_ovslt_module->latency_info[WRITE_32_IDX].cmd_opcode = WRITE_32;
	g_ovslt_module->latency_info[UNMAP_IDX].cmd_opcode = UNMAP;
	g_ovslt_module->latency_info[WRITE_SAME_IDX].cmd_opcode = WRITE_SAME;
	g_ovslt_module->latency_info[WRITE_SAME_16_IDX].cmd_opcode = WRITE_SAME_16;
	g_ovslt_module->latency_info[WRITE_SAME_32_IDX].cmd_opcode = WRITE_SAME_32;
	for (i = 0 ; i < MAX_LATENCY_INFO_SIZE ; i ++)
	{
		g_ovslt_module->latency_info[i].cmd_ovslt_cnt = 0;
		g_ovslt_module->latency_info[i].cmd_maxlaty = 0;
	}
}

static void iscsi_cmd_ovslt_cnt_dump_parameters(void)
{
	if (g_ovslt_module) {
		pr_info("[ISCSI_CMD_OVSLT_CNT] =========== Dump Test Plan ===========\n");
		pr_info("[ISCSI_CMD_OVSLT_CNT] Enable Settings: 0x%x\n", g_ovslt_module->enable);
		pr_info("[ISCSI_CMD_OVSLT_CNT] Command Timeslot Setting: %lu\n",
		  g_ovslt_module->cmd_timeslot_setting);
		pr_info("[ISCSI_CMD_OVSLT_CNT] ========== End of Dump Test Plan ==========\n");
	} else
		pr_info("[ISCSI_CMD_OVSLT_CNT] Null Item\n");
}

static void iscsi_cmd_ovslt_cnt_dump_cmd_ovslt_cnt_cmd_info(void)
{
	int i;

	if (g_ovslt_module) {
		pr_info("[ISCSI_CMD_OVSLT_CNT] =========== Dump Cmd Records ===========\n");
		for (i = 0 ; i < MAX_CMD_INFO_SIZE ; i++)
		{
			pr_info("Command Record ID: %d\t", i);
			pr_info("Command OPCODE: 0x%x\t", g_ovslt_module->cmd_info[i].cmd_opcode);
			pr_info("Command Total Elapsed Time: %lu\t",
			  g_ovslt_module->cmd_info[i].cmd_total_elapsed_time);
			pr_info("Command SBC Elapsed Time: %lu\t",
			  g_ovslt_module->cmd_info[i].cmd_sbc_elapsed_time);
			pr_info("Command SPC Elapsed Time: %lu\t",
			  g_ovslt_module->cmd_info[i].cmd_spc_elapsed_time);
			pr_info("Command Transport Elapsed Time: %lu\n",
			  g_ovslt_module->cmd_info[i].cmd_trasprt_elapsed_time);
		}
		pr_info("[ISCSI_CMD_OVSLT_CNT] =========== End of Dump Cmd Records ===========\n");
	} else
		pr_info("[ISCSI_CMD_OVSLT_CNT] Null Item\n");
}

static void iscsi_cmd_ovslt_cnt_dump_cmd_ovslt_cnt_latency_info(void)
{
  
	int i;
	struct rtc_time tm;

	if (g_ovslt_module) {
		pr_info("[ISCSI_CMD_OVSLT_CNT] =========== Dump Cmd Ovslot Cnt Latency Info ===========\n");
		for (i = 0 ; i < MAX_LATENCY_INFO_SIZE ; i++)
		{
			rtc_time_to_tm(g_ovslt_module->latency_info[i].cmd_maxlaty_exestatm.time.tv_sec
			  + 28800, &tm);
			pr_info("Command OPCODE: 0x%02x\n", g_ovslt_module->latency_info[i].cmd_opcode);
			pr_info("OverSlotCnt: %d\n", g_ovslt_module->latency_info[i].cmd_ovslt_cnt);
			pr_info("MaxLatency: %lu\n", g_ovslt_module->latency_info[i].cmd_maxlaty);
			pr_info("Maxlatency Start Time: %d-%02d-%02d %02d:%02d:%02d\n",
			  tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, 
			  tm.tm_hour, tm.tm_min, tm.tm_sec);
		}
		pr_info("[ISCSI_CMD_OVSLT_CNT] ========== End of Dump Cmd Ovslot Cnt Latency Info ===========\n");
	} else
		pr_info("[ISCSI_CMD_OVSLT_CNT] Null Item\n");
}

unsigned long iscsi_cmd_ovslt_cnt_exec_get_enable(void)
{
	int ret = 0;
  
	if (!g_ovslt_module)
		return ret;
	else {
		return g_ovslt_module->enable;
	}
}

unsigned long get_cmd_timeslot_setting(void)
{
	int ret = 0;
  
	if (!g_ovslt_module)
		return ret;
	else {
		return g_ovslt_module->cmd_timeslot_setting;
	}
}

int set_cmd_opcode(unsigned char cmd_opcode)
{
	int i, ret = 0;

	if (!g_ovslt_module)
		return ret;

	i = g_ovslt_module->cmd_cnt;
	g_ovslt_module->cmd_info[i].cmd_opcode = cmd_opcode;
	if (++i > MAX_CMD_INFO_SIZE) {
		i = 0;  
	}
	g_ovslt_module->cmd_cnt = i;
	ret = 1;

	return ret;
}

int set_cmd_sbc_elapsed_time(unsigned long cmd_sbc_elapsed_time)
{
	int i, ret = 0;

	if (!g_ovslt_module)
		return ret;

	if (ISCSI_CMD_SBC_OVSLT_CNT_ENABLE(g_ovslt_module->enable)) {
		i = g_ovslt_module->cmd_cnt;
		g_ovslt_module->cmd_info[i].cmd_sbc_elapsed_time = cmd_sbc_elapsed_time;
		pr_debug("[ISCSI_CMD_OVSLT_CNT] %s: cmd_sbc_elapsed_time: %lu\n",
		  __func__,
		  g_ovslt_module->cmd_info[i].cmd_sbc_elapsed_time);
		ret = 1;
	} else {
		pr_debug("[ISCSI_CMD_OVSLT_CNT] %s: Can not set cmd_sbc_elapsed_time\n",
		  __func__);
	}

	return ret;
}

int set_cmd_spc_elapsed_time(unsigned long cmd_spc_elapsed_time)
{
	int i, ret = 0;

	if (!g_ovslt_module)
		return ret;

	if (ISCSI_CMD_SPC_OVSLT_CNT_ENABLE(g_ovslt_module->enable)) {
		i = g_ovslt_module->cmd_cnt;
		g_ovslt_module->cmd_info[i].cmd_spc_elapsed_time = cmd_spc_elapsed_time;
		pr_debug("[ISCSI_CMD_OVSLT_CNT] %s: cmd_spc_elapsed_time: %lu\n",
		  __func__,
		  g_ovslt_module->cmd_info[i].cmd_spc_elapsed_time);
		ret = 1;
	} else {
		pr_debug("[ISCSI_CMD_OVSLT_CNT] %s: Can not set cmd_spc_elapsed_time\n",
		  __func__);
	}

	return ret;
}

int set_cmd_trasprt_elapsed_time(unsigned long cmd_trasprt_elapsed_time)
{
	int i, ret = 0;

	if (!g_ovslt_module)
		return ret;

	if (ISCSI_CMD_TRASPRT_OVSLT_CNT_ENABLE(g_ovslt_module->enable)) {
		i = g_ovslt_module->cmd_cnt;
		g_ovslt_module->cmd_info[i].cmd_trasprt_elapsed_time
			= cmd_trasprt_elapsed_time;
		pr_debug("[ISCSI_CMD_OVSLT_CNT] %s: cmd_trasprt_elapsed_time: %lu\n",
		  __func__,
		  g_ovslt_module->cmd_info[i].cmd_trasprt_elapsed_time);
		ret = 1;
	} else {
		pr_debug("[ISCSI_CMD_OVSLT_CNT] %s: Can not set cmd_trasprt_elapsed_time\n",
		  __func__);
	}

	return ret;
}

int iscsi_cmd_ovslt_cnt_exec_statistics(
	unsigned char *cmd_opcode,
	unsigned long cmd_trasprt_begin_time,
	unsigned long cmd_trasprt_end_time,
	struct timex cmd_txc)
{
	int ret = 0;
	unsigned long cmd_trasprt_elapsed_time = 0;
	
	if (!g_ovslt_module)
		return ret;

	cmd_trasprt_elapsed_time
	  = jiffies_to_msecs(cmd_trasprt_end_time - cmd_trasprt_begin_time);
	if (cmd_trasprt_elapsed_time >=
	  g_ovslt_module->cmd_timeslot_setting) {
		switch (cmd_opcode[0]) {
			case READ_6:
				cal_read_6_cmd_ovslt_cnt();
				if (cmd_trasprt_elapsed_time >=
				  g_ovslt_module->latency_info[READ_6_IDX].cmd_maxlaty) {
					set_read_6_cmd_maxlaty(cmd_trasprt_elapsed_time);
					set_read_6_cmd_maxlaty_exestatm(cmd_txc);
				}
				break;
			case READ_10:
				cal_read_10_cmd_ovslt_cnt();
				if (cmd_trasprt_elapsed_time >=
				  g_ovslt_module->latency_info[READ_10_IDX].cmd_maxlaty) {
					set_read_10_cmd_maxlaty(cmd_trasprt_elapsed_time);
					set_read_10_cmd_maxlaty_exestatm(cmd_txc);
				}
				break;
			case READ_12:
				cal_read_12_cmd_ovslt_cnt();
				if (cmd_trasprt_elapsed_time >=
				  g_ovslt_module->latency_info[READ_12_IDX].cmd_maxlaty) {
					set_read_12_cmd_maxlaty(cmd_trasprt_elapsed_time);
					set_read_12_cmd_maxlaty_exestatm(cmd_txc);
				}
				break;
			case READ_16:
				cal_read_16_cmd_ovslt_cnt();
				if (cmd_trasprt_elapsed_time >=
				  g_ovslt_module->latency_info[READ_16_IDX].cmd_maxlaty) {
					set_read_16_cmd_maxlaty(cmd_trasprt_elapsed_time);
					set_read_16_cmd_maxlaty_exestatm(cmd_txc);
				}
				break;
			case READ_32:
				cal_read_32_cmd_ovslt_cnt();
				if (cmd_trasprt_elapsed_time >=
				  g_ovslt_module->latency_info[READ_32_IDX].cmd_maxlaty) {
					set_read_32_cmd_maxlaty(cmd_trasprt_elapsed_time);
					set_read_32_cmd_maxlaty_exestatm(cmd_txc);
				}
				break;
			case WRITE_6:
				cal_write_6_cmd_ovslt_cnt();
				if (cmd_trasprt_elapsed_time >=
				  g_ovslt_module->latency_info[WRITE_6_IDX].cmd_maxlaty) {
					set_write_6_cmd_maxlaty(cmd_trasprt_elapsed_time);
					set_write_6_cmd_maxlaty_exestatm(cmd_txc);
				}
				break;
			case WRITE_10:
				cal_write_10_cmd_ovslt_cnt();
				if (cmd_trasprt_elapsed_time >=
				  g_ovslt_module->latency_info[WRITE_10_IDX].cmd_maxlaty) {
					set_write_10_cmd_maxlaty(cmd_trasprt_elapsed_time);
					set_write_10_cmd_maxlaty_exestatm(cmd_txc);
				}
				break;
			case WRITE_12:
				cal_write_12_cmd_ovslt_cnt();
				if (cmd_trasprt_elapsed_time >=
				  g_ovslt_module->latency_info[WRITE_12_IDX].cmd_maxlaty) {
					set_write_12_cmd_maxlaty(cmd_trasprt_elapsed_time);
					set_write_12_cmd_maxlaty_exestatm(cmd_txc);
				}
				break;
			case WRITE_16:
				cal_write_16_cmd_ovslt_cnt();
				if (cmd_trasprt_elapsed_time >=
				  g_ovslt_module->latency_info[WRITE_16_IDX].cmd_maxlaty) {
					set_write_16_cmd_maxlaty(cmd_trasprt_elapsed_time);
					set_write_16_cmd_maxlaty_exestatm(cmd_txc);
				}
				break;
			case WRITE_32:
				cal_write_32_cmd_ovslt_cnt();
				if (cmd_trasprt_elapsed_time >=
				  g_ovslt_module->latency_info[WRITE_32_IDX].cmd_maxlaty) {
					set_write_32_cmd_maxlaty(cmd_trasprt_elapsed_time);
					set_write_32_cmd_maxlaty_exestatm(cmd_txc);
				}
				break;
			case UNMAP:
				cal_unmap_cmd_ovslt_cnt();
				if (cmd_trasprt_elapsed_time >=
				  g_ovslt_module->latency_info[UNMAP_IDX].cmd_maxlaty) {
					set_unmap_cmd_maxlaty(cmd_trasprt_elapsed_time);
					set_unmap_cmd_maxlaty_exestatm(cmd_txc);
				}
				break;
			case WRITE_SAME:
				cal_write_same_cmd_ovslt_cnt();
				if (cmd_trasprt_elapsed_time >=
				  g_ovslt_module->latency_info[WRITE_SAME_IDX].cmd_maxlaty) {
					set_write_same_cmd_maxlaty(cmd_trasprt_elapsed_time);
					set_write_same_cmd_maxlaty_exestatm(cmd_txc);
				}
				break;
			case WRITE_SAME_16:
				cal_write_same_16_cmd_ovslt_cnt();
				if (cmd_trasprt_elapsed_time >=
				  g_ovslt_module->latency_info[WRITE_SAME_16_IDX].cmd_maxlaty) {
					set_write_same_16_cmd_maxlaty(cmd_trasprt_elapsed_time);
					set_write_same_16_cmd_maxlaty_exestatm(cmd_txc);
				}
				break;
			case WRITE_SAME_32:
				cal_write_same_32_cmd_ovslt_cnt();
				if (cmd_trasprt_elapsed_time >=
				  g_ovslt_module->latency_info[WRITE_SAME_32_IDX].cmd_maxlaty) {
					set_write_same_32_cmd_maxlaty(cmd_trasprt_elapsed_time);
					set_write_same_32_cmd_maxlaty_exestatm(cmd_txc);
				}
				break;
			default:
				break;
		}
	}
	ret = 1;

	return ret; 
}

int cal_read_6_cmd_ovslt_cnt(void)
{
	int ret = 0;

	if (!g_ovslt_module)
		return ret;

	if (ISCSI_CMD_READ_OVSLT_CNT_ENABLE(g_ovslt_module->enable)) {
		g_ovslt_module->latency_info[READ_6_IDX].cmd_ovslt_cnt++;
		pr_debug("[ISCSI_CMD_OVSLT_CNT] %s: read_6_cmd_ovslt_cnt: %d\n",
		  __func__,
		  g_ovslt_module->latency_info[READ_6_IDX].cmd_ovslt_cnt);
		ret = 1;
	} else {
		pr_debug("[ISCSI_CMD_OVSLT_CNT] %s: Can not set read_6_cmd_ovslt_cnt\n",
		  __func__);
	}

	return ret;
}

int cal_read_10_cmd_ovslt_cnt(void)
{
	int ret = 0;

	if (!g_ovslt_module)
		return ret;

	if (ISCSI_CMD_READ_OVSLT_CNT_ENABLE(g_ovslt_module->enable)) {
		g_ovslt_module->latency_info[READ_10_IDX].cmd_ovslt_cnt++;
		pr_debug("[ISCSI_CMD_OVSLT_CNT] %s: read_10_cmd_ovslt_cnt: %d\n",
		  __func__,
		  g_ovslt_module->latency_info[READ_10_IDX].cmd_ovslt_cnt);
		ret = 1;
	} else {
		pr_debug("[ISCSI_CMD_OVSLT_CNT] %s: Can not set read_10_cmd_ovslt_cnt\n",
		  __func__);
	}

	return ret;
}

int cal_read_12_cmd_ovslt_cnt(void)
{
	int ret = 0;

	if (!g_ovslt_module)
		return ret;

	if (ISCSI_CMD_READ_OVSLT_CNT_ENABLE(g_ovslt_module->enable)) {
		g_ovslt_module->latency_info[READ_12_IDX].cmd_ovslt_cnt++;
		pr_debug("[ISCSI_CMD_OVSLT_CNT] %s: read_12_cmd_ovslt_cnt: %d\n",
		  __func__,
		  g_ovslt_module->latency_info[READ_12_IDX].cmd_ovslt_cnt);
		ret = 1;
	} else {
		pr_debug("[ISCSI_CMD_OVSLT_CNT] %s: Can not set read_12_cmd_ovslt_cnt\n",
		  __func__);
	}

	return ret;
}

int cal_read_16_cmd_ovslt_cnt(void)
{
	int ret = 0;

	if (!g_ovslt_module)
		return ret;

	if (ISCSI_CMD_READ_OVSLT_CNT_ENABLE(g_ovslt_module->enable)) {
		g_ovslt_module->latency_info[READ_16_IDX].cmd_ovslt_cnt++;
		pr_debug("[ISCSI_CMD_OVSLT_CNT] %s: read_16_cmd_ovslt_cnt: %d\n",
		  __func__,
		  g_ovslt_module->latency_info[READ_16_IDX].cmd_ovslt_cnt);
		ret = 1;
	} else {
		pr_debug("[ISCSI_CMD_OVSLT_CNT] %s: Can not set read_16_cmd_ovslt_cnt\n",
		  __func__);
	}

	return ret;
}

int cal_read_32_cmd_ovslt_cnt(void)
{
	int ret = 0;

	if (!g_ovslt_module)
		return ret;

	if (ISCSI_CMD_READ_OVSLT_CNT_ENABLE(g_ovslt_module->enable)) {
		g_ovslt_module->latency_info[READ_32_IDX].cmd_ovslt_cnt++;
		pr_debug("[ISCSI_CMD_OVSLT_CNT] %s: read_32_cmd_ovslt_cnt: %d\n",
		  __func__,
		  g_ovslt_module->latency_info[READ_32_IDX].cmd_ovslt_cnt);
		ret = 1;
	} else {
		pr_debug("[ISCSI_CMD_OVSLT_CNT] %s: Can not set read_32_cmd_ovslt_cnt\n",
		  __func__);
	}

	return ret;
}

int cal_write_6_cmd_ovslt_cnt(void)
{
	int ret = 0;

	if (!g_ovslt_module)
		return ret;

	if (ISCSI_CMD_WRITE_OVSLT_CNT_ENABLE(g_ovslt_module->enable)) {
		g_ovslt_module->latency_info[WRITE_6_IDX].cmd_ovslt_cnt++;
		pr_debug("[ISCSI_CMD_OVSLT_CNT] %s: write_6_cmd_ovslt_cnt: %d\n",
		  __func__,
		  g_ovslt_module->latency_info[WRITE_6_IDX].cmd_ovslt_cnt);
		ret = 1;
	} else {
		pr_debug("[ISCSI_CMD_OVSLT_CNT] %s: Can not set write_6_cmd_ovslt_cnt\n",
		  __func__);
	}

	return ret;
}

int cal_write_10_cmd_ovslt_cnt(void)
{
	int ret = 0;

	if (!g_ovslt_module)
		return ret;

	if (ISCSI_CMD_WRITE_OVSLT_CNT_ENABLE(g_ovslt_module->enable)) {
		g_ovslt_module->latency_info[WRITE_10_IDX].cmd_ovslt_cnt++;
		pr_debug("[ISCSI_CMD_OVSLT_CNT] %s: write_10_cmd_ovslt_cnt: %d\n",
		  __func__,
		  g_ovslt_module->latency_info[WRITE_10_IDX].cmd_ovslt_cnt);
		ret = 1;
	} else {
		pr_debug("[ISCSI_CMD_OVSLT_CNT] %s: Can not set write_10_cmd_ovslt_cnt\n",
		  __func__);
	}

	return ret;
}

int cal_write_12_cmd_ovslt_cnt(void)
{
	int ret = 0;

	if (!g_ovslt_module)
		return ret;

	if (ISCSI_CMD_WRITE_OVSLT_CNT_ENABLE(g_ovslt_module->enable)) {
		g_ovslt_module->latency_info[WRITE_12_IDX].cmd_ovslt_cnt++;
		pr_debug("[ISCSI_CMD_OVSLT_CNT] %s: write_12_cmd_ovslt_cnt: %d\n",
		  __func__,
		  g_ovslt_module->latency_info[WRITE_12_IDX].cmd_ovslt_cnt);
		ret = 1;
	} else {
		pr_debug("[ISCSI_CMD_OVSLT_CNT] %s: Can not set write_12_cmd_ovslt_cnt\n",
		  __func__);
	}

	return ret;
}

int cal_write_16_cmd_ovslt_cnt(void)
{
	int ret = 0;

	if (!g_ovslt_module)
		return ret;

	if (ISCSI_CMD_WRITE_OVSLT_CNT_ENABLE(g_ovslt_module->enable)) {
		g_ovslt_module->latency_info[WRITE_16_IDX].cmd_ovslt_cnt++;
		pr_debug("[ISCSI_CMD_OVSLT_CNT] %s: write_16_cmd_ovslt_cnt: %d\n",
		  __func__,
		  g_ovslt_module->latency_info[WRITE_16_IDX].cmd_ovslt_cnt);
		ret = 1;
	} else {
		pr_debug("[ISCSI_CMD_OVSLT_CNT] %s: Can not set write_16_cmd_ovslt_cnt\n",
		  __func__);
	}

	return ret;
}

int cal_write_32_cmd_ovslt_cnt(void)
{
	int ret = 0;

	if (!g_ovslt_module)
		return ret;

	if (ISCSI_CMD_WRITE_OVSLT_CNT_ENABLE(g_ovslt_module->enable)) {
		g_ovslt_module->latency_info[WRITE_32_IDX].cmd_ovslt_cnt++;
		pr_debug("[ISCSI_CMD_OVSLT_CNT] %s: write_32_cmd_ovslt_cnt: %d\n",
		  __func__,
		  g_ovslt_module->latency_info[WRITE_32_IDX].cmd_ovslt_cnt);
		ret = 1;
	} else {
		pr_debug("[ISCSI_CMD_OVSLT_CNT] %s: Can not set write_32_cmd_ovslt_cnt\n",
		  __func__);
	}

	return ret;
}

int cal_unmap_cmd_ovslt_cnt(void)
{
	int ret = 0;

	if (!g_ovslt_module)
		return ret;

	if (ISCSI_CMD_UNMAP_OVSLT_CNT_ENABLE(g_ovslt_module->enable)) {
		g_ovslt_module->latency_info[UNMAP_IDX].cmd_ovslt_cnt++;
		pr_debug("[ISCSI_CMD_OVSLT_CNT] %s: unmap_cmd_ovslt_cnt: %d\n",
		  __func__,
		  g_ovslt_module->latency_info[UNMAP_IDX].cmd_ovslt_cnt);
		ret = 1;
	} else {
		pr_debug("[ISCSI_CMD_OVSLT_CNT] %s: Can not set unmap_cmd_ovslt_cnt\n",
		  __func__);
	}

	return ret;
}

int cal_write_same_cmd_ovslt_cnt(void)
{
	int ret = 0;

	if (!g_ovslt_module)
		return ret;

	if (ISCSI_CMD_WRITE_SAME_OVSLT_CNT_ENABLE(g_ovslt_module->enable)) {
		g_ovslt_module->latency_info[WRITE_SAME_IDX].cmd_ovslt_cnt++;
		pr_debug("[ISCSI_CMD_OVSLT_CNT] %s: write_same_cmd_ovslt_cnt: %d\n",
		  __func__,
		  g_ovslt_module->latency_info[WRITE_SAME_IDX].cmd_ovslt_cnt);
		ret = 1;
	} else {
		pr_debug("[ISCSI_CMD_OVSLT_CNT] %s: Can not set write_same_cmd_ovslt_cnt\n",
		  __func__);
	}

	return ret;
}

int cal_write_same_16_cmd_ovslt_cnt(void)
{
	int ret = 0;

	if (!g_ovslt_module)
		return ret;

	if (ISCSI_CMD_WRITE_SAME_OVSLT_CNT_ENABLE(g_ovslt_module->enable)) {
		g_ovslt_module->latency_info[WRITE_SAME_16_IDX].cmd_ovslt_cnt++;
		pr_debug("[ISCSI_CMD_OVSLT_CNT] %s: write_same_16_cmd_ovslt_cnt: %d\n",
		  __func__,
		  g_ovslt_module->latency_info[WRITE_SAME_16_IDX].cmd_ovslt_cnt);
		ret = 1;
	} else {
		pr_debug("[ISCSI_CMD_OVSLT_CNT] %s: Can not set write_same_16_cmd_ovslt_cnt\n",
		  __func__);
	}

	return ret;
}

int cal_write_same_32_cmd_ovslt_cnt(void)
{
	int ret = 0;

	if (!g_ovslt_module)
		return ret;

	if (ISCSI_CMD_WRITE_SAME_OVSLT_CNT_ENABLE(g_ovslt_module->enable)) {
		g_ovslt_module->latency_info[WRITE_SAME_32_IDX].cmd_ovslt_cnt++;
		pr_debug("[ISCSI_CMD_OVSLT_CNT] %s: write_same_32_cmd_ovslt_cnt: %d\n",
		  __func__,
		  g_ovslt_module->latency_info[WRITE_SAME_32_IDX].cmd_ovslt_cnt);
		ret = 1;
	} else {
		pr_debug("[ISCSI_CMD_OVSLT_CNT] %s: Can not set write_same_32_cmd_ovslt_cnt\n",
		  __func__);
	}

	return ret;
}

int set_read_6_cmd_maxlaty(unsigned long read_6_cmd_maxlaty)
{
	int ret = 0;

	if (!g_ovslt_module)
		return ret;

	if (ISCSI_CMD_READ_OVSLT_CNT_ENABLE(g_ovslt_module->enable)) {
		g_ovslt_module->latency_info[READ_6_IDX].cmd_maxlaty =
		  read_6_cmd_maxlaty;
		pr_debug("[ISCSI_CMD_OVSLT_CNT] %s: read_6_cmd_maxlatency: %lu\n",
		  __func__,
		  g_ovslt_module->latency_info[READ_6_IDX].cmd_maxlaty);
		ret = 1;
	} else {
		pr_debug("[ISCSI_CMD_OVSLT_CNT] %s: Can not set read_6_cmd_maxlatency\n",
		  __func__);
	}

	return ret;
}

int set_read_10_cmd_maxlaty(unsigned long read_10_cmd_maxlaty)
{
	int ret = 0;

	if (!g_ovslt_module)
		return ret;

	if (ISCSI_CMD_READ_OVSLT_CNT_ENABLE(g_ovslt_module->enable)) {
		g_ovslt_module->latency_info[READ_10_IDX].cmd_maxlaty =
		  read_10_cmd_maxlaty;
		pr_debug("[ISCSI_CMD_OVSLT_CNT] %s: read_10_cmd_maxlatency: %lu\n",
		  __func__,
		  g_ovslt_module->latency_info[READ_10_IDX].cmd_maxlaty);
		ret = 1;
	} else {
		pr_debug("[ISCSI_CMD_OVSLT_CNT] %s: Can not set read_10_cmd_maxlatency\n",
		  __func__);
	}

	return ret;
}

int set_read_12_cmd_maxlaty(unsigned long read_12_cmd_maxlaty)
{
	int ret = 0;

	if (!g_ovslt_module)
		return ret;

	if (ISCSI_CMD_READ_OVSLT_CNT_ENABLE(g_ovslt_module->enable)) {
		g_ovslt_module->latency_info[READ_12_IDX].cmd_maxlaty =
		  read_12_cmd_maxlaty;
		pr_debug("[ISCSI_CMD_OVSLT_CNT] %s: read_12_cmd_maxlatency: %lu\n",
		  __func__,
		  g_ovslt_module->latency_info[READ_12_IDX].cmd_maxlaty);
		ret = 1;
	} else {
		pr_debug("[ISCSI_CMD_OVSLT_CNT] %s: Can not set read_12_cmd_maxlatency\n",
		  __func__);
	}

	return ret;
}

int set_read_16_cmd_maxlaty(unsigned long read_16_cmd_maxlaty)
{
	int ret = 0;

	if (!g_ovslt_module)
		return ret;

	if (ISCSI_CMD_READ_OVSLT_CNT_ENABLE(g_ovslt_module->enable)) {
		g_ovslt_module->latency_info[READ_16_IDX].cmd_maxlaty =
		  read_16_cmd_maxlaty;
		pr_debug("[ISCSI_CMD_OVSLT_CNT] %s: read_16_cmd_maxlatency: %lu\n",
		  __func__,
		  g_ovslt_module->latency_info[READ_16_IDX].cmd_maxlaty);
		ret = 1;
	} else {
		pr_debug("[ISCSI_CMD_OVSLT_CNT] %s: Can not set read_16_cmd_maxlatency\n",
		  __func__);
	}

	return ret;
}

int set_read_32_cmd_maxlaty(unsigned long read_32_cmd_maxlaty)
{
	int ret = 0;

	if (!g_ovslt_module)
		return ret;

	if (ISCSI_CMD_READ_OVSLT_CNT_ENABLE(g_ovslt_module->enable)) {
		g_ovslt_module->latency_info[READ_32_IDX].cmd_maxlaty =
		  read_32_cmd_maxlaty;
		pr_debug("[ISCSI_CMD_OVSLT_CNT] %s: read_32_cmd_maxlatency: %lu\n",
		  __func__,
		  g_ovslt_module->latency_info[READ_32_IDX].cmd_maxlaty);
		ret = 1;
	} else {
		pr_debug("[ISCSI_CMD_OVSLT_CNT] %s: Can not set read_32_cmd_maxlatency\n",
		  __func__);
	}

	return ret;
}

int set_write_6_cmd_maxlaty(unsigned long write_6_cmd_maxlaty)
{
	int ret = 0;

	if (!g_ovslt_module)
		return ret;

	if (ISCSI_CMD_WRITE_OVSLT_CNT_ENABLE(g_ovslt_module->enable)) {
		g_ovslt_module->latency_info[WRITE_6_IDX].cmd_maxlaty =
		  write_6_cmd_maxlaty;
		pr_debug("[ISCSI_CMD_OVSLT_CNT] %s: write_6_cmd_maxlatency: %lu\n",
		  __func__,
		  g_ovslt_module->latency_info[WRITE_6_IDX].cmd_maxlaty);
		ret = 1;
	} else {
		pr_debug("[ISCSI_CMD_OVSLT_CNT] %s: Can not set write_6_cmd_maxlatency\n",
		  __func__);
	}

	return ret;
}

int set_write_10_cmd_maxlaty(unsigned long write_10_cmd_maxlaty)
{
	int ret = 0;

	if (!g_ovslt_module)
		return ret;

	if (ISCSI_CMD_WRITE_OVSLT_CNT_ENABLE(g_ovslt_module->enable)) {
		g_ovslt_module->latency_info[WRITE_10_IDX].cmd_maxlaty =
		  write_10_cmd_maxlaty;
		pr_debug("[ISCSI_CMD_OVSLT_CNT] %s: write_10_cmd_maxlatency: %lu\n",
		  __func__,
		  g_ovslt_module->latency_info[WRITE_10_IDX].cmd_maxlaty);
		ret = 1;
	} else {
		pr_debug("[ISCSI_CMD_OVSLT_CNT] %s: Can not set write_10_cmd_maxlatency\n",
		  __func__);
	}

	return ret;
}

int set_write_12_cmd_maxlaty(unsigned long write_12_cmd_maxlaty)
{
	int ret = 0;

	if (!g_ovslt_module)
		return ret;

	if (ISCSI_CMD_WRITE_OVSLT_CNT_ENABLE(g_ovslt_module->enable)) {
		g_ovslt_module->latency_info[WRITE_12_IDX].cmd_maxlaty =
		  write_12_cmd_maxlaty;
		pr_debug("[ISCSI_CMD_OVSLT_CNT] %s: write_12_cmd_maxlatency: %lu\n",
		  __func__,
		  g_ovslt_module->latency_info[WRITE_12_IDX].cmd_maxlaty);
		ret = 1;
	} else {
		pr_debug("[ISCSI_CMD_OVSLT_CNT] %s: Can not set write_12_cmd_maxlatency\n",
		  __func__);
	}

	return ret;
}

int set_write_16_cmd_maxlaty(unsigned long write_16_cmd_maxlaty)
{
	int ret = 0;

	if (!g_ovslt_module)
		return ret;

	if (ISCSI_CMD_WRITE_OVSLT_CNT_ENABLE(g_ovslt_module->enable)) {
		g_ovslt_module->latency_info[WRITE_16_IDX].cmd_maxlaty =
		  write_16_cmd_maxlaty;
		pr_debug("[ISCSI_CMD_OVSLT_CNT] %s: write_16_cmd_maxlatency: %lu\n",
		  __func__,
		  g_ovslt_module->latency_info[WRITE_16_IDX].cmd_maxlaty);
		ret = 1;
	} else {
		pr_debug("[ISCSI_CMD_OVSLT_CNT] %s: Can not set write_16_cmd_maxlatency\n",
		  __func__);
	}

	return ret;
}

int set_write_32_cmd_maxlaty(unsigned long write_32_cmd_maxlaty)
{
	int ret = 0;

	if (!g_ovslt_module)
		return ret;

	if (ISCSI_CMD_WRITE_OVSLT_CNT_ENABLE(g_ovslt_module->enable)) {
		g_ovslt_module->latency_info[WRITE_32_IDX].cmd_maxlaty =
		  write_32_cmd_maxlaty;
		pr_debug("[ISCSI_CMD_OVSLT_CNT] %s: write_32_cmd_maxlatency: %lu\n",
		  __func__,
		  g_ovslt_module->latency_info[WRITE_32_IDX].cmd_maxlaty);
		ret = 1;
	} else {
		pr_debug("[ISCSI_CMD_OVSLT_CNT] %s: Can not set write_32_cmd_maxlatency\n",
		  __func__);
	}

	return ret;
}

int set_unmap_cmd_maxlaty(unsigned long unmap_cmd_maxlaty)
{
	int ret = 0;

	if (!g_ovslt_module)
		return ret;

	if (ISCSI_CMD_UNMAP_OVSLT_CNT_ENABLE(g_ovslt_module->enable)) {
		g_ovslt_module->latency_info[UNMAP_IDX].cmd_maxlaty =
		  unmap_cmd_maxlaty;
		pr_debug("[ISCSI_CMD_OVSLT_CNT] %s: unmap_cmd_maxlatency: %lu\n",
		  __func__,
		  g_ovslt_module->latency_info[UNMAP_IDX].cmd_maxlaty);
		ret = 1;
	} else {
		pr_debug("[ISCSI_CMD_OVSLT_CNT] %s: Can not set unmap_cmd_maxlatency\n",
		  __func__);
	}

	return ret;
}

int set_write_same_cmd_maxlaty(unsigned long write_same_cmd_maxlaty)
{
	int ret = 0;

	if (!g_ovslt_module)
		return ret;

	if (ISCSI_CMD_WRITE_SAME_OVSLT_CNT_ENABLE(g_ovslt_module->enable)) {
		g_ovslt_module->latency_info[WRITE_SAME_IDX].cmd_maxlaty =
		  write_same_cmd_maxlaty;
		pr_debug("[ISCSI_CMD_OVSLT_CNT] %s: write_same_cmd_maxlatency: %lu\n",
		  __func__,
		  g_ovslt_module->latency_info[WRITE_SAME_IDX].cmd_maxlaty);
		ret = 1;
	} else {
		pr_debug("[ISCSI_CMD_OVSLT_CNT] %s: Can not set write_same_cmd_maxlatency\n",
		  __func__);
	}

	return ret;
}

int set_write_same_16_cmd_maxlaty(unsigned long write_same_16_cmd_maxlaty)
{
	int ret = 0;

	if (!g_ovslt_module)
		return ret;

	if (ISCSI_CMD_WRITE_SAME_OVSLT_CNT_ENABLE(g_ovslt_module->enable)) {
		g_ovslt_module->latency_info[WRITE_SAME_16_IDX].cmd_maxlaty =
		  write_same_16_cmd_maxlaty;
		pr_debug("[ISCSI_CMD_OVSLT_CNT] %s: write_same_16_cmd_maxlatency: %lu\n",
		  __func__,
		  g_ovslt_module->latency_info[WRITE_SAME_16_IDX].cmd_maxlaty);
		ret = 1;
	} else {
		pr_debug("[ISCSI_CMD_OVSLT_CNT] %s: Can not set write_same_16_cmd_maxlatency\n",
		  __func__);
	}

	return ret;
}

int set_write_same_32_cmd_maxlaty(unsigned long write_same_32_cmd_maxlaty)
{
	int ret = 0;

	if (!g_ovslt_module)
		return ret;

	if (ISCSI_CMD_WRITE_SAME_OVSLT_CNT_ENABLE(g_ovslt_module->enable)) {
		g_ovslt_module->latency_info[WRITE_SAME_32_IDX].cmd_maxlaty =
		  write_same_32_cmd_maxlaty;
		pr_debug("[ISCSI_CMD_OVSLT_CNT] %s: write_same_32_cmd_maxlatency: %lu\n",
		  __func__,
		  g_ovslt_module->latency_info[WRITE_SAME_32_IDX].cmd_maxlaty);
		ret = 1;
	} else {
		pr_debug("[ISCSI_CMD_OVSLT_CNT] %s: Can not set write_same_32_cmd_maxlatency\n",
		  __func__);
	}

	return ret;
}

int set_read_6_cmd_maxlaty_exestatm(struct timex read_6_cmd_maxlaty_txc)
{
	int ret = 0;

	if (!g_ovslt_module)
		return ret;

	if (ISCSI_CMD_READ_OVSLT_CNT_ENABLE(g_ovslt_module->enable)) {
		g_ovslt_module->latency_info[READ_6_IDX].cmd_maxlaty_exestatm =
		  read_6_cmd_maxlaty_txc;
		pr_debug("[ISCSI_CMD_OVSLT_CNT] %s: read_6_cmd_maxlatency_exestarttime: %lu\n",
		  __func__,
		  g_ovslt_module->latency_info[READ_6_IDX].cmd_maxlaty_exestatm.time.tv_sec);
		ret = 1;
	} else {
		pr_debug("[ISCSI_CMD_OVSLT_CNT] %s: Can not set read_6_cmd_maxlatency_exestarttime\n",
		  __func__);
	}

	return ret;
}

int set_read_10_cmd_maxlaty_exestatm(struct timex read_10_cmd_maxlaty_txc)
{
	int ret = 0;

	if (!g_ovslt_module)
		return ret;

	if (ISCSI_CMD_READ_OVSLT_CNT_ENABLE(g_ovslt_module->enable)) {
		g_ovslt_module->latency_info[READ_10_IDX].cmd_maxlaty_exestatm =
		  read_10_cmd_maxlaty_txc;
		pr_debug("[ISCSI_CMD_OVSLT_CNT] %s: read_10_cmd_maxlatency_exestarttime: %lu\n",
		  __func__,
		  g_ovslt_module->latency_info[READ_10_IDX].cmd_maxlaty_exestatm.time.tv_sec);
		ret = 1;
	} else {
		pr_debug("[ISCSI_CMD_OVSLT_CNT] %s: Can not set read_6_cmd_maxlatency_exestarttime\n",
		  __func__);
	}

	return ret;
}

int set_read_12_cmd_maxlaty_exestatm(struct timex read_12_cmd_maxlaty_txc)
{
	int ret = 0;

	if (!g_ovslt_module)
		return ret;

	if (ISCSI_CMD_READ_OVSLT_CNT_ENABLE(g_ovslt_module->enable)) {
		g_ovslt_module->latency_info[READ_12_IDX].cmd_maxlaty_exestatm =
		  read_12_cmd_maxlaty_txc;
		pr_debug("[ISCSI_CMD_OVSLT_CNT] %s: read_12_cmd_maxlatency_exestarttime: %lu\n",
		  __func__,
		  g_ovslt_module->latency_info[READ_12_IDX].cmd_maxlaty_exestatm.time.tv_sec);
		ret = 1;
	} else {
		pr_debug("[ISCSI_CMD_OVSLT_CNT] %s: Can not set read_12_cmd_maxlatency_exestarttime\n",
		  __func__);
	}

	return ret;
}

int set_read_16_cmd_maxlaty_exestatm(struct timex read_16_cmd_maxlaty_txc)
{
	int ret = 0;

	if (!g_ovslt_module)
		return ret;

	if (ISCSI_CMD_READ_OVSLT_CNT_ENABLE(g_ovslt_module->enable)) {
		g_ovslt_module->latency_info[READ_16_IDX].cmd_maxlaty_exestatm =
		  read_16_cmd_maxlaty_txc;
		pr_debug("[ISCSI_CMD_OVSLT_CNT] %s: read_16_cmd_maxlatency_exestarttime: %lu\n",
		  __func__,
		  g_ovslt_module->latency_info[READ_16_IDX].cmd_maxlaty_exestatm.time.tv_sec);
		ret = 1;
	} else {
		pr_debug("[ISCSI_CMD_OVSLT_CNT] %s: Can not set read_16_cmd_maxlatency_exestarttime\n",
		  __func__);
	}

	return ret;
}

int set_read_32_cmd_maxlaty_exestatm(struct timex read_32_cmd_maxlaty_txc)
{
	int ret = 0;

	if (!g_ovslt_module)
		return ret;

	if (ISCSI_CMD_READ_OVSLT_CNT_ENABLE(g_ovslt_module->enable)) {
		g_ovslt_module->latency_info[READ_32_IDX].cmd_maxlaty_exestatm =
		  read_32_cmd_maxlaty_txc;
		pr_debug("[ISCSI_CMD_OVSLT_CNT] %s: read_32_cmd_maxlatency_exestarttime: %lu\n",
		__func__,
		g_ovslt_module->latency_info[READ_32_IDX].cmd_maxlaty_exestatm.time.tv_sec);
		ret = 1;
	} else {
		pr_debug("[ISCSI_CMD_OVSLT_CNT] %s: Can not set read_32_cmd_maxlatency_exestarttime\n",
		  __func__);
	}

	return ret;
}

int set_write_6_cmd_maxlaty_exestatm(struct timex write_6_cmd_maxlaty_txc)
{
	int ret = 0;

	if (!g_ovslt_module)
		return ret;

	if (ISCSI_CMD_WRITE_OVSLT_CNT_ENABLE(g_ovslt_module->enable)) {
		g_ovslt_module->latency_info[WRITE_6_IDX].cmd_maxlaty_exestatm =
		  write_6_cmd_maxlaty_txc;
		pr_debug("[ISCSI_CMD_OVSLT_CNT] %s: write_6_cmd_maxlatency_exestarttime: %lu\n",
		  __func__,
		  g_ovslt_module->latency_info[WRITE_6_IDX].cmd_maxlaty_exestatm.time.tv_sec);
		ret = 1;
	} else {
		pr_debug("[ISCSI_CMD_OVSLT_CNT] %s: Can not set write_6_cmd_maxlatency_exestarttime\n",
		  __func__);
	}

	return ret;
}

int set_write_10_cmd_maxlaty_exestatm(struct timex write_10_cmd_maxlaty_txc)
{
	int ret = 0;

	if (!g_ovslt_module)
		return ret;

	if (ISCSI_CMD_WRITE_OVSLT_CNT_ENABLE(g_ovslt_module->enable)) {
		g_ovslt_module->latency_info[WRITE_10_IDX].cmd_maxlaty_exestatm =
		  write_10_cmd_maxlaty_txc;
		pr_debug("[ISCSI_CMD_OVSLT_CNT] %s: write_10_cmd_maxlatency_exestarttime: %lu\n",
		  __func__,
		  g_ovslt_module->latency_info[WRITE_10_IDX].cmd_maxlaty_exestatm.time.tv_sec);
		ret = 1;
	} else {
		pr_debug("[ISCSI_CMD_OVSLT_CNT] %s: Can not set write_10_cmd_maxlatency_exestarttime\n",
		  __func__);
	}

	return ret;
}

int set_write_12_cmd_maxlaty_exestatm(struct timex write_12_cmd_maxlaty_txc)
{
	int ret = 0;

	if (!g_ovslt_module)
		return ret;

	if (ISCSI_CMD_WRITE_OVSLT_CNT_ENABLE(g_ovslt_module->enable)) {
		g_ovslt_module->latency_info[WRITE_12_IDX].cmd_maxlaty_exestatm =
		  write_12_cmd_maxlaty_txc;
		pr_debug("[ISCSI_CMD_OVSLT_CNT] %s: write_12_cmd_maxlatency_exestarttime: %lu\n",
		  __func__,
		  g_ovslt_module->latency_info[WRITE_12_IDX].cmd_maxlaty_exestatm.time.tv_sec);
		ret = 1;
	} else {
		pr_debug("[ISCSI_CMD_OVSLT_CNT] %s: Can not set write_12_cmd_maxlatency_exestarttime\n",
		  __func__);
	}

	return ret;
}

int set_write_16_cmd_maxlaty_exestatm(struct timex write_16_cmd_maxlaty_txc)
{
	int ret = 0;

	if (!g_ovslt_module)
		return ret;

	if (ISCSI_CMD_WRITE_OVSLT_CNT_ENABLE(g_ovslt_module->enable)) {
		g_ovslt_module->latency_info[WRITE_16_IDX].cmd_maxlaty_exestatm =
		  write_16_cmd_maxlaty_txc;
		pr_debug("[ISCSI_CMD_OVSLT_CNT] %s: write_16_cmd_maxlatency_exestarttime: %lu\n",
		  __func__,
		  g_ovslt_module->latency_info[WRITE_16_IDX].cmd_maxlaty_exestatm.time.tv_sec);
		ret = 1;
	} else {
		pr_debug("[ISCSI_CMD_OVSLT_CNT] %s: Can not set write_16_cmd_maxlatency_exestarttime\n",
		  __func__);
	}

	return ret;
}

int set_write_32_cmd_maxlaty_exestatm(struct timex write_32_cmd_maxlaty_txc)
{
	int ret = 0;

	if (!g_ovslt_module)
		return ret;

	if (ISCSI_CMD_WRITE_OVSLT_CNT_ENABLE(g_ovslt_module->enable)) {
		g_ovslt_module->latency_info[WRITE_32_IDX].cmd_maxlaty_exestatm =
		  write_32_cmd_maxlaty_txc;
		pr_debug("[ISCSI_CMD_OVSLT_CNT] %s: write_32_cmd_maxlatency_exestarttime: %lu\n",
		  __func__,
		  g_ovslt_module->latency_info[WRITE_32_IDX].cmd_maxlaty_exestatm.time.tv_sec);
		ret = 1;
	} else {
		pr_debug("[ISCSI_CMD_OVSLT_CNT] %s: Can not set write_32_cmd_maxlatency_exestarttime\n",
		  __func__);
	}

	return ret;
}

int set_unmap_cmd_maxlaty_exestatm(struct timex unmap_cmd_maxlaty_txc)
{
	int ret = 0;

	if (!g_ovslt_module)
		return ret;

	if (ISCSI_CMD_UNMAP_OVSLT_CNT_ENABLE(g_ovslt_module->enable)) {
		g_ovslt_module->latency_info[UNMAP_IDX].cmd_maxlaty_exestatm =
		  unmap_cmd_maxlaty_txc;
		pr_debug("[ISCSI_CMD_OVSLT_CNT] %s: unmap_cmd_maxlatency_exestarttime: %lu\n",
		  __func__,
		  g_ovslt_module->latency_info[UNMAP_IDX].cmd_maxlaty_exestatm.time.tv_sec);
		ret = 1;
	} else {
		pr_debug("[ISCSI_CMD_OVSLT_CNT] %s: Can not set unmap_cmd_maxlatency_exestarttime\n",
		  __func__);
	}

	return ret;
}

int set_write_same_cmd_maxlaty_exestatm(struct timex write_same_cmd_maxlaty_txc)
{
	int ret = 0;

	if (!g_ovslt_module)
		return ret;

	if (ISCSI_CMD_WRITE_SAME_OVSLT_CNT_ENABLE(g_ovslt_module->enable)) {
		g_ovslt_module->latency_info[WRITE_SAME_IDX].cmd_maxlaty_exestatm =
		  write_same_cmd_maxlaty_txc;
		pr_debug("[ISCSI_CMD_OVSLT_CNT] %s: write_same_cmd_maxlatency_exestarttime: %lu\n",
		  __func__,
		  g_ovslt_module->latency_info[WRITE_SAME_IDX].cmd_maxlaty_exestatm.time.tv_sec);
		ret = 1;
	} else {
		pr_debug("[ISCSI_CMD_OVSLT_CNT] %s: Can not set write_same_cmd_maxlatency_exestarttime\n",
		  __func__);
	}

	return ret;
}

int set_write_same_16_cmd_maxlaty_exestatm(struct timex write_same_16_cmd_maxlaty_txc)
{
	int ret = 0;

	if (!g_ovslt_module)
		return ret;

	if (ISCSI_CMD_WRITE_SAME_OVSLT_CNT_ENABLE(g_ovslt_module->enable)) {
		g_ovslt_module->latency_info[WRITE_SAME_16_IDX].cmd_maxlaty_exestatm =
		  write_same_16_cmd_maxlaty_txc;
		pr_debug("[ISCSI_CMD_OVSLT_CNT] %s: write_same_16_cmd_maxlatency_exestarttime: %lu\n",
		  __func__,
		  g_ovslt_module->latency_info[WRITE_SAME_16_IDX].cmd_maxlaty_exestatm.time.tv_sec);
		ret = 1;
	} else {
		pr_debug("[ISCSI_CMD_OVSLT_CNT] %s: Can not set write_same_16_cmd_maxlatency_exestarttime\n",
		  __func__);
	}

	return ret;
}

int set_write_same_32_cmd_maxlaty_exestatm(struct timex write_same_32_cmd_maxlaty_txc)
{
	int ret = 0;

	if (!g_ovslt_module)
		return ret;

	if (ISCSI_CMD_WRITE_SAME_OVSLT_CNT_ENABLE(g_ovslt_module->enable)) {
		g_ovslt_module->latency_info[WRITE_SAME_32_IDX].cmd_maxlaty_exestatm =
		  write_same_32_cmd_maxlaty_txc;
		pr_debug("[ISCSI_CMD_OVSLT_CNT] %s: write_same_32_cmd_maxlatency_exestarttime: %lu\n",
		  __func__,
		  g_ovslt_module->latency_info[WRITE_SAME_32_IDX].cmd_maxlaty_exestatm.time.tv_sec);
		ret = 1;
	} else {
		pr_debug("[ISCSI_CMD_OVSLT_CNT] %s: Can not set write_same_32_cmd_maxlatency_exestarttime\n",
		  __func__);
	}

	return ret;
}

static struct configfs_attribute iscsi_cmd_ovslt_cnt_group_attr_enable = {
	.ca_owner = THIS_MODULE,
	.ca_name = "enable",
	.ca_mode = S_IRUGO | S_IWUSR,
};

static struct configfs_attribute iscsi_cmd_ovslt_cnt_group_attr_cmd_timeslot_setting = {
	.ca_owner = THIS_MODULE,
	.ca_name = "cmd_timeslot_setting",
	.ca_mode = S_IRUGO | S_IWUSR,
};

static struct configfs_attribute iscsi_cmd_ovslt_cnt_group_attr_dump_settings= {
	.ca_owner = THIS_MODULE,
	.ca_name = "dump_settings",
	.ca_mode = S_IRUGO,
};

static struct configfs_attribute iscsi_cmd_ovslt_cnt_group_attr_cmd_ovslt_cnt_cmd_info = {
	.ca_owner = THIS_MODULE,
	.ca_name = "cmd_ovslt_cnt_cmd_info",
	.ca_mode = S_IRUGO,
};

static struct configfs_attribute iscsi_cmd_ovslt_cnt_group_attr_cmd_ovslt_cnt_latency_info = {
	.ca_owner = THIS_MODULE,
	.ca_name = "cmd_ovslt_cnt_latency_info",
	.ca_mode = S_IRUGO,
};

static struct configfs_attribute *iscsi_cmd_ovslt_cnt_group_attrs[] = {
	&iscsi_cmd_ovslt_cnt_group_attr_enable,
	&iscsi_cmd_ovslt_cnt_group_attr_cmd_timeslot_setting,
	&iscsi_cmd_ovslt_cnt_group_attr_dump_settings,
	&iscsi_cmd_ovslt_cnt_group_attr_cmd_ovslt_cnt_cmd_info,
	&iscsi_cmd_ovslt_cnt_group_attr_cmd_ovslt_cnt_latency_info,
	NULL,
};

static ssize_t iscsi_cmd_ovslt_cnt_group_attr_show(struct config_item *item,
					 struct configfs_attribute *attr,
					 char *page)
{
	ssize_t count = 0;
	int i = 0;
	struct rtc_time tm;

	if (g_ovslt_module == NULL)
		return sprintf(page, "[ISCSI_CMD_OVSLT_CNT] ISCSI_CMD_OVSLT_CMD not init\n");
	else if (!strcmp(attr->ca_name, "enable"))
		count = sprintf(page, "0x%x\n", g_ovslt_module->enable);
	else if (!strcmp(attr->ca_name, "cmd_timeslot_setting"))
		count = sprintf(page, "%lu\n", g_ovslt_module->cmd_timeslot_setting);
	else if (!strcmp(attr->ca_name, "dump_settings")) {
		//iscsi_cmd_ovslt_cnt_dump_parameters();
		count = sprintf(page, "[ISCSI_CMD_OVSLT_CNT] ========== Dump Test Plan ===========\n"
			"[ISCSI_CMD_OVSLT_CNT] Enable Settings: 0x%x\n"
			"[ISCSI_CMD_OVSLT_CNT] Command Timeslot Setting: %lu\n"
			"[ISCSI_CMD_OVSLT_CNT] ========== End of Dump Test Plan ==========\n",
			g_ovslt_module->enable,
			g_ovslt_module->cmd_timeslot_setting);
	}
	else if (!strcmp(attr->ca_name, "cmd_ovslt_cnt_cmd_info")) {
		//iscsi_cmd_ovslt_cnt_dump_cmd_ovslt_cnt_cmd_info();
		count += sprintf(page + count, "%s\t%s\t%s\t%s\t%s\t%s\n",
		  "CmdNum", "OPCODE", "Total", "SBC", "SPC", "Trasprt");
		for (i = 0 ; i < MAX_CMD_INFO_SIZE ; i++)
		{
			count += sprintf(page + count, "%d\t0x%x\t%lu\t%lu\t%lu\t%lu\n", i,
			  g_ovslt_module->cmd_info[i].cmd_opcode,
			  g_ovslt_module->cmd_info[i].cmd_total_elapsed_time,
			  g_ovslt_module->cmd_info[i].cmd_sbc_elapsed_time,
			  g_ovslt_module->cmd_info[i].cmd_spc_elapsed_time,
			  g_ovslt_module->cmd_info[i].cmd_trasprt_elapsed_time);
		}
	}
	else if (!strcmp(attr->ca_name, "cmd_ovslt_cnt_latency_info")) {
		//iscsi_cmd_ovslt_cnt_dump_cmd_ovslt_cnt_latency_info();
		count += sprintf(page + count, "%s\t\t%s\t%s\t%s\t%s\n",
		  "Cmd", "OPCODE", "CmdCnt", "MaxLaty", "MaxLatyCmdTime");
		for (i = 0 ; i < MAX_LATENCY_INFO_SIZE ; i++)
		{
			rtc_time_to_tm(g_ovslt_module->latency_info[i].cmd_maxlaty_exestatm.time.tv_sec
			  + 28800, &tm);
			if (!strcmp(g_ovslt_module->latency_info[i].cmd_name, "READ_6") ||
				!strcmp(g_ovslt_module->latency_info[i].cmd_name, "READ_10") ||
				!strcmp(g_ovslt_module->latency_info[i].cmd_name, "READ_12") ||
				!strcmp(g_ovslt_module->latency_info[i].cmd_name, "READ_16") ||
				!strcmp(g_ovslt_module->latency_info[i].cmd_name, "READ_32") ||
				!strcmp(g_ovslt_module->latency_info[i].cmd_name, "WRITE_6") ||
				!strcmp(g_ovslt_module->latency_info[i].cmd_name, "UNMAP")) {
				count += sprintf(page + count,
				  "%s\t\t0x%02x\t%d\t%lu\t%d-%02d-%02d %02d:%02d:%02d\n",
				  g_ovslt_module->latency_info[i].cmd_name,
				  g_ovslt_module->latency_info[i].cmd_opcode,
				  g_ovslt_module->latency_info[i].cmd_ovslt_cnt,
				  g_ovslt_module->latency_info[i].cmd_maxlaty,
				  tm.tm_year + 1900, tm.tm_mon + 1,
				  tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec);
			}
			else {
				count += sprintf(page + count,
				  "%s\t0x%02x\t%d\t%lu\t%d-%02d-%02d %02d:%02d:%02d\n",
				  g_ovslt_module->latency_info[i].cmd_name,
				  g_ovslt_module->latency_info[i].cmd_opcode,
				  g_ovslt_module->latency_info[i].cmd_ovslt_cnt,
				  g_ovslt_module->latency_info[i].cmd_maxlaty,
				  tm.tm_year + 1900, tm.tm_mon + 1,
				  tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec);
			}
		}
	}
	else
		count = sprintf(page, "incorrect access\n");

	return count;
}

static ssize_t iscsi_cmd_ovslt_cnt_group_attr_store(struct config_item *item,
				       struct configfs_attribute *attr,
				       const char *page, size_t count)
{
	unsigned long tmp;
	char *p = (char *) page;

	tmp = simple_strtoul(p, &p, 10);
	if (!p || (*p && (*p != '\n')))
		return -EINVAL;

	if (tmp > INT_MAX)
		return -ERANGE;

	if (!strcmp(attr->ca_name, "enable")) {
		if ((ISCSI_CMD_SBC_OVSLT_CNT_ENABLE(g_ovslt_module->enable))^
		  (ISCSI_CMD_SBC_OVSLT_CNT_ENABLE(tmp))) {
			if (ISCSI_CMD_SBC_OVSLT_CNT_ENABLE(tmp))
				pr_debug("[ISCSI_CMD_OVSLT_CNT] %s: enable cmd sbc ovslt cnt\n"
				  , item->ci_name);
			else
				pr_debug("[ISCSI_CMD_OVSLT_CNT] %s: disable cmd sbc ovslt cnt\n"
				  , item->ci_name);
		}
		if ((ISCSI_CMD_SPC_OVSLT_CNT_ENABLE(g_ovslt_module->enable))^
		  (ISCSI_CMD_SPC_OVSLT_CNT_ENABLE(tmp))) {
			if (ISCSI_CMD_SPC_OVSLT_CNT_ENABLE(tmp))
				pr_debug("[ISCSI_CMD_OVSLT_CNT] %s: enable cmd spc ovslt cnt\n"
				  , item->ci_name);
			else
				pr_debug("[ISCSI_CMD_OVSLT_CNT] %s: disable cmd spc ovslt cnt\n"
				  , item->ci_name);
		}
		if ((ISCSI_CMD_TRASPRT_OVSLT_CNT_ENABLE(g_ovslt_module->enable))^
		  (ISCSI_CMD_TRASPRT_OVSLT_CNT_ENABLE(tmp))) {
			if (ISCSI_CMD_TRASPRT_OVSLT_CNT_ENABLE(tmp))
				pr_debug("[ISCSI_CMD_OVSLT_CNT] %s: enable cmd transport ovslt cnt\n"
				  , item->ci_name);
			else
				pr_debug("[ISCSI_CMD_OVSLT_CNT] %s: disable cmd transport ovslt cnt\n"
				  , item->ci_name);
		}
		if ((ISCSI_CMD_READ_OVSLT_CNT_ENABLE(g_ovslt_module->enable))^
		  (ISCSI_CMD_READ_OVSLT_CNT_ENABLE(tmp))) {
			if (ISCSI_CMD_READ_OVSLT_CNT_ENABLE(tmp))
				pr_debug("[ISCSI_CMD_OVSLT_CNT] %s: enable cmd read ovslt cnt\n"
				  , item->ci_name);
			else
				pr_debug("[ISCSI_CMD_OVSLT_CNT] %s: disable cmd read ovslt cnt\n"
				  , item->ci_name);
		}
		if ((ISCSI_CMD_WRITE_OVSLT_CNT_ENABLE(g_ovslt_module->enable))^
		  (ISCSI_CMD_WRITE_OVSLT_CNT_ENABLE(tmp))) {
			if (ISCSI_CMD_WRITE_OVSLT_CNT_ENABLE(tmp))
				pr_debug("[ISCSI_CMD_OVSLT_CNT] %s: enable cmd write ovslt cnt\n"
				  , item->ci_name);
			else
				pr_debug("[ISCSI_CMD_OVSLT_CNT] %s: disable cmd write ovslt cnt\n"
				  , item->ci_name);
		}
		if ((ISCSI_CMD_UNMAP_OVSLT_CNT_ENABLE(g_ovslt_module->enable))^
		  (ISCSI_CMD_UNMAP_OVSLT_CNT_ENABLE(tmp))) {
			if (ISCSI_CMD_UNMAP_OVSLT_CNT_ENABLE(tmp))
				pr_debug("[ISCSI_CMD_OVSLT_CNT] %s: enable cmd unmap ovslt cnt\n"
				  , item->ci_name);
			else
				pr_debug("[ISCSI_CMD_OVSLT_CNT] %s: disable cmd unamp ovslt cnt\n"
				  , item->ci_name);
		}
		if ((ISCSI_CMD_WRITE_SAME_OVSLT_CNT_ENABLE(g_ovslt_module->enable))^
		  (ISCSI_CMD_WRITE_SAME_OVSLT_CNT_ENABLE(tmp))) {
			if (ISCSI_CMD_WRITE_SAME_OVSLT_CNT_ENABLE(tmp))
				pr_debug("[ISCSI_CMD_OVSLT_CNT] %s: enable cmd write_same ovslt cnt\n"
				  , item->ci_name);
			else
				pr_debug("[ISCSI_CMD_OVSLT_CNT] %s: disable cmd write_same ovslt cnt\n"
				  , item->ci_name);
		}

		g_ovslt_module->enable = tmp;
	}
	else if (!strcmp(attr->ca_name, "cmd_timeslot_setting")) {
		g_ovslt_module->cmd_timeslot_setting = tmp;
	} else
		pr_debug("[ISCSI_CMD_OVSLT_CNT] incorrect access\n");

	return count;
}

static void iscsi_cmd_ovslt_cnt_group_release(struct config_item *item)
{
	kfree(to_iscsi_cmd_ovslt_cnt_group(item));
}

static struct configfs_item_operations iscsi_cmd_ovslt_cnt_group_ops = {
	.release		= iscsi_cmd_ovslt_cnt_group_release,
	.show_attribute		= iscsi_cmd_ovslt_cnt_group_attr_show,
	.store_attribute	= iscsi_cmd_ovslt_cnt_group_attr_store,
};

static struct config_item_type iscsi_cmd_ovslt_cnt_group_type = {
	.ct_item_ops	= &iscsi_cmd_ovslt_cnt_group_ops,
	.ct_attrs	= iscsi_cmd_ovslt_cnt_group_attrs,
	.ct_owner	= THIS_MODULE,
};

static struct configfs_subsystem iscsi_cmd_ovslt_cnt_group_subsys = {
	.su_group = {
		.cg_item = {
			.ci_namebuf = "iscsi_cmd_ovslt_cnt",
			.ci_type = &iscsi_cmd_ovslt_cnt_group_type,
		},
	},
};

static int __init iscsi_cmd_ovslt_cnt_configfs_init(void)
{
	int ret;
	struct configfs_subsystem *subsys;

	pr_info("[ISCSI_CMD_OVSLT_CNT] iscsi_target_qcmd_ovslt_cnt.ko %s\n", __func__);

	subsys = &iscsi_cmd_ovslt_cnt_group_subsys;
	config_group_init(&subsys->su_group);

	mutex_init(&subsys->su_mutex);
	ret = configfs_register_subsystem(subsys);

	if (ret) {
		printk(KERN_ERR "Error %d on registering subsystem %s\n",
		  ret, subsys->su_group.cg_item.ci_namebuf);
		goto fail_init;
	}

	g_iscsi_cmd_ovslt_cnt_group = &subsys->su_group;

	g_ovslt_module = kzalloc(sizeof(struct iscsi_cmd_ovslt_cnt_module), GFP_KERNEL);
	if (!g_ovslt_module)
		return ERR_PTR(-ENOMEM);
	else
		init_all_var();

	__QNAP_ovslt_mod_get_enable(iscsi_cmd_ovslt_cnt_exec_get_enable);
	__QNAP_ovslt_mod_statistics(iscsi_cmd_ovslt_cnt_exec_statistics);

	return 0;

fail_init:
	configfs_unregister_subsystem(subsys);
	return ret;
}

static void __exit iscsi_cmd_ovslt_cnt_configfs_exit(void)
{
	struct list_head *entry, *tmp;

	pr_info("[ISCSI_CMD_OVSLT_CNT] iscsi_target_qcmd_ovslt_cnt.ko %s\n", __func__);

	if (g_ovslt_module) {
		kfree(g_ovslt_module);
		g_ovslt_module = NULL;
	}

	if (g_iscsi_cmd_ovslt_cnt_group) {
		list_for_each_safe(entry, tmp, &g_iscsi_cmd_ovslt_cnt_group->cg_children) {
			struct config_item *item = to_item(entry);
			config_item_put(item);
		}
	}
	mutex_destroy(&iscsi_cmd_ovslt_cnt_group_subsys.su_mutex);
	configfs_unregister_subsystem(&iscsi_cmd_ovslt_cnt_group_subsys);
}

MODULE_VERSION("0.2");
MODULE_AUTHOR("williamchang@qnap.com");
MODULE_LICENSE("GPL");

module_init(iscsi_cmd_ovslt_cnt_configfs_init);
module_exit(iscsi_cmd_ovslt_cnt_configfs_exit);
