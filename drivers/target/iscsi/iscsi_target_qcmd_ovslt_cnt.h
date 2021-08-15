#ifndef ISCSI_CMD_OVSLT_CNT_H
#define ISCSI_CMD_OVSLT_CNT_H

#include <scsi/scsi_proto.h>

#define MAX_CMD_INFO_SIZE		100

/* BIT for ENABLE */
enum ENABLE{
	ISCSI_CMD_SBC_OVSLT_CNT = 0,
	ISCSI_CMD_SPC_OVSLT_CNT,
	ISCSI_CMD_TRASPRT_OVSLT_CNT,
	ISCSI_CMD_READ_OVSLT_CNT,
	ISCSI_CMD_WRITE_OVSLT_CNT,
	ISCSI_CMD_UNMAP_OVSLT_CNT,
	ISCSI_CMD_WRITE_SAME_OVSLT_CNT,
};

/* BIT for CMD_IDX */
enum CMD_IDX{
	READ_6_IDX = 0,
	READ_10_IDX,
	READ_12_IDX,
	READ_16_IDX,
	READ_32_IDX,
	WRITE_6_IDX,
	WRITE_10_IDX,
	WRITE_12_IDX,
	WRITE_16_IDX,
	WRITE_32_IDX,
	UNMAP_IDX,
	WRITE_SAME_IDX,
	WRITE_SAME_16_IDX,
	WRITE_SAME_32_IDX,
	MAX_LATENCY_INFO_SIZE,
};

/* struct for cmd info */
struct iscsi_cmd_ovslt_cnt_cmd {
	unsigned char cmd_opcode;
	unsigned long cmd_total_elapsed_time;
	unsigned long cmd_sbc_elapsed_time;
	unsigned long cmd_spc_elapsed_time;
	unsigned long cmd_trasprt_elapsed_time;
};

/* struct for latency info */
struct iscsi_cmd_ovslt_cnt_latency {
	char cmd_name[20];
	unsigned char cmd_opcode;
	int cmd_ovslt_cnt;
	unsigned long cmd_maxlaty;
	struct timex cmd_maxlaty_exestatm;
};

/* struct for module */
struct iscsi_cmd_ovslt_cnt_module
{
	unsigned int enable;
	unsigned long cmd_timeslot_setting;
	int cmd_cnt;
	struct iscsi_cmd_ovslt_cnt_cmd cmd_info[MAX_CMD_INFO_SIZE];
	struct iscsi_cmd_ovslt_cnt_latency latency_info[MAX_LATENCY_INFO_SIZE];
};

static void init_all_var(void);

static void iscsi_cmd_ovslt_cnt_dump_parameters(void);
static void iscsi_cmd_ovslt_cnt_dump_cmd_ovslt_cnt_cmd_info(void);
static void iscsi_cmd_ovslt_cnt_dump_cmd_ovslt_cnt_latency_info(void);

unsigned long iscsi_cmd_ovslt_cnt_exec_get_enable(void);
unsigned long get_cmd_timeslot_setting(void);
int set_cmd_opcode(unsigned char cmd_opcode);
int set_cmd_sbc_elapsed_time(unsigned long cmd_sbc_elapsed_time);
int set_cmd_spc_elapsed_time(unsigned long cmd_spc_elapsed_time);
int set_cmd_trasprt_elapsed_time(unsigned long cmd_trasprt_elapsed_time);

int iscsi_cmd_ovslt_cnt_exec_statistics(unsigned char *cmd_opcode,
										  unsigned long cmd_trasprt_begin_time,
										  unsigned long cmd_trasprt_end_time,
										  struct timex cmd_txc);

int cal_read_6_cmd_ovslt_cnt(void);
int cal_read_10_cmd_ovslt_cnt(void);
int cal_read_12_cmd_ovslt_cnt(void);
int cal_read_16_cmd_ovslt_cnt(void);
int cal_read_32_cmd_ovslt_cnt(void);
int cal_write_6_cmd_ovslt_cnt(void);
int cal_write_10_cmd_ovslt_cnt(void);
int cal_write_12_cmd_ovslt_cnt(void);
int cal_write_16_cmd_ovslt_cnt(void);
int cal_write_32_cmd_ovslt_cnt(void);
int cal_unmap_cmd_ovslt_cnt(void);
int cal_write_same_cmd_ovslt_cnt(void);
int cal_write_same_16_cmd_ovslt_cnt(void);
int cal_write_same_32_cmd_ovslt_cnt(void);

int set_read_6_cmd_maxlaty(unsigned long read_6_cmd_maxlaty);
int set_read_10_cmd_maxlaty(unsigned long read_10_cmd_maxlaty);
int set_read_12_cmd_maxlaty(unsigned long read_12_cmd_maxlaty);
int set_read_16_cmd_maxlaty(unsigned long read_16_cmd_maxlaty);
int set_read_32_cmd_maxlaty(unsigned long read_32_cmd_maxlaty);
int set_write_6_cmd_maxlaty(unsigned long write_6_cmd_maxlaty);
int set_write_10_cmd_maxlaty(unsigned long write_10_cmd_maxlaty);
int set_write_12_cmd_maxlaty(unsigned long write_12_cmd_maxlaty);
int set_write_16_cmd_maxlaty(unsigned long write_16_cmd_maxlaty);
int set_write_32_cmd_maxlaty(unsigned long write_32_cmd_maxlaty);
int set_unmap_cmd_maxlaty(unsigned long unmap_cmd_maxlaty);
int set_write_same_cmd_maxlaty(unsigned long write_same_cmd_maxlaty);
int set_write_same_16_cmd_maxlaty(unsigned long write_same_16_cmd_maxlaty);
int set_write_same_32_cmd_maxlaty(unsigned long write_same_32_cmd_maxlaty);

int set_read_6_cmd_maxlaty_exestatm(struct timex read_6_cmd_maxlaty_txc);
int set_read_10_cmd_maxlaty_exestatm(struct timex read_10_cmd_maxlaty_txc);
int set_read_12_cmd_maxlaty_exestatm(struct timex read_12_cmd_maxlaty_txc);
int set_read_16_cmd_maxlaty_exestatm(struct timex read_16_cmd_maxlaty_txc);
int set_read_32_cmd_maxlaty_exestatm(struct timex read_32_cmd_maxlaty_txc);
int set_write_6_cmd_maxlaty_exestatm(struct timex write_6_cmd_maxlaty_txc);
int set_write_10_cmd_maxlaty_exestatm(struct timex write_10_cmd_maxlaty_txc);
int set_write_12_cmd_maxlaty_exestatm(struct timex write_12_cmd_maxlaty_txc);
int set_write_16_cmd_maxlaty_exestatm(struct timex write_16_cmd_maxlaty_txc);
int set_write_32_cmd_maxlaty_exestatm(struct timex write_32_cmd_maxlaty_txc);
int set_unmap_cmd_maxlaty_exestatm(struct timex unmap_cmd_maxlaty_txc);
int set_write_same_cmd_maxlaty_exestatm(struct timex write_same_cmd_maxlaty_txc);
int set_write_same_16_cmd_maxlaty_exestatm(struct timex write_same_16_cmd_maxlaty_txc);
int set_write_same_32_cmd_maxlaty_exestatm(struct timex write_same_32_cmd_maxlaty_txc);

#define ISCSI_CMD_OVSLT_CNT_ENABLE(en, bit)	  en&(0x1 << bit)

#define ISCSI_CMD_SBC_OVSLT_CNT_ENABLE(en)	  ISCSI_CMD_OVSLT_CNT_ENABLE(en, ISCSI_CMD_SBC_OVSLT_CNT)
#define ISCSI_CMD_SPC_OVSLT_CNT_ENABLE(en)	  ISCSI_CMD_OVSLT_CNT_ENABLE(en, ISCSI_CMD_SPC_OVSLT_CNT)
#define ISCSI_CMD_TRASPRT_OVSLT_CNT_ENABLE(en)	  ISCSI_CMD_OVSLT_CNT_ENABLE(en, ISCSI_CMD_TRASPRT_OVSLT_CNT)
#define ISCSI_CMD_READ_OVSLT_CNT_ENABLE(en)    ISCSI_CMD_OVSLT_CNT_ENABLE(en, ISCSI_CMD_READ_OVSLT_CNT)
#define ISCSI_CMD_WRITE_OVSLT_CNT_ENABLE(en)    ISCSI_CMD_OVSLT_CNT_ENABLE(en, ISCSI_CMD_WRITE_OVSLT_CNT)
#define ISCSI_CMD_UNMAP_OVSLT_CNT_ENABLE(en)    ISCSI_CMD_OVSLT_CNT_ENABLE(en, ISCSI_CMD_UNMAP_OVSLT_CNT)
#define ISCSI_CMD_WRITE_SAME_OVSLT_CNT_ENABLE(en)    ISCSI_CMD_OVSLT_CNT_ENABLE(en, ISCSI_CMD_WRITE_SAME_OVSLT_CNT)

#endif /* ISCSI_CMD_OVSLT_CNT_H */
