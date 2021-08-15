#ifndef ISCSI_ERROR_INJECTION_H
#define ISCSI_ERROR_INJECTION_H

// struct for ops
struct iscsi_error_injection_ops {
	int (*rx_delay_process)(char *target_name, char *initiator_name, int lun_num, int cid);
	int (*tx_delay_process)(char *target_name, char *initiator_name, int lun_num, int cid);
	int (*random_drop)(char *target_name, char *initiator_name, int lun_num, int cid);
};

//BIT for ENABLE
enum {
	ISCSI_ERROR_INJECTION_DELAY_PROCESS = 0,
	ISCSI_ERROR_INJECTION_RANDOM_DROP,
	ISCSI_ERROR_INJECTION_TX_DELAY_PROCESS,
};

#define ISCSI_ERROR_INJECTION_RANDOM_BOUNDARY	256 //0~255

#define ISCSI_ERROR_INJECTION_ENABLE(en, bit)	  en&(0x1 << bit)

#define ISCSI_ERROR_INJECTION_DELAY_PROCESS_ENABLE(en)	  ISCSI_ERROR_INJECTION_ENABLE(en, ISCSI_ERROR_INJECTION_DELAY_PROCESS)
#define ISCSI_ERROR_INJECTION_RANDOM_DROP_ENABLE(en)  ISCSI_ERROR_INJECTION_ENABLE(en, ISCSI_ERROR_INJECTION_RANDOM_DROP)
#define ISCSI_ERROR_INJECTION_TX_DELAY_PROCESS_ENABLE(en)	  ISCSI_ERROR_INJECTION_ENABLE(en, ISCSI_ERROR_INJECTION_TX_DELAY_PROCESS)

#define ISCSI_ERROR_INJECTION_CHECK_LUN_SETTING(lun, lun_num)	lun&(0x1 << lun_num)
#define ISCSI_ERROR_INJECTION_CHECK_CID_SETTING(cid, cid_num)	cid&(0x1 << cid_num)

int iscsi_error_injection_get_enable(void);
int iscsi_error_injection_get_delay(void);
int iscsi_error_injection_get_level(void);
int iscsi_error_injection_get_lun(void);
int iscsi_error_injection_exec_delay_process(char *target_name, char *initiator_name, int lun_num, int cid);
int iscsi_error_injection_exec_random_drop(char *target_name, char *initiator_name, int lun_num, int cid);
int iscsi_error_injection_exec_tx_delay_process(char *target_name, char *initiator_name, int lun_num, int cid);

#endif /* ISCSI_ERROR_INJECTION_H */
