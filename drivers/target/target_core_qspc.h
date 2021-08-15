#ifndef TARGET_CORE_QSPC_H
#define TARGET_CORE_QSPC_H

typedef struct _logsense_func_table{
	u8	page_code;
	u8	sub_page_code;
	int	(*logsense_func)(struct se_cmd *se_cmd, u8 *buf);
	int	end;
}__attribute__ ((packed)) LOGSENSE_FUNC_TABLE;

typedef struct lbp_log_parameter_format{
	u8  parameter_code[2];		// byte 0~1
	u8  format_and_linking:2;	// byte 2
	u8  tmc:2;
	u8  etc:1;
	u8  tsd:1;
	u8  obsolete:1;
	u8  du:1;
	u8  parameter_length;		// byte 3
	u8  resource_count[4];		// byte 4~7
	u8  scope:2;			// byte 8
	u8  reserved0:6;
	u8  reserved1[3];		// byte 9~11
}__attribute__ ((packed)) LBP_LOG_PARAMETER_FORMAT;

typedef struct threshold_desc_format{
	u8  threshold_arming:3;	// byte 0
	u8  threshold_type:3;
	u8  reserved0:1;
	u8  enabled:1;
	u8  threshold_resource;	// byte 1
	u8  reserved1[2];	// byte 2 ~ byte 3
	u8  threshold_count[4];	// byte 4 ~ byte 7
} __attribute__ ((packed)) THRESHOLD_DESC_FORMAT;



sense_reason_t qnap_spc_logsense(struct se_cmd *se_cmd);
sense_reason_t qnap_spc_emulate_modeselect(struct se_cmd *se_cmd); //11490
int qnap_spc_modesense_caching(struct se_cmd *se_cmd, u8 pc, u8 *p);//11490


#endif
