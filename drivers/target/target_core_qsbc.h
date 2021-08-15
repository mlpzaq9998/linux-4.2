#ifndef TARGET_CORE_QSBC_H
#define TARGET_CORE_QSBC_H

#define PROVISIONING_GROUP_DESC_LEN	(20)

typedef enum{
	VPD_B2h_PROVISION_TYPE_NONE = 0x0 , // not report provisioning type
	VPD_B2h_PROVISION_TYPE_RP         , // provisioning type is resource provisioning
	VPD_B2h_PROVISION_TYPE_TP         , // provisioning type is thin provisioning
	MAX_VPD_B2h_PROVISION_TYPE        ,
}VPD_B2h_PROVISION_TYPE;


/** 
 * @enum      THRESHOLD_TYPE
 * @brief     Define threshold type value
 */
typedef enum{
	THRESHOLD_TYPE_SOFTWARE = 0x0 ,
	MAX_THRESHOLD_TYPE            ,
} THRESHOLD_TYPE;

/** 
 * @enum      THRESHOLD_ARM_TYPE
 * @brief     THRESHOLD_ARM_XXX defines which type will be triggerred when resource was changed
 */
typedef enum{
	THRESHOLD_ARM_DESC = 0x0,
	THRESHOLD_ARM_INC       ,
	MAX_THRESHOLD_ARM_TYPE  ,
} THRESHOLD_ARM_TYPE;

/** 
 * @enum      LBP_LOG_PARAMS_TYPE
 * @brief     Define the logical block provisioning parameter type
 */
typedef enum{
	LBP_LOG_PARAMS_AVAILABLE_LBA_MAP_RES_COUNT      = 0x001,
	LBP_LOG_PARAMS_USED_LBA_MAP_RES_COUNT           = 0x002,
	LBP_LOG_PARAMS_DEDUPLICATED_LBA_MAP_RES_COUNT   = 0x100,
	LBP_LOG_PARAMS_COMPRESSED_LBA_MAP_RES_COUNT     = 0x101,
	LBP_LOG_PARAMS_TOTAL_LBA_MAP_RES_COUNT          = 0x102,
    MAX_LBP_LOG_PARAMS_TYPE,
}LBP_LOG_PARAMS_TYPE;

/* sbc3r35j, page 116 */
typedef struct lba_status_desc{
	u8	lba[8];
	u8	nr_blks[4];
	u8	provisioning_status:4;
	u8	reserved0:4;
	u8	reserved1[3];
} __attribute__ ((packed)) LBA_STATUS_DESC;


sense_reason_t qnap_sbc_write_same_fast_zero(struct se_cmd *se_cmd);
sense_reason_t qnap_sbc_get_lba_status(struct se_cmd *se_cmd);
sense_reason_t qnap_sbc_unmap(struct se_cmd *se_cmd, sector_t lba, 
	sector_t nolb);

unsigned int qnap_sbc_get_io_min(struct se_device *se_dev);
unsigned int qnap_sbc_get_io_opt(struct se_device *se_dev);
int qnap_sbc_get_threshold_exp(struct se_device *se_dev);

#ifdef SUPPORT_TP
int qnap_sbc_config_tp_on_evpd_b2(struct se_device *se_dev, unsigned char *buf);
int qnap_sbc_modesense_lbp(struct se_cmd *se_cmd, u8 pc, unsigned char *p);
#endif

#endif
