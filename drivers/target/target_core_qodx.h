#ifndef TARGET_CORE_QODX_H
#define TARGET_CORE_QODX_H


#include <linux/types.h>
#include <linux/kernel.h>
#include "target_core_qodx_scsi.h"

/**/
void qnap_odx_cmd_free(struct se_cmd *se_cmd);
void qnap_odx_se_cmd_init(struct se_cmd *se_cmd);
int qnap_odx_tpg_add_and_get(struct se_portal_group *se_tpg);
void qnap_odx_tpg_del(struct se_portal_group *se_tpg);

int qnap_odx_is_in_progress(struct se_cmd *se_cmd);
sense_reason_t qnap_odx_wut(struct se_cmd *se_cmd);
sense_reason_t qnap_odx_pt(struct se_cmd *se_cmd);
sense_reason_t qnap_odx_rrti(struct se_cmd *se_cmd);
sense_reason_t qnap_odx_emulate_evpd_8f(struct se_cmd *se_cmd, 
	unsigned char *buffer);

void qnap_odx_drop_cmd(struct se_cmd *se_cmd, int type);

void qnap_odx_is_to_cancel_token(struct se_cmd *se_cmd);

#endif

