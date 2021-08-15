iscsi_target_mod-y +=		iscsi_target_parameters.o \
				iscsi_target_seq_pdu_list.o \
				iscsi_target_auth.o \
				iscsi_target_datain_values.o \
				iscsi_target_device.o \
				iscsi_target_erl0.o \
				iscsi_target_erl1.o \
				iscsi_target_erl2.o \
				iscsi_target_login.o \
				iscsi_target_nego.o \
				iscsi_target_nodeattrib.o \
				iscsi_target_tmr.o \
				iscsi_target_tpg.o \
				iscsi_target_util.o \
				iscsi_target.o \
				iscsi_target_configfs.o \
				iscsi_target_stat.o \
				iscsi_target_transport.o

# define QNAP features

iscsi_target_mod-$(CONFIG_MACH_QNAPTS) += iscsi_target_qconfigfs.o \
				iscsi_target_qtransport.o \

ifeq ($(ISCSI_ERROR_INJECTION), yes)
obj-$(CONFIG_ISCSI_ERROR_INJECTION) += iscsi_error_injection.o
endif
ifeq ($(ISCSI_CMD_OVSLT_CNT), yes)
obj-$(CONFIG_ISCSI_CMD_OVSLT_CNT) += iscsi_target_qcmd_ovslt_cnt.o
endif
obj-$(CONFIG_ISCSI_TARGET)	+= iscsi_target_mod.o


obj-$(CONFIG_ISCSI_TARGET)	+= iscsi_target_qlog.o

ccflags-$(CONFIG_MACH_QNAPTS) += -DCONFIG_MACH_QNAPTS -DCONFIG_QISCSI_LOG -DISCSI_D4_INITIATOR -DSUPPORT_ISCSI_ZERO_COPY
ccflags-$(CONFIG_MACH_QNAPTS) += -I$(ISCSI_LOGD_INCLUDE)
