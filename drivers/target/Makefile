
target_core_mod-y		:= target_core_configfs.o \
				   target_core_device.o \
				   target_core_fabric_configfs.o \
				   target_core_fabric_lib.o \
				   target_core_hba.o \
				   target_core_pr.o \
				   target_core_alua.o \
				   target_core_tmr.o \
				   target_core_tpg.o \
				   target_core_transport.o \
				   target_core_sbc.o \
				   target_core_spc.o \
				   target_core_ua.o \
				   target_core_rd.o \
				   target_core_stat.o \
				   target_core_xcopy.o

ifeq ($(QTS_CEPH),yes)
target_core_mod-y += target_core_cluster.o
endif

# define QNAP features
ccflags-$(CONFIG_MACH_QNAPTS) += -DCONFIG_MACH_QNAPTS -DISCSI_D4_INITIATOR -DSUPPORT_ISCSI_ZERO_COPY
ccflags-$(CONFIG_MACH_QNAPTS) += -I$(FBDISK_INCLUDE)

target_core_mod-$(CONFIG_MACH_QNAPTS)	+= target_core_qconfigfs.o \
				   target_core_qtransport.o \
				   target_core_qsbc.o \
				   target_core_qspc.o


ifeq ($(SUPPORT_FAST_BLOCK_CLONE),yes)
target_core_mod-$(CONFIG_MACH_QNAPTS)	+= target_core_qfbc.o
endif

obj-$(CONFIG_TARGET_CORE)	+= target_core_mod.o

# odx
target_core_mod-$(CONFIG_MACH_QNAPTS)	+= target_core_qodx.o \
				   target_core_qodx_core.o \
				   target_core_qodx_lib.o \
				   target_core_qodx_rb.o \
				   target_core_qodx_vpd.o \
				   target_core_qlib.o

# Subsystem modules
obj-$(CONFIG_TCM_IBLOCK)	+= target_core_iblock.o
obj-$(CONFIG_TCM_FILEIO)	+= target_core_file.o
obj-$(CONFIG_TCM_PSCSI)		+= target_core_pscsi.o
obj-$(CONFIG_TCM_USER2)		+= target_core_user.o
ifeq ($(QTS_CEPH),yes)
obj-$(CONFIG_TCM_RBD)		+= target_core_rbd.o
endif

# Fabric modules
obj-$(CONFIG_LOOPBACK_TARGET)	+= loopback/
obj-$(CONFIG_TCM_FC)		+= tcm_fc/
obj-$(CONFIG_ISCSI_TARGET)	+= iscsi/
obj-$(CONFIG_SBP_TARGET)	+= sbp/
