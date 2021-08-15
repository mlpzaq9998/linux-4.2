
subdir-ccflags-y += -Iinclude/drm  \
		-Idrivers/gpu/drm_amd/amd/powerplay/inc/  \
		-Idrivers/gpu/drm_amd/amd/include/asic_reg  \
		-Idrivers/gpu/drm_amd/amd/include  \
		-Idrivers/gpu/drm_amd/amd/powerplay/smumgr\
		-Idrivers/gpu/drm_amd/amd/powerplay/hwmgr \
		-Idrivers/gpu/drm_amd/amd/powerplay/eventmgr

AMD_PP_PATH = ../powerplay

PP_LIBS = smumgr hwmgr eventmgr

AMD_POWERPLAY = $(addsuffix /Makefile,$(addprefix drivers/gpu/drm_amd/amd/powerplay/,$(PP_LIBS)))

include $(AMD_POWERPLAY)

POWER_MGR = amd_powerplay.o

AMD_PP_POWER = $(addprefix $(AMD_PP_PATH)/,$(POWER_MGR))

AMD_POWERPLAY_FILES += $(AMD_PP_POWER)
