KBUILD_CFLAGS_KERNEL += -I$(srctree)/include/soc/alpine/ -I$(srctree)/drivers/mtd/nand/al/

# TODO: temp solution to allow include raid.h - will be removed after
# implementing read/write with dma support
KBUILD_CPPFLAGS += -I$(srctree)/drivers/dma/al

ifeq ($(CONFIG_ARCH_ALPINE),y)
KBUILD_CPPFLAGS += -I$(srctree)/drivers/dma/al
KBUILD_CPPFLAGS += -I$(srctree)/include/soc/alpine/
endif

obj-$(CONFIG_MTD_NAND_AL) += al-nand.o
al-nand-objs += al_nand.o
al-nand-objs += al_hal_nand.o
