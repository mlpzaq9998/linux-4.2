obj-$(CONFIG_ARCH_RTD129X) += rtd129x_restart.o
ifneq ($(CONFIG_DISABLE_REALTEK_SMP),)
else
	obj-$(CONFIG_ARCH_RTD129X) += rtd129x_spin_table.o
	obj-$(CONFIG_ARCH_RTD129X) += rtd129x_cpu_wrapper.o
	obj-$(CONFIG_ARCH_RTD129X) += rtd129x_cpu_hotplug.o
	obj-$(CONFIG_ARCH_RTD129X) += rtd129x_core_control.o
endif
obj-$(CONFIG_RTK_RBUS_BARRIER) += rtd129x_barrier.o
obj-$(CONFIG_RTK_MEM_REMAP) += rtd129x_memory_remap.o
obj-$(CONFIG_RTK_SUSPEND) += rtd129x_suspend.o
obj-$(CONFIG_RTK_SB2_MEM_TRASH_MONITOR) += rtd129x_sb2_dbg.o
obj-$(CONFIG_RTK_IR) += irda/
obj-$(CONFIG_RTK_RPC) += rpc/
obj-$(CONFIG_RTK_CODEC) += rtk_ve/
obj-$(CONFIG_RTK_ION) += rtk_ion_of.o
obj-$(CONFIG_RTK_FAN) += rtd129x_fan.o
obj-$(CONFIG_RTD_1295_HWNAT) += hw_nat/
obj-$(CONFIG_ARCH_RTD129X) += rtd129x_lockapi.o
