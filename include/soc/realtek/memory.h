/*
 *  arch/arm/mach-rtk119x/include/mach/memory.h
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */
#ifndef __ASM_ARCH_MEMORY_H
#define __ASM_ARCH_MEMORY_H

#define RTK_FLAG_NONCACHED      (1U << 0)
#define RTK_FLAG_SCPUACC        (1U << 1)
#define RTK_FLAG_ACPUACC        (1U << 2)
#define RTK_FLAG_HWIPACC        (1U << 3)
#define RTK_FLAG_VE_SPEC        (1U << 4)
#define RTK_FLAG_SECURE_AUDIO   (1U << 5)
#define RTK_FLAG_DEAULT         (/*RTK_FLAG_NONCACHED | */RTK_FLAG_SCPUACC | RTK_FLAG_ACPUACC | RTK_FLAG_HWIPACC)

#define PLAT_PHYS_OFFSET        (0x00000000)
#define PLAT_MEM_SIZE           (512*1024*1024)

/* 0x00000000 ~ 0x0001efff */ // (X) ALL
#define SYS_BOOTCODE_MEMBASE    (PLAT_PHYS_OFFSET)
#define SYS_BOOTCODE_MEMSIZE    (0x00030000)
/* 0x0001f000 ~ 0x0001ffff */
#define RPC_COMM_PHYS           (0x0001F000)
#define RPC_COMM_SIZE           (0x00001000)
/* 0x00030000 ~ 0x000fffff */
#define RESERVED_832KB_PHYS     (0x00030000)
#define RESERVED_832KB_SIZE     (0x000D0000)
/* 0x02c00000 ~ 0x0e3fffff */
#define ION_MEDIA_HEAP_PHYS1    (0x02C00000)
#define ION_MEDIA_HEAP_SIZE1    (0x0D400000)//184MB
#define ION_MEDIA_HEAP_FLAG1    (RTK_FLAG_DEAULT)
/* 0x01b00000 ~ 0x01efffff */
#define ACPU_FIREWARE_PHYS      (0x01B00000)
#define ACPU_FIREWARE_SIZE      (0x00400000)
/* 0x02600000 ~ 0x02bfffff */ // 6MB
#ifndef CONFIG_FB_RTK
#define ION_AUDIO_HEAP_PHYS     (0x11000000)
#define ION_AUDIO_HEAP_SIZE     (0x0EC00000)
#define ION_AUDIO_HEAP_FLAG    (RTK_FLAG_DEAULT)
#else
#define ION_AUDIO_HEAP_PHYS     (0x10200000)
#define ION_AUDIO_HEAP_SIZE     (0x0F800000)
#define ION_AUDIO_HEAP_FLAG    (RTK_FLAG_DEAULT)
#endif
/* 0x01ffe000 ~ 0x02001fff */
#define RPC_RINGBUF_PHYS        (0x01ffe000)
#define RPC_RINGBUF_SIZE        (0x00004000)


#define GRAPHIC_FB_COUNT		(2)
#define GRAPHIC_FB_SIZE			(2*1024*1024*4*GRAPHIC_FB_COUNT)
/* 0x11000000 ~ 0x181fffff */
#ifndef CONFIG_FB_RTK
#define ION_MEDIA_HEAP_PHYS2    (0x20000000)
#define ION_MEDIA_HEAP_SIZE2    (0x00000000)//0MB
#define ION_MEDIA_HEAP_FLAG2    (RTK_FLAG_DEAULT)
/* 0x18200000 ~ 0x189fffff */
#define ION_MEDIA_HEAP_PHYS3    (ION_MEDIA_HEAP_PHYS2+ION_MEDIA_HEAP_SIZE2)
#define ION_MEDIA_HEAP_SIZE3    (0x00800000)//8MB
#define ION_MEDIA_HEAP_FLAG3    (RTK_FLAG_DEAULT|RTK_FLAG_VE_SPEC)
#else
#define ION_MEDIA_HEAP_PHYS2    (0x20000000)
#define ION_MEDIA_HEAP_HDMI_SIZE2   (0x05000000)//80MB
#define ION_MEDIA_HEAP_FLAG2    (RTK_FLAG_DEAULT)
#define ION_MEDIA_HEAP_PHYS3    (0x10100000)
#define ION_MEDIA_HEAP_SIZE3    (0x00800000)//8MB
#define ION_MEDIA_HEAP_FLAG3    (RTK_FLAG_DEAULT|RTK_FLAG_VE_SPEC)
/* 0x18200000 ~ 0x189fffff */
#endif


/* 0x32800000 ~ 0x3effffff */
#define ION_SECURE_HEAP_PHYS    (0x32800000)
#define ION_SECURE_HEAP_SIZE    (0x0c800000)//200MB
#define ION_SECURE_HEAP_FLAG    (RTK_FLAG_HWIPACC)
/* 0x10000000 ~ 0x10013fff */ // (X) ALL
#define ACPU_IDMEM_PHYS         (0x10000000)
#define ACPU_IDMEM_SIZE         (0x00014000)
/* 0x1fc00000 ~ 0x1fc00fff */ // (X) ALL
#define ACPU_BOOTCODE_PHYS      (0x1FC00000)
#define ACPU_BOOTCODE_SIZE      (0x00001000)
/* 0x80000000 ~ 0x80007fff */
#define PLAT_SECURE_PHYS        (0x80000000)
#define PLAT_SECURE_SIZE        (0x00008000)
/* 0x88100000 ~ 0x88107fff */
#define PLAT_NOR_PHYS           (0x88100000)
#define PLAT_NOR_SIZE           (0x00008000)
/* 0x98000000 ~ 0x981fffff */
#ifdef CONFIG_ARCH_RTD129X
#define RBUS_BASE_PHYS          (0x98000000)
#else
#define RBUS_BASE_PHYS          (0x18000000)
#endif
#define RBUS_BASE_SIZE          (0x00200000)

#define RBUS_BASE_VIRT          (0xFE000000)
//#define RPC_COMM_VIRT           (RBUS_BASE_VIRT+RBUS_BASE_SIZE)
//#define RPC_RINGBUF_VIRT        (0xFC7F8000+0x00004000)

#define ROOTFS_NORMAL_START     (0x02200000)
#define ROOTFS_NORMAL_SIZE      (0x00400000) //4MB
#define ROOTFS_NORMAL_END       (ROOTFS_NORMAL_START + ROOTFS_NORMAL_SIZE)

#define ROOTFS_RESCUE_START     (0x02200000)
#if 0
#define ROOTFS_RESCUE_SIZE      (0x00C00000) //12MB
#else
#define ROOTFS_RESCUE_SIZE      (0x00400000) //4MB
#endif
#define ROOTFS_RESCUE_END       (ROOTFS_NORMAL_START + ROOTFS_RESCUE_SIZE)

#define HW_LIMITATION_PHYS      (0x3FFFF000)
#define HW_LIMITATION_SIZE      (0x00001000) //4KB
#define HW_LIMITATION_START     (HW_LIMITATION_PHYS)
#define HW_LIMITATION_END       (HW_LIMITATION_START + HW_LIMITATION_SIZE)

#define HW_LIMITATION_3GB_PHYS  (0x7FFFF000) //for 3.0-GB case
#define HW_LIMITATION_3GB_SIZE  (0x00001000) //4KB
#define HW_LIMITATION_3GB_START (HW_LIMITATION_3GB_PHYS)
#define HW_LIMITATION_3GB_END   (HW_LIMITATION_3GB_START + HW_LIMITATION_3GB_SIZE)

#define HW_SECURE_RAM_PHYS      (0x80000000)
#define HW_SECURE_RAM_SIZE      (0x00008000) //32KB
#define HW_SECURE_RAM_START     (HW_SECURE_RAM_PHYS)
#define HW_SECURE_RAM_END       (HW_SECURE_RAM_START + HW_SECURE_RAM_SIZE)

#define HW_NOR_REMAP_PHYS       (0x88100000)
#define HW_NOR_REMAP_SIZE       (0x02000000) //32MB
#define HW_NOR_REMAP_START      (HW_NOR_REMAP_PHYS)
#define HW_NOR_REMAP_END        (HW_NOR_REMAP_START + HW_NOR_REMAP_SIZE)

#define HW_RBUS_PHYS            (0x98000000)
#define HW_RBUS_SIZE            (0x00200000) //2MB
#define HW_RBUS_START           (HW_RBUS_PHYS)
#define HW_RBUS_END             (HW_RBUS_START + HW_RBUS_SIZE)

#define HW_PCI1_MMAP_PHYS       (0xC0000000)
#define HW_PCI1_MMAP_SIZE       (0x01000000) //16MB
#define HW_PCI1_MMAP_START      (HW_PCI1_MMAP_PHYS)
#define HW_PCI1_MMAP_END        (HW_PCI1_MMAP_START + HW_PCI1_MMAP_START)

#define HW_PCI2_MMAP_PHYS       (0xC1000000)
#define HW_PCI2_MMAP_SIZE       (0x01000000) //16MB
#define HW_PCI2_MMAP_START      (HW_PCI2_MMAP_PHYS)
#define HW_PCI2_MMAP_END        (HW_PCI2_MMAP_START + HW_PCI2_MMAP_START)

#define HW_JTAG_GIC_RSV_PHYS    (0xFF000000)
#define HW_JTAG_GIC_RSV_SIZE    (0x00800000) //8MB
#define HW_JTAG_GIC_RSV_START   (HW_JTAG_GIC_RSV_PHYS)
#define HW_JTAG_GIC_RSV_END     (HW_JTAG_GIC_RSV_START + HW_JTAG_GIC_RSV_SIZE)
#endif
