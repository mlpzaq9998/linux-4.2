/*
 * Shared support code for AMD K8 northbridges and derivates.
 * Copyright 2006 Andi Kleen, SUSE Labs. Subject to GPLv2.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/types.h>
#include <linux/slab.h>
#include <linux/init.h>
#include <linux/errno.h>
#include <linux/module.h>
#include <linux/spinlock.h>
#include <asm/amd_nb.h>

#define PCI_DEVICE_ID_AMD_17H_ROOT     0x1450
#define PCI_DEVICE_ID_AMD_17H_DF_F3    0x1463
#define PCI_DEVICE_ID_AMD_17H_DF_F4    0x1464

static DEFINE_MUTEX(smn_mutex);

static u32 *flush_words;

static const struct pci_device_id amd_root_ids[] = {
       { PCI_DEVICE(PCI_VENDOR_ID_AMD, PCI_DEVICE_ID_AMD_17H_ROOT) },
       {}
};

const struct pci_device_id amd_nb_misc_ids[] = {
	{ PCI_DEVICE(PCI_VENDOR_ID_AMD, PCI_DEVICE_ID_AMD_K8_NB_MISC) },
	{ PCI_DEVICE(PCI_VENDOR_ID_AMD, PCI_DEVICE_ID_AMD_10H_NB_MISC) },
	{ PCI_DEVICE(PCI_VENDOR_ID_AMD, PCI_DEVICE_ID_AMD_15H_NB_F3) },
	{ PCI_DEVICE(PCI_VENDOR_ID_AMD, PCI_DEVICE_ID_AMD_15H_M10H_F3) },
	{ PCI_DEVICE(PCI_VENDOR_ID_AMD, PCI_DEVICE_ID_AMD_15H_M30H_NB_F3) },
	{ PCI_DEVICE(PCI_VENDOR_ID_AMD, PCI_DEVICE_ID_AMD_15H_M60H_NB_F3) },
	{ PCI_DEVICE(PCI_VENDOR_ID_AMD, PCI_DEVICE_ID_AMD_16H_NB_F3) },
	{ PCI_DEVICE(PCI_VENDOR_ID_AMD, PCI_DEVICE_ID_AMD_16H_M30H_NB_F3) },
	{ PCI_DEVICE(PCI_VENDOR_ID_AMD, PCI_DEVICE_ID_AMD_17H_DF_F3) },
	{}
};
EXPORT_SYMBOL(amd_nb_misc_ids);

static const struct pci_device_id amd_nb_link_ids[] = {
	{ PCI_DEVICE(PCI_VENDOR_ID_AMD, PCI_DEVICE_ID_AMD_15H_NB_F4) },
	{ PCI_DEVICE(PCI_VENDOR_ID_AMD, PCI_DEVICE_ID_AMD_15H_M30H_NB_F4) },
	{ PCI_DEVICE(PCI_VENDOR_ID_AMD, PCI_DEVICE_ID_AMD_15H_M60H_NB_F4) },
	{ PCI_DEVICE(PCI_VENDOR_ID_AMD, PCI_DEVICE_ID_AMD_16H_NB_F4) },
	{ PCI_DEVICE(PCI_VENDOR_ID_AMD, PCI_DEVICE_ID_AMD_16H_M30H_NB_F4) },
	{ PCI_DEVICE(PCI_VENDOR_ID_AMD, PCI_DEVICE_ID_AMD_17H_DF_F4) },
	{}
};

const struct amd_nb_bus_dev_range amd_nb_bus_dev_ranges[] __initconst = {
	{ 0x00, 0x18, 0x20 },
	{ 0xff, 0x00, 0x20 },
	{ 0xfe, 0x00, 0x20 },
	{ }
};

struct amd_northbridge_info amd_northbridges;
EXPORT_SYMBOL(amd_northbridges);

static struct pci_dev *next_northbridge(struct pci_dev *dev,
					const struct pci_device_id *ids)
{
	do {
		dev = pci_get_device(PCI_ANY_ID, PCI_ANY_ID, dev);
		if (!dev)
			break;
	} while (!pci_match_id(ids, dev));
	return dev;
}

/*
 * + * Data Fabric Indirect Access uses FICAA/FICAD.
 * + *
 * + * Fabric Indirect Configuration Access Address (FICAA): Constructed based
 * + * on the device's Instance Id and the PCI function and register offset of
 * + * the desired register.
 * + *
 * + * Fabric Indirect Configuration Access Data (FICAD): There are FICAD LO
 * + * and FICAD HI registers but so far we only need the LO register.
 * + */
int amd_df_indirect_read(u16 node, u8 func, u16 reg, u8 instance_id, u32 *lo)
{
	struct pci_dev *F4;
	u32 ficaa;
	int err = -ENODEV;

	if (node >= amd_northbridges.num)
		goto out;

	F4 = node_to_amd_nb(node)->link;
	if (!F4)
		goto out;

	ficaa  = 1;
	ficaa |= reg & 0x3FC;
	ficaa |= (func & 0x7) << 11;
	ficaa |= instance_id << 16;

	mutex_lock(&smn_mutex);

	err = pci_write_config_dword(F4, 0x5C, ficaa);
	if (err) {
		pr_warn("Error writing DF Indirect FICAA, FICAA=0x%x\n", ficaa);
		goto out_unlock;
	}

	err = pci_read_config_dword(F4, 0x98, lo);
	if (err)
		pr_warn("Error reading DF Indirect FICAD LO, FICAA=0x%x.\n", ficaa);

out_unlock:
	 mutex_unlock(&smn_mutex);

out:
	return err;
}
EXPORT_SYMBOL_GPL(amd_df_indirect_read);

int amd_cache_northbridges(void)
{
	u16 i = 0;
	struct amd_northbridge *nb;
#ifdef X86_SUMMITRIDGE
		struct pci_dev *root, *misc, *link;
#else
		struct pci_dev *misc, *link;
#endif

	if (amd_nb_num())
		return 0;

	misc = NULL;
	while ((misc = next_northbridge(misc, amd_nb_misc_ids)) != NULL)
		i++;

	if (i == 0)
		return 0;

	nb = kzalloc(i * sizeof(struct amd_northbridge), GFP_KERNEL);
	if (!nb)
		return -ENOMEM;

	amd_northbridges.nb = nb;
	amd_northbridges.num = i;
#ifdef X86_SUMMITRIDGE
	link = misc = root = NULL;
#else
	link = misc = NULL;
#endif

	link = misc = NULL;
	for (i = 0; i != amd_nb_num(); i++) {
#ifdef X86_SUMMITRIDGE
		node_to_amd_nb(i)->root = root =
			next_northbridge(root, amd_root_ids);
#endif
		node_to_amd_nb(i)->misc = misc =
			next_northbridge(misc, amd_nb_misc_ids);
		node_to_amd_nb(i)->link = link =
			next_northbridge(link, amd_nb_link_ids);
	}

	if (amd_gart_present())
		amd_northbridges.flags |= AMD_NB_GART;

	/*
	 * Check for L3 cache presence.
	 */
	if (!cpuid_edx(0x80000006))
		return 0;

	/*
	 * Some CPU families support L3 Cache Index Disable. There are some
	 * limitations because of E382 and E388 on family 0x10.
	 */
	if (boot_cpu_data.x86 == 0x10 &&
	    boot_cpu_data.x86_model >= 0x8 &&
	    (boot_cpu_data.x86_model > 0x9 ||
	     boot_cpu_data.x86_mask >= 0x1))
		amd_northbridges.flags |= AMD_NB_L3_INDEX_DISABLE;

	if (boot_cpu_data.x86 == 0x15)
		amd_northbridges.flags |= AMD_NB_L3_INDEX_DISABLE;

	/* L3 cache partitioning is supported on family 0x15 */
	if (boot_cpu_data.x86 == 0x15)
		amd_northbridges.flags |= AMD_NB_L3_PARTITIONING;

	return 0;
}
EXPORT_SYMBOL_GPL(amd_cache_northbridges);

/*
 * Ignores subdevice/subvendor but as far as I can figure out
 * they're useless anyways
 */
bool __init early_is_amd_nb(u32 device)
{
	const struct pci_device_id *id;
	u32 vendor = device & 0xffff;

	device >>= 16;
	for (id = amd_nb_misc_ids; id->vendor; id++)
		if (vendor == id->vendor && device == id->device)
			return true;
	return false;
}

struct resource *amd_get_mmconfig_range(struct resource *res)
{
	u32 address;
	u64 base, msr;
	unsigned segn_busn_bits;

	if (boot_cpu_data.x86_vendor != X86_VENDOR_AMD)
		return NULL;

	/* assume all cpus from fam10h have mmconfig */
        if (boot_cpu_data.x86 < 0x10)
		return NULL;

	address = MSR_FAM10H_MMIO_CONF_BASE;
	rdmsrl(address, msr);

	/* mmconfig is not enabled */
	if (!(msr & FAM10H_MMIO_CONF_ENABLE))
		return NULL;

	base = msr & (FAM10H_MMIO_CONF_BASE_MASK<<FAM10H_MMIO_CONF_BASE_SHIFT);

	segn_busn_bits = (msr >> FAM10H_MMIO_CONF_BUSRANGE_SHIFT) &
			 FAM10H_MMIO_CONF_BUSRANGE_MASK;

	res->flags = IORESOURCE_MEM;
	res->start = base;
	res->end = base + (1ULL<<(segn_busn_bits + 20)) - 1;
	return res;
}

int amd_get_subcaches(int cpu)
{
	struct pci_dev *link = node_to_amd_nb(amd_get_nb_id(cpu))->link;
	unsigned int mask;
	int cuid;

	if (!amd_nb_has_feature(AMD_NB_L3_PARTITIONING))
		return 0;

	pci_read_config_dword(link, 0x1d4, &mask);

	cuid = cpu_data(cpu).compute_unit_id;
#ifdef X86_SUMMITRIDGE
	printk("%s:%s:%d, %d\n", __FILE__, __func__, __LINE__, cpu_data(cpu).cpu_core_id);
	return (mask >> (4 * cpu_data(cpu).cpu_core_id)) & 0xf;
#else
	return (mask >> (4 * cuid)) & 0xf;
#endif
}

int amd_set_subcaches(int cpu, unsigned long mask)
{
	static unsigned int reset, ban;
	struct amd_northbridge *nb = node_to_amd_nb(amd_get_nb_id(cpu));
	unsigned int reg;
	int cuid;

	if (!amd_nb_has_feature(AMD_NB_L3_PARTITIONING) || mask > 0xf)
		return -EINVAL;

	/* if necessary, collect reset state of L3 partitioning and BAN mode */
	if (reset == 0) {
		pci_read_config_dword(nb->link, 0x1d4, &reset);
		pci_read_config_dword(nb->misc, 0x1b8, &ban);
		ban &= 0x180000;
	}

	/* deactivate BAN mode if any subcaches are to be disabled */
	if (mask != 0xf) {
		pci_read_config_dword(nb->misc, 0x1b8, &reg);
		pci_write_config_dword(nb->misc, 0x1b8, reg & ~0x180000);
	}

#ifdef X86_SUMMITRIDGE
	printk("%s:%s:%d, %d\n", __FILE__, __func__, __LINE__, cpu_data(cpu).cpu_core_id);
	cuid = cpu_data(cpu).cpu_core_id;
#else
	cuid = cpu_data(cpu).compute_unit_id;
#endif
	mask <<= 4 * cuid;
	mask |= (0xf ^ (1 << cuid)) << 26;

	pci_write_config_dword(nb->link, 0x1d4, mask);

	/* reset BAN mode if L3 partitioning returned to reset state */
	pci_read_config_dword(nb->link, 0x1d4, &reg);
	if (reg == reset) {
		pci_read_config_dword(nb->misc, 0x1b8, &reg);
		reg &= ~0x180000;
		pci_write_config_dword(nb->misc, 0x1b8, reg | ban);
	}

	return 0;
}

static int amd_cache_gart(void)
{
	u16 i;

       if (!amd_nb_has_feature(AMD_NB_GART))
               return 0;

       flush_words = kmalloc(amd_nb_num() * sizeof(u32), GFP_KERNEL);
       if (!flush_words) {
               amd_northbridges.flags &= ~AMD_NB_GART;
               return -ENOMEM;
       }

       for (i = 0; i != amd_nb_num(); i++)
               pci_read_config_dword(node_to_amd_nb(i)->misc, 0x9c,
                                     &flush_words[i]);

       return 0;
}

void amd_flush_garts(void)
{
	int flushed, i;
	unsigned long flags;
	static DEFINE_SPINLOCK(gart_lock);

	if (!amd_nb_has_feature(AMD_NB_GART))
		return;

	/* Avoid races between AGP and IOMMU. In theory it's not needed
	   but I'm not sure if the hardware won't lose flush requests
	   when another is pending. This whole thing is so expensive anyways
	   that it doesn't matter to serialize more. -AK */
	spin_lock_irqsave(&gart_lock, flags);
	flushed = 0;
	for (i = 0; i < amd_nb_num(); i++) {
		pci_write_config_dword(node_to_amd_nb(i)->misc, 0x9c,
				       flush_words[i] | 1);
		flushed++;
	}
	for (i = 0; i < amd_nb_num(); i++) {
		u32 w;
		/* Make sure the hardware actually executed the flush*/
		for (;;) {
			pci_read_config_dword(node_to_amd_nb(i)->misc,
					      0x9c, &w);
			if (!(w & 1))
				break;
			cpu_relax();
		}
	}
	spin_unlock_irqrestore(&gart_lock, flags);
	if (!flushed)
		pr_notice("nothing to flush?\n");
}
EXPORT_SYMBOL_GPL(amd_flush_garts);

static __init int init_amd_nbs(void)
{
	int err = 0;

	err = amd_cache_northbridges();

	if (err < 0)
		pr_notice("Cannot enumerate AMD northbridges\n");

	if (amd_cache_gart() < 0)
		pr_notice("Cannot initialize GART flush words, GART support disabled\n");

	return err;
}

/* This has to go after the PCI subsystem */
fs_initcall(init_amd_nbs);
