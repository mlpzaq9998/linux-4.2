/*
 * Driver for Aquantia PHY
 *
 * Author: Shaohui Xie <Shaohui.Xie@freescale.com>
 *
 * Copyright 2015 Freescale Semiconductor, Inc.
 *
 * This file is licensed under the terms of the GNU General Public License
 * version 2.  This program is licensed "as is" without any warranty of any
 * kind, whether express or implied.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/delay.h>
#include <linux/mii.h>
#include <linux/ethtool.h>
#include <linux/phy.h>
#include <linux/mdio.h>
#include <linux/netdevice.h>
//#include <linux/delay.h>

#define PHY_ID_AQ1202	0x03a1b445
#define PHY_ID_AQ2104	0x03a1b460
#define PHY_ID_AQR105	0x03a1b4a2
#define PHY_ID_AQR405	0x03a1b4b0
#define PHY_ID_AQR112C  0x03a1b792


#define PHY_AQUANTIA_FEATURES	(SUPPORTED_10000baseT_Full | \
				 SUPPORTED_1000baseT_Full | \
				 SUPPORTED_100baseT_Full | \
				 PHY_DEFAULT_FEATURES)

#define PHY_AQR112C_FEATURES (SUPPORTED_2500baseX_Full | \
                 SUPPORTED_1000baseT_Full | SUPPORTED_1000baseT_Half | \
                 SUPPORTED_100baseT_Full | SUPPORTED_100baseT_Half | \
                 PHY_DEFAULT_FEATURES)

static int aquantia_config_aneg(struct phy_device *phydev)
{
#if defined(CONFIG_MACH_QNAPTS)
    if (phydev->drv)
    {
        if (phydev->drv->phy_id == PHY_ID_AQR112C)
        {
            phydev->supported = PHY_AQR112C_FEATURES;
            phydev->advertising = phydev->supported;
            return 0;
        }
    }
#endif

	phydev->supported = PHY_AQUANTIA_FEATURES;
	phydev->advertising = phydev->supported;

	return 0;
}

static int aquantia_aneg_done(struct phy_device *phydev)
{
	int reg;

	reg = phy_read_mmd(phydev, MDIO_MMD_AN, MDIO_STAT1);
	return (reg < 0) ? reg : (reg & BMSR_ANEGCOMPLETE);
}

static int aquantia_config_intr(struct phy_device *phydev)
{
	int err;

	if (phydev->interrupts == PHY_INTERRUPT_ENABLED) {
		err = phy_write_mmd(phydev, MDIO_MMD_AN, 0xd401, 1);
		if (err < 0)
			return err;

		err = phy_write_mmd(phydev, MDIO_MMD_VEND1, 0xff00, 1);
		if (err < 0)
			return err;

		err = phy_write_mmd(phydev, MDIO_MMD_VEND1, 0xff01, 0x1001);
	} else {
		err = phy_write_mmd(phydev, MDIO_MMD_AN, 0xd401, 0);
		if (err < 0)
			return err;

		err = phy_write_mmd(phydev, MDIO_MMD_VEND1, 0xff00, 0);
		if (err < 0)
			return err;

		err = phy_write_mmd(phydev, MDIO_MMD_VEND1, 0xff01, 0);
	}

	return err;
}

static int aquantia_ack_interrupt(struct phy_device *phydev)
{
	int reg;

	reg = phy_read_mmd(phydev, MDIO_MMD_AN, 0xcc01);
	return (reg < 0) ? reg : 0;
}

static int aquantia_read_status(struct phy_device *phydev)
{
	int reg;

	reg = phy_read_mmd(phydev, MDIO_MMD_AN, MDIO_STAT1);
	reg = phy_read_mmd(phydev, MDIO_MMD_AN, MDIO_STAT1);
	if (reg & MDIO_STAT1_LSTATUS)
		phydev->link = 1;
	else
		phydev->link = 0;

	reg = phy_read_mmd(phydev, MDIO_MMD_AN, 0xc800);
	mdelay(10);
	reg = phy_read_mmd(phydev, MDIO_MMD_AN, 0xc800);

	switch (reg) {
	case 0x9:
		phydev->speed = SPEED_2500;
		break;
	case 0x5:
		phydev->speed = SPEED_1000;
		break;
	case 0x3:
		phydev->speed = SPEED_100;
		break;
	case 0x7:
	default:
		phydev->speed = SPEED_10000;
		break;
	}
	phydev->duplex = DUPLEX_FULL;

	return 0;
}

#if defined(CONFIG_MACH_QNAPTS)
#define AQR112C_LOC_MAC_ADDR_32_47_OFFSET    (0xc339)
#define AQR112C_LOC_MAC_ADDR_16_31_OFFSET    (0xc33a)
#define AQR112C_LOC_MAC_ADDR_0_15_OFFSET     (0xc33b)

#define AQR112C_10G_BASET_CTRL    (0x20)
#define AQR112C_AN_VEN_PROV1    (0xc400)

#define AQR112C_GBE_PHY_RSI1_CTRL6    (0xc355)
#define AQR112C_GBE_PHY_RSI1_CTRL7    (0xc356)
#define AQR112C_GBE_PHY_RSI1_CTRL8    (0xc357)
#define AQR112C_AN_RSV_VEN_PROV1    (0xc410)
#define AQR112C_GBE_PHY_SGMII_TX_INT_MASK1    (0xf420)

#define AQR112C_GLOBAL_INT_CHIP_WIDE_STANDARD_MASK    (0xff00)
#define AQR112C_GLOBAL_INT_CHIP_WIDE_VEN_MASK    (0xff01)

#define AQR112C_GLOBAL_SYS_CONF_FOR_100M    (0x31b)
#define AQR112C_GLOBAL_SYS_CONF_FOR_1G    (0x31c)

#define AQR112C_AN_STANDARD_CTRL1    (0x0)
#define AQR112C_AN_RSV_VEN_STATUS3    (0xc812)
#define AQR112C_WOL_READY_BIT    (0x1)

static int aqr112c_set_wol(struct phy_device *phydev, struct ethtool_wolinfo *wol)
{
    struct net_device *ndev = phydev->attached_dev;
    struct device *dev = &phydev->dev;
    int err = 0;
    u16 value = 0;


    if (!ndev || !dev)
        return -ENODEV;

    if (wol->wolopts & WAKE_MAGIC)
	{
		// Set the MAC address for the PHY
		err = phy_write_mmd(phydev, MDIO_MMD_C22EXT, AQR112C_LOC_MAC_ADDR_32_47_OFFSET, (ndev->dev_addr[0] | (ndev->dev_addr[1] << 8)) & 0xffff);
		if (err < 0)
		{
			dev_err(dev, "Set the MAC address[15:0] for the PHY failed\n");
			return err;
		}
			
		err = phy_write_mmd(phydev, MDIO_MMD_C22EXT, AQR112C_LOC_MAC_ADDR_16_31_OFFSET, (ndev->dev_addr[2] | (ndev->dev_addr[3] << 8)) & 0xffff);
		if (err < 0)
		{
			dev_err(dev, "Set the MAC address[31:16] for the PHY failed\n");
			return err;
		}

		err = phy_write_mmd(phydev, MDIO_MMD_C22EXT, AQR112C_LOC_MAC_ADDR_0_15_OFFSET, (ndev->dev_addr[4] | (ndev->dev_addr[5] << 8)) & 0xffff);
		if (err < 0)
		{
			dev_err(dev, "Set the MAC address[31:16] for the PHY failed\n");
			return err;
		}


		// Disables all advertised speeds except for the WoL speed (100BASE-TX FD or 1000BASE-T)
		err = phy_write_mmd(phydev, MDIO_MMD_AN, AQR112C_10G_BASET_CTRL, 0x1);
		if (err < 0)
		{
			dev_err(dev, "Disables all advertised speeds except for the WoL speed failed\n");
			return err;
		}
		
		value =  phy_read_mmd(phydev, MDIO_MMD_AN, AQR112C_AN_VEN_PROV1);
		value &= ~0xff00;
		value |= 0x9000;
		err = phy_write_mmd(phydev, MDIO_MMD_AN, AQR112C_AN_VEN_PROV1, value);
		if (err < 0)
		{
			dev_err(dev, "Disables all advertised speeds except for the WoL speed failed\n");
			return err;
		}
		else
		{
			value =  phy_read_mmd(phydev, MDIO_MMD_AN, AQR112C_AN_VEN_PROV1);
			dev_err(dev, "Disables all advertised speeds except for the WoL, 0x%x.0x%x = 0x%x\n", MDIO_MMD_AN, AQR112C_AN_VEN_PROV1, value);
		}
			
		
		// Enable the magic frame and wake up frame detection for the PHY
		err = phy_write_mmd(phydev, MDIO_MMD_C22EXT, AQR112C_GBE_PHY_RSI1_CTRL6, 0x1);
		if (err < 0)
		{
			dev_err(dev, "Enable the magic frame and wake up frame detection for the PHY failed\n");
			return err;
		}

		err = phy_write_mmd(phydev, MDIO_MMD_C22EXT, AQR112C_GBE_PHY_RSI1_CTRL7, 0x1);
		if (err < 0)
		{
			dev_err(dev, "Enable the magic frame and wake up frame detection for the PHY failed\n");
			return err;
		}

		// Set the WoL enable bit
		value =  phy_read_mmd(phydev, MDIO_MMD_AN, AQR112C_AN_RSV_VEN_PROV1);
		value |= (0x1 << 6);
		err = phy_write_mmd(phydev, MDIO_MMD_AN, AQR112C_AN_RSV_VEN_PROV1, value);
		if (err < 0)
		{
			dev_err(dev, "Set the WoL enable bit failed\n");
			return err;
		}
		else
		{
			value =  phy_read_mmd(phydev, MDIO_MMD_AN, AQR112C_AN_RSV_VEN_PROV1);
			dev_err(dev, "Set the WoL enable bit, 0x%x.0x%x = 0x%x\n", MDIO_MMD_AN, AQR112C_AN_RSV_VEN_PROV1, value);
		}
		
		// Set the WoL INT_N trigger bit
		value =  phy_read_mmd(phydev, MDIO_MMD_C22EXT, AQR112C_GBE_PHY_RSI1_CTRL8);
		value |= (0x1 << 15);
		err = phy_write_mmd(phydev, MDIO_MMD_C22EXT, AQR112C_GBE_PHY_RSI1_CTRL8, value);
		if (err < 0)
		{
			dev_err(dev, "Set the WoL INT_N trigger bit failed\n");
			return err;
		}
		else
		{
			value =  phy_read_mmd(phydev, MDIO_MMD_C22EXT, AQR112C_GBE_PHY_RSI1_CTRL8);
			dev_err(dev, "Set the WoL INT_N trigger bit, 0x%x.0x%x = 0x%x\n", MDIO_MMD_C22EXT, AQR112C_GBE_PHY_RSI1_CTRL8, value);
		}
		
		// Optional: Enable Interrupt INT_N Generation at pin level
		value =  phy_read_mmd(phydev, MDIO_MMD_C22EXT, AQR112C_GBE_PHY_SGMII_TX_INT_MASK1);
		value |= (0x3 << 4);
		err = phy_write_mmd(phydev, MDIO_MMD_C22EXT, AQR112C_GBE_PHY_SGMII_TX_INT_MASK1, value);
		if (err < 0)
		{
			dev_err(dev, "Enable Interrupt INT_N Generation at pin level failed\n");
			return err;
		}
		else
		{
			value =  phy_read_mmd(phydev, MDIO_MMD_C22EXT, AQR112C_GBE_PHY_SGMII_TX_INT_MASK1);
			dev_err(dev, "Enable Interrupt INT_N Generation at pin level, 0x%x.0x%x = 0x%x\n", MDIO_MMD_C22EXT, AQR112C_GBE_PHY_SGMII_TX_INT_MASK1, value);
		}

		value =  phy_read_mmd(phydev, MDIO_MMD_VEND1, AQR112C_GLOBAL_INT_CHIP_WIDE_STANDARD_MASK);
		value |= 0x1;
		err = phy_write_mmd(phydev, MDIO_MMD_VEND1, AQR112C_GLOBAL_INT_CHIP_WIDE_STANDARD_MASK, value);
		if (err < 0)
		{
			dev_err(dev, "Enable Interrupt INT_N Generation at pin level failed\n");
			return err;
		}
		else
		{
			value =  phy_read_mmd(phydev, MDIO_MMD_VEND1, AQR112C_GLOBAL_INT_CHIP_WIDE_STANDARD_MASK);
			dev_err(dev, "Enable Interrupt INT_N Generation at pin level, 0x%x.0x%x = 0x%x\n", MDIO_MMD_VEND1, AQR112C_GLOBAL_INT_CHIP_WIDE_STANDARD_MASK, value);
		}

		value =  phy_read_mmd(phydev, MDIO_MMD_VEND1, AQR112C_GLOBAL_INT_CHIP_WIDE_VEN_MASK);
		value |= (0x1 << 11);
		err = phy_write_mmd(phydev, MDIO_MMD_VEND1, AQR112C_GLOBAL_INT_CHIP_WIDE_VEN_MASK, value);
		if (err < 0)
		{
			dev_err(dev, "Enable Interrupt INT_N Generation at pin level failed\n");
			return err;
		}
		else
		{
			value =  phy_read_mmd(phydev, MDIO_MMD_VEND1, AQR112C_GLOBAL_INT_CHIP_WIDE_VEN_MASK);
			dev_err(dev, "Enable Interrupt INT_N Generation at pin level, 0x%x.0x%x = 0x%x\n", MDIO_MMD_VEND1, AQR112C_GLOBAL_INT_CHIP_WIDE_VEN_MASK, value);
		}
		
		// Set the system interface to SGMII
		err = phy_write_mmd(phydev, MDIO_MMD_VEND1, AQR112C_GLOBAL_SYS_CONF_FOR_100M, 0xb);
		if (err < 0)
		{
			dev_err(dev, "Set the system interface to SGMII failed\n");
			return err;
		}
		else
		{
			value =  phy_read_mmd(phydev, MDIO_MMD_VEND1, AQR112C_GLOBAL_SYS_CONF_FOR_100M);
			dev_err(dev, "Set the system interface to SGMII, 0x%x.0x%x = 0x%x\n", MDIO_MMD_VEND1, AQR112C_GLOBAL_SYS_CONF_FOR_100M, value);
		}

		err = phy_write_mmd(phydev, MDIO_MMD_VEND1, AQR112C_GLOBAL_SYS_CONF_FOR_1G, 0xb);
		if (err < 0)
		{
			dev_err(dev, "Set the system interface to SGMII failed\n");
			return err;
		}
		else
		{
			value =  phy_read_mmd(phydev, MDIO_MMD_VEND1, AQR112C_GLOBAL_SYS_CONF_FOR_1G);
			dev_err(dev, "Set the system interface to SGMII, 0x%x.0x%x = 0x%x\n", MDIO_MMD_VEND1, AQR112C_GLOBAL_SYS_CONF_FOR_1G, value);
		}
		
		// Perform a link re-negotiation/auto-negotiation
		value =  phy_read_mmd(phydev, MDIO_MMD_AN, AQR112C_AN_STANDARD_CTRL1);
		value |= (0x1 << 9);
		err = phy_write_mmd(phydev, MDIO_MMD_AN, AQR112C_AN_STANDARD_CTRL1, value);
		if (err < 0)
		{
			dev_err(dev, "Perform a link re-negotiation/auto-negotiation failed\n");
			return err;
		}
		else
		{
			value =  phy_read_mmd(phydev, MDIO_MMD_AN, AQR112C_AN_STANDARD_CTRL1);
			dev_err(dev, "Set the system interface to SGMII, 0x%x.0x%x = 0x%x\n", MDIO_MMD_AN, AQR112C_AN_STANDARD_CTRL1, value);
		}

        mdelay(10);
		// The WoL status bit should be 1 which indicates that the WoL is active. The PHY now is in sleep mode
		value =  phy_read_mmd(phydev, MDIO_MMD_AN, AQR112C_AN_RSV_VEN_STATUS3);
		dev_err(dev, "Try to check is in sleep mode, 0x%x.0x%x = 0x%x\n", MDIO_MMD_AN, AQR112C_AN_RSV_VEN_STATUS3, value);
		if ((value & AQR112C_WOL_READY_BIT) != AQR112C_WOL_READY_BIT)
		{
			dev_err(dev, "The PHY now is not in sleep mode!\n");
			return -1;
		}
	}
	else
	{
		// The WoL status bit should be 1 which indicates that the WoL is active. The PHY now is in sleep mode
		value =  phy_read_mmd(phydev, MDIO_MMD_AN, AQR112C_AN_RSV_VEN_STATUS3);
		dev_err(dev, "Check PHY is in sleep mode?, 0x%x.0x%x = 0x%x\n", MDIO_MMD_AN, AQR112C_AN_RSV_VEN_STATUS3, value);
		if ((value & AQR112C_WOL_READY_BIT) != AQR112C_WOL_READY_BIT)
		{
			dev_err(dev, "The PHY now is not in sleep mode!\n");
			return 0;
		}
		
		// Manual Wake Up
		// MAC request PHY to exit Sleep state by clearing WoL Enable bit
		value =  phy_read_mmd(phydev, MDIO_MMD_AN, AQR112C_AN_RSV_VEN_PROV1);
		value &= ~(0x1 << 6);
		err = phy_write_mmd(phydev, MDIO_MMD_AN, AQR112C_AN_RSV_VEN_PROV1, value);
		if (err < 0)
		{
			dev_err(dev, "Set the WoL enable bit failed\n");
			return err;
		}
		
		value =  phy_read_mmd(phydev, MDIO_MMD_AN, AQR112C_AN_STANDARD_CTRL1);
		value |= (0x1 << 9);
		err = phy_write_mmd(phydev, MDIO_MMD_AN, AQR112C_AN_STANDARD_CTRL1, value);
		if (err < 0)
		{
			dev_err(dev, "Perform a link re-negotiation/auto-negotiation failed\n");
			return err;
		}
		else
		{
			value =  phy_read_mmd(phydev, MDIO_MMD_AN, AQR112C_AN_STANDARD_CTRL1);
			dev_err(dev, "Set the system interface to SGMII, 0x%x.0x%x = 0x%x\n", MDIO_MMD_AN, AQR112C_AN_STANDARD_CTRL1, value);
		}
		
		
	}

    return 0;
}

static void aqr112c_get_wol(struct phy_device *phydev, struct ethtool_wolinfo *wol)
{
    u16 value;
    struct device *dev = &phydev->dev;
	
    if (!dev)
        return ;
	
    wol->supported = WAKE_MAGIC;
    wol->wolopts = 0;

	value =  phy_read_mmd(phydev, MDIO_MMD_AN, AQR112C_AN_RSV_VEN_STATUS3);
	if ((value & AQR112C_WOL_READY_BIT) != AQR112C_WOL_READY_BIT)
	{
		dev_err(dev, "The PHY now is not in sleep mode!\n");
	}
	else
	{
		wol->wolopts |= WAKE_MAGIC;
	}
		
}
#endif

static struct phy_driver aquantia_driver[] = {
{
	.phy_id		= PHY_ID_AQ1202,
	.phy_id_mask	= 0xfffffff0,
	.name		= "Aquantia AQ1202",
	.features	= PHY_AQUANTIA_FEATURES,
	.flags		= PHY_HAS_INTERRUPT,
	.aneg_done	= aquantia_aneg_done,
	.config_aneg    = aquantia_config_aneg,
	.config_intr	= aquantia_config_intr,
	.ack_interrupt	= aquantia_ack_interrupt,
	.read_status	= aquantia_read_status,
	.driver		= { .owner = THIS_MODULE,},
},
{
	.phy_id		= PHY_ID_AQ2104,
	.phy_id_mask	= 0xfffffff0,
	.name		= "Aquantia AQ2104",
	.features	= PHY_AQUANTIA_FEATURES,
	.flags		= PHY_HAS_INTERRUPT,
	.aneg_done	= aquantia_aneg_done,
	.config_aneg    = aquantia_config_aneg,
	.config_intr	= aquantia_config_intr,
	.ack_interrupt	= aquantia_ack_interrupt,
	.read_status	= aquantia_read_status,
	.driver		= { .owner = THIS_MODULE,},
},
{
	.phy_id		= PHY_ID_AQR105,
	.phy_id_mask	= 0xfffffff0,
	.name		= "Aquantia AQR105",
	.features	= PHY_AQUANTIA_FEATURES,
	.flags		= PHY_HAS_INTERRUPT,
	.aneg_done	= aquantia_aneg_done,
	.config_aneg    = aquantia_config_aneg,
	.config_intr	= aquantia_config_intr,
	.ack_interrupt	= aquantia_ack_interrupt,
	.read_status	= aquantia_read_status,
	.driver		= { .owner = THIS_MODULE,},
},
{
	.phy_id		= PHY_ID_AQR405,
	.phy_id_mask	= 0xfffffff0,
	.name		= "Aquantia AQR405",
	.features	= PHY_AQUANTIA_FEATURES,
	.flags		= PHY_HAS_INTERRUPT,
	.aneg_done	= aquantia_aneg_done,
	.config_aneg    = aquantia_config_aneg,
	.config_intr	= aquantia_config_intr,
	.ack_interrupt	= aquantia_ack_interrupt,
	.read_status	= aquantia_read_status,
	.driver		= { .owner = THIS_MODULE,},
},
{
    .phy_id     = PHY_ID_AQR112C,
    .phy_id_mask    = 0xfffffff0,
    .name       = "Aquantia AQR112",
    .features   = PHY_AQUANTIA_FEATURES,
    .flags      = PHY_HAS_INTERRUPT,
    .aneg_done  = aquantia_aneg_done,
    .config_aneg    = aquantia_config_aneg,
    .config_intr    = aquantia_config_intr,
    .ack_interrupt  = aquantia_ack_interrupt,
    .read_status    = aquantia_read_status,
#if defined(CONFIG_MACH_QNAPTS)
//    .set_wol        = aqr112c_set_wol, // side effect: lan disconnect
//    .get_wol        = aqr112c_get_wol,
#endif
    .driver     = { .owner = THIS_MODULE,},
},

};

static int __init aquantia_init(void)
{
	return phy_drivers_register(aquantia_driver,
				    ARRAY_SIZE(aquantia_driver));
}

static void __exit aquantia_exit(void)
{
	return phy_drivers_unregister(aquantia_driver,
				      ARRAY_SIZE(aquantia_driver));
}

module_init(aquantia_init);
module_exit(aquantia_exit);

static struct mdio_device_id __maybe_unused aquantia_tbl[] = {
	{ PHY_ID_AQ1202, 0xfffffff0 },
	{ PHY_ID_AQ2104, 0xfffffff0 },
	{ PHY_ID_AQR105, 0xfffffff0 },
	{ PHY_ID_AQR405, 0xfffffff0 },
#if defined(CONFIG_MACH_QNAPTS)
	{ PHY_ID_AQR112C, 0xfffffff0 },
#endif
	{ }
};

MODULE_DEVICE_TABLE(mdio, aquantia_tbl);

MODULE_DESCRIPTION("Aquantia PHY driver");
MODULE_AUTHOR("Shaohui Xie <Shaohui.Xie@freescale.com>");
MODULE_LICENSE("GPL v2");
