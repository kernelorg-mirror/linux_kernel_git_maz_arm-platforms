/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * include/linux/irqchip/arm-vgic-info.h
 *
 * Copyright (C) 2016 ARM Limited, All Rights Reserved.
 */
#ifndef __LINUX_IRQCHIP_ARM_VGIC_INFO_H
#define __LINUX_IRQCHIP_ARM_VGIC_INFO_H

#include <linux/types.h>
#include <linux/ioport.h>

enum gic_type {
	/* Full GICv2 */
	GIC_V2,
	/* Full GICv3, optionally with v2 compat */
	GIC_V3,
	/* Full GICv5, optionally with v3 compat */
	GIC_V5,
};

struct gic_kvm_info {
	/* GIC type */
	enum gic_type	type;
	/* Virtual CPU interface */
	struct resource vcpu;
	/* GICv2 GICC VA */
	void __iomem	*gicc_base;
	/* Interrupt number */
	unsigned int	maint_irq;
	/* No interrupt mask, no need to use the above field */
	bool		no_maint_irq_mask;
	/* Virtual control interface */
	struct resource vctrl;
	/* vlpi support */
	bool		has_v4;
	/* rvpeid support */
	bool		has_v4_1;
	/* Deactivation impared, subpar stuff */
	bool		no_hw_deactivation;
	/* GICv5 VM capabilities */
	struct {
		void __iomem	*irs_base;
		bool		two_level_vmt_support;
		u32		max_vms;
		u32		max_vpes;
		u16		vmd_size;
		u16		vped_size;
		u8		ist_id_bits;
		u8		min_ist_id_bits;
		bool		ist_levels;
		u8		ist_l2sz;
		bool		istmd;
		u8		istmd_sz;
		bool		irs_non_coherent;
	}		gicv5_vm_caps;
};

#ifdef CONFIG_KVM
void vgic_set_kvm_info(const struct gic_kvm_info *info);
#else
static inline void vgic_set_kvm_info(const struct gic_kvm_info *info) {}
#endif

#endif
