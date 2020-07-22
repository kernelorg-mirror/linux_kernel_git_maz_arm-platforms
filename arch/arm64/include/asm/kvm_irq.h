/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2020 - Google LLC
 * Author: Marc Zyngier <maz@kernel.org>
 */

#ifndef __ARM64_KVM_IRQ_H__
#define __ARM64_KVM_IRQ_H__

enum kvm_irqchip_type {
	IRQCHIP_USER,		/* Implemented in userspace */
	IRQCHIP_GICv2,		/* v2 on v2, or v2 on v3 */
	IRQCHIP_GICv3,		/* v3 on v3 */
};

#define irqchip_in_kernel(k)	((k)->arch.irqchip_type != IRQCHIP_USER)
#define irqchip_is_gic_v2(k)	((k)->arch.irqchip_type == IRQCHIP_GICv2)
#define irqchip_is_gic_v3(k)	((k)->arch.irqchip_type == IRQCHIP_GICv3)

#endif
