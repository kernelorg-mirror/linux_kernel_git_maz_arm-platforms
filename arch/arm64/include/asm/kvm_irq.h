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

struct kvm_irqchip_flow {
	void (*irqchip_destroy)(struct kvm *);
	int  (*irqchip_vcpu_init)(struct kvm_vcpu *);
	void (*irqchip_vcpu_blocking)(struct kvm_vcpu *);
	void (*irqchip_vcpu_unblocking)(struct kvm_vcpu *);
	void (*irqchip_vcpu_load)(struct kvm_vcpu *);
	void (*irqchip_vcpu_put)(struct kvm_vcpu *);
};

/*
 * Macro galore. At the point this is included, the various types are
 * not defined yet. Yes, this is terminally ugly.
 */
#define __kvm_irqchip_action(k, x, ...)					\
	do {								\
		if (likely((k)->arch.irqchip_flow.irqchip_##x))		\
			(k)->arch.irqchip_flow.irqchip_##x(__VA_ARGS__); \
	} while (0)

#define __kvm_irqchip_action_ret(k, x, ...)				\
	({								\
		typeof ((k)->arch.irqchip_flow.irqchip_##x(__VA_ARGS__)) ret; \
		ret = (likely((k)->arch.irqchip_flow.irqchip_##x) ?	\
		       (k)->arch.irqchip_flow.irqchip_##x(__VA_ARGS__) : \
		       0);						\
									\
		ret;							\
	 })

#define __vcpu_irqchip_action(v, ...)			\
	__kvm_irqchip_action((v)->kvm, __VA_ARGS__)

#define __vcpu_irqchip_action_ret(v, ...)		\
	__kvm_irqchip_action_ret((v)->kvm, __VA_ARGS__)

#define kvm_irqchip_destroy(k)				\
	__kvm_irqchip_action((k), destroy, (k))

#define kvm_irqchip_vcpu_init(v)			\
	__vcpu_irqchip_action_ret((v), vcpu_init, (v))

#define kvm_irqchip_vcpu_blocking(v)			\
	__vcpu_irqchip_action((v), vcpu_blocking, (v))

#define kvm_irqchip_vcpu_unblocking(v)			\
	__vcpu_irqchip_action((v), vcpu_unblocking, (v))

#define kvm_irqchip_vcpu_load(v)			\
	__vcpu_irqchip_action((v), vcpu_load, (v))

#define kvm_irqchip_vcpu_put(v)				\
	__vcpu_irqchip_action((v), vcpu_put, (v))

#endif
