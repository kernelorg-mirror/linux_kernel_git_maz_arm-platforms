// SPDX-License-Identifier: GPL-2.0-only
/*
 * rVIC/rVID PV interrupt controller implementation for KVM/arm64.
 *
 * Copyright 2020 Google LLC.
 * Author: Marc Zyngier <maz@kernel.org>
 */

#ifndef __KVM_ARM_RVIC_H__
#define __KVM_ARM_RVIC_H__

#include <linux/list.h>
#include <linux/spinlock.h>

struct kvm_vcpu;

struct rvic_irq {
	spinlock_t		lock;
	struct list_head	delivery_entry;
	bool			(*get_line_level)(int intid);
	unsigned int		intid;
	unsigned int		host_irq;
	bool			pending;
	bool			masked;
	bool			line_level; /* If get_line_level == NULL */
};

struct rvic {
	spinlock_t		lock;
	struct list_head	delivery;
	struct rvic_irq		*irqs;
	unsigned int		nr_trusted;
	unsigned int		nr_total;
	bool			enabled;
};

int kvm_rvic_handle_hcall(struct kvm_vcpu *vcpu);
int kvm_rvid_handle_hcall(struct kvm_vcpu *vcpu);
int kvm_register_rvic_device(void);

#endif
