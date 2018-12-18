/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __ARM_KVM_NESTED_H
#define __ARM_KVM_NESTED_H

#include <linux/kvm_host.h>

static inline bool nested_virt_in_use(const struct kvm_vcpu *vcpu) { return false; }

#endif /* __ARM_KVM_NESTED_H */
