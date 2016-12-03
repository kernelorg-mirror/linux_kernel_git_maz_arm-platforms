/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __ARM_KVM_NESTED_H
#define __ARM_KVM_NESTED_H

#include <linux/kvm_host.h>

static inline bool nested_virt_in_use(const struct kvm_vcpu *vcpu) { return false; }
static inline void check_nested_vcpu_requests(struct kvm_vcpu *vcpu) {}

#endif /* __ARM_KVM_NESTED_H */
