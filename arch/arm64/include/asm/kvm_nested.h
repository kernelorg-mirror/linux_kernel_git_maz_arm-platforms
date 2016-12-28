/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __ARM64_KVM_NESTED_H
#define __ARM64_KVM_NESTED_H

#include <linux/kvm_host.h>

static inline bool nested_virt_in_use(const struct kvm_vcpu *vcpu)
{
	return cpus_have_const_cap(ARM64_HAS_NESTED_VIRT) &&
		test_bit(KVM_ARM_VCPU_NESTED_VIRT, vcpu->arch.features);
}

int handle_wfx_nested(struct kvm_vcpu *vcpu, bool is_wfe);

#endif /* __ARM64_KVM_NESTED_H */
