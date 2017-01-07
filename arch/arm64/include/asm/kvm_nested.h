/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __ARM64_KVM_NESTED_H
#define __ARM64_KVM_NESTED_H

#include <linux/kvm_host.h>

static inline bool nested_virt_in_use(const struct kvm_vcpu *vcpu)
{
	return cpus_have_const_cap(ARM64_HAS_NESTED_VIRT) &&
		test_bit(KVM_ARM_VCPU_NESTED_VIRT, vcpu->arch.features);
}

extern void kvm_init_nested(struct kvm *kvm);
extern int kvm_vcpu_init_nested(struct kvm_vcpu *vcpu);
extern void kvm_init_s2_mmu(struct kvm_s2_mmu *mmu);
extern struct kvm_s2_mmu *lookup_s2_mmu(struct kvm *kvm, u64 vttbr, u64 hcr);
extern void kvm_vcpu_load_hw_mmu(struct kvm_vcpu *vcpu);
extern void kvm_vcpu_put_hw_mmu(struct kvm_vcpu *vcpu);

struct kvm_s2_trans {
	phys_addr_t output;
	phys_addr_t block_size;
	bool writable;
	bool readable;
	int level;
	u32 esr;
	u64 upper_attr;
};

extern int kvm_walk_nested_s2(struct kvm_vcpu *vcpu, phys_addr_t gipa,
			      struct kvm_s2_trans *result);

int handle_wfx_nested(struct kvm_vcpu *vcpu, bool is_wfe);
extern bool forward_traps(struct kvm_vcpu *vcpu, u64 control_bit);
extern bool forward_nv_traps(struct kvm_vcpu *vcpu);

#endif /* __ARM64_KVM_NESTED_H */
