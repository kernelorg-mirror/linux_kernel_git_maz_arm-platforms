/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __ARM64_KVM_NESTED_H
#define __ARM64_KVM_NESTED_H

#include <linux/kvm_host.h>

static inline bool nested_virt_in_use(const struct kvm_vcpu *vcpu)
{
	return cpus_have_final_cap(ARM64_HAS_NESTED_VIRT) &&
		test_bit(KVM_ARM_VCPU_HAS_EL2, vcpu->arch.features);
}

extern void kvm_init_nested(struct kvm *kvm);
extern int kvm_vcpu_init_nested(struct kvm_vcpu *vcpu);
extern void kvm_init_nested_s2_mmu(struct kvm_s2_mmu *mmu);
extern struct kvm_s2_mmu *lookup_s2_mmu(struct kvm *kvm, u64 vttbr, u64 hcr);
extern void kvm_vcpu_load_hw_mmu(struct kvm_vcpu *vcpu);
extern void kvm_vcpu_put_hw_mmu(struct kvm_vcpu *vcpu);

struct kvm_s2_trans {
	phys_addr_t output;
	unsigned long block_size;
	bool writable;
	bool readable;
	int level;
	u32 esr;
	u64 upper_attr;
};

extern int kvm_walk_nested_s2(struct kvm_vcpu *vcpu, phys_addr_t gipa,
			      struct kvm_s2_trans *result);

int handle_wfx_nested(struct kvm_vcpu *vcpu, bool is_wfe);
extern bool __forward_traps(struct kvm_vcpu *vcpu, unsigned int reg,
			    u64 control_bit);
extern bool forward_traps(struct kvm_vcpu *vcpu, u64 control_bit);
extern bool forward_nv_traps(struct kvm_vcpu *vcpu);

struct sys_reg_params;
struct sys_reg_desc;

void access_nested_id_reg(struct kvm_vcpu *v, struct sys_reg_params *p,
			  const struct sys_reg_desc *r);

#endif /* __ARM64_KVM_NESTED_H */
