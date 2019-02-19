/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __ARM64_KVM_NESTED_H
#define __ARM64_KVM_NESTED_H

#include <linux/bitfield.h>
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
	unsigned long block_size;
	bool writable;
	bool readable;
	int level;
	u32 esr;
	u64 upper_attr;
};

static inline phys_addr_t kvm_s2_trans_output(struct kvm_s2_trans *trans)
{
	return trans->output;
}

static inline unsigned long kvm_s2_trans_size(struct kvm_s2_trans *trans)
{
	return trans->block_size;
}

static inline u32 kvm_s2_trans_esr(struct kvm_s2_trans *trans)
{
	return trans->esr;
}

static inline bool kvm_s2_trans_readable(struct kvm_s2_trans *trans)
{
	return trans->readable;
}

static inline bool kvm_s2_trans_writable(struct kvm_s2_trans *trans)
{
	return trans->writable;
}

extern int kvm_walk_nested_s2(struct kvm_vcpu *vcpu, phys_addr_t gipa,
			      struct kvm_s2_trans *result);

extern int kvm_s2_handle_perm_fault(struct kvm_vcpu *vcpu,
				    struct kvm_s2_trans *trans);
extern int kvm_inject_s2_fault(struct kvm_vcpu *vcpu, u64 esr_el2);
extern void kvm_nested_s2_wp(struct kvm *kvm);
extern void kvm_nested_s2_clear(struct kvm *kvm);
extern void kvm_nested_s2_flush(struct kvm *kvm);
int handle_wfx_nested(struct kvm_vcpu *vcpu, bool is_wfe);
extern bool forward_traps(struct kvm_vcpu *vcpu, u64 control_bit);
extern bool forward_nv_traps(struct kvm_vcpu *vcpu);
u8 get_guest_mapping_ttl(struct kvm_vcpu *vcpu, struct kvm_s2_mmu *mmu,
			 u64 addr);
unsigned int ttl_to_size(u8 ttl);

#define KVM_NV_GUEST_MAP_SZ	GENMASK_ULL(56, 55)

static inline u64 kvm_encode_nested_level(struct kvm_s2_trans *trans)
{
	return FIELD_PREP(KVM_NV_GUEST_MAP_SZ, trans->level);
}

#endif /* __ARM64_KVM_NESTED_H */
