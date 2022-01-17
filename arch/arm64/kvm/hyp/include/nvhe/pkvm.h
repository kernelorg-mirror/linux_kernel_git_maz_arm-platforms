/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2021 Google LLC
 * Author: Fuad Tabba <tabba@google.com>
 */

#ifndef __ARM64_KVM_NVHE_PKVM_H__
#define __ARM64_KVM_NVHE_PKVM_H__

#include <asm/kvm_pkvm.h>

#include <nvhe/gfp.h>
#include <nvhe/spinlock.h>

/*
 * Holds the relevant data for maintaining the vcpu state completely at hyp.
 */
struct kvm_shadow_vcpu_state {
	/* The data for the shadow vcpu. */
	struct kvm_vcpu shadow_vcpu;

	/* A pointer to the host's vcpu. */
	struct kvm_vcpu *host_vcpu;

	/* A pointer to the shadow vm. */
	struct kvm_shadow_vm *shadow_vm;

	/* Tracks exit code for the protected guest. */
	u32 exit_code;

	/*
	 * Track the power state transition of a protected vcpu.
	 * Can be in one of three states:
	 * PSCI_0_2_AFFINITY_LEVEL_ON
	 * PSCI_0_2_AFFINITY_LEVEL_OFF
	 * PSCI_0_2_AFFINITY_LEVEL_PENDING
	 */
	int power_state;

	/* True if this vcpu is currently loaded on a cpu. */
	bool loaded_on_cpu;
};

/*
 * Holds the relevant data for running a protected vm.
 */
struct kvm_shadow_vm {
	/* A unique id to the shadow structs in the hyp shadow area. */
	int shadow_handle;

	/* Number of vcpus for the vm. */
	int created_vcpus;

	/* The host's kvm structure. */
	struct kvm *host_kvm;

	/* The total size of the donated shadow area. */
	size_t shadow_area_size;

	struct kvm_arch arch;
	struct kvm_pgtable pgt;
	struct kvm_pgtable_mm_ops mm_ops;
	struct hyp_pool pool;
	hyp_spinlock_t lock;

	/* Array of the shadow state per vcpu. */
	struct kvm_shadow_vcpu_state shadow_vcpu_states[0];
};

static inline bool vcpu_is_protected(struct kvm_vcpu *vcpu)
{
	struct kvm_shadow_vcpu_state *shadow_state;

	if (!is_protected_kvm_enabled())
		return false;

	shadow_state = container_of(vcpu, struct kvm_shadow_vcpu_state, shadow_vcpu);

	return shadow_state->shadow_vm->arch.pkvm.enabled;
}

void hyp_shadow_table_init(void *tbl);
int __pkvm_init_shadow(struct kvm *kvm, void *shadow_va, size_t size, void *pgd);
int __pkvm_teardown_shadow(int shadow_handle);
struct kvm_shadow_vcpu_state *pkvm_get_shadow_vcpu_state(int shadow_handle, unsigned int vcpu_idx);
void pkvm_put_shadow_vcpu_state(struct kvm_shadow_vcpu_state *shadow_state);

u64 pvm_read_id_reg(const struct kvm_vcpu *vcpu, u32 id);
bool kvm_handle_pvm_sysreg(struct kvm_vcpu *vcpu, u64 *exit_code);
bool kvm_handle_pvm_restricted(struct kvm_vcpu *vcpu, u64 *exit_code);
void kvm_reset_pvm_sys_regs(struct kvm_vcpu *vcpu);
int kvm_check_pvm_sysreg_table(void);

void pkvm_reset_vcpu(struct kvm_shadow_vcpu_state *shadow_state);

bool kvm_handle_pvm_hvc64(struct kvm_vcpu *vcpu, u64 *exit_code);

struct kvm_shadow_vcpu_state *pkvm_mpidr_to_vcpu_state(struct kvm_shadow_vm *vm, unsigned long mpidr);

#endif /* __ARM64_KVM_NVHE_PKVM_H__ */
