// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2021 Google LLC
 * Author: Fuad Tabba <tabba@google.com>
 */

#include <asm/kvm_asm.h>
#include <asm/kvm_emulate.h>
#include <asm/kvm_host.h>
#include <asm/kvm_mmu.h>
#include <asm/memory.h>

#include <linux/kvm_host.h>
#include <linux/mm.h>

#include <kvm/arm_hypercalls.h>
#include <kvm/arm_psci.h>

#include <nvhe/fixed_config.h>
#include <nvhe/mem_protect.h>
#include <nvhe/mm.h>
#include <nvhe/pkvm.h>
#include <nvhe/trap_handler.h>

/*
 * Set trap register values based on features in ID_AA64PFR0.
 */
static void pvm_init_traps_aa64pfr0(struct kvm_vcpu *vcpu)
{
	const u64 feature_ids = pvm_read_id_reg(vcpu, SYS_ID_AA64PFR0_EL1);
	u64 hcr_set = HCR_RW;
	u64 hcr_clear = 0;
	u64 cptr_set = 0;

	/* Protected KVM does not support AArch32 guests. */
	BUILD_BUG_ON(FIELD_GET(ARM64_FEATURE_MASK(ID_AA64PFR0_EL0),
		PVM_ID_AA64PFR0_RESTRICT_UNSIGNED) != ID_AA64PFR0_ELx_64BIT_ONLY);
	BUILD_BUG_ON(FIELD_GET(ARM64_FEATURE_MASK(ID_AA64PFR0_EL1),
		PVM_ID_AA64PFR0_RESTRICT_UNSIGNED) != ID_AA64PFR0_ELx_64BIT_ONLY);

	/*
	 * Linux guests assume support for floating-point and Advanced SIMD. Do
	 * not change the trapping behavior for these from the KVM default.
	 */
	BUILD_BUG_ON(!FIELD_GET(ARM64_FEATURE_MASK(ID_AA64PFR0_FP),
				PVM_ID_AA64PFR0_ALLOW));
	BUILD_BUG_ON(!FIELD_GET(ARM64_FEATURE_MASK(ID_AA64PFR0_ASIMD),
				PVM_ID_AA64PFR0_ALLOW));

	/* Trap RAS unless all current versions are supported */
	if (FIELD_GET(ARM64_FEATURE_MASK(ID_AA64PFR0_RAS), feature_ids) <
	    ID_AA64PFR0_RAS_V1P1) {
		hcr_set |= HCR_TERR | HCR_TEA;
		hcr_clear |= HCR_FIEN;
	}

	/* Trap AMU */
	if (!FIELD_GET(ARM64_FEATURE_MASK(ID_AA64PFR0_AMU), feature_ids)) {
		hcr_clear |= HCR_AMVOFFEN;
		cptr_set |= CPTR_EL2_TAM;
	}

	/* Trap SVE */
	if (!FIELD_GET(ARM64_FEATURE_MASK(ID_AA64PFR0_SVE), feature_ids))
		cptr_set |= CPTR_EL2_TZ;

	vcpu->arch.hcr_el2 |= hcr_set;
	vcpu->arch.hcr_el2 &= ~hcr_clear;
	vcpu->arch.cptr_el2 |= cptr_set;
}

/*
 * Set trap register values based on features in ID_AA64PFR1.
 */
static void pvm_init_traps_aa64pfr1(struct kvm_vcpu *vcpu)
{
	const u64 feature_ids = pvm_read_id_reg(vcpu, SYS_ID_AA64PFR1_EL1);
	u64 hcr_set = 0;
	u64 hcr_clear = 0;

	/* Memory Tagging: Trap and Treat as Untagged if not supported. */
	if (!FIELD_GET(ARM64_FEATURE_MASK(ID_AA64PFR1_MTE), feature_ids)) {
		hcr_set |= HCR_TID5;
		hcr_clear |= HCR_DCT | HCR_ATA;
	}

	vcpu->arch.hcr_el2 |= hcr_set;
	vcpu->arch.hcr_el2 &= ~hcr_clear;
}

/*
 * Set trap register values based on features in ID_AA64DFR0.
 */
static void pvm_init_traps_aa64dfr0(struct kvm_vcpu *vcpu)
{
	const u64 feature_ids = pvm_read_id_reg(vcpu, SYS_ID_AA64DFR0_EL1);
	u64 mdcr_set = 0;
	u64 mdcr_clear = 0;
	u64 cptr_set = 0;

	/* Trap/constrain PMU */
	if (!FIELD_GET(ARM64_FEATURE_MASK(ID_AA64DFR0_PMUVER), feature_ids)) {
		mdcr_set |= MDCR_EL2_TPM | MDCR_EL2_TPMCR;
		mdcr_clear |= MDCR_EL2_HPME | MDCR_EL2_MTPME |
			      MDCR_EL2_HPMN_MASK;
	}

	/* Trap Debug */
	if (!FIELD_GET(ARM64_FEATURE_MASK(ID_AA64DFR0_DEBUGVER), feature_ids))
		mdcr_set |= MDCR_EL2_TDRA | MDCR_EL2_TDA | MDCR_EL2_TDE;

	/* Trap OS Double Lock */
	if (!FIELD_GET(ARM64_FEATURE_MASK(ID_AA64DFR0_DOUBLELOCK), feature_ids))
		mdcr_set |= MDCR_EL2_TDOSA;

	/* Trap SPE */
	if (!FIELD_GET(ARM64_FEATURE_MASK(ID_AA64DFR0_PMSVER), feature_ids)) {
		mdcr_set |= MDCR_EL2_TPMS;
		mdcr_clear |= MDCR_EL2_E2PB_MASK << MDCR_EL2_E2PB_SHIFT;
	}

	/* Trap Trace Filter */
	if (!FIELD_GET(ARM64_FEATURE_MASK(ID_AA64DFR0_TRACE_FILT), feature_ids))
		mdcr_set |= MDCR_EL2_TTRF;

	/* Trap Trace */
	if (!FIELD_GET(ARM64_FEATURE_MASK(ID_AA64DFR0_TRACEVER), feature_ids))
		cptr_set |= CPTR_EL2_TTA;

	vcpu->arch.mdcr_el2 |= mdcr_set;
	vcpu->arch.mdcr_el2 &= ~mdcr_clear;
	vcpu->arch.cptr_el2 |= cptr_set;
}

/*
 * Set trap register values based on features in ID_AA64MMFR0.
 */
static void pvm_init_traps_aa64mmfr0(struct kvm_vcpu *vcpu)
{
	const u64 feature_ids = pvm_read_id_reg(vcpu, SYS_ID_AA64MMFR0_EL1);
	u64 mdcr_set = 0;

	/* Trap Debug Communications Channel registers */
	if (!FIELD_GET(ARM64_FEATURE_MASK(ID_AA64MMFR0_FGT), feature_ids))
		mdcr_set |= MDCR_EL2_TDCC;

	vcpu->arch.mdcr_el2 |= mdcr_set;
}

/*
 * Set trap register values based on features in ID_AA64MMFR1.
 */
static void pvm_init_traps_aa64mmfr1(struct kvm_vcpu *vcpu)
{
	const u64 feature_ids = pvm_read_id_reg(vcpu, SYS_ID_AA64MMFR1_EL1);
	u64 hcr_set = 0;

	/* Trap LOR */
	if (!FIELD_GET(ARM64_FEATURE_MASK(ID_AA64MMFR1_LOR), feature_ids))
		hcr_set |= HCR_TLOR;

	vcpu->arch.hcr_el2 |= hcr_set;
}

/*
 * Set baseline trap register values.
 */
static void pvm_init_trap_regs(struct kvm_vcpu *vcpu)
{
	const u64 hcr_trap_feat_regs = HCR_TID3;
	const u64 hcr_trap_impdef = HCR_TACR | HCR_TIDCP | HCR_TID1;

	/*
	 * Always trap:
	 * - Feature id registers: to control features exposed to guests
	 * - Implementation-defined features
	 */
	vcpu->arch.hcr_el2 |= hcr_trap_feat_regs | hcr_trap_impdef;

	/* Clear res0 and set res1 bits to trap potential new features. */
	vcpu->arch.hcr_el2 &= ~(HCR_RES0);
	vcpu->arch.mdcr_el2 &= ~(MDCR_EL2_RES0);
	vcpu->arch.cptr_el2 |= CPTR_NVHE_EL2_RES1;
	vcpu->arch.cptr_el2 &= ~(CPTR_NVHE_EL2_RES0);
}

/*
 * Initialize trap register values for protected VMs.
 */
static void pkvm_vcpu_init_traps(struct kvm_vcpu *vcpu)
{
	pvm_init_trap_regs(vcpu);
	pvm_init_traps_aa64pfr0(vcpu);
	pvm_init_traps_aa64pfr1(vcpu);
	pvm_init_traps_aa64dfr0(vcpu);
	pvm_init_traps_aa64mmfr0(vcpu);
	pvm_init_traps_aa64mmfr1(vcpu);
}

/*
 * Start the shadow table handle at the offset defined instead of at 0.
 * Mainly for sanity checking and debugging.
 */
#define HANDLE_OFFSET 0x1000

extern unsigned long hyp_nr_cpus;

/*
 * Spinlock for protecting the shadow table related state.
 * Protects writes to shadow_table, num_shadow_entries, and next_shadow_alloc,
 * as well as reads and writes to last_shadow_vcpu_lookup.
 * TODO: fix, not necessary for percpu cache
 */
DEFINE_HYP_SPINLOCK(shadow_lock);

/*
 * The table of shadow entries for protected VMs in hyp.
 * Allocated at hyp initialization and setup.
 */
struct shadow_memory_area *shadow_table;

/* Current number of vms in the shadow table. */
int num_shadow_entries;

/* The next entry index to try to allocate from. */
int next_shadow_alloc;

/*
 * Entry to use for cached lookups.
 */
struct vcpu_state_cache_entry {
	const struct kvm_vcpu *vcpu;
	struct shadow_vcpu_state *state;
};

/*
 * A single-entry cache for the most recent lookup on this cpu.
 *
 * Linux tries to schedule the same vcpu on the same cpu, because migration is
 * expensive. This single entry cache keeps the most recent lookup  performed on
 * this cpu.
 */
DEFINE_PER_CPU(struct vcpu_state_cache_entry, last_shadow_vcpu_lookup);

/*
 * Update the shadow vcpu lookup cache with latest successful lookup.
 */
static void update_shadow_vcpu_cache(const struct kvm_vcpu *vcpu,
				     struct shadow_vcpu_state *state)
{
	struct vcpu_state_cache_entry *entry =
		this_cpu_ptr(&last_shadow_vcpu_lookup);

	*entry = (struct vcpu_state_cache_entry){vcpu, state};
}

/*
 * Lookup the shadow vcpu state in the cache.
 */
static struct shadow_vcpu_state *
lookup_shadow_vcpu_cache(const struct kvm_vcpu *vcpu)
{
	const struct vcpu_state_cache_entry *entry =
		this_cpu_ptr(&last_shadow_vcpu_lookup);

	if (likely(entry->vcpu == vcpu))
		return entry->state;

	return NULL;
}

/*
 * Clear the shadow cache.
 */
void clear_shadow_cache(void)
{
	int i;

	for (i = 0; i < hyp_nr_cpus; i++) {
		// TODO: Is this safe?
		struct vcpu_state_cache_entry *entry =
			per_cpu_ptr(&last_shadow_vcpu_lookup, i);
		memset(entry, 0, sizeof(*entry));
	}
}

/*
 * Return the shadow memory area corresponding to the handle.
 */
static struct shadow_memory_area *get_shadow_memory(int shadow_handle)
{
	int shadow_index = shadow_handle - HANDLE_OFFSET;

	if (unlikely(shadow_index < 0 || shadow_index >= KVM_MAX_PVMS))
		return NULL;

	return &shadow_table[shadow_index];
}

/*
 * Return a pointer to the hyp's shadow vm from the shadow memory area;
 */
static inline struct kvm_shadow_vm *get_shadow_vm(void *shadow_addr)
{
	return shadow_addr + SHADOW_VM_OFFSET;
}

/*
 * Return a pointer to the ith shadow vcpu state.
 */
static struct shadow_vcpu_state *
get_shadow_vcpu_state(void *shadow_addr, int i)
{
	struct shadow_vcpu_state *shadow_vcpu_states =
		(struct shadow_vcpu_state *)
		       ((unsigned long)(shadow_addr) + SHADOW_VCPUS_OFFSET);

	return &shadow_vcpu_states[i];
}

/*
 * Returns the hyp shadow vcpu for the corresponding host vcpu,
 * or NULL if it fails.
 */
struct kvm_vcpu *hyp_get_shadow_vcpu(const struct kvm_vcpu *vcpu)
{
	struct shadow_vcpu_state *shadow_vcpu_state;
	struct shadow_memory_area *shadow_memory_area;
	int vcpu_idx;
	int shadow_handle;

	if (!kvm_vm_is_protected(kern_hyp_va(vcpu->kvm)))
		return NULL;

	shadow_vcpu_state = lookup_shadow_vcpu_cache(vcpu);
	if (likely(shadow_vcpu_state))
		return &shadow_vcpu_state->vcpu;

	shadow_handle = vcpu->arch.pkvm.shadow_handle;
	shadow_memory_area = get_shadow_memory(shadow_handle);
	vcpu_idx = vcpu->vcpu_idx;

	if (unlikely(vcpu_idx < 0 || vcpu_idx >= shadow_memory_area->num_vcpus))
		return NULL;

	shadow_vcpu_state =
		get_shadow_vcpu_state(shadow_memory_area->shadow_addr, vcpu_idx);
	update_shadow_vcpu_cache(vcpu, shadow_vcpu_state);

	return &shadow_vcpu_state->vcpu;
}

/*
 * Unmap the physical address range from the host's stage 2 mmu.
 *
 * Return 0 on success, negative error code on failure.
 */
static int stage2_unmap_host(unsigned long pa, size_t size)
{
	int ret;

	hyp_spin_lock(&host_kvm.lock);
	ret = kvm_pgtable_stage2_unmap(&host_kvm.pgt, pa, size);
	hyp_spin_unlock(&host_kvm.lock);

	return ret;
}

/*
 * Initialize and check the values of the shadow state donated by the host.
 *
 * Ensures that all pointers are either mapped to a valid hyp address, or set to
 * NULL if not of interest to hyp.
 *
 * Return 0 on success, negative error code on failure.
 */
static int init_shadow_structs(struct kvm *kvm,
			       void *shadow_addr,
			       size_t size,
			       int shadow_handle)
{
	int num_vcpus = kvm->created_vcpus;
	struct kvm_shadow_vm *vm = get_shadow_vm(shadow_addr);
	int i;

	vm->shadow_handle = shadow_handle;
	vm->created_vcpus = num_vcpus;
	vm->psci_version = kvm->arch.psci_version;

	/* TODO: initialize the protected MMU. For now, use the host's. */
	vm->mmu = &kvm->arch.mmu;

	for (i = 0; i < num_vcpus; i++) {
		struct shadow_vcpu_state *shadow_state =
			get_shadow_vcpu_state(shadow_addr, i);
		struct kvm_vcpu *shadow_vcpu = &shadow_state->vcpu;
		struct kvm_vcpu *host_vcpu = kern_hyp_va(kvm->vcpus[i]);

		vm->vcpus[i] = shadow_vcpu;

		pkvm_vcpu_init_traps(shadow_vcpu);

		shadow_state->vm = vm;
		shadow_vcpu->arch.hw_mmu = host_vcpu->arch.hw_mmu;
		shadow_vcpu->arch.pkvm.shadow_handle = shadow_handle;
		shadow_vcpu->arch.pkvm.host_vcpu = host_vcpu;
		shadow_vcpu->arch.pkvm.shadow_vm = vm;
		shadow_vcpu->arch.pkvm.power_state = OFF;
		shadow_vcpu->arch.pkvm.exit_code = -1;
	}

	return 0;
}

/*
 * Allocate a shadow table entry and insert a pointer to the shadow area.
 *
 * Return a unique handle to the protected VM on success,
 * negative error code on failure.
 */
static int insert_shadow_table(void *shadow_addr,
			       int num_vcpus,
			       size_t shadow_size)
{
	int ret;

	hyp_spin_lock(&shadow_lock);

	if (unlikely(num_shadow_entries >= KVM_MAX_PVMS)) {
		ret = -ENOMEM;
		goto out_unlock;
	}

	/*
	 * Initializing protected state might have failed, yet a malicious host
	 * could trigger this function. Thus, ensure that shadow_table exists.
	 */
	if (unlikely(!shadow_table)) {
		ret = -EINVAL;
		goto out_unlock;
	}

	/* Find the next free entry in the shadow table. */
	while (shadow_table[next_shadow_alloc].shadow_addr)
		next_shadow_alloc = (next_shadow_alloc + 1) % KVM_MAX_PVMS;

	shadow_table[next_shadow_alloc] =
		(struct shadow_memory_area){ .shadow_addr = shadow_addr,
					     .num_vcpus = num_vcpus,
					     .shadow_size = shadow_size };
	ret = HANDLE_OFFSET + next_shadow_alloc;

	next_shadow_alloc = (next_shadow_alloc + 1) % KVM_MAX_PVMS;
	num_shadow_entries++;

out_unlock:
	hyp_spin_unlock(&shadow_lock);
	return ret;
}

/*
 * Deallocate and remove the shadow table entry corresponding to the handle.
 */
static void remove_shadow_table(struct shadow_memory_area *shadow_memory_area)
{
	if (!shadow_memory_area)
		return;


	hyp_spin_lock(&shadow_lock);

	/* Clear the shadow cache for all cpus. */
	// TODO: I think this should be done under lock and key to avoid race
	// conditions. Reason about it some more.
	clear_shadow_cache();

	memset(shadow_memory_area, 0, sizeof(*shadow_memory_area));
	num_shadow_entries--;

	hyp_spin_unlock(&shadow_lock);
}

/*
 * Checks whether the size of the area donated by the host is sufficient for
 * the shadow structues required for num_vcpus as well as the shadow vm.
 */
static int check_shadow_size(int num_vcpus, size_t shadow_size)
{
	if (num_vcpus < 1 || num_vcpus > KVM_MAX_VCPUS)
		return -EINVAL;

	/*
	 * Shadow size is rounded up when allocated and donated by the host,
	 * so it's likely to be larger than the sum of the struct sizes.
	 */
	if (shadow_size < hyp_get_shadow_size(num_vcpus))
		return -EINVAL;

	return 0;
}

/*
 * Initialize the shadow copy of the protected VM state using the memory
 * donated by the host.
 *
 * Unmaps the donated memory from the host at stage 2.
 *
 * Return a unique handle to the protected VM on success,
 * negative error code on failure.
 */
int __pkvm_init_shadow(struct kvm *kvm,
		       void *shadow_va,
		       size_t shadow_size)
{
	void *shadow_addr = kern_hyp_va(shadow_va);
	void *shadow_end = (void *)((unsigned long)shadow_addr) + shadow_size;
	unsigned long shadow_pa = __pa((unsigned long)shadow_va);
	int shadow_handle;
	int ret = 0;

	/* Don't automatically trust host-provided memory. */
	ret = check_host_memory_addr((u64)kvm, sizeof(*kvm));
	if (ret)
		goto err;

	ret = check_host_memory_addr((u64)shadow_va, shadow_size);
	if (ret)
		goto err;

	kvm = kern_hyp_va(kvm);

	/* Only use shadows for protected VMs. */
	if (!kvm_vm_is_protected(kvm))
		return -EINVAL;

	/* Ensure the host has donated enough memory for the shadow structs. */
	ret = check_shadow_size(kvm->created_vcpus, shadow_size);
	if (ret)
		goto err;

	/* Unmap the donated shadow memory from the host's stage 2. */
	ret = stage2_unmap_host(shadow_pa, shadow_size);
	if (ret < 0)
		goto err;

	/* Shadow memory should be owned exclusively by hyp. */
	// TODO
	//ret = __pkvm_mark_hyp(shadow_pa, shadow_pa + shadow_size);
	if (ret < 0)
		goto err;

	/* Create hyp mappings for the donated area. */
	ret = pkvm_create_mappings(shadow_addr, shadow_end, PAGE_HYP);
	if (ret < 0)
		goto err_mark_host;

	/* Add the entry to the shadow table. */
	ret = insert_shadow_table(shadow_addr, kvm->created_vcpus, shadow_size);
	if (ret < 0)
		goto err_remove_hyp_mappings;

	shadow_handle = ret;

	/* Initialize the data in shadow memory. */
	ret = init_shadow_structs(kvm, shadow_addr, shadow_size, shadow_handle);
	if (ret < 0)
		goto err_clear_shadow;

	return shadow_handle;

err_clear_shadow:
	/* Clear the donated shadow memory on failure to avoid data leaks. */
	memset(shadow_addr, 0, shadow_size);
	remove_shadow_table(get_shadow_memory(shadow_handle));

err_remove_hyp_mappings:
	/* TODO: Remove hyp mappings for the shadow area. */

err_mark_host:
	/* Return shadow memory ownership to the host. */
	// TODO
	//__pkvm_mark_host(shadow_pa, shadow_pa + shadow_size);

err:
	return ret;
}

void __pkvm_teardown_shadow(struct kvm *kvm)
{
	struct shadow_memory_area *shadow_memory_area;
	size_t shadow_size;
	//phys_addr_t shadow_kvm_pa;
	int shadow_handle;
	void *shadow_addr;

	/* Don't automatically trust host-provided memory. */
	if (unlikely(check_host_memory_addr((u64)kvm, sizeof(*kvm))))
		return;

	kvm = kern_hyp_va(kvm);

	shadow_handle = kvm->arch.pkvm.shadow_handle;

	/* Lookup then remove entry from the shadow table. */
	shadow_memory_area = get_shadow_memory(shadow_handle);
	shadow_size = shadow_memory_area->shadow_size;
	shadow_addr = shadow_memory_area->shadow_addr;
	remove_shadow_table(shadow_memory_area);

	/* Clear the shadow memory since hyp is releasing it back to host. */
	memset(shadow_addr, 0, shadow_size);

	/* TODO: Remove hyp mappings for the donated shadow area. */

	/* Return shadow memory ownership to the host. */
	// TODO
	//__pkvm_mark_host(shadow_kvm_pa, shadow_kvm_pa + shadow_size);
}

// TODO: share with reset.c
static int kvm_vcpu_enable_ptrauth(struct kvm_vcpu *vcpu)
{
	/*
	 * For now make sure that both address/generic pointer authentication
	 * features are requested by the userspace together and the system
	 * supports these capabilities.
	 */
	if (!test_bit(KVM_ARM_VCPU_PTRAUTH_ADDRESS, vcpu->arch.features) ||
	    !test_bit(KVM_ARM_VCPU_PTRAUTH_GENERIC, vcpu->arch.features) ||
	    !system_has_full_ptr_auth())
		return -EINVAL;

	vcpu->arch.flags |= KVM_ARM64_GUEST_HAS_PTRAUTH;
	return 0;
}

// TODO: share with reset.c
/*
 * ARMv8 Reset Values
 */
#define VCPU_RESET_PSTATE_EL1	(PSR_MODE_EL1h | PSR_A_BIT | PSR_I_BIT | \
				 PSR_F_BIT | PSR_D_BIT)

/*
 * This function sets the registers on the virtual CPU struct to their
 * architecturally defined reset values. It should be called only the the vcpu
 * itself immediately it has been reset.
 */
int pkvm_reset_vcpu(struct kvm_vcpu *vcpu)
{
	struct vcpu_reset_state *reset_state = &vcpu->arch.reset_state;

	/*
	 * TODO: kvm_arch_vcpu_put(vcpu):
	 * - kvm_arch_vcpu_put_fp(vcpu);
	 * - kvm_timer_vcpu_put(vcpu);
	 * - kvm_vgic_put(vcpu, false);
	 */

	if (test_bit(KVM_ARM_VCPU_PTRAUTH_ADDRESS, vcpu->arch.features) ||
	    test_bit(KVM_ARM_VCPU_PTRAUTH_GENERIC, vcpu->arch.features)) {
		if (kvm_vcpu_enable_ptrauth(vcpu))
			return -EINVAL;
	}

	/* Reset core registers */
	memset(vcpu_gp_regs(vcpu), 0, sizeof(*vcpu_gp_regs(vcpu)));
	memset(&vcpu->arch.ctxt.fp_regs, 0, sizeof(vcpu->arch.ctxt.fp_regs));
	vcpu->arch.ctxt.spsr_abt = 0;
	vcpu->arch.ctxt.spsr_und = 0;
	vcpu->arch.ctxt.spsr_irq = 0;
	vcpu->arch.ctxt.spsr_fiq = 0;
	vcpu_gp_regs(vcpu)->pstate = VCPU_RESET_PSTATE_EL1;

	/*
	 * Additional reset state handling that PSCI may have imposed on us.
	 * Must be done after all the sys_reg reset.
	 */
	if (reset_state->reset) {
		unsigned long target_pc = reset_state->pc;

		/* Propagate caller endianness */
		if (reset_state->be)
			__vcpu_sys_reg(vcpu, SCTLR_EL1) |= SCTLR_ELx_EE;

		*vcpu_pc(vcpu) = target_pc;
		vcpu_set_reg(vcpu, 0, reset_state->r0);
	}

	/* TODO: kvm_timer_vcpu_reset() */

	/*
	 * TODO: kvm_arch_vcpu_load()
	 * - kvm_vgic_load(vcpu);
	 * - kvm_timer_vcpu_load(vcpu);
	 * - kvm_arch_vcpu_load_fp(vcpu);
	 */

	reset_state->reset = false;

	// TODO: Should never happen, for debugging.
	WARN_ON(!vcpu->arch.power_off);
	WARN_ON(vcpu->arch.pkvm.power_state != PENDING_ON);

	WRITE_ONCE(vcpu->arch.power_off, true);
	WRITE_ONCE(vcpu->arch.pkvm.power_state, ON);

	return 0;
}

#define PVM_PSCI_VER KVM_ARM_VCPU_PSCI_0_2

// TODO: make common with one in kvm_emulate.h
static inline unsigned long vcpu_get_mpidr_aff(struct kvm_vcpu *vcpu)
{
	return __vcpu_sys_reg(vcpu, MPIDR_EL1) & MPIDR_HWID_BITMASK;
}

// TODO: make common with one in kvm_emulate.h
static inline bool vcpu_is_be(struct kvm_vcpu *vcpu)
{
	if (vcpu_mode_is_32bit(vcpu))
		return !!(*vcpu_cpsr(vcpu) & PSR_AA32_E_BIT);

	if (vcpu_mode_priv(vcpu))
		return !!(__vcpu_sys_reg(vcpu, SCTLR_EL1) & SCTLR_ELx_EE);
	else
		return !!(__vcpu_sys_reg(vcpu, SCTLR_EL1) & SCTLR_EL1_E0E);
}

struct kvm_vcpu *pvm_mpidr_to_vcpu(struct kvm_shadow_vm *vm, unsigned long mpidr)
{
	struct kvm_vcpu *vcpu;
	int i;

	mpidr &= MPIDR_HWID_BITMASK;

	for (i = 0; i < vm->created_vcpus; i++) {
		vcpu = vm->vcpus[i];

		if (mpidr == vcpu_get_mpidr_aff(vcpu))
			return vcpu;
	}

	return NULL;
}

/*
 * Returns true if the hypervisor handled PSCI call, and control should go back
 * to the guest, or false if the host needs to do some additional work (i.e.,
 * wake up the vcpu).
 */
static bool pvm_psci_vcpu_on(struct kvm_vcpu *source_vcpu)
{
	struct kvm_shadow_vm *vm = source_vcpu->arch.pkvm.shadow_vm;
	struct kvm_vcpu *vcpu;
	struct vcpu_reset_state *reset_state;
	unsigned long cpu_id;
	unsigned long hvc_ret_val;
	enum kvm_vcpu_power_state power_state;

	cpu_id = smccc_get_arg1(source_vcpu);
	if (!kvm_psci_valid_affinity(source_vcpu, cpu_id)) {
		hvc_ret_val = PSCI_RET_INVALID_PARAMS;
		goto error;
	}

	vcpu = pvm_mpidr_to_vcpu(vm, cpu_id);

	/* Make sure the caller requested a valid vcpu. */
	if (!vcpu) {
		hvc_ret_val = PSCI_RET_INVALID_PARAMS;
		goto error;
	}

	/*
	 * Make sure the requested vcpu is not on to begin with.
	 * Atomic to avoid race between vcpus trying to power on the same vcpu.
	 */
	power_state = cmpxchg(&vcpu->arch.pkvm.power_state, OFF, PENDING_ON);
	if (power_state != OFF) {
		hvc_ret_val = PSCI_RET_ALREADY_ON;
		goto error;
	}

	// TODO: Should never happen. For debugging.
	WARN_ON(!vcpu->arch.power_off);

	reset_state = &vcpu->arch.reset_state;

	reset_state->pc = smccc_get_arg2(source_vcpu);

	/* Propagate caller endianness */
	reset_state->be = vcpu_is_be(source_vcpu);

	/*
	 * NOTE: We always update r0 (or x0) because for PSCI v0.1
	 * the general purpose registers are undefined upon CPU_ON.
	 */
	reset_state->r0 = smccc_get_arg3(source_vcpu);

	reset_state->reset = true;

	/*
	 * Return to the host, which should make the KVM_REQ_VCPU_RESET request
	 * as well as kvm_vcpu_wake_up() to schedule the vcpu.
	 */
	return false;

error:
	/* If there's an error go back straight to the guest. */
	smccc_set_retval(source_vcpu, hvc_ret_val, 0, 0, 0);
	return true;
}

static bool pvm_psci_vcpu_affinity_info(struct kvm_vcpu *vcpu)
{
	int i, matching_cpus = 0;
	unsigned long mpidr;
	unsigned long target_affinity;
	unsigned long target_affinity_mask;
	unsigned long lowest_affinity_level;
	struct kvm_shadow_vm *vm = vcpu->arch.pkvm.shadow_vm;
	struct kvm_vcpu *tmp;
	unsigned long hvc_ret_val;

	target_affinity = smccc_get_arg1(vcpu);
	lowest_affinity_level = smccc_get_arg2(vcpu);

	if (!kvm_psci_valid_affinity(vcpu, target_affinity)) {
		hvc_ret_val = PSCI_RET_INVALID_PARAMS;
		goto done;
	}

	/* Determine target affinity mask */
	target_affinity_mask = psci_affinity_mask(lowest_affinity_level);
	if (!target_affinity_mask) {
		hvc_ret_val = PSCI_RET_INVALID_PARAMS;
		goto done;
	}

	/* Ignore other bits of target affinity */
	target_affinity &= target_affinity_mask;

	/*
	 * If one or more VCPU matching target affinity are running
	 * then ON else OFF
	 */
	for (i = 0; i < vm->created_vcpus; i++) {
		tmp = vm->vcpus[i];

		mpidr = vcpu_get_mpidr_aff(tmp);
		if ((mpidr & target_affinity_mask) == target_affinity) {
			matching_cpus++;
			if (!tmp->arch.power_off) {
				// TODO: make sure to use power_state if that's what we settle on
				hvc_ret_val = PSCI_0_2_AFFINITY_LEVEL_ON;
				goto done;
			}
		}
	}

	if (!matching_cpus) {
		hvc_ret_val = PSCI_RET_INVALID_PARAMS;
		goto done;
	}

	hvc_ret_val = PSCI_0_2_AFFINITY_LEVEL_OFF;

done:
	/* Nothing to be handled by the host. Go back to the guest. */
	smccc_set_retval(vcpu, hvc_ret_val, 0, 0, 0);
	return true;
}

/*
 * Returns true if the hypervisor handled PSCI call, and control should go back
 * to the guest, or false if the host needs to do some additional work (i.e.,
 * turn off and update vcpu scheduling status).
 */
static bool pvm_psci_vcpu_off(struct kvm_vcpu *vcpu)
{
	if (vcpu->vcpu_id == 0) {
		/* Not allowed to power off vcpu 0. Go back to the guest. */
		smccc_set_retval(vcpu, PSCI_RET_DENIED, 0, 0, 0);
		return true;
	}

	// TODO: Should never happen, for debugging.
	WARN_ON(vcpu->arch.power_off);
	WARN_ON(vcpu->arch.pkvm.power_state != ON);


	WRITE_ONCE(vcpu->arch.power_off, true);
	WRITE_ONCE(vcpu->arch.pkvm.power_state, OFF);

	/* Return to the host so that it can finish powering off the vcpu. */
	return false;
}

static bool pvm_psci_version(struct kvm_vcpu *vcpu)
{
	/* Nothing to be handled by the host. Go back to the guest. */
	smccc_set_retval(vcpu, PVM_PSCI_VER, 0, 0, 0);
	return true;
}

static bool pvm_psci_not_supported(struct kvm_vcpu *vcpu)
{
	/* Nothing to be handled by the host. Go back to the guest. */
	smccc_set_retval(vcpu, PSCI_RET_NOT_SUPPORTED, 0, 0, 0);
	return true;
}

bool pkvm_handle_hvc(struct kvm_vcpu *vcpu)
{
	u32 psci_fn = smccc_get_function(vcpu);

	switch (psci_fn) {
	case PSCI_0_2_FN_CPU_ON:
		kvm_psci_narrow_to_32bit(vcpu);
		fallthrough;
	case PSCI_0_2_FN64_CPU_ON:
		return pvm_psci_vcpu_on(vcpu);

	case PSCI_0_2_FN_CPU_OFF:
		return pvm_psci_vcpu_off(vcpu);

	case PSCI_0_2_FN_AFFINITY_INFO:
		kvm_psci_narrow_to_32bit(vcpu);
		fallthrough;
	case PSCI_0_2_FN64_AFFINITY_INFO:
		return pvm_psci_vcpu_affinity_info(vcpu);

	case PSCI_0_2_FN_PSCI_VERSION:
		return pvm_psci_version(vcpu);

	case PSCI_0_2_FN_CPU_SUSPEND:
	case PSCI_0_2_FN64_CPU_SUSPEND:
	case PSCI_0_2_FN_SYSTEM_OFF:
		return false; /* Handled by the host. */

	default:
		break;
	}

	return pvm_psci_not_supported(vcpu);
}
