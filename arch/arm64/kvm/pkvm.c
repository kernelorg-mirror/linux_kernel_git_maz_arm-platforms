// SPDX-License-Identifier: GPL-2.0-only
/*
 * KVM host (EL1) interface to Protected KVM (pkvm) code at EL2.
 *
 * Copyright (C) 2021 Google LLC
 * Authors: Will Deacon <will@kernel.org> and Fuad Tabba <tabba@google.com>
 */

#include <linux/io.h>
#include <linux/kvm_host.h>
#include <linux/mm.h>
#include <linux/of_fdt.h>
#include <linux/of_reserved_mem.h>

#include <asm/kvm_fixed_config.h>

static struct reserved_mem *pkvm_firmware_mem;

static int __init pkvm_firmware_rmem_err(struct reserved_mem *rmem,
					 const char *reason)
{
	phys_addr_t end = rmem->base + rmem->size;

	kvm_err("Ignoring pkvm guest firmware memory reservation [%pa - %pa]: %s\n",
		&rmem->base, &end, reason);
	return -EINVAL;
}

static int __init pkvm_firmware_rmem_init(struct reserved_mem *rmem)
{
	unsigned long node = rmem->fdt_node;

	if (kvm_get_mode() != KVM_MODE_PROTECTED)
		return pkvm_firmware_rmem_err(rmem, "protected mode not enabled");

	if (pkvm_firmware_mem)
		return pkvm_firmware_rmem_err(rmem, "duplicate reservation");

	if (!of_get_flat_dt_prop(node, "no-map", NULL))
		return pkvm_firmware_rmem_err(rmem, "missing \"no-map\" property");

	if (of_get_flat_dt_prop(node, "reusable", NULL))
		return pkvm_firmware_rmem_err(rmem, "\"reusable\" property unsupported");

	if (!PAGE_ALIGNED(rmem->base))
		return pkvm_firmware_rmem_err(rmem, "base is not page-aligned");

	if (!PAGE_ALIGNED(rmem->size))
		return pkvm_firmware_rmem_err(rmem, "size is not page-aligned");

	pkvm_firmware_mem = rmem;
	return 0;
}
RESERVEDMEM_OF_DECLARE(pkvm_firmware, "linux,pkvm-guest-firmware-memory",
		       pkvm_firmware_rmem_init);

/*
 * Set trap register values for features not allowed in ID_AA64PFR0.
 */
static void pvm_init_traps_aa64pfr0(struct kvm_vcpu *vcpu)
{
	const u64 feature_ids = PVM_ID_AA64PFR0_ALLOW;
	u64 hcr_set = 0;
	u64 hcr_clear = 0;
	u64 cptr_set = 0;

	/* Trap AArch32 guests */
	if (FIELD_GET(ARM64_FEATURE_MASK(ID_AA64PFR0_EL0), feature_ids) <
		    ID_AA64PFR0_ELx_32BIT_64BIT ||
	    FIELD_GET(ARM64_FEATURE_MASK(ID_AA64PFR0_EL1), feature_ids) <
		    ID_AA64PFR0_ELx_32BIT_64BIT)
		hcr_set |= HCR_RW | HCR_TID0;

	/* Trap RAS unless all versions are supported */
	if (FIELD_GET(ARM64_FEATURE_MASK(ID_AA64PFR0_RAS), feature_ids) <
	    ID_AA64PFR0_RAS_ANY) {
		hcr_set |= HCR_TERR | HCR_TEA;
		hcr_clear |= HCR_FIEN;
	}

	/* Trap AMU */
	if (!FIELD_GET(ARM64_FEATURE_MASK(ID_AA64PFR0_AMU), feature_ids)) {
		hcr_clear |= HCR_AMVOFFEN;
		cptr_set |= CPTR_EL2_TAM;
	}

	/* Trap ASIMD */
	if (!FIELD_GET(ARM64_FEATURE_MASK(ID_AA64PFR0_ASIMD), feature_ids))
		cptr_set |= CPTR_EL2_TFP;

	/* Trap SVE */
	if (!FIELD_GET(ARM64_FEATURE_MASK(ID_AA64PFR0_SVE), feature_ids))
		cptr_set |= CPTR_EL2_TZ;

	vcpu->arch.hcr_el2 |= hcr_set;
	vcpu->arch.hcr_el2 &= ~hcr_clear;
	vcpu->arch.cptr_el2 |= cptr_set;
}

/*
 * Set trap register values for features not allowed in ID_AA64PFR1.
 */
static void pvm_init_traps_aa64pfr1(struct kvm_vcpu *vcpu)
{
	const u64 feature_ids = PVM_ID_AA64PFR1_ALLOW;
	u64 hcr_set = 0;
	u64 hcr_clear = 0;

	/* Memory Tagging: Trap and Treat as Untagged if not allowed. */
	if (!FIELD_GET(ARM64_FEATURE_MASK(ID_AA64PFR1_MTE), feature_ids)) {
		hcr_set |= HCR_TID5;
		hcr_clear |= HCR_DCT | HCR_ATA;
	}

	vcpu->arch.hcr_el2 |= hcr_set;
	vcpu->arch.hcr_el2 &= ~hcr_clear;
}

/*
 * Set trap register values for features not allowed in ID_AA64DFR0.
 */
static void pvm_init_traps_aa64dfr0(struct kvm_vcpu *vcpu)
{
	const u64 feature_ids = PVM_ID_AA64DFR0_ALLOW;
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
 * Set trap register values for features not allowed in ID_AA64MMFR0.
 */
static void pvm_init_traps_aa64mmfr0(struct kvm_vcpu *vcpu)
{
	const u64 feature_ids = PVM_ID_AA64MMFR0_ALLOW;
	u64 mdcr_set = 0;

	/* Trap Debug Communications Channel registers */
	if (!FIELD_GET(ARM64_FEATURE_MASK(ID_AA64MMFR0_FGT), feature_ids))
		mdcr_set |= MDCR_EL2_TDCC;

	vcpu->arch.mdcr_el2 |= mdcr_set;
}

/*
 * Set trap register values for features not allowed in ID_AA64MMFR1.
 */
static void pvm_init_traps_aa64mmfr1(struct kvm_vcpu *vcpu)
{
	const u64 feature_ids = PVM_ID_AA64MMFR1_ALLOW;
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
static void kvm_init_protected_traps(struct kvm_vcpu *vcpu)
{
	pvm_init_trap_regs(vcpu);
	pvm_init_traps_aa64pfr0(vcpu);
	pvm_init_traps_aa64pfr1(vcpu);
	pvm_init_traps_aa64dfr0(vcpu);
	pvm_init_traps_aa64mmfr0(vcpu);
	pvm_init_traps_aa64mmfr1(vcpu);
}

int kvm_arm_pkvm_get_max_brps(void)
{
	int num = FIELD_GET(ARM64_FEATURE_MASK(ID_AA64DFR0_BRPS), PVM_ID_AA64DFR0_ALLOW);

	/*
	 * If breakpoints are supported, the maximum number is 1 + the field.
	 * Otherwise, return 0, which is not compliant with the architecture,
	 * but is reserved and is used here to indicate no debug support.
	 */
	if (num)
		return 1 + num;
	else
		return 0;
}

int kvm_arm_pkvm_get_max_wrps(void)
{
	int num = FIELD_GET(ARM64_FEATURE_MASK(ID_AA64DFR0_WRPS), PVM_ID_AA64DFR0_ALLOW);

	/*
	 * If breakpoints are supported, the maximum number is 1 + the field.
	 * Otherwise, return 0, which is not compliant with the architecture,
	 * but is reserved and is used here to indicate no debug support.
	 */
	if (num)
		return 1 + num;
	else
		return 0;
}

int kvm_arm_vcpu_pkvm_init(struct kvm_vcpu *vcpu)
{
	struct kvm *kvm = vcpu->kvm;

	if (!kvm_vm_is_protected(kvm))
		return 0;

	/*
	 * Initialize traps for protected VMs.
	 * NOTE: Move  trap initialization to EL2 once the code is in place for
	 * maintaining protected VM state at EL2 instead of the host.
	 */
	kvm_init_protected_traps(vcpu);

	if (!vcpu->vcpu_id) {
		int i;
		struct kvm_memory_slot *slot = kvm->arch.pkvm.firmware_slot;
		struct user_pt_regs *regs = vcpu_gp_regs(vcpu);

		if (!slot)
			return 0;

		/* X0 - X14 provided by VMM (preserved) */

		/* X15: Boot protocol version */
		regs->regs[15] = 0;

		/* X16 - X30 reserved (zeroed) */
		for (i = 16; i <= 30; ++i)
			regs->regs[i] = 0;

		/* PC: IPA base of bootloader memslot */
		regs->pc = slot->base_gfn << PAGE_SHIFT;

		/* SP: IPA end of bootloader memslot */
		regs->sp = (slot->base_gfn + slot->npages) << PAGE_SHIFT;
	} else if (!test_bit(KVM_ARM_VCPU_POWER_OFF, vcpu->arch.features)) {
		return -EPERM;
	}

	return 0;
}

static int __do_not_call_this_function(struct kvm_memory_slot *slot)
{
	int uncopied;
	size_t sz = pkvm_firmware_mem->size;
	void *src, __user *dst = (__force void __user *)slot->userspace_addr;

	if (clear_user(dst, slot->npages * PAGE_SIZE))
		return -EFAULT;

	src = memremap(pkvm_firmware_mem->base, sz, MEMREMAP_WB);
	if (!src)
		return -EFAULT;

	//((u32 *)src)[0] = 0xaa0f03e0; // MOV	X0, X15
	//((u32 *)src)[1] = 0xd61f0200; // BR	X16
	uncopied = copy_to_user(dst, src, sz);
	memunmap(src);
	return uncopied ? -EFAULT : 0;
}

static int pkvm_init_el2_context(struct kvm *kvm)
{
#if 0
	/*
	 * TODO:
	 * Eventually, this will involve a call to EL2 to:
	 * - Register this VM as a protected VM
	 * - Provide pages for the firmware
	 * - Unmap memslots from the host
	 * - Force reset state and lock down access
	 * - Prevent attempts to run unknown vCPUs
	 * - Ensure that no vCPUs have previously entered the VM
	 * - ...
	 */
	kvm_pr_unimpl("Stage-2 protection is not yet implemented; ignoring\n");
	return 0;
#else
	return __do_not_call_this_function(kvm->arch.pkvm.firmware_slot);
#endif
}

static int pkvm_init_firmware_slot(struct kvm *kvm, u64 slotid)
{
	struct kvm_memslots *slots;
	struct kvm_memory_slot *slot;

	if (slotid >= KVM_MEM_SLOTS_NUM || !pkvm_firmware_mem)
		return -EINVAL;

	slots = kvm_memslots(kvm);
	if (!slots)
		return -ENOENT;

	slot = id_to_memslot(slots, slotid);
	if (!slot)
		return -ENOENT;

	if (slot->flags)
		return -EINVAL;

	if ((slot->npages << PAGE_SHIFT) < pkvm_firmware_mem->size)
		return -ENOMEM;

	kvm->arch.pkvm.firmware_slot = slot;
	return 0;
}

static void pkvm_teardown_firmware_slot(struct kvm *kvm)
{
	kvm->arch.pkvm.firmware_slot = NULL;
}

static int pkvm_enable(struct kvm *kvm, u64 slotid)
{
	int ret;

	ret = pkvm_init_firmware_slot(kvm, slotid);
	if (ret)
		return ret;

	ret = pkvm_init_el2_context(kvm);
	if (ret)
		pkvm_teardown_firmware_slot(kvm);

	return ret;
}

static int pkvm_vm_ioctl_enable(struct kvm *kvm, u64 slotid)
{
	int ret = 0;

	mutex_lock(&kvm->lock);
	if (kvm_vm_is_protected(kvm)) {
		ret = -EPERM;
		goto out_kvm_unlock;
	}

	mutex_lock(&kvm->slots_lock);
	ret = pkvm_enable(kvm, slotid);
	if (ret)
		goto out_slots_unlock;

	kvm->arch.pkvm.enabled = true;
out_slots_unlock:
	mutex_unlock(&kvm->slots_lock);
out_kvm_unlock:
	mutex_unlock(&kvm->lock);
	return ret;
}

static int pkvm_vm_ioctl_info(struct kvm *kvm,
			      struct kvm_protected_vm_info __user *info)
{
	struct kvm_protected_vm_info kinfo = {
		.firmware_size = pkvm_firmware_mem ?
				 pkvm_firmware_mem->size :
				 0,
	};

	return copy_to_user(info, &kinfo, sizeof(kinfo)) ? -EFAULT : 0;
}

int kvm_arm_vm_ioctl_pkvm(struct kvm *kvm, struct kvm_enable_cap *cap)
{
	if (cap->args[1] || cap->args[2] || cap->args[3])
		return -EINVAL;

	switch (cap->flags) {
	case KVM_CAP_ARM_PROTECTED_VM_FLAGS_ENABLE:
		return pkvm_vm_ioctl_enable(kvm, cap->args[0]);
	case KVM_CAP_ARM_PROTECTED_VM_FLAGS_INFO:
		return pkvm_vm_ioctl_info(kvm, (void __user *)cap->args[0]);
	default:
		return -EINVAL;
	}

	return 0;
}
