// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2021 Google LLC
 * Author: Fuad Tabba <tabba@google.com>
 */

#include <linux/kvm_host.h>

#include <asm/kvm_asm.h>
#include <asm/kvm_emulate.h>
#include <asm/kvm_fixed_config.h>
#include <asm/kvm_mmu.h>

#include <hyp/adjust_pc.h>

#include "../../sys_regs.h"

/*
 * Copies of the host's CPU features registers holding sanitized values.
 */
u64 id_aa64pfr0_el1_sys_val;
u64 id_aa64pfr1_el1_sys_val;
u64 id_aa64mmfr2_el1_sys_val;

/*
 * Inject an unknown/undefined exception to the guest.
 */
static void inject_undef(struct kvm_vcpu *vcpu)
{
	u32 esr = (ESR_ELx_EC_UNKNOWN << ESR_ELx_EC_SHIFT);

	vcpu->arch.flags |= (KVM_ARM64_EXCEPT_AA64_EL1 |
			     KVM_ARM64_EXCEPT_AA64_ELx_SYNC |
			     KVM_ARM64_PENDING_EXCEPTION);

	__kvm_adjust_pc(vcpu);

	write_sysreg_el1(esr, SYS_ESR);
	write_sysreg_el1(read_sysreg_el2(SYS_ELR), SYS_ELR);
}

/*
 * Accessor for undefined accesses.
 */
static bool undef_access(struct kvm_vcpu *vcpu,
			 struct sys_reg_params *p,
			 const struct sys_reg_desc *r)
{
	inject_undef(vcpu);
	return false;
}

/*
 * Accessors for feature registers.
 *
 * If access is allowed, set the regval to the protected VM's view of the
 * register and return true.
 * Otherwise, inject an undefined exception and return false.
 */

/*
 * Returns the minimum feature supported and allowed.
 */
static u64 get_min_feature(u64 feature, u64 allowed_features,
			   u64 supported_features)
{
	const u64 allowed_feature = FIELD_GET(feature, allowed_features);
	const u64 supported_feature = FIELD_GET(feature, supported_features);

	return min(allowed_feature, supported_feature);
}

/* Accessor for ID_AA64PFR0_EL1. */
static bool pvm_access_id_aa64pfr0(struct kvm_vcpu *vcpu,
				   struct sys_reg_params *p,
				   const struct sys_reg_desc *r)
{
	const struct kvm *kvm = (const struct kvm *) kern_hyp_va(vcpu->kvm);
	const u64 feature_ids = PVM_ID_AA64PFR0_ALLOW;
	u64 set_mask = 0;
	u64 clear_mask = 0;

	if (p->is_write)
		return undef_access(vcpu, p, r);

	/* Get the RAS version allowed and supported */
	clear_mask |= ARM64_FEATURE_MASK(ID_AA64PFR0_RAS);
	set_mask |= FIELD_PREP(ARM64_FEATURE_MASK(ID_AA64PFR0_RAS),
			       get_min_feature(ARM64_FEATURE_MASK(ID_AA64PFR0_RAS),
					       feature_ids,
					       id_aa64pfr0_el1_sys_val));

	/* AArch32 guests: if not allowed then force guests to 64-bits only */
	clear_mask |= ARM64_FEATURE_MASK(ID_AA64PFR0_EL0) | ARM64_FEATURE_MASK(ID_AA64PFR0_EL1) |
		      ARM64_FEATURE_MASK(ID_AA64PFR0_EL2) | ARM64_FEATURE_MASK(ID_AA64PFR0_EL3);

	set_mask |= FIELD_PREP(ARM64_FEATURE_MASK(ID_AA64PFR0_EL0),
			       get_min_feature(ARM64_FEATURE_MASK(ID_AA64PFR0_EL0),
					       feature_ids,
			                       id_aa64pfr0_el1_sys_val));
	set_mask |= FIELD_PREP(ARM64_FEATURE_MASK(ID_AA64PFR0_EL1),
			       get_min_feature(ARM64_FEATURE_MASK(ID_AA64PFR0_EL1),
					       feature_ids,
			                       id_aa64pfr0_el1_sys_val));
	set_mask |= FIELD_PREP(ARM64_FEATURE_MASK(ID_AA64PFR0_EL2),
			       get_min_feature(ARM64_FEATURE_MASK(ID_AA64PFR0_EL2),
					       feature_ids,
			                       id_aa64pfr0_el1_sys_val));
	set_mask |= FIELD_PREP(ARM64_FEATURE_MASK(ID_AA64PFR0_EL3),
			       get_min_feature(ARM64_FEATURE_MASK(ID_AA64PFR0_EL3),
					       feature_ids,
			                       id_aa64pfr0_el1_sys_val));

	/* Spectre and Meltdown mitigation */
	set_mask |= FIELD_PREP(ARM64_FEATURE_MASK(ID_AA64PFR0_CSV2),
			       (u64)kvm->arch.pfr0_csv2);
	set_mask |= FIELD_PREP(ARM64_FEATURE_MASK(ID_AA64PFR0_CSV3),
			       (u64)kvm->arch.pfr0_csv3);

	p->regval = (id_aa64pfr0_el1_sys_val & feature_ids & ~clear_mask) |
		    set_mask;
	return true;
}

/* Accessor for ID_AA64PFR1_EL1. */
static bool pvm_access_id_aa64pfr1(struct kvm_vcpu *vcpu,
				   struct sys_reg_params *p,
				   const struct sys_reg_desc *r)
{
	const u64 feature_ids = PVM_ID_AA64PFR1_ALLOW;

	if (p->is_write)
		return undef_access(vcpu, p, r);

	p->regval = id_aa64pfr1_el1_sys_val & feature_ids;
	return true;
}

/* Accessor for ID_AA64ZFR0_EL1. */
static bool pvm_access_id_aa64zfr0(struct kvm_vcpu *vcpu,
				   struct sys_reg_params *p,
				   const struct sys_reg_desc *r)
{
	if (p->is_write)
		return undef_access(vcpu, p, r);

	/*
	 * No support for Scalable Vectors, therefore, pKVM has no sanitized
	 * copy of the feature id register.
	 */
	BUILD_BUG_ON(PVM_ID_AA64ZFR0_ALLOW != 0ULL);

	p->regval = 0;
	return true;
}

/* Accessor for ID_AA64DFR0_EL1. */
static bool pvm_access_id_aa64dfr0(struct kvm_vcpu *vcpu,
				   struct sys_reg_params *p,
				   const struct sys_reg_desc *r)
{
	if (p->is_write)
		return undef_access(vcpu, p, r);

	/*
	 * No support for debug, including breakpoints, and watchpoints,
	 * therefore, pKVM has no sanitized copy of the feature id register.
	 */
	BUILD_BUG_ON(PVM_ID_AA64DFR0_ALLOW != 0ULL);

	p->regval = 0;
	return true;
}

/*
 * No restrictions on ID_AA64ISAR1_EL1 features, therefore, pKVM has no
 * sanitized copy of the feature id register and it's handled by the host.
 */
static_assert(PVM_ID_AA64ISAR1_ALLOW == ~0ULL);

/* Accessor for ID_AA64MMFR0_EL1. */
static bool pvm_access_id_aa64mmfr0(struct kvm_vcpu *vcpu,
				    struct sys_reg_params *p,
				    const struct sys_reg_desc *r)
{
	const u64 feature_ids = PVM_ID_AA64MMFR0_ALLOW;
	u64 set_mask = PVM_ID_AA64MMFR0_SET;

	if (p->is_write)
		return undef_access(vcpu, p, r);

	p->regval = (id_aa64mmfr0_el1_sys_val & feature_ids) | set_mask;
	return true;
}

/* Accessor for ID_AA64MMFR1_EL1. */
static bool pvm_access_id_aa64mmfr1(struct kvm_vcpu *vcpu,
				    struct sys_reg_params *p,
				    const struct sys_reg_desc *r)
{
	const u64 feature_ids = PVM_ID_AA64MMFR1_ALLOW;

	if (p->is_write)
		return undef_access(vcpu, p, r);

	p->regval = id_aa64mmfr1_el1_sys_val & feature_ids;
	return true;
}

/* Accessor for ID_AA64MMFR2_EL1. */
static bool pvm_access_id_aa64mmfr2(struct kvm_vcpu *vcpu,
				    struct sys_reg_params *p,
				    const struct sys_reg_desc *r)
{
	const u64 feature_ids = PVM_ID_AA64MMFR2_ALLOW;

	if (p->is_write)
		return undef_access(vcpu, p, r);

	p->regval = id_aa64mmfr2_el1_sys_val & feature_ids;
	return true;
}

/*
 * Accessor for AArch32 Processor Feature Registers.
 *
 * The value of these registers is "unknown" according to the spec if AArch32
 * isn't supported.
 */
static bool pvm_access_id_aarch32(struct kvm_vcpu *vcpu,
				  struct sys_reg_params *p,
				  const struct sys_reg_desc *r)
{
	if (p->is_write)
		return undef_access(vcpu, p, r);

	/*
	 * No support for AArch32 guests, therefore, pKVM has no sanitized copy
	 * of AArch 32 feature id registers.
	 */
	BUILD_BUG_ON(FIELD_GET(ARM64_FEATURE_MASK(ID_AA64PFR0_EL1),
		     PVM_ID_AA64PFR0_ALLOW) > ID_AA64PFR0_ELx_64BIT_ONLY);

	/* Use 0 for architecturally "unknown" values. */
	p->regval = 0;
	return true;
}

/* Mark the specified system register as an AArch32 feature register. */
#define AARCH32(REG) { SYS_DESC(REG), .access = pvm_access_id_aarch32 }

/* Mark the specified system register as not being handled in hyp. */
#define HOST_HANDLED(REG) { SYS_DESC(REG), .access = NULL }

/*
 * Architected system registers.
 * Important: Must be sorted ascending by Op0, Op1, CRn, CRm, Op2
 *
 * NOTE: Anything not explicitly listed here will be *restricted by default*,
 * i.e., it will lead to injecting an exception into the guest.
 */
static const struct sys_reg_desc pvm_sys_reg_descs[] = {
	/* Cache maintenance by set/way operations are restricted. */

	/* Debug and Trace Registers are all restricted */

	/* AArch64 mappings of the AArch32 ID registers */
	/* CRm=1 */
	AARCH32(SYS_ID_PFR0_EL1),
	AARCH32(SYS_ID_PFR1_EL1),
	AARCH32(SYS_ID_DFR0_EL1),
	AARCH32(SYS_ID_AFR0_EL1),
	AARCH32(SYS_ID_MMFR0_EL1),
	AARCH32(SYS_ID_MMFR1_EL1),
	AARCH32(SYS_ID_MMFR2_EL1),
	AARCH32(SYS_ID_MMFR3_EL1),

	/* CRm=2 */
	AARCH32(SYS_ID_ISAR0_EL1),
	AARCH32(SYS_ID_ISAR1_EL1),
	AARCH32(SYS_ID_ISAR2_EL1),
	AARCH32(SYS_ID_ISAR3_EL1),
	AARCH32(SYS_ID_ISAR4_EL1),
	AARCH32(SYS_ID_ISAR5_EL1),
	AARCH32(SYS_ID_MMFR4_EL1),
	AARCH32(SYS_ID_ISAR6_EL1),

	/* CRm=3 */
	AARCH32(SYS_MVFR0_EL1),
	AARCH32(SYS_MVFR1_EL1),
	AARCH32(SYS_MVFR2_EL1),
	AARCH32(SYS_ID_PFR2_EL1),
	AARCH32(SYS_ID_DFR1_EL1),
	AARCH32(SYS_ID_MMFR5_EL1),

	/* AArch64 ID registers */
	/* CRm=4 */
	{ SYS_DESC(SYS_ID_AA64PFR0_EL1), .access = pvm_access_id_aa64pfr0 },
	{ SYS_DESC(SYS_ID_AA64PFR1_EL1), .access = pvm_access_id_aa64pfr1 },
	{ SYS_DESC(SYS_ID_AA64ZFR0_EL1), .access = pvm_access_id_aa64zfr0 },
	{ SYS_DESC(SYS_ID_AA64DFR0_EL1), .access = pvm_access_id_aa64dfr0 },
	HOST_HANDLED(SYS_ID_AA64DFR1_EL1),
	HOST_HANDLED(SYS_ID_AA64AFR0_EL1),
	HOST_HANDLED(SYS_ID_AA64AFR1_EL1),
	HOST_HANDLED(SYS_ID_AA64ISAR0_EL1),
	HOST_HANDLED(SYS_ID_AA64ISAR1_EL1),
	{ SYS_DESC(SYS_ID_AA64MMFR0_EL1), .access = pvm_access_id_aa64mmfr0 },
	{ SYS_DESC(SYS_ID_AA64MMFR1_EL1), .access = pvm_access_id_aa64mmfr1 },
	{ SYS_DESC(SYS_ID_AA64MMFR2_EL1), .access = pvm_access_id_aa64mmfr2 },

	HOST_HANDLED(SYS_SCTLR_EL1),
	HOST_HANDLED(SYS_ACTLR_EL1),
	HOST_HANDLED(SYS_CPACR_EL1),

	HOST_HANDLED(SYS_RGSR_EL1),
	HOST_HANDLED(SYS_GCR_EL1),

	/* Scalable Vector Registers are restricted. */

	HOST_HANDLED(SYS_TTBR0_EL1),
	HOST_HANDLED(SYS_TTBR1_EL1),
	HOST_HANDLED(SYS_TCR_EL1),

	HOST_HANDLED(SYS_APIAKEYLO_EL1),
	HOST_HANDLED(SYS_APIAKEYHI_EL1),
	HOST_HANDLED(SYS_APIBKEYLO_EL1),
	HOST_HANDLED(SYS_APIBKEYHI_EL1),
	HOST_HANDLED(SYS_APDAKEYLO_EL1),
	HOST_HANDLED(SYS_APDAKEYHI_EL1),
	HOST_HANDLED(SYS_APDBKEYLO_EL1),
	HOST_HANDLED(SYS_APDBKEYHI_EL1),
	HOST_HANDLED(SYS_APGAKEYLO_EL1),
	HOST_HANDLED(SYS_APGAKEYHI_EL1),

	HOST_HANDLED(SYS_AFSR0_EL1),
	HOST_HANDLED(SYS_AFSR1_EL1),
	HOST_HANDLED(SYS_ESR_EL1),

	HOST_HANDLED(SYS_ERRIDR_EL1),
	HOST_HANDLED(SYS_ERRSELR_EL1),
	HOST_HANDLED(SYS_ERXFR_EL1),
	HOST_HANDLED(SYS_ERXCTLR_EL1),
	HOST_HANDLED(SYS_ERXSTATUS_EL1),
	HOST_HANDLED(SYS_ERXADDR_EL1),
	HOST_HANDLED(SYS_ERXMISC0_EL1),
	HOST_HANDLED(SYS_ERXMISC1_EL1),

	HOST_HANDLED(SYS_TFSR_EL1),
	HOST_HANDLED(SYS_TFSRE0_EL1),

	HOST_HANDLED(SYS_FAR_EL1),
	HOST_HANDLED(SYS_PAR_EL1),

	/* Performance Monitoring Registers are restricted. */

	HOST_HANDLED(SYS_MAIR_EL1),
	HOST_HANDLED(SYS_AMAIR_EL1),

	/* Limited Ordering Regions Registers are restricted. */

	HOST_HANDLED(SYS_VBAR_EL1),
	HOST_HANDLED(SYS_DISR_EL1),

	/* GIC CPU Interface registers are restricted. */

	HOST_HANDLED(SYS_CONTEXTIDR_EL1),
	HOST_HANDLED(SYS_TPIDR_EL1),

	HOST_HANDLED(SYS_SCXTNUM_EL1),

	HOST_HANDLED(SYS_CNTKCTL_EL1),

	HOST_HANDLED(SYS_CCSIDR_EL1),
	HOST_HANDLED(SYS_CLIDR_EL1),
	HOST_HANDLED(SYS_CSSELR_EL1),
	HOST_HANDLED(SYS_CTR_EL0),

	/* Performance Monitoring Registers are restricted. */

	HOST_HANDLED(SYS_TPIDR_EL0),
	HOST_HANDLED(SYS_TPIDRRO_EL0),

	HOST_HANDLED(SYS_SCXTNUM_EL0),

	/* Activity Monitoring Registers are restricted. */

	HOST_HANDLED(SYS_CNTP_TVAL_EL0),
	HOST_HANDLED(SYS_CNTP_CTL_EL0),
	HOST_HANDLED(SYS_CNTP_CVAL_EL0),

	/* Performance Monitoring Registers are restricted. */

	HOST_HANDLED(SYS_DACR32_EL2),
	HOST_HANDLED(SYS_IFSR32_EL2),
	HOST_HANDLED(SYS_FPEXC32_EL2),
};

/*
 * Handler for protected VM MSR, MRS or System instruction execution in AArch64.
 *
 * Return 1 if handled, or 0 if not.
 */
int kvm_handle_pvm_sys64(struct kvm_vcpu *vcpu)
{
	const struct sys_reg_desc *r;
	struct sys_reg_params params;
	unsigned long esr = kvm_vcpu_get_esr(vcpu);
	int Rt = kvm_vcpu_sys_get_rt(vcpu);

	params = esr_sys64_to_params(esr);
	params.regval = vcpu_get_reg(vcpu, Rt);

	r = find_reg(&params, pvm_sys_reg_descs, ARRAY_SIZE(pvm_sys_reg_descs));

	/* Undefined access (RESTRICTED). */
	if (r == NULL) {
		inject_undef(vcpu);
		return 1;
	}

	/* Handled by the host (HOST_HANDLED) */
	if (r->access == NULL)
		return 0;

	/* Handled by hyp: skip instruction if instructed to do so. */
	if (r->access(vcpu, &params, r))
		__kvm_skip_instr(vcpu);

	vcpu_set_reg(vcpu, Rt, params.regval);
	return 1;
}

/*
 * Handler for protected VM restricted exceptions.
 *
 * Inject an undefined exception into the guest and return 1 to indicate that
 * it was handled.
 */
int kvm_handle_pvm_restricted(struct kvm_vcpu *vcpu)
{
	inject_undef(vcpu);
	return 1;
}
