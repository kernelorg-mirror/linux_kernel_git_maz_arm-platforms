// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2012-2015 - ARM Ltd
 * Author: Marc Zyngier <marc.zyngier@arm.com>
 */

#include <linux/compiler.h>
#include <linux/kvm_host.h>

#include <asm/kprobes.h>
#include <asm/kvm_asm.h>
#include <asm/kvm_emulate.h>
#include <asm/kvm_hyp.h>

/*
 * Non-VHE: Both host and guest must save everything.
 *
 * VHE: Host and guest must save mdscr_el1 and sp_el0 (and the PC and
 * pstate, which are handled as part of the el2 return state) on every
 * switch (sp_el0 is being dealt with in the assembly code).
 * tpidr_el0 and tpidrro_el0 only need to be switched when going
 * to host userspace or a different VCPU.  EL1 registers only need to be
 * switched when potentially going to run a different VCPU.  The latter two
 * classes are handled as part of kvm_arch_vcpu_load and kvm_arch_vcpu_put.
 */

static void __hyp_text __sysreg_save_common_state(struct kvm_cpu_context *ctxt)
{
	ctxt_sys_reg(ctxt, MDSCR_EL1)	= read_sysreg(mdscr_el1);
}

static void __hyp_text __sysreg_save_user_state(struct kvm_cpu_context *ctxt)
{
	ctxt_sys_reg(ctxt, TPIDR_EL0)	= read_sysreg(tpidr_el0);
	ctxt_sys_reg(ctxt, TPIDRRO_EL0)	= read_sysreg(tpidrro_el0);
}

static void __hyp_text __sysreg_save_el1_state(struct kvm_cpu_context *ctxt)
{
	ctxt_sys_reg(ctxt, CSSELR_EL1)	= read_sysreg(csselr_el1);
	ctxt_sys_reg(ctxt, SCTLR_EL1)	= read_sysreg_el1(SYS_SCTLR);
	ctxt_sys_reg(ctxt, CPACR_EL1)	= read_sysreg_el1(SYS_CPACR);
	ctxt_sys_reg(ctxt, TTBR0_EL1)	= read_sysreg_el1(SYS_TTBR0);
	ctxt_sys_reg(ctxt, TTBR1_EL1)	= read_sysreg_el1(SYS_TTBR1);
	ctxt_sys_reg(ctxt, TCR_EL1)	= read_sysreg_el1(SYS_TCR);
	ctxt_sys_reg(ctxt, ESR_EL1)	= read_sysreg_el1(SYS_ESR);
	ctxt_sys_reg(ctxt, AFSR0_EL1)	= read_sysreg_el1(SYS_AFSR0);
	ctxt_sys_reg(ctxt, AFSR1_EL1)	= read_sysreg_el1(SYS_AFSR1);
	ctxt_sys_reg(ctxt, FAR_EL1)	= read_sysreg_el1(SYS_FAR);
	ctxt_sys_reg(ctxt, MAIR_EL1)	= read_sysreg_el1(SYS_MAIR);
	ctxt_sys_reg(ctxt, VBAR_EL1)	= read_sysreg_el1(SYS_VBAR);
	ctxt_sys_reg(ctxt, CONTEXTIDR_EL1) = read_sysreg_el1(SYS_CONTEXTIDR);
	ctxt_sys_reg(ctxt, AMAIR_EL1)	= read_sysreg_el1(SYS_AMAIR);
	ctxt_sys_reg(ctxt, CNTKCTL_EL1)	= read_sysreg_el1(SYS_CNTKCTL);
	ctxt_sys_reg(ctxt, PAR_EL1)	= read_sysreg(par_el1);
	ctxt_sys_reg(ctxt, TPIDR_EL1)	= read_sysreg(tpidr_el1);

	ctxt->sp_el1			= read_sysreg(sp_el1);
	ctxt_sys_reg(ctxt, ELR_EL1)	= read_sysreg_el1(SYS_ELR);
	ctxt->spsr[KVM_SPSR_EL1]	= read_sysreg_el1(SYS_SPSR);
}

static void __hyp_text __sysreg_save_el2_return_state(struct kvm_cpu_context *ctxt)
{
	ctxt->regs.pc			= read_sysreg_el2(SYS_ELR);
	ctxt->regs.pstate		= read_sysreg_el2(SYS_SPSR);

	if (cpus_have_final_cap(ARM64_HAS_RAS_EXTN))
		ctxt_sys_reg(ctxt, DISR_EL1) = read_sysreg_s(SYS_VDISR_EL2);
}

void __hyp_text __sysreg_save_state_nvhe(struct kvm_cpu_context *ctxt)
{
	__sysreg_save_el1_state(ctxt);
	__sysreg_save_common_state(ctxt);
	__sysreg_save_user_state(ctxt);
	__sysreg_save_el2_return_state(ctxt);
}

void sysreg_save_host_state_vhe(struct kvm_cpu_context *ctxt)
{
	__sysreg_save_common_state(ctxt);
}
NOKPROBE_SYMBOL(sysreg_save_host_state_vhe);

void sysreg_save_guest_state_vhe(struct kvm_cpu_context *ctxt)
{
	__sysreg_save_common_state(ctxt);
	__sysreg_save_el2_return_state(ctxt);
}
NOKPROBE_SYMBOL(sysreg_save_guest_state_vhe);

static void __hyp_text __sysreg_restore_common_state(struct kvm_cpu_context *ctxt)
{
	write_sysreg(ctxt_sys_reg(ctxt, MDSCR_EL1),  mdscr_el1);
}

static void __hyp_text __sysreg_restore_user_state(struct kvm_cpu_context *ctxt)
{
	write_sysreg(ctxt_sys_reg(ctxt, TPIDR_EL0),	tpidr_el0);
	write_sysreg(ctxt_sys_reg(ctxt, TPIDRRO_EL0),	tpidrro_el0);
}

static void __hyp_text __sysreg_restore_el1_state(struct kvm_cpu_context *ctxt)
{
	write_sysreg(ctxt_sys_reg(ctxt, MPIDR_EL1),	vmpidr_el2);
	write_sysreg(ctxt_sys_reg(ctxt, CSSELR_EL1),	csselr_el1);

	if (has_vhe() ||
	    !cpus_have_final_cap(ARM64_WORKAROUND_SPECULATIVE_AT)) {
		write_sysreg_el1(ctxt_sys_reg(ctxt, SCTLR_EL1),	SYS_SCTLR);
		write_sysreg_el1(ctxt_sys_reg(ctxt, TCR_EL1),	SYS_TCR);
	} else	if (!ctxt->__hyp_running_vcpu) {
		/*
		 * Must only be done for guest registers, hence the context
		 * test. We're coming from the host, so SCTLR.M is already
		 * set. Pairs with __activate_traps_nvhe().
		 */
		write_sysreg_el1((ctxt_sys_reg(ctxt, TCR_EL1) |
				  TCR_EPD1_MASK | TCR_EPD0_MASK),
				 SYS_TCR);
		isb();
	}

	write_sysreg_el1(ctxt_sys_reg(ctxt, CPACR_EL1),	SYS_CPACR);
	write_sysreg_el1(ctxt_sys_reg(ctxt, TTBR0_EL1),	SYS_TTBR0);
	write_sysreg_el1(ctxt_sys_reg(ctxt, TTBR1_EL1),	SYS_TTBR1);
	write_sysreg_el1(ctxt_sys_reg(ctxt, ESR_EL1),	SYS_ESR);
	write_sysreg_el1(ctxt_sys_reg(ctxt, AFSR0_EL1),	SYS_AFSR0);
	write_sysreg_el1(ctxt_sys_reg(ctxt, AFSR1_EL1),	SYS_AFSR1);
	write_sysreg_el1(ctxt_sys_reg(ctxt, FAR_EL1),	SYS_FAR);
	write_sysreg_el1(ctxt_sys_reg(ctxt, MAIR_EL1),	SYS_MAIR);
	write_sysreg_el1(ctxt_sys_reg(ctxt, VBAR_EL1),	SYS_VBAR);
	write_sysreg_el1(ctxt_sys_reg(ctxt, CONTEXTIDR_EL1), SYS_CONTEXTIDR);
	write_sysreg_el1(ctxt_sys_reg(ctxt, AMAIR_EL1),	SYS_AMAIR);
	write_sysreg_el1(ctxt_sys_reg(ctxt, CNTKCTL_EL1), SYS_CNTKCTL);
	write_sysreg(ctxt_sys_reg(ctxt, PAR_EL1),	par_el1);
	write_sysreg(ctxt_sys_reg(ctxt, TPIDR_EL1),	tpidr_el1);

	if (!has_vhe() &&
	    cpus_have_final_cap(ARM64_WORKAROUND_SPECULATIVE_AT) &&
	    ctxt->__hyp_running_vcpu) {
		/*
		 * Must only be done for host registers, hence the context
		 * test. Pairs with __deactivate_traps_nvhe().
		 */
		isb();
		/*
		 * At this stage, and thanks to the above isb(), S2 is
		 * deconfigured and disabled. We can now restore the host's
		 * S1 configuration: SCTLR, and only then TCR.
		 */
		write_sysreg_el1(ctxt_sys_reg(ctxt, SCTLR_EL1),	SYS_SCTLR);
		isb();
		write_sysreg_el1(ctxt_sys_reg(ctxt, TCR_EL1),	SYS_TCR);
	}

	write_sysreg(ctxt->sp_el1,			sp_el1);
	write_sysreg_el1(ctxt_sys_reg(ctxt, ELR_EL1),	SYS_ELR);
	write_sysreg_el1(ctxt->spsr[KVM_SPSR_EL1],	SYS_SPSR);
}

static void __hyp_text
__sysreg_restore_el2_return_state(struct kvm_cpu_context *ctxt)
{
	u64 pstate = ctxt->regs.pstate;
	u64 mode = pstate & PSR_AA32_MODE_MASK;

	/*
	 * Safety check to ensure we're setting the CPU up to enter the guest
	 * in a less privileged mode.
	 *
	 * If we are attempting a return to EL2 or higher in AArch64 state,
	 * program SPSR_EL2 with M=EL2h and the IL bit set which ensures that
	 * we'll take an illegal exception state exception immediately after
	 * the ERET to the guest.  Attempts to return to AArch32 Hyp will
	 * result in an illegal exception return because EL2's execution state
	 * is determined by SCR_EL3.RW.
	 */
	if (!(mode & PSR_MODE32_BIT) && mode >= PSR_MODE_EL2t)
		pstate = PSR_MODE_EL2h | PSR_IL_BIT;

	write_sysreg_el2(ctxt->regs.pc,			SYS_ELR);
	write_sysreg_el2(pstate,			SYS_SPSR);

	if (cpus_have_final_cap(ARM64_HAS_RAS_EXTN))
		write_sysreg_s(ctxt_sys_reg(ctxt, DISR_EL1), SYS_VDISR_EL2);
}

void __hyp_text __sysreg_restore_state_nvhe(struct kvm_cpu_context *ctxt)
{
	__sysreg_restore_el1_state(ctxt);
	__sysreg_restore_common_state(ctxt);
	__sysreg_restore_user_state(ctxt);
	__sysreg_restore_el2_return_state(ctxt);
}

void sysreg_restore_host_state_vhe(struct kvm_cpu_context *ctxt)
{
	__sysreg_restore_common_state(ctxt);
}
NOKPROBE_SYMBOL(sysreg_restore_host_state_vhe);

void sysreg_restore_guest_state_vhe(struct kvm_cpu_context *ctxt)
{
	__sysreg_restore_common_state(ctxt);
	__sysreg_restore_el2_return_state(ctxt);
}
NOKPROBE_SYMBOL(sysreg_restore_guest_state_vhe);

void __hyp_text __sysreg32_save_state(struct kvm_vcpu *vcpu)
{
	u64 *spsr;

	if (!vcpu_el1_is_32bit(vcpu))
		return;

	spsr = vcpu->arch.ctxt.spsr;

	spsr[KVM_SPSR_ABT] = read_sysreg(spsr_abt);
	spsr[KVM_SPSR_UND] = read_sysreg(spsr_und);
	spsr[KVM_SPSR_IRQ] = read_sysreg(spsr_irq);
	spsr[KVM_SPSR_FIQ] = read_sysreg(spsr_fiq);

	__vcpu_sys_reg(vcpu, DACR32_EL2) = read_sysreg(dacr32_el2);
	__vcpu_sys_reg(vcpu, IFSR32_EL2) = read_sysreg(ifsr32_el2);

	if (has_vhe() || vcpu->arch.flags & KVM_ARM64_DEBUG_DIRTY)
		__vcpu_sys_reg(vcpu, DBGVCR32_EL2) = read_sysreg(dbgvcr32_el2);
}

void __hyp_text __sysreg32_restore_state(struct kvm_vcpu *vcpu)
{
	u64 *spsr;

	if (!vcpu_el1_is_32bit(vcpu))
		return;

	spsr = vcpu->arch.ctxt.spsr;

	write_sysreg(spsr[KVM_SPSR_ABT], spsr_abt);
	write_sysreg(spsr[KVM_SPSR_UND], spsr_und);
	write_sysreg(spsr[KVM_SPSR_IRQ], spsr_irq);
	write_sysreg(spsr[KVM_SPSR_FIQ], spsr_fiq);

	write_sysreg(__vcpu_sys_reg(vcpu, DACR32_EL2), dacr32_el2);
	write_sysreg(__vcpu_sys_reg(vcpu, IFSR32_EL2), ifsr32_el2);

	if (has_vhe() || vcpu->arch.flags & KVM_ARM64_DEBUG_DIRTY)
		write_sysreg(__vcpu_sys_reg(vcpu, DBGVCR32_EL2), dbgvcr32_el2);
}

/**
 * kvm_vcpu_load_sysregs - Load guest system registers to the physical CPU
 *
 * @vcpu: The VCPU pointer
 *
 * Load system registers that do not affect the host's execution, for
 * example EL1 system registers on a VHE system where the host kernel
 * runs at EL2.  This function is called from KVM's vcpu_load() function
 * and loading system register state early avoids having to load them on
 * every entry to the VM.
 */
void kvm_vcpu_load_sysregs(struct kvm_vcpu *vcpu)
{
	struct kvm_cpu_context *guest_ctxt = &vcpu->arch.ctxt;
	struct kvm_cpu_context *host_ctxt;

	if (!has_vhe())
		return;

	host_ctxt = &__hyp_this_cpu_ptr(kvm_host_data)->host_ctxt;
	__sysreg_save_user_state(host_ctxt);

	/*
	 * Load guest EL1 and user state
	 *
	 * We must restore the 32-bit state before the sysregs, thanks
	 * to erratum #852523 (Cortex-A57) or #853709 (Cortex-A72).
	 */
	__sysreg32_restore_state(vcpu);
	__sysreg_restore_user_state(guest_ctxt);
	__sysreg_restore_el1_state(guest_ctxt);

	vcpu->arch.sysregs_loaded_on_cpu = true;

	activate_traps_vhe_load(vcpu);
}

/**
 * kvm_vcpu_put_sysregs - Restore host system registers to the physical CPU
 *
 * @vcpu: The VCPU pointer
 *
 * Save guest system registers that do not affect the host's execution, for
 * example EL1 system registers on a VHE system where the host kernel
 * runs at EL2.  This function is called from KVM's vcpu_put() function
 * and deferring saving system register state until we're no longer running the
 * VCPU avoids having to save them on every exit from the VM.
 */
void kvm_vcpu_put_sysregs(struct kvm_vcpu *vcpu)
{
	struct kvm_cpu_context *guest_ctxt = &vcpu->arch.ctxt;
	struct kvm_cpu_context *host_ctxt;

	if (!has_vhe())
		return;

	host_ctxt = &__hyp_this_cpu_ptr(kvm_host_data)->host_ctxt;
	deactivate_traps_vhe_put();

	__sysreg_save_el1_state(guest_ctxt);
	__sysreg_save_user_state(guest_ctxt);
	__sysreg32_save_state(vcpu);

	/* Restore host user state */
	__sysreg_restore_user_state(host_ctxt);

	vcpu->arch.sysregs_loaded_on_cpu = false;
}

void __hyp_text __kvm_enable_ssbs(void)
{
	u64 tmp;

	asm volatile(
	"mrs	%0, sctlr_el2\n"
	"orr	%0, %0, %1\n"
	"msr	sctlr_el2, %0"
	: "=&r" (tmp) : "L" (SCTLR_ELx_DSSBS));
}
