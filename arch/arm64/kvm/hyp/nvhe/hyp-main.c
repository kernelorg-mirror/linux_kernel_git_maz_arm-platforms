// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2020 - Google Inc
 * Author: Andrew Scull <ascull@google.com>
 */

#include <hyp/switch.h>

#include <asm/kvm_asm.h>
#include <asm/kvm_emulate.h>
#include <asm/kvm_host.h>
#include <asm/kvm_hyp.h>
#include <asm/kvm_mmu.h>

#define cpu_reg(ctxt, r)	(ctxt)->regs.regs[r]
#define DECLARE_REG(type, name, ctxt, reg)	\
				type name = (type)cpu_reg(ctxt, (reg))

static void handle___kvm_vcpu_run(struct kvm_cpu_context *host_ctxt)
{
	DECLARE_REG(struct kvm_vcpu *, vcpu, host_ctxt, 1);

	cpu_reg(host_ctxt, 1) =  __kvm_vcpu_run(kern_hyp_va(vcpu));
}

static void handle___kvm_flush_vm_context(struct kvm_cpu_context *host_ctxt)
{
	__kvm_flush_vm_context();
}

static void handle___kvm_tlb_flush_vmid_ipa(struct kvm_cpu_context *host_ctxt)
{
	DECLARE_REG(struct kvm_s2_mmu *, mmu, host_ctxt, 1);
	DECLARE_REG(phys_addr_t, ipa, host_ctxt, 2);
	DECLARE_REG(int, level, host_ctxt, 3);

	__kvm_tlb_flush_vmid_ipa(kern_hyp_va(mmu), ipa, level);
}

static void handle___kvm_tlb_flush_vmid(struct kvm_cpu_context *host_ctxt)
{
	DECLARE_REG(struct kvm_s2_mmu *, mmu, host_ctxt, 1);

	__kvm_tlb_flush_vmid(kern_hyp_va(mmu));
}

static void handle___kvm_tlb_flush_local_vmid(struct kvm_cpu_context *host_ctxt)
{
	DECLARE_REG(struct kvm_s2_mmu *, mmu, host_ctxt, 1);

	__kvm_tlb_flush_local_vmid(kern_hyp_va(mmu));
}

static void handle___kvm_timer_set_cntvoff(struct kvm_cpu_context *host_ctxt)
{
	__kvm_timer_set_cntvoff(cpu_reg(host_ctxt, 1));
}

static void handle___kvm_enable_ssbs(struct kvm_cpu_context *host_ctxt)
{
	u64 tmp;

	tmp = read_sysreg_el2(SYS_SCTLR);
	tmp |= SCTLR_ELx_DSSBS;
	write_sysreg_el2(tmp, SYS_SCTLR);
}

static void handle___vgic_v3_get_ich_vtr_el2(struct kvm_cpu_context *host_ctxt)
{
	cpu_reg(host_ctxt, 1) = __vgic_v3_get_ich_vtr_el2();
}

static void handle___vgic_v3_read_vmcr(struct kvm_cpu_context *host_ctxt)
{
	cpu_reg(host_ctxt, 1) = __vgic_v3_read_vmcr();
}

static void handle___vgic_v3_write_vmcr(struct kvm_cpu_context *host_ctxt)
{
	__vgic_v3_write_vmcr(cpu_reg(host_ctxt, 1));
}

static void handle___vgic_v3_init_lrs(struct kvm_cpu_context *host_ctxt)
{
	__vgic_v3_init_lrs();
}

static void handle___kvm_get_mdcr_el2(struct kvm_cpu_context *host_ctxt)
{
	cpu_reg(host_ctxt, 1) = __kvm_get_mdcr_el2();
}

static void handle___vgic_v3_save_aprs(struct kvm_cpu_context *host_ctxt)
{
	DECLARE_REG(struct vgic_v3_cpu_if *, cpu_if, host_ctxt, 1);

	__vgic_v3_save_aprs(kern_hyp_va(cpu_if));
}

static void handle___vgic_v3_restore_aprs(struct kvm_cpu_context *host_ctxt)
{
	DECLARE_REG(struct vgic_v3_cpu_if *, cpu_if, host_ctxt, 1);

	__vgic_v3_restore_aprs(kern_hyp_va(cpu_if));
}

extern char __kvm_sandbox_hack[];

static unsigned long sandbox_entry_ipa = (unsigned long)__kvm_sandbox_hack;

static void handle___kvm_sandbox_enter(struct kvm_cpu_context *host_ctxt)
{
	struct kvm_cpu_context *sandbox_ctxt;
	struct kvm_host_data *data;
	u64 val;

	data = container_of(host_ctxt, typeof(*data), host_ctxt);
	sandbox_ctxt = &data->sandbox_ctxt;

	host_ctxt->regs.pc = read_sysreg_el2(SYS_ELR);
	host_ctxt->regs.pstate = read_sysreg_el2(SYS_SPSR);
	host_ctxt->regs.sp = read_sysreg(sp_el0);

	/* Trap General Exceptions, Default Cacheable */
	val = read_sysreg(hcr_el2);
	val |= HCR_TGE | HCR_DC;
	write_sysreg(val, hcr_el2);

	/*
	 * Prepare for an EL0 entry, with all possible exceptions masked.
	 */
	val = (PSR_MODE_EL0t | PSR_F_BIT | PSR_I_BIT | PSR_A_BIT | PSR_D_BIT);
	write_sysreg_el2(val, SYS_SPSR);
	write_sysreg_el2(kimg_pa(sandbox_entry_ipa), SYS_ELR);
	write_sysreg(sandbox_ctxt->regs.sp, sp_el0);

	/*
	 * Nuke Stage-1 TLBs for this CPU only, as we are giving it a
	 * new S1 translation (effectively an idmap).
	 */
	__tlbi(vmalle1);
	dsb(nsh);

	/* Tell the sandbox something interesting */
	cpu_reg(sandbox_ctxt, 0) = cpu_reg(host_ctxt, 1);
}

static void handle_sandbox_exit(struct kvm_cpu_context *sandbox_ctxt)
{
	struct kvm_cpu_context *host_ctxt;
	struct kvm_host_data *data;
	u64 val;

	sandbox_ctxt->regs.sp = read_sysreg(sp_el0);

	data = container_of(sandbox_ctxt, typeof(*data), sandbox_ctxt);
	host_ctxt = &data->host_ctxt;

	write_sysreg_el2(host_ctxt->regs.pc, SYS_ELR);
	write_sysreg_el2(host_ctxt->regs.pstate, SYS_SPSR);
	write_sysreg(host_ctxt->regs.sp, sp_el0);

	val = read_sysreg(hcr_el2);
	val &= ~(HCR_TGE | HCR_DC);
	write_sysreg(val, hcr_el2);

	/*
	 * Nuke Stage-1 TLBs for this CPU only, as we restore its
	 * original MM configuration (TGE/DC clear);
	 */
	__tlbi(vmalle1);
	dsb(nsh);

	/*
	 * Whatever the sandbox said, we already have SMCCC_RET_SUCCESS
	 * pre-populated in x0 from the HVC path...
	 */
	cpu_reg(host_ctxt, 1) = cpu_reg(sandbox_ctxt, 0);
}

#define HANDLE_FUNC(x)	[__KVM_HOST_SMCCC_FUNC_##x] = handle_##x

typedef void (*hcall_t)(struct kvm_cpu_context *);

static const hcall_t host_hcall[] = {
	HANDLE_FUNC(__kvm_vcpu_run),
	HANDLE_FUNC(__kvm_flush_vm_context),
	HANDLE_FUNC(__kvm_tlb_flush_vmid_ipa),
	HANDLE_FUNC(__kvm_tlb_flush_vmid),
	HANDLE_FUNC(__kvm_tlb_flush_local_vmid),
	HANDLE_FUNC(__kvm_timer_set_cntvoff),
	HANDLE_FUNC(__kvm_enable_ssbs),
	HANDLE_FUNC(__vgic_v3_get_ich_vtr_el2),
	HANDLE_FUNC(__vgic_v3_read_vmcr),
	HANDLE_FUNC(__vgic_v3_write_vmcr),
	HANDLE_FUNC(__vgic_v3_init_lrs),
	HANDLE_FUNC(__kvm_get_mdcr_el2),
	HANDLE_FUNC(__vgic_v3_save_aprs),
	HANDLE_FUNC(__vgic_v3_restore_aprs),
	HANDLE_FUNC(__kvm_sandbox_enter),
};

static void handle_host_hcall(struct kvm_cpu_context *host_ctxt)
{
	DECLARE_REG(unsigned long, id, host_ctxt, 0);
	unsigned long ret = SMCCC_RET_NOT_SUPPORTED;
	hcall_t hcall;

	id -= KVM_HOST_SMCCC_ID(0);

	if (unlikely(id >= ARRAY_SIZE(host_hcall)))
		goto inval;

	hcall = host_hcall[id];
	if (unlikely(!hcall))
		goto inval;

	hcall = kimg_hyp_va(hcall);

	hcall(host_ctxt);
	ret = SMCCC_RET_SUCCESS;

inval:
	cpu_reg(host_ctxt, 0) = ret;
}

void handle_trap(struct kvm_cpu_context *ctxt)
{
	u64 esr = read_sysreg_el2(SYS_ESR);

	switch (ESR_ELx_EC(esr)) {
	case ESR_ELx_EC_HVC64:
		handle_host_hcall(ctxt);
		break;
	case ESR_ELx_EC_SVC64:
		handle_sandbox_exit(ctxt);
		break;
	default:
		hyp_panic();
	}
}
