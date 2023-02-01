// SPDX-License-Identifier: GPL-2.0-only

#include <linux/cpu.h>
#include <linux/kvm.h>
#include <linux/kvm_host.h>
#include <linux/interrupt.h>
#include <linux/io.h>
#include <linux/uaccess.h>

#include <kvm/arm_vgic.h>

#include <asm/kvm_arm.h>
#include <asm/kvm_emulate.h>
#include <asm/kvm_nested.h>

#include "vgic.h"

#define ICH_LRN(n)	(ICH_LR0_EL2 + (n))
#define ICH_AP0RN(n)	(ICH_AP0R0_EL2 + (n))
#define ICH_AP1RN(n)	(ICH_AP1R0_EL2 + (n))

#define CREATE_TRACE_POINTS
#include "vgic-nested-trace.h"

/*
 * The shadow registers loaded to the hardware when running a L2 guest
 * with the virtual IMO/FMO bits set.
 */
static DEFINE_PER_CPU(struct vgic_v3_cpu_if, shadow_cpuif);

/*
 * Nesting GICv3 support
 *
 * On a non-nesting VM (only running at EL0/EL1), the host hypervisor
 * completely controls the interrupts injected via the list registers.
 * Consequently, most of the state that is modified by the guest (by ACK-ing
 * and EOI-ing interrupts) is synced by KVM on each entry/exit, so that we
 * keep a semi-consistent view of the interrupts.
 *
 * This still applies for a NV guest, but only while "InHost" (either
 * running at EL2, or at EL0 with HCR_EL2.{E2H.TGE}=={1,1}.
 *
 * When running a L2 guest ("not InHost"), things are radically different,
 * as the L1 guest is in charge of provisioning the interrupts via its own
 * view of the ICH_LR*_EL2 registers, which conveniently live in the VNCR
 * page.  This means that the flow described above does work (there is no
 * state to rebuild in the L0 hypervisor), and that most things happed on L2
 * load/put:
 *
 * - on L2 load: move the in-memory L1 vGIC configuration into a shadow,
 *   per-CPU data structure that is used to populate the actual LRs. This is
 *   an extra copy that we could avoid, but life is short. In the process,
 *   we remap any interrupt that has the HW bit set to the mapped interrupt
 *   on the host, should the host consider it a HW one. This allows the HW
 *   deactivation to take its course, such as for the timer.
 *
 * - on L2 put: perform the inverse transformation, so that the result of L2
 *   running becomes visible to L1 in the VNCR-accessible registers.
 *
 * - there is nothing to do on L2 entry, as everything will have happenned
 *   on load. However, this is the point where we detect that an interrupt
 *   targeting L1 and prepare the grand switcheroo.
 *
 * - on L2 exit: emulate the HW bit, and deactivate corresponding the L1
 *   interrupt. The L0 active state will be cleared by the HW if the L1
 *   interrupt was itself backed by a HW interrupt.
 *
 * Maintenance Interrupt (MI) management:
 *
 * Since the L2 guest runs the vgic in its full glory, MIs get delivered and
 * used as a handover point between L2 and L1.
 *
 * - on delivery of a MI to L0 while L2 is running: make the L1 MI pending,
 *   and let it rip. This will initiate a vcpu_put() on L2, and allow L1 to
 *   run and process the MI.
 *
 * - L1 MI is a fully virtual interrupt, not linked to the host's MI. Its
 *   state must be computed at each entry/exit of the guest, much like we do
 *   it for the PMU interrupt.
 *
 * - because most of the ICH_*_EL2 registers live in the VNCR page, the
 *   quality of emulation is poor: L1 can setup the vgic so that an MI would
 *   immediately fire, and not observe anything until the next exit. Trying
 *   to read ICH_MISR_EL2 would do the trick, for example.
 *
 * System register emulation:
 *
 * We get two classes of registers:
 *
 * - those backed by memory (LRs, APRs, HCR, VMCR): L1 can freely access
 *   them, and L0 doesn't see a thing.
 *
 * - those that always trap (ELRSR, EISR, MISR): these are status registers
 *   that are built on the fly based on the in-memory state.
 *
 * Only L1 can access the ICH_*_EL2 registers. A non-NV L2 obviously cannot,
 * and a NV L2 would either access the VNCR page provided by L1 (memory
 * based registers), or see the access redirected to L1 (registers that
 * trap) thanks to NV being set by L1.
 */

bool vgic_state_is_nested(struct kvm_vcpu *vcpu)
{
	u64 xmo;

	if (vcpu_has_nv(vcpu) && !is_hyp_ctxt(vcpu)) {
		xmo = __vcpu_sys_reg(vcpu, HCR_EL2) & (HCR_IMO | HCR_FMO);
		WARN_ONCE(xmo && xmo != (HCR_IMO | HCR_FMO),
			  "Separate virtual IRQ/FIQ settings not supported\n");

		return !!xmo;
	}

	return false;
}

static inline struct vgic_v3_cpu_if *vcpu_shadow_if(struct kvm_vcpu *vcpu)
{
	return this_cpu_ptr(&shadow_cpuif);
}

static inline bool lr_triggers_eoi(u64 lr)
{
	return !(lr & (ICH_LR_STATE | ICH_LR_HW)) && (lr & ICH_LR_EOI);
}

u16 vgic_v3_get_eisr(struct kvm_vcpu *vcpu)
{
	u16 reg = 0;

	for (int i = 0; i < kvm_vgic_global_state.nr_lr; i++) {
		if (lr_triggers_eoi(__vcpu_sys_reg(vcpu, ICH_LRN(i))))
			reg |= BIT(i);
	}

	return reg;
}

u16 vgic_v3_get_elrsr(struct kvm_vcpu *vcpu)
{
	u16 reg = 0;

	for (int i = 0; i < kvm_vgic_global_state.nr_lr; i++) {
		if (!(__vcpu_sys_reg(vcpu, ICH_LRN(i)) & ICH_LR_STATE))
			reg |= BIT(i);
	}

	return reg;
}

u64 vgic_v3_get_misr(struct kvm_vcpu *vcpu)
{
	u64 reg = 0, hcr, vmcr;

	hcr = __vcpu_sys_reg(vcpu, ICH_HCR_EL2);
	vmcr = __vcpu_sys_reg(vcpu, ICH_VMCR_EL2);

	if (vgic_v3_get_eisr(vcpu))
		reg |= ICH_MISR_EL2_EOI;

	if (__vcpu_sys_reg(vcpu, ICH_HCR_EL2) & ICH_HCR_EL2_UIE) {
		int used_lrs = kvm_vgic_global_state.nr_lr;

		used_lrs -= hweight16(vgic_v3_get_elrsr(vcpu));
		reg |= (used_lrs <= 1) ? ICH_MISR_EL2_U : 0;
	}

	if ((hcr & ICH_HCR_EL2_LRENPIE) && FIELD_GET(ICH_HCR_EL2_EOIcount_MASK, hcr))
		reg |= ICH_MISR_EL2_LRENP;

	if (hcr & ICH_HCR_EL2_NPIE) {
		u64 val = 0;

		for (int i = 0; i < kvm_vgic_global_state.nr_lr; i++)
			val |= __vcpu_sys_reg(vcpu, ICH_LRN(i));

		reg |= (val & ICH_LR_PENDING_BIT) ? 0 : ICH_MISR_EL2_NP;
	}

	if ((hcr & ICH_HCR_EL2_VGrp0EIE) && (vmcr & ICH_VMCR_ENG0_MASK))
		reg |= ICH_MISR_EL2_VGrp0E;

	if ((hcr & ICH_HCR_EL2_VGrp0DIE) && !(vmcr & ICH_VMCR_ENG0_MASK))
		reg |= ICH_MISR_EL2_VGrp0D;

	if ((hcr & ICH_HCR_EL2_VGrp1EIE) && (vmcr & ICH_VMCR_ENG1_MASK))
		reg |= ICH_MISR_EL2_VGrp1E;

	if ((hcr & ICH_HCR_EL2_VGrp1DIE) && !(vmcr & ICH_VMCR_ENG1_MASK))
		reg |= ICH_MISR_EL2_VGrp1D;

	return reg;
}

/*
 * For LRs which have HW bit set such as timer interrupts, we modify them to
 * have the host hardware interrupt number instead of the virtual one programmed
 * by the guest hypervisor.
 */
static void vgic_v3_create_shadow_lr(struct kvm_vcpu *vcpu,
				     struct vgic_v3_cpu_if *s_cpu_if)
{
	struct vgic_irq *irq;

	for (int i = 0; i < kvm_vgic_global_state.nr_lr; i++) {
		u64 lr = __vcpu_sys_reg(vcpu, ICH_LRN(i));

		if (!(lr & ICH_LR_STATE))
			lr = 0;

		if (!(lr & ICH_LR_HW))
			goto next;

		/* We have the HW bit set, check for validity of pINTID */
		irq = vgic_get_irq(vcpu->kvm, vcpu,
				   FIELD_GET(ICH_LR_PHYS_ID_MASK, lr));
		if (!irq || !irq->hw || irq->intid > VGIC_MAX_SPI ) {
			/* There was no real mapping, so nuke the HW bit */
			lr &= ~ICH_LR_HW;
			if (irq)
				vgic_put_irq(vcpu->kvm, irq);
			goto next;
		}

		/* It is illegal to have the EOI bit set with HW */
		lr &= ~ICH_LR_EOI;

		/* Translate the virtual mapping to the real one */
		lr &= ~ICH_LR_PHYS_ID_MASK;
		lr |= FIELD_PREP(ICH_LR_PHYS_ID_MASK, (u64)irq->hwintid);

		vgic_put_irq(vcpu->kvm, irq);

next:
		s_cpu_if->vgic_lr[i] = lr;
	}

	trace_vgic_create_shadow_lrs(vcpu, kvm_vgic_global_state.nr_lr,
				     s_cpu_if->vgic_lr,
				     __ctxt_sys_reg(&vcpu->arch.ctxt, ICH_LR0_EL2));

	s_cpu_if->used_lrs = kvm_vgic_global_state.nr_lr;
}

void vgic_v3_sync_nested(struct kvm_vcpu *vcpu)
{
	struct vgic_v3_cpu_if *s_cpu_if = vcpu_shadow_if(vcpu);

	for (int i = 0; i < s_cpu_if->used_lrs; i++) {
		u64 lr = __vcpu_sys_reg(vcpu, ICH_LRN(i));
		struct vgic_irq *irq;

		if (!(lr & ICH_LR_HW) || !(lr & ICH_LR_STATE))
			continue;

		/*
		 * If we had a HW lr programmed by the guest hypervisor, we
		 * need to emulate the HW effect between the guest hypervisor
		 * and the nested guest.
		 */
		irq = vgic_get_irq(vcpu->kvm, vcpu,
				   FIELD_GET(ICH_LR_PHYS_ID_MASK, lr));
		if (WARN_ON(!irq)) /* Shouldn't happen as we check on load */
			continue;

		lr = __gic_v3_get_lr(i);
		if (!(lr & ICH_LR_STATE)) {
			trace_vgic_nested_hw_emulate(i, lr, irq->intid);
			irq->active = false;
		}

		vgic_put_irq(vcpu->kvm, irq);
	}
}

static void vgic_v3_create_shadow_state(struct kvm_vcpu *vcpu,
					struct vgic_v3_cpu_if *s_cpu_if)
{
	struct vgic_v3_cpu_if *host_if = &vcpu->arch.vgic_cpu.vgic_v3;
	u64 val = 0;
	int i;

	/*
	 * If we're on a system with a broken vgic that requires
	 * trapping, propagate the trapping requirements.
	 *
	 * Ah, the smell of rotten fruits...
	 */
	if (static_branch_unlikely(&vgic_v3_cpuif_trap))
		val = host_if->vgic_hcr & (ICH_HCR_EL2_TALL0 | ICH_HCR_EL2_TALL1 |
					   ICH_HCR_EL2_TC | ICH_HCR_EL2_TDIR);
	s_cpu_if->vgic_hcr = __vcpu_sys_reg(vcpu, ICH_HCR_EL2) | val;
	s_cpu_if->vgic_vmcr = __vcpu_sys_reg(vcpu, ICH_VMCR_EL2);
	s_cpu_if->vgic_sre = host_if->vgic_sre;

	for (i = 0; i < 4; i++) {
		s_cpu_if->vgic_ap0r[i] = __vcpu_sys_reg(vcpu, ICH_AP0RN(i));
		s_cpu_if->vgic_ap1r[i] = __vcpu_sys_reg(vcpu, ICH_AP1RN(i));
	}

	vgic_v3_create_shadow_lr(vcpu, s_cpu_if);
}

void vgic_v3_load_nested(struct kvm_vcpu *vcpu)
{
	struct vgic_v3_cpu_if *cpu_if;

	BUG_ON(!vgic_state_is_nested(vcpu));

	cpu_if = vcpu->arch.vgic_cpu.current_cpu_if = vcpu_shadow_if(vcpu);

	vgic_v3_create_shadow_state(vcpu, cpu_if);

	__vgic_v3_restore_vmcr_aprs(cpu_if);
	__vgic_v3_activate_traps(cpu_if);

	__vgic_v3_restore_state(cpu_if);
}

void vgic_v3_put_nested(struct kvm_vcpu *vcpu)
{
	struct vgic_v3_cpu_if *s_cpu_if = vcpu_shadow_if(vcpu);
	u64 val;
	int i;

	__vgic_v3_save_vmcr_aprs(s_cpu_if);
	__vgic_v3_deactivate_traps(s_cpu_if);
	__vgic_v3_save_state(s_cpu_if);

	trace_vgic_put_nested(vcpu, kvm_vgic_global_state.nr_lr, s_cpu_if->vgic_lr);

	/*
	 * Translate the shadow state HW fields back to the virtual ones
	 * before copying the shadow struct back to the nested one.
	 */
	val = __vcpu_sys_reg(vcpu, ICH_HCR_EL2);
	val &= ~ICH_HCR_EL2_EOIcount_MASK;
	val |= (s_cpu_if->vgic_hcr & ICH_HCR_EL2_EOIcount_MASK);
	__vcpu_sys_reg(vcpu, ICH_HCR_EL2) = val;
	__vcpu_sys_reg(vcpu, ICH_VMCR_EL2) = s_cpu_if->vgic_vmcr;

	for (i = 0; i < 4; i++) {
		__vcpu_sys_reg(vcpu, ICH_AP0RN(i)) = s_cpu_if->vgic_ap0r[i];
		__vcpu_sys_reg(vcpu, ICH_AP1RN(i)) = s_cpu_if->vgic_ap1r[i];
	}

	for (i = 0; i < s_cpu_if->used_lrs; i++) {
		val = __vcpu_sys_reg(vcpu, ICH_LRN(i));

		val &= ~ICH_LR_STATE;
		val |= s_cpu_if->vgic_lr[i] & ICH_LR_STATE;

		__vcpu_sys_reg(vcpu, ICH_LRN(i)) = val;
		s_cpu_if->vgic_lr[i] = 0;
	}

	/* Default back to the non-nested state for sanity */
	vcpu->arch.vgic_cpu.current_cpu_if = &vcpu->arch.vgic_cpu.vgic_v3;
}

/*
 * If we exit a L2 VM with a pending maintenance interrupt from the GIC,
 * then we need to forward this to L1 so that it can re-sync the appropriate
 * LRs and sample level triggered interrupts again.
 */
void vgic_v3_handle_nested_maint_irq(struct kvm_vcpu *vcpu)
{
	bool state;

	state  = __vcpu_sys_reg(vcpu, ICH_HCR_EL2) & ICH_HCR_EL2_En;
	state &= read_sysreg_s(SYS_ICH_MISR_EL2);

	/* This will force a switch back to L1 if the level is high */
	kvm_vgic_inject_irq(vcpu->kvm, vcpu,
			    vcpu->kvm->arch.vgic.maint_irq, state, vcpu);

	sysreg_clear_set_s(SYS_ICH_HCR_EL2, ICH_HCR_EL2_En, 0);
}

void vgic_v3_nested_update_mi(struct kvm_vcpu *vcpu)
{
	bool level;

	level  = __vcpu_sys_reg(vcpu, ICH_HCR_EL2) & ICH_HCR_EL2_En;
	level &= vgic_v3_get_misr(vcpu);
	kvm_vgic_inject_irq(vcpu->kvm, vcpu,
			    vcpu->kvm->arch.vgic.maint_irq, level, vcpu);
}
