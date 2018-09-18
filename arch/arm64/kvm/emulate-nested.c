/*
 * Copyright (C) 2016 - Linaro and Columbia University
 * Author: Jintack Lim <jintack.lim@linaro.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <linux/kvm.h>
#include <linux/kvm_host.h>

#include <asm/kvm_coproc.h>
#include <asm/kvm_emulate.h>

#include "trace.h"

/* This is borrowed from get_except_vector in inject_fault.c */
static u64 get_el2_except_vector(struct kvm_vcpu *vcpu,
		enum exception_type type)
{
	u64 exc_offset;

	switch (*vcpu_cpsr(vcpu) & (PSR_MODE_MASK | PSR_MODE32_BIT)) {
	case PSR_MODE_EL2t:
		exc_offset = CURRENT_EL_SP_EL0_VECTOR;
		break;
	case PSR_MODE_EL2h:
		exc_offset = CURRENT_EL_SP_ELx_VECTOR;
		break;
	case PSR_MODE_EL1t:
	case PSR_MODE_EL1h:
	case PSR_MODE_EL0t:
		exc_offset = LOWER_EL_AArch64_VECTOR;
		break;
	default:
		kvm_err("Unexpected previous exception level: aarch32\n");
		exc_offset = LOWER_EL_AArch32_VECTOR;
	}

	return __vcpu_sys_reg(vcpu, VBAR_EL2) + exc_offset + type;
}

void kvm_emulate_nested_eret(struct kvm_vcpu *vcpu)
{
	unsigned long spsr = vcpu_read_spsr_el2(vcpu);
	unsigned long elr = vcpu_read_sys_reg(vcpu, ELR_EL2);

	trace_kvm_nested_eret(vcpu, elr, spsr);

	/*
	 * Forward this trap to the virtual EL2 if the virtual HCR_EL2.NV
	 * bit is set.
	 */
	if (forward_nv_traps(vcpu)) {
		kvm_inject_nested_sync(vcpu, kvm_vcpu_get_hsr(vcpu));
		return;
	}

	preempt_disable();
	kvm_timer_vcpu_put(vcpu);

	/*
	 * Note that the current exception level is always the virtual EL2,
	 * since we set HCR_EL2.NV bit only when entering the virtual EL2.
	 */
	*vcpu_pc(vcpu) = elr;
	*vcpu_cpsr(vcpu) = spsr;

	kvm_timer_vcpu_load(vcpu);
	preempt_enable();
}

/*
 * Emulate taking an exception to EL2.
 * See ARM ARM J8.1.2 AArch64.TakeException()
 */
static int kvm_inject_nested(struct kvm_vcpu *vcpu, u64 esr_el2,
			     enum exception_type type)
{
	int ret = 1;

	if (!nested_virt_in_use(vcpu)) {
		kvm_err("Unexpected call to %s for the non-nesting configuration\n",
				__func__);
		return -EINVAL;
	}

	preempt_disable();
	kvm_timer_vcpu_put(vcpu);

	vcpu_write_spsr_el2(vcpu, *vcpu_cpsr(vcpu));
	__vcpu_sys_reg(vcpu, ELR_EL2) = *vcpu_pc(vcpu);
	__vcpu_sys_reg(vcpu, ESR_EL2) = esr_el2;

	*vcpu_pc(vcpu) = get_el2_except_vector(vcpu, type);
	/* On an exception, PSTATE.SP becomes 1 */
	*vcpu_cpsr(vcpu) = PSR_MODE_EL2h;
	*vcpu_cpsr(vcpu) |= PSR_A_BIT | PSR_F_BIT | PSR_I_BIT | PSR_D_BIT;

	trace_kvm_inject_nested_exception(vcpu, esr_el2, *vcpu_pc(vcpu));

	kvm_timer_vcpu_load(vcpu);
	preempt_enable();

	return ret;
}

int kvm_inject_nested_sync(struct kvm_vcpu *vcpu, u64 esr_el2)
{
	return kvm_inject_nested(vcpu, esr_el2, except_type_sync);
}

int kvm_inject_nested_irq(struct kvm_vcpu *vcpu)
{
	/*
	 * Do not inject an irq if the current exception level is EL2 and
	 * virtual HCR_EL2.IMO is set and IRQ mask is set.
	 * See Table D1-16 Physical interrupt masking when EL3 is not
	 * implemented and EL2 is implemented.
	 */
	if ((__vcpu_sys_reg(vcpu, HCR_EL2) & HCR_IMO) && vcpu_mode_el2(vcpu)
	    && (*vcpu_cpsr(vcpu) & PSR_I_BIT))
		return 1;

	/* esr_el2 value doesn't matter for exits due to irqs. */
	return kvm_inject_nested(vcpu, 0, except_type_irq);
}
