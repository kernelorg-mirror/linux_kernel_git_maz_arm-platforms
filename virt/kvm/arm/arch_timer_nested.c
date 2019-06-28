// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2019 ARM Ltd.
 * Author: Marc Zyngier <maz@kernel.org>
 *
 * Override timer accessors to be nested-capable on ARMv8.4.
 */

#include <linux/kernel.h>
#include <linux/kvm_host.h>

u32 timer_get_ctl(struct arch_timer_context *ctxt)
{
	struct kvm_vcpu *vcpu = ctxt->vcpu;

	switch(arch_timer_ctx_index(ctxt)) {
	case TIMER_VTIMER:
		return __vcpu_sys_reg(vcpu, CNTV_CTL_EL0);
	case TIMER_PTIMER:
		return __vcpu_sys_reg(vcpu, CNTP_CTL_EL0);
	default:
		return ctxt->cnt_ctl;
	}
}

u64 timer_get_cval(struct arch_timer_context *ctxt)
{
	struct kvm_vcpu *vcpu = ctxt->vcpu;

	switch(arch_timer_ctx_index(ctxt)) {
	case TIMER_VTIMER:
		return __vcpu_sys_reg(vcpu, CNTV_CVAL_EL0);
	case TIMER_PTIMER:
		return __vcpu_sys_reg(vcpu, CNTP_CVAL_EL0);
	default:
		return ctxt->cnt_cval;
	}
}

u64 timer_get_offset(struct arch_timer_context *ctxt)
{
	struct kvm_vcpu *vcpu = ctxt->vcpu;

	switch(arch_timer_ctx_index(ctxt)) {
	case TIMER_VTIMER:
		return __vcpu_sys_reg(vcpu, CNTVOFF_EL2);
	default:
		return 0;
	}
}

void timer_set_ctl(struct arch_timer_context *ctxt, u32 ctl)
{
	struct kvm_vcpu *vcpu = ctxt->vcpu;

	switch(arch_timer_ctx_index(ctxt)) {
	case TIMER_VTIMER:
		__vcpu_sys_reg(vcpu, CNTV_CTL_EL0) = ctl;
		break;
	case TIMER_PTIMER:
		__vcpu_sys_reg(vcpu, CNTP_CTL_EL0) = ctl;
		break;
	default:
		ctxt->cnt_ctl = ctl;
	}
}

void timer_set_cval(struct arch_timer_context *ctxt, u64 cval)
{
	struct kvm_vcpu *vcpu = ctxt->vcpu;

	switch(arch_timer_ctx_index(ctxt)) {
	case TIMER_VTIMER:
		__vcpu_sys_reg(vcpu, CNTV_CVAL_EL0) = cval;
		break;
	case TIMER_PTIMER:
		__vcpu_sys_reg(vcpu, CNTP_CVAL_EL0) = cval;
		break;
	default:
		ctxt->cnt_cval = cval;
	}
}

void timer_set_offset(struct arch_timer_context *ctxt, u64 offset)
{
	struct kvm_vcpu *vcpu = ctxt->vcpu;

	switch(arch_timer_ctx_index(ctxt)) {
	case TIMER_VTIMER:
		__vcpu_sys_reg(vcpu, CNTVOFF_EL2) = offset;
		break;
	default:
		WARN(offset, "timer %ld\n", arch_timer_ctx_index(ctxt));
	}
}
