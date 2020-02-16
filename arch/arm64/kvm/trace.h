/* SPDX-License-Identifier: GPL-2.0 */
#if !defined(_TRACE_ARM64_KVM_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_ARM64_KVM_H

#include <kvm/arm_arch_timer.h>
#include <linux/tracepoint.h>
#include "sys_regs.h"

#undef TRACE_SYSTEM
#define TRACE_SYSTEM kvm

TRACE_EVENT(kvm_wfx_arm64,
	TP_PROTO(unsigned long vcpu_pc, bool is_wfe),
	TP_ARGS(vcpu_pc, is_wfe),

	TP_STRUCT__entry(
		__field(unsigned long,	vcpu_pc)
		__field(bool,		is_wfe)
	),

	TP_fast_assign(
		__entry->vcpu_pc = vcpu_pc;
		__entry->is_wfe  = is_wfe;
	),

	TP_printk("guest executed wf%c at: 0x%08lx",
		  __entry->is_wfe ? 'e' : 'i', __entry->vcpu_pc)
);

TRACE_EVENT(kvm_hvc_arm64,
	TP_PROTO(unsigned long vcpu_pc, unsigned long r0, unsigned long imm),
	TP_ARGS(vcpu_pc, r0, imm),

	TP_STRUCT__entry(
		__field(unsigned long, vcpu_pc)
		__field(unsigned long, r0)
		__field(unsigned long, imm)
	),

	TP_fast_assign(
		__entry->vcpu_pc = vcpu_pc;
		__entry->r0 = r0;
		__entry->imm = imm;
	),

	TP_printk("HVC at 0x%08lx (r0: 0x%08lx, imm: 0x%lx)",
		  __entry->vcpu_pc, __entry->r0, __entry->imm)
);

TRACE_EVENT(kvm_arm_setup_debug,
	TP_PROTO(struct kvm_vcpu *vcpu, __u32 guest_debug),
	TP_ARGS(vcpu, guest_debug),

	TP_STRUCT__entry(
		__field(struct kvm_vcpu *, vcpu)
		__field(__u32, guest_debug)
	),

	TP_fast_assign(
		__entry->vcpu = vcpu;
		__entry->guest_debug = guest_debug;
	),

	TP_printk("vcpu: %p, flags: 0x%08x", __entry->vcpu, __entry->guest_debug)
);

TRACE_EVENT(kvm_arm_clear_debug,
	TP_PROTO(__u32 guest_debug),
	TP_ARGS(guest_debug),

	TP_STRUCT__entry(
		__field(__u32, guest_debug)
	),

	TP_fast_assign(
		__entry->guest_debug = guest_debug;
	),

	TP_printk("flags: 0x%08x", __entry->guest_debug)
);

TRACE_EVENT(kvm_arm_set_dreg32,
	TP_PROTO(const char *name, __u32 value),
	TP_ARGS(name, value),

	TP_STRUCT__entry(
		__field(const char *, name)
		__field(__u32, value)
	),

	TP_fast_assign(
		__entry->name = name;
		__entry->value = value;
	),

	TP_printk("%s: 0x%08x", __entry->name, __entry->value)
);

TRACE_DEFINE_SIZEOF(__u64);

TRACE_EVENT(kvm_arm_set_regset,
	TP_PROTO(const char *type, int len, __u64 *control, __u64 *value),
	TP_ARGS(type, len, control, value),
	TP_STRUCT__entry(
		__field(const char *, name)
		__field(int, len)
		__array(u64, ctrls, 16)
		__array(u64, values, 16)
	),
	TP_fast_assign(
		__entry->name = type;
		__entry->len = len;
		memcpy(__entry->ctrls, control, len << 3);
		memcpy(__entry->values, value, len << 3);
	),
	TP_printk("%d %s CTRL:%s VALUE:%s", __entry->len, __entry->name,
		__print_array(__entry->ctrls, __entry->len, sizeof(__u64)),
		__print_array(__entry->values, __entry->len, sizeof(__u64)))
);

TRACE_EVENT(trap_reg,
	TP_PROTO(const char *fn, int reg, bool is_write, u64 write_value),
	TP_ARGS(fn, reg, is_write, write_value),

	TP_STRUCT__entry(
		__field(const char *, fn)
		__field(int, reg)
		__field(bool, is_write)
		__field(u64, write_value)
	),

	TP_fast_assign(
		__entry->fn = fn;
		__entry->reg = reg;
		__entry->is_write = is_write;
		__entry->write_value = write_value;
	),

	TP_printk("%s %s reg %d (0x%08llx)", __entry->fn,  __entry->is_write?"write to":"read from", __entry->reg, __entry->write_value)
);

TRACE_EVENT(kvm_handle_sys_reg,
	TP_PROTO(unsigned long hsr),
	TP_ARGS(hsr),

	TP_STRUCT__entry(
		__field(unsigned long,	hsr)
	),

	TP_fast_assign(
		__entry->hsr = hsr;
	),

	TP_printk("HSR 0x%08lx", __entry->hsr)
);

TRACE_EVENT(kvm_sys_access,
	TP_PROTO(unsigned long vcpu_pc, struct sys_reg_params *params, const struct sys_reg_desc *reg),
	TP_ARGS(vcpu_pc, params, reg),

	TP_STRUCT__entry(
		__field(unsigned long,			vcpu_pc)
		__field(bool,				is_write)
		__field(const char *,			name)
		__field(u8,				Op0)
		__field(u8,				Op1)
		__field(u8,				CRn)
		__field(u8,				CRm)
		__field(u8,				Op2)
	),

	TP_fast_assign(
		__entry->vcpu_pc = vcpu_pc;
		__entry->is_write = params->is_write;
		__entry->name = reg->name;
		__entry->Op0 = reg->Op0;
		__entry->Op0 = reg->Op0;
		__entry->Op1 = reg->Op1;
		__entry->CRn = reg->CRn;
		__entry->CRm = reg->CRm;
		__entry->Op2 = reg->Op2;
	),

	TP_printk("PC: %lx %s (%d,%d,%d,%d,%d) %s",
		  __entry->vcpu_pc, __entry->name ?: "UNKN",
		  __entry->Op0, __entry->Op1, __entry->CRn,
		  __entry->CRm, __entry->Op2,
		  __entry->is_write ? "write" : "read")
);

TRACE_EVENT(kvm_set_guest_debug,
	TP_PROTO(struct kvm_vcpu *vcpu, __u32 guest_debug),
	TP_ARGS(vcpu, guest_debug),

	TP_STRUCT__entry(
		__field(struct kvm_vcpu *, vcpu)
		__field(__u32, guest_debug)
	),

	TP_fast_assign(
		__entry->vcpu = vcpu;
		__entry->guest_debug = guest_debug;
	),

	TP_printk("vcpu: %p, flags: 0x%08x", __entry->vcpu, __entry->guest_debug)
);

/*
 * Tracepoints for entry/exit to guest
 */
TRACE_EVENT(kvm_entry,
	TP_PROTO(unsigned long vcpu_pc),
	TP_ARGS(vcpu_pc),

	TP_STRUCT__entry(
		__field(	unsigned long,	vcpu_pc		)
	),

	TP_fast_assign(
		__entry->vcpu_pc		= vcpu_pc;
	),

	TP_printk("PC: 0x%08lx", __entry->vcpu_pc)
);

TRACE_EVENT(kvm_exit,
	TP_PROTO(int ret, unsigned int esr_ec, unsigned long vcpu_pc),
	TP_ARGS(ret, esr_ec, vcpu_pc),

	TP_STRUCT__entry(
		__field(	int,		ret		)
		__field(	unsigned int,	esr_ec		)
		__field(	unsigned long,	vcpu_pc		)
	),

	TP_fast_assign(
		__entry->ret			= ARM_EXCEPTION_CODE(ret);
		__entry->esr_ec = ARM_EXCEPTION_IS_TRAP(ret) ? esr_ec : 0;
		__entry->vcpu_pc		= vcpu_pc;
	),

	TP_printk("%s: HSR_EC: 0x%04x (%s), PC: 0x%08lx",
		  __print_symbolic(__entry->ret, kvm_arm_exception_type),
		  __entry->esr_ec,
		  __print_symbolic(__entry->esr_ec, kvm_arm_exception_class),
		  __entry->vcpu_pc)
);

TRACE_EVENT(kvm_guest_fault,
	TP_PROTO(unsigned long vcpu_pc, unsigned long hsr,
		 unsigned long hxfar,
		 unsigned long long ipa),
	TP_ARGS(vcpu_pc, hsr, hxfar, ipa),

	TP_STRUCT__entry(
		__field(	unsigned long,	vcpu_pc		)
		__field(	unsigned long,	hsr		)
		__field(	unsigned long,	hxfar		)
		__field(   unsigned long long,	ipa		)
	),

	TP_fast_assign(
		__entry->vcpu_pc		= vcpu_pc;
		__entry->hsr			= hsr;
		__entry->hxfar			= hxfar;
		__entry->ipa			= ipa;
	),

	TP_printk("ipa %#llx, hsr %#08lx, hxfar %#08lx, pc %#08lx",
		  __entry->ipa, __entry->hsr,
		  __entry->hxfar, __entry->vcpu_pc)
);

TRACE_EVENT(kvm_access_fault,
	TP_PROTO(unsigned long ipa),
	TP_ARGS(ipa),

	TP_STRUCT__entry(
		__field(	unsigned long,	ipa		)
	),

	TP_fast_assign(
		__entry->ipa		= ipa;
	),

	TP_printk("IPA: %lx", __entry->ipa)
);

TRACE_EVENT(kvm_irq_line,
	TP_PROTO(unsigned int type, int vcpu_idx, int irq_num, int level),
	TP_ARGS(type, vcpu_idx, irq_num, level),

	TP_STRUCT__entry(
		__field(	unsigned int,	type		)
		__field(	int,		vcpu_idx	)
		__field(	int,		irq_num		)
		__field(	int,		level		)
	),

	TP_fast_assign(
		__entry->type		= type;
		__entry->vcpu_idx	= vcpu_idx;
		__entry->irq_num	= irq_num;
		__entry->level		= level;
	),

	TP_printk("Inject %s interrupt (%d), vcpu->idx: %d, num: %d, level: %d",
		  (__entry->type == KVM_ARM_IRQ_TYPE_CPU) ? "CPU" :
		  (__entry->type == KVM_ARM_IRQ_TYPE_PPI) ? "VGIC PPI" :
		  (__entry->type == KVM_ARM_IRQ_TYPE_SPI) ? "VGIC SPI" : "UNKNOWN",
		  __entry->type, __entry->vcpu_idx, __entry->irq_num, __entry->level)
);

TRACE_EVENT(kvm_mmio_emulate,
	TP_PROTO(unsigned long vcpu_pc, unsigned long instr,
		 unsigned long cpsr),
	TP_ARGS(vcpu_pc, instr, cpsr),

	TP_STRUCT__entry(
		__field(	unsigned long,	vcpu_pc		)
		__field(	unsigned long,	instr		)
		__field(	unsigned long,	cpsr		)
	),

	TP_fast_assign(
		__entry->vcpu_pc		= vcpu_pc;
		__entry->instr			= instr;
		__entry->cpsr			= cpsr;
	),

	TP_printk("Emulate MMIO at: 0x%08lx (instr: %08lx, cpsr: %08lx)",
		  __entry->vcpu_pc, __entry->instr, __entry->cpsr)
);

TRACE_EVENT(kvm_unmap_hva_range,
	TP_PROTO(unsigned long start, unsigned long end),
	TP_ARGS(start, end),

	TP_STRUCT__entry(
		__field(	unsigned long,	start		)
		__field(	unsigned long,	end		)
	),

	TP_fast_assign(
		__entry->start		= start;
		__entry->end		= end;
	),

	TP_printk("mmu notifier unmap range: %#08lx -- %#08lx",
		  __entry->start, __entry->end)
);

TRACE_EVENT(kvm_set_spte_hva,
	TP_PROTO(unsigned long hva),
	TP_ARGS(hva),

	TP_STRUCT__entry(
		__field(	unsigned long,	hva		)
	),

	TP_fast_assign(
		__entry->hva		= hva;
	),

	TP_printk("mmu notifier set pte hva: %#08lx", __entry->hva)
);

TRACE_EVENT(kvm_age_hva,
	TP_PROTO(unsigned long start, unsigned long end),
	TP_ARGS(start, end),

	TP_STRUCT__entry(
		__field(	unsigned long,	start		)
		__field(	unsigned long,	end		)
	),

	TP_fast_assign(
		__entry->start		= start;
		__entry->end		= end;
	),

	TP_printk("mmu notifier age hva: %#08lx -- %#08lx",
		  __entry->start, __entry->end)
);

TRACE_EVENT(kvm_test_age_hva,
	TP_PROTO(unsigned long hva),
	TP_ARGS(hva),

	TP_STRUCT__entry(
		__field(	unsigned long,	hva		)
	),

	TP_fast_assign(
		__entry->hva		= hva;
	),

	TP_printk("mmu notifier test age hva: %#08lx", __entry->hva)
);

TRACE_EVENT(kvm_set_way_flush,
	    TP_PROTO(unsigned long vcpu_pc, bool cache),
	    TP_ARGS(vcpu_pc, cache),

	    TP_STRUCT__entry(
		    __field(	unsigned long,	vcpu_pc		)
		    __field(	bool,		cache		)
	    ),

	    TP_fast_assign(
		    __entry->vcpu_pc		= vcpu_pc;
		    __entry->cache		= cache;
	    ),

	    TP_printk("S/W flush at 0x%016lx (cache %s)",
		      __entry->vcpu_pc, __entry->cache ? "on" : "off")
);

TRACE_EVENT(kvm_toggle_cache,
	    TP_PROTO(unsigned long vcpu_pc, bool was, bool now),
	    TP_ARGS(vcpu_pc, was, now),

	    TP_STRUCT__entry(
		    __field(	unsigned long,	vcpu_pc		)
		    __field(	bool,		was		)
		    __field(	bool,		now		)
	    ),

	    TP_fast_assign(
		    __entry->vcpu_pc		= vcpu_pc;
		    __entry->was		= was;
		    __entry->now		= now;
	    ),

	    TP_printk("VM op at 0x%016lx (cache was %s, now %s)",
		      __entry->vcpu_pc, __entry->was ? "on" : "off",
		      __entry->now ? "on" : "off")
);

/*
 * Tracepoints for arch_timer
 */
TRACE_EVENT(kvm_timer_update_irq,
	TP_PROTO(unsigned long vcpu_id, __u32 irq, int level),
	TP_ARGS(vcpu_id, irq, level),

	TP_STRUCT__entry(
		__field(	unsigned long,	vcpu_id	)
		__field(	__u32,		irq	)
		__field(	int,		level	)
	),

	TP_fast_assign(
		__entry->vcpu_id	= vcpu_id;
		__entry->irq		= irq;
		__entry->level		= level;
	),

	TP_printk("VCPU: %ld, IRQ %d, level %d",
		  __entry->vcpu_id, __entry->irq, __entry->level)
);

TRACE_EVENT(kvm_get_timer_map,
	TP_PROTO(unsigned long vcpu_id, struct timer_map *map),
	TP_ARGS(vcpu_id, map),

	TP_STRUCT__entry(
		__field(	unsigned long,		vcpu_id	)
		__field(	int,			direct_vtimer	)
		__field(	int,			direct_ptimer	)
		__field(	int,			emul_ptimer	)
	),

	TP_fast_assign(
		__entry->vcpu_id		= vcpu_id;
		__entry->direct_vtimer		= arch_timer_ctx_index(map->direct_vtimer);
		__entry->direct_ptimer =
			(map->direct_ptimer) ? arch_timer_ctx_index(map->direct_ptimer) : -1;
		__entry->emul_ptimer =
			(map->emul_ptimer) ? arch_timer_ctx_index(map->emul_ptimer) : -1;
	),

	TP_printk("VCPU: %ld, dv: %d, dp: %d, ep: %d",
		  __entry->vcpu_id,
		  __entry->direct_vtimer,
		  __entry->direct_ptimer,
		  __entry->emul_ptimer)
);

TRACE_EVENT(kvm_timer_save_state,
	TP_PROTO(struct arch_timer_context *ctx),
	TP_ARGS(ctx),

	TP_STRUCT__entry(
		__field(	unsigned long,		ctl		)
		__field(	unsigned long long,	cval		)
		__field(	int,			timer_idx	)
	),

	TP_fast_assign(
		__entry->ctl			= ctx->cnt_ctl;
		__entry->cval			= ctx->cnt_cval;
		__entry->timer_idx		= arch_timer_ctx_index(ctx);
	),

	TP_printk("   CTL: %#08lx CVAL: %#16llx arch_timer_ctx_index: %d",
		  __entry->ctl,
		  __entry->cval,
		  __entry->timer_idx)
);

TRACE_EVENT(kvm_timer_restore_state,
	TP_PROTO(struct arch_timer_context *ctx),
	TP_ARGS(ctx),

	TP_STRUCT__entry(
		__field(	unsigned long,		ctl		)
		__field(	unsigned long long,	cval		)
		__field(	int,			timer_idx	)
	),

	TP_fast_assign(
		__entry->ctl			= ctx->cnt_ctl;
		__entry->cval			= ctx->cnt_cval;
		__entry->timer_idx		= arch_timer_ctx_index(ctx);
	),

	TP_printk("CTL: %#08lx CVAL: %#16llx arch_timer_ctx_index: %d",
		  __entry->ctl,
		  __entry->cval,
		  __entry->timer_idx)
);

TRACE_EVENT(kvm_timer_hrtimer_expire,
	TP_PROTO(struct arch_timer_context *ctx),
	TP_ARGS(ctx),

	TP_STRUCT__entry(
		__field(	int,			timer_idx	)
	),

	TP_fast_assign(
		__entry->timer_idx		= arch_timer_ctx_index(ctx);
	),

	TP_printk("arch_timer_ctx_index: %d", __entry->timer_idx)
);

TRACE_EVENT(kvm_timer_emulate,
	TP_PROTO(struct arch_timer_context *ctx, bool should_fire),
	TP_ARGS(ctx, should_fire),

	TP_STRUCT__entry(
		__field(	int,			timer_idx	)
		__field(	bool,			should_fire	)
	),

	TP_fast_assign(
		__entry->timer_idx		= arch_timer_ctx_index(ctx);
		__entry->should_fire		= should_fire;
	),

	TP_printk("arch_timer_ctx_index: %d (should_fire: %d)",
		  __entry->timer_idx, __entry->should_fire)
);

#endif /* _TRACE_ARM64_KVM_H */

#undef TRACE_INCLUDE_PATH
#define TRACE_INCLUDE_PATH .
#undef TRACE_INCLUDE_FILE
#define TRACE_INCLUDE_FILE trace

/* This part must be outside protection */
#include <trace/define_trace.h>
