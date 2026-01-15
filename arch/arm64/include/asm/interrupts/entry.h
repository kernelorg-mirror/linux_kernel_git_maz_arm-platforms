/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2025 Arm Ltd.
 */
#ifndef __ASM_INTERRUPTS_ENTRY_H
#define __ASM_INTERRUPTS_ENTRY_H

#include <asm/arch_gicv3.h>
#include <asm/bug.h>
#include <asm/interrupts/common_flags.h>
#include <asm/ptrace.h>
#include <asm/sysreg.h>

/*
 * Exception handlers should always be called with DAIF and ALLINT set,
 * and PMR not masking any exceptions.
 * They should always return after setting DAIF and ALLINT.
 * As we always know what should be saved/restored, instead track what we are
 * changing things to, so we can detect inconsistent interrupt masking by
 * the code we call.
 */
struct entry_irqs_state {
	enum arm64_irqs_masks unmasked_to;
	u8 restored_pmr;
};

static inline
struct entry_irqs_state entry_unmask_irqs_to(enum arm64_irqs_masks mask)
{
	struct entry_irqs_state state = {
		.unmasked_to = mask,
		.restored_pmr = system_uses_irq_prio_masking() ?
				gic_read_pmr() : 0,
	};
	unsigned long daif_flags;

	/*
	 * The EL0 exception handlers do not care about the PMR :
	 * they only operate on DAIF.
	 * This way we can have a consistent view of interrupts in code directly
	 * called from EL0 handlers : either they are fully unmsaked or they
	 * are masked via DAIF.
	 * This relies on the early entry code setting the PMR accordingly.
	 */
	WARN_ON(system_has_prio_mask_debugging() &&
		(state.restored_pmr != GIC_PRIO_IRQON));

	switch (mask) {
	case PROCESS_CONTEXT:
		trace_hardirqs_on();
		daif_flags = DAIF_PROCCTX;
		break;
	case NOIRQ_PROCESS_CONTEXT:
	case NONMI_PROCESS_CONTEXT:
		daif_flags = DAIF_PROCCTX_NOIRQ;
		break;
	case ERROR_CONTEXT:
		daif_flags = DAIF_ERRCTX;
		break;
	/* Should not be useful, as this is the default on entry. */
	case CRITICAL_CONTEXT:
		daif_flags = DAIF_MASK;
		break;
	default:
		WARN(true, "Invalid interrupt mask in exception handler, not unmasking to be safe.\n");
		daif_flags = DAIF_MASK;
		break;
	}

	write_sysreg(daif_flags, daif);

	if (system_uses_nmi() && mask < NONMI_PROCESS_CONTEXT)
		_allint_clear();

	return state;
}

/*
 * Called to drop the interrupt masking further than we already did and
 * check for consistency with the previous drop.
 */
static inline
struct entry_irqs_state entry_unmask_irqs_nested(enum arm64_irqs_masks mask,
		struct entry_irqs_state previous_state)
{
	struct entry_irqs_state new_state;

	/* We should not be trying to drop to a stricter interrupt masking. */
	WARN_ON(mask > previous_state.unmasked_to);
	/* Someome did not properly keep track of PMR... */
	WARN_ON(system_has_prio_mask_debugging() &&
		(gic_read_pmr() != previous_state.restored_pmr));

	new_state = entry_unmask_irqs_to(mask);
	/* Keep the original PMR, we still want to check against it. */
	new_state.restored_pmr = previous_state.restored_pmr;
	return new_state;
}

static inline struct entry_irqs_state entry_inherit_irqs(struct pt_regs *regs)
{
	struct entry_irqs_state state;
	unsigned long daif_flags = regs->pstate & DAIF_MASK;
	unsigned long allint = regs->pstate & PSR_ALLINT_BIT;

	if (!regs_irqs_disabled(regs))
		trace_hardirqs_on();

	if (system_uses_irq_prio_masking()) {
		state.restored_pmr = regs->pmr;

		/*
		 * There has been concern that the write to daif
		 * might be reordered before this write to PMR.
		 * From the ARM ARM DDI 0487D.a, section D1.7.1
		 * "Accessing PSTATE fields":
		 *   Writes to the PSTATE fields have side-effects on
		 *   various aspects of the PE operation. All of these
		 *   side-effects are guaranteed:
		 *     - Not to be visible to earlier instructions in
		 *       the execution stream.
		 *     - To be visible to later instructions in the
		 *       execution stream
		 *
		 * Also, writes to PMR are self-synchronizing, so no
		 * interrupts with a lower priority than PMR is signaled
		 * to the PE after the write.
		 *
		 * So we don't need additional synchronization here.
		 */
		gic_write_pmr(state.restored_pmr);
	}

	write_sysreg(daif_flags, daif);

	if (system_uses_nmi() && allint == 0)
		_allint_clear();

	state.unmasked_to = get_irqs_mask(daif_flags, state.restored_pmr, allint);
	return state;
}

static inline void entry_mask_irqs_exit(struct entry_irqs_state saved_state)
{
	unsigned long pmr = system_uses_irq_prio_masking() ? gic_read_pmr() : 0;
	unsigned long allint = system_uses_nmi() ?
				read_sysreg_s(SYS_ALLINT) : 0;
	/*
	 * Exception handlers don't use the PMR to mask exceptions.
	 * If we restore with an inconsistent PMR, that means the code we called
	 * did not properly restore PMR before returning to us.
	 * It will safely be restored during kernel exit, but signal it.
	 */
	// FIXME: This cannot work yet, need consistent PMR handling beforehand...
	//WARN_ON(system_has_prio_mask_debugging() &&
	//	(saved_state.restored_pmr != pmr));

	WARN_ON(IS_ENABLED(CONFIG_DEBUG_IRQFLAGS) &&
		(get_irqs_mask(read_sysreg(daif), pmr, allint) <
						saved_state.unmasked_to));

	if (system_uses_nmi())
		_allint_set();

	write_sysreg(DAIF_MASK, daif);
	/*
	 * Always trace_hardirqs_off : some handlers return having
	 * turned interrupts off, but left hardirqs on.
	 */
	trace_hardirqs_off();
}

#endif /* __ASM_INTERRUPTS_ENTRY_H */
