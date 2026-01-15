/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2025 Arm Ltd.
 */
#ifndef __ASM_INTERRUPTS_MASKING_H
#define __ASM_INTERRUPTS_MASKING_H

#include <asm/arch_gicv3.h>
#include <asm/bug.h>
#include <asm/interrupts/common_flags.h>
#include <asm/ptrace.h>
#include <asm/sysreg.h>

struct arm64_irqs_state {
	enum arm64_irqs_masks masked_to;
	u64 daif;
	u64 pmr;
};

#ifdef CONFIG_DEBUG_IRQFLAGS
/* Make sure the CPU init/tear down masking functions are only used once. */
static DEFINE_PER_CPU(bool, irqs_masks_cpu_init_done);
static DEFINE_PER_CPU(bool, irqs_masks_cpu_final_done);
#endif

static inline void __local_all_irqs_set_mask(enum arm64_irqs_masks new_mask)
{
	u64 daif_flags;

	switch (new_mask) {
	case PROCESS_CONTEXT:
		daif_flags = DAIF_PROCCTX;
		trace_hardirqs_on();
		break;
	case NOIRQ_PROCESS_CONTEXT:
	case NONMI_PROCESS_CONTEXT:
		daif_flags = DAIF_PROCCTX_NOIRQ;
		break;
	case ERROR_CONTEXT:
		daif_flags = DAIF_ERRCTX;
		break;
	case CRITICAL_CONTEXT:
		daif_flags = DAIF_MASK;
		break;
	default:
		BUILD_BUG_ON(new_mask > CRITICAL_CONTEXT);
		break;
	}

	if (system_uses_irq_prio_masking()) {
		u64 pmr = GIC_PRIO_IRQON;

		/*
		 * If interrupts are disabled but we can take
		 * asynchronous errors, we can take NMIs
		 */
		if (new_mask == NOIRQ_PROCESS_CONTEXT) {
			daif_flags = DAIF_PROCCTX;
			pmr = GIC_PRIO_IRQOFF;
		} else if (new_mask == NONMI_PROCESS_CONTEXT) {
			daif_flags = DAIF_PROCCTX;
			pmr = GIC_PRIO_NMIOFF;
		}

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
		gic_write_pmr(pmr);
		if (new_mask == PROCESS_CONTEXT)
			pmr_sync();
	}

	write_sysreg(daif_flags, daif);

	if (new_mask > PROCESS_CONTEXT)
		trace_hardirqs_off();
}

static inline
struct arm64_irqs_state local_all_irqs_save_mask(enum arm64_irqs_masks new_mask)
{
	struct arm64_irqs_state irqs_state = {
		.masked_to = new_mask,
		.daif = read_sysreg(daif)
	};
	if (system_uses_irq_prio_masking())
		irqs_state.pmr = gic_read_pmr();

	WARN_ON(IS_ENABLED(CONFIG_DEBUG_IRQFLAGS) &&
		new_mask < get_irqs_mask(irqs_state.daif, irqs_state.pmr));

	__local_all_irqs_set_mask(new_mask);

	return irqs_state;
}

static inline void local_all_irqs_restore(struct arm64_irqs_state irqs_state)
{
	if (IS_ENABLED(CONFIG_DEBUG_IRQFLAGS)) {
		enum arm64_irqs_masks current_mask;
		unsigned long pmr = system_uses_irq_prio_masking() ?
				gic_read_pmr() : GIC_PRIO_IRQON;

		current_mask = get_irqs_mask(read_sysreg(daif), pmr);

		/* Inconsistent IRQ masking between save and restore */
		WARN_ON(current_mask != irqs_state.masked_to);
	}

	if (get_irqs_mask(irqs_state.daif, irqs_state.pmr) == PROCESS_CONTEXT)
		trace_hardirqs_on();

	if (system_uses_irq_prio_masking())
		gic_write_pmr(irqs_state.pmr);

	write_sysreg(irqs_state.daif, daif);
}

#ifdef CONFIG_DEBUG_IRQFLAGS
static inline
void local_all_irqs_cpu_init_mask(enum arm64_irqs_masks init_irqs_mask)
{
	WARN_ON(__this_cpu_read(irqs_masks_cpu_init_done));
	__local_all_irqs_set_mask(init_irqs_mask);
	__this_cpu_write(irqs_masks_cpu_init_done, true);
}

static inline void local_all_irqs_final_mask(void)
{
	WARN_ON(__this_cpu_read(irqs_masks_cpu_final_done));
	__local_all_irqs_set_mask(CRITICAL_CONTEXT);
	__this_cpu_write(irqs_masks_cpu_final_done, true);
}
#else /* CONFIG_DEBUG_IRQFLAGS */
static inline
void local_all_irqs_cpu_init_mask(enum arm64_irqs_masks init_irqs_mask)
{
	__local_all_irqs_set_mask(init_irqs_mask);
}

static inline void local_all_irqs_final_mask(void)
{
	__local_all_irqs_set_mask(CRITICAL_CONTEXT);
}
#endif /* CONFIG_DEBUG_IRQFLAGS */

/*
 * In some cases, WFI or guest entry for example, we always want interrupts
 * to reach the CPU even if masked. Masking via the PMR prevents them from
 * reaching the CPU and waking it up.
 * Force IQR masking using DAIF by raising the priority mask
 * and setting the IF flags.
 *
 * Should only be called when IRQs are already masked.
 */
static inline struct arm64_irqs_state local_all_irqs_force_daif_save(void)
{
	struct arm64_irqs_state saved_state;
	/*
	 * Cannot use lockdep_assert here as idle entry enables hardirqs
	 * while keeping interrupts masked.
	 */
	WARN_ON_ONCE(!irqs_disabled());

	if (system_uses_irq_prio_masking()) {
		saved_state.daif = read_sysreg(daif);
		saved_state.pmr = gic_read_pmr();
		write_sysreg(saved_state.daif | DAIF_PROCCTX_NOIRQ, daif);
		gic_write_pmr(GIC_PRIO_IRQON);
		pmr_sync();
	}

	return saved_state;
}

/*
 * Return to masking with the PMR, restoring previously saved DAIF and PMR.
 *
 * IRQs or interrupt priority masking should not have been re-enabled in between
 * the save and restore.
 */
static inline
void local_all_irqs_force_daif_restore(struct arm64_irqs_state saved_state)
{
	/*
	 * Cannot use lockdep_assert here as idle entry enables hardirqs
	 * while keeping interrupts masked.
	 */
	WARN_ON_ONCE(!irqs_disabled());
	WARN_ON_ONCE(system_has_prio_mask_debugging() &&
		gic_read_pmr() != GIC_PRIO_IRQON);

	if (system_uses_irq_prio_masking()) {
		/*
		 * As above : the PMR is self-synchronizing and will not signal
		 * IRQs of lower priority as soon as this write is executed.
		 */
		gic_write_pmr(saved_state.pmr);
		write_sysreg(saved_state.daif, daif);
	}
}

/*
 * During early boot, we unmask PSR.DA before the GIC has been set up.
 * If we use IRQ priority masking, the PMR and PSR will be out of sync
 * after the GIC is enabled : sync them up.
 */
static inline void local_interrupt_priority_init(void)
{
	WARN_ON(read_sysreg(daif) & PSR_A_BIT);
	lockdep_assert_irqs_disabled();

	gic_write_pmr(GIC_PRIO_IRQOFF);
	write_sysreg(DAIF_PROCCTX, daif);
}

#endif /* __ASM_INTERRUPTS_MASKING_H */
