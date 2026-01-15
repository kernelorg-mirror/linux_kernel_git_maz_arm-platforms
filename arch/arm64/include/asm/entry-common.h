/* SPDX-License-Identifier: GPL-2.0 */

#ifndef _ASM_ARM64_ENTRY_COMMON_H
#define _ASM_ARM64_ENTRY_COMMON_H

#include <linux/thread_info.h>

#include <asm/cpufeature.h>
#include <asm/fpsimd.h>
#include <asm/interrupts/masking.h>
#include <asm/mte.h>
#include <asm/stacktrace.h>

#define ARCH_EXIT_TO_USER_MODE_WORK (_TIF_MTE_ASYNC_FAULT | _TIF_FOREIGN_FPSTATE)

static __always_inline void arch_exit_to_user_mode_work(struct pt_regs *regs,
							unsigned long ti_work)
{
	if (ti_work & _TIF_MTE_ASYNC_FAULT) {
		clear_thread_flag(TIF_MTE_ASYNC_FAULT);
		send_sig_fault(SIGSEGV, SEGV_MTEAERR, (void __user *)NULL, current);
	}

	if (ti_work & _TIF_FOREIGN_FPSTATE)
		fpsimd_restore_current_state();
}

#define arch_exit_to_user_mode_work arch_exit_to_user_mode_work

static inline bool arch_irqentry_exit_need_resched(void)
{
	/*
	 * DAIF.DA are cleared at the start of IRQ/FIQ handling, and when GIC
	 * priority masking is used the GIC irqchip driver will clear DAIF.IF
	 * in gic_unmask_pnmis() for normal IRQs. If anything is set in
	 * DAIF we must have handled an NMI, so skip preemption.
	 */
	if (system_uses_irq_prio_masking() && read_sysreg(daif))
		return false;

	/*
	 * Preempting a task from an IRQ means we leave copies of PSTATE
	 * on the stack. cpufeature's enable calls may modify PSTATE, but
	 * resuming one of these preempted tasks would undo those changes.
	 *
	 * Only allow a task to be preempted once cpufeatures have been
	 * enabled.
	 */
	if (!system_capabilities_finalized())
		return false;

	return true;
}

#define arch_irqentry_exit_need_resched arch_irqentry_exit_need_resched

/* When exiting EL1 handlers, we masked all interrupts.
 * This is not compatible with the scheduling done in `irqentry_exit()`,
 * as it expects *only* local_irqs to be masked, and will unmask them.
 * However, we still want to have everything properly mask when exiting
 * the kernel, so partially unmask in preparation for scheduling.
 */
static inline void arch_irqentry_exit_prepare_schedule_irq(void) {
	__local_all_irqs_schedule_irq_unmask();
}

#define arch_irqentry_exit_prepare_schedule_irq arch_irqentry_exit_prepare_schedule_irq

/*
 * Now that we are done scheduling in `irqentry_exit()`, mask all interrupts
 * properly again so that we can safely exit the kernel.
 */
static inline void arch_irqentry_exit_complete_schedule_irq(void) {
	__local_all_irqs_schedule_irq_mask();
}

#define arch_irqentry_exit_complete_schedule_irq arch_irqentry_exit_complete_schedule_irq

#endif /* _ASM_ARM64_ENTRY_COMMON_H */
