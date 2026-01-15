/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __ASM_CPUIDLE_H
#define __ASM_CPUIDLE_H

#include <asm/proc-fns.h>

#ifdef CONFIG_ARM64_PSEUDO_NMI
#include <asm/interrupts/masking.h>

struct arm_cpuidle_irq_context {
	struct arm64_irqs_state arm64_context;
};

#define arm_cpuidle_save_irq_context(__c)				\
	do {								\
		struct arm_cpuidle_irq_context *c = __c;		\
		if (system_uses_irq_prio_masking()) {			\
			c->arm64_context = local_all_irqs_force_daif_save(); \
		}							\
	} while (0)

#define arm_cpuidle_restore_irq_context(__c)				\
	do {								\
		struct arm_cpuidle_irq_context *c = __c;		\
		if (system_uses_irq_prio_masking()) {			\
			local_all_irqs_force_daif_restore(c->arm64_context); \
		}							\
	} while (0)
#else
struct arm_cpuidle_irq_context { };

#define arm_cpuidle_save_irq_context(c)		(void)c
#define arm_cpuidle_restore_irq_context(c)	(void)c
#endif
#endif
