/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2025 Arm Ltd.
 */
#ifndef __ASM_INTERRUPTS_COMMON_FLAGS_H
#define __ASM_INTERRUPTS_COMMON_FLAGS_H

#include <asm/ptrace.h>

#define DAIF_PROCCTX		0
#define DAIF_PROCCTX_NOIRQ	(PSR_I_BIT | PSR_F_BIT)
#define DAIF_ERRCTX		(PSR_A_BIT | PSR_I_BIT | PSR_F_BIT)
#define DAIF_MASK		(PSR_D_BIT | PSR_A_BIT | PSR_I_BIT | PSR_F_BIT)

enum arm64_irqs_masks {
	PROCESS_CONTEXT,
	NOIRQ_PROCESS_CONTEXT,
	NONMI_PROCESS_CONTEXT,
	ERROR_CONTEXT,
	CRITICAL_CONTEXT,
};

static inline
enum arm64_irqs_masks get_irqs_mask(unsigned long daif, unsigned long pmr,
				unsigned long allint)
{
	enum arm64_irqs_masks mask = PROCESS_CONTEXT;

	if (daif >= PSR_D_BIT)
		mask = CRITICAL_CONTEXT;
	else if (daif >= PSR_A_BIT)
		mask = ERROR_CONTEXT;
	else if (system_uses_nmi() && allint > 0)
		mask = NONMI_PROCESS_CONTEXT;
	else if (daif > 0)
		mask = NOIRQ_PROCESS_CONTEXT;
	else if (system_uses_irq_prio_masking() && pmr < GIC_PRIO_NMIOFF)
		mask = NONMI_PROCESS_CONTEXT;
	else if (system_uses_irq_prio_masking() && pmr < GIC_PRIO_IRQON)
		mask = NOIRQ_PROCESS_CONTEXT;

	return mask;
}

#ifdef CONFIG_ARM64_NMI
static __always_inline void _allint_clear(void)
{
	asm volatile(__msr_s(SYS_ALLINT_CLR, "xzr"));
}

static __always_inline void _allint_set(void)
{
	asm volatile(__msr_s(SYS_ALLINT_SET, "xzr"));
}
#else
static __always_inline void _allint_clear(void) {}
static __always_inline void _allint_set(void) {}
#endif /* CONFIG_ARM64_NMI */


#endif /* __ASM_INTERRUPTS_COMMON_FLAGS_H */
