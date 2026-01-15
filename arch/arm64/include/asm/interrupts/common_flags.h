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
	ERROR_CONTEXT,
};

static inline
enum arm64_irqs_masks get_irqs_mask(unsigned long daif, unsigned long pmr)
{
	enum arm64_irqs_masks mask = PROCESS_CONTEXT;

	if (daif >= PSR_A_BIT)
		mask = ERROR_CONTEXT;
	else if (daif > 0)
		mask = NOIRQ_PROCESS_CONTEXT;
	else if (system_uses_irq_prio_masking() && pmr < GIC_PRIO_IRQON)
		mask = NOIRQ_PROCESS_CONTEXT;

	return mask;
}

#endif /* __ASM_INTERRUPTS_COMMON_FLAGS_H */
