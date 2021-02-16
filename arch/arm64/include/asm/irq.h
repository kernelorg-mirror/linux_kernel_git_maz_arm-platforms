/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __ASM_IRQ_H
#define __ASM_IRQ_H

#ifndef __ASSEMBLER__

#include <asm-generic/irq.h>

#define ARCH_IRQ_MULTI_HANDLER_NR_ENTRY 2

struct pt_regs;

int __init set_handle_irq_entry(void (*handle_irq)(struct pt_regs *), int nr);
static inline int set_handle_irq(void (*handle_irq)(struct pt_regs *))
{
	return set_handle_irq_entry(handle_irq, 0);
}

#define set_handle_irq	set_handle_irq

/*
 * Allows interrupt handlers to find the irqchip that's been registered as the
 * top-level IRQ handler.
 */
extern void (*handle_arch_irq[ARCH_IRQ_MULTI_HANDLER_NR_ENTRY])(struct pt_regs *) __ro_after_init;

static inline int nr_legacy_irqs(void)
{
	return 0;
}

#endif /* !__ASSEMBLER__ */
#endif
