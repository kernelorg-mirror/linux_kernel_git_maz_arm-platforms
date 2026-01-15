/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2012 ARM Ltd.
 */
#ifndef __ASM_IRQFLAGS_H
#define __ASM_IRQFLAGS_H

#include <asm/barrier.h>
#include <asm/ptrace.h>
#include <asm/sysreg.h>

#include <linux/compiler.h>

/*
 * Aarch64 has flags for masking: Debug, Asynchronous (serror), Interrupts and
 * FIQ exceptions, in the 'daif' register. We mask and unmask them in 'daif'
 * order:
 * Masking debug exceptions causes all other exceptions to be masked too/
 * Masking SError masks IRQ/FIQ, but not debug exceptions. IRQ and FIQ are
 * always masked and unmasked together, and have no side effects for other
 * flags. Keeping to this order makes it easier for entry.S to know which
 * exceptions should be unmasked.
 */

 /*
  * Internally, we want to independently manipulate and track the different
  * interrupt masking mechanisms.
  * Externally, the generic irqflags API expects unsgined longs to represent
  * the state of interrupts, which are treated as obscure arch-specific data.
  */
union arm64_local_irqs {
	struct {
		u16 daif;
		u8 pmr;
	};
	unsigned long irqflags;
};
static_assert(sizeof(union arm64_local_irqs) == sizeof(unsigned long));

static __always_inline void __daif_local_irq_enable(void)
{
	barrier();
	asm volatile("msr daifclr, #3");
	barrier();
}

static __always_inline void __pmr_local_irq_enable(void)
{
	if (IS_ENABLED(CONFIG_ARM64_DEBUG_PRIORITY_MASKING)) {
		u32 pmr = read_sysreg_s(SYS_ICC_PMR_EL1);
		WARN_ON_ONCE(pmr != GIC_PRIO_IRQON && pmr != GIC_PRIO_IRQOFF);
	}

	barrier();
	write_sysreg_s(GIC_PRIO_IRQON, SYS_ICC_PMR_EL1);
	pmr_sync();
	barrier();
}

static inline void arch_local_irq_enable(void)
{
	if (system_uses_irq_prio_masking()) {
		__pmr_local_irq_enable();
	} else {
		__daif_local_irq_enable();
	}
}

static __always_inline void __daif_local_irq_disable(void)
{
	barrier();
	asm volatile("msr daifset, #3");
	barrier();
}

static __always_inline void __pmr_local_irq_disable(void)
{
	if (IS_ENABLED(CONFIG_ARM64_DEBUG_PRIORITY_MASKING)) {
		u32 pmr = read_sysreg_s(SYS_ICC_PMR_EL1);
		WARN_ON_ONCE(pmr != GIC_PRIO_IRQON && pmr != GIC_PRIO_IRQOFF);
	}

	barrier();
	write_sysreg_s(GIC_PRIO_IRQOFF, SYS_ICC_PMR_EL1);
	barrier();
}

static inline void arch_local_irq_disable(void)
{
	if (system_uses_irq_prio_masking()) {
		__pmr_local_irq_disable();
	} else {
		__daif_local_irq_disable();
	}
}

static __always_inline union arm64_local_irqs __daif_local_save_flags(void)
{
	return (union arm64_local_irqs){ .daif = read_sysreg(daif) };
}

static __always_inline union arm64_local_irqs __pmr_local_save_flags(void)
{
	return (union arm64_local_irqs){ .pmr = read_sysreg_s(SYS_ICC_PMR_EL1) };
}

/*
 * Save the current interrupt enable state.
 */
static inline unsigned long arch_local_save_flags(void)
{
	if (system_uses_irq_prio_masking()) {
		return __pmr_local_save_flags().irqflags;
	} else {
		return __daif_local_save_flags().irqflags;
	}
}

static __always_inline
bool __daif_irqs_disabled_flags(union arm64_local_irqs irqs)
{
	return irqs.daif & PSR_I_BIT;
}

static __always_inline
bool __pmr_irqs_disabled_flags(union arm64_local_irqs irqs)
{
	return irqs.pmr != GIC_PRIO_IRQON;
}

static inline bool arch_irqs_disabled_flags(unsigned long flags)
{
	union arm64_local_irqs irqs = { .irqflags = flags };
	if (system_uses_irq_prio_masking()) {
		return __pmr_irqs_disabled_flags(irqs);
	} else {
		return __daif_irqs_disabled_flags(irqs);
	}
}

static __always_inline bool __daif_irqs_disabled(void)
{
	return __daif_irqs_disabled_flags(__daif_local_save_flags());
}

static __always_inline bool __pmr_irqs_disabled(void)
{
	return __pmr_irqs_disabled_flags(__pmr_local_save_flags());
}

static inline bool arch_irqs_disabled(void)
{
	if (system_uses_irq_prio_masking()) {
		return __pmr_irqs_disabled();
	} else {
		return __daif_irqs_disabled();
	}
}

static __always_inline union arm64_local_irqs __daif_local_irq_save(void)
{
	union arm64_local_irqs irqs = __daif_local_save_flags();

	__daif_local_irq_disable();

	return irqs;
}

static __always_inline union arm64_local_irqs __pmr_local_irq_save(void)
{
	union arm64_local_irqs irqs = __pmr_local_save_flags();

	/*
	 * There are too many states with IRQs disabled, just keep the current
	 * state if interrupts are already disabled/masked.
	 */
	if (!__pmr_irqs_disabled_flags(irqs))
		__pmr_local_irq_disable();

	return irqs;
}

static inline unsigned long arch_local_irq_save(void)
{
	if (system_uses_irq_prio_masking()) {
		return __pmr_local_irq_save().irqflags;
	} else {
		return __daif_local_irq_save().irqflags;
	}
}

static __always_inline
void __daif_local_irq_restore(union arm64_local_irqs irqs)
{
	barrier();
	write_sysreg(irqs.daif, daif);
	barrier();
}

static __always_inline
void __pmr_local_irq_restore(union arm64_local_irqs irqs)
{
	barrier();
	write_sysreg_s(irqs.pmr, SYS_ICC_PMR_EL1);
	pmr_sync();
	barrier();
}

/*
 * restore saved IRQ state
 */
static inline void arch_local_irq_restore(unsigned long flags)
{
	union arm64_local_irqs irqs = { .irqflags = flags };
	if (system_uses_irq_prio_masking()) {
		__pmr_local_irq_restore(irqs);
	} else {
		__daif_local_irq_restore(irqs);
	}
}

#endif /* __ASM_IRQFLAGS_H */
