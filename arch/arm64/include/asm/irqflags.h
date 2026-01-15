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
 *
 * With the addition of the FEAT_NMI extension we gain an additional
 * class of superpriority IRQ/FIQ which is separately masked with a
 * choice of modes controlled by SCTLR_ELn.{SPINTMASK,NMI}.
 * Linux sets SPINTMASK to 0 and NMI to 1 which results in ALLINT.ALLINT
 * masking both superpriority interrupts and IRQ/FIQ regardless of the
 * I and F settings. Since these superpriority interrupts are being
 * used as NMIs we do not include them in the interrupt masking here,
 * anything that requires that NMIs be masked needs to explicitly do so,
 * but we do check for ALLINT masking IRQs/FIQs.
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
		u16 allint;
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

/*
 * Save the current interrupt enable state.
 */
static inline unsigned long arch_local_save_flags(void)
{
	union arm64_local_irqs irqs = { .daif = read_sysreg(daif) };

	if (system_uses_nmi())
		irqs.allint = read_sysreg_s(SYS_ALLINT);

	if (system_uses_irq_prio_masking())
		irqs.pmr = read_sysreg_s(SYS_ICC_PMR_EL1);

	return irqs.irqflags;
}

static inline bool arch_irqs_disabled_flags(unsigned long flags)
{
	union arm64_local_irqs irqs = { .irqflags = flags };
	/* If I is set, the PMR doesn't matter : interrupts will not be taken. */
	if (irqs.daif & PSR_I_BIT)
		return true;

	/* SCTLR_EL1.SPINTMASK is clear, so ALLINT masks *all* IRQs/FIQs. */
	if (system_uses_nmi() && irqs.allint > 0)
		return true;

	if (system_uses_irq_prio_masking() && irqs.pmr < GIC_PRIO_IRQON)
		return true;

	return false;
}

static inline bool arch_irqs_disabled(void)
{
	return arch_irqs_disabled_flags(arch_local_save_flags());
}

static inline unsigned long arch_local_irq_save(void)
{
	unsigned long flags = arch_local_save_flags();

	if (system_uses_irq_prio_masking()) {
		/*
		 * There are too many states with IRQs disabled, just keep the current
		 * state if interrupts are already disabled/masked.
		 */
		if (!arch_irqs_disabled_flags(flags))
			__pmr_local_irq_disable();
	} else {
		__daif_local_irq_disable();
	}

	return flags;
}

/*
 * restore saved IRQ state
 */
static inline void arch_local_irq_restore(unsigned long flags)
{
	union arm64_local_irqs irqs = { .irqflags = flags };

	barrier();
	if (system_uses_irq_prio_masking()) {
		write_sysreg_s(irqs.pmr, SYS_ICC_PMR_EL1);
		pmr_sync();
	} else {
		write_sysreg(irqs.daif, daif);
	}
	barrier();
}

#endif /* __ASM_IRQFLAGS_H */
