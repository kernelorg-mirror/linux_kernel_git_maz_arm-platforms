/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Apple SoC vendor-defined system register definitions
 *
 * Copyright The Asahi Linux Contributors

 * This file contains only well-understood registers that are useful to
 * Linux. If you are looking for things to add here, you should visit:
 *
 * https://github.com/AsahiLinux/docs/wiki/HW:ARM-System-Registers
 */

#ifndef __ASM_SYSREG_APPLE_H
#define __ASM_SYSREG_APPLE_H

#include <asm/sysreg.h>

/*
 * Keep these registers in encoding order, except for register arrays;
 * those should be listed in array order starting from the position of
 * the encoding of the first register.
 */

#define SYS_APL_PMCR0			sys_reg(3, 1, 15, 0, 0)
#define PMCR0_IMODE_OFF			(0 << 8)
#define PMCR0_IMODE_PMI			(1 << 8)
#define PMCR0_IMODE_AIC			(2 << 8)
#define PMCR0_IMODE_HALT		(3 << 8)
#define PMCR0_IMODE_FIQ			(4 << 8)
#define PMCR0_IMODE_MASK		(7 << 8)
#define PMCR0_IACT			(BIT(11))

/* IPI request registers */
#define SYS_APL_IPI_RR_LOCAL		sys_reg(3, 5, 15, 0, 0)
#define SYS_APL_IPI_RR_GLOBAL		sys_reg(3, 5, 15, 0, 1)
#define IPI_RR_CPU(cpu)			(cpu)
/* Cluster only used for the GLOBAL register */
#define IPI_RR_CLUSTER(cpu)		((cluster) << 16)
#define IPI_RR_IMMEDIATE		(0 << 28)
#define IPI_RR_RETRACT			(1 << 28)
#define IPI_RR_DEFERRED			(2 << 28)
#define IPI_RR_NOWAKE			(3 << 28)

/* IPI status register */
#define SYS_APL_IPI_SR			sys_reg(3, 5, 15, 1, 1)
#define IPI_SR_PENDING			(BIT(0))

/* Guest timer FIQ mask register */
#define SYS_APL_VM_TMR_MASK		sys_reg(3, 5, 15, 1, 3)
#define VM_TMR_MASK_V			(BIT(0))
#define VM_TMR_MASK_P			(BIT(1))

/* Deferred IPI countdown register */
#define SYS_APL_IPI_CR			sys_reg(3, 5, 15, 3, 1)

#define SYS_APL_UPMCR0			sys_reg(3, 7, 15, 0, 4)
#define UPMCR0_IMODE_OFF		(0 << 16)
#define UPMCR0_IMODE_AIC		(2 << 16)
#define UPMCR0_IMODE_HALT		(3 << 16)
#define UPMCR0_IMODE_FIQ		(4 << 16)
#define UPMCR0_IMODE_MASK		(7 << 16)

#define SYS_APL_UPMSR			sys_reg(3, 7, 15, 6, 4)
#define UPMSR_IACT			(BIT(0))

#endif	/* __ASM_SYSREG_APPLE_H */
