// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2025 - ARM Ltd
 */

#include <linux/irqchip/arm-gic-v5.h>

#include <asm/kvm_hyp.h>

void __vgic_v5_detect_ppis(u64 *impl_ppi_mask)
{
	/* Disable DVI for all PPIs */
	write_sysreg_s(0, SYS_ICH_PPI_DVIR0_EL2);
	write_sysreg_s(0, SYS_ICH_PPI_DVIR1_EL2);

	/* Write all 1s to the PPI enable regs */
	write_sysreg_s(GENMASK_ULL(63, 0), SYS_ICH_PPI_ENABLER0_EL2);
	write_sysreg_s(GENMASK_ULL(63, 0), SYS_ICH_PPI_ENABLER1_EL2);

	/* Read back to figure out which are stateful */
	impl_ppi_mask[0] = read_sysreg_s(SYS_ICH_PPI_ENABLER0_EL2);
	impl_ppi_mask[1] = read_sysreg_s(SYS_ICH_PPI_ENABLER1_EL2);

	/* Disable them all again! */
	write_sysreg_s(0, SYS_ICH_PPI_ENABLER0_EL2);
	write_sysreg_s(0, SYS_ICH_PPI_ENABLER1_EL2);
}
