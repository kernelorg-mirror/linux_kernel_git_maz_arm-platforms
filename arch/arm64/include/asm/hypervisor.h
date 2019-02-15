/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_ARM64_HYPERVISOR_H
#define _ASM_ARM64_HYPERVISOR_H

#include <linux/types.h>
#include <asm/xen/hypervisor.h>

typedef struct pv_cond_yield_ent {
	u64	pc;
	u64	mask;
	u8	val_reg;
	u8	addr_reg;
	u16	__reserved;
	u32	flags;
} pv_cond_yield_ent_t;

#endif
