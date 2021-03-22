/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Code copied from arch/arm64/mm/cache.S.
 */

#include <linux/linkage.h>
#include <asm/assembler.h>
#include <asm/alternative.h>
#include <asm/asm-bug.h>

SYM_FUNC_START_PI(__flush_dcache_area)
alternative_if_not ARM64_KVM_PROTECTED_MODE
	ASM_BUG()
alternative_else_nop_endif
	dcache_by_line_op civac, sy, x0, x1, x2, x3
	ret
SYM_FUNC_END_PI(__flush_dcache_area)
