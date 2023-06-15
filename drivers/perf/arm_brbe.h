/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Branch Record Buffer Extension Helpers.
 *
 * Copyright (C) 2022 ARM Limited
 *
 * Author: Anshuman Khandual <anshuman.khandual@arm.com>
 */
#define pr_fmt(fmt) "brbe: " fmt

#include <linux/perf/arm_pmu.h>

#define BRBFCR_EL1_BRANCH_FILTERS (BRBFCR_EL1_DIRECT   | \
				   BRBFCR_EL1_INDIRECT | \
				   BRBFCR_EL1_RTN      | \
				   BRBFCR_EL1_INDCALL  | \
				   BRBFCR_EL1_DIRCALL  | \
				   BRBFCR_EL1_CONDDIR)

#define BRBFCR_EL1_DEFAULT_CONFIG (BRBFCR_EL1_BANK_MASK | \
				   BRBFCR_EL1_PAUSED    | \
				   BRBFCR_EL1_EnI       | \
				   BRBFCR_EL1_BRANCH_FILTERS)

/*
 * BRBTS_EL1 is currently not used for branch stack implementation
 * purpose but BRBCR_EL1.TS needs to have a valid value from all
 * available options. BRBCR_EL1_TS_VIRTUAL is selected for this.
 */
#define BRBCR_EL1_DEFAULT_TS      FIELD_PREP(BRBCR_EL1_TS_MASK, BRBCR_EL1_TS_VIRTUAL)

#define BRBCR_EL1_DEFAULT_CONFIG  (BRBCR_EL1_EXCEPTION | \
				   BRBCR_EL1_ERTN      | \
				   BRBCR_EL1_CC        | \
				   BRBCR_EL1_MPRED     | \
				   BRBCR_EL1_E1BRE     | \
				   BRBCR_EL1_E0BRE     | \
				   BRBCR_EL1_FZP       | \
				   BRBCR_EL1_DEFAULT_TS)
/*
 * BRBE Instructions
 *
 * BRB_IALL : Invalidate the entire buffer
 * BRB_INJ  : Inject latest branch record derived from [BRBSRCINJ, BRBTGTINJ, BRBINFINJ]
 */
#define BRB_IALL __emit_inst(0xD5000000 | sys_insn(1, 1, 7, 2, 4) | (0x1f))
#define BRB_INJ  __emit_inst(0xD5000000 | sys_insn(1, 1, 7, 2, 5) | (0x1f))

/*
 * BRBE Buffer Organization
 *
 * BRBE buffer is arranged as multiple banks of 32 branch record
 * entries each. An individual branch record in a given bank could
 * be accessed, after selecting the bank in BRBFCR_EL1.BANK and
 * accessing the registers i.e [BRBSRC, BRBTGT, BRBINF] set with
 * indices [0..31].
 *
 * Bank 0
 *
 *	---------------------------------	------
 *	| 00 | BRBSRC | BRBTGT | BRBINF |	| 00 |
 *	---------------------------------	------
 *	| 01 | BRBSRC | BRBTGT | BRBINF |	| 01 |
 *	---------------------------------	------
 *	| .. | BRBSRC | BRBTGT | BRBINF |	| .. |
 *	---------------------------------	------
 *	| 31 | BRBSRC | BRBTGT | BRBINF |	| 31 |
 *	---------------------------------	------
 *
 * Bank 1
 *
 *	---------------------------------	------
 *	| 32 | BRBSRC | BRBTGT | BRBINF |	| 00 |
 *	---------------------------------	------
 *	| 33 | BRBSRC | BRBTGT | BRBINF |	| 01 |
 *	---------------------------------	------
 *	| .. | BRBSRC | BRBTGT | BRBINF |	| .. |
 *	---------------------------------	------
 *	| 63 | BRBSRC | BRBTGT | BRBINF |	| 31 |
 *	---------------------------------	------
 */
#define BRBE_BANK_MAX_ENTRIES 32

#define BRBE_BANK0_IDX_MIN 0
#define BRBE_BANK0_IDX_MAX 31
#define BRBE_BANK1_IDX_MIN 32
#define BRBE_BANK1_IDX_MAX 63

struct brbe_hw_attr {
	int	brbe_version;
	int	brbe_cc;
	int	brbe_nr;
	int	brbe_format;
};

enum brbe_bank_idx {
	BRBE_BANK_IDX_INVALID = -1,
	BRBE_BANK_IDX_0,
	BRBE_BANK_IDX_1,
	BRBE_BANK_IDX_MAX
};

#define RETURN_READ_BRBSRCN(n) \
	read_sysreg_s(SYS_BRBSRC##n##_EL1)

#define RETURN_READ_BRBTGTN(n) \
	read_sysreg_s(SYS_BRBTGT##n##_EL1)

#define RETURN_READ_BRBINFN(n) \
	read_sysreg_s(SYS_BRBINF##n##_EL1)

#define BRBE_REGN_CASE(n, case_macro) \
	case n: return case_macro(n); break

#define BRBE_REGN_SWITCH(x, case_macro)				\
	do {							\
		switch (x) {					\
		BRBE_REGN_CASE(0, case_macro);			\
		BRBE_REGN_CASE(1, case_macro);			\
		BRBE_REGN_CASE(2, case_macro);			\
		BRBE_REGN_CASE(3, case_macro);			\
		BRBE_REGN_CASE(4, case_macro);			\
		BRBE_REGN_CASE(5, case_macro);			\
		BRBE_REGN_CASE(6, case_macro);			\
		BRBE_REGN_CASE(7, case_macro);			\
		BRBE_REGN_CASE(8, case_macro);			\
		BRBE_REGN_CASE(9, case_macro);			\
		BRBE_REGN_CASE(10, case_macro);			\
		BRBE_REGN_CASE(11, case_macro);			\
		BRBE_REGN_CASE(12, case_macro);			\
		BRBE_REGN_CASE(13, case_macro);			\
		BRBE_REGN_CASE(14, case_macro);			\
		BRBE_REGN_CASE(15, case_macro);			\
		BRBE_REGN_CASE(16, case_macro);			\
		BRBE_REGN_CASE(17, case_macro);			\
		BRBE_REGN_CASE(18, case_macro);			\
		BRBE_REGN_CASE(19, case_macro);			\
		BRBE_REGN_CASE(20, case_macro);			\
		BRBE_REGN_CASE(21, case_macro);			\
		BRBE_REGN_CASE(22, case_macro);			\
		BRBE_REGN_CASE(23, case_macro);			\
		BRBE_REGN_CASE(24, case_macro);			\
		BRBE_REGN_CASE(25, case_macro);			\
		BRBE_REGN_CASE(26, case_macro);			\
		BRBE_REGN_CASE(27, case_macro);			\
		BRBE_REGN_CASE(28, case_macro);			\
		BRBE_REGN_CASE(29, case_macro);			\
		BRBE_REGN_CASE(30, case_macro);			\
		BRBE_REGN_CASE(31, case_macro);			\
		default:					\
			pr_warn("unknown register index\n");	\
			return -1;				\
		}						\
	} while (0)

static inline int buffer_to_brbe_idx(int buffer_idx)
{
	return buffer_idx % BRBE_BANK_MAX_ENTRIES;
}

static inline u64 get_brbsrc_reg(int buffer_idx)
{
	int brbe_idx = buffer_to_brbe_idx(buffer_idx);

	BRBE_REGN_SWITCH(brbe_idx, RETURN_READ_BRBSRCN);
}

static inline u64 get_brbtgt_reg(int buffer_idx)
{
	int brbe_idx = buffer_to_brbe_idx(buffer_idx);

	BRBE_REGN_SWITCH(brbe_idx, RETURN_READ_BRBTGTN);
}

static inline u64 get_brbinf_reg(int buffer_idx)
{
	int brbe_idx = buffer_to_brbe_idx(buffer_idx);

	BRBE_REGN_SWITCH(brbe_idx, RETURN_READ_BRBINFN);
}

static inline u64 brbe_record_valid(u64 brbinf)
{
	return FIELD_GET(BRBINFx_EL1_VALID_MASK, brbinf);
}

static inline bool brbe_invalid(u64 brbinf)
{
	return brbe_record_valid(brbinf) == BRBINFx_EL1_VALID_NONE;
}

static inline bool brbe_record_is_complete(u64 brbinf)
{
	return brbe_record_valid(brbinf) == BRBINFx_EL1_VALID_FULL;
}

static inline bool brbe_record_is_source_only(u64 brbinf)
{
	return brbe_record_valid(brbinf) == BRBINFx_EL1_VALID_SOURCE;
}

static inline bool brbe_record_is_target_only(u64 brbinf)
{
	return brbe_record_valid(brbinf) == BRBINFx_EL1_VALID_TARGET;
}

static inline int brbe_get_in_tx(u64 brbinf)
{
	return FIELD_GET(BRBINFx_EL1_T_MASK, brbinf);
}

static inline int brbe_get_mispredict(u64 brbinf)
{
	return FIELD_GET(BRBINFx_EL1_MPRED_MASK, brbinf);
}

static inline int brbe_get_lastfailed(u64 brbinf)
{
	return FIELD_GET(BRBINFx_EL1_LASTFAILED_MASK, brbinf);
}

static inline int brbe_get_cycles(u64 brbinf)
{
	/*
	 * Captured cycle count is unknown and hence
	 * should not be passed on to the user space.
	 */
	if (brbinf & BRBINFx_EL1_CCU)
		return 0;

	return FIELD_GET(BRBINFx_EL1_CC_MASK, brbinf);
}

static inline int brbe_get_type(u64 brbinf)
{
	return FIELD_GET(BRBINFx_EL1_TYPE_MASK, brbinf);
}

static inline int brbe_get_el(u64 brbinf)
{
	return FIELD_GET(BRBINFx_EL1_EL_MASK, brbinf);
}

static inline int brbe_get_numrec(u64 brbidr)
{
	return FIELD_GET(BRBIDR0_EL1_NUMREC_MASK, brbidr);
}

static inline int brbe_get_format(u64 brbidr)
{
	return FIELD_GET(BRBIDR0_EL1_FORMAT_MASK, brbidr);
}

static inline int brbe_get_cc_bits(u64 brbidr)
{
	return FIELD_GET(BRBIDR0_EL1_CC_MASK, brbidr);
}
