/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2021 Google LLC
 * Author: Fuad Tabba <tabba@google.com>
 */

#ifndef __ARM64_KVM_FIXED_CONFIG_H__
#define __ARM64_KVM_FIXED_CONFIG_H__

#include <asm/sysreg.h>

/*
 * This file contains definitions for features to be allowed or restricted for
 * guest virtual machines as a baseline, depending on what mode KVM is running
 * in and on the type of guest is running.
 *
 * The features are represented as the highest allowed value for a feature in
 * the feature id registers. If the field is set to all ones (i.e., 0b1111),
 * then it's only restricted by what the system allows. If the feature is set to
 * another value, then that value would be the maximum value allowed and
 * supported in pKVM, even if the system supports a higher value.
 *
 * Some features are forced to a certain value, in which case a SET bitmap is
 * used to force these values.
 */


/*
 * Allowed features for protected guests (Protected KVM)
 *
 * The approach taken here is to allow features that are:
 * - needed by common Linux distributions (e.g., flooating point)
 * - are trivial, e.g., supporting the feature doesn't introduce or require the
 * tracking of additional state
 * - not trapable
 */

/*
 * - Floating-point and Advanced SIMD:
 *	Don't require much support other than maintaining the context, which KVM
 *	already has.
 * - AArch64 guests only (no support for AArch32 guests):
 *	Simplify support in case of asymmetric AArch32 systems.
 * - RAS (v1)
 *	v1 doesn't require much additional support, but later versions do.
 * - Data Independent Timing
 *	Trivial
 * Remaining features are not supported either because they require too much
 * support from KVM, or risk leaking guest data.
 */
#define PVM_ID_AA64PFR0_ALLOW (\
	ARM64_FEATURE_MASK(ID_AA64PFR0_FP) | \
	FIELD_PREP(ARM64_FEATURE_MASK(ID_AA64PFR0_EL0), ID_AA64PFR0_ELx_64BIT_ONLY) | \
	FIELD_PREP(ARM64_FEATURE_MASK(ID_AA64PFR0_EL1), ID_AA64PFR0_ELx_64BIT_ONLY) | \
	FIELD_PREP(ARM64_FEATURE_MASK(ID_AA64PFR0_EL2), ID_AA64PFR0_ELx_64BIT_ONLY) | \
	FIELD_PREP(ARM64_FEATURE_MASK(ID_AA64PFR0_EL3), ID_AA64PFR0_ELx_64BIT_ONLY) | \
	FIELD_PREP(ARM64_FEATURE_MASK(ID_AA64PFR0_RAS), ID_AA64PFR0_RAS_V1) | \
	ARM64_FEATURE_MASK(ID_AA64PFR0_ASIMD) | \
	ARM64_FEATURE_MASK(ID_AA64PFR0_DIT) \
	)

/*
 * - Branch Target Identification
 * - Speculative Store Bypassing
 *	These features are trivial to support
 */
#define PVM_ID_AA64PFR1_ALLOW (\
	ARM64_FEATURE_MASK(ID_AA64PFR1_BT) | \
	ARM64_FEATURE_MASK(ID_AA64PFR1_SSBS) \
	)

/*
 * No support for Scalable Vectors:
 *	Requires additional support from KVM
 */
#define PVM_ID_AA64ZFR0_ALLOW (0ULL)

/*
 * No support for debug, including breakpoints, and watchpoints:
 *	Reduce complexity and avoid exposing/leaking guest data
 *
 * NOTE: The Arm architecture mandates support for at least the Armv8 debug
 * architecture, which would include at least 2 hardware breakpoints and
 * watchpoints. Providing that support to protected guests adds considerable
 * state and complexity, and risks leaking guest data. Therefore, the reserved
 * value of 0 is used for debug-related fields.
 */
#define PVM_ID_AA64DFR0_ALLOW (0ULL)

/*
 * These features are chosen because they are supported by KVM and to limit the
 * confiruation state space and make it more deterministic.
 * - 40-bit IPA
 * - 16-bit ASID
 * - Mixed-endian
 * - Distinction between Secure and Non-secure Memory
 * - Mixed-endian at EL0 only
 * - Non-context synchronizing exception entry and exit
 */
#define PVM_ID_AA64MMFR0_ALLOW (\
	FIELD_PREP(ARM64_FEATURE_MASK(ID_AA64MMFR0_PARANGE), ID_AA64MMFR0_PARANGE_40) | \
	FIELD_PREP(ARM64_FEATURE_MASK(ID_AA64MMFR0_ASID), ID_AA64MMFR0_ASID_16) | \
	ARM64_FEATURE_MASK(ID_AA64MMFR0_BIGENDEL) | \
	ARM64_FEATURE_MASK(ID_AA64MMFR0_SNSMEM) | \
	ARM64_FEATURE_MASK(ID_AA64MMFR0_BIGENDEL0) | \
	ARM64_FEATURE_MASK(ID_AA64MMFR0_EXS) \
	)

/*
 * - 64KB granule not supported
 */
#define PVM_ID_AA64MMFR0_SET (\
	FIELD_PREP(ARM64_FEATURE_MASK(ID_AA64MMFR0_TGRAN64), ID_AA64MMFR0_TGRAN64_NI) \
	)

/*
 * These features are chosen because they are supported by KVM and to limit the
 * confiruation state space and make it more deterministic.
 * - Hardware translation table updates to Access flag and Dirty state
 * - Number of VMID bits from CPU
 * - Hierarchical Permission Disables
 * - Privileged Access Never
 * - SError interrupt exceptions from speculative reads
 * - Enhanced Translation Synchronization
 */
#define PVM_ID_AA64MMFR1_ALLOW (\
	ARM64_FEATURE_MASK(ID_AA64MMFR1_HADBS) | \
	ARM64_FEATURE_MASK(ID_AA64MMFR1_VMIDBITS) | \
	ARM64_FEATURE_MASK(ID_AA64MMFR1_HPD) | \
	ARM64_FEATURE_MASK(ID_AA64MMFR1_PAN) | \
	ARM64_FEATURE_MASK(ID_AA64MMFR1_SPECSEI) | \
	ARM64_FEATURE_MASK(ID_AA64MMFR1_ETS) \
	)

/*
 * These features are chosen because they are supported by KVM and to limit the
 * confiruation state space and make it more deterministic.
 * - Common not Private translations
 * - User Access Override
 * - IESB bit in the SCTLR_ELx registers
 * - Unaligned single-copy atomicity and atomic functions
 * - ESR_ELx.EC value on an exception by read access to feature ID space
 * - TTL field in address operations.
 * - Break-before-make sequences when changing translation block size
 * - E0PDx mechanism
 */
#define PVM_ID_AA64MMFR2_ALLOW (\
	ARM64_FEATURE_MASK(ID_AA64MMFR2_CNP) | \
	ARM64_FEATURE_MASK(ID_AA64MMFR2_UAO) | \
	ARM64_FEATURE_MASK(ID_AA64MMFR2_IESB) | \
	ARM64_FEATURE_MASK(ID_AA64MMFR2_AT) | \
	ARM64_FEATURE_MASK(ID_AA64MMFR2_IDS) | \
	ARM64_FEATURE_MASK(ID_AA64MMFR2_TTL) | \
	ARM64_FEATURE_MASK(ID_AA64MMFR2_BBM) | \
	ARM64_FEATURE_MASK(ID_AA64MMFR2_E0PD) \
	)

/*
 * Allow all features in this register because they are trivial to support, or
 * are already supported by KVM:
 * - LS64
 * - XS
 * - I8MM
 * - DGB
 * - BF16
 * - SPECRES
 * - SB
 * - FRINTTS
 * - PAuth
 * - FPAC
 * - LRCPC
 * - FCMA
 * - JSCVT
 * - DPB
 */
#define PVM_ID_AA64ISAR1_ALLOW (~0ULL)

#endif /* __ARM64_KVM_FIXED_CONFIG_H__ */
