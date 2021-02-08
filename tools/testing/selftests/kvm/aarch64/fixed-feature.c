// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2021 Google LLC
 * Author: Fuad Tabba <tabba@google.com>
 */

/*
 * Tests fixed CPU features of protected VMs.
 *
 * For security and simplicity, protected VMs have fewer and more restricted CPU
 * features compared with nonprotected VMs. These unit tests perform sanity
 * checking to ensure that the features are not exposed via feature registers.
 * They also check that the features that are possible to restrict generate
 * traps in the guest VM.
 *
 * NOTE: This test (and the kvm selftest ucall interface) will not work once
 * protected VMs are more fully protected, i.e., memory isolation is implemented
 * in KVM. When that happens, we need to consider another way to implementing
 * these tests.
 */

#include "kvm_util.h"
#include "test_util.h"
#include "processor.h"
#include "sysreg.h"

#define VCPU_ID 0

/*
 * Additional ucalls for printing guest values.
 */

/* Print a constant string. */
#define UCALL_PR_STR (UCALL_LAST + 1)
#define PR_STR(value) ucall(UCALL_PR_STR, 1, value)
static void pr_str(struct ucall *uc)
{
	const char *str = (const char *)uc->args[0];

	pr_info("%s", str);
}

/* Print a uint64_t. */
#define UCALL_PR_U64 (UCALL_LAST + 2)
#define PR_U64(value) ucall(UCALL_PR_U64, 1, value)
static void pr_u64(struct ucall *uc)
{
	uint64_t value = (uint64_t)uc->args[0];

	pr_info("guest value: 0x%016lx\n", value);
}
/* Print a constant string and a uint64_t. */
#define UCALL_PR_STR_U64 (UCALL_LAST + 3)
#define PR_STR_U64(str, value) ucall(UCALL_PR_STR_U64, 2, str, value)
static void pr_str_u64(struct ucall *uc)
{
	const char *str = (const char *)uc->args[0];
	uint64_t value = (uint64_t)uc->args[1];

	pr_info("%s=0x%016lx\n", str, value);
}

/* Print a system register and its value.*/
#define print_sysreg(name) PR_STR_U64(#name, read_sysreg_s(SYS_ ## name))

/*
 * Beginning of guest code
 */

/* Counter for the number of exceptions (cur_spx_sync) taken by the guest. */
static volatile uint64_t num_exceptions;

/*
 * Exception handler callback called via synchronous exceptions (cur_spx_sync).
 *
 * Increment num_exceptions for every exception taken.
 */
static void feature_reg_exception_handler(struct ex_regs *regs)
{
	++num_exceptions;
	regs->pc += 4;
}

/* Assert that the executed code causes n exceptions in the guest. */
#define ASSERT_EXCEPTION_COUNT(code, n)                                        \
	do {                                                                   \
		uint64_t last_num = num_exceptions;                            \
		code;                                                          \
		GUEST_ASSERT(num_exceptions == last_num + (n));                \
	} while (0)

/* Assert that the executed code causes one exception in the guest. */
#define ASSERT_EXCEPTION(code) ASSERT_EXCEPTION_COUNT(code, 1)

/* Assert that the executed code does not cause any exceptions in the guest. */
#define ASSERT_NO_EXCEPTION(code) ASSERT_EXCEPTION_COUNT(code, 0)

/* Assert that reading the register causes an exception. */
#define ASSERT_EXCEPTION_READ(reg) \
	ASSERT_EXCEPTION(read_sysreg_s(reg))

/* Assert that writing to the register causes an exception. */
#define ASSERT_EXCEPTION_WRITE(reg) \
	ASSERT_EXCEPTION(write_sysreg_s(0, reg))

/* Assert that reading from and writing to the register causes exceptions. */
#define ASSERT_EXCEPTION_READ_WRITE(reg)				\
do {									\
	ASSERT_EXCEPTION_READ(reg);					\
	ASSERT_EXCEPTION_WRITE(reg);					\
} while (0)

/* Assert that reading the register doesn't cause an exception. */
#define ASSERT_NO_EXCEPTION_READ(reg) \
	ASSERT_NO_EXCEPTION(read_sysreg_s(reg))

/* Assert that writing to the register doesn't cause an exception. */
#define ASSERT_NO_EXCEPTION_WRITE(reg) \
	ASSERT_NO_EXCEPTION(write_sysreg_s(0, reg))

/* Assert that reading from/writing to the register doesn't cause exceptions. */
#define ASSERT_NO_EXCEPTION_READ_WRITE(reg)				\
do {									\
	ASSERT_NO_EXCEPTION_READ(reg);					\
	ASSERT_NO_EXCEPTION_WRITE(reg);					\
} while (0)

/* Return number of breakpoint (BRP) registers available. */
static int get_num_brps(void)
{
	uint64_t dfr0 = read_sysreg_s(SYS_ID_AA64DFR0_EL1);
	int value = (dfr0 >> ID_AA64DFR0_BRPS_SHIFT) & 0xfUL;

	if (value > 0)
		return value + 1;
	else
		return 0;
}

/* Return number of watchpoint (WRP) registers available. */
static int get_num_wrps(void)
{
	uint64_t dfr0 = read_sysreg_s(SYS_ID_AA64DFR0_EL1);
	int value = (dfr0 >> ID_AA64DFR0_WRPS_SHIFT) & 0xfUL;

	if (value > 0)
		return value + 1;
	else
		return 0;
}

/* Test miscellaneous system features. */
static void test_misc(bool is_protected)
{
	if (!is_protected)
		return;

	ASSERT_EXCEPTION_READ_WRITE(SYS_PMINTENSET_EL1);
	ASSERT_EXCEPTION_READ_WRITE(SYS_PMINTENCLR_EL1);
	ASSERT_EXCEPTION_READ_WRITE(SYS_PMCR_EL0);
	ASSERT_EXCEPTION_READ_WRITE(SYS_PMCNTENSET_EL0);
	ASSERT_EXCEPTION_READ_WRITE(SYS_PMCNTENCLR_EL0);
	ASSERT_EXCEPTION_READ_WRITE(SYS_PMOVSCLR_EL0);
	ASSERT_EXCEPTION_READ_WRITE(SYS_PMSWINC_EL0);
	ASSERT_EXCEPTION_READ_WRITE(SYS_PMSELR_EL0);
	ASSERT_EXCEPTION_READ_WRITE(SYS_PMCEID0_EL0);
	ASSERT_EXCEPTION_READ_WRITE(SYS_PMCEID1_EL0);
	ASSERT_EXCEPTION_READ_WRITE(SYS_PMCCNTR_EL0);
	ASSERT_EXCEPTION_READ_WRITE(SYS_PMXEVTYPER_EL0);
	ASSERT_EXCEPTION_READ_WRITE(SYS_PMXEVCNTR_EL0);
	ASSERT_EXCEPTION_READ_WRITE(SYS_PMUSERENR_EL0);
	ASSERT_EXCEPTION_READ_WRITE(SYS_PMOVSSET_EL0);
	ASSERT_EXCEPTION_READ_WRITE(SYS_PMCCFILTR_EL0);

	ASSERT_EXCEPTION_READ_WRITE(SYS_ZCR_EL1);

	/* Implementation-defined system registers. */
	ASSERT_EXCEPTION(read_sysreg(S3_0_c11_c0_5));
	ASSERT_EXCEPTION(read_sysreg(S3_0_c15_c0_5));

	/* Implementation-defined system instructions. */
	ASSERT_EXCEPTION(asm volatile("sys #0, C11, C0, #0, x0"));
	ASSERT_EXCEPTION(asm volatile("sys #0, C15, C0, #0, x0"));
	ASSERT_EXCEPTION(asm volatile("sysl x0, #0, C11, C0, #0"));
	ASSERT_EXCEPTION(asm volatile("sysl x0, #0, C15, C0, #0"));

	/*
	 * The following are close to the encoding ranges of many blocked
	 * features but should not be blocked.
	 * These assertions test that they are allowed.
	 */
	ASSERT_NO_EXCEPTION_READ(SYS_FAR_EL1);
	ASSERT_NO_EXCEPTION_READ(SYS_PAR_EL1);
	ASSERT_NO_EXCEPTION_WRITE(SYS_FAR_EL1);
	ASSERT_NO_EXCEPTION_WRITE(SYS_PAR_EL1);
}

/* Test for debug features. */
static void test_debug(bool is_protected)
{
	int num_brps = get_num_brps();
	int num_wrps = get_num_wrps();

	ASSERT_EXCEPTION(asm volatile("brk #0"));

	/*
	 * Check that the number of breakpoint/watchpoint registers is in line
	 * with the architecture spec for normal VMs, and with the pVM
	 * requirements for protected VMs.
	 */
	if (is_protected) {
		GUEST_ASSERT(num_brps == 0);
		GUEST_ASSERT(num_wrps == 0);
	} else {
		/* Arm Architecture Reference Manual mandates at least 2. */
		GUEST_ASSERT(num_brps > 1);
		GUEST_ASSERT(num_wrps > 1);
	}

/*
 * Assert whether accessing the register triggers an exception.
 *
 * In protected mode, all debug register accesses should cause an exception.
 * In non-protected mode, only accesses to non-existing (or invisible) registers
 * cause an exception.
 */
#define ASSERT_DEBUG_REG_EXCEPTION(name, n, count)			\
do {									\
	ASSERT_EXCEPTION_COUNT(read_sysreg_s(name(n)),			\
				is_protected || (count) <= (n));	\
	ASSERT_EXCEPTION_COUNT(write_sysreg_s(0, name(n)),		\
				is_protected || (count) <= (n));	\
} while (0)

/* A macro to expand DBG{BCR,BVR,WVR,WCR}n_EL1 registers */
#define DBG_BCR_BVR_WCR_WVR_EL1(n) \
do {									\
	ASSERT_DEBUG_REG_EXCEPTION(SYS_DBGBVRn_EL1, n, num_brps);	\
	ASSERT_DEBUG_REG_EXCEPTION(SYS_DBGBCRn_EL1, n, num_brps);	\
	ASSERT_DEBUG_REG_EXCEPTION(SYS_DBGWVRn_EL1, n, num_wrps);	\
	ASSERT_DEBUG_REG_EXCEPTION(SYS_DBGWCRn_EL1, n, num_wrps);	\
} while (0)

	DBG_BCR_BVR_WCR_WVR_EL1(0);
	DBG_BCR_BVR_WCR_WVR_EL1(1);
	DBG_BCR_BVR_WCR_WVR_EL1(2);
	DBG_BCR_BVR_WCR_WVR_EL1(3);
	DBG_BCR_BVR_WCR_WVR_EL1(4);
	DBG_BCR_BVR_WCR_WVR_EL1(5);
	DBG_BCR_BVR_WCR_WVR_EL1(6);
	DBG_BCR_BVR_WCR_WVR_EL1(7);
	DBG_BCR_BVR_WCR_WVR_EL1(8);
	DBG_BCR_BVR_WCR_WVR_EL1(9);
	DBG_BCR_BVR_WCR_WVR_EL1(10);
	DBG_BCR_BVR_WCR_WVR_EL1(11);
	DBG_BCR_BVR_WCR_WVR_EL1(12);
	DBG_BCR_BVR_WCR_WVR_EL1(13);
	DBG_BCR_BVR_WCR_WVR_EL1(14);
	DBG_BCR_BVR_WCR_WVR_EL1(15);

	/*
	 * Only perform the remainder tests for protected VMs, to avoid having
	 * to lookup features supported by nonprotected VMs.
	 */
	if (!is_protected)
		return;

	ASSERT_EXCEPTION_READ_WRITE(SYS_OSDTRRX_EL1);
	ASSERT_EXCEPTION_READ_WRITE(SYS_MDCCINT_EL1);
	ASSERT_EXCEPTION_READ_WRITE(SYS_MDSCR_EL1);
	ASSERT_EXCEPTION_READ_WRITE(SYS_OSDTRTX_EL1);
	ASSERT_EXCEPTION_READ_WRITE(SYS_OSECCR_EL1);
	ASSERT_EXCEPTION_READ_WRITE(SYS_MDRAR_EL1);
	ASSERT_EXCEPTION_READ_WRITE(SYS_OSLAR_EL1);
	ASSERT_EXCEPTION_READ_WRITE(SYS_OSLSR_EL1);
	ASSERT_EXCEPTION_READ_WRITE(SYS_OSDLR_EL1);
	ASSERT_EXCEPTION_READ_WRITE(SYS_DBGPRCR_EL1);
	ASSERT_EXCEPTION_READ_WRITE(SYS_DBGCLAIMSET_EL1);
	ASSERT_EXCEPTION_READ_WRITE(SYS_DBGCLAIMCLR_EL1);
	ASSERT_EXCEPTION_READ_WRITE(SYS_DBGAUTHSTATUS_EL1);
	ASSERT_EXCEPTION_READ_WRITE(SYS_MDCCSR_EL0);
	ASSERT_EXCEPTION_READ_WRITE(SYS_DBGDTR_EL0);
	ASSERT_EXCEPTION_READ_WRITE(SYS_DBGDTRRX_EL0);
	ASSERT_EXCEPTION_READ_WRITE(SYS_DBGDTRTX_EL0);
}

/*
 * The following masks are to select the feature id register bits that the
 * following tests will compare against.
 */

#define AA64MMFR0_MASK (0xff0000fUL)
#define AA64MMFR0_EXP  (0x0000002UL)

#define AA64MMFR1_MASK (0xff00f0f00UL)
#define AA64MMFR1_EXP  (0x0UL)

#define AA64MMFR2_MASK (0xf00f00ffff000UL)
#define AA64MMFR2_EXP  (0x0UL)

/* RAS can have a maximum value of 1, hence masking bits 31:28 by 0xe. */
/* EL3 can have a maximum value of 1, hence masking bits 15:12 by 0xe. */
#define AA64PFR0_MASK (0xffffef00efffUL)
#define AA64PFR0_EXP  (0x000000000111UL)

#define AA64PFR1_MASK (0xfff00UL)
#define AA64PFR1_EXP  (0x0UL)

/* Sanity-check the values of feature registers. */
static void test_feature_regs(bool is_protected)
{
	if (!is_protected)
		return;

	/* No AArch32 support. */
	GUEST_ASSERT(read_sysreg_s(SYS_ID_PFR0_EL1) == 0);
	GUEST_ASSERT(read_sysreg_s(SYS_ID_PFR1_EL1) == 0);
	GUEST_ASSERT(read_sysreg_s(SYS_ID_DFR0_EL1) == 0);
	GUEST_ASSERT(read_sysreg_s(SYS_ID_AFR0_EL1) == 0);
	GUEST_ASSERT(read_sysreg_s(SYS_ID_MMFR0_EL1) == 0);
	GUEST_ASSERT(read_sysreg_s(SYS_ID_MMFR1_EL1) == 0);
	GUEST_ASSERT(read_sysreg_s(SYS_ID_MMFR2_EL1) == 0);
	GUEST_ASSERT(read_sysreg_s(SYS_ID_MMFR3_EL1) == 0);

	GUEST_ASSERT(read_sysreg_s(SYS_ID_AA64AFR0_EL1) == 0);
	GUEST_ASSERT(read_sysreg_s(SYS_ID_AA64DFR0_EL1) == 0);
	GUEST_ASSERT(read_sysreg_s(SYS_ID_AA64ZFR0_EL1) == 0);

	GUEST_ASSERT((read_sysreg_s(SYS_ID_AA64MMFR0_EL1) & AA64MMFR0_MASK)
		== AA64MMFR0_EXP);
	GUEST_ASSERT((read_sysreg_s(SYS_ID_AA64MMFR1_EL1) & AA64MMFR1_MASK)
		== AA64MMFR1_EXP);
	GUEST_ASSERT((read_sysreg_s(SYS_ID_AA64MMFR2_EL1) & AA64MMFR2_MASK)
		== AA64MMFR2_EXP);
	GUEST_ASSERT((read_sysreg_s(SYS_ID_AA64PFR0_EL1) & AA64PFR0_MASK)
		== AA64PFR0_EXP);
	GUEST_ASSERT((read_sysreg_s(SYS_ID_AA64PFR1_EL1) & AA64PFR1_MASK)
		== AA64PFR1_EXP);
}

/*
 * Print the values of the feature registers that are fixed for protected VMs.
 *
 * For visual inspection, because it's difficult to write assertions for some of
 * the expected values.
 */
static void print_feature_regs(void)
{
	ASSERT_NO_EXCEPTION(
	print_sysreg(ID_AA64AFR0_EL1);
	print_sysreg(ID_AA64DFR0_EL1);
	print_sysreg(ID_AA64ISAR0_EL1);
	print_sysreg(ID_AA64ISAR1_EL1);
	print_sysreg(ID_AA64MMFR0_EL1);
	print_sysreg(ID_AA64MMFR1_EL1);
	print_sysreg(ID_AA64MMFR2_EL1);
	print_sysreg(ID_AA64PFR0_EL1);
	print_sysreg(ID_AA64PFR1_EL1);
	print_sysreg(ID_AA64ZFR0_EL1);
	);
}

/* Guest start function */
static void guest_code(bool is_protected)
{
	PR_STR_U64("is_protected", is_protected);

	print_feature_regs();
	test_feature_regs(is_protected);
	test_debug(is_protected);
	test_misc(is_protected);

	PR_STR_U64("num_exceptions", num_exceptions);

	GUEST_DONE();
}
/*
 * End guest code
 */

void run_test(bool is_protected)
{
	struct kvm_vm *vm;
	struct kvm_run *run;
	struct ucall uc;
	struct kvm_enable_cap protected_cap = {
		.cap = KVM_CAP_ARM_PROTECTED_VM,
		.flags = KVM_CAP_ARM_PROTECTED_VM_FLAGS_ENABLE,
		.args[0] = -1, /* No firmware. */
	};

	/* Create a VM with one VCPU. */
	vm = vm_create_default(VCPU_ID, 0, guest_code);
	vcpu_args_set(vm, VCPU_ID, 1, is_protected);

	if (is_protected)
		vm_enable_cap(vm, &protected_cap);

	ucall_init(vm, NULL);

	vm_init_descriptor_tables(vm);
	vcpu_init_descriptor_tables(vm, VCPU_ID);

	vm_install_sync_handler(vm, VECTOR_SYNC_CURRENT,
				ESR_EC_UNKNOWN, feature_reg_exception_handler);

	vm_install_sync_handler(vm, VECTOR_SYNC_CURRENT,
				ESR_EC_BRK_INS, feature_reg_exception_handler);

	run = vcpu_state(vm, VCPU_ID);

	for (;;) {
		vcpu_run(vm, 0);
		switch (get_ucall(vm, VCPU_ID, &uc)) {
		case UCALL_DONE:
			if (!is_protected) {
				/* Protected VMs cannot be freed. */
				kvm_vm_free(vm);
			}
			return;
		case UCALL_ABORT:
			/* Handles guest assertion failures. */
			TEST_FAIL("%s at %s:%ld", (const char *)uc.args[0],
				  __FILE__, uc.args[1]);
			break;
		case UCALL_PR_STR:
			pr_str(&uc);
			break;
		case UCALL_PR_U64:
			pr_u64(&uc);
			break;
		case UCALL_PR_STR_U64:
			pr_str_u64(&uc);
			break;
		default:
			TEST_FAIL("Unexpected exit: %s",
				  exit_reason_str(run->exit_reason));
			break;
		}
	}
}

void run_test_nonprotected(void)
{
	pr_info("Testing a nonprotected VM.\n");
	run_test(false);
}

void run_test_protected(void)
{
	if (!kvm_check_cap(KVM_CAP_ARM_PROTECTED_VM)) {
		fprintf(stderr, "Skipping: Protected KVM not available.\n");
		exit(KSFT_SKIP);
	}

	pr_info("Testing a protected VM.\n");

	run_test(true);
}

int main(int ac, char **av)
{
	run_test_nonprotected();
	run_test_protected();

	pr_info("Tests passed.\n\n");

	return 0;
}
