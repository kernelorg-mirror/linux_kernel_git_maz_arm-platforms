// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2017 - Columbia University and Linaro Ltd.
 * Author: Jintack Lim <jintack.lim@linaro.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <linux/kvm.h>
#include <linux/kvm_host.h>

#include <asm/kvm_emulate.h>
#include <asm/kvm_nested.h>
#include <asm/sysreg.h>

#include "sys_regs.h"

/*
 * Inject wfx to the virtual EL2 if this is not from the virtual EL2 and
 * the virtual HCR_EL2.TWX is set. Otherwise, let the host hypervisor
 * handle this.
 */
int handle_wfx_nested(struct kvm_vcpu *vcpu, bool is_wfe)
{
	u64 hcr_el2 = __vcpu_sys_reg(vcpu, HCR_EL2);

	if (vcpu_mode_el2(vcpu))
		return -EINVAL;

	if ((is_wfe && (hcr_el2 & HCR_TWE)) || (!is_wfe && (hcr_el2 & HCR_TWI)))
		return kvm_inject_nested_sync(vcpu, kvm_vcpu_get_hsr(vcpu));

	return -EINVAL;
}

#define FEATURE(x)	(GENMASK_ULL(x##_SHIFT + 3, x##_SHIFT))

/*
 * Our emulated CPU doesn't support all the possible features. For the
 * sake of simplicity (and probably mental sanity), wipe out a number
 * of feature bits we don't intend to support for the time being.
 * This list should get updated as new features get added to the NV
 * support, and new extension to the architecture.
 *
 * Revisit: Implement as a whitelist rather than a blacklist?
 */
void access_nested_id_reg(struct kvm_vcpu *v, struct sys_reg_params *p,
			  const struct sys_reg_desc *r)
{
	u32 id = sys_reg((u32)r->Op0, (u32)r->Op1,
			 (u32)r->CRn, (u32)r->CRm, (u32)r->Op2);
	u64 val, tmp;

	if (!nested_virt_in_use(v))
		return;

	val = p->regval;

	switch (id) {
	case SYS_ID_AA64DFR0_EL1:
		/* No SPE */
		val &= ~FEATURE(ID_AA64DFR0_PMSVER);
		/* Cap PMU to ARMv8.1 */
		tmp = FIELD_GET(FEATURE(ID_AA64DFR0_PMUVER), val);
		if (tmp > 0b0100) {
			val &= FEATURE(ID_AA64DFR0_PMUVER);
			val |= FIELD_PREP(FEATURE(ID_AA64DFR0_PMUVER), 0b0100);
		}
		/* No trace */
		val &= FEATURE(ID_AA64DFR0_TRACEVER);
		/* Cap Debug to ARMv8.1 */
		tmp = FIELD_GET(FEATURE(ID_AA64DFR0_DEBUGVER), val);
		if (tmp > 0b0111) {
			val &= FEATURE(ID_AA64DFR0_DEBUGVER);
			val |= FIELD_PREP(FEATURE(ID_AA64DFR0_DEBUGVER), 0b0111);
		}
		break;

	case SYS_ID_AA64ISAR1_EL1:
		/* No PtrAuth */
		val &= ~(FEATURE(ID_AA64ISAR1_APA) |
			 FEATURE(ID_AA64ISAR1_API) |
			 FEATURE(ID_AA64ISAR1_GPA) |
			 FEATURE(ID_AA64ISAR1_GPI));
		break;

	case SYS_ID_AA64MMFR0_EL1:
		/* Cap PARange to 40bits */
		tmp = FIELD_GET(FEATURE(ID_AA64MMFR0_PARANGE), val);
		if (tmp > 0b0010) {
			val &= ~FEATURE(ID_AA64MMFR0_PARANGE);
			val |= FIELD_PREP(FEATURE(ID_AA64MMFR0_PARANGE), 0b0010);
		}
		break;

	case SYS_ID_AA64MMFR1_EL1:
		/* No XNX */
		val &= ~FEATURE(ID_AA64MMFR1_XNX);
		/* No RAS */
		val &= ~FEATURE(ID_AA64MMFR1_SpecSEI);
		/* No Hierarchical Permission Disable */
		val &= ~FEATURE(ID_AA64MMFR1_HPD);
		/* No Hardward Access flags and Dirty Bit State update */
		val &= ~FEATURE(ID_AA64MMFR1_HADBS);
		break;

	case SYS_ID_AA64MMFR2_EL1:
		/* No ARMv8.2-EVT */
		val &= ~FEATURE(ID_AA64MMFR2_EVT);
		/* No ARMv8.4-TTRem */
		val &= ~FEATURE(ID_AA64MMFR2_BBM);
		/* No ARMv8.4-TTST */
		val &= ~FEATURE(ID_AA64MMFR2_ST);
		/* No ARMv8.3-CCIDX */
		val &= ~FEATURE(ID_AA64MMFR2_CCIDX);
		/* No ARMv8.2-LVA */
		val &= ~FEATURE(ID_AA64MMFR2_LVA);
		break;

	case SYS_ID_AA64PFR0_EL1:
		/* No AMU */
		val &= ~FEATURE(ID_AA64PFR0_AMU);
		/* No MPAM */
		val &= ~FEATURE(ID_AA64PFR0_MPAM);
		/* No Secure EL2 */
		val &= ~FEATURE(ID_AA64PFR0_SEL2);
		/* No RAS */
		val &= ~FEATURE(ID_AA64PFR0_RAS);
		/* No SVE */
		val &= ~FEATURE(ID_AA64PFR0_SVE);
		/* EL2 is AArch64 only */
		val &= ~FEATURE(ID_AA64PFR0_EL2);
		val |= FIELD_PREP(FEATURE(ID_AA64PFR0_EL2), 0b0001);
		break;

	case SYS_ID_AA64PFR1_EL1:
		/* No MTE */
		val &= ~FEATURE(ID_AA64PFR1_MTE);
		/* No BT */
		val &= ~FEATURE(ID_AA64PFR1_BT);
		break;
	}

	p->regval = val;
}
