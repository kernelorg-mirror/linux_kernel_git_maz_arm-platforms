/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef	__ARM64_KVM_CONFIG_H__
#define	__ARM64_KVM_CONFIG_H__

#define FEAT_SPE		ID_AA64DFR0_EL1, PMSVer, IMP
#define FEAT_SPE_FnE		ID_AA64DFR0_EL1, PMSVer, V1P2
#define FEAT_BRBE		ID_AA64DFR0_EL1, BRBE, IMP
#define FEAT_TRC_SR		ID_AA64DFR0_EL1, TraceVer, IMP
#define FEAT_PMUv3		ID_AA64DFR0_EL1, PMUVer, IMP
#define FEAT_TRBE		ID_AA64DFR0_EL1, TraceBuffer, IMP
#define FEAT_TRBEv1p1		ID_AA64DFR0_EL1, TraceBuffer, TRBE_V1P1
#define FEAT_DoubleLock		ID_AA64DFR0_EL1, DoubleLock, IMP
#define FEAT_TRF		ID_AA64DFR0_EL1, TraceFilt, IMP
#define FEAT_AA32EL0		ID_AA64PFR0_EL1, EL0, AARCH32
#define FEAT_AA32EL1		ID_AA64PFR0_EL1, EL1, AARCH32
#define FEAT_AA64EL1		ID_AA64PFR0_EL1, EL1, IMP
#define FEAT_AA64EL3		ID_AA64PFR0_EL1, EL3, IMP
#define FEAT_AIE		ID_AA64MMFR3_EL1, AIE, IMP
#define FEAT_S2POE		ID_AA64MMFR3_EL1, S2POE, IMP
#define FEAT_S1POE		ID_AA64MMFR3_EL1, S1POE, IMP
#define FEAT_S1PIE		ID_AA64MMFR3_EL1, S1PIE, IMP
#define FEAT_THE		ID_AA64PFR1_EL1, THE, IMP
#define FEAT_SME		ID_AA64PFR1_EL1, SME, IMP
#define FEAT_GCS		ID_AA64PFR1_EL1, GCS, IMP
#define FEAT_LS64		ID_AA64ISAR1_EL1, LS64, LS64
#define FEAT_LS64_V		ID_AA64ISAR1_EL1, LS64, LS64_V
#define FEAT_LS64_ACCDATA	ID_AA64ISAR1_EL1, LS64, LS64_ACCDATA
#define FEAT_RAS		ID_AA64PFR0_EL1, RAS, IMP
#define FEAT_RASv2		ID_AA64PFR0_EL1, RAS, V2
#define FEAT_GICv3		ID_AA64PFR0_EL1, GIC, IMP
#define FEAT_LOR		ID_AA64MMFR1_EL1, LO, IMP
#define FEAT_SPEv1p2		ID_AA64DFR0_EL1, PMSVer, V1P2
#define FEAT_SPEv1p4		ID_AA64DFR0_EL1, PMSVer, V1P4
#define FEAT_SPEv1p5		ID_AA64DFR0_EL1, PMSVer, V1P5
#define FEAT_ATS1A		ID_AA64ISAR2_EL1, ATS1A, IMP
#define FEAT_SPECRES2		ID_AA64ISAR1_EL1, SPECRES, COSP_RCTX
#define FEAT_SPECRES		ID_AA64ISAR1_EL1, SPECRES, IMP
#define FEAT_TLBIRANGE		ID_AA64ISAR0_EL1, TLB, RANGE
#define FEAT_TLBIOS		ID_AA64ISAR0_EL1, TLB, OS
#define FEAT_PAN2		ID_AA64MMFR1_EL1, PAN, PAN2
#define FEAT_DPB2		ID_AA64ISAR1_EL1, DPB, DPB2
#define FEAT_AMUv1		ID_AA64PFR0_EL1, AMU, IMP
#define FEAT_AMUv1p1		ID_AA64PFR0_EL1, AMU, V1P1
#define FEAT_CMOW		ID_AA64MMFR1_EL1, CMOW, IMP
#define FEAT_D128		ID_AA64MMFR3_EL1, D128, IMP
#define FEAT_DoubleFault2	ID_AA64PFR1_EL1, DF2, IMP
#define FEAT_FPMR		ID_AA64PFR2_EL1, FPMR, IMP
#define FEAT_MOPS		ID_AA64ISAR2_EL1, MOPS, IMP
#define FEAT_NMI		ID_AA64PFR1_EL1, NMI, IMP
#define FEAT_SCTLR2		ID_AA64MMFR3_EL1, SCTLRX, IMP
#define FEAT_TCR2		ID_AA64MMFR3_EL1, TCRX, IMP
#define FEAT_XS			ID_AA64ISAR1_EL1, XS, IMP
#define FEAT_EVT		ID_AA64MMFR2_EL1, EVT, IMP
#define FEAT_EVT_TTLBxS		ID_AA64MMFR2_EL1, EVT, TTLBxS
#define FEAT_RME		ID_AA64PFR0_EL1, RME, IMP
#define FEAT_MPAM		ID_AA64PFR0_EL1, MPAM, 1
#define FEAT_S2FWB		ID_AA64MMFR2_EL1, FWB, IMP
#define FEAT_TME		ID_AA64ISAR0_EL1, TME, IMP
#define FEAT_TWED		ID_AA64MMFR1_EL1, TWED, IMP
#define FEAT_E2H0		ID_AA64MMFR4_EL1, E2H0, IMP
#define FEAT_SRMASK		ID_AA64MMFR4_EL1, SRMASK, IMP
#define FEAT_PoPS		ID_AA64MMFR4_EL1, PoPS, IMP
#define FEAT_PFAR		ID_AA64PFR1_EL1, PFAR, IMP
#define FEAT_Debugv8p9		ID_AA64DFR0_EL1, PMUVer, V3P9
#define FEAT_PMUv3_SS		ID_AA64DFR0_EL1, PMSS, IMP
#define FEAT_SEBEP		ID_AA64DFR0_EL1, SEBEP, IMP
#define FEAT_EBEP		ID_AA64DFR1_EL1, EBEP, IMP
#define FEAT_ITE		ID_AA64DFR1_EL1, ITE, IMP
#define FEAT_PMUv3_ICNTR	ID_AA64DFR1_EL1, PMICNTR, IMP
#define FEAT_SPMU		ID_AA64DFR1_EL1, SPMU, IMP
#define FEAT_SPE_nVM		ID_AA64DFR2_EL1, SPE_nVM, IMP
#define FEAT_STEP2		ID_AA64DFR2_EL1, STEP, IMP
#define FEAT_SYSREG128		ID_AA64ISAR2_EL1, SYSREG_128, IMP
#define FEAT_CPA2		ID_AA64ISAR3_EL1, CPA, CPA2
#define FEAT_ASID2		ID_AA64MMFR4_EL1, ASID2, IMP
#define FEAT_MEC		ID_AA64MMFR3_EL1, MEC, IMP
#define FEAT_HAFT		ID_AA64MMFR1_EL1, HAFDBS, HAFT
#define FEAT_BTI		ID_AA64PFR1_EL1, BT, IMP
#define FEAT_ExS		ID_AA64MMFR0_EL1, EXS, IMP
#define FEAT_IESB		ID_AA64MMFR2_EL1, IESB, IMP
#define FEAT_LSE2		ID_AA64MMFR2_EL1, AT, IMP
#define FEAT_LSMAOC		ID_AA64MMFR2_EL1, LSM, IMP
#define FEAT_MixedEnd		ID_AA64MMFR0_EL1, BIGEND, IMP
#define FEAT_MixedEndEL0	ID_AA64MMFR0_EL1, BIGENDEL0, IMP
#define FEAT_MTE2		ID_AA64PFR1_EL1, MTE, MTE2
#define FEAT_MTE_ASYNC		ID_AA64PFR1_EL1, MTE_frac, ASYNC
#define FEAT_MTE_STORE_ONLY	ID_AA64PFR2_EL1, MTESTOREONLY, IMP
#define FEAT_PAN		ID_AA64MMFR1_EL1, PAN, IMP
#define FEAT_PAN3		ID_AA64MMFR1_EL1, PAN, PAN3
#define FEAT_SSBS		ID_AA64PFR1_EL1, SSBS, IMP
#define FEAT_TIDCP1		ID_AA64MMFR1_EL1, TIDCP1, IMP
#define FEAT_FGT		ID_AA64MMFR0_EL1, FGT, IMP
#define FEAT_MTPMU		ID_AA64DFR0_EL1, MTPMU, IMP

#define __expand_field_sign_unsigned(id, fld, val)			\
	((u64)SYS_FIELD_VALUE(id, fld, val))

#define __expand_field_sign_signed(id, fld, val)			\
	({								\
		u64 __val = SYS_FIELD_VALUE(id, fld, val);		\
		sign_extend64(__val, id##_##fld##_WIDTH - 1);		\
	})

#define get_idreg_field_unsigned(kvm, id, fld)				\
	({								\
		u64 __val = kvm_read_vm_id_reg((kvm), SYS_##id);	\
		FIELD_GET(id##_##fld##_MASK, __val);			\
	})

#define get_idreg_field_signed(kvm, id, fld)				\
	({								\
		u64 __val = get_idreg_field_unsigned(kvm, id, fld);	\
		sign_extend64(__val, id##_##fld##_WIDTH - 1);		\
	})

#define get_idreg_field_enum(kvm, id, fld)				\
	get_idreg_field_unsigned(kvm, id, fld)

#define kvm_cmp_feat_signed(kvm, id, fld, op, limit)			\
	(get_idreg_field_signed((kvm), id, fld) op __expand_field_sign_signed(id, fld, limit))

#define kvm_cmp_feat_unsigned(kvm, id, fld, op, limit)			\
	(get_idreg_field_unsigned((kvm), id, fld) op __expand_field_sign_unsigned(id, fld, limit))

#define kvm_cmp_feat(kvm, id, fld, op, limit)				\
	(id##_##fld##_SIGNED ?						\
	 kvm_cmp_feat_signed(kvm, id, fld, op, limit) :			\
	 kvm_cmp_feat_unsigned(kvm, id, fld, op, limit))

#define __kvm_has_feat(kvm, id, fld, limit)				\
	kvm_cmp_feat(kvm, id, fld, >=, limit)

#define kvm_has_feat(kvm, ...) __kvm_has_feat(kvm, __VA_ARGS__)

#define __kvm_has_feat_enum(kvm, id, fld, val)				\
	kvm_cmp_feat_unsigned(kvm, id, fld, ==, val)

#define kvm_has_feat_enum(kvm, ...) __kvm_has_feat_enum(kvm, __VA_ARGS__)

#define kvm_has_feat_range(kvm, id, fld, min, max)			\
	(kvm_cmp_feat(kvm, id, fld, >=, min) &&				\
	kvm_cmp_feat(kvm, id, fld, <=, max))

/* Check for a given level of PAuth support */
#define kvm_has_pauth(k, l)						\
	({								\
		bool pa, pi, pa3;					\
									\
		pa  = kvm_has_feat((k), ID_AA64ISAR1_EL1, APA, l);	\
		pa &= kvm_has_feat((k), ID_AA64ISAR1_EL1, GPA, IMP);	\
		pi  = kvm_has_feat((k), ID_AA64ISAR1_EL1, API, l);	\
		pi &= kvm_has_feat((k), ID_AA64ISAR1_EL1, GPI, IMP);	\
		pa3  = kvm_has_feat((k), ID_AA64ISAR2_EL1, APA3, l);	\
		pa3 &= kvm_has_feat((k), ID_AA64ISAR2_EL1, GPA3, IMP);	\
									\
		(pa + pi + pa3) == 1;					\
	})

#define kvm_has_fpmr(k)					\
	(system_supports_fpmr() &&			\
	 kvm_has_feat((k), ID_AA64PFR2_EL1, FPMR, IMP))

#define kvm_has_tcr2(k)				\
	(kvm_has_feat((k), ID_AA64MMFR3_EL1, TCRX, IMP))

#define kvm_has_s1pie(k)				\
	(kvm_has_feat((k), ID_AA64MMFR3_EL1, S1PIE, IMP))

#define kvm_has_s1poe(k)				\
	(kvm_has_feat((k), ID_AA64MMFR3_EL1, S1POE, IMP))

#define kvm_has_ras(k)					\
	(kvm_has_feat((k), ID_AA64PFR0_EL1, RAS, IMP))

#define kvm_has_sctlr2(k)				\
	(kvm_has_feat((k), ID_AA64MMFR3_EL1, SCTLRX, IMP))

#endif	/* __ARM64_KVM_CONFIG_H__ */
