/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2025 ARM Limited, All Rights Reserved.
 */
#ifndef __KVM_ARM_VGICV5_TABLES_NEW_H__
#define __KVM_ARM_VGICV5_TABLES_NEW_H__

#include <linux/irqchip/arm-gic-v5.h>

#define VM_ID_BITS_MIN	8
#define VM_ID_BITS_MAX	16
#define VMD_MIN_SIZE	8
#define VMD_MAX_SIZE	4096
#define VPED_MIN_SIZE	8
#define VPED_MAX_SIZE 	4096
#define VPE_ID_BITS_MIN	8
#define VPE_ID_BITS_MAX	16

// Level 1 Virtual Machine Table Entry
typedef __le64 vmtl1_entry;
#define GICV5_VMTEL1E_VALID		BIT_ULL(0)
// Note that there is no shift for the address by design
#define GICV5_VMTEL1E_L2_ADDR		GENMASK(51, 12)

#define GICV5_VMTEL2E_SIZE		32ULL
// An L2 table (two-level VMT) is ALWAYS 4kB!
#define GICV5_VMT_L2_TABLE_SIZE		4096ULL
#define GICV5_VMT_L2_TABLE_ENTRIES	(GICV5_VMT_L2_TABLE_SIZE / GICV5_VMTEL2E_SIZE)

// Level 2 Virtual Machine Table Entry
struct vmtl2_entry {
	__le64 val[4];
};

/*
 * As the L2 VMTE is a large data structure, we are splitting it into 4 parts.
 * We only mask and shift WITHIN each part for simplicity.
 */
// First 64-bit chunk
#define GICV5_VMTEL2E_VALID		BIT_ULL(0)
#define GICV5_VMTEL2E_VMD_ADDR_SHIFT	3ULL
#define GICV5_VMTEL2E_VMD_ADDR		GENMASK_ULL(55, 3)
// Second 64-bit chunk
#define GICV5_VMTEL2E_VPET_ADDR_SHIFT	3ULL
#define GICV5_VMTEL2E_VPET_ADDR		GENMASK_ULL(55, 3)
#define GICV5_VMTEL2E_VPE_ID_BITS	GENMASK_ULL(63, 59)
// Third & fourth 64-bit chunks (the encodings are the same for each)
#define GICV5_VMTEL2E_IST_VALID		BIT_ULL(0)
#define GICV5_VMTEL2E_IST_L2SZ		GENMASK_ULL(2, 1)
#define GICV5_VMTEL2E_IST_ADDR_SHIFT	6ULL
#define GICV5_VMTEL2E_IST_ADDR		GENMASK_ULL(55, 6)
#define GICV5_VMTEL2E_IST_ISTSZ		GENMASK_ULL(57, 56)
#define GICV5_VMTEL2E_IST_STRUCTURE	BIT_ULL(58)
#define GICV5_VMTEL2E_IST_ID_BITS	GENMASK_ULL(63, 59)

// Virtual PE Table Entry
typedef __le64 vpe_entry;
#define GICV5_VPE_VALID			BIT_ULL(0)
// Note that there is no shift for the address by design
#define GICV5_VPED_ADDR_SHIFT		3ULL
#define GICV5_VPED_ADDR			GENMASK_ULL(55, 3)

typedef struct vm_info {
	void * __iomem vmd_base;
	vpe_entry * __iomem vpet_base;
	void ** __iomem vped_ptrs;
} gicv5_vm_info;

typedef struct vmt {
	union {
		struct {
			struct vmtl2_entry *vmt_base;
			unsigned int num_ents;
		} linear;
		struct {
			vmtl1_entry *vmt_base;
			struct vmtl2_entry **l2ptrs;
			unsigned int num_l1_ents;
		} l2;
	};
	bool two_level;
	unsigned int num_entries;
	unsigned int max_vpes;
	size_t vmd_size;
	size_t vped_size;
	struct ida vm_id_ida;
} gicv5_vmt;

struct vgic_v5_host_ist_caps {
	u8	ist_id_bits;
	u8	min_ist_id_bits;
	bool	ist_levels;
	u8	ist_l2sz;
	bool	istmd;
	u8	istmd_sz;
	bool	irs_non_coherent;
};

struct vgic_v5_host_ist_caps *vgic_v5_host_caps(void);
bool vgic_v5_vmt_allocated(void);
u16 vgic_v5_vm_id(struct kvm *kvm);
u16 vgic_v5_vpe_id(struct kvm_vcpu *vcpu);
int vgic_v5_vpe_db(struct kvm_vcpu *vcpu);
int vgic_v5_vmt_allocate(bool two_level, unsigned int num_entries,
			 size_t vmd_size, size_t vped_size,
			 unsigned int vpe_id_bits);
int vgic_v5_vmt_free(void);
int vgic_v5_allocate_vm_id(struct kvm *kvm);
int vgic_v5_vmte_init(struct kvm *kvm);
int vgic_v5_vmte_release(struct kvm *kvm);
int vgic_v5_vmte_alloc_vpe(struct kvm_vcpu *vcpu);
int vgic_v5_vmte_free_vpe(struct kvm_vcpu *vcpu);
phys_addr_t vgic_v5_get_vmt_base(void);
unsigned int vgic_v5_get_vpe_id_bits(void);

#endif
