/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2025 ARM Limited, All Rights Reserved.
 */
#ifndef __KVM_ARM_VGICV5_TABLES_NEW_H__
#define __KVM_ARM_VGICV5_TABLES_NEW_H__

#include <linux/irqchip/arm-gic-v5.h>
#include <linux/list.h>

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

#define GICV5_VMTEL2_LPI_SECTION	2
#define GICV5_VMTEL2_SPI_SECTION	3

// Virtual PE Table Entry
typedef __le64 vpe_entry;
#define GICV5_VPE_VALID			BIT_ULL(0)
// Note that there is no shift for the address by design
#define GICV5_VPED_ADDR_SHIFT		3ULL
#define GICV5_VPED_ADDR			GENMASK_ULL(55, 3)

// L2 IST Entry
#define GICV5_ISTL2E_PENDING	BIT(0)
#define GICV5_ISTL2E_ACTIVE	BIT(1)
#define GICV5_ISTL2E_HM		BIT(2)
#define GICV5_ISTL2E_ENABLE	BIT(3)
#define GICV5_ISTL2E_IRM	BIT(4)
#define GICV5_ISTL2E_HWU	GENMASK(10, 9)
#define GICV5_ISTL2E_PRIORITY	GENMASK(15, 11)
#define GICV5_ISTL2E_IAFFID	GENMASK(31, 16)

/*
 * Save Restore Header Format
 *
 * Track what has been saved into the guest's IST. Specifically, we track if the
 * SPI and LPI ISTs have been stored, and the number of ID bits for each. This
 * can be used to figure out where these start and end in the guest's memory.
 */
#define GICV5_SAVE_TABLES_IRS_IST_HEADER_SPI_IST	BIT(0)
#define GICV5_SAVE_TABLES_IRS_IST_HEADER_SPI_ID_BITS	GENMASK(5, 1)
#define GICV5_SAVE_TABLES_IRS_IST_HEADER_LPI_IST	BIT(6)
#define GICV5_SAVE_TABLES_IRS_IST_HEADER_LPI_ID_BITS	GENMASK(11, 7)

struct pending_irq {
	u32 irq;
	struct list_head next;
};

typedef struct vm_info {
	void * __iomem vmd_base;
	vpe_entry * __iomem vpet_base;
	void ** __iomem vped_ptrs;

	/* Tracking for the hyp-owned ISTs */
	bool h_lpi_ist_structure;
	__le64 *h_lpi_ist;
	__le64 **h_lpi_l2_ists;
	__le64 *h_spi_ist;

	/* Tracking of pending interrupts as part of IST restore */
	struct list_head pending_irqs;
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
void vgic_v5_release_vm_id(struct kvm *kvm);
int vgic_v5_vmte_init(struct kvm *kvm);
int vgic_v5_vmte_release(struct kvm *kvm);
int vgic_v5_vmte_alloc_vpe(struct kvm_vcpu *vcpu);
int vgic_v5_vmte_free_vpe(struct kvm_vcpu *vcpu);
int vgic_v5_vmte_assign_ist(struct kvm *kvm, phys_addr_t ist_base,
			    bool two_level, unsigned int id_bits,
			    unsigned int l2sz, unsigned int istsz, bool spi_ist);
int vgic_v5_spi_ist_allocate(struct kvm *kvm, phys_addr_t *base_addr,
			     unsigned int id_bits, unsigned int istsz);
int vgic_v5_lpi_ist_alloc(struct kvm *kvm, gpa_t guest_ist_base, unsigned id_bits);
int vgic_v5_lpi_ist_free(struct kvm *kvm);
int vgic_v5_save_spi_ist(struct kvm *kvm, struct kvm_device_attr *attr);
int vgic_v5_save_lpi_ist(struct kvm *kvm);
int vgic_v5_restore_spi_ist(struct kvm *kvm, struct kvm_device_attr *attr);
int vgic_v5_restore_lpi_ist(struct kvm *kvm);
int vgic_v5_restore_pending_irqs(struct kvm *kvm);
phys_addr_t vgic_v5_get_vmt_base(void);
unsigned int vgic_v5_get_vpe_id_bits(void);

#endif
