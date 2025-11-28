/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2025 ARM Limited, All Rights Reserved.
 */

#include <kvm/arm_vgic.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/sizes.h>
#include <linux/slab.h>
#include <linux/xarray.h>
#include <asm/kvm_mmu.h>

#include "vgic.h"
#include "vgic-v5-tables.h"

static gicv5_vmt *vmt_info = NULL;
struct vgic_v5_host_ist_caps gicv5_host_ist_caps;
DEFINE_XARRAY(vm_info);

bool vgic_v5_vmt_allocated(void)
{
	return vmt_info != NULL;
}

struct vgic_v5_host_ist_caps *vgic_v5_host_caps(void)
{
	return &gicv5_host_ist_caps;
}

u16 vgic_v5_vm_id(struct kvm *kvm)
{
	return kvm->arch.vgic.gicv5_vm.vm_id;
}

u16 vgic_v5_vpe_id(struct kvm_vcpu *vcpu)
{
	return vcpu->vcpu_id;
}

int vgic_v5_vpe_db(struct kvm_vcpu *vcpu)
{
	return vcpu->arch.vgic_cpu.vgic_v5.gicv5_vpe.db;
}

static int vgic_v5_alloc_vmt_linear(unsigned int num_entries)
{
	unsigned int l2_entries_per_page;
	size_t alloc_size;

	vmt_info->num_entries = num_entries;

	l2_entries_per_page = PAGE_SIZE / GICV5_VMTEL2E_SIZE;
	if (num_entries < l2_entries_per_page) {
		pr_warn("Too few entries for VMT - bumping to %u\n",
			l2_entries_per_page);
		num_entries = l2_entries_per_page;
	}

	alloc_size = num_entries * sizeof(struct vmtl2_entry);

	vmt_info->linear.vmt_base = kzalloc(alloc_size, GFP_KERNEL);
	if (vmt_info->linear.vmt_base == NULL) {
		kvm_err("Failed to allocate memory for VMT\n");
		return -ENOMEM;
	}

	if (gicv5_host_ist_caps.irs_non_coherent) {
		dcache_clean_inval_poc((unsigned long)vmt_info->linear.vmt_base,
				       (unsigned long)vmt_info->linear.vmt_base + alloc_size);
	} else {
		dsb(ishst);
	}

	return 0;
}

static int vgic_v5_alloc_vmt_two_level(unsigned int num_entries)
{
	size_t alloc_size;

	vmt_info->num_entries = num_entries;

	if (num_entries < GICV5_VMT_L2_TABLE_ENTRIES) {
		pr_warn("Too few entries for two-level VMT - bumping to %llu\n",
			GICV5_VMT_L2_TABLE_ENTRIES);
		num_entries = GICV5_VMT_L2_TABLE_ENTRIES;
	}

	/*
	 * Let's make sure that we always allocate a whole power of 2
	 * of entries. Note that we need to subtract 1 from the fls()
	 * result in order to give the correct number of bits as we
	 * are operating on a whole power of 2.
	 */
	num_entries = roundup_pow_of_two(num_entries);

	vmt_info->l2.num_l1_ents = (num_entries / GICV5_VMT_L2_TABLE_ENTRIES);
	alloc_size = vmt_info->l2.num_l1_ents * sizeof(vmtl1_entry);

	vmt_info->l2.vmt_base = kzalloc(alloc_size, GFP_KERNEL);
	if (vmt_info->l2.vmt_base == NULL) {
		kvm_err("Failed to allocate memory for VMT\n");
		return -ENOMEM;
	}

	if (gicv5_host_ist_caps.irs_non_coherent) {
		dcache_clean_inval_poc((unsigned long)vmt_info->linear.vmt_base,
				       (unsigned long)vmt_info->linear.vmt_base + alloc_size);
	} else {
		dsb(ishst);
	}

	vmt_info->l2.l2ptrs = kzalloc(sizeof(*vmt_info->l2.l2ptrs) *
				vmt_info->l2.num_l1_ents, GFP_KERNEL);
	if (vmt_info->l2.l2ptrs == NULL) {
		kvm_err("Failed to allocate memory for L2 tracking\n");
		kfree(vmt_info->l2.vmt_base);
		return -ENOMEM;
	}

	return 0;
}

static int vgic_v5_alloc_l2_vmt(struct kvm *kvm)
{
	unsigned int l1_index;
	struct vmtl2_entry * l2_table;
	vmtl1_entry tmp;
	u16 vm_id = vgic_v5_vm_id(kvm);
	struct kvm_vcpu *vcpu0 = kvm_get_vcpu(kvm, 0);
	struct gicv5_cmd_info cmd_info;

	if (!vgic_v5_vmt_allocated()) {
		kvm_err("The VMT has not been allocated. Bailing.\n");
		return -EBUSY;
	}

	if (!vmt_info->two_level) {
		/*
		 * We call this eagerly, so just return silently if we
		 * don't have two-level tables. Linear tables are
		 * fully pre-allocated.
		 */
		return 0;
	}

	if (vm_id > vmt_info->num_entries)
		return -EINVAL;

	/*
	 * We have 4k-sized L2 tables - this is mandated by the spec
	 * for two-level VMTs. This means that we have 128 entries per
	 * L1 VMTE.
	 */
	l1_index = vm_id / GICV5_VMT_L2_TABLE_ENTRIES;

	if (l1_index > vmt_info->l2.num_l1_ents)
		return -EINVAL;

	/* Already valid? Great! */
	if (!!FIELD_GET(GICV5_VMTEL1E_VALID, vmt_info->l2.vmt_base[l1_index]))
		return 0;

	l2_table = kzalloc(GICV5_VMT_L2_TABLE_SIZE, GFP_KERNEL);
	if (l2_table == NULL)
		return -ENOMEM;

	vmt_info->l2.l2ptrs[l1_index] = l2_table;

	if (virt_to_phys(l2_table) & ~GICV5_VMTEL1E_L2_ADDR)
		return -EINVAL;

	tmp = virt_to_phys(l2_table) & GICV5_VMTEL1E_L2_ADDR;
	WRITE_ONCE(vmt_info->l2.vmt_base[l1_index], cpu_to_le64(tmp));

	if (gicv5_host_ist_caps.irs_non_coherent) {
		dcache_clean_inval_poc((unsigned long)l2_table,
				       (unsigned long)l2_table + GICV5_VMT_L2_TABLE_SIZE);
		dcache_clean_poc((unsigned long)(&vmt_info->l2.vmt_base[l1_index]),
				 (unsigned long)(&vmt_info->l2.vmt_base[l1_index]) + sizeof(__le64));
	} else {
		dsb(ishst);
	}

	/* Finally, vmap in the L2 VMT */
	cmd_info.cmd_type = VMT_L2_MAP;
	return irq_set_vcpu_affinity(vgic_v5_vpe_db(vcpu0), &cmd_info);
}

/*
 * Allocate the top-level VMT.
 */
int vgic_v5_vmt_allocate(bool two_level, unsigned int num_entries, size_t vmd_size,
			size_t vped_size, unsigned int max_vpes)
{
	int ret = 0;

	if (vgic_v5_vmt_allocated()) {
		kvm_err("The VMT has already been allocated. Bailing.\n");
		return -EBUSY;
	}

	/* VMD is optional; use 0 to signal that it not needed. */
	if (vmd_size != 0 &&
		(vmd_size < VMD_MIN_SIZE || vmd_size > VMD_MAX_SIZE)) {
		kvm_err("Incorrect VMD size of %lu requested.\n", vmd_size);
		return -EINVAL;
	}

	/* The minimum size for the VPED is 8, and the maximum is 4096. */
	if (vped_size < VPED_MIN_SIZE || vped_size > VPED_MAX_SIZE) {
		kvm_err("Incorrect VPED size of %lu requested.\n", vped_size);
		return -EINVAL;
	}

	/* Allocate the tracking structure */
	vmt_info = kzalloc(sizeof(*vmt_info), GFP_KERNEL);
	if (vmt_info == NULL) {
		kvm_err("Failed to allocate memory for vmt_info\n");
		return -ENOMEM;
	}

	ida_init(&vmt_info->vm_id_ida);
	vmt_info->max_vpes = max_vpes;
	vmt_info->vmd_size = vmd_size;
	vmt_info->vped_size = vped_size;
	vmt_info->two_level = two_level;

	if (!two_level)	{
		ret = vgic_v5_alloc_vmt_linear(num_entries);
		if (ret)
			goto fail_free_info;
	} else {
		ret = vgic_v5_alloc_vmt_two_level(num_entries);
		if (ret)
			goto fail_free_info;
	}

	return 0;

fail_free_info:
	kfree(vmt_info);
	return ret;
}

int vgic_v5_vmt_free(void)
{
	if (!vgic_v5_vmt_allocated())
		return -EINVAL;

	if (!vmt_info->two_level) {
		kfree(vmt_info->linear.vmt_base);
	} else {
		/*
		 * Free the VALID L2 tables, ignore the rest.
		 */
		for(int i = 0; i < vmt_info->l2.num_l1_ents; ++i)
		{
			if(!!FIELD_GET(GICV5_VMTEL1E_VALID, vmt_info->l2.vmt_base[i]))
				kfree(vmt_info->l2.l2ptrs[i]);
		}
		kfree(vmt_info->l2.l2ptrs);
		kfree(vmt_info->l2.vmt_base);
	}

	ida_destroy(&vmt_info->vm_id_ida);
	kfree(vmt_info);

	return 0;
}

static inline int vgic_v5_check_vm_id(u16 vm_id)
{
	if (!vgic_v5_vmt_allocated()) {
		kvm_err("VMT is not allocated; cannot populate\n");
		return -EINVAL;
	}

	if (vmt_info->num_entries < vm_id) {
		kvm_err("VMT index %u out of range\n", vm_id);
		return -EINVAL;
	}

	return 0;
}

static int vgic_v5_get_l2_vmte(u16 vm_id, struct vmtl2_entry **vmte)
{
	unsigned int l1_index, l2_index;
	struct vmtl2_entry *l2_table;
	int ret;

	ret = vgic_v5_check_vm_id(vm_id);
	if (ret)
		return ret;

	if (!vmt_info->two_level) {
		/* All entries always valid for Linear table */
		*vmte = &vmt_info->linear.vmt_base[vm_id];
	} else {
		l1_index = vm_id / GICV5_VMT_L2_TABLE_ENTRIES;
		l2_index = vm_id % GICV5_VMT_L2_TABLE_ENTRIES;

		if (l1_index > vmt_info->l2.num_l1_ents)
			return -E2BIG;

		if (!FIELD_GET(GICV5_VMTEL1E_VALID, vmt_info->l2.vmt_base[l1_index]))
			return -EINVAL;

		l2_table = vmt_info->l2.l2ptrs[l1_index];
		*vmte = &l2_table[l2_index];
	}

	return 0;
}

static int vgic_v5_reset_vmte(u16 vm_id)
{
	int ret;
	struct vmtl2_entry *vmte;

	ret = vgic_v5_check_vm_id(vm_id);
	if (ret)
		return ret;

	ret = vgic_v5_get_l2_vmte(vm_id, &vmte);
	if (ret)
		return ret;

	WRITE_ONCE(vmte->val[0], cpu_to_le64(0ULL));
	WRITE_ONCE(vmte->val[1], cpu_to_le64(0ULL));
	WRITE_ONCE(vmte->val[2], cpu_to_le64(0ULL));
	WRITE_ONCE(vmte->val[3], cpu_to_le64(0ULL));

	if (gicv5_host_ist_caps.irs_non_coherent) {
		dcache_clean_poc((unsigned long)vmte,
				 (unsigned long)vmte + sizeof(*vmte));
	} else {
		dsb(ishst);
	}

	return 0;
}

int vgic_v5_allocate_vm_id(struct kvm *kvm)
{
	int id = ida_alloc_max(&vmt_info->vm_id_ida, vmt_info->num_entries - 1u,
			       GFP_KERNEL);
	if (id < 0)
		return id;

	kvm->arch.vgic.gicv5_vm.vm_id = id;

	return 0;
}

/*
 * Initialise an entry in the VMT based on the index of the VM. We
 * make the assumption that our VM ID is zero based, and that we can
 * use it to index into the VMT. We check that the index is in the
 * allowed range, just in case.
 *
 * We allocate:
 *     * The VM Descriptor
 *     * The VPE Table
 *
 * We set:
 *     * The VPE ID Bits
 *
 * Note: We don't mark the VMTE as valid as this needs to be done by
 * the hardware..
 */
int vgic_v5_vmte_init(struct kvm *kvm)
{
	struct vmtl2_entry *vmte;
	gicv5_vm_info *vmi;
	void *vmd = NULL, *vpet = NULL;
	void **vped_ptrs = NULL;
	size_t vpet_alloc_size;
	int ret;
	u64 tmp;
	u16 vm_id = vgic_v5_vm_id(kvm);

	if (!vgic_v5_vmt_allocated()) {
		kvm_err("VMT is not allocated; cannot populate\n");
		ret = -EINVAL;
		goto out_fail;
	}

	if (vm_id < 0) {
		kvm_err("Failed to find free vm_id\n");
		return vm_id;
	}

	if (vgic_v5_alloc_l2_vmt(kvm)) {
		kvm_err("Failed to make the L2 VMTE valid!\n");
		return -EIO;
	}

	ret = vgic_v5_get_l2_vmte(vm_id, &vmte);
	if (ret) {
		kvm_err("Failed to look up VMTE\n");
		return ret;
	}

	if (FIELD_GET(GICV5_VMTEL2E_VALID, vmte->val[0])) {
		kvm_err("Attempt to initialize a valid VMTE (0x%x)!\n", vm_id);
		return -EINVAL;
	}

	ret = vgic_v5_reset_vmte(vm_id);
	if (ret) {
		kvm_err("Failed to reset VMTE\n");
		return ret;
	}

	vmi = kzalloc(sizeof(gicv5_vm_info), GFP_KERNEL);
	if (vmi == NULL) {
		ret = -ENOMEM;
		goto out_fail;
	}

	/* Allocate and assign the VM Descriptor, if requested. */
	if (vmt_info->vmd_size != 0) {
		vmd = kzalloc(vmt_info->vmd_size, GFP_KERNEL);
		if (vmd == NULL) {
			kvm_err("Failed to allocate memory for VM Descriptor\n");
			ret = -ENOMEM;
			goto out_fail;
		}

		if (!IS_ALIGNED((u64)vmd, vmt_info->vmd_size)) {
			kvm_err("VMD is incorrectly aligned\n");
			ret = -EFAULT;
			goto out_fail;
		}

		/* Stash the VA so we can free it later */
		vmi->vmd_base = vmd;

		tmp = FIELD_PREP(GICV5_VMTEL2E_VMD_ADDR,
				virt_to_phys(vmd) >>
				GICV5_VMTEL2E_VMD_ADDR_SHIFT);
		WRITE_ONCE(vmte->val[0], cpu_to_le64(tmp));
	}

	/*
	 * Allocate and assign the VPE Table.
	 */
	vpet_alloc_size = sizeof(vpe_entry) * vmt_info->max_vpes;
	vpet = kzalloc(vpet_alloc_size, GFP_KERNEL);
	if (vpet == NULL) {
		kvm_err("Failed to allocate memory for VPE Table\n");
		ret = -ENOMEM;
		goto out_fail;
	}

	if (!IS_ALIGNED((u64)vpet, vpet_alloc_size)) {
		kvm_err("VPET is incorrectly aligned\n");
		ret = -EFAULT;
		goto out_fail;
	}

	/* Stash the VA so we can free it later */
	vmi->vpet_base = vpet;

	tmp = FIELD_PREP(GICV5_VMTEL2E_VPET_ADDR,
			virt_to_phys(vpet) >> GICV5_VMTEL2E_VPET_ADDR_SHIFT);
	tmp |= FIELD_PREP(GICV5_VMTEL2E_VPE_ID_BITS, fls(vmt_info->max_vpes) - 1);
	WRITE_ONCE(vmte->val[1], cpu_to_le64(tmp));

	vped_ptrs = kzalloc(vmt_info->max_vpes * sizeof(vped_ptrs), GFP_KERNEL);
	if (vped_ptrs == NULL) {
		kvm_err("Failed to allocate memory for VPED tracking\n");
		ret = -ENOMEM;
		goto out_fail;
	}
	vmi->vped_ptrs = vped_ptrs;

	if (gicv5_host_ist_caps.irs_non_coherent) {
		if (vmd)
			dcache_clean_inval_poc((unsigned long)vmd,
					       (unsigned long)vmd + vmt_info->vmd_size);
		if (vpet)
			dcache_clean_inval_poc((unsigned long)vpet,
					       (unsigned long)vpet + vpet_alloc_size);
		dcache_clean_poc((unsigned long)vmte,
				 (unsigned long)vmte + sizeof(*vmte));
	} else {
		dsb(ishst);
	}

	ret = xa_insert(&vm_info, vm_id, vmi, GFP_KERNEL);
	if (ret)
		goto out_fail;

	return 0;

out_fail:
	if (vmd)
		kfree(vmd);
	if (vpet)
		kfree(vpet);
	if (vped_ptrs)
		kfree(vped_ptrs);
	if (vmi)
		kfree(vmi);

	vgic_v5_reset_vmte(vm_id);

	return ret;
}

static int vgic_v5_allocate_linear_ist(struct kvm *kvm, bool spi_ist,
				       unsigned int id_bits,
				       unsigned int istsz);
static int vgic_v5_allocate_l1_ist(struct kvm *kvm, unsigned int id_bits,
				   unsigned int istsz, unsigned int l2_split);
static int vgic_v5_allocate_l2_ists(struct kvm *kvm, unsigned int id_bits,
				    unsigned int istsz, unsigned int l2_split);
static int vgic_v5_allocate_two_level_ist(struct kvm *kvm, unsigned int id_bits,
					  unsigned int istsz,
					  unsigned int l2_split);
static int vgic_v5_linear_ist_free(struct kvm *kvm, bool spi);
static int vgic_v5_two_level_ist_free(struct kvm *kvm, bool spi);
static int vgic_v5_spi_ist_free(struct kvm *kvm);

int vgic_v5_vmte_release(struct kvm *kvm)
{
	u16 vm_id = vgic_v5_vm_id(kvm);
	struct vmtl2_entry *vmte;
	gicv5_vm_info *vmi;
	int ret;

	ret = vgic_v5_check_vm_id(vm_id);
	if (ret)
		return ret;

	ret = vgic_v5_get_l2_vmte(vm_id, &vmte);
	if (ret)
		return ret;

	if (FIELD_GET(GICV5_VMTEL2E_VALID, vmte->val[0])) {
		kvm_err("Attempt to release a valid VMTE (0x%u)!\n", vm_id);
		return -EINVAL;
	}

	vmi = xa_load(&vm_info, vm_id);
	if (WARN_ON_ONCE(!vmi))
		goto no_vmi;

	if (vmi->vmd_base) {
		kfree(vmi->vmd_base);
		vmi->vmd_base = NULL;
	}

	if (vmi->vpet_base) {
		kfree(vmi->vpet_base);
		vmi->vpet_base = NULL;
	}

	/* If we have an LPI IST, free it */
	if (FIELD_GET(GICV5_VMTEL2E_IST_VALID, vmte->val[2])) {
		if (ret) {
			kvm_err("Failed to make the LPI IST for VM %u invalid\n",
				vm_id);
			return ret;
		}

		ret = vgic_v5_lpi_ist_free(kvm);
		if (ret)
			return ret;
	}

	/* If we have an SPI IST, free it */
	if (FIELD_GET(GICV5_VMTEL2E_IST_VALID, vmte->val[3])) {
		if (ret) {
			kvm_err("Failed to make the SPI IST for VM %u invalid\n",
				vm_id);
			return ret;
		}

		ret = vgic_v5_spi_ist_free(kvm);
		if (ret)
			return ret;
	}

	vmi = xa_erase(&vm_info, vm_id);

no_vmi:
	ret = vgic_v5_reset_vmte(vm_id);
	if (ret)
		return ret;

	/*
	 * Finally, release the vm_id in the ida.
	 */
	ida_free(&vmt_info->vm_id_ida, vm_id);

	return 0;
}

int vgic_v5_vmte_alloc_vpe(struct kvm_vcpu *vcpu)
{
	u16 vm_id = vgic_v5_vm_id(vcpu->kvm);
	u16 vpe_id = vgic_v5_vpe_id(vcpu);
	vpe_entry *vpet_base;
	vpe_entry tmp;
	gicv5_vm_info *vmi;
	void *vped;
	int ret;

	ret = vgic_v5_check_vm_id(vm_id);
	if (ret)
		return ret;

	if (vpe_id >= vmt_info->max_vpes) {
		kvm_err("VPE ID is outside of VPET range\n");
		return -E2BIG;
	}

	vmi = xa_load(&vm_info, vm_id);
	if (WARN_ON_ONCE(!vmi))
		return -EINVAL;

	vpet_base = vmi->vpet_base;

	/* If the VPETE for this CPU is already valid we've gone wrong */
	if (FIELD_GET(GICV5_VPE_VALID, vpet_base[vpe_id])) {
		kvm_err("VPE 0x%x has already been assigned\n", vpe_id);
		return -EINVAL;
	}

	/* Alloc VPE Descriptor. Only used by IRS. */
	vped = kzalloc(vmt_info->vped_size, GFP_KERNEL);
	if (vped == NULL) {
		kvm_err("Failed to allocate memory for VPE Descriptor\n");
		return -ENOMEM;
	}

	if (!IS_ALIGNED((u64)vped, vmt_info->vped_size)) {
		kvm_err("VPE Descriptor is incorrectly aligned\n");
		kfree(vped);
		return -EFAULT;
	}

	vmi->vped_ptrs[vpe_id] = vped;

	tmp = FIELD_PREP(GICV5_VPED_ADDR, virt_to_phys(vped) >> GICV5_VPED_ADDR_SHIFT);
	WRITE_ONCE(vpet_base[vpe_id], cpu_to_le64(tmp));

	if (gicv5_host_ist_caps.irs_non_coherent) {
		dcache_clean_inval_poc((unsigned long)vped,
				       (unsigned long)vped + vmt_info->vped_size);
		dcache_clean_poc((unsigned long)&vpet_base[vpe_id],
				 (unsigned long)&vpet_base[vpe_id] + sizeof(*vpet_base));
	} else {
		dsb(ishst);
	}

	return 0;
}

int vgic_v5_vmte_free_vpe(struct kvm_vcpu *vcpu)
{
	u16 vm_id = vgic_v5_vm_id(vcpu->kvm);
	u16 vpe_id = vgic_v5_vpe_id(vcpu);
	vpe_entry *vpet_base;
	void *vped;
	struct vmtl2_entry *vmte;
	gicv5_vm_info *vmi;
	int ret;

	ret = vgic_v5_check_vm_id(vm_id);
	if (ret)
		return ret;

	vmi = xa_load(&vm_info, vm_id);
	if (WARN_ON_ONCE(!vmi))
		return -EINVAL;

	ret = vgic_v5_get_l2_vmte(vm_id, &vmte);
	if (ret)
		return ret;

	if (FIELD_GET(GICV5_VMTEL2E_VALID, vmte->val[0])) {
		kvm_err("The VMTE is marked valid; cannot free a VPE\n");
		return -EPERM;
	}

	if (vpe_id >= vmt_info->max_vpes) {
		kvm_err("VPE ID is outside of VPET range\n");
		return -E2BIG;
	}

	vpet_base = vmi->vpet_base;
	WRITE_ONCE(vpet_base[vpe_id], cpu_to_le64(0ULL));

	if (gicv5_host_ist_caps.irs_non_coherent) {
		dcache_clean_poc((unsigned long)&vpet_base[vpe_id],
				 (unsigned long)&vpet_base[vpe_id] + sizeof(*vpet_base));
	} else {
		dsb(ishst);
	}

	/* Free VPE Descriptor. Only used by IRS. */
	vped = vmi->vped_ptrs[vpe_id];
	vmi->vped_ptrs[vpe_id] = NULL;
	kfree(vped);

	return 0;
}

/*
 * Assign an already allocated IST to the VM by populating the fields
 * in the corresponding VMTE. We re-use this code for both an SPI IST
 * and LPI IST, even if the paths to reach it might be vastly
 * different.
 */
int vgic_v5_vmte_assign_ist(struct kvm *kvm, phys_addr_t ist_base,
			    bool two_level, unsigned int id_bits,
			    unsigned int l2sz, unsigned int istsz,
			    bool spi_ist)
{
	struct vmtl2_entry *vmte;
	unsigned int section;
	u64 tmp;
	int ret;
	u16 vm_id = vgic_v5_vm_id(kvm);
	struct kvm_vcpu *vcpu0 = kvm_get_vcpu(kvm, 0);
	struct gicv5_cmd_info cmd_info;

	ret = vgic_v5_check_vm_id(vm_id);
	if (ret)
		return ret;

	if (ist_base & ~GICV5_VMTEL2E_IST_ADDR) {
		kvm_err("IST alignment issue! Address: 0x%llx, Mask 0x%llx\n",
			ist_base, GICV5_VMTEL2E_IST_ADDR);
		return -EINVAL;
	}

	/*
	 * In order to allow this code to be reused, we use section to pick
	 * either the fields for the LPI IST or the SPI IST
	 */
	if (spi_ist)
		section = GICV5_VMTEL2_SPI_SECTION;
	else
		section = GICV5_VMTEL2_LPI_SECTION;

	ret = vgic_v5_get_l2_vmte(vm_id, &vmte);
	if (ret)
		return ret;

	/* Bail if already allocated */
	if (FIELD_GET(GICV5_VMTEL2E_IST_VALID, vmte->val[section])) {
		kvm_err("IST already assigned and marked valid\n");
		return -EINVAL;
	}

	tmp = 0ULL;

	/* L2 Size */
	tmp |= FIELD_PREP(GICV5_VMTEL2E_IST_L2SZ, l2sz);

	/* IST Addr */
	tmp |= FIELD_PREP(GICV5_VMTEL2E_IST_ADDR,
			ist_base >> GICV5_VMTEL2E_IST_ADDR_SHIFT);

	/* The ISTE size used by the IST  */
	tmp |= FIELD_PREP(GICV5_VMTEL2E_IST_ISTSZ, istsz);

	/* IST Structure - either clear or set the bit */
	if (!two_level) {
		tmp &= ~FIELD_PREP(GICV5_VMTEL2E_IST_STRUCTURE, 1);
	} else {
		tmp |= FIELD_PREP(GICV5_VMTEL2E_IST_STRUCTURE, 1);
	}

	/* ID Bits */
	tmp |= FIELD_PREP(GICV5_VMTEL2E_IST_ID_BITS, id_bits);

	WRITE_ONCE(vmte->val[section], cpu_to_le64(tmp));

	if (gicv5_host_ist_caps.irs_non_coherent) {
		dcache_clean_poc((unsigned long)vmte,
				 (unsigned long)vmte + sizeof(*vmte));
	} else {
		dsb(ishst);
	}

	/* Finally, mark the entry as valid */
	cmd_info.cmd_type = spi_ist? SPI_VIST_MAKE_VALID : LPI_VIST_MAKE_VALID;
	return irq_set_vcpu_affinity(vgic_v5_vpe_db(vcpu0), &cmd_info);
}

static int vgic_v5_allocate_linear_ist(struct kvm *kvm, bool spi_ist,
				       unsigned int id_bits, unsigned int istsz)
{
	u16 vm_id = vgic_v5_vm_id(kvm);
	__le64 *ist;
	u32 l1sz;
	const size_t n = id_bits + 1 + istsz;
	gicv5_vm_info *vmi;

	vmi = xa_load(&vm_info, vm_id);
	if (WARN_ON_ONCE(!vmi))
		return -EINVAL;

	/*
	 * Allocate the IST. We only have one level, so we just use the L2 ISTE.
	 */
	l1sz = BIT(n + 1);
	ist = kzalloc(l1sz, GFP_KERNEL);
	if (!ist)
		return -ENOMEM;

	if (gicv5_host_ist_caps.irs_non_coherent) {
		dcache_clean_inval_poc((unsigned long)ist,
				       (unsigned long)ist + l1sz);
	} else {
		dsb(ishst);
	}

	if (spi_ist) {
		vmi->h_spi_ist = ist;
	} else {
		vmi->h_lpi_ist_structure = false;
		vmi->h_lpi_ist = ist;
	}

	return 0;
}

static int vgic_v5_allocate_l1_ist(struct kvm *kvm, unsigned int id_bits,
				   unsigned int istsz, unsigned int l2sz)
{
	u16 vm_id = vgic_v5_vm_id(kvm);
	__le64 *ist;
	u32 l1sz;
	const size_t n =  max(5, id_bits - ((10 - istsz) + (2 * l2sz)) + 3 - 1);
	gicv5_vm_info *vmi;

	vmi = xa_load(&vm_info, vm_id);
	if (WARN_ON_ONCE(!vmi))
		return -EINVAL;

	l1sz = BIT(n + 1);

	ist = kzalloc(l1sz, GFP_KERNEL);
	if (!ist)
		return -ENOMEM;

	if (gicv5_host_ist_caps.irs_non_coherent) {
		dcache_clean_inval_poc((unsigned long)ist,
				       (unsigned long)ist + l1sz);
	} else {
		dsb(ishst);
	}

	vmi->h_lpi_ist_structure = true;
	vmi->h_lpi_ist = ist;

	return 0;
}

static int vgic_v5_allocate_l2_ists(struct kvm *kvm, unsigned int id_bits,
				    unsigned int istsz, unsigned int l2sz)
{
	u16 vm_id = vgic_v5_vm_id(kvm);
	u32 index;
	__le64 *l2ist;
	const size_t n =  max(5, id_bits - ((10 - istsz) + (2 * l2sz)) + 3 - 1);
	const int l1_entries = BIT(n + 1) / GICV5_IRS_ISTL1E_SIZE;
	const size_t l2size = BIT(11 + (2 * l2sz) + 1);
	__le64 *l1ist;
	gicv5_vm_info *vmi;

	vmi = xa_load(&vm_info, vm_id);
	if (WARN_ON_ONCE(!vmi))
		return -EINVAL;

	l1ist = vmi->h_lpi_ist;

	// Allocate the storage for the pointers to the L2 ISTs (for freeing later)
	vmi->h_lpi_l2_ists = kzalloc(
		l1_entries * sizeof(vmi->h_lpi_l2_ists),
		GFP_KERNEL);
	if (!vmi->h_lpi_l2_ists)
		return -ENOMEM;

	// for each L1 entry:
	for (index = 0; index < l1_entries; ++index) {
		l2ist = kzalloc(l2size, GFP_KERNEL);
		if (!l2ist)
			return -ENOMEM;

		l1ist[index] = cpu_to_le64(
			virt_to_phys(l2ist) & GICV5_ISTL1E_L2_ADDR_MASK) |
			GICV5_ISTL1E_VALID;

		if (gicv5_host_ist_caps.irs_non_coherent) {
			dcache_clean_inval_poc((unsigned long)l2ist,
					       (unsigned long)l2ist + l2size);
			dcache_clean_poc((unsigned long)(l1ist + index),
					 (unsigned long)(l1ist + index) + sizeof(*l1ist));
		} else {
			dsb(ishst);
		}

		vmi->h_lpi_l2_ists[index] = l2ist;
	}

	return 0;
}

static int vgic_v5_allocate_two_level_ist(struct kvm *kvm, unsigned int id_bits,
					  unsigned int istsz, unsigned int l2sz)
{
	int ret;

	// Allocate the L1 IST first
	ret = vgic_v5_allocate_l1_ist(kvm, id_bits, istsz, l2sz);
	if (ret)
		return ret;

	return vgic_v5_allocate_l2_ists(kvm, id_bits, istsz, l2sz);
}

/*
 * Free a Linear IST. Should only happen once the VM is dead.
 */
static int vgic_v5_linear_ist_free(struct kvm *kvm, bool spi)
{
	u16 vm_id = vgic_v5_vm_id(kvm);
	void *base_addr;
	int section;
	struct vmtl2_entry *vmte;
	gicv5_vm_info *vmi;
	int ret;

	ret = vgic_v5_check_vm_id(vm_id);
	if (ret)
		return ret;

	vmi = xa_load(&vm_info, vm_id);
	if (WARN_ON_ONCE(!vmi))
		return -EINVAL;

	if (spi) {
		section = GICV5_VMTEL2_SPI_SECTION;
		base_addr = vmi->h_spi_ist;
		vmi->h_spi_ist = NULL;
	} else {
		section = GICV5_VMTEL2_LPI_SECTION;
		base_addr = vmi->h_lpi_ist;
		vmi->h_lpi_ist = NULL;
	}

	kfree(base_addr);

	ret = vgic_v5_get_l2_vmte(vm_id, &vmte);
	if (ret)
		return ret;

	/* The VM should be dead here, so we can just zero the VMT section */
	WRITE_ONCE(vmte->val[section], cpu_to_le64(0ULL));

	if (gicv5_host_ist_caps.irs_non_coherent) {
		dcache_clean_poc((unsigned long)vmte,
				 (unsigned long)vmte + sizeof(*vmte));
	} else {
		dsb(ishst);
	}

	return 0;
}

/*
 * Free a Two-Level IST. Should only happen once the VM is dead.
 */
static int vgic_v5_two_level_ist_free(struct kvm *kvm, bool spi)
{
	u16 vm_id = vgic_v5_vm_id(kvm);
	unsigned int id_bits, istsz, l2sz;
	bool structure;
	size_t n;
	int section, l1_entries;
	__le64 *l1ist, *l2ist;
	u32 index;
	struct vmtl2_entry *vmte;
	gicv5_vm_info *vmi;
	int ret;

	ret = vgic_v5_check_vm_id(vm_id);
	if (ret)
		return ret;

	vmi = xa_load(&vm_info, vm_id);
	if (WARN_ON_ONCE(!vmi))
		return -EINVAL;

	/*
	 * We don't ever create two level SPI ISTs, so freeing is a bad idea!
	 */
	if (spi)
		return -EINVAL;

	section = GICV5_VMTEL2_LPI_SECTION;
	l1ist = vmi->h_lpi_ist;
	vmi->h_lpi_ist = NULL;

	ret = vgic_v5_get_l2_vmte(vm_id, &vmte);
	if (ret)
		return ret;

	structure = FIELD_GET(GICV5_VMTEL2E_IST_STRUCTURE, vmte->val[section]);
	if (!structure) {
		kvm_err("Expected a two-level IST; got linear\n");
		return -EINVAL;
	}

	id_bits = FIELD_GET(GICV5_VMTEL2E_IST_ID_BITS, vmte->val[section]);
	istsz = FIELD_GET(GICV5_VMTEL2E_IST_ISTSZ, vmte->val[section]);
	l2sz = FIELD_GET(GICV5_VMTEL2E_IST_L2SZ, vmte->val[section]);

	n =  max(2, id_bits - ((10 - istsz) + (2 * l2sz)) + 3 - 1);
	l1_entries = BIT(n + 1) / GICV5_IRS_ISTL1E_SIZE;

	// for each L1 entry free the L2 IST it points to
	for (index = 0; index < l1_entries; ++index) {
		l2ist = vmi->h_lpi_l2_ists[index];
		if (l2ist == NULL)
			continue;

		kfree(l2ist);
	}

	// Free the L2 pointers
	kfree(vmi->h_lpi_l2_ists);
	vmi->h_lpi_l2_ists = NULL;

	// Free the L1 IST itself
	kfree(l1ist);

	/* The VM should be dead here, so we can just zero the VMT section */
	WRITE_ONCE(vmte->val[section], cpu_to_le64(0ULL));

	if (gicv5_host_ist_caps.irs_non_coherent) {
		dcache_clean_poc((unsigned long)vmte,
				 (unsigned long)vmte + sizeof(*vmte));
	} else {
		dsb(ishst);
	}

	return 0;
}

/*
 * Allocate an IST for SPIs.
 *
 * We don't anticipate a large number of SPIs being allocated. Therefore, we
 * always allocate a Linear IST for SPIs. This will need to be revisited should
 * that assumption no longer hold.
 */
int vgic_v5_spi_ist_allocate(struct kvm *kvm, phys_addr_t *base_addr,
			     unsigned int id_bits, unsigned int istsz)
{
	u16 vm_id = vgic_v5_vm_id(kvm);
	int ret;
	gicv5_vm_info *vmi;

	ret = vgic_v5_check_vm_id(vm_id);
	if (ret)
		return ret;

	vmi = xa_load(&vm_info, vm_id);
	if (WARN_ON_ONCE(!vmi))
		return -EINVAL;

	ret = vgic_v5_allocate_linear_ist(kvm, true, id_bits, istsz);
	if (ret)
		return ret;

	*base_addr = virt_to_phys(vmi->h_spi_ist);
	return 0;
}

/*
 * Free the IST for SPIs. Should only happen once the VM is dead.
 */
static int vgic_v5_spi_ist_free(struct kvm *kvm)
{
	return vgic_v5_linear_ist_free(kvm, true);
}

static unsigned vgic_v5_ist_l2sz(void)
{
	switch (PAGE_SIZE) {
	case SZ_64K:
		if (gicv5_host_ist_caps.ist_l2sz & 0x4)
			return GICV5_IRS_IST_CFGR_L2SZ_64K;
		fallthrough;
	case SZ_4K:
		if (gicv5_host_ist_caps.ist_l2sz & 0x1)
			return GICV5_IRS_IST_CFGR_L2SZ_4K;
		fallthrough;
	case SZ_16K:
		if (gicv5_host_ist_caps.ist_l2sz & 0x2)
			return GICV5_IRS_IST_CFGR_L2SZ_16K;
		break;
	}

	if (gicv5_host_ist_caps.ist_l2sz & 0x1)
		return GICV5_IRS_IST_CFGR_L2SZ_4K;

	return GICV5_IRS_IST_CFGR_L2SZ_64K;
}

static unsigned vgic_v5_ist_istsz(unsigned id_bits)
{
	if (!gicv5_host_ist_caps.istmd)
		return GICV5_IRS_IST_CFGR_ISTSZ_4;

	if (id_bits >= gicv5_host_ist_caps.istmd_sz)
		return GICV5_IRS_IST_CFGR_ISTSZ_16;

	return GICV5_IRS_IST_CFGR_ISTSZ_8;
}

int vgic_v5_lpi_ist_alloc(struct kvm *kvm, gpa_t guest_ist_base, unsigned id_bits)
{
	u16 vm_id = vgic_v5_vm_id(kvm);
	int ret;
	phys_addr_t host_phys_addr;
	bool host_two_level;
	unsigned host_istsz, host_l2sz;
	gicv5_vm_info *vmi;

	ret = vgic_v5_check_vm_id(vm_id);
	if (ret)
		return ret;

	vmi = xa_load(&vm_info, vm_id);
	if (WARN_ON_ONCE(!vmi))
		return -EINVAL;

	host_istsz = vgic_v5_ist_istsz(id_bits);
	/* Go for two level if we need more than one page for the IST */
	host_two_level = gicv5_host_ist_caps.ist_levels && id_bits > PAGE_SIZE / host_istsz;
	host_l2sz = vgic_v5_ist_l2sz();

	if (!host_two_level)
		ret = vgic_v5_allocate_linear_ist(kvm, false, id_bits, host_istsz);
	else
		ret = vgic_v5_allocate_two_level_ist(kvm, id_bits, host_istsz, host_l2sz);
	if (ret) {
		kvm_err("Failed to allocate LPI IST\n");
		return ret;
	}

	host_phys_addr = virt_to_phys(vmi->h_lpi_ist);

	return vgic_v5_vmte_assign_ist(kvm, host_phys_addr, host_two_level,
				       id_bits, 0, 0, false);
}

/*
 * Free the shim layer that we have allocated over the guest's IST if it has
 * been allocated. Else, do nothing.
 */
int vgic_v5_lpi_ist_free(struct kvm *kvm)
{
	u16 vm_id = vgic_v5_vm_id(kvm);
	bool two_level;
	int ret;
	struct vmtl2_entry *vmte;

	ret = vgic_v5_check_vm_id(vm_id);
	if (ret)
		return ret;

	ret = vgic_v5_get_l2_vmte(vm_id, &vmte);
	if (ret)
		return ret;

	/* If we have nothing to clean up, return immediately. */
	if (!FIELD_GET(GICV5_VMTEL2E_IST_VALID, vmte->val[2]))
		return 0;

	two_level = FIELD_GET(GICV5_VMTEL2E_IST_STRUCTURE,
			vmte->val[2]);

	if (!two_level)
		return vgic_v5_linear_ist_free(kvm, false);
	else
		return vgic_v5_two_level_ist_free(kvm, false);

	return 0;
}

phys_addr_t vgic_v5_get_vmt_base(void)
{
	phys_addr_t vmt_base;

	if (!vgic_v5_vmt_allocated()) {
		kvm_err("VMT is not allocated\n");
		return -ENXIO;
	}

	if (!vmt_info->two_level)
		vmt_base = virt_to_phys(vmt_info->linear.vmt_base);
	else
		vmt_base = virt_to_phys(vmt_info->l2.vmt_base);

	return vmt_base;
}

unsigned int vgic_v5_get_vpe_id_bits(void)
{
	return fls(vmt_info->max_vpes) - 1;
}
