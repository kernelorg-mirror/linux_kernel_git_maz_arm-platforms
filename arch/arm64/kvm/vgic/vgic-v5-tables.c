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
