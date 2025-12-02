// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2025 Arm Ltd.
 */

#include <kvm/arm_vgic.h>
#include <linux/irqchip/arm-vgic-info.h>
#include <linux/irqdomain.h>

#include "vgic.h"
#include "vgic-v5-tables.h"

static struct vgic_v5_ppi_caps *ppi_caps;
static void __iomem *irs_base;

/*
 * Probe for a vGICv5 compatible interrupt controller, returning 0 on success.
 */
int vgic_v5_probe(const struct gic_kvm_info *info)
{
	u64 ich_vtr_el2;
	int ret;

	kvm_vgic_global_state.type = VGIC_V5;

	kvm_vgic_global_state.vcpu_base = 0;
	kvm_vgic_global_state.vctrl_base = NULL;
	kvm_vgic_global_state.can_emulate_gicv2 = false;
	kvm_vgic_global_state.has_gicv4 = false;
	kvm_vgic_global_state.has_gicv4_1 = false;

	/*
	 * GICv5 is currently not supported in Protected mode. Skip the
	 * registration of GICv5 completely to make sure no guests can create a
	 * GICv5-based guest.
	 */
	if (is_protected_kvm_enabled()) {
		kvm_info("GICv5-based guests are not supported with pKVM\n");
		goto skip_v5;
	}

	kvm_vgic_global_state.max_gic_vcpus = VGIC_V5_MAX_CPUS;

	ret = kvm_register_vgic_device(KVM_DEV_TYPE_ARM_VGIC_V5);
	if (ret) {
		kvm_err("Cannot register GICv5 KVM device.\n");
		goto skip_v5;
	}

	kvm_info("GCIE system register CPU interface\n");

skip_v5:
	/* If we don't support the GICv3 compat mode we're done. */
	if (!cpus_have_final_cap(ARM64_HAS_GICV5_LEGACY))
		return 0;

	kvm_vgic_global_state.has_gcie_v3_compat = true;
	ich_vtr_el2 =  kvm_call_hyp_ret(__vgic_v3_get_gic_config);
	kvm_vgic_global_state.ich_vtr_el2 = (u32)ich_vtr_el2;

	/*
	 * The ListRegs field is 5 bits, but there is an architectural
	 * maximum of 16 list registers. Just ignore bit 4...
	 */
	kvm_vgic_global_state.nr_lr = (ich_vtr_el2 & 0xf) + 1;

	ret = kvm_register_vgic_device(KVM_DEV_TYPE_ARM_VGIC_V3);
	if (ret) {
		kvm_err("Cannot register GICv3-legacy KVM device.\n");
		return ret;
	}

	/* We potentially limit the max VCPUs further than we need to here */
	kvm_vgic_global_state.max_gic_vcpus = min(VGIC_V3_MAX_CPUS,
						  VGIC_V5_MAX_CPUS);

	static_branch_enable(&kvm_vgic_global_state.gicv3_cpuif);
	kvm_info("GCIE legacy system register CPU interface\n");

	return 0;
}

static irqreturn_t db_handler(int irq, void *data)
{
	struct kvm_vcpu *vcpu = data;

	WRITE_ONCE(vcpu->arch.vgic_cpu.vgic_v5.gicv5_vpe.db_fired, true);

	kvm_make_request(KVM_REQ_IRQ_PENDING, vcpu);
	kvm_vcpu_kick(vcpu);

	return IRQ_HANDLED;
}

static int vgic_v5_send_command(struct kvm_vcpu *vcpu,
			 enum gicv5_vcpu_info_cmd_type type)
{
	struct gicv5_cmd_info cmd_info;
	cmd_info.cmd_type = type;

	if (!vcpu)
		return -EINVAL;

	return irq_set_vcpu_affinity(vgic_v5_vpe_db(vcpu), &cmd_info);
}

/*
 * The IRS MMIO interface is shared between all VMs, so make sure we don't do
 * anything stupid!
 */
static DEFINE_RAW_SPINLOCK(vm_config_lock);

static u32 irs_readl_relaxed(const u32 reg_offset)
{
	return readl_relaxed(irs_base + reg_offset);
}

static void irs_writel_relaxed(const u32 val, const u32 reg_offset)
{
	writel_relaxed(val, irs_base + reg_offset);
}

static u64 irs_readq_relaxed(const u32 reg_offset)
{
	return readq_relaxed(irs_base + reg_offset);
}

static void irs_writeq_relaxed(const u64 val, const u32 reg_offset)
{
	writeq_relaxed(val, irs_base + reg_offset);
}

/*
 * Wait for completion of a change in any of IRS_VMT_BASER, IRS_VMAP_L2_VMTR,
 * IRS_VMAP_VMR, IRS_VMAP_VPER, IRS_VMAP_VISTR, IRS_VMAP_L2_VISTR.
 */
static int vgic_v5_irs_wait_for_vm_op(void)
{
	int ret;
	u32 statusr;

	ret = readl_relaxed_poll_timeout_atomic(
		irs_base + GICV5_IRS_VMT_STATUSR, statusr,
		FIELD_GET(GICV5_IRS_VMT_STATUSR_IDLE, statusr), 1,
		USEC_PER_SEC);

	if (ret == -ETIMEDOUT) {
		pr_err_ratelimited("Time out waiting for IRS VM Op\n");
		return ret;
	}

	return 0;
}

/* Wait for completion of an VPE_STATUSR change */
static int vgic_v5_irs_wait_for_vpe_op(void)
{
	int ret;
	u32 statusr;

	ret = readl_relaxed_poll_timeout_atomic(
		irs_base + GICV5_IRS_VPE_STATUSR, statusr,
		FIELD_GET(GICV5_IRS_VPE_STATUSR_IDLE, statusr), 1,
		USEC_PER_SEC);

	if (ret == -ETIMEDOUT) {
		pr_err_ratelimited("Time out waiting for IRS VPE Op\n");
		return ret;
	}

	return 0;
}

static int vgic_v5_irs_assign_vmt(bool two_level, u8 vm_id_bits, phys_addr_t vmt_base)
{
	int rc;
	u64 vmt_baser;
	u32 vmt_cfgr;

	vmt_baser = irs_readq_relaxed(GICV5_IRS_VMT_BASER);
	if (!!FIELD_GET(GICV5_IRS_VMT_BASER_VALID, vmt_baser)) {
		pr_err("VMT is already valid; can't assign a new VMT!\n");
		return -EBUSY;
	}

	vmt_cfgr = FIELD_PREP(GICV5_IRS_VMT_CFGR_VM_ID_BITS, vm_id_bits);
	if (!two_level)
		vmt_cfgr |= FIELD_PREP(GICV5_IRS_VMT_CFGR_STRUCTURE,
				       GICV5_IRS_VMT_CFGR_STRUCTURE_LINEAR);
	else
		vmt_cfgr |= FIELD_PREP(GICV5_IRS_VMT_CFGR_STRUCTURE,
				       GICV5_IRS_VMT_CFGR_STRUCTURE_TWO_LEVEL);

	irs_writel_relaxed(vmt_cfgr, GICV5_IRS_VMT_CFGR);

	vmt_baser = FIELD_PREP(GICV5_IRS_VMT_BASER_VALID, true) |
		    FIELD_PREP(GICV5_IRS_VMT_BASER_ADDR,
			       vmt_base >> GICV5_IRS_VMT_BASER_ADDR_SHIFT);
	irs_writeq_relaxed(vmt_baser, GICV5_IRS_VMT_BASER);

	rc = vgic_v5_irs_wait_for_vm_op();
	if (rc)
		pr_err("Failed to initialise VMT\n");
	else
		pr_debug("GICv5-IRS: initialised VMT correctly\n");

	return rc;
}

static int vgic_v5_irs_vmap_l2_vmt(int vm_id)
{
	u64 vmap_l2_vmtr;
	int rc = 0;

	raw_spin_lock(&vm_config_lock);

	/* Make sure that we are idle to begin with */
	rc = vgic_v5_irs_wait_for_vm_op();
	if (rc) {
		pr_err("GICv5 IRS_VMT_STATUSR stable state not reached\n");
		goto out_fail;
	}

	/* Mark the VM as valid */
	vmap_l2_vmtr = FIELD_PREP(GICV5_IRS_VMAP_L2_VMTR_VM_ID, vm_id) |
		   FIELD_PREP(GICV5_IRS_VMAP_L2_VMTR_M, true);
	irs_writeq_relaxed(vmap_l2_vmtr, GICV5_IRS_VMAP_L2_VMTR);

	rc = vgic_v5_irs_wait_for_vm_op();
	if (rc) {
		pr_err("GICv5 IRS_VMT_STATUSR stable state not reached\n");
		goto out_fail;
	}

out_fail:
	raw_spin_unlock(&vm_config_lock);

	return rc;
}

static int __vgic_v5_irs_vmap_vm(int vm_id, bool unmap)
{
	u64 vmap_vmr;
	int rc = 0;

	raw_spin_lock(&vm_config_lock);

	/* Make sure that we are idle to begin with */
	rc = vgic_v5_irs_wait_for_vm_op();
	if (rc) {
		pr_err("GICv5 IRS_VMT_STATUSR stable state not reached\n");
		goto out_fail;
	}

	/* Mark the VM as valid */
	vmap_vmr = FIELD_PREP(GICV5_IRS_VMAP_VMR_VM_ID, vm_id) |
		   FIELD_PREP(GICV5_IRS_VMAP_VMR_U, unmap) |
		   FIELD_PREP(GICV5_IRS_VMAP_VMR_M, true);
	irs_writeq_relaxed(vmap_vmr, GICV5_IRS_VMAP_VMR);

	rc = vgic_v5_irs_wait_for_vm_op();
	if (rc) {
		pr_err("GICv5 IRS_VMT_STATUSR stable state not reached\n");
		goto out_fail;
	}

out_fail:
	raw_spin_unlock(&vm_config_lock);

	return rc;
}

static int vgic_v5_irs_set_vm_valid(int vm_id)
{
	return __vgic_v5_irs_vmap_vm(vm_id, false);
}

static int vgic_v5_irs_set_vm_invalid(int vm_id)
{
	return __vgic_v5_irs_vmap_vm(vm_id, true);
}

static int __vgic_v5_irs_update_vist_validity(int vm_id, bool spi_ist, bool unmap)
{
	u64 vmap_vistr;
	u8 type = spi_ist ? 0b011 : 0b010;
	int rc = 0;

	raw_spin_lock(&vm_config_lock);

	/* Make sure that we are idle to begin with */
	rc = vgic_v5_irs_wait_for_vm_op();
	if (rc) {
		pr_err("GICv5 IRS_VMT_STATUSR stable state not reached\n");
		goto out_fail;
	}

	/* Mark the IST as valid */
	vmap_vistr = FIELD_PREP(GICV5_IRS_VMAP_VISTR_TYPE, type) |
		     FIELD_PREP(GICV5_IRS_VMAP_VISTR_VM_ID, vm_id) |
		     FIELD_PREP(GICV5_IRS_VMAP_VISTR_U, unmap) |
		     FIELD_PREP(GICV5_IRS_VMAP_VISTR_M, true);
	irs_writeq_relaxed(vmap_vistr, GICV5_IRS_VMAP_VISTR);

	rc = vgic_v5_irs_wait_for_vm_op();
	if (rc) {
		pr_err("GICv5 IRS_VMT_STATUSR stable state not reached\n");
		goto out_fail;
	}

out_fail:
	raw_spin_unlock(&vm_config_lock);

	return rc;
}

static int vgic_v5_irs_set_vist_valid(int vm_id, bool spi_ist)
{
	return __vgic_v5_irs_update_vist_validity(vm_id, spi_ist, false);
}

/* Note: We currently do not use this as we rely on the VM becoming invalid. */
static int vgic_v5_irs_set_vist_invalid(int vm_id, bool spi_ist)
{
	return __vgic_v5_irs_update_vist_validity(vm_id, spi_ist, true);
}

static int vgic_v5_irs_set_up_vpe(int vm_id, int vpe_id, irq_hw_number_t db_hwirq)
{
	u64 vmap_vper, dbr, selr;
	u32 statusr, cr0;
	int rc = 0;

	raw_spin_lock(&vm_config_lock);

	/* Make sure that we are idle to begin with */
	rc = vgic_v5_irs_wait_for_vm_op();
	if (rc) {
		pr_err("GICv5 IRS_VMT_STATUSR stable state not reached\n");
		goto out_fail;
	}

	/* Mark the VPE as valid */
	vmap_vper = FIELD_PREP(GICV5_IRS_VMAP_VPER_VPE_ID, vpe_id) |
		    FIELD_PREP(GICV5_IRS_VMAP_VPER_VM_ID, vm_id) |
		    FIELD_PREP(GICV5_IRS_VMAP_VPER_M, true);
	irs_writeq_relaxed(vmap_vper, GICV5_IRS_VMAP_VPER);

	/* Wait for the VPE to be marked valid in the VPET */
	rc = vgic_v5_irs_wait_for_vm_op();
	if (rc) {
		pr_err("GICv5 IRS_VMT_STATUSR stable state not reached\n");
		goto out_fail;
	}

	selr = FIELD_PREP(GICV5_IRS_VPE_SELR_VPE_ID, vpe_id) |
	       FIELD_PREP(GICV5_IRS_VPE_SELR_VM_ID, vm_id) |
	       FIELD_PREP(GICV5_IRS_VPE_SELR_S, true);
	irs_writeq_relaxed(selr, GICV5_IRS_VPE_SELR);

	rc = vgic_v5_irs_wait_for_vpe_op();
	if (rc) {
		pr_err("GICv5 IRS_VPE stable state not reached\n");
		goto out_fail;
	}

	statusr = irs_readl_relaxed( GICV5_IRS_VPE_STATUSR);
	if (!FIELD_GET(GICV5_IRS_VPE_STATUSR_V, statusr)) {
		pr_err("Write to IRS_VPE_SELR did not successfully select a valid VPE\n");
		rc = -EINVAL;
		goto out_fail;
	}

	/* Set targetted only routing (disable 1ofN vPE selection) */
	cr0 = FIELD_PREP(GICV5_IRS_VPE_CR0_DPS, true);
	irs_writel_relaxed( cr0, GICV5_IRS_VPE_CR0);

	rc = vgic_v5_irs_wait_for_vpe_op();
	if (rc) {
		pr_err("GICv5 IRS_VPE stable state not reached\n");
		goto out_fail;
	}

	statusr = irs_readl_relaxed(GICV5_IRS_VPE_STATUSR);
	if (FIELD_GET(GICV5_IRS_VPE_STATUSR_F, statusr)) {
		pr_err("Write to IRS_VPE_CR0 did not succesfully update the VPE configuration\n");
		rc = -EINVAL;
		goto out_fail;
	}

	/*
	 * The VPE has not yet run. Therefore, make sure that all interrupts
	 * will generate a doorbell.
	 */
	dbr = FIELD_PREP(GICV5_IRS_VPE_DBR_LPI_ID, db_hwirq) |
	      FIELD_PREP(GICV5_IRS_VPE_DBR_DBPM, 0b11111) |
	      FIELD_PREP(GICV5_IRS_VPE_DBR_REQ_DB, false) |
	      FIELD_PREP(GICV5_IRS_VPE_DBR_DBV, true);
	irs_writeq_relaxed(dbr, GICV5_IRS_VPE_DBR);

	rc = vgic_v5_irs_wait_for_vpe_op();
	if (rc) {
		pr_err("GICv5 IRS_VPE stable state not reached\n");
		goto out_fail;
	}

	statusr = irs_readl_relaxed(GICV5_IRS_VPE_STATUSR);
	if (FIELD_GET(GICV5_IRS_VPE_STATUSR_F, statusr)) {
		pr_err("Write to IRS_VPE_DBR did not succesfully update the VPE configuration\n");
		rc = -EINVAL;
		goto out_fail;
	}

out_fail:
	raw_spin_unlock(&vm_config_lock);
	return rc;
}

static int vgic_v5_irs_vpe_cr0_read(int vm_id, int vpe_id, u64 *cr0)
{
	u64 selr;
	u32 statusr;
	int rc = 0;

	raw_spin_lock(&vm_config_lock);

	selr = FIELD_PREP(GICV5_IRS_VPE_SELR_VPE_ID, vpe_id) |
	       FIELD_PREP(GICV5_IRS_VPE_SELR_VM_ID, vm_id) |
	       FIELD_PREP(GICV5_IRS_VPE_SELR_S, true);
	irs_writeq_relaxed(selr, GICV5_IRS_VPE_SELR);

	rc = vgic_v5_irs_wait_for_vpe_op();
	if (rc) {
		pr_err("GICv5 IRS_VPE stable state not reached\n");
		goto out_fail;
	}

	statusr = irs_readl_relaxed(GICV5_IRS_VPE_STATUSR);
	if (!FIELD_GET(GICV5_IRS_VPE_STATUSR_V, statusr)) {
		pr_err("Write to IRS_VPE_SELR did not successfully select a valid VPE\n");
		rc = -EINVAL;
		goto out_fail;
	}

	*cr0 = irs_readl_relaxed(GICV5_IRS_VPE_CR0);

out_fail:
	raw_spin_unlock(&vm_config_lock);
	return rc;
}

static int vgic_v5_irs_vpe_cr0_update(int vm_id, int vpe_id, u32 cr0)
{
	u64 selr;
	u32 statusr;
	int rc = 0;

	raw_spin_lock(&vm_config_lock);

	selr = FIELD_PREP(GICV5_IRS_VPE_SELR_VPE_ID, vpe_id) |
	       FIELD_PREP(GICV5_IRS_VPE_SELR_VM_ID, vm_id) |
	       FIELD_PREP(GICV5_IRS_VPE_SELR_S, true);
	irs_writeq_relaxed(selr, GICV5_IRS_VPE_SELR);

	rc = vgic_v5_irs_wait_for_vpe_op();
	if (rc) {
		pr_err("GICv5 IRS_VPE stable state not reached\n");
		goto out_fail;
	}

	statusr = irs_readl_relaxed(GICV5_IRS_VPE_STATUSR);
	if (!FIELD_GET(GICV5_IRS_VPE_STATUSR_V, statusr)) {
		pr_err("Write to IRS_VPE_SELR did not successfully select a valid VPE\n");
		rc = -EINVAL;
		goto out_fail;
	}

	irs_writel_relaxed(cr0, GICV5_IRS_VPE_CR0);

	rc = vgic_v5_irs_wait_for_vpe_op();
	if (rc) {
		pr_err("GICv5 IRS_VPE stable state not reached\n");
		goto out_fail;
	}

	statusr = irs_readl_relaxed(GICV5_IRS_VPE_STATUSR);
	if (FIELD_GET(GICV5_IRS_VPE_STATUSR_F, statusr)) {
		pr_err("Write to IRS_VPE_DBR did not succesfully update the VPE configuration\n");
		rc = -EINVAL;
		goto out_fail;
	}

out_fail:
	raw_spin_unlock(&vm_config_lock);
	return rc;
}

static int vgic_v5_db_set_vcpu_affinity(struct irq_data *data, void *vcpu_info)
{
	struct gicv5_cmd_info *cmd_info = vcpu_info;
	struct gicv5_vm *vm = data->domain->host_data;
	/* Our VPE ID is the index within the doorbell domain */
	u16 vpe_id = data->hwirq;

	switch(cmd_info->cmd_type) {
	case VMT_L2_MAP:
		return vgic_v5_irs_vmap_l2_vmt(vm->vm_id);
	case VMTE_MAKE_VALID:
		return vgic_v5_irs_set_vm_valid(vm->vm_id);
	case VMTE_MAKE_INVALID:
		return vgic_v5_irs_set_vm_invalid(vm->vm_id);
	case VPE_MAKE_VALID:
		/*
		 * We need the actual LPI ID which lives in the top-most parent
		 * domain. This hwirq won't include the type (LPI) but that's
		 * not required for the IRS_VPE_DBR.
		 */
		while (data->parent_data != NULL)
			data = data->parent_data;
		return vgic_v5_irs_set_up_vpe(vm->vm_id, vpe_id, data->hwirq);
	case VPE_CR0_READ:
		return vgic_v5_irs_vpe_cr0_read(vm->vm_id, vpe_id, &cmd_info->data);
	case VPE_CR0_WRITE:
		return vgic_v5_irs_vpe_cr0_update(vm->vm_id, vpe_id, cmd_info->data);
	case SPI_VIST_MAKE_VALID:
		return vgic_v5_irs_set_vist_valid(vm->vm_id, true);
	case LPI_VIST_MAKE_VALID:
		return vgic_v5_irs_set_vist_valid(vm->vm_id, false);
	case LPI_VIST_MAKE_INVALID:
		return vgic_v5_irs_set_vist_invalid(vm->vm_id, false);
	default:
		return -EINVAL;
	}
}

/*
 * This set of irq_chip functions is specific for doorbells.
 */
static struct irq_chip vgic_v5_db_irq_chip = {
	.name = "GICv5-DB",
	.irq_mask = irq_chip_mask_parent,
	.irq_unmask = irq_chip_unmask_parent,
	.irq_eoi = irq_chip_eoi_parent,
	.irq_set_affinity = irq_chip_set_affinity_parent,
	.irq_get_irqchip_state = irq_chip_get_parent_state,
	.irq_set_irqchip_state = irq_chip_set_parent_state,
	.irq_set_vcpu_affinity = vgic_v5_db_set_vcpu_affinity,
	.flags = IRQCHIP_SET_TYPE_MASKED | IRQCHIP_SKIP_SET_WAKE |
		 IRQCHIP_MASK_ON_SUSPEND,
};

static int vgic_v5_irq_db_domain_map(struct irq_domain *d, unsigned int virq,
				   u16 vpe_id)
{
	int ret;
	u32 lpi;
	irq_hw_number_t hwirq;
	struct irq_chip *chip = &vgic_v5_db_irq_chip;
	struct irq_data *irqd = irq_desc_get_irq_data(irq_to_desc(virq));

	/*
	 * For the DB domain, we don't use the same hwirq as for LPIs.
	 */
	hwirq = vpe_id;

	ret = gicv5_alloc_lpi();
	if (ret < 0)
		return ret;

	lpi = ret;

	irq_domain_set_hwirq_and_chip(d, virq, hwirq, chip, d->host_data);
	irqd_set_single_target(irqd);

	irq_domain_alloc_irqs_parent(d, virq, 1, &lpi);

	return 0;
}

static int vgic_v5_irq_db_domain_alloc(struct irq_domain *domain,
				     unsigned int virq, unsigned int nr_irqs,
				     void *arg)
{
	struct gicv5_vm *vm = arg;
	int ret;

	if (vm->nr_vpes != nr_irqs) {
		return -EINVAL;
	}

	if (vm == NULL) {
		pr_err("invalid parameter for doorbell irq allocation");
		return -EINVAL;
	}

	for (int i = 0; i < nr_irqs; i++) {
		ret = vgic_v5_irq_db_domain_map(domain, virq + i, i);
		if (ret)
			break;
	}

	return ret;
}

static void vgic_v5_irq_db_domain_free(struct irq_domain *domain,
				     unsigned int virq, unsigned int nr_irqs)
{
	int i;

	for (i = 0; i < nr_irqs; i++) {
		struct irq_data *d = irq_domain_get_irq_data(domain, virq + i);

		gicv5_free_lpi(d->parent_data->hwirq);
		irq_set_handler(virq + i, NULL);
		irq_domain_reset_irq_data(d);
	}

	irq_domain_free_irqs_parent(domain, virq, nr_irqs);
}

static const struct irq_domain_ops vgic_v5_irq_db_domain_ops = {
	.alloc = vgic_v5_irq_db_domain_alloc,
	.free = vgic_v5_irq_db_domain_free,
};

static int vgic_v5_create_per_vm_domain(struct gicv5_vm *vm)
{
	if (!gicv5_global_data.lpi_domain) {
		pr_err("LPI domain uninitialized, can't set up KVM Doorbells");
		return -ENODEV;
	}

	vm->fwnode = irq_domain_alloc_named_id_fwnode("GICv5-vpe-db",
						  task_pid_nr(current));

	/*
	 * KVM per-VM VPE DB domain; child of LPI domain; only ever handles
	 * doorbells. We know how many doorbells we have, and therefore we
	 * create a linear domain.
	 */
	vm->domain = irq_domain_create_hierarchy(gicv5_global_data.lpi_domain,
						 0, vm->nr_vpes, vm->fwnode,
						 &vgic_v5_irq_db_domain_ops, vm);

	if (WARN_ON(!vm->domain))
		return -ENOMEM;

	return 0;
}

static void vgic_v5_teardown_per_vm_domain(struct gicv5_vm *vm)
{
	if (vm->domain) {
		irq_domain_remove(vm->domain);
		irq_domain_free_fwnode(vm->fwnode);
	}
}

void vgic_v5_reset(struct kvm_vcpu *vcpu)
{
	int rc;
	u64 idr0;

	idr0 = read_sysreg_s(SYS_ICC_IDR0_EL1);
	switch (FIELD_GET(ICC_IDR0_EL1_ID_BITS, idr0)) {
	case ICC_IDR0_EL1_ID_BITS_16BITS:
		vcpu->arch.vgic_cpu.num_id_bits = 16;
		break;
	case ICC_IDR0_EL1_ID_BITS_24BITS:
		vcpu->arch.vgic_cpu.num_id_bits = 24;
		break;
	default:
		pr_warn("unknown value for id_bits");
		vcpu->arch.vgic_cpu.num_id_bits = 16;
	}

	switch (FIELD_GET(ICC_IDR0_EL1_PRI_BITS, idr0)) {
	case ICC_IDR0_EL1_PRI_BITS_4BITS:
		vcpu->arch.vgic_cpu.num_pri_bits = 4;
		break;
	case ICC_IDR0_EL1_PRI_BITS_5BITS:
		vcpu->arch.vgic_cpu.num_pri_bits = 5;
		break;
	default:
		pr_warn("unknown value for priority_bits");
		vcpu->arch.vgic_cpu.num_pri_bits = 4;
	}

	/* Make the VPE valid in the VPET */
	rc = vgic_v5_send_command(vcpu, VPE_MAKE_VALID);
	if (WARN_ON(rc)) {
		pr_warn("could not map VPE to IRS");
		kvm_vm_dead(vcpu->kvm);
		return;
	}

	enable_irq(vgic_v5_vpe_db(vcpu));
}

static void vgic_v5_disable_vcpu(struct kvm_vcpu *vcpu)
{
	/*
	 * We are called in the vgic_v5_teardown path. We no longer need the
	 * doorbell virqs.
	 */
	disable_irq(vgic_v5_vpe_db(vcpu));

	/* Free the doorbell irq (counter-part to request_irq)*/
	free_irq(vgic_v5_vpe_db(vcpu), vcpu);

	/* Remove the irq from the domain too */
	irq_domain_free_irqs(vgic_v5_vpe_db(vcpu), 1);
}

int vgic_v5_map_resources(struct kvm *kvm)
{
	if (!vgic_initialized(kvm))
		return -EBUSY;

	return 0;
}

/*
 * Claim and populate a VMTE (optionally making a new L2 VMT valid), create VPE
 * doorbells, allocate VPET and populate for each VPE. Finally, we also init the
 * vIRS, which means allocating and making the virtual SPI IST valid.
 *
 * Note: We do need to put the cart before the horse here. The VPE doorbells are
 * our conduit for communication with the IRS, which means we need to have those
 * before making the VMTE valid.
 */
int vgic_v5_init(struct kvm *kvm)
{
	int nr_vcpus, ret = 0;
	struct kvm_vcpu *vcpu, *vcpu0;
	unsigned long i;
	struct irq_data *d;
	unsigned int db_virq;

	if (!vgic_v5_vmt_allocated()) {
		pr_err("No VM tables allocated; something is horribly wrong\n");
		return -ENODEV;
	}

	kvm_for_each_vcpu(i, vcpu, kvm) {
		if (vcpu_has_nv(vcpu)) {
			kvm_err("Nested GICv5 VMs are currently unsupported\n");
			return -EINVAL;
		}
	}
	nr_vcpus = atomic_read(&kvm->online_vcpus);
	if (WARN_ON(nr_vcpus == 0)) {
		ret = -ENODEV;
		goto fail;

	}
	kvm->arch.vgic.gicv5_vm.nr_vpes = nr_vcpus;

	/*
	 * We only allow userspace to drive the SW_PPI, if it is
	 * implemented.
	 */
	kvm->arch.vgic.gicv5_vm.userspace_ppis[0] = GICV5_SW_PPI & GICV5_HWIRQ_ID;
	kvm->arch.vgic.gicv5_vm.userspace_ppis[0] &= ppi_caps->impl_ppi_mask[0];
	kvm->arch.vgic.gicv5_vm.userspace_ppis[1] = 0;

	ret = vgic_v5_allocate_vm_id(kvm);
	if (ret)
		goto fail;

	if (vgic_v5_create_per_vm_domain(&kvm->arch.vgic.gicv5_vm))
		goto fail_cleanup_id;

	/*
	 * Allocate VPE doorbells first - these are our conduit for
	 * communicating with the host irqchip driver. Can't do any earlier as
	 * we wouldn't know the VM ID.
	 */
	db_virq = irq_domain_alloc_irqs(kvm->arch.vgic.gicv5_vm.domain,
					nr_vcpus, NUMA_NO_NODE,
					&kvm->arch.vgic.gicv5_vm);
	if (db_virq < 0) {
		ret = db_virq;
		goto fail_cleanup_domain;
	}
	kvm->arch.vgic.gicv5_vm.vpe_db_base = db_virq;

	kvm_for_each_vcpu(i, vcpu, kvm) {
		d = irq_domain_get_irq_data(kvm->arch.vgic.gicv5_vm.domain,
					    db_virq + i);
		irq_set_status_flags(db_virq + i, IRQ_NOAUTOEN);

		ret = request_irq(db_virq + i, db_handler, 0, "vcpu", vcpu);
		if (ret)
			goto fail_cleanup_partial_dbs;

		/* Stash it with the VCPU for easy retrieval */
		vcpu->arch.vgic_cpu.vgic_v5.gicv5_vpe.db = db_virq + i;
	}

	/* Populate VMTE (with VPET and VM descriptor) */
	ret = vgic_v5_vmte_init(kvm);
	if (ret)
		goto fail_cleanup_dbs;

	/* We pick the first vcpu to make the VMTE valid - any would do */
	vcpu0 = kvm_get_vcpu(kvm, 0);
	ret = vgic_v5_send_command(vcpu0, VMTE_MAKE_VALID);
	if (ret)
		goto fail_cleanup_vmte;

	/* Loop over all VPEs, allocate/populate their data structures */
	kvm_for_each_vcpu(i, vcpu, kvm) {
		ret = vgic_v5_vmte_alloc_vpe(vcpu);
		if (ret)
			goto fail_cleanup_vpes;
	}

	return ret;

fail_cleanup_vpes:
	/* i contains the first vCPU that failed */
	if (i == 0)
		goto fail_cleanup_vmte;

	do {
		vcpu = kvm_get_vcpu(kvm, --i);
		vgic_v5_vmte_free_vpe(vcpu);
	} while (i != 0);

fail_cleanup_vmte:
	vgic_v5_vmte_release(kvm);

fail_cleanup_dbs:
	i = nr_vcpus;
fail_cleanup_partial_dbs:
	/* i contains the first vCPU that failed */
	if (i == 0)
		goto fail_cleanup_domain;

	do {
		vcpu = kvm_get_vcpu(kvm, --i);
		vgic_v5_disable_vcpu(vcpu);
	} while (i != 0);

fail_cleanup_domain:
	vgic_v5_teardown_per_vm_domain(&kvm->arch.vgic.gicv5_vm);

fail_cleanup_id:
	vgic_v5_release_vm_id(kvm);

fail:
	return ret;
}

void vgic_v5_teardown(struct kvm *kvm)
{
	struct kvm_vcpu *vcpu, *vcpu0;
	struct vgic_dist *dist = &kvm->arch.vgic;
	unsigned long i;
	int rc;

	/*
	 * There's a chance we don't have CPUs yet, in which case we've also not
	 * initialised the tables.
	 */
	if (!atomic_read(&kvm->online_vcpus))
		return;

	/* Make the VM invalid  */
	vcpu0 = kvm_get_vcpu(kvm, 0);
	rc = vgic_v5_send_command(vcpu0, VMTE_MAKE_INVALID);
	if (rc)
		kvm_err("could not make VMTE invalid\n");

	kvm_for_each_vcpu(i, vcpu, kvm) {
		/* Goodbye doorbell */
		vgic_v5_disable_vcpu(vcpu);

		if (vgic_v5_vmte_free_vpe(vcpu))
			kvm_err("Failed to free VPE\n");
	}

	vgic_v5_teardown_per_vm_domain(&kvm->arch.vgic.gicv5_vm);

	if (vgic_v5_vmte_release(kvm))
		kvm_err("Failed to release VM 0x%x\n", dist->gicv5_vm.vm_id);

	vgic_v5_release_vm_id(kvm);
}

static u32 vgic_v5_get_effective_priority_mask(struct kvm_vcpu *vcpu)
{
	struct vgic_v5_cpu_if *cpu_if = &vcpu->arch.vgic_cpu.vgic_v5;
	u32 highest_ap, priority_mask;

	/*
	 * Counting the number of trailing zeros gives the current
	 * active priority. Explicitly use the 32-bit version here as
	 * we have 32 priorities. 0x20 then means that there are no
	 * active priorities.
	 */
	highest_ap = cpu_if->vgic_apr ? __builtin_ctz(cpu_if->vgic_apr) : 32;

	/*
	 * An interrupt is of sufficient priority if it is equal to or
	 * greater than the priority mask. Add 1 to the priority mask
	 * (i.e., lower priority) to match the APR logic before taking
	 * the min. This gives us the lowest priority that is masked.
	 */
	priority_mask = FIELD_GET(FEAT_GCIE_ICH_VMCR_EL2_VPMR, cpu_if->vgic_vmcr);
	priority_mask = min(highest_ap, priority_mask + 1);

	return priority_mask;
}

static int vgic_v5_finalize_state(struct kvm_vcpu *vcpu)
{
	if (!ppi_caps)
		return -ENXIO;

	vcpu->arch.vgic_cpu.vgic_v5.vgic_ppi_mask[0] = 0;
	vcpu->arch.vgic_cpu.vgic_v5.vgic_ppi_mask[1] = 0;
	vcpu->arch.vgic_cpu.vgic_v5.vgic_ppi_hmr[0] = 0;
	vcpu->arch.vgic_cpu.vgic_v5.vgic_ppi_hmr[1] = 0;
	for (int i = 0; i < VGIC_V5_NR_PRIVATE_IRQS; ++i) {
		int reg = i / 64;
		u64 bit = BIT_ULL(i % 64);
		struct vgic_irq *irq = &vcpu->arch.vgic_cpu.private_irqs[i];

		raw_spin_lock(&irq->irq_lock);

		/*
		 * We only expose PPIs with an owner or thw SW_PPI to
		 * the guest.
		 */
		if (!irq->owner && irq->intid == GICV5_SW_PPI)
			goto unlock;

		/*
		 * If the PPI isn't implemented, we can't pass it
		 * through to a guest anyhow.
		 */
		if (!(ppi_caps->impl_ppi_mask[reg] & bit))
			goto unlock;

		vcpu->arch.vgic_cpu.vgic_v5.vgic_ppi_mask[reg] |= bit;

		if (irq->config == VGIC_CONFIG_LEVEL)
			vcpu->arch.vgic_cpu.vgic_v5.vgic_ppi_hmr[reg] |= bit;

unlock:
		raw_spin_unlock(&irq->irq_lock);
	}

	return 0;
}

int vgic_v5_finalize_ppi_state(struct kvm *kvm)
{
	struct kvm_vcpu *vcpu;
	unsigned long c;
	int ret;

	if (!vgic_is_v5(kvm))
		return 0;

	kvm_for_each_vcpu(c, vcpu, kvm) {
		ret = vgic_v5_finalize_state(vcpu);
		if (ret)
			return ret;
	}

	return 0;
}

bool vgic_v5_ppi_set_pending_state(struct kvm_vcpu *vcpu,
				   struct vgic_irq *irq)
{
	struct vgic_v5_cpu_if *cpu_if;
	const u64 id_bit = BIT_ULL(irq->intid % 64);
	const u32 reg = FIELD_GET(GICV5_HWIRQ_ID, irq->intid) / 64;

	if (!vcpu || !irq)
		return false;

	/* Skip injecting the state altogether */
	if (irq->directly_injected)
		return true;

	cpu_if = &vcpu->arch.vgic_cpu.vgic_v5;

	if (irq_is_pending(irq))
		cpu_if->vgic_ppi_pendr[reg] |= id_bit;
	else
		cpu_if->vgic_ppi_pendr[reg] &= ~id_bit;

	return true;
}

/*
 * For GICv5, the PPIs are mostly directly managed by the hardware. We
 * (the hypervisor) handle the pending, active, enable state
 * save/restore, but don't need the PPIs to be queued on a per-VCPU AP
 * list. Therefore, sanity check the state, unlock, and return.
 */
bool vgic_v5_ppi_queue_irq_unlock(struct kvm *kvm, struct vgic_irq *irq,
				  unsigned long flags)
	__releases(&irq->irq_lock)
{
	struct kvm_vcpu *vcpu;

	lockdep_assert_held(&irq->irq_lock);

	if (WARN_ON_ONCE(!__irq_is_ppi(KVM_DEV_TYPE_ARM_VGIC_V5, irq->intid)))
		goto out_unlock_fail;

	vcpu = irq->target_vcpu;
	if (WARN_ON_ONCE(!vcpu))
		goto out_unlock_fail;

	raw_spin_unlock_irqrestore(&irq->irq_lock, flags);

	/* Directly kick the target VCPU to make sure it sees the IRQ */
	kvm_make_request(KVM_REQ_IRQ_PENDING, vcpu);
	kvm_vcpu_kick(vcpu);

	return true;

out_unlock_fail:
	raw_spin_unlock_irqrestore(&irq->irq_lock, flags);

	return false;
}

static struct irq_ops vgic_v5_ppi_irq_ops = {
	.set_pending_state = vgic_v5_ppi_set_pending_state,
	.queue_irq_unlock = vgic_v5_ppi_queue_irq_unlock,
};

void vgic_v5_set_ppi_ops(struct vgic_irq *irq)
{
	if (WARN_ON(!irq))
		return;

	scoped_guard(raw_spinlock, &irq->irq_lock) {
		if (!WARN_ON(irq->ops))
			irq->ops = &vgic_v5_ppi_irq_ops;
	}
}


/*
 * Sync back the PPI priorities to the vgic_irq shadow state
 */
static void vgic_v5_sync_ppi_priorities(struct kvm_vcpu *vcpu)
{
	struct vgic_v5_cpu_if *cpu_if = &vcpu->arch.vgic_cpu.vgic_v5;
	int i, reg;

	/* We have 16 PPI Priority regs */
	for (reg = 0; reg < 16; reg++) {
		const unsigned long priorityr = cpu_if->vgic_ppi_priorityr[reg];

		for (i = 0; i < 8; ++i) {
			struct vgic_irq *irq;
			u32 intid;
			u8 priority;

			priority = (priorityr >> (i * 8)) & 0x1f;

			intid = FIELD_PREP(GICV5_HWIRQ_TYPE, GICV5_HWIRQ_TYPE_PPI);
			intid |= FIELD_PREP(GICV5_HWIRQ_ID, reg * 8 + i);

			irq = vgic_get_vcpu_irq(vcpu, intid);

			scoped_guard(raw_spinlock, &irq->irq_lock)
				irq->priority = priority;

			vgic_put_irq(vcpu->kvm, irq);
		}
	}
}

bool vgic_v5_has_pending_ppi(struct kvm_vcpu *vcpu)
{
	struct vgic_v5_cpu_if *cpu_if = &vcpu->arch.vgic_cpu.vgic_v5;
	int i, reg;
	unsigned int priority_mask;

	/* If no pending bits are set, exit early */
	if (likely(!cpu_if->vgic_ppi_pendr[0] && !cpu_if->vgic_ppi_pendr[1]))
		return false;

	priority_mask = vgic_v5_get_effective_priority_mask(vcpu);

	/* If the combined priority mask is 0, nothing can be signalled! */
	if (!priority_mask)
		return false;

	/* The shadow priority is only updated on demand, sync it across first */
	vgic_v5_sync_ppi_priorities(vcpu);

	for (reg = 0; reg < 2; reg++) {
		unsigned long possible_bits;
		const unsigned long enabler = cpu_if->vgic_ich_ppi_enabler_exit[reg];
		const unsigned long pendr = cpu_if->vgic_ppi_pendr_exit[reg];
		bool has_pending = false;

		/* Check all interrupts that are enabled and pending */
		possible_bits = enabler & pendr;

		/*
		 * Optimisation: pending and enabled with no active priorities
		 */
		if (possible_bits && priority_mask > 0x1f)
			return true;

		for_each_set_bit(i, &possible_bits, 64) {
			struct vgic_irq *irq;
			u32 intid;

			intid = FIELD_PREP(GICV5_HWIRQ_TYPE, GICV5_HWIRQ_TYPE_PPI);
			intid |= FIELD_PREP(GICV5_HWIRQ_ID, reg * 64 + i);

			irq = vgic_get_vcpu_irq(vcpu, intid);

			scoped_guard(raw_spinlock, &irq->irq_lock) {
				/*
				 * We know that the interrupt is
				 * enabled and pending, so only check
				 * the priority.
				 */
				if (irq->priority <= priority_mask)
					has_pending = true;
			}

			vgic_put_irq(vcpu->kvm, irq);

			if (has_pending)
				return true;
		}
	}

	return false;
}

/*
 * Detect any PPIs state changes, and propagate the state with KVM's
 * shadow structures.
 */
static void vgic_v5_fold_ppi_state(struct kvm_vcpu *vcpu)
{
	struct vgic_v5_cpu_if *cpu_if = &vcpu->arch.vgic_cpu.vgic_v5;
	int i, reg;

	for (reg = 0; reg < 2; reg++) {
		unsigned long changed_bits;
		const unsigned long enabler = cpu_if->vgic_ich_ppi_enabler_exit[reg];
		const unsigned long activer = cpu_if->vgic_ppi_activer_exit[reg];
		const unsigned long pendr = cpu_if->vgic_ppi_pendr_exit[reg];

		/*
		 * Track what changed across enabler, activer, pendr, but mask
		 * with ~DVI.
		 */
		changed_bits = cpu_if->vgic_ich_ppi_enabler_entry[reg] ^ enabler;
		changed_bits |= cpu_if->vgic_ppi_activer_entry[reg] ^ activer;
		changed_bits |= cpu_if->vgic_ppi_pendr_entry[reg] ^ pendr;
		changed_bits &= ~cpu_if->vgic_ppi_dvir[reg];

		for_each_set_bit(i, &changed_bits, 64) {
			struct vgic_irq *irq;
			u32 intid;

			intid = FIELD_PREP(GICV5_HWIRQ_TYPE, GICV5_HWIRQ_TYPE_PPI);
			intid |= FIELD_PREP(GICV5_HWIRQ_ID, reg * 64 + i);

			irq = vgic_get_vcpu_irq(vcpu, intid);

			scoped_guard(raw_spinlock, &irq->irq_lock) {
				irq->enabled = !!(enabler & BIT(i));
				irq->active = !!(activer & BIT(i));

				/* This is an OR to avoid losing incoming edges! */
				if (irq->config == VGIC_CONFIG_EDGE)
					irq->pending_latch |= !!(pendr & BIT(i));
			}

			vgic_put_irq(vcpu->kvm, irq);
		}

		/* Re-inject the exit state as entry state next time! */
		cpu_if->vgic_ich_ppi_enabler_entry[reg] = enabler;
		cpu_if->vgic_ppi_activer_entry[reg] = activer;

		/*
		 * Pending state is a bit different. We only propagate back
		 * pending state for Edge interrupts. Moreover, this is OR'd
		 * with the incoming state to make sure we don't lose incoming
		 * edges. Use the (inverse) HMR to mask off all Level bits, and
		 * OR.
		 */
		cpu_if->vgic_ppi_pendr[reg] |= pendr & ~cpu_if->vgic_ppi_hmr[reg];
	}
}

void vgic_v5_flush_ppi_state(struct kvm_vcpu *vcpu)
{
	struct vgic_v5_cpu_if *cpu_if = &vcpu->arch.vgic_cpu.vgic_v5;

	/*
	 * We're about to enter the guest. Copy the shadow state to the pending
	 * reg that will be written to the ICH_PPI_PENDRx_EL2 regs. While the
	 * guest is running we track any incoming changes to the pending state in
	 * vgic_ppi_pendr. The incoming changes are merged with the outgoing
	 * changes on the return path.
	 */
	cpu_if->vgic_ppi_pendr_entry[0] = cpu_if->vgic_ppi_pendr[0];
	cpu_if->vgic_ppi_pendr_entry[1] = cpu_if->vgic_ppi_pendr[1];

	/*
	 * Make sure that we can correctly detect "edges" in the PPI
	 * state. There's a path where we never actually enter the guest, and
	 * failure to do this risks losing pending state
	 */
	cpu_if->vgic_ppi_pendr_exit[0] = cpu_if->vgic_ppi_pendr[0];
	cpu_if->vgic_ppi_pendr_exit[1] = cpu_if->vgic_ppi_pendr[1];

}

/*
 * Not all PPIs are guaranteed to be implemented for
 * GICv5. Deterermine which ones are, and generate a mask. This is
 * called early in boot, so we can just write directly to the ICH_PPI*
 * regs and have no state to preserve.
 */
void vgic_v5_get_implemented_ppis(void)
{
	if (!cpus_have_final_cap(ARM64_HAS_GICV5_CPUIF))
		return;

	/* Never freed again */
	ppi_caps = kzalloc(sizeof(*ppi_caps), GFP_KERNEL);
	if (!ppi_caps)
		return;

	if (!has_vhe()) {
		struct arm_smccc_res res;

		kvm_call_hyp_nvhe_res(&res, __vgic_v5_detect_ppis);
		ppi_caps->impl_ppi_mask[0] = res.a1;
		ppi_caps->impl_ppi_mask[1] = res.a2;
	} else {
		__vgic_v5_detect_ppis(ppi_caps->impl_ppi_mask);
	}
}


void vgic_v5_fold_irq_state(struct kvm_vcpu *vcpu)
{
	struct vgic_dist *vgic_dist = &vcpu->kvm->arch.vgic;
	struct vgic_irq *irq, *tmp;

	/* Sync back the guest PPI state to the KVM shadow state */
	vgic_v5_fold_ppi_state(vcpu);

	/*
	 * For SPIs, which are on the global AP list, we synchronise their state
	 * with the hardware state. If they have been deactivated, notify, and
	 * immediately pop them off the list.
	 */
	raw_spin_lock(&vgic_dist->vgic_v5_spi_ap_list_lock);
	list_for_each_entry_safe(irq, tmp, &vgic_dist->vgic_v5_spi_ap_list_head, ap_list) {
		u64 icsr;
		bool pending;

		if (WARN_ON_ONCE(!__irq_is_spi(KVM_DEV_TYPE_ARM_VGIC_V5, irq->intid)))
			continue;

		raw_spin_lock(&irq->irq_lock);

		icsr = kvm_call_hyp_ret(__vgic_v5_vdrcfg, irq->intid);

		irq->active = !!FIELD_GET(ICC_ICSR_EL1_Active, icsr);
		pending = !!FIELD_GET(ICC_ICSR_EL1_Pending, icsr);

		if (irq->config == VGIC_CONFIG_EDGE)
			irq->pending_latch = pending;

		if (irq->config == VGIC_CONFIG_LEVEL && !(pending || irq->active))
			irq->pending_latch = false;

		/* Deactivated? */
		if (!irq->active & !irq_is_pending(irq)) {
			/* Use raw SPI index without type for the GSI */
			kvm_notify_acked_irq(vcpu->kvm, 0,
					     FIELD_GET(GICV5_HWIRQ_ID, irq->intid));

			/* And we're done with this SPI */
			list_del(&irq->ap_list);
			irq->vcpu = NULL;

			vgic_put_irq(vcpu->kvm, irq);
		}

		raw_spin_unlock(&irq->irq_lock);
	}
	raw_spin_unlock(&vgic_dist->vgic_v5_spi_ap_list_lock);
}

/*
 * Sets/clears the corresponding bit in the ICH_PPI_DVIR register.
 */
int vgic_v5_set_ppi_dvi(struct kvm_vcpu *vcpu, u32 irq, bool dvi)
{
	struct vgic_v5_cpu_if *cpu_if = &vcpu->arch.vgic_cpu.vgic_v5;
	u32 ppi = FIELD_GET(GICV5_HWIRQ_ID, irq);

	if (ppi >= 128)
		return -EINVAL;

	if (dvi) {
		/* Set the bit */
		cpu_if->vgic_ppi_dvir[ppi / 64] |= 1UL << (ppi % 64);
	} else {
		/* Clear the bit */
		cpu_if->vgic_ppi_dvir[ppi / 64] &= ~(1UL << (ppi % 64));
	}

	return 0;
}

static bool vgic_v5_set_spi_pending_state(struct kvm_vcpu *vcpu,
					  struct vgic_irq *irq)
{
	vgic_v5_set_irq_pend(irq->target_vcpu, irq);
	return true;
}

/*
 * Put the SPI on the SPI AP list. No need to kick the VCPU. If it is running,
 * the interrupt will signal at some point, and if not, then a VPE doorbell will
 * fire (based on the IAFFID the guest has configured).
 */
static bool vgic_v5_spi_queue_irq_unlock(struct kvm *kvm,
					struct vgic_irq *irq,
					unsigned long flags)
	__releases(&irq->irq_lock)
{
	struct vgic_dist *vgic_dist = &kvm->arch.vgic;

	lockdep_assert_held(&irq->irq_lock);

	if (WARN_ON(!__irq_is_spi(KVM_DEV_TYPE_ARM_VGIC_V5, irq->intid)))
		return false;

retry:
	/*
	 * We're already on the AP list or don't need to be on
	 * one; nothing more to do.
	 */
	if (irq->vcpu) {
		raw_spin_unlock_irqrestore(&irq->irq_lock, flags);
		return true;
	}

	raw_spin_unlock_irqrestore(&irq->irq_lock, flags);

	/* someone can do stuff here, which we re-check below */
	raw_spin_lock_irqsave(&vgic_dist->vgic_v5_spi_ap_list_lock, flags);
	raw_spin_lock(&irq->irq_lock);

	/*
	 * We've lost the race; and have already been queued. Unlock
	 * global AP list, relock IRQ, and retry.
	 */
	if (unlikely(irq->vcpu)) {
		raw_spin_unlock(&irq->irq_lock);
		raw_spin_unlock_irqrestore(&vgic_dist->vgic_v5_spi_ap_list_lock, flags);

		raw_spin_lock_irqsave(&irq->irq_lock, flags);

		goto retry;
	}

	/*
	 * Grab a reference to the irq to reflect the fact that it is
	 * now in the ap_list. This is safe as the caller must already
	 * hold a reference on the irq.
	 */
	vgic_get_irq_ref(irq);
	list_add_tail(&irq->ap_list, &vgic_dist->vgic_v5_spi_ap_list_head);

	/*
	 * Use the VCPU we've been given as the target VCPU to track
	 * that we're on an AP list. We're not queued on that VCPU's AP
	 * list, but in lieu of an AP flag, this will do.
	 */
	irq->vcpu = irq->target_vcpu;

	raw_spin_unlock(&irq->irq_lock);
	raw_spin_unlock_irqrestore(&vgic_dist->vgic_v5_spi_ap_list_lock, flags);

	return true;
}

static struct irq_ops vgic_v5_spi_irq_ops = {
	.set_pending_state = vgic_v5_set_spi_pending_state,
	.queue_irq_unlock = vgic_v5_spi_queue_irq_unlock,
};

void vgic_v5_set_spi_ops(struct vgic_irq *irq)
{
	if (WARN_ON(!irq) || WARN_ON(irq->ops))
		return;

	irq->ops = &vgic_v5_spi_irq_ops;
}

/* Set the pending state for GICv5 SPIs and LPIs */
void vgic_v5_set_irq_pend(struct kvm_vcpu *vcpu, struct vgic_irq *irq)
{
	if (WARN_ON(__irq_is_ppi(KVM_DEV_TYPE_ARM_VGIC_V5, irq->intid)))
		return;

	kvm_call_hyp(__vgic_v5_vdpend, irq->intid, irq_is_pending(irq),
		     vcpu->kvm->arch.vgic.gicv5_vm.vm_id);
}

void vgic_v5_load(struct kvm_vcpu *vcpu)
{
	struct vgic_v5_cpu_if *cpu_if = &vcpu->arch.vgic_cpu.vgic_v5;
	u16 vm = vgic_v5_vm_id(vcpu->kvm);
	u16 vpe = vgic_v5_vpe_id(vcpu);

	/*
	 * On the WFI path, vgic_load is called a second time. The first is when
	 * scheduling in the vcpu thread again, and the second is when leaving
	 * WFI. Skip the second instance as it serves no purpose and just
	 * restores the same state again.
	 */
	if (READ_ONCE(cpu_if->gicv5_vpe.resident))
		return;

	kvm_call_hyp(__vgic_v5_restore_vmcr_apr, cpu_if);

	cpu_if->vgic_contextr = FIELD_PREP(ICH_CONTEXTR_EL2_V, true) |
				FIELD_PREP(ICH_CONTEXTR_EL2_VPE, vpe) |
				FIELD_PREP(ICH_CONTEXTR_EL2_VM, vm);

	kvm_call_hyp(__vgic_v5_make_resident, cpu_if);
}

void vgic_v5_put(struct kvm_vcpu *vcpu)
{
	struct vgic_v5_cpu_if *cpu_if = &vcpu->arch.vgic_cpu.vgic_v5;
	bool req_db = !!vcpu_get_flag(vcpu, IN_WFI);
	int dbpm;

	/*
	 * Do nothing if we're not resident. This can happen in the WFI path
	 * where we do a vgic_put in the WFI path and again later when
	 * descheduling the thread. We risk losing VMCR state if we sync it
	 * twice, so instead return early in this case.
	 */
	if (!READ_ONCE(cpu_if->gicv5_vpe.resident))
		return;

	kvm_call_hyp(__vgic_v5_save_apr, cpu_if);

	cpu_if->vgic_contextr = 0;

	if (req_db) {
		/*
		* Find the virual running priority and use this to calculate the
		* doorbell priority mask. We combine the highest active priority
		* and the CPU's priority mask. The guest can't handle interrupts
		* with priorities less than or equal to the virtual running
		* priority, so there's literally no point in waking the guest
		* for these.
		*
		* The priority needs to be higher than the mask to signal, so
		* pick the next higher priority (subtract 1).
		*/
		dbpm = vgic_v5_get_effective_priority_mask(vcpu) - 1;

		/* Don't request a doorbell if the max priority is masked */
		if (dbpm > 0)
			cpu_if->vgic_contextr = FIELD_PREP(ICH_CONTEXTR_EL2_DB, 1) |
						FIELD_PREP(ICH_CONTEXTR_EL2_DBPM, dbpm);

		/* Make the doorbell affine to this CPU */
		WARN_ON(irq_set_affinity(vgic_v5_vpe_db(vcpu),
					 cpumask_of(smp_processor_id())));
	}

	kvm_call_hyp(__vgic_v5_make_non_resident, cpu_if);
}

void vgic_v5_get_vmcr(struct kvm_vcpu *vcpu, struct vgic_vmcr *vmcrp)
{
	struct vgic_v5_cpu_if *cpu_if = &vcpu->arch.vgic_cpu.vgic_v5;
	u64 vmcr = cpu_if->vgic_vmcr;

	vmcrp->en = FIELD_GET(FEAT_GCIE_ICH_VMCR_EL2_EN, vmcr);
	vmcrp->pmr = FIELD_GET(FEAT_GCIE_ICH_VMCR_EL2_VPMR, vmcr);
}

void vgic_v5_set_vmcr(struct kvm_vcpu *vcpu, struct vgic_vmcr *vmcrp)
{
	struct vgic_v5_cpu_if *cpu_if = &vcpu->arch.vgic_cpu.vgic_v5;
	u64 vmcr;

	vmcr = FIELD_PREP(FEAT_GCIE_ICH_VMCR_EL2_VPMR, vmcrp->pmr) |
	       FIELD_PREP(FEAT_GCIE_ICH_VMCR_EL2_EN, vmcrp->en);

	cpu_if->vgic_vmcr = vmcr;
}

void vgic_v5_restore_state(struct kvm_vcpu *vcpu)
{
	struct vgic_v5_cpu_if *cpu_if = &vcpu->arch.vgic_cpu.vgic_v5;

	__vgic_v5_restore_state(cpu_if);
	kvm_call_hyp(__vgic_v5_restore_ppi_state, cpu_if);
	dsb(sy);
}

void vgic_v5_save_state(struct kvm_vcpu *vcpu)
{
	struct vgic_v5_cpu_if *cpu_if = &vcpu->arch.vgic_cpu.vgic_v5;

	__vgic_v5_save_state(cpu_if);
	kvm_call_hyp(__vgic_v5_save_ppi_state, cpu_if);
	dsb(sy);
}
