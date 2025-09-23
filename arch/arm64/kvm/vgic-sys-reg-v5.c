// SPDX-License-Identifier: GPL-2.0-only
/*
 * VGICv5 system registers handling functions for AArch64 mode
 */

#include <linux/irqchip/arm-gic-v5.h>
#include <linux/kvm.h>
#include <linux/kvm_host.h>
#include <asm/kvm_emulate.h>
#include "vgic/vgic.h"
#include "sys_regs.h"

static int set_gic_apr(struct kvm_vcpu *vcpu, const struct sys_reg_desc *r,
		       u64 val)
{
	struct vgic_v5_cpu_if *cpu_if = &vcpu->arch.vgic_cpu.vgic_v5;
	cpu_if->vgic_apr = val;

	return 0;
}

static int get_gic_apr(struct kvm_vcpu *vcpu, const struct sys_reg_desc *r,
		       u64 *val)
{
	struct vgic_v5_cpu_if *cpu_if = &vcpu->arch.vgic_cpu.vgic_v5;
	*val = cpu_if->vgic_apr;

	return 0;
}

static int set_gic_cr0(struct kvm_vcpu *vcpu, const struct sys_reg_desc *r,
		       u64 val)
{
	struct vgic_v5_cpu_if *cpu_if = &vcpu->arch.vgic_cpu.vgic_v5;

	/* We only support setting the ICC_CR0_EL1.En bit */
	cpu_if->vgic_vmcr &= ~FEAT_GCIE_ICH_VMCR_EL2_EN;
	cpu_if->vgic_vmcr |= FIELD_PREP(FEAT_GCIE_ICH_VMCR_EL2_EN,
					FIELD_GET(ICC_CR0_EL1_EN, val));

	return 0;
}

static int get_gic_cr0(struct kvm_vcpu *vcpu, const struct sys_reg_desc *r,
		       u64 *val)
{
	struct vgic_v5_cpu_if *cpu_if = &vcpu->arch.vgic_cpu.vgic_v5;
	*val = FIELD_PREP(ICC_CR0_EL1_EN,
			  FIELD_GET(FEAT_GCIE_ICH_VMCR_EL2_EN, cpu_if->vgic_vmcr));

	return 0;
}

static int set_gic_pcr(struct kvm_vcpu *vcpu, const struct sys_reg_desc *r,
		       u64 val)
{
	struct vgic_v5_cpu_if *cpu_if = &vcpu->arch.vgic_cpu.vgic_v5;

	cpu_if->vgic_vmcr &= ~FEAT_GCIE_ICH_VMCR_EL2_VPMR;
	cpu_if->vgic_vmcr |= FIELD_PREP(FEAT_GCIE_ICH_VMCR_EL2_VPMR,
					FIELD_GET(ICC_PCR_EL1_PRIORITY, val));

	return 0;
}

static int get_gic_pcr(struct kvm_vcpu *vcpu, const struct sys_reg_desc *r,
		       u64 *val)
{
	struct vgic_v5_cpu_if *cpu_if = &vcpu->arch.vgic_cpu.vgic_v5;
	*val = FIELD_PREP(ICC_PCR_EL1_PRIORITY,
			  FIELD_GET(FEAT_GCIE_ICH_VMCR_EL2_VPMR, cpu_if->vgic_vmcr));

	return 0;
}

static int set_gic_icsr(struct kvm_vcpu *vcpu, const struct sys_reg_desc *r,
		       u64 val)
{
	struct vgic_v5_cpu_if *cpu_if = &vcpu->arch.vgic_cpu.vgic_v5;
	cpu_if->vgic_icsr = val;

	return 0;
}

static int get_gic_icsr(struct kvm_vcpu *vcpu, const struct sys_reg_desc *r,
		       u64 *val)
{
	struct vgic_v5_cpu_if *cpu_if = &vcpu->arch.vgic_cpu.vgic_v5;
	*val = cpu_if->vgic_icsr;

	return 0;
}

static int set_gic_ppi_enabler(struct kvm_vcpu *vcpu, const struct sys_reg_desc *r,
			u64 val)
{
	struct vgic_v5_cpu_if *cpu_if = &vcpu->arch.vgic_cpu.vgic_v5;
	int idx = r->Op2 % 2;

	cpu_if->vgic_ich_ppi_enabler_entry[idx] = val;

	return 0;
}

static int get_gic_ppi_enabler(struct kvm_vcpu *vcpu, const struct sys_reg_desc *r,
		       u64 *val)
{
	struct vgic_v5_cpu_if *cpu_if = &vcpu->arch.vgic_cpu.vgic_v5;
	int idx = r->Op2 % 2;

	*val = cpu_if->vgic_ich_ppi_enabler_entry[idx];

	return 0;
}

static int set_gic_ppi_activer(struct kvm_vcpu *vcpu, const struct sys_reg_desc *r,
			u64 val)
{
	struct vgic_v5_cpu_if *cpu_if = &vcpu->arch.vgic_cpu.vgic_v5;
	int idx = r->Op2 % 2;

	cpu_if->vgic_ppi_activer_entry[idx] = val;

	return 0;
}

static int get_gic_ppi_activer(struct kvm_vcpu *vcpu, const struct sys_reg_desc *r,
		       u64 *val)
{
	struct vgic_v5_cpu_if *cpu_if = &vcpu->arch.vgic_cpu.vgic_v5;
	int idx = r->Op2 % 2;

	*val = cpu_if->vgic_ppi_activer_entry[idx];

	return 0;
}

static int set_gic_ppi_pendr(struct kvm_vcpu *vcpu, const struct sys_reg_desc *r,
			u64 val)
{
	struct vgic_v5_cpu_if *cpu_if = &vcpu->arch.vgic_cpu.vgic_v5;
	int idx = r->Op2 % 2;

	cpu_if->vgic_ppi_pendr_entry[idx] = val;

	return 0;
}

static int get_gic_ppi_pendr(struct kvm_vcpu *vcpu, const struct sys_reg_desc *r,
		       u64 *val)
{
	struct vgic_v5_cpu_if *cpu_if = &vcpu->arch.vgic_cpu.vgic_v5;
	int idx = r->Op2 % 2;

	*val = cpu_if->vgic_ppi_pendr_entry[idx];

	return 0;
}

static int set_gic_ppi_priorityr(struct kvm_vcpu *vcpu, const struct sys_reg_desc *r,
			u64 val)
{
	struct vgic_v5_cpu_if *cpu_if = &vcpu->arch.vgic_cpu.vgic_v5;
	int idx = r->Op2;

	cpu_if->vgic_ppi_priorityr[idx] = val;

	return 0;
}

static int get_gic_ppi_priorityr(struct kvm_vcpu *vcpu, const struct sys_reg_desc *r,
		       u64 *val)
{
	struct vgic_v5_cpu_if *cpu_if = &vcpu->arch.vgic_cpu.vgic_v5;
	int idx = r->Op2;

	*val = cpu_if->vgic_ppi_priorityr[idx];

	return 0;
}

static const struct sys_reg_desc gic_v5_icc_reg_descs[] = {
	{ SYS_DESC(SYS_ICC_ICSR_EL1),
	  .set_user = set_gic_icsr, .get_user = get_gic_icsr, },
	{ SYS_DESC(SYS_ICC_PPI_ENABLER0_EL1),
	  .set_user = set_gic_ppi_enabler, .get_user = get_gic_ppi_enabler, },
	{ SYS_DESC(SYS_ICC_PPI_ENABLER1_EL1),
	  .set_user = set_gic_ppi_enabler, .get_user = get_gic_ppi_enabler, },
	/*
	 * Only ICC_SACTIVER<n>_EL1 is exposed to the guest. This is treated as
	 * a RAW write of register state for writes.
	 */
	{ SYS_DESC(SYS_ICC_PPI_SACTIVER0_EL1),
	  .set_user = set_gic_ppi_activer, .get_user = get_gic_ppi_activer, },
	{ SYS_DESC(SYS_ICC_PPI_SACTIVER1_EL1),
	  .set_user = set_gic_ppi_activer, .get_user = get_gic_ppi_activer, },
	/*
	 * Only ICC_SPENDR<n>_EL1 is exposed to the guest. This is treated as
	 * a RAW write of register state for writes.
	 */
	{ SYS_DESC(SYS_ICC_PPI_SPENDR0_EL1),
	  .set_user = set_gic_ppi_pendr, .get_user = get_gic_ppi_pendr, },
	{ SYS_DESC(SYS_ICC_PPI_SPENDR1_EL1),
	  .set_user = set_gic_ppi_pendr, .get_user = get_gic_ppi_pendr, },
	{ SYS_DESC(SYS_ICC_PPI_PRIORITYR0_EL1),
	  .set_user = set_gic_ppi_priorityr, .get_user = get_gic_ppi_priorityr, },
	{ SYS_DESC(SYS_ICC_PPI_PRIORITYR1_EL1),
	  .set_user = set_gic_ppi_priorityr, .get_user = get_gic_ppi_priorityr, },
	{ SYS_DESC(SYS_ICC_PPI_PRIORITYR2_EL1),
	  .set_user = set_gic_ppi_priorityr, .get_user = get_gic_ppi_priorityr, },
	{ SYS_DESC(SYS_ICC_PPI_PRIORITYR3_EL1),
	  .set_user = set_gic_ppi_priorityr, .get_user = get_gic_ppi_priorityr, },
	{ SYS_DESC(SYS_ICC_PPI_PRIORITYR4_EL1),
	  .set_user = set_gic_ppi_priorityr, .get_user = get_gic_ppi_priorityr, },
	{ SYS_DESC(SYS_ICC_PPI_PRIORITYR5_EL1),
	  .set_user = set_gic_ppi_priorityr, .get_user = get_gic_ppi_priorityr, },
	{ SYS_DESC(SYS_ICC_PPI_PRIORITYR6_EL1),
	  .set_user = set_gic_ppi_priorityr, .get_user = get_gic_ppi_priorityr, },
	{ SYS_DESC(SYS_ICC_PPI_PRIORITYR7_EL1),
	  .set_user = set_gic_ppi_priorityr, .get_user = get_gic_ppi_priorityr, },
	{ SYS_DESC(SYS_ICC_PPI_PRIORITYR8_EL1),
	  .set_user = set_gic_ppi_priorityr, .get_user = get_gic_ppi_priorityr, },
	{ SYS_DESC(SYS_ICC_PPI_PRIORITYR9_EL1),
	  .set_user = set_gic_ppi_priorityr, .get_user = get_gic_ppi_priorityr, },
	{ SYS_DESC(SYS_ICC_PPI_PRIORITYR10_EL1),
	  .set_user = set_gic_ppi_priorityr, .get_user = get_gic_ppi_priorityr, },
	{ SYS_DESC(SYS_ICC_PPI_PRIORITYR11_EL1),
	  .set_user = set_gic_ppi_priorityr, .get_user = get_gic_ppi_priorityr, },
	{ SYS_DESC(SYS_ICC_PPI_PRIORITYR12_EL1),
	  .set_user = set_gic_ppi_priorityr, .get_user = get_gic_ppi_priorityr, },
	{ SYS_DESC(SYS_ICC_PPI_PRIORITYR13_EL1),
	  .set_user = set_gic_ppi_priorityr, .get_user = get_gic_ppi_priorityr, },
	{ SYS_DESC(SYS_ICC_PPI_PRIORITYR14_EL1),
	  .set_user = set_gic_ppi_priorityr, .get_user = get_gic_ppi_priorityr, },
	{ SYS_DESC(SYS_ICC_PPI_PRIORITYR15_EL1),
	  .set_user = set_gic_ppi_priorityr, .get_user = get_gic_ppi_priorityr, },
	{ SYS_DESC(SYS_ICC_APR_EL1),
	  .set_user = set_gic_apr, .get_user = get_gic_apr, },
	{ SYS_DESC(SYS_ICC_CR0_EL1),
	  .set_user = set_gic_cr0, .get_user = get_gic_cr0, },
	{ SYS_DESC(SYS_ICC_PCR_EL1),
	  .set_user = set_gic_pcr, .get_user = get_gic_pcr, },
};

const struct sys_reg_desc *vgic_v5_get_sysreg_table(unsigned int *sz)
{
	*sz = ARRAY_SIZE(gic_v5_icc_reg_descs);
	return gic_v5_icc_reg_descs;
}

static u64 attr_to_id(u64 attr)
{
	return ARM64_SYS_REG(FIELD_GET(KVM_REG_ARM_VGIC_SYSREG_OP0_MASK, attr),
			     FIELD_GET(KVM_REG_ARM_VGIC_SYSREG_OP1_MASK, attr),
			     FIELD_GET(KVM_REG_ARM_VGIC_SYSREG_CRN_MASK, attr),
			     FIELD_GET(KVM_REG_ARM_VGIC_SYSREG_CRM_MASK, attr),
			     FIELD_GET(KVM_REG_ARM_VGIC_SYSREG_OP2_MASK, attr));
}

int vgic_v5_has_cpu_sysregs_attr(struct kvm_vcpu *vcpu, struct kvm_device_attr *attr)
{
	const struct sys_reg_desc *r;

	r = get_reg_by_id(attr_to_id(attr->attr), gic_v5_icc_reg_descs,
			  ARRAY_SIZE(gic_v5_icc_reg_descs));

	if (r && !sysreg_hidden(vcpu, r))
		return 0;

	return -ENXIO;
}

int vgic_v5_cpu_sysregs_uaccess(struct kvm_vcpu *vcpu,
				struct kvm_device_attr *attr,
				bool is_write)
{
	struct kvm_one_reg reg = {
		.id	= attr_to_id(attr->attr),
		.addr	= attr->addr,
	};

	if (is_write)
		return kvm_sys_reg_set_user(vcpu, &reg, gic_v5_icc_reg_descs,
					    ARRAY_SIZE(gic_v5_icc_reg_descs));
	else
		return kvm_sys_reg_get_user(vcpu, &reg, gic_v5_icc_reg_descs,
					    ARRAY_SIZE(gic_v5_icc_reg_descs));
}
