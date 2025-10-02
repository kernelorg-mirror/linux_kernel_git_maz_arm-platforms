/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2025 ARM Limited, All Rights Reserved.
 */
#include <linux/bitops.h>
#include <linux/bsearch.h>
#include <linux/interrupt.h>
#include <linux/irq.h>
#include <linux/kvm.h>
#include <linux/kvm_host.h>
#include <kvm/iodev.h>
#include <kvm/arm_arch_timer.h>
#include <kvm/arm_vgic.h>

#include "vgic.h"
#include "vgic-mmio.h"
#include "vgic-v5-tables.h"

static struct vgic_dist *vgic_v5_get_vgic(struct kvm_vcpu *vcpu)
{
	return &vcpu->kvm->arch.vgic;
}

static struct vgic_v5_irs *vgic_v5_get_irs(struct kvm_vcpu *vcpu)
{
	return vcpu->kvm->arch.vgic.vgic_v5_irs_data;
}

static unsigned long vgic_v5_mmio_read_irs_misc(struct kvm_vcpu *vcpu,
						gpa_t addr, unsigned int len)
{
	struct vgic_v5_irs *irs = vgic_v5_get_irs(vcpu);
	struct gicv5_cmd_info cmd_info;
	u64 value = 0;
	int rc;
	const size_t offset = addr & (SZ_64K - 1);

	switch (offset) {
	case GICV5_IRS_IDR0:
		value = FIELD_PREP(GICV5_IRS_IDR0_DOM, irs->idr0.domain);
		value |= FIELD_PREP(GICV5_IRS_IDR0_PA_RANGE, irs->idr0.pa_range);
		value |= FIELD_PREP(GICV5_IRS_IDR0_VIRT, irs->idr0.virt);
		value |= FIELD_PREP(GICV5_IRS_IDR0_ONEOFN, irs->idr0.one_of_n);
		value |= FIELD_PREP(GICV5_IRS_IDR0_VIRT1OFN, irs->idr0.virt_one_of_n);
		value |= FIELD_PREP(GICV5_IRS_IDR0_SETLPI, irs->idr0.setlpi);
		value |= FIELD_PREP(GICV5_IRS_IDR0_MEC, irs->idr0.mec);
		value |= FIELD_PREP(GICV5_IRS_IDR0_MPAM, irs->idr0.mpam);
		value |= FIELD_PREP(GICV5_IRS_IDR0_SWE, irs->idr0.swe);
		value |= FIELD_PREP(GICV5_IRS_IDR0_IRSID, irs->idr0.irs_id);
		break;
	case GICV5_IRS_IDR1:
		/* Populate PE count the first time the guest reads it */
		if (irs->idr1.num_pes == 0)
			irs->idr1.num_pes =
				vcpu->kvm->online_vcpus.counter;

		value = FIELD_PREP(GICV5_IRS_IDR1_PE_CNT, irs->idr1.num_pes);
		value |= FIELD_PREP(GICV5_IRS_IDR1_IAFFID_BITS, vgic_v5_get_vpe_id_bits());
		value |= FIELD_PREP(GICV5_IRS_IDR1_PRIORITY_BITS, irs->idr1.priority_bits);
		break;
	case GICV5_IRS_IDR2:
		value = FIELD_PREP(GICV5_IRS_IDR2_ISTMD_SZ, irs->idr2.istmd_sz);
		value |= FIELD_PREP(GICV5_IRS_IDR2_ISTMD, irs->idr2.istmd);
		value |= FIELD_PREP(GICV5_IRS_IDR2_IST_L2SZ, irs->idr2.ist_l2sz);
		value |= FIELD_PREP(GICV5_IRS_IDR2_IST_LEVELS, irs->idr2.ist_levels);
		value |= FIELD_PREP(GICV5_IRS_IDR2_MIN_LPI_ID_BITS, irs->idr2.min_lpi_id_bits);
		value |= GICV5_IRS_IDR2_LPI; /* We always support LPIs */
		value |= FIELD_PREP(GICV5_IRS_IDR2_ID_BITS, irs->idr2.id_bits);
		break;
	case GICV5_IRS_IDR3:
		value = FIELD_PREP(GICV5_IRS_IDR3_VMT_LEVELS, irs->idr3.vmt_levels);
		value |= FIELD_PREP(GICV5_IRS_IDR3_VM_ID_BITS, irs->idr3.vm_id_bits);
		value |= FIELD_PREP(GICV5_IRS_IDR3_VMD_SZ, irs->idr3.vmd_size);
		value |= FIELD_PREP(GICV5_IRS_IDR3_VMD, irs->idr3.vmd);
		break;
	case GICV5_IRS_IDR4:
		value = FIELD_PREP(GICV5_IRS_IDR4_VPE_ID_BITS, irs->idr4.vpe_id_bits);
		value |= FIELD_PREP(GICV5_IRS_IDR4_VPED_SZ, irs->idr4.vped_size);
		break;
	case GICV5_IRS_IDR5:
		value = FIELD_PREP(GICV5_IRS_IDR5_SPI_RANGE, irs->idr5.spi_range);
		break;
	case GICV5_IRS_IDR6:
		value = FIELD_PREP(GICV5_IRS_IDR6_SPI_IRS_RANGE, irs->idr6.spi_irs_range);
		break;
	case GICV5_IRS_IDR7:
		value = FIELD_PREP(GICV5_IRS_IDR7_SPI_BASE, irs->idr7.spi_base);
		break;
	case GICV5_IRS_IIDR:
		/* Revision, Variant, ProductID are implementation defined */
		value = FIELD_PREP(GICV5_IRS_IIDR_PRODUCT_ID, 0);
		value |= FIELD_PREP(GICV5_IRS_IIDR_VARIANT, 0);
		value |= FIELD_PREP(GICV5_IRS_IIDR_REVISION, 0);
		value |= FIELD_PREP(GICV5_IRS_IIDR_IMPLEMENTER,
				    GICV5_IIDR_IMPLEMENTER_ARM);
		break;
	case GICV5_IRS_AIDR:
		value = FIELD_PREP(GICV5_IRS_AIDR_COMPONENT,
				   GICV5_AIDR_COMPONENT_IRS);
		value |= FIELD_PREP(GICV5_IRS_AIDR_ARCHMAJORREV,
				    GICV5_AIDR_ARCH_MAJ_REV_V5);
		value |= FIELD_PREP(GICV5_IRS_AIDR_ARCHMINORREV,
				    GICV5_AIDR_ARCH_MIN_REV_V0);
		break;
	case GICV5_IRS_CR0:
		/*
		 * The IRS is ALWAYS idle as we handle things instantaneously
		 * from a guest's viewpoint.
		 */
		value = GICV5_IRS_CR0_IDLE;
		value |= FIELD_PREP(GICV5_IRS_CR0_IRSEN,
				    irs->enabled);
		break;
	case GICV5_IRS_CR1:
		value = FIELD_PREP(GICV5_IRS_CR1_VPED_WA, irs->cr1.vped_wa);
		value |= FIELD_PREP(GICV5_IRS_CR1_VPED_RA, irs->cr1.vped_ra);
		value |= FIELD_PREP(GICV5_IRS_CR1_VMD_WA, irs->cr1.vmd_wa);
		value |= FIELD_PREP(GICV5_IRS_CR1_VMD_RA, irs->cr1.vmd_ra);
		value |= FIELD_PREP(GICV5_IRS_CR1_VPET_RA, irs->cr1.vpet_ra);
		value |= FIELD_PREP(GICV5_IRS_CR1_VMT_RA, irs->cr1.vmt_ra);
		value |= FIELD_PREP(GICV5_IRS_CR1_IST_WA, irs->cr1.ist_wa);
		value |= FIELD_PREP(GICV5_IRS_CR1_IST_RA, irs->cr1.ist_ra);
		value |= FIELD_PREP(GICV5_IRS_CR1_IC, irs->cr1.ic);
		value |= FIELD_PREP(GICV5_IRS_CR1_OC, irs->cr1.oc);
		value |= FIELD_PREP(GICV5_IRS_CR1_SH, irs->cr1.sh);
		break;
	case GICV5_IRS_SYNC_STATUSR:
		value = GICV5_IRS_SYNC_STATUSR_IDLE;
		break;
	case GICV5_IRS_PE_SELR:
		value = FIELD_PREP(GICV5_IRS_PE_SELR_IAFFID, irs->pe_selr.iaffid);
		break;
	case GICV5_IRS_PE_STATUSR:
		/* We assume that the PE is Online if present. Always IDLE too */
		value = GICV5_IRS_PE_STATUSR_IDLE;
		value |= GICV5_IRS_PE_STATUSR_ONLINE;

		/* Set V if IAFFID is reasonable */
		if (irs->pe_selr.iaffid < vcpu->kvm->online_vcpus.counter)
			value |= GICV5_IRS_PE_STATUSR_V;
		break;
	case GICV5_IRS_PE_CR0:
		/*
		 * Make sure that we are doing something reasonable first.
		 * Remember, the IAFFID is the same as the VPE_ID
		 */
		if (irs->pe_selr.iaffid >= vcpu->kvm->online_vcpus.counter) {
			kvm_err("Guest programmed invalid IAFFID (0x%x) into the IRS_PE_SELR\n",
				irs->pe_selr.iaffid);
			break;
		}

		mutex_lock(&vcpu->kvm->arch.config_lock);

		/*
		 * Write the corresponding IRS_VPE_CR0. We do so via the
		 * doorbell for the specific vcpu we have in the PE_SELR.
		 */
		cmd_info.cmd_type = VPE_CR0_WRITE;
		vcpu = kvm_get_vcpu(vcpu->kvm, irs->pe_selr.iaffid);
		rc = irq_set_vcpu_affinity(vgic_v5_vpe_db(vcpu), &cmd_info);
		if (rc)
			kvm_err("Could not read VPE_CR0 in IRS: %d\n", rc);
		else
			value = cmd_info.data;

		mutex_unlock(&vcpu->kvm->arch.config_lock);

		break;
	default:
		return 0;
	}

	return value;
}

static void vgic_v5_mmio_write_irs_misc(struct kvm_vcpu *vcpu, gpa_t addr,
					unsigned int len, unsigned long val)
{
	struct vgic_v5_irs *irs = vgic_v5_get_irs(vcpu);
	struct vgic_dist *vgic = vgic_v5_get_vgic(vcpu);
	struct gicv5_cmd_info cmd_info;
	int rc;
	const size_t offset = addr & (SZ_64K - 1);

	switch (offset) {
	case GICV5_IRS_CR0:
		mutex_lock(&vcpu->kvm->arch.config_lock);
		/*
		 * We need to make sure that the IRS coming online (or
		 * going offline) is visible to all vCPUs, even if
		 * they are currently resident. Halt all of the vCPUs
		 * now, and resume once we've done the update.
		 */
		kvm_arm_halt_guest(vcpu->kvm);

		if (FIELD_GET(GICV5_IRS_CR0_IRSEN, val)) {
			irs->enabled = true;
			/*
			 * This second enable is the one used by the existing,
			 * non-GICv5 code.
			 */
			vgic->enabled = true;
		} else {
			irs->enabled = false;
			/* Ditto */
			vgic->enabled = false;
		}

		kvm_arm_resume_guest(vcpu->kvm);
		mutex_unlock(&vcpu->kvm->arch.config_lock);

		return;
	case GICV5_IRS_CR1:
		irs->cr1.sh = FIELD_GET(GICV5_IRS_CR1_SH, val);
		irs->cr1.oc = FIELD_GET(GICV5_IRS_CR1_OC, val);
		irs->cr1.ic = FIELD_GET(GICV5_IRS_CR1_IC, val);
		irs->cr1.ist_ra = FIELD_GET(GICV5_IRS_CR1_IST_RA, val);
		irs->cr1.ist_wa = FIELD_GET(GICV5_IRS_CR1_IST_WA, val);
		irs->cr1.vmt_ra = FIELD_GET(GICV5_IRS_CR1_VMT_RA, val);
		irs->cr1.vpet_ra = FIELD_GET(GICV5_IRS_CR1_VPET_RA, val);
		irs->cr1.vmd_ra = FIELD_GET(GICV5_IRS_CR1_VMD_RA, val);
		irs->cr1.vmd_wa = FIELD_GET(GICV5_IRS_CR1_VMD_WA, val);
		irs->cr1.vped_ra = FIELD_GET(GICV5_IRS_CR1_VPED_RA, val);
		irs->cr1.vped_wa = FIELD_GET(GICV5_IRS_CR1_VPED_WA, val);
		return;
	case GICV5_IRS_SYNCR:
		if (FIELD_GET(GICV5_IRS_SYNCR_SYNC, val))
			kvm_err("Write to IRS_SYNCR not implemented\n");
		return;
	case GICV5_IRS_PE_SELR:
		irs->pe_selr.iaffid = FIELD_GET(GICV5_IRS_PE_SELR_IAFFID, val);
		return;
	case GICV5_IRS_PE_CR0:
		/*
		 * Make sure that we are doing something reasonable first.
		 * Remember, the IAFFID is the same as the VPE_ID.
		 */
		if (irs->pe_selr.iaffid >=
			atomic_read(&vcpu->kvm->online_vcpus)) {
			kvm_err("Guest programmed invalid IAFFID (0x%x) into "
				"the IRS_PE_SELR\n",
				irs->pe_selr.iaffid);
			return;
		}

		mutex_lock(&vcpu->kvm->arch.config_lock);

		/*
		 * Write the corresponding IRS_VPE_CR0. We do so via the
		 * doorbell for the specific vcpu we have in the PE_SELR.
		 */
		cmd_info.cmd_type = VPE_CR0_WRITE;
		cmd_info.data = val;
		vcpu = kvm_get_vcpu(vcpu->kvm, irs->pe_selr.iaffid);
		rc = irq_set_vcpu_affinity(vgic_v5_vpe_db(vcpu), &cmd_info);
		if (rc)
			kvm_err("Could not update VPE_CR0 in IRS: %d\n", rc);

		mutex_unlock(&vcpu->kvm->arch.config_lock);
		return;
	default:
		return;
	}
}

static bool vgic_v5_is_spi_selr_valid(struct vgic_v5_irs *irs)
{
	bool valid = true;

	/* Invalid - we don't have any SPIs at all */
	if (irs->idr5.spi_range == 0)
		valid = false;

	/* Invalid - we don't have any on this IRS */
	if (irs->idr6.spi_irs_range == 0)
		valid = false;

	/* Invalid - ID is less than min */
	if (irs->spi_selr.id < irs->idr7.spi_base)
		valid = false;

	/* Invalid - ID is greater than max */
	if (irs->spi_selr.id >=
	    (irs->idr7.spi_base + irs->idr6.spi_irs_range))
		valid = false;

	if (!valid) {
		kvm_err("Guest IRS_SPI_SELR Invalid!\n");
	}

	return valid;
}

static unsigned long vgic_v5_mmio_read_irs_spi(struct kvm_vcpu *vcpu,
					       gpa_t addr, unsigned int len)
{
	struct vgic_v5_irs *irs = vgic_v5_get_irs(vcpu);
	struct vgic_dist *vgic = vgic_v5_get_vgic(vcpu);
	u64 value = 0;
	const size_t offset = addr & (SZ_64K - 1);

	switch (offset) {
	case GICV5_IRS_SPI_SELR:
		/* Return whatever was last written */
		value = FIELD_PREP(GICV5_IRS_SPI_SELR_ID, irs->spi_selr.id);
		break;
	case GICV5_IRS_SPI_STATUSR:
		/* We assume that we can always claim to be idle */
		value = GICV5_IRS_SPI_STATUSR_IDLE;
		value |= FIELD_PREP(GICV5_IRS_SPI_STATUSR_V, vgic_v5_is_spi_selr_valid(irs));
		break;
	case GICV5_IRS_SPI_DOMAINR:
		value = FIELD_PREP(GICV5_IRS_SPI_DOMAINR_DOMAIN,
				   GICV5_IRS_SPI_DOMAINR_DOMAIN_NON_SECURE);
		break;
	case GICV5_IRS_SPI_VMR:
		pr_warn_once("Guest accesses to IRS_SPI_VMR are not implemented\n");
		value = 0;
		break;
	case GICV5_IRS_SPI_CFGR:
		if (!vgic_v5_is_spi_selr_valid(irs)) {
			/* Fault with IRS_SPI_SELR; return 0*/
			value = 0;
			break;
		}

		/* Sanity check for KVM's sake */
		if (irs->spi_selr.id >= vgic->nr_spis) {
			kvm_err("Guest trying to access SPI not backed by KVM\n");
			value = 0;
			break;
		}

		if (vgic->spis[irs->spi_selr.id].config == VGIC_CONFIG_EDGE)
			value = FIELD_PREP(GICV5_IRS_SPI_CFGR_TM, GICV5_IRS_SPI_CFGR_TM_EDGE);
		else
			value = FIELD_PREP(GICV5_IRS_SPI_CFGR_TM, GICV5_IRS_SPI_CFGR_TM_LEVEL);

		break;
	default:
		return 0;
	}

	return value;
}

static void vgic_v5_mmio_write_irs_spi(struct kvm_vcpu *vcpu, gpa_t addr,
				       unsigned int len, unsigned long val)
{
	struct vgic_v5_irs *irs = vgic_v5_get_irs(vcpu);
	struct vgic_irq *irq;
	const size_t offset = addr & (SZ_64K - 1);

	switch (offset) {
	case GICV5_IRS_SPI_SELR:
		irs->spi_selr.id = FIELD_GET(GICV5_IRS_SPI_SELR_ID, val);
		return;
	case GICV5_IRS_SPI_VMR:
		pr_warn_once("Guest accesses to IRS_SPI_VMR are not implemented\n");
		return;
	case GICV5_IRS_SPI_CFGR:
		if (!vgic_v5_is_spi_selr_valid(irs)) {
			kvm_err("ISR_SPI_CFGR write with invalid ISR_SPI_SELR\n");
			irs->spi_statusr.fault = true;
			return;
		}

		/*
		 * Find KVM's representation of the interrupt - we need to make
		 * sure that KVM's view agrees with the guest's, else interrupt
		 * injection won't work properly for level-triggered interrupts
		 * (we fail to handle the clearing of the pending state if KVM
		 * thinks that the interrupt is edge-triggered, which is the
		 * default.)
		*/
		irq = vgic_get_irq(vcpu->kvm,
				   FIELD_PREP(GICV5_HWIRQ_ID, irs->spi_selr.id) |
				   FIELD_PREP(GICV5_HWIRQ_TYPE, GICV5_HWIRQ_TYPE_SPI));
		if (!irq) {
			kvm_err("Failed to get KVM IRQ\n");
			irs->spi_statusr.fault = true;
			return;
		}

		if (FIELD_GET(GICV5_IRS_SPI_CFGR_TM, val))
			irq->config = VGIC_CONFIG_LEVEL;
		else
			irq->config = VGIC_CONFIG_EDGE;

		vgic_put_irq(vcpu->kvm, irq);
		irs->spi_statusr.fault = false;

		return;
	case GICV5_IRS_SPI_RESAMPLER:
		if(FIELD_GET(GICV5_IRS_SPI_RESAMPLER_RESAMPLE, val))
			kvm_err("Write of IRS_SPI_RESAMPLER unimplemented\n");
		return;
	default:
		return;
	}
}

static unsigned long vgic_v5_mmio_read_irs_ist(struct kvm_vcpu *vcpu,
					       gpa_t addr, unsigned int len)
{
	struct vgic_v5_irs *irs = vgic_v5_get_irs(vcpu);
	u64 value = 0;
	const size_t offset = addr & (SZ_64K - 1);

	switch (offset) {
	case GICV5_IRS_IST_STATUSR:
		return 1;
	case GICV5_IRS_IST_CFGR:
		value = FIELD_PREP(GICV5_IRS_IST_CFGR_STRUCTURE, irs->ist_cfgr.structure);
		value |= FIELD_PREP(GICV5_IRS_IST_CFGR_ISTSZ, irs->ist_cfgr.istsz);
		value |= FIELD_PREP(GICV5_IRS_IST_CFGR_L2SZ, irs->ist_cfgr.l2sz);
		value |= FIELD_PREP(GICV5_IRS_IST_CFGR_LPI_ID_BITS, irs->ist_cfgr.lpi_id_bits);
		break;
	case GICV5_IRS_IST_BASER:
		value = FIELD_PREP(GICV5_IRS_IST_BASER_ADDR_MASK,
				   irs->ist_baser.addr >> GICV5_IRS_IST_BASER_ADDR_SHIFT);
		value |= FIELD_PREP(GICV5_IRS_IST_BASER_VALID, irs->ist_baser.valid);
		break;
	case GICV5_IRS_MAP_L2_ISTR:
		/* It is a WO register; just return 0 */
		return 0;
	default:
		return 0;
	}

	return value;
}

static void vgic_v5_mmio_write_irs_ist(struct kvm_vcpu *vcpu, gpa_t addr,
				       unsigned int len, unsigned long val)
{
	struct vgic_v5_irs *irs = vgic_v5_get_irs(vcpu);
	struct gicv5_cmd_info cmd_info;
	const size_t offset = addr & (SZ_64K - 1);

	switch (offset) {
	case GICV5_IRS_IST_CFGR:
		irs->ist_cfgr.lpi_id_bits = FIELD_GET(GICV5_IRS_IST_CFGR_LPI_ID_BITS, val);
		irs->ist_cfgr.l2sz = FIELD_GET(GICV5_IRS_IST_CFGR_L2SZ, val);
		irs->ist_cfgr.istsz = FIELD_GET(GICV5_IRS_IST_CFGR_ISTSZ, val);
		irs->ist_cfgr.structure = FIELD_GET(GICV5_IRS_IST_CFGR_STRUCTURE, val);
		return;
	case GICV5_IRS_IST_BASER:
		mutex_lock(&vcpu->kvm->arch.config_lock);

		if (irs->ist_baser.valid &&
		    !FIELD_GET(GICV5_IRS_IST_BASER_VALID, val)) {
			/* Make the LPI IST invalid... */
			cmd_info.cmd_type = LPI_VIST_MAKE_INVALID;
			WARN_ON(irq_set_vcpu_affinity(vgic_v5_vpe_db(vcpu),
						      &cmd_info));
			/* ... then free any host shims */
			vgic_v5_lpi_ist_free(vcpu->kvm);
		}

		irs->ist_baser.valid = FIELD_GET(GICV5_IRS_IST_BASER_VALID, val);
		irs->ist_baser.addr = FIELD_GET(GICV5_IRS_IST_BASER_ADDR_MASK, val)
					   << GICV5_IRS_IST_BASER_ADDR_SHIFT;

		if (irs->ist_baser.valid) {
			if (vgic_v5_lpi_ist_alloc(vcpu->kvm, irs->ist_baser.addr,
						  irs->ist_cfgr.lpi_id_bits)) {
				kvm_err("Failed to alloc LPI IST\n");
			}
		}

		mutex_unlock(&vcpu->kvm->arch.config_lock);
		return;
	case GICV5_IRS_MAP_L2_ISTR:
		kvm_err("Write to IRS_MAP_L2_ISTR is unhandled\n");
		return;
	default:
		return;
	}
}

static unsigned long vgic_v5_mmio_read_irs_unimpl(struct kvm_vcpu *vcpu,
						  gpa_t addr, unsigned int len)
{	const size_t offset = addr & (SZ_64K - 1);

	kvm_err("Read from unimplemented IRS register at offset 0x%lx\n",
		offset);

	return 0;
}

static void vgic_v5_mmio_write_irs_unimpl(struct kvm_vcpu *vcpu, gpa_t addr,
					  unsigned int len, unsigned long val)
{	const size_t offset = addr & (SZ_64K - 1);
	kvm_err("Write of 0x%lx to  unimplemented IRS register at offset "
		"0x%lx\n",
		val, offset);

	return;
}

static int vgic_v5_mmio_uaccess_write_irs(struct kvm_vcpu *vcpu, gpa_t addr,
					  unsigned int len, unsigned long val)
{
	size_t offset = addr & (SZ_64K - 1);
	struct vgic_dist *vgic = &vcpu->kvm->arch.vgic;
	struct vgic_v5_irs *irs_data = vgic->vgic_v5_irs_data;

	/*
	 * The following registers are ONLY settable via uaccesses. The guest
	 * cannot write them!
	 */

	switch(offset) {
	case GICV5_IRS_IDR0:
		irs_data->idr0.domain = FIELD_GET(GICV5_IRS_IDR0_DOM, val);
		irs_data->idr0.pa_range = FIELD_GET(GICV5_IRS_IDR0_PA_RANGE, val);
		irs_data->idr0.virt = FIELD_GET(GICV5_IRS_IDR0_VIRT, val);
		irs_data->idr0.one_of_n = FIELD_GET(GICV5_IRS_IDR0_ONEOFN, val);
		irs_data->idr0.virt_one_of_n = FIELD_GET(GICV5_IRS_IDR0_VIRT1OFN, val);
		irs_data->idr0.setlpi = FIELD_GET(GICV5_IRS_IDR0_SETLPI, val);
		irs_data->idr0.mec = FIELD_GET(GICV5_IRS_IDR0_MEC, val);
		irs_data->idr0.mpam = FIELD_GET(GICV5_IRS_IDR0_MPAM, val);
		irs_data->idr0.swe = FIELD_GET(GICV5_IRS_IDR0_SWE, val);
		irs_data->idr0.irs_id = FIELD_GET(GICV5_IRS_IDR0_IRSID, val);
		break;
	case GICV5_IRS_IDR1:
		/* Ignore writes to PE_CNT as this is populated from num vcpus */

		/*
		 * The number of IAFFID bits supported. If userspace tries to
		 * set something less than what we support, reject the write.
		 */
		if (FIELD_GET(GICV5_IRS_IDR1_IAFFID_BITS, val) > vgic_v5_get_vpe_id_bits())
			return -EINVAL;

		if (FIELD_GET(GICV5_IRS_IDR1_PRIORITY_BITS, val) > 0b100)
			return -EINVAL;

		irs_data->idr1.priority_bits = FIELD_GET(GICV5_IRS_IDR1_PRIORITY_BITS, val);
		break;
	case GICV5_IRS_IDR2:
		/* We only support Linear guest ISTs for SAVE/RESTORE */
		if (FIELD_GET(GICV5_IRS_IDR2_IST_LEVELS, val))
			return -EINVAL;

		/* We always support LPIs */
		if (!FIELD_GET(GICV5_IRS_IDR2_LPI, val))
			return -EINVAL;

		irs_data->idr2.istmd_sz = FIELD_GET(GICV5_IRS_IDR2_ISTMD_SZ, val);
		irs_data->idr2.istmd = FIELD_GET(GICV5_IRS_IDR2_ISTMD, val);
		irs_data->idr2.ist_l2sz = FIELD_GET(GICV5_IRS_IDR2_IST_L2SZ, val);
		irs_data->idr2.ist_levels = FIELD_GET(GICV5_IRS_IDR2_IST_LEVELS, val);
		irs_data->idr2.min_lpi_id_bits = FIELD_GET(GICV5_IRS_IDR2_MIN_LPI_ID_BITS, val);
		irs_data->idr2.id_bits = FIELD_GET(GICV5_IRS_IDR2_ID_BITS, val);
		break;
	case GICV5_IRS_IDR3:
		irs_data->idr3.vmt_levels = FIELD_GET(GICV5_IRS_IDR3_VMT_LEVELS, val);
		irs_data->idr3.vm_id_bits = FIELD_GET(GICV5_IRS_IDR3_VM_ID_BITS, val);
		irs_data->idr3.vmd_size = FIELD_GET(GICV5_IRS_IDR3_VMD_SZ, val);
		irs_data->idr3.vmd = FIELD_GET(GICV5_IRS_IDR3_VMD, val);
		break;
	case GICV5_IRS_IDR4:
		irs_data->idr4.vpe_id_bits = FIELD_GET(GICV5_IRS_IDR4_VPE_ID_BITS, val);
		irs_data->idr4.vped_size = FIELD_GET(GICV5_IRS_IDR4_VPED_SZ, val);
		break;
	case GICV5_IRS_IDR5:
		if (FIELD_GET(GICV5_IRS_IDR5_SPI_RANGE, val) != irs_data->idr5.spi_range)
			return -EINVAL;
		break;
	case GICV5_IRS_IDR6:
		if (FIELD_GET(GICV5_IRS_IDR6_SPI_IRS_RANGE, val) != irs_data->idr6.spi_irs_range)
			return -EINVAL;
		break;
	case GICV5_IRS_IDR7:
		if (FIELD_GET(GICV5_IRS_IDR7_SPI_BASE, val) != irs_data->idr7.spi_base)
			return -EINVAL;
		break;
	case GICV5_IRS_IIDR: fallthrough;
	case GICV5_IRS_AIDR: fallthrough;
	case GICV5_IRS_MAP_L2_ISTR:
		/* Ignore the write */
		break;
	default:
		return -EINVAL;
	}

	return 0;
}

static const struct vgic_register_region vgic_v5_irs_registers[] = {
	/*
	 * This is the IRS_CONFIG_FRAME.
	 */
	REGISTER_DESC_WITH_LENGTH_UACCESS(GICV5_IRS_IDR0, vgic_v5_mmio_read_irs_misc,
					  vgic_mmio_write_wi, NULL,
					  vgic_v5_mmio_uaccess_write_irs, 4,
					  VGIC_ACCESS_32bit),
	REGISTER_DESC_WITH_LENGTH_UACCESS(GICV5_IRS_IDR1, vgic_v5_mmio_read_irs_misc,
					  vgic_mmio_write_wi, NULL,
					  vgic_v5_mmio_uaccess_write_irs, 4,
					  VGIC_ACCESS_32bit),
	REGISTER_DESC_WITH_LENGTH_UACCESS(GICV5_IRS_IDR2, vgic_v5_mmio_read_irs_misc,
					  vgic_mmio_write_wi, NULL,
					  vgic_v5_mmio_uaccess_write_irs, 4,
					  VGIC_ACCESS_32bit),
	REGISTER_DESC_WITH_LENGTH_UACCESS(GICV5_IRS_IDR3, vgic_v5_mmio_read_irs_misc,
					  vgic_mmio_write_wi, NULL,
					  vgic_v5_mmio_uaccess_write_irs, 4,
					  VGIC_ACCESS_32bit),
	REGISTER_DESC_WITH_LENGTH_UACCESS(GICV5_IRS_IDR4, vgic_v5_mmio_read_irs_misc,
					  vgic_mmio_write_wi, NULL,
					  vgic_v5_mmio_uaccess_write_irs, 4,
					  VGIC_ACCESS_32bit),
	REGISTER_DESC_WITH_LENGTH_UACCESS(GICV5_IRS_IDR5, vgic_v5_mmio_read_irs_misc,
					  vgic_mmio_write_wi, NULL,
					  vgic_v5_mmio_uaccess_write_irs, 4,
					  VGIC_ACCESS_32bit),
	REGISTER_DESC_WITH_LENGTH_UACCESS(GICV5_IRS_IDR6, vgic_v5_mmio_read_irs_misc,
					  vgic_mmio_write_wi, NULL,
					  vgic_v5_mmio_uaccess_write_irs, 4,
					  VGIC_ACCESS_32bit),
	REGISTER_DESC_WITH_LENGTH_UACCESS(GICV5_IRS_IDR7, vgic_v5_mmio_read_irs_misc,
					  vgic_mmio_write_wi, NULL,
					  vgic_v5_mmio_uaccess_write_irs, 4,
					  VGIC_ACCESS_32bit),
	REGISTER_DESC_WITH_LENGTH_UACCESS(GICV5_IRS_IIDR, vgic_v5_mmio_read_irs_misc,
					  vgic_mmio_write_wi, NULL,
					  vgic_v5_mmio_uaccess_write_irs, 4,
					  VGIC_ACCESS_32bit),
	REGISTER_DESC_WITH_LENGTH_UACCESS(GICV5_IRS_AIDR, vgic_v5_mmio_read_irs_misc,
					  vgic_mmio_write_wi, NULL,
					  vgic_v5_mmio_uaccess_write_irs, 4,
					  VGIC_ACCESS_32bit),
	REGISTER_DESC_WITH_LENGTH(GICV5_IRS_CR0, vgic_v5_mmio_read_irs_misc,
				  vgic_v5_mmio_write_irs_misc, 4,
				  VGIC_ACCESS_32bit),
	REGISTER_DESC_WITH_LENGTH(GICV5_IRS_CR1, vgic_v5_mmio_read_irs_misc,
				  vgic_v5_mmio_write_irs_misc, 4,
				  VGIC_ACCESS_32bit),
	REGISTER_DESC_WITH_LENGTH(GICV5_IRS_SYNCR, vgic_mmio_read_raz,
				  vgic_v5_mmio_write_irs_misc, 4,
				  VGIC_ACCESS_32bit),
	REGISTER_DESC_WITH_LENGTH(GICV5_IRS_SYNC_STATUSR,
				  vgic_v5_mmio_read_irs_misc,
				  vgic_mmio_write_wi, 4, VGIC_ACCESS_32bit),
	REGISTER_DESC_WITH_LENGTH(GICV5_IRS_SPI_VMR, vgic_v5_mmio_read_irs_spi,
				  vgic_v5_mmio_write_irs_spi, 8,
				  VGIC_ACCESS_64bit),
	REGISTER_DESC_WITH_LENGTH(GICV5_IRS_SPI_SELR, vgic_v5_mmio_read_irs_spi,
				  vgic_v5_mmio_write_irs_spi, 4,
				  VGIC_ACCESS_32bit),
	REGISTER_DESC_WITH_LENGTH(
		GICV5_IRS_SPI_DOMAINR, vgic_v5_mmio_read_irs_spi,
		vgic_v5_mmio_write_irs_spi, 4, VGIC_ACCESS_32bit),
	REGISTER_DESC_WITH_LENGTH(GICV5_IRS_SPI_RESAMPLER, vgic_mmio_read_raz,
				  vgic_v5_mmio_write_irs_spi, 4,
				  VGIC_ACCESS_32bit),
	REGISTER_DESC_WITH_LENGTH(GICV5_IRS_SPI_CFGR, vgic_v5_mmio_read_irs_spi,
				  vgic_v5_mmio_write_irs_spi, 4,
				  VGIC_ACCESS_32bit),
	REGISTER_DESC_WITH_LENGTH(GICV5_IRS_SPI_STATUSR,
				  vgic_v5_mmio_read_irs_spi, vgic_mmio_write_wi,
				  4, VGIC_ACCESS_32bit),
	REGISTER_DESC_WITH_LENGTH(GICV5_IRS_PE_SELR, vgic_v5_mmio_read_irs_misc,
				  vgic_v5_mmio_write_irs_misc, 4,
				  VGIC_ACCESS_32bit),
	REGISTER_DESC_WITH_LENGTH(GICV5_IRS_PE_STATUSR,
				  vgic_v5_mmio_read_irs_misc,
				  vgic_mmio_write_wi, 4, VGIC_ACCESS_32bit),
	REGISTER_DESC_WITH_LENGTH(GICV5_IRS_PE_CR0, vgic_v5_mmio_read_irs_misc,
				  vgic_v5_mmio_write_irs_misc, 4,
				  VGIC_ACCESS_32bit),
	REGISTER_DESC_WITH_LENGTH(
		GICV5_IRS_IST_BASER, vgic_v5_mmio_read_irs_ist,
		vgic_v5_mmio_write_irs_ist, 8, VGIC_ACCESS_64bit),
	REGISTER_DESC_WITH_LENGTH(GICV5_IRS_IST_CFGR, vgic_v5_mmio_read_irs_ist,
				  vgic_v5_mmio_write_irs_ist, 4,
				  VGIC_ACCESS_32bit),
	REGISTER_DESC_WITH_LENGTH(GICV5_IRS_IST_STATUSR,
				  vgic_v5_mmio_read_irs_ist, vgic_mmio_write_wi,
				  4, VGIC_ACCESS_32bit),
	REGISTER_DESC_WITH_LENGTH_UACCESS(
		GICV5_IRS_MAP_L2_ISTR, vgic_v5_mmio_read_irs_ist,
		vgic_v5_mmio_write_irs_ist,  NULL,
		vgic_v5_mmio_uaccess_write_irs, 4, VGIC_ACCESS_32bit),

	/*
	 * All of the registers (EXCEPT SETLPI!) from this point onwards are
	 * only for running VMs. We do not expect them to be touched by the
	 * Guest. If they are, we warn and ignore.
	 */
	REGISTER_DESC_WITH_LENGTH(
		GICV5_IRS_VMT_BASER, vgic_v5_mmio_read_irs_unimpl,
		vgic_v5_mmio_write_irs_unimpl, 8, VGIC_ACCESS_64bit),
	REGISTER_DESC_WITH_LENGTH(
		GICV5_IRS_VMT_CFGR, vgic_v5_mmio_read_irs_unimpl,
		vgic_v5_mmio_write_irs_unimpl, 4, VGIC_ACCESS_32bit),
	REGISTER_DESC_WITH_LENGTH(
		GICV5_IRS_VMT_STATUSR, vgic_v5_mmio_read_irs_unimpl,
		vgic_v5_mmio_write_irs_unimpl, 4, VGIC_ACCESS_32bit),
	REGISTER_DESC_WITH_LENGTH(
		GICV5_IRS_VPE_SELR, vgic_v5_mmio_read_irs_unimpl,
		vgic_v5_mmio_write_irs_unimpl, 8, VGIC_ACCESS_64bit),
	REGISTER_DESC_WITH_LENGTH(
		GICV5_IRS_VPE_DBR, vgic_v5_mmio_read_irs_unimpl,
		vgic_v5_mmio_write_irs_unimpl, 8, VGIC_ACCESS_64bit),
	REGISTER_DESC_WITH_LENGTH(
		GICV5_IRS_VPE_HPPIR, vgic_v5_mmio_read_irs_unimpl,
		vgic_v5_mmio_write_irs_unimpl, 8, VGIC_ACCESS_64bit),
	REGISTER_DESC_WITH_LENGTH(
		GICV5_IRS_VPE_CR0, vgic_v5_mmio_read_irs_unimpl,
		vgic_v5_mmio_write_irs_unimpl, 4, VGIC_ACCESS_32bit),
	REGISTER_DESC_WITH_LENGTH(
		GICV5_IRS_VPE_STATUSR, vgic_v5_mmio_read_irs_unimpl,
		vgic_v5_mmio_write_irs_unimpl, 4, VGIC_ACCESS_32bit),
	REGISTER_DESC_WITH_LENGTH(
		GICV5_IRS_VM_DBR, vgic_v5_mmio_read_irs_unimpl,
		vgic_v5_mmio_write_irs_unimpl, 8, VGIC_ACCESS_64bit),
	REGISTER_DESC_WITH_LENGTH(
		GICV5_IRS_VM_SELR, vgic_v5_mmio_read_irs_unimpl,
		vgic_v5_mmio_write_irs_unimpl, 4, VGIC_ACCESS_32bit),
	REGISTER_DESC_WITH_LENGTH(
		GICV5_IRS_VM_STATUSR, vgic_v5_mmio_read_irs_unimpl,
		vgic_v5_mmio_write_irs_unimpl, 4, VGIC_ACCESS_32bit),
	REGISTER_DESC_WITH_LENGTH(
		GICV5_IRS_VMAP_L2_VMTR, vgic_v5_mmio_read_irs_unimpl,
		vgic_v5_mmio_write_irs_unimpl, 8, VGIC_ACCESS_64bit),
	REGISTER_DESC_WITH_LENGTH(
		GICV5_IRS_VMAP_VMR, vgic_v5_mmio_read_irs_unimpl,
		vgic_v5_mmio_write_irs_unimpl, 8, VGIC_ACCESS_64bit),
	REGISTER_DESC_WITH_LENGTH(
		GICV5_IRS_VMAP_VISTR, vgic_v5_mmio_read_irs_unimpl,
		vgic_v5_mmio_write_irs_unimpl, 8, VGIC_ACCESS_64bit),
	REGISTER_DESC_WITH_LENGTH(
		GICV5_IRS_VMAP_L2_VISTR, vgic_v5_mmio_read_irs_unimpl,
		vgic_v5_mmio_write_irs_unimpl, 8, VGIC_ACCESS_64bit),
	REGISTER_DESC_WITH_LENGTH(
		GICV5_IRS_VMAP_VPER, vgic_v5_mmio_read_irs_unimpl,
		vgic_v5_mmio_write_irs_unimpl, 8, VGIC_ACCESS_64bit),
	REGISTER_DESC_WITH_LENGTH(
		GICV5_IRS_SAVE_VMR, vgic_v5_mmio_read_irs_unimpl,
		vgic_v5_mmio_write_irs_unimpl, 8, VGIC_ACCESS_64bit),
	REGISTER_DESC_WITH_LENGTH(
		GICV5_IRS_SAVE_VM_STATUSR, vgic_v5_mmio_read_irs_unimpl,
		vgic_v5_mmio_write_irs_unimpl, 4, VGIC_ACCESS_32bit),

	/* MEC, MPAM, SWERR - all unimplimented */

	REGISTER_DESC_WITH_LENGTH(
		GICV5_IRS_MEC_IDR, vgic_v5_mmio_read_irs_unimpl,
		vgic_v5_mmio_write_irs_unimpl, 4, VGIC_ACCESS_32bit),
	REGISTER_DESC_WITH_LENGTH(
		GICV5_IRS_MEC_MECID_R, vgic_v5_mmio_read_irs_unimpl,
		vgic_v5_mmio_write_irs_unimpl, 4, VGIC_ACCESS_32bit),
	REGISTER_DESC_WITH_LENGTH(
		GICV5_IRS_MPAM_IDR, vgic_v5_mmio_read_irs_unimpl,
		vgic_v5_mmio_write_irs_unimpl, 4, VGIC_ACCESS_32bit),
	REGISTER_DESC_WITH_LENGTH(
		GICV5_IRS_MPAM_PARTID_R, vgic_v5_mmio_read_irs_unimpl,
		vgic_v5_mmio_write_irs_unimpl, 4, VGIC_ACCESS_32bit),
	REGISTER_DESC_WITH_LENGTH(
		GICV5_IRS_SWERR_STATUSR, vgic_v5_mmio_read_irs_unimpl,
		vgic_v5_mmio_write_irs_unimpl, 8, VGIC_ACCESS_64bit),
	REGISTER_DESC_WITH_LENGTH(
		GICV5_IRS_SWERR_SYNDROMER0, vgic_v5_mmio_read_irs_unimpl,
		vgic_v5_mmio_write_irs_unimpl, 8, VGIC_ACCESS_64bit),
	REGISTER_DESC_WITH_LENGTH(
		GICV5_IRS_SWERR_SYNDROMER1, vgic_v5_mmio_read_irs_unimpl,
		vgic_v5_mmio_write_irs_unimpl, 8, VGIC_ACCESS_64bit),
};

unsigned int vgic_v5_init_irs_iodev(struct vgic_io_device *dev)
{
	dev->regions = vgic_v5_irs_registers;
	dev->nr_regions = ARRAY_SIZE(vgic_v5_irs_registers);

	kvm_iodevice_init(&dev->dev, &kvm_io_gic_ops);

	/* We represent both of the IRS frames back to back, so this is 128K */
	return KVM_VGIC_V5_IRS_SIZE;
}

int vgic_v5_register_irs_iodev(struct kvm *kvm, gpa_t irs_base_address)
{
	struct vgic_io_device *io_device =
		&kvm->arch.vgic.vgic_v5_irs_data->iodev;
	unsigned int len;

	/*
	 * Design choice (?): Force MMIO region to be 64k aligned. Simplifies
	 * pulling out registers.
	 */
	if (!IS_ALIGNED(irs_base_address, SZ_64K)) {
		kvm_err("IRS Base address is not aligned to 64k\n");
		return -EINVAL;
	}

	len = vgic_v5_init_irs_iodev(io_device);

	io_device->base_addr = irs_base_address;
	io_device->iodev_type = IODEV_GICV5_IRS;
	io_device->redist_vcpu = NULL;

	return kvm_io_bus_register_dev(kvm, KVM_MMIO_BUS, irs_base_address, len,
				       &io_device->dev);
}

/**
 * kvm_vgic_v5_irs_init: initialize the IRS data structures
 * @kvm: kvm struct pointer
 * @nr_spis: number of spis, frozen by caller
 */
int kvm_vgic_v5_irs_init(struct kvm *kvm, unsigned int nr_spis)
{
	struct vgic_dist *dist = &kvm->arch.vgic;
	struct vgic_v5_irs *irs = dist->vgic_v5_irs_data;
	struct kvm_vcpu *vcpu0 = kvm_get_vcpu(kvm, 0);
	int i;
	phys_addr_t spi_ist_phys_base;
	size_t istsz, nr_spi_bits, istmd_sz, ist_l2sz;
	u64 mmfr0;
	int ret = 0;

	INIT_LIST_HEAD(&dist->vgic_v5_spi_ap_list_head);
	raw_spin_lock_init(&dist->vgic_v5_spi_ap_list_lock);

	/*
	 * We (KVM) allocate an Interrupt State Table (IST) for SPIs. The
	 * hardware mandates that lower 6 bits of the address are 0. Each ISTE
	 * is 4 bytes in size (or larger if metadata storage is required). In
	 * order to simplify the allocation logic, we round up the minimum
	 * number of SPIs to 16 (2^6 = 64, 64/4 = 16).
	 */
	if (nr_spis && nr_spis < 16)
		nr_spis = 16;

	if (nr_spis) {
		dist->spis = kcalloc(nr_spis, sizeof(struct vgic_irq),
				     GFP_KERNEL_ACCOUNT);
		if (!dist->spis)
			return -ENOMEM;

		/*
		 * In the following code we do not take the irq struct lock since
		 * no other action on irq structs can happen while the VGIC is
		 * not initialized yet:
		 * If someone wants to inject an interrupt or does a MMIO access,
		 * we require prior initialization in case of a virtual GICv3.
		 */
		for (i = 0; i < nr_spis; i++) {
			struct vgic_irq *irq = &dist->spis[i];

			/*
			 * We use the full GICv5-style IntID here, rather than
			 * just the index of the SPI. This helps to correctly
			 * identify the interrupt when injecting it.
			 */
			irq->intid = i | FIELD_PREP(GICV5_HWIRQ_TYPE,
						    GICV5_HWIRQ_TYPE_SPI);
			INIT_LIST_HEAD(&irq->ap_list);
			raw_spin_lock_init(&irq->irq_lock);
			irq->vcpu = NULL;
			irq->target_vcpu = vcpu0;
			refcount_set(&irq->refcount, 0);
			/*
			 * The guest controls the enable state, and again it is
			 * directly handled by the hardware. From our point of
			 * view it is always enabled.
			 */
			irq->enabled = 1;
			vgic_v5_set_spi_ops(irq);
		}

		nr_spi_bits = fls(roundup_pow_of_two(nr_spis)) - 1;

		istsz = GICV5_IRS_IST_CFGR_ISTSZ_4;
		if (vgic_v5_host_caps()->istmd) {
			istmd_sz = vgic_v5_host_caps()->istmd_sz;

			if (nr_spi_bits < istmd_sz)
				istsz = GICV5_IRS_IST_CFGR_ISTSZ_8;
			else
				istsz = GICV5_IRS_IST_CFGR_ISTSZ_16;
		}

		ret = vgic_v5_spi_ist_allocate(kvm, &spi_ist_phys_base,
					      nr_spi_bits, istsz);
		if (ret)
			return ret;

		ret = vgic_v5_vmte_assign_ist(kvm, spi_ist_phys_base, false,
					     nr_spi_bits, ist_l2sz, istsz,
					     true);
		if (ret)
			return ret;
	}

	irs->idr0.domain = GICV5_IRS_IDR0_DOMAIN_NON_SECURE;

	mmfr0 = read_sanitised_ftr_reg(SYS_ID_AA64MMFR0_EL1);
	irs->idr0.pa_range = cpuid_feature_extract_unsigned_field(
		mmfr0, ID_AA64MMFR0_EL1_PARANGE_SHIFT);

	irs->idr0.virt = 0;
	irs->idr0.one_of_n = 0;
	irs->idr0.virt_one_of_n = 0;
	irs->idr0.setlpi = 1;
	irs->idr0.mec = 0;
	irs->idr0.mpam = 0;
	irs->idr0.swe = 0;
	irs->idr0.irs_id = 0;
	/*
	 * Zero means uninitialised - the value gets populated when first read.
	 * There is a chance that more PEs are created after this point so it is
	 * too early to init this.
	 */
	irs->idr1.num_pes = 0;
	irs->idr1.priority_bits = gicv5_global_data.irs_pri_bits - 1;

	/* We match the host here, by default */
	irs->idr2.id_bits = vgic_v5_host_caps()->ist_id_bits;
	irs->idr2.min_lpi_id_bits = vgic_v5_host_caps()->min_ist_id_bits;
	/* Only allow the guest to create Linear ISTs - simplifies Save/Restore */
	irs->idr2.ist_levels = 0;
	irs->idr2.ist_l2sz = GICV5_IRS_IST_CFGR_L2SZ_4K;
	irs->idr2.istmd = 0;
	irs->idr2.istmd_sz = 0;

	/* We don't support nested virt - init to 0 */
	irs->idr3.vmd = false;
	irs->idr3.vmd_size = 0;
	irs->idr3.vm_id_bits = 0;
	irs->idr3.vmt_levels = 0;

	/* We don't support nested virt - init to 0 */
	irs->idr4.vped_size = 0;
	irs->idr4.vpe_id_bits = 0;

	irs->idr5.spi_range = nr_spis;

	irs->idr6.spi_irs_range = nr_spis;

	irs->idr7.spi_base = 0;

	irs->cr1.sh = 0;
	irs->cr1.oc = 0;
	irs->cr1.ic = 0;
	irs->cr1.ist_ra = 0;
	irs->cr1.ist_wa = 0;
	irs->cr1.vmt_ra = 0;
	irs->cr1.vpet_ra = 0;
	irs->cr1.vmd_ra = 0;
	irs->cr1.vmd_wa = 0;
	irs->cr1.vped_ra = 0;
	irs->cr1.vped_wa = 0;

	irs->spi_selr.id = -1;

	irs->spi_statusr.fault = false;

	irs->pe_selr.iaffid = -1;

	irs->ist_cfgr.lpi_id_bits = 0;
	irs->ist_cfgr.l2sz = 0;
	irs->ist_cfgr.istsz = 0;
	irs->ist_cfgr.structure = 0;

	irs->ist_baser.valid = 0;
	irs->ist_baser.addr = 0;

	irs->inv_istr.id = 0;
	irs->inv_istr.type = 0;
	irs->inv_istr.vm_id = 0;
	irs->inv_istr.virt = 0;
	irs->inv_istr.v = 0;

	return ret;
}

int vgic_v5_has_attr_regs(struct kvm_device *dev, struct kvm_device_attr *attr)
{
	const struct vgic_register_region *region;
	struct vgic_reg_attr reg_attr;
	struct kvm_vcpu *vcpu;
	gpa_t addr, offset;
	int ret, align;

	ret = vgic_v5_parse_attr(dev, attr, &reg_attr);
	if (ret)
		return ret;

	vcpu = reg_attr.vcpu;
	addr = reg_attr.addr;

	if (attr->group == KVM_DEV_ARM_VGIC_GRP_CPU_SYSREGS)
		return vgic_v5_has_cpu_sysregs_attr(vcpu, attr);

	offset = attr->attr;

	if (IS_VGIC_ADDR_UNDEF(dev->kvm->arch.vgic.vgic_v5_irs_base)) {
		return -ENXIO;
	}

	region = vgic_find_mmio_region(vgic_v5_irs_registers,
				       ARRAY_SIZE(vgic_v5_irs_registers),
				       offset);
	if (!region) {
		return -ENXIO;
	}

	align = region->access_flags & VGIC_ACCESS_64bit ? 0x7 : 0x3;
	if (offset & align)
		return -EINVAL;

	return 0;
}

/*
 * Access the IRS MMIO Regs. Relevant locks have been taken by the calling code.
 */
int vgic_v5_irs_attr_regs_access(struct kvm_device *dev,
				 struct kvm_device_attr *attr,
				 u64 *reg, bool is_write)
{
	const struct vgic_register_region *region;
	gpa_t addr, offset;
	unsigned int len;
	int align, ret = 0;

	offset = attr->attr;

	if (IS_VGIC_ADDR_UNDEF(dev->kvm->arch.vgic.vgic_v5_irs_base)) {
		return -ENXIO;
	}

	region = vgic_find_mmio_region(vgic_v5_irs_registers,
				       ARRAY_SIZE(vgic_v5_irs_registers),
				       offset);
	if (!region) {
		return -ENXIO;
	}

	/*
	 * Although the spec supports upper/lower 32-bit accesses to
	 * 64-bit IRS registers, the userspace ABI requires 64-bit
	 * accesses to all 64-bit wide registers. We therefore only
	 * support 32-bit accesses to 32-bit-wide registers.
	 */
	align = region->access_flags & VGIC_ACCESS_64bit ? 0x7 : 0x3;
	len = region->access_flags & VGIC_ACCESS_64bit ? 8 : 4;

	if (offset & align)
		return -EINVAL;

	addr = dev->kvm->arch.vgic.vgic_v5_irs_base + offset;

	if (is_write) {
		if (region->uaccess_write)
			ret = region->uaccess_write(kvm_get_vcpu(dev->kvm, 0),
						    addr, len, *reg);
		else
			region->write(kvm_get_vcpu(dev->kvm, 0), addr, len, *reg);
	} else {
		*reg = region->read(kvm_get_vcpu(dev->kvm, 0), addr, len);
	}

	return ret;
}
