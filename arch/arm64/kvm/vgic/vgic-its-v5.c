/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2025 ARM Limited, All Rights Reserved.
 */

#include <linux/hashtable.h>
#include <linux/highmem.h>
#include <linux/kernel.h>
#include <linux/kvm_host.h>
#include <linux/mm.h>
#include <linux/sizes.h>
#include <linux/slab.h>

#include <asm/io.h>
#include <asm/kvm_arm.h>
#include <asm/kvm_mmu.h>

#include <kvm/arm_vgic.h>

#include <linux/irqchip/arm-gic-v5.h>

#include "vgic.h"
#include "vgic-mmio.h"

struct its_cache_translation_entry {
	struct hlist_node node;
	u64 key;
	u32 lpi;
};

static int its_cache_add_translation(struct vgic_v5_its *its, u32 device_id,
				     u16 event_id, u32 lpi)
{
	struct its_cache_translation_entry *entry;
	entry = kzalloc(sizeof(*entry), GFP_KERNEL);
	if (entry == NULL)
		return -ENOMEM;

	entry->key = (u64)device_id << 16;
	entry->key |= (u64)event_id;
	entry->lpi = lpi;

	hash_add(its->translation_cache, &entry->node, entry->key);
	return 0;
}

static int its_cache_remove_translation(struct vgic_v5_its *its, u32 device_id,
				 u16 event_id)
{
	struct its_cache_translation_entry *entry;
	struct hlist_node *tmp;
	u64 key = ((u64)device_id << 16) | (u64)event_id;

	hash_for_each_possible_safe(its->translation_cache, entry, tmp,
				    node, key) {
		if (entry->key == key) {
			hash_del(&entry->node);
			kfree(entry);
			return 0;
		}
	}

	/* No warning as this can be called speculatively via ITS MMIO IF */
	return -EINVAL;
}

static void its_cache_clear_translations(struct vgic_v5_its *its)
{
	int bkt;
	struct its_cache_translation_entry *entry;
	struct hlist_node *tmp;

	hash_for_each_safe(its->translation_cache, bkt, tmp, entry, node) {
		hash_del(&entry->node);
		kfree(entry);
	}

	BUG_ON(!hash_empty(its->translation_cache));

	return;
}

static int its_cache_look_up_translation(struct vgic_v5_its *its,
					 u32 device_id, u16 event_id, u32 *lpi)
{
	struct its_cache_translation_entry *entry;
	u64 key = ((u64)device_id << 16) | (u64)event_id;

	hash_for_each_possible(its->translation_cache, entry, node, key) {
		if (entry->key == key) {
			/* Success! */
			*lpi = entry->lpi;
			return 0;
		}
	}

	return -ENXIO;
}

/*
 * Invalidate all cached translations for the specific device_id provided. We
 * only invalidate events that can be represented with the given number of
 * event_id_bits. The expectation is that event_id_bits would match the ITT
 * size, but this isn't guranteed in the spec.
*/
static void its_cache_handle_inv_devicer_l2(struct vgic_v5_its *its,
					    u32 device_id, u8 event_id_bits)
{
	int bkt;
	struct its_cache_translation_entry *entry;
	struct hlist_node *tmp;
	u64 event_id_limit;

	/* Calculate the first event_id that should NOT be invalidated */
	if (event_id_bits > 16)
		event_id_bits = 16;
	event_id_limit = (1ULL << event_id_bits);

	hash_for_each_safe(its->translation_cache, bkt, tmp, entry, node) {
		/*
		 * Free entry if the DeviceID matches and if the EventID is
		 * lower than the first that shouldn't be affected.
		 */
		if ((entry->key >> 16 == device_id) &&
		    ((entry->key & 0xFFFFULL) < event_id_limit)) {
			hash_del(&entry->node);
			kfree(entry);
		}
	}
}

/*
 * Invalidate all cached translations for all device_ids covered by an L1 DT
 * entry.
 */
static void its_cache_handle_inv_devicer_l1(struct vgic_v5_its *its,
					    u32 device_id, u8 l2sz)
{
	int bkt;
	struct its_cache_translation_entry *entry;
	struct hlist_node *tmp;
	u8 device_id_split_bits;
	u32 device_id_mask;

	/*
	 * Mask off the lower device_id bits, retaining only those used to index
	 * the L1 entry. Any device_id that matches these upper bits is covered
	 * by the same L1 DT entry, and hence should be invalidated.
	 */
	switch (l2sz) {
	case 0:
		device_id_split_bits = 9;
		break;
	case 1:
		device_id_split_bits = 11;
		break;
	case 2:
		device_id_split_bits = 13;
		break;
	default:
		BUG();
	}

	device_id_mask = ~((1U << device_id_split_bits) - 1);
	device_id &= device_id_mask;

	hash_for_each_safe(its->translation_cache, bkt, tmp, entry, node) {
		/*
		 * Free entry if the upper part of the DeviceID matches and if
		 * the EventID is in range.
		 */
		if (((entry->key >> 16) & device_id_mask) == device_id) {
			hash_del(&entry->node);
			kfree(entry);
		}
	}
}

static void its_cache_handle_inv_devicer(struct vgic_v5_its *its)
{
	u32 device_id = its->didr.device_id;
	u8 event_id_bits = its->inv_devicer.event_id_bits;
	bool l1 = its->inv_devicer.l1;
	u8 l2sz = its->dt_cfgr.l2sz;
	bool structure = its->dt_cfgr.structure;

	/* L1 being set makes no sense for a single-level structure */
	if (!structure)
		l1 = false;

	if (!l1) {
		its_cache_handle_inv_devicer_l2(its, device_id, event_id_bits);
	} else {
		its_cache_handle_inv_devicer_l1(its, device_id, l2sz);
	}
}

/*
 * Invalidate all event_ids that are covered by the same L1 ITTE for a specific
 * device_id.
 */
static void its_cache_handle_inv_eventr_l1(struct vgic_v5_its *its,
					   u32 device_id, u16 event_id,
					   u8 itt_l2sz)
{
	int bkt;
	struct its_cache_translation_entry *entry;
	struct hlist_node *tmp;
	u8 lower_event_id_bit;
	u16 event_id_mask;

	/*
	 * Mask off the lower event_id bits, retaining only those used to index
	 * the L1 ITT entry. Any event_id that matches these upper bits is
	 * covered by the same L1 ITT entry, and hence should be invalidated.
	 */
	switch (itt_l2sz) {
	case 0:
		lower_event_id_bit = 9;
		break;
	case 1:
		lower_event_id_bit = 11;
		break;
	case 2:
		lower_event_id_bit = 13;
		break;
	default:
		BUG();
	}
	event_id_mask = (u16)((0xffffU << lower_event_id_bit) & 0xffffU);
	event_id &= event_id_mask;

	hash_for_each_safe(its->translation_cache, bkt, tmp, entry, node) {
		/*
		 * Free entry if the DeviceID matches and if the entry's EventID
		 * matches the masked EventID (falls into the same L1 ITT).
		 */
		if ((entry->key >> 16 == device_id) &&
		    ((entry->key & event_id_mask) == event_id)) {
			hash_del(&entry->node);
			kfree(entry);
		}
	}
}

static void its_cache_handle_inv_eventr(struct vgic_v5_its *its)
{
	u32 device_id = its->didr.device_id;
	u16 event_id = its->eidr.event_id;
	u8 itt_l2sz = its->inv_eventr.itt_l2sz;
	bool l1 = its->inv_eventr.l1;

	if (l1 == false) {
		/* Single Event - reuse the existing interface */
		its_cache_remove_translation(its, device_id, event_id);
	} else {
		its_cache_handle_inv_eventr_l1(its, device_id, event_id,
			itt_l2sz);
	}
}

/******************************************************************************/

static int parse_linear_dt(struct kvm *kvm, gpa_t dt_base, u32 device_id,
			   gpa_t *itt_base, bool *two_level_itt,
			   unsigned *event_id_bits, unsigned *itt_l2sz)
{
	int ret;
	__le64 dt_l2_entry;
	gpa_t entry_addr;

	entry_addr = dt_base + device_id * sizeof(__le64);

	ret = kvm_read_guest_lock(kvm, entry_addr, &dt_l2_entry,
				  sizeof(__le64));
	if (ret) {
		kvm_err("Failed to read guest memory for L2 DT!");
		return ret;
	}

	if (!FIELD_GET(GICV5_DTL2E_VALID, dt_l2_entry)) {
		kvm_err("Guest DT entry is invalid!\n");
		return -EINVAL;
	}

	*itt_base = FIELD_GET(GICV5_DTL2E_ITT_ADDR_MASK, dt_l2_entry) << 3;
	*two_level_itt = FIELD_GET(GICV5_DTL2E_ITT_STRUCTURE, dt_l2_entry);
	*event_id_bits = FIELD_GET(GICV5_DTL2E_EVENT_ID_BITS, dt_l2_entry);
	*itt_l2sz = FIELD_GET(GICV5_DTL2E_ITT_L2SZ, dt_l2_entry);

	return ret;
}

static int parse_two_level_dt(struct kvm *kvm, gpa_t dt_base, unsigned dt_l2sz,
			      u32 device_id, gpa_t *itt_base,
			      bool *two_level_itt, unsigned *event_id_bits,
			      unsigned *itt_l2sz)
{
	int ret;
	__le64 dt_l1_entry;
	unsigned device_id_l1_shift, l2_device_id;
	gpa_t dt_l2_base;
	gpa_t entry_addr;

	if (dt_l2sz == 0) {
		// 9 bits for L2 table (4kB)
		device_id_l1_shift = 9;
	} else if (dt_l2sz == 1) {
		// 11 bits for L2 table (16kB)
		device_id_l1_shift = 11;
	} else if (dt_l2sz == 2) {
		// 13 bits for L2 table (64kB)
		device_id_l1_shift = 13;
	}

	entry_addr = dt_base +
		     (device_id >> device_id_l1_shift) * sizeof(__le64);

	ret = kvm_read_guest_lock(kvm, entry_addr, &dt_l1_entry,
				  sizeof(__le64));
	if (ret) {
		kvm_err("Failed to read guest memory for L1 DT!");
		return ret;
	}

	if (!FIELD_GET(GICV5_DTL1E_VALID, dt_l1_entry)) {
		kvm_err("Guest DT L1 entry is invalid!\n");
		return -EINVAL;
	}

	dt_l2_base = FIELD_GET(GICV5_DTL1E_L2_ADDR_MASK, dt_l1_entry) << 3;
	l2_device_id = device_id % (1UL << device_id_l1_shift);
	if (l2_device_id >= (1UL << FIELD_GET(GICV5_DTL1E_SPAN, dt_l1_entry))) {
		kvm_err("DeviceID 0x%x out of range of guest DT\n", device_id);
		return -ENXIO;
	}

	return parse_linear_dt(kvm, dt_l2_base, l2_device_id, itt_base,
			       two_level_itt, event_id_bits, itt_l2sz);
}

/*
 * Get the GPA for the ITT corresponding to device_id in the guest.
 */
static int get_itt(struct kvm *kvm, struct vgic_v5_its *its, u32 device_id,
		   gpa_t *itt_base, bool *two_level_itt,
		   unsigned *event_id_bits, unsigned *itt_l2sz)
{
	gpa_t dt_base;
	bool two_level_dt;
	unsigned dt_l2sz, device_id_bits;
	int ret;

	/*
	 * First of all, let's make sure that we have a valid ITS_DT_BASER. This
	 * MMIO register doesn't have a valid bit, so we assume that it is valid
	 * if the guest enabled the virtual ITS. This matches the expected
	 * behaviour of a HW device.
	 */
	if (its->enabled == 0) {
		kvm_err("Cannot look up LPI; vITS is disabled!\n");
		return -ENXIO;
	}

	/* The physical address of the DT in the guest */
	dt_base = its->dt_baser.addr;

	two_level_dt = its->dt_cfgr.structure;
	dt_l2sz = its->dt_cfgr.l2sz;
	device_id_bits = its->dt_cfgr.device_id_bits;

	if (device_id >= 1UL << device_id_bits) {
		kvm_err("Device ID out of range!\n");
		return -E2BIG;
	}

	if (!two_level_dt) {
		ret = parse_linear_dt(kvm, dt_base, device_id, itt_base,
				      two_level_itt, event_id_bits, itt_l2sz);
	} else {
		ret = parse_two_level_dt(kvm, dt_base, dt_l2sz, device_id,
					 itt_base, two_level_itt, event_id_bits,
					 itt_l2sz);
	}

	return ret;
}

static int parse_linear_itt(struct kvm *kvm, u32 event_id, gpa_t itt_base,
			    __le64 *itt_l2_entry)
{
	int ret = 0;
	gpa_t entry_addr = itt_base + event_id * sizeof(*itt_l2_entry);

	ret = kvm_read_guest_lock(kvm, entry_addr, itt_l2_entry,
				  sizeof(*itt_l2_entry));
	if (ret) {
		kvm_err("Failed to read guest memory for L2 ITT!");
		return ret;
	}

	return ret;
}

static int parse_two_level_itt(struct kvm *kvm, u32 event_id, gpa_t itt_base,
			       unsigned itt_l2sz, __le64 *itt_l2_entry)
{
	int ret = 0;
	__le64 itt_l1_entry;
	gpa_t itt_l2_base;
	unsigned itt_split_bits, l2_event_id_bits;
	u32 l1_event_id, l2_event_id;
	gpa_t entry_addr;

	if (itt_l2sz == 0) {
		// 9 bits for L2 table (4kB)
		itt_split_bits = 9;
	} else if (itt_l2sz == 1) {
		// 11 bits for L2 table (16kB)
		itt_split_bits = 11;
	} else if (itt_l2sz == 2) {
		// 13 bits for L2 table (64kB)
		itt_split_bits = 13;
	}

	/* Get the bits of the EventID used for L1 indexing */
	l1_event_id = event_id >> itt_split_bits;

	entry_addr = itt_base + l1_event_id * sizeof(itt_l1_entry);
	ret = kvm_read_guest_lock(kvm, entry_addr, &itt_l1_entry,
				  sizeof(itt_l1_entry));
	if (ret) {
		kvm_err("Failed to read guest memory for L1 ITT!");
		return ret;
	}

	if (!FIELD_GET(GICV5_ITTL1E_VALID, itt_l1_entry)) {
		kvm_err("Guest ITT L1 entry is invalid!\n");
		return -EINVAL;
	}

	itt_l2_base = FIELD_GET(GICV5_ITTL1E_L2_ADDR_MASK, itt_l1_entry) << 3;

	/*
	 * L2 event is limited by the min value of itt_split_bits and the span
	 * from the L1 entry.
	 */
	l2_event_id_bits =
		min(FIELD_GET(GICV5_ITTL1E_SPAN, itt_l1_entry), itt_split_bits);
	l2_event_id = event_id % (1UL << l2_event_id_bits);

	/*
	 * If the event is unreachable because it doesn't exist at L2 (span
	 * smaller than the number of L2 bits), we can't continue!
	 */
	if ((itt_split_bits != l2_event_id_bits) &&
	    (event_id % itt_split_bits) != l2_event_id) {
		kvm_err("EventID is out of range of L2 ITT!");
		return -ENXIO;
	}

	return parse_linear_itt(kvm, l2_event_id, itt_l2_base, itt_l2_entry);

	return ret;
}

static int get_itte(struct kvm *kvm, u32 event_id, gpa_t itt_base,
		    bool two_level_itt, unsigned itt_l2sz,
		    __le64 *itt_l2_entry)
{
	int ret = 0;

	if (!two_level_itt) {
		ret = parse_linear_itt(kvm, event_id, itt_base, itt_l2_entry);
	} else {
		ret = parse_two_level_itt(kvm, event_id, itt_base, itt_l2sz,
					  itt_l2_entry);
	}

	return ret;
}

struct vgic_v5_its *vgic_v5_msi_to_its(struct kvm *kvm, struct kvm_msi *msi)
{
	u64 address;
	struct kvm_io_device *kvm_io_dev;
	struct vgic_io_device *iodev;

	if (!vgic_has_its(kvm))
		return ERR_PTR(-ENODEV);

	if (!(msi->flags & KVM_MSI_VALID_DEVID))
		return ERR_PTR(-EINVAL);

	address = (u64)msi->address_hi << 32 | msi->address_lo;

	kvm_io_dev = kvm_io_bus_get_dev(kvm, KVM_MMIO_BUS, address);
	if (!kvm_io_dev)
		return ERR_PTR(-EINVAL);

	if (kvm_io_dev->ops != &kvm_io_gic_ops)
		return ERR_PTR(-EINVAL);

	iodev = container_of(kvm_io_dev, struct vgic_io_device, dev);
	if (iodev->iodev_type != IODEV_GICV5_ITS)
		return ERR_PTR(-EINVAL);

	return iodev->v5its;
}

/*
 * Iterate over the guest's DT and ITT to find the vLPI for a given DeviceID and
 * EventID pairing. This is used when injecting MSIs for a guest.
 */
int vgic_v5_its_look_up_lpi(struct kvm *kvm, struct vgic_v5_its *its,
			    u32 device_id, u16 event_id, u32 *lpi)
{
	int ret = 0;
	gpa_t itt_base;
	bool two_level_itt;
	unsigned itt_l2sz, event_id_bits;
	__le64 itt_l2_entry;

	/* Check if we have it cached */
	ret = its_cache_look_up_translation(its, device_id, event_id, lpi);
	if (!ret) {
		/* Success */
		return 0;
	}

	/*
	* Make sure that we have the correct context to look up the
	* translation in the guest's memory.
	*/
	BUG_ON(kvm->mm != get_current()->mm);

	ret = get_itt(kvm, its, device_id, &itt_base, &two_level_itt,
		      &event_id_bits, &itt_l2sz);
	if (ret) {
		kvm_err("Error parsing guest's DT\n");
		return ret;
	}

	if (event_id >= 1UL << event_id_bits) {
		kvm_err("Event ID out of range!\n");
		return -E2BIG;
	}

	ret = get_itte(kvm, event_id, itt_base, two_level_itt, itt_l2sz,
		       &itt_l2_entry);

	if (!FIELD_GET(GICV5_ITTL2E_VALID, itt_l2_entry)) {
		kvm_err("ITTE is not valid!\n");
		return -EINVAL;
	}

	*lpi = FIELD_GET(GICV5_ITTL2E_LPI_ID, itt_l2_entry);

	/* Remember it for next time */
	return its_cache_add_translation(its, device_id, event_id, *lpi);
}

int vgic_v5_its_inject_msi(struct kvm *kvm, struct kvm_msi *msi)
{
	struct vgic_v5_its *its;
	int ret;
	u32 lpi;

	/*
	 * Make sure that the addr in the MSI maps to something
	 * we'd expect.
	 */
	ret = vgic_v5_check_msi(kvm, msi, vgic_has_its(kvm));
	if (ret)
		return ret;

	its = vgic_v5_msi_to_its(kvm, msi);
	if (IS_ERR(its))
		return PTR_ERR(its);

	ret = vgic_v5_its_look_up_lpi(kvm, its, msi->devid, msi->data,
				      &lpi);
	if (ret)
		return ret;

	/* Make it into a proper GICv5 IntID */
	lpi &= GICV5_HWIRQ_ID;
	lpi |= FIELD_PREP(GICV5_HWIRQ_TYPE, GICV5_HWIRQ_TYPE_LPI);

	/*
	 * And inject it in to the guest. We do no tracking of LPI state, and
	 * instead rely on the hardware to manage the LPIS. As this is driven
	 * from the MSI path, all of the LPIs we inject are Edge, which makes
	 * this a fire-and-forget situation.
	 */
	kvm_call_hyp(__vgic_v5_vdpend, lpi, true, kvm->arch.vgic.gicv5_vm.vm_id);

	return 1;
}

int vgic_v5_its_inject_cached_translation(struct kvm *kvm, struct kvm_msi *msi)
{
	struct vgic_v5_its *its;
	int ret;
	u32 lpi;

	ret = vgic_v5_check_msi(kvm, msi, vgic_has_its(kvm));
	if (ret)
		return ret;

	its = vgic_v5_msi_to_its(kvm, msi);
	if (IS_ERR(its))
		return PTR_ERR(its);

	/* Check if we have it cached */
	ret = its_cache_look_up_translation(its, msi->devid, msi->data, &lpi);
	if (ret)
		return -EWOULDBLOCK;

	/* Make it into a proper GICv5 IntID */
	lpi &= GICV5_HWIRQ_ID;
	lpi |= FIELD_PREP(GICV5_HWIRQ_TYPE, GICV5_HWIRQ_TYPE_LPI);

	kvm_call_hyp(__vgic_v5_vdpend, lpi, true, kvm->arch.vgic.gicv5_vm.vm_id);

	return 0;
}

/******************************************************************************/

static unsigned long vgic_v5_mmio_read_its_misc(struct kvm *kvm, void *dev,
						gpa_t addr, unsigned int len)
{
	struct vgic_v5_its *its = dev;
	u64 value = 0;
	/*
	* Mask off the upper addr bits - we just want the offset into the MMIO
	* region.
	*/
	size_t offset = addr & (SZ_64K - 1);

	switch (offset) {
	case GICV5_ITS_IDR0:
		value = FIELD_PREP(GICV5_ITS_IDR0_ITSID, its->idr0.its_id);
		value |= FIELD_PREP(GICV5_ITS_IDR0_SWE, its->idr0.swe);
		value |= FIELD_PREP(GICV5_ITS_IDR0_MPAM, its->idr0.mpam);
		value |= FIELD_PREP(GICV5_ITS_IDR0_MEC, its->idr0.mec);
		value |= FIELD_PREP(GICV5_ITS_IDR0_PA_RANGE,
				    its->idr0.pa_range);
		value |= FIELD_PREP(GICV5_ITS_IDR0_DOM,
				    its->idr0.domain);
		break;
	case GICV5_ITS_IDR1:
		value = FIELD_PREP(GICV5_ITS_IDR1_L2SZ,
				   its->idr1.l2sz);
		value |= FIELD_PREP(GICV5_ITS_IDR1_ITT_LEVELS,
				    its->idr1.itt_levels);
		value |= FIELD_PREP(GICV5_ITS_IDR1_DT_LEVELS,
				    its->idr1.dt_levels);
		value |= FIELD_PREP(GICV5_ITS_IDR1_DEVICEID_BITS,
				    its->idr1.device_id_bits);
		break;
	case GICV5_ITS_IDR2:
		value = FIELD_PREP(GICV5_ITS_IDR2_XDMN_EVENTS,
				   its->idr2.xdmn_events);
		value = FIELD_PREP(GICV5_ITS_IDR2_EVENTID_BITS,
				   its->idr2.event_id_bits);
		break;
	case GICV5_ITS_IIDR:
		/* Revision, Variant, ProductID are implementation defined */
		value = FIELD_PREP(GICV5_ITS_IIDR_PRODUCT_ID, 0);
		value |= FIELD_PREP(GICV5_ITS_IIDR_VARIANT, 0);
		value |= FIELD_PREP(GICV5_ITS_IIDR_REVISION, 0);
		value |= FIELD_PREP(GICV5_ITS_IIDR_IMPLEMENTER,
				    GICV5_IIDR_IMPLEMENTER_ARM);
		break;
	case GICV5_ITS_AIDR:
		value = FIELD_PREP(GICV5_ITS_AIDR_COMPONENT,
				   GICV5_AIDR_COMPONENT_ITS);
		value |= FIELD_PREP(GICV5_ITS_AIDR_ARCHMAJORREV,
				    GICV5_AIDR_ARCH_MAJ_REV_V5);
		value |= FIELD_PREP(GICV5_ITS_AIDR_ARCHMINORREV,
				    GICV5_AIDR_ARCH_MIN_REV_V0);
		break;
	case GICV5_ITS_CR0:
		/* We are always idle */
		value = GICV5_ITS_CR0_IDLE;
		value |= FIELD_PREP(GICV5_ITS_CR0_ITSEN, its->enabled);
		break;
	case GICV5_ITS_CR1:
		value = FIELD_PREP(GICV5_ITS_CR1_ITT_RA, its->cr1.itt_ra);
		value |= FIELD_PREP(GICV5_ITS_CR1_DT_RA, its->cr1.dt_ra);
		value |= FIELD_PREP(GICV5_ITS_CR1_IC, its->cr1.ic);
		value |= FIELD_PREP(GICV5_ITS_CR1_OC, its->cr1.oc);
		value |= FIELD_PREP(GICV5_ITS_CR1_SH, its->cr1.sh);
		break;
	default:
		return 0;
	}

	return value;
}

static void vgic_v5_mmio_write_its_misc(struct kvm *kvm, void *dev, gpa_t addr,
					unsigned int len, unsigned long val)
{
	struct vgic_v5_its *its = dev;
	/*
	* Mask off the upper addr bits - we just want the offset into the MMIO
	* region.
	*/
	size_t offset = addr & (SZ_64K - 1);

	switch (offset) {
	case GICV5_ITS_CR0:
		if (FIELD_GET(GICV5_ITS_CR0_ITSEN, val)) {
			its->enabled = true;
		} else {
			its->enabled = false;
		}
		return;
	case GICV5_ITS_CR1:
		its->cr1.sh = FIELD_GET(GICV5_ITS_CR1_SH, val);
		its->cr1.oc = FIELD_GET(GICV5_ITS_CR1_OC, val);
		its->cr1.ic = FIELD_GET(GICV5_ITS_CR1_IC, val);
		its->cr1.dt_ra = FIELD_GET(GICV5_ITS_CR1_DT_RA, val);
		its->cr1.itt_ra = FIELD_GET(GICV5_ITS_CR1_ITT_RA, val);
		return;
	default:
		return;
	}
}

static unsigned long vgic_v5_mmio_read_its_dt_itt(struct kvm *kvm, void *dev,
						  gpa_t addr, unsigned int len)
{
	struct vgic_v5_its *its = dev;
	u64 value = 0;
	/*
	* Mask off the upper addr bits - we just want the offset into the MMIO
	* region.
	*/
	size_t offset = addr & (SZ_64K - 1);

	switch (offset) {
	case GICV5_ITS_DT_CFGR:
		value = FIELD_PREP(GICV5_ITS_DT_CFGR_STRUCTURE,
				   its->dt_cfgr.structure);
		value |= FIELD_PREP(GICV5_ITS_DT_CFGR_L2SZ,
				    its->dt_cfgr.l2sz);
		value |= FIELD_PREP(GICV5_ITS_DT_CFGR_DEVICEID_BITS,
				    its->dt_cfgr.device_id_bits);
		break;
	case GICV5_ITS_DT_BASER:
		value = FIELD_PREP(GICV5_ITS_DT_BASER_ADDR_MASK,
				   its->dt_baser.addr >>
					   GICV5_ITS_DT_BASER_ADDR_SHIFT);
		break;
	case GICV5_ITS_DIDR:
		value = FIELD_PREP(GICV5_ITS_DIDR_DEVICEID,
				   its->didr.device_id);
		break;
	case GICV5_ITS_EIDR:
		value = FIELD_PREP(GICV5_ITS_EIDR_EVENTID,
				   its->eidr.event_id);
		break;
	case GICV5_ITS_STATUSR:
		/* We are always idle */
		value = GICV5_ITS_STATUSR_IDLE;
		break;
	case GICV5_ITS_SYNC_STATUSR:
		/* We are always idle */
		value = GICV5_ITS_STATUSR_IDLE;
		break;
	case GICV5_ITS_READ_EVENT_DATAR:
		pr_warn("Read of ITS_READ_EVENT_DATAR is not implemented\n");
		break;
	case GICV5_ITS_GEN_EVENT_EIDR:
		value = FIELD_PREP(GICV5_ITS_GEN_EVENT_EIDR_EVENTID,
				   its->gen_event_eidr.event_id);
		break;
	case GICV5_ITS_GEN_EVENT_DIDR:
		value = FIELD_PREP(GICV5_ITS_GEN_EVENT_DIDR_DEVICEID,
				   its->gen_event_didr.device_id);
		break;
	case GICV5_ITS_GEN_EVENT_STATUSR:
		/* We are always idle */
		value = GICV5_ITS_GEN_EVENT_STATUSR_IDLE;
		break;
	default:
		return 0;
	}

	return value;
}

static void vgic_v5_mmio_write_its_dt_itt(struct kvm *kvm, void *dev,
					  gpa_t addr, unsigned int len,
					  unsigned long val)
{
	struct vgic_v5_its *its = dev;
	/*
	* Mask off the upper addr bits - we just want the offset into the MMIO
	* region.
	*/
	size_t offset = addr & (SZ_64K - 1);

	switch (offset) {
	case GICV5_ITS_DT_CFGR:
		its->dt_cfgr.device_id_bits =
			FIELD_GET(GICV5_ITS_DT_CFGR_DEVICEID_BITS, val);
		its->dt_cfgr.l2sz =
			FIELD_GET(GICV5_ITS_DT_CFGR_L2SZ, val);
		its->dt_cfgr.structure =
			FIELD_GET(GICV5_ITS_DT_CFGR_STRUCTURE, val);
		return;
	case GICV5_ITS_DT_BASER:
		its->dt_baser.addr =
			FIELD_GET(GICV5_ITS_DT_BASER_ADDR_MASK, val)
			<< GICV5_ITS_DT_BASER_ADDR_SHIFT;
		return;
	case GICV5_ITS_INV_DEVICER:
		its->inv_devicer.l1 =
			FIELD_GET(GICV5_ITS_INV_DEVICER_L1, val);
		its->inv_devicer.event_id_bits =
			FIELD_GET(GICV5_ITS_INV_DEVICER_EVENTID_BITS, val);
		its->inv_devicer.i =
			FIELD_GET(GICV5_ITS_INV_DEVICER_I, val);

		if (its->inv_devicer.i)
			its_cache_handle_inv_devicer(its);

		return;
	case GICV5_ITS_DIDR:
		its->didr.device_id =
			FIELD_GET(GICV5_ITS_DIDR_DEVICEID, val);
		return;
	case GICV5_ITS_EIDR:
		its->eidr.event_id =
			FIELD_GET(GICV5_ITS_EIDR_EVENTID, val);
		return;
	case GICV5_ITS_INV_EVENTR:
		its->inv_eventr.l1 =
			FIELD_GET(GICV5_ITS_INV_EVENTR_L1, val);
		its->inv_eventr.itt_l2sz =
		  FIELD_GET(GICV5_ITS_INV_EVENTR_ITT_L2SZ, val);
		its->inv_eventr.i = FIELD_GET(GICV5_ITS_INV_EVENTR_I, val);

		if (its->inv_eventr.i)
			its_cache_handle_inv_eventr(its);

		return;
	case GICV5_ITS_SYNCR:
		pr_warn("Write to ITS_SYNCR ignored\n");
		return;
	case GICV5_ITS_READ_EVENTR:
		pr_warn("Write to ITS_READ_EVENTR ignored\n");
		return;
	case GICV5_ITS_GEN_EVENT_EIDR:
		its->gen_event_eidr.event_id =
			FIELD_GET(GICV5_ITS_GEN_EVENT_EIDR_EVENTID, val);
		return;
	case GICV5_ITS_GEN_EVENT_DIDR:
		its->gen_event_didr.device_id =
			FIELD_GET(GICV5_ITS_GEN_EVENT_DIDR_DEVICEID, val);
		return;
	case GICV5_ITS_GEN_EVENTR:
		pr_warn("Write to ITS_GEN_EVENTR ignored\n");
		return;
	default:
		return;
	}
}

static unsigned long vgic_v5_mmio_read_its_unimpl(struct kvm *kvm, void *dev,
						  gpa_t addr, unsigned int len)
{
	/*
	* Mask off the upper addr bits - we just want the offset into the MMIO
	* region.
	*/
	size_t offset = addr & (SZ_64K - 1);

	pr_warn("Read from unimplemented ITS register at offset 0x%lx\n",
		offset);

	return 0;
}

static void vgic_v5_mmio_write_its_unimpl(struct kvm *kvm, void *dev,
					  gpa_t addr, unsigned int len,
					  unsigned long val)
{
	/*
	* Mask off the upper addr bits - we just want the offset into the MMIO
	* region.
	*/
	size_t offset = addr & (SZ_64K - 1);
	pr_warn("Write of 0x%lx to  unimplemented ITS register at offset "
		"0x%lx\n",
		val, offset);

	return;
}

static void vgic_v5_mmio_write_its_transl(struct kvm *kvm, void *dev,
					  gpa_t addr, unsigned int len,
					  unsigned long val)
{
	pr_warn("Write of 0x%lx to unimplemented ITS_(RL_)TRANSLATE register\n",
		val);

	return;
}

static unsigned long vgic_v5_mmio_read_its_raz(struct kvm *kvm, void *dev,
					       gpa_t addr, unsigned int len)
{
	return 0;
}

static void vgic_v5_mmio_write_its_wi(struct kvm *kvm, void *dev, gpa_t addr,
				      unsigned int len, unsigned long val)
{
	/* Ignore */
}

/* copied from vgic-its.c */
#define REGISTER_ITS_V5_DESC(off, rd, wr, length, acc)                 \
	{                                                              \
		.reg_offset = off, .len = length, .access_flags = acc, \
		.its_read = rd, .its_write = wr,                       \
	}

static const struct vgic_register_region vgic_v5_its_registers[] = {
	/*
	 * This is the ITS_CONFIG_FRAME.
	 */
	REGISTER_ITS_V5_DESC(GICV5_ITS_IDR0, vgic_v5_mmio_read_its_misc,
			     vgic_v5_mmio_write_its_wi, 4, VGIC_ACCESS_32bit),
	REGISTER_ITS_V5_DESC(GICV5_ITS_IDR1, vgic_v5_mmio_read_its_misc,
			     vgic_v5_mmio_write_its_wi, 4, VGIC_ACCESS_32bit),
	REGISTER_ITS_V5_DESC(GICV5_ITS_IDR2, vgic_v5_mmio_read_its_misc,
			     vgic_v5_mmio_write_its_wi, 4, VGIC_ACCESS_32bit),
	REGISTER_ITS_V5_DESC(GICV5_ITS_IIDR, vgic_v5_mmio_read_its_misc,
			     vgic_v5_mmio_write_its_wi, 4, VGIC_ACCESS_32bit),
	REGISTER_ITS_V5_DESC(GICV5_ITS_AIDR, vgic_v5_mmio_read_its_misc,
			     vgic_v5_mmio_write_its_wi, 4, VGIC_ACCESS_32bit),
	REGISTER_ITS_V5_DESC(GICV5_ITS_CR0, vgic_v5_mmio_read_its_misc,
			     vgic_v5_mmio_write_its_misc, 4, VGIC_ACCESS_32bit),
	REGISTER_ITS_V5_DESC(GICV5_ITS_CR1, vgic_v5_mmio_read_its_misc,
			     vgic_v5_mmio_write_its_misc, 4, VGIC_ACCESS_32bit),
	REGISTER_ITS_V5_DESC(GICV5_ITS_DT_BASER, vgic_v5_mmio_read_its_dt_itt,
			     vgic_v5_mmio_write_its_dt_itt, 8,
			     VGIC_ACCESS_64bit),
	REGISTER_ITS_V5_DESC(GICV5_ITS_DT_CFGR, vgic_v5_mmio_read_its_dt_itt,
			     vgic_v5_mmio_write_its_dt_itt, 4,
			     VGIC_ACCESS_32bit),
	REGISTER_ITS_V5_DESC(GICV5_ITS_DIDR, vgic_v5_mmio_read_its_dt_itt,
			     vgic_v5_mmio_write_its_dt_itt, 8,
			     VGIC_ACCESS_64bit),
	REGISTER_ITS_V5_DESC(GICV5_ITS_EIDR, vgic_v5_mmio_read_its_dt_itt,
			     vgic_v5_mmio_write_its_dt_itt, 4,
			     VGIC_ACCESS_32bit),
	REGISTER_ITS_V5_DESC(GICV5_ITS_INV_EVENTR, vgic_v5_mmio_read_its_raz,
			     vgic_v5_mmio_write_its_dt_itt, 4,
			     VGIC_ACCESS_32bit),
	REGISTER_ITS_V5_DESC(GICV5_ITS_INV_DEVICER, vgic_v5_mmio_read_its_raz,
			     vgic_v5_mmio_write_its_dt_itt, 4,
			     VGIC_ACCESS_32bit),
	REGISTER_ITS_V5_DESC(GICV5_ITS_READ_EVENTR, vgic_v5_mmio_read_its_raz,
			     vgic_v5_mmio_write_its_dt_itt, 4,
			     VGIC_ACCESS_32bit),
	REGISTER_ITS_V5_DESC(GICV5_ITS_READ_EVENT_DATAR,
			     vgic_v5_mmio_read_its_dt_itt,
			     vgic_v5_mmio_write_its_wi, 8, VGIC_ACCESS_64bit),
	REGISTER_ITS_V5_DESC(GICV5_ITS_STATUSR, vgic_v5_mmio_read_its_dt_itt,
			     vgic_v5_mmio_write_its_wi, 4, VGIC_ACCESS_32bit),
	REGISTER_ITS_V5_DESC(GICV5_ITS_SYNCR, vgic_v5_mmio_read_its_raz,
			     vgic_v5_mmio_write_its_dt_itt, 4,
			     VGIC_ACCESS_32bit),
	REGISTER_ITS_V5_DESC(GICV5_ITS_SYNC_STATUSR,
			     vgic_v5_mmio_read_its_dt_itt,
			     vgic_v5_mmio_write_its_wi, 4, VGIC_ACCESS_32bit),
	REGISTER_ITS_V5_DESC(
		GICV5_ITS_GEN_EVENT_DIDR, vgic_v5_mmio_read_its_dt_itt,
		vgic_v5_mmio_write_its_dt_itt, 8, VGIC_ACCESS_64bit),
	REGISTER_ITS_V5_DESC(
		GICV5_ITS_GEN_EVENT_EIDR, vgic_v5_mmio_read_its_dt_itt,
		vgic_v5_mmio_write_its_dt_itt, 4, VGIC_ACCESS_32bit),
	REGISTER_ITS_V5_DESC(GICV5_ITS_GEN_EVENTR, vgic_v5_mmio_read_its_raz,
			     vgic_v5_mmio_write_its_dt_itt, 4,
			     VGIC_ACCESS_32bit),
	REGISTER_ITS_V5_DESC(GICV5_ITS_GEN_EVENT_STATUSR,
			     vgic_v5_mmio_read_its_dt_itt,
			     vgic_v5_mmio_write_its_wi, 4, VGIC_ACCESS_32bit),
	REGISTER_ITS_V5_DESC(GICV5_ITS_MEC_IDR, vgic_v5_mmio_read_its_unimpl,
			     vgic_v5_mmio_write_its_wi, 4, VGIC_ACCESS_32bit),
	REGISTER_ITS_V5_DESC(
		GICV5_ITS_MEC_MECID_R, vgic_v5_mmio_read_its_unimpl,
		vgic_v5_mmio_write_its_unimpl, 4, VGIC_ACCESS_32bit),
	REGISTER_ITS_V5_DESC(GICV5_ITS_MPAM_IDR, vgic_v5_mmio_read_its_unimpl,
			     vgic_v5_mmio_write_its_wi, 4, VGIC_ACCESS_32bit),
	REGISTER_ITS_V5_DESC(
		GICV5_ITS_MPAM_PARTID_R, vgic_v5_mmio_read_its_unimpl,
		vgic_v5_mmio_write_its_unimpl, 4, VGIC_ACCESS_32bit),
	REGISTER_ITS_V5_DESC(
		GICV5_ITS_SWERR_STATUSR, vgic_v5_mmio_read_its_unimpl,
		vgic_v5_mmio_write_its_unimpl, 8, VGIC_ACCESS_64bit),
	REGISTER_ITS_V5_DESC(
		GICV5_ITS_SWERR_SYNDROMER0, vgic_v5_mmio_read_its_unimpl,
		vgic_v5_mmio_write_its_unimpl, 8, VGIC_ACCESS_64bit),
	REGISTER_ITS_V5_DESC(
		GICV5_ITS_SWERR_SYNDROMER1, vgic_v5_mmio_read_its_unimpl,
		vgic_v5_mmio_write_its_unimpl, 8, VGIC_ACCESS_64bit),

	/*
	* This is the ITS_TRANSLATE_FRAME. For simplicity, this is offset by
	* 64k relative to the config frame in this KVM implementation.
	*/
	REGISTER_ITS_V5_DESC(
		GICV5_ITS_TRANSLATER + SZ_64K, vgic_v5_mmio_read_its_raz,
		vgic_v5_mmio_write_its_transl, 4, VGIC_ACCESS_32bit),
	REGISTER_ITS_V5_DESC(
		GICV5_ITS_RL_TRANSLATER + SZ_64K, vgic_v5_mmio_read_its_raz,
		vgic_v5_mmio_write_its_transl, 4, VGIC_ACCESS_32bit),

};

/******************************************************************************/

static int vgic_v5_its_create(struct kvm_device *dev, u32 type)
{
	struct vgic_v5_its *its;
	u64 mmfr0;

	if (type != KVM_DEV_TYPE_ARM_VGIC_V5_ITS)
		return -ENODEV;

	its = kzalloc(sizeof(struct vgic_v5_its), GFP_KERNEL_ACCOUNT);
	if (!its)
		return -ENOMEM;

	mutex_lock(&dev->kvm->arch.config_lock);

	/*
	 * TODO: Init ITS defaults with good values. Many of these should be
	 * populated using the real ITS registers
	 */

	its->idr0.domain = GICV5_IRS_IDR0_DOMAIN_NON_SECURE;

	mmfr0 = read_sanitised_ftr_reg(SYS_ID_AA64MMFR0_EL1);
	its->idr0.pa_range = cpuid_feature_extract_unsigned_field(
		mmfr0, ID_AA64MMFR0_EL1_PARANGE_SHIFT);

	its->idr0.mec = 0;
	its->idr0.mpam = 0;
	its->idr0.swe = 0;
	its->idr0.its_id = 0;

	/* TODO: Should we just match the host here? */
	its->idr1.device_id_bits = 20;
	/*
	 * Allow the guest to create a single- or two-level DT & ITT. It doesn't
	 * matter if the HW supports that or not as we only ever traverse these
	 * guest structures in Software.
	 */
	its->idr1.dt_levels = 1;
	its->idr1.itt_levels = 1;
	its->idr1.l2sz = 0;

	/* TODO: Should we just match the host here? */
	its->idr2.event_id_bits = 10;
	its->idr2.xdmn_events = 0;

	/* A sane default value for the ITS_DT_BASER */
	its->dt_baser.addr = 0;

	/* Initialise the translation cache */
	hash_init(its->translation_cache);

	its->vgic_v5_its_base = VGIC_ADDR_UNDEF;
	its->enabled = false;
	its->dev = dev;

	dev->kvm->arch.vgic.msis_require_devid = true;
	dev->kvm->arch.vgic.has_its = true;
	dev->private = its;

	mutex_unlock(&dev->kvm->arch.config_lock);

	return 0;
}

static void vgic_v5_its_destroy(struct kvm_device *kvm_dev)
{
	struct vgic_v5_its *its = kvm_dev->private;

	its_cache_clear_translations(its);

	kfree(its);
	kfree(kvm_dev); /* alloc by kvm_ioctl_create_device, free by .destroy */
}

static int vgic_v5_register_its_iodev(struct kvm *kvm, struct vgic_v5_its *its,
				      u64 addr)
{
	struct vgic_io_device *iodev = &its->iodev;
	int ret;

	mutex_lock(&kvm->slots_lock);
	if (!IS_VGIC_ADDR_UNDEF(its->vgic_v5_its_base)) {
		ret = -EBUSY;
		goto out;
	}

	if (!IS_ALIGNED(addr, SZ_64K)) {
		kvm_err("ITS Base address is not aligned to 64k\n");
		ret = -EINVAL;
		goto out;
	}

	its->vgic_v5_its_base = addr;
	iodev->base_addr = addr;
	iodev->regions = vgic_v5_its_registers;
	iodev->nr_regions = ARRAY_SIZE(vgic_v5_its_registers);
	iodev->iodev_type = IODEV_GICV5_ITS;
	iodev->redist_vcpu = NULL;
	iodev->v5its = its;
	kvm_iodevice_init(&iodev->dev, &kvm_io_gic_ops);

	ret = kvm_io_bus_register_dev(kvm, KVM_MMIO_BUS, iodev->base_addr,
				      KVM_VGIC_V5_ITS_SIZE, &iodev->dev);
out:
	mutex_unlock(&kvm->slots_lock);

	return ret;
}

static int vgic_v5_its_has_attr_regs(struct kvm_device *dev, struct kvm_device_attr *attr)
{
	struct vgic_v5_its *its = dev->private;
	const struct vgic_register_region *region;
	gpa_t offset;
	int align;

	offset = attr->attr;

	if (IS_VGIC_ADDR_UNDEF(its->vgic_v5_its_base)) {
		return -ENXIO;
	}

	region = vgic_find_mmio_region(vgic_v5_its_registers,
				       ARRAY_SIZE(vgic_v5_its_registers),
				       offset);
	if (!region) {
		return -ENXIO;
	}

	align = region->access_flags & VGIC_ACCESS_64bit ? 0x7 : 0x3;
	if (offset & align)
		return -EINVAL;

	return 0;
}

static int vgic_v5_its_attr_regs_access(struct kvm_device *dev,
				 struct kvm_device_attr *attr,
				 u64 *reg, bool is_write)
{
	const struct vgic_register_region *region;
	struct vgic_v5_its *its;
	gpa_t addr, offset;
	unsigned int len;
	int align, ret = 0;

	its = dev->private;
	offset = attr->attr;

	mutex_lock(&dev->kvm->lock);

	if (kvm_trylock_all_vcpus(dev->kvm)) {
		mutex_unlock(&dev->kvm->lock);
		return -EBUSY;
	}

	mutex_lock(&dev->kvm->arch.config_lock);

	if (IS_VGIC_ADDR_UNDEF(its->vgic_v5_its_base)) {
		ret = -ENXIO;
		goto out;
	}

	region = vgic_find_mmio_region(vgic_v5_its_registers,
				       ARRAY_SIZE(vgic_v5_its_registers),
				       offset);
	if (!region) {
		ret = -ENXIO;
		goto out;
	}

	/*
	 * Although the spec supports upper/lower 32-bit accesses to
	 * 64-bit ITS registers, the userspace ABI requires 64-bit
	 * accesses to all 64-bit wide registers. We therefore only
	 * support 32-bit accesses to 32-bit-wide registers.
	 */
	align = region->access_flags & VGIC_ACCESS_64bit ? 0x7 : 0x3;
	len = region->access_flags & VGIC_ACCESS_64bit ? 8 : 4;

	if (offset & align)
		return -EINVAL;

	addr = its->vgic_v5_its_base + offset;

	if (is_write) {
		region->its_write(dev->kvm, its, addr, len, *reg);
	} else {
		*reg = region->its_read(dev->kvm, its, addr, len);
	}
out:
	mutex_unlock(&dev->kvm->arch.config_lock);
	kvm_unlock_all_vcpus(dev->kvm);
	mutex_unlock(&dev->kvm->lock);

	return ret;
}

static int vgic_v5_its_ctrl(struct kvm *kvm, struct vgic_v5_its *its, u64 attr)
{
	int ret = 0;

	if (attr == KVM_DEV_ARM_VGIC_CTRL_INIT) /* Nothing to do */
		return 0;

	mutex_lock(&kvm->lock);

	if (kvm_trylock_all_vcpus(kvm)) {
		mutex_unlock(&kvm->lock);
		return -EBUSY;
	}

	mutex_lock(&kvm->arch.config_lock);
	//mutex_lock(&its->its_lock); // TODO

	switch (attr) {
	case KVM_DEV_ARM_VGIC_CTRL_INIT:
	case KVM_DEV_ARM_ITS_CTRL_RESET:
	default:
		ret = -ENXIO;
		break;
	}

	//mutex_unlock(&its->its_lock);
	mutex_unlock(&kvm->arch.config_lock);
	kvm_unlock_all_vcpus(kvm);
	mutex_unlock(&kvm->lock);
	return ret;
}

static int vgic_v5_its_set_attr(struct kvm_device *dev,
				struct kvm_device_attr *attr)
{
	struct vgic_v5_its *its = dev->private;
	int ret;

	switch (attr->group) {
	case KVM_DEV_ARM_VGIC_GRP_ADDR: {
		u64 __user *uaddr = (u64 __user *)(long)attr->addr;
		unsigned long type = (unsigned long)attr->attr;
		u64 addr;

		if (type != KVM_VGIC_V5_ADDR_TYPE_ITS)
			return -ENODEV;

		if (copy_from_user(&addr, uaddr, sizeof(addr)))
			return -EFAULT;

		ret = vgic_check_iorange(dev->kvm, its->vgic_v5_its_base, addr,
					 SZ_64K, KVM_VGIC_V5_ITS_SIZE);
		if (ret)
			return ret;

		ret = vgic_v5_register_its_iodev(dev->kvm, its, addr);

		return ret;
	}
	case KVM_DEV_ARM_VGIC_GRP_CTRL:
		return vgic_v5_its_ctrl(dev->kvm, its, attr->attr);
		break;
	case KVM_DEV_ARM_VGIC_GRP_ITS_REGS:
		u64 __user *uaddr = (u64 __user *)(long)attr->addr;
		u64 reg;

		if (get_user(reg, uaddr))
			return -EFAULT;

		return vgic_v5_its_attr_regs_access(dev, attr, &reg, true);
	}

	return -ENXIO;
}

static int vgic_v5_its_get_attr(struct kvm_device *dev,
				struct kvm_device_attr *attr)
{
	switch (attr->group) {
	case KVM_DEV_ARM_VGIC_GRP_ADDR: {
		struct vgic_v5_its *its = dev->private;
		u64 addr = its->vgic_v5_its_base;
		u64 __user *uaddr = (u64 __user *)(long)attr->addr;
		unsigned long type = (unsigned long)attr->attr;

		if (type != KVM_VGIC_V5_ADDR_TYPE_ITS)
			return -ENODEV;

		if (copy_to_user(uaddr, &addr, sizeof(addr)))
			return -EFAULT;
		break;
	}
	case KVM_DEV_ARM_VGIC_GRP_ITS_REGS:
		u64 __user *uaddr = (u64 __user *)(long)attr->addr;
		u64 reg;
		int err;

		err = vgic_v5_its_attr_regs_access(dev, attr, &reg, false);
		if (err)
			return err;

		if (put_user(reg, uaddr))
			return -EFAULT;

		return 0;

	default:
		return -ENXIO;
	}

	return 0;
}

static int vgic_v5_its_has_attr(struct kvm_device *dev,
				struct kvm_device_attr *attr)
{
	switch (attr->group) {
	case KVM_DEV_ARM_VGIC_GRP_ADDR:
		switch (attr->attr) {
		case KVM_VGIC_V5_ADDR_TYPE_ITS:
			return 0;
		}
		break;
	case KVM_DEV_ARM_VGIC_GRP_CTRL:
		switch (attr->attr) {
		case KVM_DEV_ARM_VGIC_CTRL_INIT:
			return 0;
		}
		break;
	case KVM_DEV_ARM_VGIC_GRP_ITS_REGS:
		return vgic_v5_its_has_attr_regs(dev, attr);
	}

	return -ENXIO;
}

static struct kvm_device_ops kvm_arm_vgic_v5_its_ops = {
	.name = "kvm-arm-vgic-v5-its",
	.create = vgic_v5_its_create,
	.destroy = vgic_v5_its_destroy,
	.set_attr = vgic_v5_its_set_attr,
	.get_attr = vgic_v5_its_get_attr,
	.has_attr = vgic_v5_its_has_attr,
};

int kvm_vgic_v5_register_its_device(void)
{
	return kvm_register_device_ops(&kvm_arm_vgic_v5_its_ops,
				       KVM_DEV_TYPE_ARM_VGIC_V5_ITS);
}
