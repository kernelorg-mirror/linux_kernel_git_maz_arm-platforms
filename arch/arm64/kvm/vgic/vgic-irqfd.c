// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2015, 2016 ARM Ltd.
 */

#include <linux/kvm.h>
#include <linux/kvm_host.h>
#include <trace/events/kvm.h>
#include <kvm/arm_vgic.h>
#include "vgic.h"

/**
 * vgic_irqfd_set_irq: inject the IRQ corresponding to the
 * irqchip routing entry
 *
 * This is the entry point for irqfd IRQ injection
 */
int vgic_irqfd_set_irq(struct kvm_kernel_irq_routing_entry *e,
		       struct kvm *kvm, int irq_source_id,
		       int level, bool line_status)
{
	unsigned int spi_id = e->irqchip.pin + VGIC_NR_PRIVATE_IRQS;

	if (!vgic_valid_spi(kvm, spi_id))
		return -EINVAL;
	return kvm_vgic_inject_irq(kvm, 0, spi_id, level, NULL);
}

static void kvm_populate_msi(struct kvm_kernel_irq_routing_entry *e,
			     struct kvm_msi *msi)
{
	msi->address_lo = e->msi.address_lo;
	msi->address_hi = e->msi.address_hi;
	msi->data = e->msi.data;
	msi->flags = e->msi.flags;
	msi->devid = e->msi.devid;
}

/**
 * vgic_set_msi: inject the MSI corresponding to the
 * MSI routing entry
 *
 * This is the entry point for irqfd MSI injection
 * and userspace MSI injection.
 */
int vgic_set_msi(struct kvm_kernel_irq_routing_entry *e,
		 struct kvm *kvm, int irq_source_id,
		 int level, bool line_status)
{
	struct kvm_msi msi;

	if (!vgic_has_its(kvm))
		return -ENODEV;

	if (!level)
		return -1;

	kvm_populate_msi(e, &msi);
	return vgic_its_inject_msi(kvm, &msi);
}

/**
 * vgic_set_irq_inatomic: fast-path for irqfd injection
 */
int vgic_set_irq_inatomic(struct kvm_kernel_irq_routing_entry *e,
			  struct kvm *kvm, int irq_source_id, int level,
			  bool line_status)
{
	switch (e->type) {
	case KVM_IRQ_ROUTING_MSI: {
		struct kvm_msi msi;

		if (!vgic_has_its(kvm))
			break;

		kvm_populate_msi(e, &msi);
		return vgic_its_inject_cached_translation(kvm, &msi);
	}

	case KVM_IRQ_ROUTING_IRQCHIP:
		return vgic_irqfd_set_irq(e, kvm, irq_source_id, 1, line_status);
	}

	return -EWOULDBLOCK;
}

int kvm_vgic_setup_default_irq_routing(struct kvm *kvm)
{
	struct kvm_irq_routing_entry *entries;
	struct vgic_dist *dist = &kvm->arch.vgic;
	u32 nr = dist->nr_spis;
	int i, ret;

	entries = kcalloc(nr, sizeof(*entries), GFP_KERNEL);
	if (!entries)
		return -ENOMEM;

	for (i = 0; i < nr; i++) {
		entries[i].gsi = i;
		entries[i].type = KVM_IRQ_ROUTING_IRQCHIP;
		entries[i].u.irqchip.irqchip = 0;
		entries[i].u.irqchip.pin = i;
	}
	ret = kvm_set_irq_routing(kvm, entries, nr, 0);
	kfree(entries);
	return ret;
}
