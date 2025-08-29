// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2016 Linaro
 * Author: Christoffer Dall <christoffer.dall@linaro.org>
 */

#include <linux/cpu.h>
#include <linux/debugfs.h>
#include <linux/interrupt.h>
#include <linux/kvm_host.h>
#include <linux/seq_file.h>
#include <kvm/arm_vgic.h>
#include <asm/kvm_mmu.h>
#include "vgic.h"

enum iter_state {
	Start,
	Next_VCPU,
	Per_VCPU, /* SGIs and PPIs */
	SPI,
	LPI,
	Done
};

/*
 * Structure to control looping through the entire vgic state.  We start at
 * zero for each field and move upwards.  So, if dist_id is 0 we print the
 * distributor info.  When dist_id is 1, we have already printed it and move
 * on.
 *
 * When vcpu_id < nr_cpus we print the vcpu info until vcpu_id == nr_cpus and
 * so on.
 */
struct vgic_state_iter {
	int nr_cpus;
	int nr_per_vcpu;
	int nr_spis;
	int nr_lpis;
	int dist_id;
	int vcpu_id;
	unsigned long intid;
	int idx;
	enum iter_state state;
	enum iter_state next_state;
};

static void iter_next(struct kvm *kvm, struct vgic_state_iter *iter)
{
	struct vgic_dist *dist = &kvm->arch.vgic;
	bool v5 = dist->vgic_model == KVM_DEV_TYPE_ARM_VGIC_V5;

	iter->state = iter->next_state;

	/* Build the correct intid */
	switch(iter->state) {
	case Next_VCPU:
		++iter->vcpu_id;
		fallthrough;
	case Start:
		iter->idx = 0;
		iter->dist_id++;
		fallthrough;
	case Per_VCPU:
		if (!v5)
			iter->intid = iter->idx;
		else
			iter->intid = FIELD_PREP(GICV5_HWIRQ_TYPE, GICV5_HWIRQ_TYPE_PPI) |
				FIELD_PREP(GICV5_HWIRQ_ID, iter->idx);
		break;
	case SPI:
		if (!v5)
			iter->intid = iter->idx + VGIC_NR_PRIVATE_IRQS;
		else
			iter->intid = FIELD_PREP(GICV5_HWIRQ_TYPE, GICV5_HWIRQ_TYPE_SPI) |
				FIELD_PREP(GICV5_HWIRQ_ID, iter->idx);
		break;
	case LPI:
		if (iter->idx < iter->nr_lpis)
			xa_find_after(&dist->lpi_xa, &iter->intid,
				      VGIC_LPI_MAX_INTID,
				      LPI_XA_MARK_DEBUG_ITER);
		break;
	case Done:
		fallthrough;
	default:
		return;
	}

	iter->idx++;

	switch(iter->state) {
	case Start:
		fallthrough;
	case Next_VCPU:
		iter->next_state = Per_VCPU;
		fallthrough;
	case Per_VCPU:
		/* Display all Per_VCPU IRQs per VCPU first */
		if (iter->idx == iter->nr_per_vcpu && iter->vcpu_id < iter->nr_cpus - 1) {
			iter->next_state = Next_VCPU;
			iter->idx = 0;
			break;
		}

		/* We're done with all Per_VCPU IRQs */
		if (iter->idx == iter->nr_per_vcpu) {
			iter->idx = 0;
			if (iter->nr_spis)
				iter->next_state = SPI;
			else if (iter->nr_lpis)
				iter->next_state = LPI;
			else
				iter->next_state = Done;
		}
		break;
	case SPI:
		/* We're done with SPIs */
		if (iter->idx == iter->nr_spis) {
			iter->idx = 0;
			if (iter->nr_lpis)
				iter->next_state = LPI;
			else
				iter->next_state = Done;
		}
		break;
	case LPI:
		/* We're just done */
		if (iter->idx == iter->nr_lpis)
			iter->next_state = Done;
		break;
	default:
		iter->next_state = Done;
	}
}

static int iter_mark_lpis(struct kvm *kvm)
{
	struct vgic_dist *dist = &kvm->arch.vgic;
	unsigned long intid, flags;
	struct vgic_irq *irq;
	int nr_lpis = 0;

	xa_lock_irqsave(&dist->lpi_xa, flags);

	xa_for_each(&dist->lpi_xa, intid, irq) {
		if (!vgic_try_get_irq_ref(irq))
			continue;

		__xa_set_mark(&dist->lpi_xa, intid, LPI_XA_MARK_DEBUG_ITER);
		nr_lpis++;
	}

	xa_unlock_irqrestore(&dist->lpi_xa, flags);

	return nr_lpis;
}

static void iter_unmark_lpis(struct kvm *kvm)
{
	struct vgic_dist *dist = &kvm->arch.vgic;
	unsigned long intid, flags;
	struct vgic_irq *irq;

	xa_for_each_marked(&dist->lpi_xa, intid, irq, LPI_XA_MARK_DEBUG_ITER) {
		xa_lock_irqsave(&dist->lpi_xa, flags);
		__xa_clear_mark(&dist->lpi_xa, intid, LPI_XA_MARK_DEBUG_ITER);
		xa_unlock_irqrestore(&dist->lpi_xa, flags);

		/* vgic_put_irq() expects to be called outside of the xa_lock */
		vgic_put_irq(kvm, irq);
	}
}

static void iter_init(struct kvm *kvm, struct vgic_state_iter *iter,
		      loff_t pos)
{
	int nr_cpus = atomic_read(&kvm->online_vcpus);

	memset(iter, 0, sizeof(*iter));

	iter->next_state = Start;
	iter->nr_cpus = nr_cpus;
	iter->nr_spis = kvm->arch.vgic.nr_spis;
	if (kvm->arch.vgic.vgic_model == KVM_DEV_TYPE_ARM_VGIC_V3) {
		iter->nr_lpis = iter_mark_lpis(kvm);
		iter->nr_per_vcpu = VGIC_NR_PRIVATE_IRQS;
	} else if (kvm->arch.vgic.vgic_model == KVM_DEV_TYPE_ARM_VGIC_V5) {
		iter->nr_lpis = iter_mark_lpis(kvm);
		iter->nr_per_vcpu = VGIC_V5_NR_PRIVATE_IRQS;
	}

	/* Fast forward to the right position if needed */
	while (pos--)
		iter_next(kvm, iter);
}

static bool end_of_vgic(struct vgic_state_iter *iter)
{
	/*
	 * Has printed dist
	 * Has printed PPIs for all CPUs
	 * Has printed SPIs
	 * Has printed LPIs or there are no LPIs to print
	 */
	return iter->state == Done;
}

static void *vgic_debug_start(struct seq_file *s, loff_t *pos)
{
	struct kvm *kvm = s->private;
	struct vgic_state_iter *iter;

	mutex_lock(&kvm->arch.config_lock);
	iter = kvm->arch.vgic.iter;
	if (iter) {
		iter = ERR_PTR(-EBUSY);
		goto out;
	}

	iter = kmalloc(sizeof(*iter), GFP_KERNEL);
	if (!iter) {
		iter = ERR_PTR(-ENOMEM);
		goto out;
	}

	iter_init(kvm, iter, *pos);
	kvm->arch.vgic.iter = iter;

	if (end_of_vgic(iter))
		iter = NULL;
out:
	mutex_unlock(&kvm->arch.config_lock);
	return iter;
}

static void *vgic_debug_next(struct seq_file *s, void *v, loff_t *pos)
{
	struct kvm *kvm = s->private;
	struct vgic_state_iter *iter = kvm->arch.vgic.iter;

	++*pos;
	iter_next(kvm, iter);
	if (end_of_vgic(iter))
		iter = NULL;
	return iter;
}

static void vgic_debug_stop(struct seq_file *s, void *v)
{
	struct kvm *kvm = s->private;
	struct vgic_state_iter *iter;

	/*
	 * If the seq file wasn't properly opened, there's nothing to clearn
	 * up.
	 */
	if (IS_ERR(v))
		return;

	mutex_lock(&kvm->arch.config_lock);
	iter = kvm->arch.vgic.iter;
	iter_unmark_lpis(kvm);
	kfree(iter);
	kvm->arch.vgic.iter = NULL;
	mutex_unlock(&kvm->arch.config_lock);
}

static void print_dist_state(struct seq_file *s, struct vgic_dist *dist,
			     struct vgic_state_iter *iter)
{
	bool v3 = dist->vgic_model == KVM_DEV_TYPE_ARM_VGIC_V3;
	bool v5 = dist->vgic_model == KVM_DEV_TYPE_ARM_VGIC_V5;

	seq_printf(s, "Distributor\n");
	seq_printf(s, "===========\n");
	seq_printf(s, "vgic_model:\t%s\n", v5 ? "GICv5" : v3 ? "GICv3" : "GICv2");
	seq_printf(s, "nr_spis:\t%d\n", dist->nr_spis);
	if (v3)
		seq_printf(s, "nr_lpis:\t%d\n", iter->nr_lpis);
	seq_printf(s, "enabled:\t%d\n", dist->enabled);
	seq_printf(s, "\n");

	seq_printf(s, "P=pending_latch, L=line_level, A=active\n");
	seq_printf(s, "E=enabled, H=hw, C=config (level=1, edge=0)\n");
	seq_printf(s, "G=group\n");
}

static void print_header(struct seq_file *s, struct vgic_irq *irq,
			 struct kvm_vcpu *vcpu)
{
	int id = 0;
	char *hdr = "SPI ";

	if (vcpu) {
		hdr = "VCPU";
		id = vcpu->vcpu_idx;
	}

	seq_printf(s, "\n");
	seq_printf(s, "%s%2d TYP   ID TGT_ID PLAEHCG     HWID   TARGET SRC PRI VCPU_ID\n", hdr, id);
	seq_printf(s, "----------------------------------------------------------------\n");
}

static void print_irq_state(struct seq_file *s, struct vgic_irq *irq,
			    struct kvm_vcpu *vcpu)
{
	char *type;
	bool pending;
	struct kvm *kvm = s->private;

	if (irq_is_sgi(kvm, irq->intid))
		type = "SGI";
	else if (irq_is_ppi(kvm, irq->intid))
		type = "PPI";
	else if (irq_is_spi(kvm, irq->intid))
		type = "SPI";
	else
		type = "LPI";

	if (!vgic_is_v5(kvm) &&
	    (irq->intid == 0 || irq->intid == VGIC_NR_PRIVATE_IRQS))
		print_header(s, irq, vcpu);

	if (vgic_is_v5(kvm) && irq_int_id_v5(irq->intid) == 0 &&
	    !__irq_is_lpi(KVM_DEV_TYPE_ARM_VGIC_V5, irq->intid))
		print_header(s, irq, vcpu);

	pending = irq->pending_latch;
	if (irq->hw && vgic_irq_is_sgi(irq->intid)) {
		int err;

		err = irq_get_irqchip_state(irq->host_irq,
					    IRQCHIP_STATE_PENDING,
					    &pending);
		WARN_ON_ONCE(err);
	}

	seq_printf(s, "       %s %4lu "
		      "    %2d "
		      "%d%d%d%d%d%d%d "
		      "%8d "
		      "%8x "
		      " %2x "
		      "%3d "
		      "     %2d "
		      "\n",
		   type, vgic_is_v5(kvm) ? irq_int_id_v5(irq->intid) : irq->intid,
			(irq->target_vcpu) ? irq->target_vcpu->vcpu_idx : -1,
			pending,
			irq->line_level,
			irq->active,
			irq->enabled,
			irq->hw,
			irq->config == VGIC_CONFIG_LEVEL,
			irq->group,
			irq->hwintid,
			irq->mpidr,
			irq->source,
			irq->priority,
			(irq->vcpu) ? irq->vcpu->vcpu_idx : -1);
}

static int vgic_debug_show(struct seq_file *s, void *v)
{
	struct kvm *kvm = s->private;
	struct vgic_state_iter *iter = v;
	struct vgic_irq *irq;
	struct kvm_vcpu *vcpu = NULL;
	unsigned long flags;

	bool v5 = kvm->arch.vgic.vgic_model == KVM_DEV_TYPE_ARM_VGIC_V5;

	if (iter->dist_id == 0) {
		print_dist_state(s, &kvm->arch.vgic, iter);
		return 0;
	}

	if (!kvm->arch.vgic.initialized)
		return 0;

	if (iter->vcpu_id < iter->nr_cpus)
		vcpu = kvm_get_vcpu(kvm, iter->vcpu_id);

	/*
	 * Expect this to succeed, as iter_mark_lpis() takes a reference on
	 * every LPI to be visited.
	 */
	if (!v5 && iter->intid < VGIC_NR_PRIVATE_IRQS)
		irq = vgic_get_vcpu_irq(vcpu, iter->intid);
	else if (irq_is_ppi(kvm, iter->intid))
		irq = vgic_get_vcpu_irq(vcpu, iter->intid);
	else
		irq = vgic_get_irq(kvm, iter->intid);
	if (WARN_ON_ONCE(!irq))
		return -EINVAL;

	raw_spin_lock_irqsave(&irq->irq_lock, flags);
	print_irq_state(s, irq, vcpu);
	raw_spin_unlock_irqrestore(&irq->irq_lock, flags);

	vgic_put_irq(kvm, irq);
	return 0;
}

static const struct seq_operations vgic_debug_sops = {
	.start = vgic_debug_start,
	.next  = vgic_debug_next,
	.stop  = vgic_debug_stop,
	.show  = vgic_debug_show
};

DEFINE_SEQ_ATTRIBUTE(vgic_debug);

void vgic_debug_init(struct kvm *kvm)
{
	debugfs_create_file("vgic-state", 0444, kvm->debugfs_dentry, kvm,
			    &vgic_debug_fops);
}

void vgic_debug_destroy(struct kvm *kvm)
{
}

/**
 * struct vgic_its_iter - Iterator for traversing VGIC ITS device tables.
 * @dev: Pointer to the current its_device being processed.
 * @ite: Pointer to the current its_ite within the device being processed.
 *
 * This structure is used to maintain the current position during iteration
 * over the ITS device tables. It holds pointers to both the current device
 * and the current ITE within that device.
 */
struct vgic_its_iter {
	struct its_device *dev;
	struct its_ite *ite;
};

/**
 * end_of_iter - Checks if the iterator has reached the end.
 * @iter: The iterator to check.
 *
 * When the iterator completed processing the final ITE in the last device
 * table, it was marked to indicate the end of iteration by setting its
 * device and ITE pointers to NULL.
 * This function checks whether the iterator was marked as end.
 *
 * Return: True if the iterator is marked as end, false otherwise.
 */
static inline bool end_of_iter(struct vgic_its_iter *iter)
{
	return !iter->dev && !iter->ite;
}

/**
 * vgic_its_iter_next - Advances the iterator to the next entry in the ITS tables.
 * @its: The VGIC ITS structure.
 * @iter: The iterator to advance.
 *
 * This function moves the iterator to the next ITE within the current device,
 * or to the first ITE of the next device if the current ITE is the last in
 * the device. If the current device is the last device, the iterator is set
 * to indicate the end of iteration.
 */
static void vgic_its_iter_next(struct vgic_its *its, struct vgic_its_iter *iter)
{
	struct its_device *dev = iter->dev;
	struct its_ite *ite = iter->ite;

	if (!ite || list_is_last(&ite->ite_list, &dev->itt_head)) {
		if (list_is_last(&dev->dev_list, &its->device_list)) {
			dev = NULL;
			ite = NULL;
		} else {
			dev = list_next_entry(dev, dev_list);
			ite = list_first_entry_or_null(&dev->itt_head,
						       struct its_ite,
						       ite_list);
		}
	} else {
		ite = list_next_entry(ite, ite_list);
	}

	iter->dev = dev;
	iter->ite = ite;
}

/**
 * vgic_its_debug_start - Start function for the seq_file interface.
 * @s: The seq_file structure.
 * @pos: The starting position (offset).
 *
 * This function initializes the iterator to the beginning of the ITS tables
 * and advances it to the specified position. It acquires the its_lock mutex
 * to protect shared data.
 *
 * Return: An iterator pointer on success, NULL if no devices are found or
 *         the end of the list is reached, or ERR_PTR(-ENOMEM) on memory
 *         allocation failure.
 */
static void *vgic_its_debug_start(struct seq_file *s, loff_t *pos)
{
	struct vgic_its *its = s->private;
	struct vgic_its_iter *iter;
	struct its_device *dev;
	loff_t offset = *pos;

	mutex_lock(&its->its_lock);

	dev = list_first_entry_or_null(&its->device_list,
				       struct its_device, dev_list);
	if (!dev)
		return NULL;

	iter = kmalloc(sizeof(*iter), GFP_KERNEL);
	if (!iter)
		return ERR_PTR(-ENOMEM);

	iter->dev = dev;
	iter->ite = list_first_entry_or_null(&dev->itt_head,
					     struct its_ite, ite_list);

	while (!end_of_iter(iter) && offset--)
		vgic_its_iter_next(its, iter);

	if (end_of_iter(iter)) {
		kfree(iter);
		return NULL;
	}

	return iter;
}

/**
 * vgic_its_debug_next - Next function for the seq_file interface.
 * @s: The seq_file structure.
 * @v: The current iterator.
 * @pos: The current position (offset).
 *
 * This function advances the iterator to the next entry and increments the
 * position.
 *
 * Return: An iterator pointer on success, or NULL if the end of the list is
 *         reached.
 */
static void *vgic_its_debug_next(struct seq_file *s, void *v, loff_t *pos)
{
	struct vgic_its *its = s->private;
	struct vgic_its_iter *iter = v;

	++*pos;
	vgic_its_iter_next(its, iter);

	if (end_of_iter(iter)) {
		kfree(iter);
		return NULL;
	}
	return iter;
}

/**
 * vgic_its_debug_stop - Stop function for the seq_file interface.
 * @s: The seq_file structure.
 * @v: The current iterator.
 *
 * This function frees the iterator and releases the its_lock mutex.
 */
static void vgic_its_debug_stop(struct seq_file *s, void *v)
{
	struct vgic_its *its = s->private;
	struct vgic_its_iter *iter = v;

	if (!IS_ERR_OR_NULL(iter))
		kfree(iter);
	mutex_unlock(&its->its_lock);
}

/**
 * vgic_its_debug_show - Show function for the seq_file interface.
 * @s: The seq_file structure.
 * @v: The current iterator.
 *
 * This function formats and prints the ITS table entry information to the
 * seq_file output.
 *
 * Return: 0 on success.
 */
static int vgic_its_debug_show(struct seq_file *s, void *v)
{
	struct vgic_its_iter *iter = v;
	struct its_device *dev = iter->dev;
	struct its_ite *ite = iter->ite;

	if (!ite)
		return 0;

	if (list_is_first(&ite->ite_list, &dev->itt_head)) {
		seq_printf(s, "\n");
		seq_printf(s, "Device ID: 0x%x, Event ID Range: [0 - %llu]\n",
			   dev->device_id, BIT_ULL(dev->num_eventid_bits) - 1);
		seq_printf(s, "EVENT_ID    INTID  HWINTID   TARGET   COL_ID HW\n");
		seq_printf(s, "-----------------------------------------------\n");
	}

	if (ite->irq && ite->collection) {
		seq_printf(s, "%8u %8u %8u %8u %8u %2d\n",
			   ite->event_id, ite->irq->intid, ite->irq->hwintid,
			   ite->collection->target_addr,
			   ite->collection->collection_id, ite->irq->hw);
	}

	return 0;
}

static const struct seq_operations vgic_its_debug_sops = {
	.start = vgic_its_debug_start,
	.next  = vgic_its_debug_next,
	.stop  = vgic_its_debug_stop,
	.show  = vgic_its_debug_show
};

DEFINE_SEQ_ATTRIBUTE(vgic_its_debug);

/**
 * vgic_its_debug_init - Initializes the debugfs interface for VGIC ITS.
 * @dev: The KVM device structure.
 *
 * This function creates a debugfs file named "vgic-its-state@%its_base"
 * to expose the ITS table information.
 *
 * Return: 0 on success.
 */
int vgic_its_debug_init(struct kvm_device *dev)
{
	struct vgic_its *its = dev->private;
	char *name;

	name = kasprintf(GFP_KERNEL, "vgic-its-state@%llx", (u64)its->vgic_its_base);
	if (!name)
		return -ENOMEM;

	debugfs_create_file(name, 0444, dev->kvm->debugfs_dentry, its, &vgic_its_debug_fops);

	kfree(name);
	return 0;
}

void vgic_its_debug_destroy(struct kvm_device *dev)
{
}
