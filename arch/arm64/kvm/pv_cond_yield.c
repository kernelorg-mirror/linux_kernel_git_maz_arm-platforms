// SPDX-License-Identifier: GPL-2.0
//
// Copyright (C) 2019 - ARM Ltd
// Author: Marc Zyngier <marc.zyngier@arm.com>

#define DEBUG	1

#include <linux/kvm_host.h>
#include <linux/rbtree.h>
#include <linux/rwlock.h>

#include <asm/hypervisor.h>
#include <asm/kvm_emulate.h>
#include <asm/sysreg.h>

/* Internal data structure */
struct kvm_pv_cond_yield {
	struct rb_node			node;
	struct pv_cond_yield_ent	entry;
	atomic_t			ref;
};

/* Must take read lock */
static struct kvm_pv_cond_yield *kvm_pvcy_search(struct kvm *kvm, u64 pc)
{
        struct rb_node *node = kvm->arch.pvcy_root.rb_node;
	struct kvm_pv_cond_yield *pvcy;

        while (node) {
		pvcy = container_of(node, typeof(*pvcy), node);

                if (pc < pvcy->entry.pc)
                        node = node->rb_left;
                else if (pc > pvcy->entry.pc)
                        node = node->rb_right;
                else
                        return pvcy;
        }

        return NULL;
}

static void kvm_pvcy_insert(struct kvm *kvm, struct kvm_pv_cond_yield *pvcy)
{
        struct rb_node **new, *parent = NULL;

	atomic_set(&pvcy->ref, 0);
	write_lock(&kvm->arch.pvcy_lock);

	new = &kvm->arch.pvcy_root.rb_node;

	/* Figure out where to put new node */
        while (*new) {
                struct kvm_pv_cond_yield *this;

		this = container_of(*new, typeof(*this), node);

                parent = *new;
                if	(pvcy->entry.pc < this->entry.pc)
                        new = &((*new)->rb_left);
                else if	(pvcy->entry.pc > this->entry.pc)
                        new = &((*new)->rb_right);
                else {
			WARN_ON(1); /* same PC twice???? */
			goto out;
		}
        }

        /* Add new node and rebalance tree. */
        rb_link_node(&pvcy->node, parent, new);
        rb_insert_color(&pvcy->node, &kvm->arch.pvcy_root);
out:
	write_unlock(&kvm->arch.pvcy_lock);
}

void kvm_pvcy_populate(struct kvm *kvm, phys_addr_t array_ipa, int nr)
{
	struct kvm_pv_cond_yield *pvcy;
	int i, ret;

	for (i = 0; i < nr; i++) {
		pvcy = kzalloc(sizeof(*pvcy), GFP_KERNEL);
		if (WARN_ON(!pvcy))
			return;

		ret = kvm_read_guest_lock(kvm, array_ipa, &pvcy->entry,
					  sizeof(pvcy->entry));
		if (WARN_ON(ret ||
			    pvcy->entry.flags ||
			    pvcy->entry.__reserved)) {
			kfree(pvcy);
			return;
		}

		kvm_pvcy_insert(kvm, pvcy);

		array_ipa += sizeof(pvcy->entry);
		pr_debug("pvcy%d: %llx x%d x%d\n", i, pvcy->entry.pc,
			 pvcy->entry.addr_reg, pvcy->entry.val_reg);
	}
}

void kvm_pvcy_revoke(struct kvm *kvm, phys_addr_t array_ipa, int nr)
{
	int i;

	for (i = 0; i < nr; i++) {
		struct pv_cond_yield_ent entry;
		struct kvm_pv_cond_yield *pvcy;
		int ret;

		ret = kvm_read_guest_lock(kvm, array_ipa, &entry, sizeof(entry));
		if (WARN_ON(ret))
			return;

		write_lock(&kvm->arch.pvcy_lock);

		/*
		 * TODO: return an error on revoking a call site with
		 * a positive refcount.
		 */
		pvcy = kvm_pvcy_search(kvm, entry.pc);
		if (WARN_ON(!pvcy) ||
		    WARN_ON(atomic_read(&pvcy->ref))) {
			write_unlock(&kvm->arch.pvcy_lock);
			return;
		}

		rb_erase(&pvcy->node, &kvm->arch.pvcy_root);
		kfree(pvcy);

		write_unlock(&kvm->arch.pvcy_lock);
	}
}

void kvm_pvcy_init(struct kvm *kvm)
{
	kvm->arch.pvcy_root = RB_ROOT;
	rwlock_init(&kvm->arch.pvcy_lock);
}

void kvm_pvcy_teardown(struct kvm *kvm)
{
	struct rb_node *node;

	write_lock(&kvm->arch.pvcy_lock);

	node = rb_first(&kvm->arch.pvcy_root);
	while (node) {
		struct kvm_pv_cond_yield *pvcy;

		pvcy = rb_entry(node, typeof(*pvcy), node);
		node = rb_next(node);

		/*
		 * This is only called on VM teardown, we can safely
		 * ignore the refcounts and free the structure. The
		 * vcpus themselves are long gone.
		 */
		rb_erase(&pvcy->node, &kvm->arch.pvcy_root);
		kfree(pvcy);
	}

	write_unlock(&kvm->arch.pvcy_lock);
}

void kvm_pvcy_prepare_state(struct kvm_vcpu *vcpu)
{
	struct kvm_pv_cond_yield *pvcy;
	struct kvm *kvm = vcpu->kvm;

	if (vcpu_el1_is_32bit(vcpu))
		return;

	read_lock(&kvm->arch.pvcy_lock);

	pvcy = kvm_pvcy_search(kvm, *vcpu_pc(vcpu));

	if (pvcy) {
		u64 ipa, va;

		va = vcpu_get_reg(vcpu, pvcy->entry.addr_reg);
		asm volatile("at s1e1r, %0" : : "r" (va));
		isb();

		ipa = read_sysreg(par_el1);
		if (unlikely(ipa & 1)) {
			pvcy = NULL;
		} else {
			ipa &= GENMASK_ULL(51,12);
			ipa |= va & GENMASK_ULL(11, 0);
			vcpu->arch.pvcy_ipa = ipa;
		}
	}

	if (pvcy) {
		atomic_inc(&pvcy->ref);
		vcpu->arch.pvcy_node = &pvcy->node;
	}

	read_unlock(&kvm->arch.pvcy_lock);
}

/*
 * -1: Unable to evaluate state
 *  0: State unchanged
 *  1: State changed
 */
int kvm_pvcy_check_state(struct kvm_vcpu *vcpu)
{
	struct kvm_pv_cond_yield *pvcy;
	struct kvm *kvm = vcpu->kvm;
	u64 val;
	int ret;

	/* No PVCY, don't bother */
	if (!vcpu->arch.pvcy_node)
		return -1;

	pvcy = container_of(vcpu->arch.pvcy_node, typeof(*pvcy), node);

	ret = kvm_read_guest_lock(kvm, vcpu->arch.pvcy_ipa, &val, sizeof(val));
	if (ret)
		return -1;

	val ^= vcpu_get_reg(vcpu, pvcy->entry.val_reg);
	val &= pvcy->entry.mask;

	ret = (val != 0);

	if (!ret) {
		/*
		 * If we have an interrupt pending, and that the guest can
		 * take it, pretend that the state has changed as well.
		 * FIXME: What about FIQ and Abort?
		 */
		if (!(*vcpu_cpsr(vcpu) & PSR_I_BIT))
			ret |= kvm_arch_vcpu_runnable(vcpu);

		ret |= !!signal_pending(current);
        }

	if (ret) {
		atomic_dec(&pvcy->ref);
		vcpu->arch.pvcy_node = NULL;
	}

	return ret;
}
