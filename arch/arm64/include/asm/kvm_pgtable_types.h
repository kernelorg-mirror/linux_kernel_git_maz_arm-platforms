// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2020 Google LLC
 * Author: Will Deacon <will@kernel.org>
 */

#ifndef __ARM64_KVM_PGTABLE_TYPES_H__
#define __ARM64_KVM_PGTABLE_TYPES_H__

typedef u64 kvm_pte_t;

/**
 * struct kvm_pgtable_mm_ops - Memory management callbacks.
 * @zalloc_page:		Allocate a single zeroed memory page.
 *				The @arg parameter can be used by the walker
 *				to pass a memcache. The initial refcount of
 *				the page is 1.
 * @zalloc_pages_exact:		Allocate an exact number of zeroed memory pages.
 *				The @size parameter is in bytes, and is rounded
 *				up to the next page boundary. The resulting
 *				allocation is physically contiguous.
 * @free_pages_exact:		Free an exact number of memory pages previously
 *				allocated by zalloc_pages_exact.
 * @free_unlinked_table:	Free an unlinked paging structure by unlinking and
 *				dropping references.
 * @get_page:			Increment the refcount on a page.
 * @put_page:			Decrement the refcount on a page. When the
 *				refcount reaches 0 the page is automatically
 *				freed.
 * @page_count:			Return the refcount of a page.
 * @phys_to_virt:		Convert a physical address into a virtual
 *				address	mapped in the current context.
 * @virt_to_phys:		Convert a virtual address mapped in the current
 *				context into a physical address.
 * @dcache_clean_inval_poc:	Clean and invalidate the data cache to the PoC
 *				for the	specified memory address range.
 * @icache_inval_pou:		Invalidate the instruction cache to the PoU
 *				for the specified memory address range.
 */
struct kvm_pgtable_mm_ops {
	void*		(*zalloc_page)(void *arg);
	void*		(*zalloc_pages_exact)(size_t size);
	void		(*free_pages_exact)(void *addr, size_t size);
	void		(*free_unlinked_table)(void *addr, s8 level);
	void		(*get_page)(void *addr);
	void		(*put_page)(void *addr);
	int		(*page_count)(void *addr);
	void*		(*phys_to_virt)(phys_addr_t phys);
	phys_addr_t	(*virt_to_phys)(void *addr);
	void		(*dcache_clean_inval_poc)(void *addr, size_t size);
	void		(*icache_inval_pou)(void *addr, size_t size);
};

/**
 * enum kvm_pgtable_stage2_flags - Stage-2 page-table flags.
 * @KVM_PGTABLE_S2_NOFWB:	Don't enforce Normal-WB even if the CPUs have
 *				ARM64_HAS_STAGE2_FWB.
 * @KVM_PGTABLE_S2_IDMAP:	Only use identity mappings.
 */
enum kvm_pgtable_stage2_flags {
	KVM_PGTABLE_S2_NOFWB			= BIT(0),
	KVM_PGTABLE_S2_IDMAP			= BIT(1),
};

/**
 * enum kvm_pgtable_prot - Page-table permissions and attributes.
 * @KVM_PGTABLE_PROT_X:		Execute permission.
 * @KVM_PGTABLE_PROT_W:		Write permission.
 * @KVM_PGTABLE_PROT_R:		Read permission.
 * @KVM_PGTABLE_PROT_DEVICE:	Device attributes.
 * @KVM_PGTABLE_PROT_NORMAL_NC:	Normal noncacheable attributes.
 * @KVM_PGTABLE_PROT_SW0:	Software bit 0.
 * @KVM_PGTABLE_PROT_SW1:	Software bit 1.
 * @KVM_PGTABLE_PROT_SW2:	Software bit 2.
 * @KVM_PGTABLE_PROT_SW3:	Software bit 3.
 */
enum kvm_pgtable_prot {
	KVM_PGTABLE_PROT_X			= BIT(0),
	KVM_PGTABLE_PROT_W			= BIT(1),
	KVM_PGTABLE_PROT_R			= BIT(2),

	KVM_PGTABLE_PROT_DEVICE			= BIT(3),
	KVM_PGTABLE_PROT_NORMAL_NC		= BIT(4),

	KVM_PGTABLE_PROT_SW0			= BIT(55),
	KVM_PGTABLE_PROT_SW1			= BIT(56),
	KVM_PGTABLE_PROT_SW2			= BIT(57),
	KVM_PGTABLE_PROT_SW3			= BIT(58),
};

typedef bool (*kvm_pgtable_force_pte_cb_t)(u64 addr, u64 end,
					   enum kvm_pgtable_prot prot);

/**
 * enum kvm_pgtable_walk_flags - Flags to control a depth-first page-table walk.
 * @KVM_PGTABLE_WALK_LEAF:		Visit leaf entries, including invalid
 *					entries.
 * @KVM_PGTABLE_WALK_TABLE_PRE:		Visit table entries before their
 *					children.
 * @KVM_PGTABLE_WALK_TABLE_POST:	Visit table entries after their
 *					children.
 * @KVM_PGTABLE_WALK_SHARED:		Indicates the page-tables may be shared
 *					with other software walkers.
 * @KVM_PGTABLE_WALK_HANDLE_FAULT:	Indicates the page-table walk was
 *					invoked from a fault handler.
 * @KVM_PGTABLE_WALK_SKIP_BBM_TLBI:	Visit and update table entries
 *					without Break-before-make's
 *					TLB invalidation.
 * @KVM_PGTABLE_WALK_SKIP_CMO:		Visit and update table entries
 *					without Cache maintenance
 *					operations required.
 */
enum kvm_pgtable_walk_flags {
	KVM_PGTABLE_WALK_LEAF			= BIT(0),
	KVM_PGTABLE_WALK_TABLE_PRE		= BIT(1),
	KVM_PGTABLE_WALK_TABLE_POST		= BIT(2),
	KVM_PGTABLE_WALK_SHARED			= BIT(3),
	KVM_PGTABLE_WALK_HANDLE_FAULT		= BIT(4),
	KVM_PGTABLE_WALK_SKIP_BBM_TLBI		= BIT(5),
	KVM_PGTABLE_WALK_SKIP_CMO		= BIT(6),
};

struct kvm_pgtable_visit_ctx {
	kvm_pte_t				*ptep;
	kvm_pte_t				old;
	void					*arg;
	struct kvm_pgtable_mm_ops		*mm_ops;
	u64					start;
	u64					addr;
	u64					end;
	s8					level;
	enum kvm_pgtable_walk_flags		flags;
};

typedef int (*kvm_pgtable_visitor_fn_t)(const struct kvm_pgtable_visit_ctx *ctx,
					enum kvm_pgtable_walk_flags visit);

#if defined(__KVM_NVHE_HYPERVISOR__) || defined(__KVM_VHE_HYPERVISOR__)

typedef kvm_pte_t *kvm_pteref_t;

#else

typedef kvm_pte_t __rcu *kvm_pteref_t;

#endif

/**
 * struct kvm_pgtable - KVM page-table.
 * @ia_bits:		Maximum input address size, in bits.
 * @start_level:	Level at which the page-table walk starts.
 * @pgd:		Pointer to the first top-level entry of the page-table.
 * @mm_ops:		Memory management callbacks.
 * @mmu:		Stage-2 KVM MMU struct. Unused for stage-1 page-tables.
 * @flags:		Stage-2 page-table flags.
 * @force_pte_cb:	Function that returns true if page level mappings must
 *			be used instead of block mappings.
 */
struct kvm_pgtable {
	u32					ia_bits;
	s8					start_level;
	kvm_pteref_t				pgd;
	struct kvm_pgtable_mm_ops		*mm_ops;

	/* Stage-2 only */
	struct kvm_s2_mmu			*mmu;
	enum kvm_pgtable_stage2_flags		flags;
	kvm_pgtable_force_pte_cb_t		force_pte_cb;
};

#endif	/* __ARM64_KVM_PGTABLE_TYPES_H__ */
