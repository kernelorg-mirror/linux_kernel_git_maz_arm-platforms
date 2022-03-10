/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * A stand-alone rwlock implementation for use by the non-VHE KVM
 * hypervisor code running at EL2. This is *not* a fair lock and is
 * likely to scale very badly under contention.
 *
 * Copyright (C) 2022 Google LLC
 * Author: Will Deacon <will@kernel.org>
 *
 * Heavily based on the implementation removed by 087133ac9076 which was:
 * Copyright (C) 2012 ARM Ltd.
 */

#ifndef __ARM64_KVM_NVHE_RWLOCK_H__
#define __ARM64_KVM_NVHE_RWLOCK_H__

typedef struct {
	u32	__val;
} hyp_rwlock_t;

#define __HYP_RWLOCK_INITIALIZER \
	{ .__val = 0 }

#define __HYP_RWLOCK_UNLOCKED \
	((hyp_rwlock_t) __HYP_RWLOCK_INITIALIZER)

#define DEFINE_HYP_RWLOCK(x)	hyp_rwlock_t x = __HYP_RWLOCK_UNLOCKED

#define hyp_rwlock_init(l)						\
do {									\
	*(l) = __HYP_RWLOCK_UNLOCKED;					\
} while (0)

static inline void hyp_write_lock(hyp_rwlock_t *rw)
{
	/* TODO */
}

static inline void hyp_write_unlock(hyp_rwlock_t *rw)
{
	/* TODO */
}

static inline void hyp_read_lock(hyp_rwlock_t *rw)
{
	/* TODO */
}

static inline void hyp_read_unlock(hyp_rwlock_t *rw)
{
	/* TODO */
}

#ifdef CONFIG_NVHE_EL2_DEBUG
static inline void hyp_assert_write_lock_held(hyp_spinlock_t *lock)
{
	/* TODO */
}
#else
static inline void hyp_assert_write_lock_held(hyp_spinlock_t *lock) { }
#endif

#endif	/* __ARM64_KVM_NVHE_RWLOCK_H__ */
