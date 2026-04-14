/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2026 bmax121.
 * RCU + spinlock synchronization for hook chain operations.
 *
 * Enabled only when CONFIG_KH_CHAIN_RCU is defined.
 * When disabled, include/sync.h provides empty inline stubs — zero overhead.
 */

#ifdef CONFIG_KH_CHAIN_RCU

#include <types.h>
#include <hook.h>

#ifdef KMOD_FREESTANDING

#include <symbol.h>
#include <linux/printk.h>

/* Resolved kernel symbols */
static void (*_rcu_read_lock)(void);
static void (*_rcu_read_unlock)(void);
static void (*_synchronize_rcu)(void);
static void (*_raw_spin_lock_fn)(void *);
static void (*_raw_spin_unlock_fn)(void *);

/* Static spinlock storage — zero-initialized is valid for raw_spinlock_t.
 * 64-byte aligned to avoid false sharing. */
static char chain_lock_storage[64] __attribute__((aligned(64)));

KCFI_EXEMPT
void sync_read_lock(void)
{
    _rcu_read_lock();
}

KCFI_EXEMPT
void sync_read_unlock(void)
{
    _rcu_read_unlock();
}

KCFI_EXEMPT
void sync_write_lock(void)
{
    _raw_spin_lock_fn(chain_lock_storage);
}

KCFI_EXEMPT
void sync_write_unlock(void)
{
    _raw_spin_unlock_fn(chain_lock_storage);
    _synchronize_rcu();
}

int sync_init(void)
{
    /* rcu_read_lock is inline on many kernels; the exported symbol may be
     * __rcu_read_lock (GKI 6.1+) or rcu_read_lock depending on kernel config.
     * Try both names so the same binary works across kernel variants. */
    _rcu_read_lock = (void (*)(void))ksyms_lookup("rcu_read_lock");
    if (!_rcu_read_lock)
        _rcu_read_lock = (void (*)(void))ksyms_lookup("__rcu_read_lock");
    if (!_rcu_read_lock) {
        pr_err("kernelhook: sync: failed to resolve rcu_read_lock/__rcu_read_lock\n");
        return -1;
    }

    _rcu_read_unlock = (void (*)(void))ksyms_lookup("rcu_read_unlock");
    if (!_rcu_read_unlock)
        _rcu_read_unlock = (void (*)(void))ksyms_lookup("__rcu_read_unlock");
    if (!_rcu_read_unlock) {
        pr_err("kernelhook: sync: failed to resolve rcu_read_unlock/__rcu_read_unlock\n");
        return -1;
    }

    _synchronize_rcu = (void (*)(void))ksyms_lookup("synchronize_rcu");
    if (!_synchronize_rcu) {
        pr_err("kernelhook: sync: failed to resolve synchronize_rcu\n");
        return -1;
    }

    _raw_spin_lock_fn = (void (*)(void *))ksyms_lookup("_raw_spin_lock");
    if (!_raw_spin_lock_fn) {
        pr_err("kernelhook: sync: failed to resolve _raw_spin_lock\n");
        return -1;
    }

    _raw_spin_unlock_fn = (void (*)(void *))ksyms_lookup("_raw_spin_unlock");
    if (!_raw_spin_unlock_fn) {
        pr_err("kernelhook: sync: failed to resolve _raw_spin_unlock\n");
        return -1;
    }

    return 0;
}

void sync_cleanup(void)
{
    /* No-op: nothing to tear down */
}

#else /* !KMOD_FREESTANDING — standard kbuild */

#include <linux/rcupdate.h>
#include <linux/spinlock.h>
#include <linux/printk.h>

static DEFINE_SPINLOCK(chain_lock);

void sync_read_lock(void)
{
    rcu_read_lock();
}

void sync_read_unlock(void)
{
    rcu_read_unlock();
}

void sync_write_lock(void)
{
    spin_lock(&chain_lock);
}

void sync_write_unlock(void)
{
    spin_unlock(&chain_lock);
    synchronize_rcu();
}

int sync_init(void)
{
    return 0;
}

void sync_cleanup(void)
{
    /* No-op */
}

#endif /* KMOD_FREESTANDING */

#endif /* CONFIG_KH_CHAIN_RCU */
