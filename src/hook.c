/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2026 bmax121.
 * Userspace hook chain API — adapts the kernel core logic for
 * userspace memory management and hook installation.
 */

#include <types.h>
#include <hook.h>
#include <sync.h>
#include <memory.h>
#include <platform.h>
#include <kh_log.h>

/* Flush D-cache and I-cache for a memory region that contains code.
 * Required after writing instructions to the ROX pool — the I-cache
 * may still hold stale instructions from a previous allocation at the
 * same address.
 *
 * ARM64 requires: DC CVAU (clean D-cache to PoU) → DSB ISH →
 * IC IVAU (invalidate I-cache to PoU) → DSB ISH → ISB.
 *
 * Userspace uses __builtin___clear_cache which issues the SVC for
 * CTR_EL0-based maintenance. */
static void flush_code_cache(void *addr, size_t size)
{
#if defined(__aarch64__) || defined(__arm64__)
#ifdef __USERSPACE__
    __builtin___clear_cache((char *)addr, (char *)addr + size);
#else
    uintptr_t start = (uintptr_t)addr;
    uintptr_t end = start + size;
    uintptr_t line;
    for (line = start; line < end; line += 4)
        asm volatile("dc cvau, %0" :: "r"(line) : "memory");
    asm volatile("dsb ish" ::: "memory");
    for (line = start; line < end; line += 4)
        asm volatile("ic ivau, %0" :: "r"(line) : "memory");
    asm volatile("dsb ish\n\tisb" ::: "memory");
#endif
#endif
}

/* ---- Generic chain operations (shared by inline and FP hooks) ----
 *
 * hook_chain_rw_t and fp_hook_chain_rw_t share the same field layout
 * for chain_items_max, items[], sorted_indices[], sorted_count.
 * Use macros to generate type-safe wrappers without code duplication.
 */

#define DEFINE_CHAIN_OPS(PREFIX, RW_TYPE, MASK_TYPE)                             \
                                                                                \
static void PREFIX##_rebuild_sorted(RW_TYPE *rw)                                \
{                                                                               \
    int32_t count = 0;                                                          \
    MASK_TYPE mask = rw->occupied_mask;                                          \
    while (mask) {                                                              \
        int32_t i = __builtin_ctz(mask);                                        \
        rw->sorted_indices[count++] = i;                                        \
        mask &= ~((MASK_TYPE)1 << i);                                           \
    }                                                                           \
    for (int32_t i = 1; i < count; i++) {                                      \
        int32_t key = rw->sorted_indices[i];                                    \
        int32_t key_pri = rw->items[key].priority;                              \
        int32_t j = i - 1;                                                      \
        while (j >= 0 && rw->items[rw->sorted_indices[j]].priority < key_pri) { \
            rw->sorted_indices[j + 1] = rw->sorted_indices[j];                 \
            j--;                                                                \
        }                                                                       \
        rw->sorted_indices[j + 1] = key;                                        \
    }                                                                           \
    rw->sorted_count = count;                                                   \
}                                                                               \
                                                                                \
static hook_err_t PREFIX##_chain_add(RW_TYPE *rw, void *before, void *after,    \
                                      void *udata, int32_t priority)            \
{                                                                               \
    if (!rw) return HOOK_BAD_ADDRESS;                                           \
    sync_write_lock();                                                          \
    MASK_TYPE avail = ~rw->occupied_mask;                                        \
    if (!avail) { sync_write_unlock(); return HOOK_CHAIN_FULL; }               \
    int32_t slot = __builtin_ctz(avail);                                        \
    if (slot >= rw->chain_items_max) { sync_write_unlock(); return HOOK_CHAIN_FULL; } \
    rw->occupied_mask |= (MASK_TYPE)1 << slot;                                  \
    hook_chain_item_t *item = &rw->items[slot];                                 \
    item->priority = priority;                                                  \
    item->udata = udata;                                                        \
    item->before = before;                                                      \
    item->after = after;                                                        \
    __builtin_memset(&item->local, 0, sizeof(hook_local_t));                    \
    PREFIX##_rebuild_sorted(rw);                                                \
    sync_write_unlock();                                                        \
    return HOOK_NO_ERR;                                                         \
}                                                                               \
                                                                                \
static void PREFIX##_chain_remove(RW_TYPE *rw, void *before, void *after)       \
{                                                                               \
    if (!rw) return;                                                            \
    sync_write_lock();                                                          \
    MASK_TYPE mask = rw->occupied_mask;                                          \
    while (mask) {                                                              \
        int32_t i = __builtin_ctz(mask);                                        \
        mask &= ~((MASK_TYPE)1 << i);                                           \
        hook_chain_item_t *item = &rw->items[i];                                \
        if (item->before == before && item->after == after) {                   \
            rw->occupied_mask &= ~((MASK_TYPE)1 << i);                          \
            item->before = 0;                                                   \
            item->after = 0;                                                    \
            item->udata = 0;                                                    \
            item->priority = 0;                                                 \
            PREFIX##_rebuild_sorted(rw);                                        \
            sync_write_unlock();                                                \
            return;                                                             \
        }                                                                       \
    }                                                                           \
    sync_write_unlock();                                                        \
}                                                                               \
                                                                                \
static int PREFIX##_chain_all_empty(RW_TYPE *rw)                                \
{                                                                               \
    return rw->occupied_mask == 0;                                              \
}

/* Generate inline hook chain ops (il_ prefix, 8 slots, uint16_t mask) */
DEFINE_CHAIN_OPS(il, hook_chain_rw_t, uint16_t)

/* Generate FP hook chain ops (fp_ prefix, 16 slots, uint32_t mask) */
DEFINE_CHAIN_OPS(fp, fp_hook_chain_rw_t, uint32_t)

/* Public API wrappers for inline hook chain */
hook_err_t hook_chain_add(hook_chain_rw_t *rw, void *before, void *after,
                          void *udata, int32_t priority)
{
    return il_chain_add(rw, before, after, udata, priority);
}

void hook_chain_remove(hook_chain_rw_t *rw, void *before, void *after)
{
    il_chain_remove(rw, before, after);
}

/* ---- Simple inline hook (no chain) ---- */

hook_err_t hook(void *func, void *replace, void **backup)
{
    if (!func || !replace || !backup)
        return HOOK_BAD_ADDRESS;

    func = STRIP_PAC(func);
    uintptr_t func_addr = (uintptr_t)func;

    if (hook_mem_get_rox_from_origin(func_addr))
        return HOOK_DUPLICATED;

    hook_chain_rox_t *rox =
        (hook_chain_rox_t *)hook_mem_alloc_rox(sizeof(hook_chain_rox_t));
    if (!rox)
        return HOOK_NO_MEM;

    hook_mem_rox_write_enable(rox, sizeof(hook_chain_rox_t));

    rox->rw = 0;

    hook_t *h = &rox->hook;
    h->func_addr = func_addr;
    h->origin_addr = func_addr;
    h->replace_addr = (uintptr_t)replace;
    h->relo_addr = (uintptr_t)h->relo_insts;
    h->tramp_insts_num = 0;
    h->relo_insts_num = 0;

    hook_err_t err = hook_prepare(h);
    if (err) {
        hook_mem_rox_write_disable(rox, sizeof(hook_chain_rox_t));
        hook_mem_free_rox(rox, sizeof(hook_chain_rox_t));
        return err;
    }

    hook_mem_rox_write_disable(rox, sizeof(hook_chain_rox_t));
    flush_code_cache(rox, sizeof(hook_chain_rox_t));

    hook_install(h);

    if (hook_mem_register_origin(func_addr, rox) != 0) {
        hook_uninstall(h);
        hook_mem_free_rox(rox, sizeof(hook_chain_rox_t));
        return HOOK_NO_MEM;
    }

    *backup = (void *)h->relo_addr;
    return HOOK_NO_ERR;
}

void unhook(void *func)
{
    if (!func)
        return;

    func = STRIP_PAC(func);
    uintptr_t func_addr = (uintptr_t)func;
    hook_chain_rox_t *rox =
        (hook_chain_rox_t *)hook_mem_get_rox_from_origin(func_addr);
    if (!rox)
        return;

    hook_uninstall(&rox->hook);
    hook_mem_unregister_origin(func_addr);
    hook_mem_free_rox(rox, sizeof(hook_chain_rox_t));
}

/* ---- Chain-based inline hook (hook_wrap) ---- */

hook_err_t hook_wrap(void *func, int32_t argno, void *before,
                     void *after, void *udata, int32_t priority)
{
    if (!func)
        return HOOK_BAD_ADDRESS;

    func = STRIP_PAC(func);
    uintptr_t func_addr = (uintptr_t)func;
    hook_chain_rox_t *rox;
    hook_chain_rw_t *rw;

    rox = (hook_chain_rox_t *)hook_mem_get_rox_from_origin(func_addr);

    if (!rox) {
        rox = (hook_chain_rox_t *)hook_mem_alloc_rox(sizeof(hook_chain_rox_t));
        if (!rox)
            return HOOK_NO_MEM;

        rw = (hook_chain_rw_t *)hook_mem_alloc_rw(sizeof(hook_chain_rw_t));
        if (!rw) {
            hook_mem_free_rox(rox, sizeof(hook_chain_rox_t));
            return HOOK_NO_MEM;
        }

        __builtin_memset(rw, 0, sizeof(hook_chain_rw_t));
        rw->rox = rox;
        rw->chain_items_max = HOOK_CHAIN_NUM;
        rw->argno = argno;
        rw->sorted_count = 0;

        hook_mem_rox_write_enable(rox, sizeof(hook_chain_rox_t));

        rox->rw = rw;

        hook_t *h = &rox->hook;
        h->func_addr = func_addr;
        h->origin_addr = func_addr;
        h->replace_addr = (uintptr_t)&rox->transit[2]; /* transit stub entry */
        h->relo_addr = (uintptr_t)h->relo_insts;
        h->tramp_insts_num = 0;
        h->relo_insts_num = 0;

        hook_err_t err = hook_prepare(h);
        if (err) {
            hook_mem_rox_write_disable(rox, sizeof(hook_chain_rox_t));
            hook_mem_free_rox(rox, sizeof(hook_chain_rox_t));
            hook_mem_free_rw(rw, sizeof(hook_chain_rw_t));
            return err;
        }

        hook_chain_setup_transit(rox);

        hook_mem_rox_write_disable(rox, sizeof(hook_chain_rox_t));
        flush_code_cache(rox, sizeof(hook_chain_rox_t));

        if (hook_mem_register_origin(func_addr, rox) != 0) {
            hook_mem_free_rox(rox, sizeof(hook_chain_rox_t));
            hook_mem_free_rw(rw, sizeof(hook_chain_rw_t));
            return HOOK_NO_MEM;
        }

        hook_install(&rox->hook);
    } else {
        rw = rox->rw;
        if (!rw)
            return HOOK_BAD_ADDRESS;
    }

    return hook_chain_add(rw, before, after, udata, priority);
}

/* ---- Hook unwrap / remove ---- */

void hook_unwrap_remove(void *func, void *before, void *after, int remove)
{
    if (!func)
        return;

    func = STRIP_PAC(func);
    uintptr_t func_addr = (uintptr_t)func;
    hook_chain_rox_t *rox =
        (hook_chain_rox_t *)hook_mem_get_rox_from_origin(func_addr);
    if (!rox || !rox->rw)
        return;

    hook_chain_rw_t *rw = rox->rw;

    hook_chain_remove(rw, before, after);

    if (remove && il_chain_all_empty(rw)) {
        hook_uninstall(&rox->hook);
        hook_mem_unregister_origin(func_addr);
        hook_mem_free_rw(rw, sizeof(hook_chain_rw_t));
        hook_mem_free_rox(rox, sizeof(hook_chain_rox_t));
    }
}

/* ==================================================================
 * Function pointer hook API
 * ================================================================== */

static void write_fp_value(uintptr_t fp_addr, uintptr_t value)
{
    *(volatile uintptr_t *)fp_addr = value;
}

/* ---- Simple function pointer hook (no chain) ---- */

void fp_hook(uintptr_t fp_addr, void *replace, void **backup)
{
    if (!fp_addr || !replace || !backup)
        return;

    fp_addr = (uintptr_t)STRIP_PAC(fp_addr);
    *backup = *(void **)fp_addr;
    write_fp_value(fp_addr, (uintptr_t)replace);
}

void fp_unhook(uintptr_t fp_addr, void *backup)
{
    if (!fp_addr)
        return;

    fp_addr = (uintptr_t)STRIP_PAC(fp_addr);
    write_fp_value(fp_addr, (uintptr_t)backup);
}

/* ---- Chain-based function pointer hook ---- */

hook_err_t fp_hook_wrap(uintptr_t fp_addr, int32_t argno, void *before,
                        void *after, void *udata, int32_t priority)
{
    if (!fp_addr)
        return HOOK_BAD_ADDRESS;

    fp_addr = (uintptr_t)STRIP_PAC(fp_addr);
    fp_hook_chain_rox_t *rox;
    fp_hook_chain_rw_t *rw;

    rox = (fp_hook_chain_rox_t *)hook_mem_get_rox_from_origin(fp_addr);

    if (!rox) {
        rox = (fp_hook_chain_rox_t *)hook_mem_alloc_rox(sizeof(fp_hook_chain_rox_t));
        if (!rox)
            return HOOK_NO_MEM;

        rw = (fp_hook_chain_rw_t *)hook_mem_alloc_rw(sizeof(fp_hook_chain_rw_t));
        if (!rw) {
            hook_mem_free_rox(rox, sizeof(fp_hook_chain_rox_t));
            return HOOK_NO_MEM;
        }

        __builtin_memset(rw, 0, sizeof(fp_hook_chain_rw_t));
        rw->rox = rox;
        rw->chain_items_max = FP_HOOK_CHAIN_NUM;
        rw->argno = argno;
        rw->sorted_count = 0;

        hook_mem_rox_write_enable(rox, sizeof(fp_hook_chain_rox_t));

        rox->rw = rw;

        fp_hook_t *h = &rox->hook;
        h->fp_addr = fp_addr;
        h->origin_fp = *(uintptr_t *)fp_addr;
        h->replace_addr = (uintptr_t)&rox->transit[2];

        fp_hook_chain_setup_transit(rox);

        hook_mem_rox_write_disable(rox, sizeof(fp_hook_chain_rox_t));
        flush_code_cache(rox, sizeof(fp_hook_chain_rox_t));

        if (hook_mem_register_origin(fp_addr, rox) != 0) {
            hook_mem_free_rox(rox, sizeof(fp_hook_chain_rox_t));
            hook_mem_free_rw(rw, sizeof(fp_hook_chain_rw_t));
            return HOOK_NO_MEM;
        }

        write_fp_value(fp_addr, h->replace_addr);
    } else {
        rw = rox->rw;
        if (!rw)
            return HOOK_BAD_ADDRESS;
    }

    return fp_chain_add(rw, before, after, udata, priority);
}

void fp_hook_unwrap(uintptr_t fp_addr, void *before, void *after)
{
    if (!fp_addr)
        return;

    fp_addr = (uintptr_t)STRIP_PAC(fp_addr);
    fp_hook_chain_rox_t *rox =
        (fp_hook_chain_rox_t *)hook_mem_get_rox_from_origin(fp_addr);
    if (!rox || !rox->rw)
        return;

    fp_hook_chain_rw_t *rw = rox->rw;

    fp_chain_remove(rw, before, after);

    if (fp_chain_all_empty(rw)) {
        write_fp_value(fp_addr, rox->hook.origin_fp);
        hook_mem_unregister_origin(fp_addr);
        hook_mem_free_rw(rw, sizeof(fp_hook_chain_rw_t));
        hook_mem_free_rox(rox, sizeof(fp_hook_chain_rox_t));
    }
}
