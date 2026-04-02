// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2026 bmax121.
 * Kernel-side hook_mem_ops_t backend.
 *
 * Two build paths:
 *   Kbuild (default):     uses kernel headers (vmalloc, set_memory_*)
 *   KMOD_FREESTANDING:    resolves all symbols via ksyms_lookup() at runtime
 */

#ifdef KMOD_FREESTANDING
#include "../shim/kmod_shim.h"
#include <hmem.h>
#include <hook.h>
#include <ksyms.h>
#include <log.h>
#else
#include <linux/vmalloc.h>
#include <linux/mm.h>
#include <linux/version.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0)
#include <linux/set_memory.h>
#else
#include <asm/set_memory.h>
#endif
#include "../../include/hmem.h"
#include "../../include/log.h"
#endif /* KMOD_FREESTANDING */

/* ========================================================================
 * Freestanding path: resolve vmalloc/vfree/set_memory_* via ksyms
 * ======================================================================== */
#ifdef KMOD_FREESTANDING

typedef void *(*vmalloc_fn_t)(unsigned long size);
typedef void  (*vfree_fn_t)(const void *addr);
typedef int   (*set_memory_fn_t)(unsigned long addr, int numpages);

static vmalloc_fn_t    sym_vmalloc;
static vfree_fn_t      sym_vfree;
static set_memory_fn_t sym_set_memory_rw;
static set_memory_fn_t sym_set_memory_ro;
static set_memory_fn_t sym_set_memory_x;

struct sym_fallback {
    const char *primary;
    const char *fallback;
};

static uint64_t resolve_with_fallback(const struct sym_fallback *fb)
{
    uint64_t addr = ksyms_lookup(fb->primary);
    if (!addr && fb->fallback)
        addr = ksyms_lookup(fb->fallback);
    return addr;
}

static int resolve_freestanding_syms(void)
{
    static const struct sym_fallback fb_vmalloc    = { "vmalloc",         NULL };
    static const struct sym_fallback fb_vfree      = { "vfree",           NULL };
    static const struct sym_fallback fb_set_rw     = { "set_memory_rw",   NULL };
    static const struct sym_fallback fb_set_ro     = { "set_memory_ro",   NULL };
    /* set_memory_x was added in 5.8; older kernels export set_memory_exec */
    static const struct sym_fallback fb_set_x      = { "set_memory_x",    "set_memory_exec" };

    sym_vmalloc = (vmalloc_fn_t)(uintptr_t)resolve_with_fallback(&fb_vmalloc);
    if (!sym_vmalloc) {
        logke("kmod_mem_ops: failed to resolve vmalloc");
        return -1;
    }

    sym_vfree = (vfree_fn_t)(uintptr_t)resolve_with_fallback(&fb_vfree);
    if (!sym_vfree) {
        logke("kmod_mem_ops: failed to resolve vfree");
        return -1;
    }

    sym_set_memory_rw = (set_memory_fn_t)(uintptr_t)resolve_with_fallback(&fb_set_rw);
    if (!sym_set_memory_rw) {
        logke("kmod_mem_ops: failed to resolve set_memory_rw");
        return -1;
    }

    sym_set_memory_ro = (set_memory_fn_t)(uintptr_t)resolve_with_fallback(&fb_set_ro);
    if (!sym_set_memory_ro) {
        logke("kmod_mem_ops: failed to resolve set_memory_ro");
        return -1;
    }

    sym_set_memory_x = (set_memory_fn_t)(uintptr_t)resolve_with_fallback(&fb_set_x);
    if (!sym_set_memory_x) {
        logkw("kmod_mem_ops: set_memory_x/set_memory_exec not found — ROX pool may not be executable");
    }

    return 0;
}

/* Inline wrappers so the ops table below can use a uniform calling convention.
 * KCFI_EXEMPT: all sym_* are ksyms-resolved function pointers — kCFI hash
 * may not match (especially with CONFIG_CFI_ICALL_NORMALIZE_INTEGERS). */
KCFI_EXEMPT
static void *kmod_vmalloc(uint64_t size)
{
    return sym_vmalloc((unsigned long)size);
}
KCFI_EXEMPT
static void kmod_vfree(const void *addr)
{
    sym_vfree(addr);
}
KCFI_EXEMPT
static int kmod_set_memory_rw(unsigned long addr, int numpages)
{
    return sym_set_memory_rw(addr, numpages);
}
KCFI_EXEMPT
static int kmod_set_memory_ro(unsigned long addr, int numpages)
{
    return sym_set_memory_ro(addr, numpages);
}
KCFI_EXEMPT
static int kmod_set_memory_x(unsigned long addr, int numpages)
{
    if (!sym_set_memory_x)
        return 0;
    return sym_set_memory_x(addr, numpages);
}

#else /* !KMOD_FREESTANDING — Kbuild path, kernel headers available */

static void *kmod_vmalloc(uint64_t size)
{
    return vmalloc((unsigned long)size);
}
static void kmod_vfree(const void *addr)
{
    vfree(addr);
}
static int kmod_set_memory_rw(unsigned long addr, int numpages)
{
    return set_memory_rw(addr, numpages);
}
static int kmod_set_memory_ro(unsigned long addr, int numpages)
{
    return set_memory_ro(addr, numpages);
}
static int kmod_set_memory_x(unsigned long addr, int numpages)
{
    return set_memory_x(addr, numpages);
}

#endif /* KMOD_FREESTANDING */

/* ========================================================================
 * hook_mem_ops_t callbacks (shared by both build paths)
 * ======================================================================== */

/* ROX pool — read / execute memory, modifiable transiently via set_memory_rw */

static void *rox_alloc(uint64_t size)
{
    return kmod_vmalloc(size);
}

static void rox_free(void *ptr)
{
    kmod_vfree(ptr);
}

static int rox_set_memory_rw(uint64_t addr, int numpages)
{
    return kmod_set_memory_rw((unsigned long)addr, numpages);
}

static int rox_set_memory_ro(uint64_t addr, int numpages)
{
    return kmod_set_memory_ro((unsigned long)addr, numpages);
}

static int rox_set_memory_x(uint64_t addr, int numpages)
{
    return kmod_set_memory_x((unsigned long)addr, numpages);
}

/* RW pool — ordinary read/write memory, no permission toggling needed */

static void *rw_alloc(uint64_t size)
{
    return kmod_vmalloc(size);
}

static void rw_free(void *ptr)
{
    kmod_vfree(ptr);
}

static int rw_set_memory_nop(uint64_t addr __unused, int numpages __unused)
{
    return 0;
}

/* ========================================================================
 * Public API
 * ======================================================================== */

int kmod_hook_mem_init(void)
{
#ifdef KMOD_FREESTANDING
    int rc = resolve_freestanding_syms();
    if (rc)
        return rc;
#endif

    static const hook_mem_ops_t rox_ops = {
        .alloc          = rox_alloc,
        .free           = rox_free,
        .set_memory_rw  = rox_set_memory_rw,
        .set_memory_ro  = rox_set_memory_ro,
        .set_memory_x   = rox_set_memory_x,
    };

    static const hook_mem_ops_t rw_ops = {
        .alloc          = rw_alloc,
        .free           = rw_free,
        .set_memory_rw  = rw_set_memory_nop,
        .set_memory_ro  = rw_set_memory_nop,
        .set_memory_x   = rw_set_memory_nop,
    };

    return hook_mem_init(&rox_ops, &rw_ops, PAGE_SIZE);
}

void kmod_hook_mem_cleanup(void)
{
    /* The ROX pool was made read-only + executable via set_memory_ro/x.
     * vfree() internally calls clear_page() which writes to the pages.
     * We must restore write permission before freeing, otherwise the
     * write to RO pages causes a fatal exception (clear_page panic). */
    /* hook_mem_rox_pool_base/size declared in hmem.h */
    uint64_t rox_base = hook_mem_rox_pool_base();
    uint64_t rox_size = hook_mem_rox_pool_size();
    if (rox_base && rox_size) {
        int npages = (int)(rox_size / PAGE_SIZE);
        kmod_set_memory_rw((unsigned long)rox_base, npages);
    }

    hook_mem_cleanup();
}
