/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2026 bmax121.
 * Userspace hook_mem_ops_t backends using platform.h abstraction.
 */

#include <ktypes.h>
#include <hmem.h>
#include <platform.h>
#include <hmem_user.h>

/* hook_mem_ops_t.free takes (ptr) only, but platform_free needs (ptr, size). */

#define MAX_ALLOC_TRACK 4

static struct {
    void *ptr;
    uint64_t size;
} alloc_track[MAX_ALLOC_TRACK];
static int alloc_track_count;

static void alloc_track_add(void *ptr, uint64_t size)
{
    if (alloc_track_count < MAX_ALLOC_TRACK) {
        alloc_track[alloc_track_count].ptr = ptr;
        alloc_track[alloc_track_count].size = size;
        alloc_track_count++;
    }
}

static uint64_t alloc_track_remove(void *ptr)
{
    for (int i = 0; i < alloc_track_count; i++) {
        if (alloc_track[i].ptr == ptr) {
            uint64_t size = alloc_track[i].size;
            alloc_track[i] = alloc_track[alloc_track_count - 1];
            alloc_track_count--;
            return size;
        }
    }
    return 0;
}

/* ---- ROX ops wrappers ---- */

static void *rox_alloc(uint64_t size)
{
    void *ptr = platform_alloc_rox(size);
    if (ptr)
        alloc_track_add(ptr, size);
    return ptr;
}

static void rox_free(void *ptr)
{
    uint64_t size = alloc_track_remove(ptr);
    if (size)
        platform_free(ptr, size);
}

static int rox_set_memory(uint64_t addr, int numpages, int (*fn)(uint64_t, uint64_t))
{
    return fn(addr, (uint64_t)numpages * platform_page_size());
}

static int rox_set_memory_rw(uint64_t addr, int numpages) { return rox_set_memory(addr, numpages, platform_set_rw); }
static int rox_set_memory_ro(uint64_t addr, int numpages) { return rox_set_memory(addr, numpages, platform_set_ro); }
static int rox_set_memory_x(uint64_t addr, int numpages)  { return rox_set_memory(addr, numpages, platform_set_rx); }

/* ---- RW ops wrappers ---- */

static void *rw_alloc(uint64_t size)
{
    void *ptr = platform_alloc_rw(size);
    if (ptr)
        alloc_track_add(ptr, size);
    return ptr;
}

static void rw_free(void *ptr)
{
    uint64_t size = alloc_track_remove(ptr);
    if (size)
        platform_free(ptr, size);
}

static int rw_set_memory_nop(uint64_t addr __maybe_unused, int numpages __maybe_unused)
{
    return 0;
}

/* ---- Public API ---- */

int hmem_user_init(void)
{
    static const hook_mem_ops_t rox_ops = {
        .alloc = rox_alloc,
        .free = rox_free,
        .set_memory_rw = rox_set_memory_rw,
        .set_memory_ro = rox_set_memory_ro,
        .set_memory_x = rox_set_memory_x,
    };

    static const hook_mem_ops_t rw_ops = {
        .alloc = rw_alloc,
        .free = rw_free,
        .set_memory_rw = rw_set_memory_nop,
        .set_memory_ro = rw_set_memory_nop,
        .set_memory_x = rw_set_memory_nop,
    };

    alloc_track_count = 0;

    return hook_mem_init(&rox_ops, &rw_ops, platform_page_size());
}

void hmem_user_cleanup(void)
{
    hook_mem_cleanup();
    alloc_track_count = 0;
}
