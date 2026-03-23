/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2026 bmax121.
 * Userspace hook_install / hook_uninstall and transit buffer setup.
 *
 * Replaces kernel pgtable-based write_insts_at() with
 * platform_set_rw / platform_set_rx + icache flush.
 */

#include <ktypes.h>
#include <hook.h>
#include <platform.h>
/* Use __builtin_memcpy for portability across freestanding and hosted. */
#define memcpy __builtin_memcpy

/* ---- Page-aligned mprotect helpers ---- */

/* Return the page-aligned start address containing addr. */
static uint64_t page_start(uint64_t addr)
{
    uint64_t ps = platform_page_size();
    return addr & ~(ps - 1);
}

/*
 * Write instructions to a code page.
 *
 * 1. Make the target page(s) RW
 * 2. Copy instructions
 * 3. Flush icache
 * 4. Restore RX
 *
 * Handles the case where the instruction range spans a page boundary.
 */
static void write_insts_at(uint64_t va, uint32_t *insts, int32_t count)
{
    uint64_t size = (uint64_t)count * sizeof(uint32_t);
    uint64_t start = page_start(va);
    uint64_t end = page_start(va + size - 1);

    /* Total region to mprotect: from start of first page to end of last page */
    uint64_t prot_size = (end - start) + platform_page_size();

    platform_set_rw(start, prot_size);

    for (int32_t i = 0; i < count; i++)
        *((uint32_t *)va + i) = insts[i];

    platform_flush_icache(va, size);
    platform_set_rx(start, prot_size);
}

/* ---- Public API ---- */

void hook_install(hook_t *hook)
{
    write_insts_at(hook->origin_addr, hook->tramp_insts, hook->tramp_insts_num);
}

void hook_uninstall(hook_t *hook)
{
    write_insts_at(hook->origin_addr, hook->origin_insts, hook->tramp_insts_num);
}

/* ---- Transit buffer setup ---- */

/* Defined in transit.c — naked asm stub template. */
extern uint64_t _transit(void);

/*
 * _transit_end is placed by the linker immediately after _transit.
 * With userspace toolchains we compute the size from _transit_end - _transit.
 * If the linker script does not provide _transit_end (e.g. no custom linker
 * script), we fall back to TRANSIT_INST_NUM which is the buffer capacity.
 */
extern void _transit_end(void) __attribute__((weak));

static uint64_t transit_stub_size(void)
{
    if (_transit_end) {
        return (uintptr_t)_transit_end - (uintptr_t)_transit;
    }
    /* Conservative fallback: TRANSIT_INST_NUM uint32_t words minus the
     * 2-word (8-byte) self-pointer prefix = (TRANSIT_INST_NUM - 2) * 4.
     * In practice, the stub is much smaller than this capacity. */
    return (TRANSIT_INST_NUM - 2) * sizeof(uint32_t);
}

/*
 * Set up the transit buffer inside a hook_chain_rox_t.
 *
 * Layout:
 *   transit[0..1] = uint64_t self-pointer to the containing hook_chain_rox_t
 *   transit[2..]  = copied _transit stub machine code
 *
 * The ROX memory must be made writable before calling this function,
 * and restored to RX afterwards (caller is responsible).
 */
void hook_chain_setup_transit(hook_chain_rox_t *rox)
{
    /* Self-pointer: the transit stub uses this to locate rox in O(1). */
    *(uint64_t *)&rox->transit[0] = (uint64_t)rox;

    /* Copy the universal asm stub template. */
    uint64_t sz = transit_stub_size();
    memcpy(&rox->transit[2], (void *)(uintptr_t)_transit, sz);
}

/* ---- Function pointer hook transit setup ---- */

extern uint64_t _fp_transit(void);
extern void _fp_transit_end(void) __attribute__((weak));

static uint64_t fp_transit_stub_size(void)
{
    if (_fp_transit_end) {
        return (uintptr_t)_fp_transit_end - (uintptr_t)_fp_transit;
    }
    return (TRANSIT_INST_NUM - 2) * sizeof(uint32_t);
}

void fp_hook_chain_setup_transit(fp_hook_chain_rox_t *rox)
{
    *(uint64_t *)&rox->transit[0] = (uint64_t)rox;

    uint64_t sz = fp_transit_stub_size();
    memcpy(&rox->transit[2], (void *)(uintptr_t)_fp_transit, sz);
}
