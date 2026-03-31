/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Kernel-side transit buffer setup.
 *
 * Provides hook_chain_setup_transit() and fp_hook_chain_setup_transit()
 * for the freestanding kernel build.  These copy the asm transit stubs
 * into the ROX buffer — no platform_write_code() needed because the
 * caller already holds the ROX write-enable.
 */

#ifdef KMOD_FREESTANDING
#include "../shim/kmod_shim.h"
#else
#include <linux/string.h>
#endif

#include <ktypes.h>
#include <hook.h>
#include <log.h>

extern uint64_t _transit(void);
extern void _transit_end(void);
extern uint64_t _fp_transit(void);
extern void _fp_transit_end(void);

static uint64_t stub_size(void *start, void *end)
{
    if (end)
        return (uintptr_t)end - (uintptr_t)start;
    return (TRANSIT_INST_NUM - 2) * sizeof(uint32_t);
}

static void setup_transit(void *rox, uint32_t *transit,
                           void *stub_start, void *stub_end)
{
    *(uint64_t *)&transit[0] = (uint64_t)rox;
    uint64_t sz = stub_size(stub_start, stub_end);
    uint64_t avail = (TRANSIT_INST_NUM - 2) * sizeof(uint32_t);
    if (sz > avail) {
        logke("transit stub (%llu) exceeds buffer (%llu)",
              (unsigned long long)sz, (unsigned long long)avail);
        return;
    }
    memcpy(&transit[2], stub_start, sz);
}

void hook_chain_setup_transit(hook_chain_rox_t *rox)
{
    setup_transit(rox, rox->transit,
                  (void *)(uintptr_t)_transit, (void *)(uintptr_t)_transit_end);
}

void fp_hook_chain_setup_transit(fp_hook_chain_rox_t *rox)
{
    setup_transit(rox, rox->transit,
                  (void *)(uintptr_t)_fp_transit, (void *)(uintptr_t)_fp_transit_end);
}
