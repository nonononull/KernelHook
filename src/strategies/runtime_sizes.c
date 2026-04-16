/* src/strategies/runtime_sizes.c */
/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * SP-7 Capability: pt_regs_size (Task 19)
 *
 * Strategies:
 *   prio 0: probe_from_current_task — returns ENODATA in the current impl.
 *           An honest runtime probe requires a live syscall entry to inspect;
 *           not available from module_init context. Reserved for future work.
 *   prio 1: const_default — returns 0x150 (stable arm64 sizeof(pt_regs) on
 *           GKI 5.10+). Logs a pr_warn indicating probe was unavailable.
 *
 * Build modes: freestanding + kbuild (not userspace -- kernel-only).
 */

#include <kh_strategy.h>
#include <kh_log.h>
#include <types.h>

#ifdef __USERSPACE__
/* pt_regs_size strategies are kernel-only.
 * In userspace builds the translation unit compiles to nothing. */
#else

static int strat_probe_pt_regs_size(void *out, size_t sz)
{
    (void)out;
    if (sz != sizeof(uint64_t)) return -22;
    /* No reliable probe from module_init context. Defer to const_default. */
    return KH_STRAT_ENODATA;
}

static int strat_const_default_pt_regs_size(void *out, size_t sz)
{
    if (sz != sizeof(uint64_t)) return -22;
    *(uint64_t *)out = 0x150;
    /* pr_info not pr_warn: probe is intentionally ENODATA — const_default
     * is the designed-active path, not an abnormality. */
    pr_info("[kh_strategy] pt_regs_size const default 0x150 (probe deferred)\n");
    return 0;
}

KH_STRATEGY_DECLARE(pt_regs_size, probe_from_current_task, 0, strat_probe_pt_regs_size,         sizeof(uint64_t));
KH_STRATEGY_DECLARE(pt_regs_size, const_default,           1, strat_const_default_pt_regs_size, sizeof(uint64_t));

#endif /* !__USERSPACE__ */
