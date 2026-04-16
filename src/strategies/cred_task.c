/* src/strategies/cred_task.c */
/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * SP-7 Capability: init_cred (and in future Task 13: init_thread_union,
 * thread_size).
 *
 * Three fallback strategies for resolving `init_cred`:
 *   1. kallsyms_init_cred - direct lookup (init_cred symbol IS the cred
 *      struct itself, so the symbol address IS the pointer we want)
 *   2. current_task_walk  - read current (sp_el0) and scan the task_struct
 *      for a plausible cred pointer field
 *   3. init_task_walk     - look up init_task, walk it the same way
 *
 * The walk heuristic: scan first 0x1000 bytes of task_struct at 8-byte
 * stride. Candidate is a kernel VA (>= 0xffff000000000000) whose first
 * 4 bytes look like a small reference count (1..0xFFFF) and next 4 bytes
 * look like a plausible uid (<65536 or 0xFFFFFFFF meaning KUIDT_INIT).
 * This mirrors KernelPatch's task_cred.c layout probe.
 *
 * Build modes: freestanding + kbuild (not userspace -- kernel-only).
 */

#include <kh_strategy.h>
#include <kh_log.h>
#include <types.h>

#ifdef __USERSPACE__
#else

#include <symbol.h>

/* in_interrupt() — provided by linux/preempt.h in kbuild mode; our
 * freestanding shim defines it too. Pull via linux/sched.h as specified
 * in the task plan. */
#include <linux/sched.h>

static uint64_t walk_task_for_cred(uint64_t task)
{
    /* Scan the first 0x1000 bytes of task_struct at 8-byte stride looking
     * for a `struct cred *cred` (or `real_cred`) field. Candidate must:
     *   - be a kernel VA (bit 63 set for canonical 48-bit VAs)
     *   - first 4 bytes read as a plausible usage count (1..0xFFFF)
     *   - next 4 bytes read as a plausible uid (< 65536 or 0xFFFFFFFF
     *     for the init KUIDT sentinel)
     * Returns 0 if no candidate found. */
    for (unsigned long off = 0; off < 0x1000; off += 8) {
        uint64_t cand = *(uint64_t *)(task + off);
        if (cand < 0xffff000000000000ULL) continue;
        uint32_t usage = *(uint32_t *)cand;
        if (usage < 1 || usage > 0xFFFF) continue;
        uint32_t uid = *(uint32_t *)(cand + 4);
        if (uid < 65536 || uid == 0xFFFFFFFFU)
            return cand;
    }
    return 0;
}

static int strat_kallsyms_init_cred(void *out, size_t sz)
{
    if (sz != sizeof(uint64_t)) return -22;
    uint64_t a = ksyms_lookup("init_cred");
    if (!a) return KH_STRAT_ENODATA;
    /* init_cred IS a struct cred; its symbol address IS the pointer. */
    *(uint64_t *)out = a;
    return 0;
}

static int strat_current_task_walk(void *out, size_t sz)
{
    if (sz != sizeof(uint64_t)) return -22;
    /* current_task_walk is a "does current have a cred" probe; it may
     * return a DIFFERENT cred than init_cred for non-init tasks. The
     * L2 test handles this asymmetry (does not assert equality with
     * kallsyms_init_cred). */
    if (in_interrupt()) return -11;   /* -EAGAIN: cannot probe current
                                         task from interrupt context */
    uint64_t task;
    asm volatile("mrs %0, sp_el0" : "=r"(task));
    uint64_t c = walk_task_for_cred(task);
    if (!c) return KH_STRAT_ENODATA;
    *(uint64_t *)out = c;
    return 0;
}

static int strat_init_task_walk(void *out, size_t sz)
{
    if (sz != sizeof(uint64_t)) return -22;
    uint64_t task = ksyms_lookup("init_task");
    if (!task) return KH_STRAT_ENODATA;
    uint64_t c = walk_task_for_cred(task);
    if (!c) return KH_STRAT_ENODATA;
    *(uint64_t *)out = c;
    return 0;
}

KH_STRATEGY_DECLARE(init_cred, kallsyms_init_cred, 0, strat_kallsyms_init_cred, sizeof(uint64_t));
KH_STRATEGY_DECLARE(init_cred, current_task_walk,  1, strat_current_task_walk,  sizeof(uint64_t));
KH_STRATEGY_DECLARE(init_cred, init_task_walk,     2, strat_init_task_walk,     sizeof(uint64_t));

#endif /* !__USERSPACE__ */
