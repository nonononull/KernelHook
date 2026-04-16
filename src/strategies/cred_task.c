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

/*
 * sp_el0 caveat for pre-4.9 kernels (CONFIG_THREAD_INFO_IN_TASK=n,
 * i.e. GKI 4.4): sp_el0 holds `struct thread_info *`, not
 * `struct task_struct *`. On those kernels this strategy walks
 * thread_info and almost always fails the walker's usage+uid
 * heuristic, returning ENODATA so the registry falls through to
 * init_task_walk (prio 2). In the unlikely case the heuristic
 * accepts a false positive, the caller would cache a wrong cred
 * pointer -- but in practice kallsyms_init_cred (prio 0) succeeds
 * on GKI 4.4 kernels we've tested, so this path is rarely reached.
 *
 * From 4.9+ (CONFIG_THREAD_INFO_IN_TASK=y, Android 9 onward and
 * every GKI target except the Pixel_28 AVD) sp_el0 holds the
 * task pointer and this walk is semantically correct.
 *
 * No runtime version detection is attempted: Linux version
 * sniffing is fragile across BSP backports. The priority ordering
 * + strict walker criteria provide sufficient defense in depth.
 */
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

/* ========================================================================
 * SP-7 Capability: init_thread_union (kernel stack base VA)
 *
 * Three strategies:
 *   1. kallsyms_init_thread_union - direct lookup (standard export name)
 *   2. kallsyms_init_stack         - alternate export name on some kernels
 *   3. current_task_stack          - scan current task_struct for a
 *                                    thread-size-aligned kernel-VA field
 * ======================================================================== */

static int strat_kallsyms_init_thread_union(void *out, size_t sz)
{
    if (sz != sizeof(uint64_t)) return -22;
    uint64_t a = ksyms_lookup("init_thread_union");
    if (!a) return KH_STRAT_ENODATA;
    *(uint64_t *)out = a;
    return 0;
}

static int strat_kallsyms_init_stack(void *out, size_t sz)
{
    if (sz != sizeof(uint64_t)) return -22;
    uint64_t a = ksyms_lookup("init_stack");
    if (!a) return KH_STRAT_ENODATA;
    *(uint64_t *)out = a;
    return 0;
}

/* Walk the first 0x200 bytes of a task_struct at 8-byte stride looking for
 * a kernel-VA pointer that is aligned to a known thread size (8K/16K/32K).
 * Returns 0 if no candidate found. Same sp_el0 caveat as
 * strat_current_task_walk applies on pre-4.9 kernels. */
static uint64_t find_stack_in_task(uint64_t task)
{
    for (unsigned long off = 0; off < 0x200; off += 8) {
        uint64_t cand = *(uint64_t *)(task + off);
        if (cand < 0xffff000000000000ULL) continue;
        /* Thread sizes we accept: 8K (older ARM32-ish), 16K (most ARM64),
         * 32K (some hardened builds). Try largest alignment first so we
         * prefer the strongest match. */
        for (uint64_t ts = 32768; ts >= 8192; ts >>= 1) {
            if ((cand & (ts - 1)) == 0) return cand;
        }
    }
    return 0;
}

/* See strat_current_task_walk in the init_cred section for the sp_el0
 * semantics caveat on pre-4.9 kernels (CONFIG_THREAD_INFO_IN_TASK=n). */
static int strat_current_task_stack(void *out, size_t sz)
{
    if (sz != sizeof(uint64_t)) return -22;
    if (in_interrupt()) return -11;   /* -EAGAIN */
    uint64_t task;
    asm volatile("mrs %0, sp_el0" : "=r"(task));
    uint64_t s = find_stack_in_task(task);
    if (!s) return KH_STRAT_ENODATA;
    *(uint64_t *)out = s;
    return 0;
}

KH_STRATEGY_DECLARE(init_thread_union, kallsyms_init_thread_union, 0, strat_kallsyms_init_thread_union, sizeof(uint64_t));
KH_STRATEGY_DECLARE(init_thread_union, kallsyms_init_stack,        1, strat_kallsyms_init_stack,        sizeof(uint64_t));
KH_STRATEGY_DECLARE(init_thread_union, current_task_stack,         2, strat_current_task_stack,         sizeof(uint64_t));

/* ========================================================================
 * SP-7 Capability: thread_size (kernel stack size)
 *
 * Two strategies:
 *   1. probe_from_current_task - infer from stack alignment of current
 *   2. const_default           - 16384 (most common ARM64 value)
 * ======================================================================== */

static int strat_probe_thread_size(void *out, size_t sz)
{
    if (sz != sizeof(uint64_t)) return -22;
    /* Direct intra-file call instead of kh_strategy_resolve("init_thread_union",...).
     * Rationale:
     *   (a) avoids pulling the registry cache for a different capability into
     *       this probe;
     *   (b) strat_current_task_stack handles its own in_interrupt guard.
     * Implication: a kh_strategy_force("init_thread_union", ...) is NOT
     * respected by this path — we always use strat_current_task_stack. That is
     * by design (the probe needs CURRENT's stack, not the natural-priority
     * init_thread_union winner, which could be the kallsyms init_thread_union
     * address == pointing to init's stack, irrelevant to current's size). */
    uint64_t stack = 0;
    int rc = strat_current_task_stack(&stack, sizeof(stack));
    if (rc) return rc;
    /* Largest alignment wins (most specific). */
    for (uint64_t ts = 32768; ts >= 8192; ts >>= 1) {
        if ((stack & (ts - 1)) == 0) { *(uint64_t *)out = ts; return 0; }
    }
    return KH_STRAT_ENODATA;
}

static int strat_const_default_thread_size(void *out, size_t sz)
{
    if (sz != sizeof(uint64_t)) return -22;
    *(uint64_t *)out = 16384;
    pr_warn("[kh_strategy] thread_size using const default 16384\n");
    return 0;
}

KH_STRATEGY_DECLARE(thread_size, probe_from_current_task, 0, strat_probe_thread_size,         sizeof(uint64_t));
KH_STRATEGY_DECLARE(thread_size, const_default,           1, strat_const_default_thread_size, sizeof(uint64_t));

#endif /* !__USERSPACE__ */
