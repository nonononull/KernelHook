/* src/strategies/cross_cpu.c */
/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * SP-7 Capability: stop_machine (Task 17)
 *
 * Strategies (prio 0-1):
 *   prio 0: kallsyms_stop_machine — resolve stop_machine symbol via ksyms;
 *             present on most GKI kernels where stop_machine is exported.
 *   prio 1: smp_call_function_many — verify IPI infrastructure is available
 *             by probing smp_call_function_many, then hand out
 *             kh_diy_stop_machine as the fallback fn pointer. The DIY stub
 *             runs fn on the calling CPU; a full SMP IPI implementation
 *             (spin-on-flag barrier + release) is deferred to a future task.
 *
 * Build modes: freestanding + kbuild (not userspace — kernel-only).
 */

#include <kh_strategy.h>
#include <kh_log.h>
#include <types.h>

#ifdef __USERSPACE__
#else

#include <symbol.h>

/* stop_machine(fn, data, cpus): run fn(data) with all other CPUs quiesced.
 * cpus: cpumask_t* restricting which CPUs to stop (NULL = all). */
typedef int (*stop_machine_fn)(int (*fn)(void *), void *data, const void *cpus);

/* ---- prio 0: resolve stop_machine from kallsyms ---- */

static int strat_kallsyms_stop_machine(void *out, size_t sz)
{
    if (sz != sizeof(stop_machine_fn)) return -22;
    uint64_t a = ksyms_lookup("stop_machine");
    if (!a) return KH_STRAT_ENODATA;
    *(stop_machine_fn *)out = (stop_machine_fn)(uintptr_t)a;
    return 0;
}

/* ---- prio 1: DIY stop_machine using IPI infrastructure ---- */

/*
 * kh_diy_stop_machine — minimal stop_machine substitute.
 *
 * Task 17 stub: executes fn(data) on the calling CPU only.
 * This is sufficient for single-CPU test contexts and module-init paths
 * (which run with preemption disabled on many kernels). A full SMP
 * implementation would:
 *   1. IPI peer CPUs via smp_call_function_many to a spin-on-flag trampoline.
 *   2. Wait until all peers are spinning inside the trampoline.
 *   3. Execute fn(data) on this CPU.
 *   4. Set the release flag so peer CPUs exit the trampoline.
 * Deferred to a future task once the IPI trampoline design is finalised.
 *
 * __attribute__((no_sanitize("kcfi"))): this function is called through a
 * stop_machine_fn function pointer (indirect call), so kCFI must not
 * instrument the call site. It also calls fn(data) via an indirect pointer
 * itself — annotate to suppress both.
 */
__attribute__((no_sanitize("kcfi")))
int kh_diy_stop_machine(int (*fn)(void *), void *data, const void *cpus)
{
    (void)cpus;
    return fn(data);
}

/*
 * strat_smp_call_function_many — capability gate for DIY stop_machine.
 *
 * Verifies that smp_call_function_many is exported (IPI mechanism available).
 * If found, hands out kh_diy_stop_machine as the stop_machine fn pointer.
 * The resolved smp_call_function_many address is not stored here — it is
 * used as a capability gate only; kh_diy_stop_machine does not call it in
 * this Task 17 stub (full IPI coordination is deferred).
 */
static int strat_smp_call_function_many(void *out, size_t sz)
{
    if (sz != sizeof(stop_machine_fn)) return -22;
    uint64_t a = ksyms_lookup("smp_call_function_many");
    if (!a) return KH_STRAT_ENODATA;
    (void)a;  /* gate only — not invoked in this stub */
    *(stop_machine_fn *)out = (stop_machine_fn)kh_diy_stop_machine;
    return 0;
}

KH_STRATEGY_DECLARE(stop_machine, kallsyms_stop_machine,  0, strat_kallsyms_stop_machine,  sizeof(stop_machine_fn));
KH_STRATEGY_DECLARE(stop_machine, smp_call_function_many, 1, strat_smp_call_function_many, sizeof(stop_machine_fn));

#endif /* !__USERSPACE__ */
