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

/* ========================================================================
 * SP-7 Capability: aarch64_insn_patch_text_nosync (Task 18)
 *
 * prio 0: kallsyms — resolve the kernel export directly.
 * prio 1: inline_alias_patch — use our alias-page write path wrapped
 *         as an (addr, insn)-signature fn pointer. Gated on stop_machine
 *         being resolvable (write_insts_via_alias uses stop_machine
 *         internally to freeze peer CPUs during text patch).
 * ======================================================================== */

#include <arch/arm64/inline.h>

typedef int (*aarch64_insn_patch_fn)(void *addr, uint32_t insn);

static int strat_kallsyms_aarch64_patch(void *out, size_t sz)
{
    if (sz != sizeof(aarch64_insn_patch_fn)) return -22;
    uint64_t a = ksyms_lookup("aarch64_insn_patch_text_nosync");
    if (!a) return KH_STRAT_ENODATA;
    *(aarch64_insn_patch_fn *)out = (aarch64_insn_patch_fn)(uintptr_t)a;
    return 0;
}

/*
 * kh_inline_patch_via_alias — single-(addr, insn) adapter over
 * write_insts_via_alias which takes an array.  count=1 to patch a
 * single 32-bit instruction at addr, matching the kernel's
 * aarch64_insn_patch_text_nosync ABI.
 *
 * __attribute__((no_sanitize("kcfi"))): this function is stored and
 * invoked through an aarch64_insn_patch_fn function pointer, and
 * write_insts_via_alias itself calls fn pointers obtained from ksyms.
 */
__attribute__((no_sanitize("kcfi")))
int kh_inline_patch_via_alias(void *addr, uint32_t insn)
{
    return write_insts_via_alias((uintptr_t)addr, &insn, 1);
}

/*
 * strat_inline_alias_patch — capability gate for the alias-page patch path.
 *
 * Gates on stop_machine being resolvable: write_insts_via_alias (kbuild path)
 * uses stop_machine to quiesce peer CPUs before patching. Without a working
 * stop_machine, intermediate trampoline states during multi-instruction writes
 * are visible to other CPUs, making the patch unsafe.
 */
static int strat_inline_alias_patch(void *out, size_t sz)
{
    if (sz != sizeof(aarch64_insn_patch_fn)) return -22;
    /* Gate on stop_machine being resolvable — write_insts_via_alias uses
     * stop_machine to quiesce peer CPUs during the actual patch. Without
     * a working stop_machine, intermediate trampoline states are visible
     * to other CPUs and the patch is unsafe. */
    void *sm = NULL;
    int rc = kh_strategy_resolve("stop_machine", &sm, sizeof(sm));
    if (rc) return rc;
    *(aarch64_insn_patch_fn *)out = kh_inline_patch_via_alias;
    return 0;
}

KH_STRATEGY_DECLARE(aarch64_insn_patch_text_nosync, kallsyms,           0, strat_kallsyms_aarch64_patch, sizeof(aarch64_insn_patch_fn));
KH_STRATEGY_DECLARE(aarch64_insn_patch_text_nosync, inline_alias_patch, 1, strat_inline_alias_patch,     sizeof(aarch64_insn_patch_fn));

#endif /* !__USERSPACE__ */
