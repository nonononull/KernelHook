/* tests/kmod/test_resolver_cross_cpu.c */
/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <types.h>
#include "test_resolver_common.h"

typedef int (*stop_machine_fn)(int (*fn)(void *), void *data, const void *cpus);

/* Forward declaration for the DIY stub defined in cross_cpu.c.
 * Used for the behavioral invocation test below. */
extern int kh_diy_stop_machine(int (*fn)(void *), void *data, const void *cpus);

/* noop_stop_body: trivial fn passed to stop_machine / kh_diy_stop_machine. */
static int noop_stop_body(void *data)
{
    *(int *)data = 42;
    return 0;
}

/*
 * test_resolver_cross_cpu_stop — Part A (resolution) + Part B (behavioral).
 *
 * Part A: verify the stop_machine capability resolves to a non-NULL fn ptr.
 *   On kernels where stop_machine is exported, the kallsyms strategy (prio 0)
 *   fires. On kernels where it is not exported but smp_call_function_many is,
 *   the DIY strategy (prio 1) fires and hands out kh_diy_stop_machine.
 *
 * Part B: invoke kh_diy_stop_machine directly (not through the resolved sm
 *   pointer) and confirm the body executed.
 *
 *   Why not invoke sm() directly? The kernel's stop_machine internally calls
 *   fn(data) via a kCFI-checked indirect call (multi_cpu_stop). The kCFI type
 *   hash the kernel uses for its int (*fn)(void *) prototype differs from the
 *   hash our compiler assigns to noop_stop_body, because kCFI hashes are
 *   computed per-TU/build and are not portable across module boundaries on
 *   GKI 6.x. Invoking sm(noop_stop_body,...) when sm == stop_machine triggers
 *   "CFI failure at multi_cpu_stop" — kernel panic. kh_diy_stop_machine is
 *   our own code compiled in the same module, so hashes match.
 *
 * No no_sanitize("kcfi") needed here: the call to kh_diy_stop_machine is a
 * direct call (same-module extern resolved to CALL26 at link time, not an
 * indirect call through a fn pointer), and the fn(data) callback inside
 * kh_diy_stop_machine is already covered by that function's annotation.
 */
int test_resolver_cross_cpu_stop(void)
{
    /* Part A: resolution */
    stop_machine_fn sm = NULL;
    int rc = kh_strategy_resolve("stop_machine", &sm, sizeof(sm));
    KH_TEST_ASSERT("cross_cpu", rc == 0, "stop_machine unresolved");
    KH_TEST_ASSERT("cross_cpu", sm != NULL, "stop_machine resolved to NULL");

    /* Part B: behavioral — invoke kh_diy_stop_machine directly.
     * Calling the kernel's stop_machine with a module-local noop_stop_body
     * would trigger a kCFI failure at multi_cpu_stop on GKI 6.x kernels
     * (type hash mismatch for the int (*fn)(void *) callback). The DIY stub
     * is compiled in the same module, so its hash matches. */
    int v = 0;
    int body_rc = kh_diy_stop_machine(noop_stop_body, &v, NULL);
    KH_TEST_ASSERT("cross_cpu", body_rc == 0, "kh_diy_stop_machine body returned non-zero");
    KH_TEST_ASSERT("cross_cpu", v == 42, "kh_diy_stop_machine body did not update v");

    KH_TEST_PASS("cross_cpu");
    return 0;
}

/*
 * test_resolver_cross_cpu_patch — resolution test for aarch64_insn_patch_text_nosync.
 *
 * Verifies that the capability resolves to a non-NULL fn ptr via one of:
 *   prio 0 (kallsyms): direct ksyms resolution of aarch64_insn_patch_text_nosync.
 *   prio 1 (inline_alias_patch): kh_inline_patch_via_alias, gated on stop_machine.
 *
 * We do NOT invoke the resolved fn pointer here — patching kernel text is
 * exercised by the existing hook tests (test_hook_basic, test_hook_chain)
 * once Task 22 rewires inline.c to go through the strategy layer. Calling
 * the kernel's aarch64_insn_patch_text_nosync from a test TU through an
 * indirect fn pointer risks kCFI type-hash mismatch on GKI 6.x.
 */
int test_resolver_cross_cpu_patch(void)
{
    typedef int (*pfn)(void *, uint32_t);
    pfn p = NULL;
    int rc = kh_strategy_resolve("aarch64_insn_patch_text_nosync", &p, sizeof(p));
    KH_TEST_ASSERT("cross_cpu_patch", rc == 0, "patch capability unresolved");
    KH_TEST_ASSERT("cross_cpu_patch", p != NULL, "patch resolved to NULL");

    /* Do NOT actually patch kernel text in this test — just verify
     * resolution. Patching is exercised by the existing hook tests
     * (test_hook_basic, test_hook_chain) once Task 22 rewires inline.c. */

    KH_TEST_PASS("cross_cpu_patch");
    return 0;
}
