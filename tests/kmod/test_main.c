// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * KernelHook kernel module test harness
 *
 * Loads as a kernel module, initialises the full KernelHook subsystem, and
 * runs hook tests in kernel context with real page table manipulation.
 * Results are emitted via pr_info/pr_err to dmesg.
 *
 * Build paths:
 *   Kbuild (Approach A):       uses kernel headers; kprobes auto-detects
 *                              kallsyms_lookup_name when kallsyms_addr==0
 *   Freestanding (Approach B): uses shim.h; kallsyms_addr is required
 *
 * Test plan for security-mechanism-enabled kernels:
 *
 *   kCFI (CONFIG_CFI_CLANG):
 *     - Verify KCFI_EXEMPT attribute on transit_body bypasses kCFI checks
 *     - Verify indirect calls through hook callbacks do not trigger kCFI traps
 *     - Requires: kernel built with CONFIG_CFI_CLANG=y, Clang >= 16
 *
 *   Shadow Call Stack (CONFIG_SHADOW_CALL_STACK):
 *     - Verify SCS push/pop instructions in prologue are relocated correctly
 *     - Verify SCS stack balance is maintained through hook call chain
 *     - Requires: kernel built with CONFIG_SHADOW_CALL_STACK=y, GCC >= 12 or Clang >= 14
 *
 *   PAC (CONFIG_ARM64_PTR_AUTH_KERNEL):
 *     - Verify PAC-signed function pointers are stripped at API entry
 *     - Verify FPAC-safe SP invariant: SP unchanged between BLR and relocated PACIASP
 *     - Requires: kernel built with CONFIG_ARM64_PTR_AUTH_KERNEL=y, ARMv8.3+ hardware
 *
 *   BTI (CONFIG_ARM64_BTI_KERNEL):
 *     - Verify BTI_JC landing pad is emitted at trampoline entry
 *     - Verify transit stubs start with BTI_JC for BR-based entry
 *     - Requires: kernel built with CONFIG_ARM64_BTI_KERNEL=y, ARMv8.5+ hardware
 *
 * Kernel version requirements:
 *   - Minimum: Linux 5.10 (baseline ARM64 PAC/BTI support)
 *   - kCFI:   Linux 6.1+ (CONFIG_CFI_CLANG on ARM64)
 *   - SCS:    Linux 5.8+  (CONFIG_SHADOW_CALL_STACK on ARM64)
 *   - BTI:    Linux 5.10+ (CONFIG_ARM64_BTI_KERNEL)
 *   - PAC:    Linux 5.0+  (CONFIG_ARM64_PTR_AUTH_KERNEL)
 *
 * Required kernel config options (check via /proc/config.gz or
 * /boot/config-$(uname -r)):
 *   CONFIG_MODULES=y
 *   CONFIG_MODULE_UNLOAD=y
 *   And for specific security mechanism tests:
 *   CONFIG_CFI_CLANG=y             (kCFI tests)
 *   CONFIG_SHADOW_CALL_STACK=y     (SCS tests)
 *   CONFIG_ARM64_PTR_AUTH_KERNEL=y (PAC tests)
 *   CONFIG_ARM64_BTI_KERNEL=y      (BTI tests)
 */

#if defined(KH_SDK_MODE)
/* Mode B: SDK — kernelhook.ko provides the API */
#include <kernelhook/hook.h>
#include <kernelhook/types.h>
#else
/* Mode A (freestanding) uses fake headers from kmod/shim/include/;
 * Mode C (kbuild) uses real kernel headers. Same include list either way. */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/vmalloc.h>
#include <linux/mm.h>
#include <linux/version.h>
#ifdef CONFIG_KPROBES
#include <linux/kprobes.h>
#endif
#endif

#if !defined(KH_SDK_MODE)
#include <types.h>
#include <hook.h>
#include <memory.h>
#include <symbol.h>
#include <arch/arm64/pgtable.h>
#include <sync.h>
#endif
#include "mem_ops.h"
#include "test_hook_kernel.h"

#if !defined(KH_SDK_MODE)
/* log.c — no dedicated header */
extern int log_init(void);
#endif

MODULE_LICENSE("GPL");
MODULE_AUTHOR("bmax121");
MODULE_DESCRIPTION("KernelHook test harness for kernel-context hook verification");

#ifdef KMOD_FREESTANDING
MODULE_VERSIONS();
MODULE_VERMAGIC();
MODULE_THIS_MODULE();
#endif

#if !defined(KH_SDK_MODE)
/* kallsyms_addr: patched directly into ELF by kmod_loader before loading.
 * This avoids module_param, which triggers shadow-CFI indirect call checks
 * on 5.10 kernels — the param handler isn't in the CFI shadow.
 * Initialized to 1 (not 0) so the linker places it in .data, not .bss —
 * the loader needs actual file bytes to patch. */
unsigned long kallsyms_addr = 1;
#endif

#define KH_TEST_TAG "kh_test: "

/*
 * Shared test counters — NOT static so test_hook_kernel.c can extern them.
 */
int tests_run;
int tests_passed;
int tests_failed;

#if !defined(KH_SDK_MODE)
/*
 * Track whether the KernelHook subsystem was successfully initialised so
 * that kh_test_exit() knows whether cleanup is needed.
 */
static int kh_initialized = 0;
#endif

/* -------------------------------------------------------------------------
 * Test framework macros
 * ---------------------------------------------------------------------- */

#define KH_ASSERT(cond, msg)                                              \
    do {                                                                  \
        tests_run++;                                                      \
        if (cond) {                                                       \
            tests_passed++;                                               \
            pr_info(KH_TEST_TAG "PASS: %s\n", (msg));                    \
        } else {                                                          \
            tests_failed++;                                               \
            pr_err(KH_TEST_TAG "FAIL: %s (at %s:%d)\n",                  \
                   (msg), __FILE__, __LINE__);                            \
        }                                                                 \
    } while (0)

#define KH_SKIP(msg) \
    pr_info(KH_TEST_TAG "SKIP: %s\n", (msg))

/* -------------------------------------------------------------------------
 * kprobes trick: resolve kallsyms_lookup_name without a symbol table
 * (Kbuild path only; CONFIG_KPROBES must be enabled)
 * ---------------------------------------------------------------------- */

#if !defined(KH_SDK_MODE) && !defined(KMOD_FREESTANDING) && defined(CONFIG_KPROBES)
static unsigned long find_kallsyms_via_kprobes(void)
{
    struct kprobe kp = { .symbol_name = "kallsyms_lookup_name" };
    int ret = register_kprobe(&kp);

    if (ret < 0)
        return 0;
    unsigned long addr = (unsigned long)kp.addr;
    unregister_kprobe(&kp);
    return addr;
}
#endif

/* -------------------------------------------------------------------------
 * Phase 1: Infrastructure tests
 * ---------------------------------------------------------------------- */

/*
 * test_framework_sanity — verify the test framework itself works.
 */
static void test_framework_sanity(void)
{
    KH_ASSERT(1 == 1, "test framework sanity check");
}

/*
 * test_vmalloc_available — verify vmalloc/vfree round-trip.
 * (Prerequisite for hook memory allocation.)
 * Freestanding: SKIPped because vmalloc is resolved only after subsystem init.
 */
static void test_vmalloc_available(void)
{
#ifdef KMOD_FREESTANDING
    KH_SKIP("vmalloc_available (freestanding: symbol resolved at subsystem init)");
#else
    void *p = vmalloc(PAGE_SIZE);

    KH_ASSERT(p != NULL, "vmalloc allocates memory in kernel context");
    if (p)
        vfree(p);
#endif
}

/* -------------------------------------------------------------------------
 * Phase 2: Security mechanism functional tests
 *
 * These tests are defined in test_hook_kernel.c and exercise the real hook
 * machinery under each security mechanism.  They require the subsystem to
 * be initialised first (ksyms, hook_mem, etc.), so they are called in
 * Phase 4 alongside the other hook tests.  Phase 2 is now a no-op
 * placeholder kept for numbering consistency.
 * ---------------------------------------------------------------------- */

/* -------------------------------------------------------------------------
 * Phase 3: Subsystem initialisation
 * ---------------------------------------------------------------------- */

#if !defined(KH_SDK_MODE)
/*
 * kh_subsystem_init — resolve kallsyms, then bring up ksyms → log → pgtable
 * → hook_mem in order.
 *
 * Returns 0 on success, negative errno on failure.
 */
static int kh_subsystem_init(void)
{
    unsigned long ksym_addr = kallsyms_addr;
    int rc;

    /* Resolve kallsyms_lookup_name address if not supplied */
    if (!ksym_addr) {
#if defined(KMOD_FREESTANDING)
        pr_err(KH_TEST_TAG
               "kallsyms_addr required for freestanding build "
               "(pass via insmod kallsyms_addr=0x...)\n");
        return -EINVAL;
#elif defined(CONFIG_KPROBES)
        ksym_addr = find_kallsyms_via_kprobes();
        if (!ksym_addr) {
            pr_err(KH_TEST_TAG
                   "kprobes: failed to resolve kallsyms_lookup_name\n");
            return -ENOENT;
        }
        pr_info(KH_TEST_TAG "kprobes: kallsyms_lookup_name @ 0x%lx\n",
                ksym_addr);
#else
        pr_err(KH_TEST_TAG
               "kallsyms_addr not provided and CONFIG_KPROBES not set — "
               "cannot resolve kallsyms_lookup_name\n");
        return -ENOENT;
#endif
    }

    /* 1. ksyms */
    rc = ksyms_init((uint64_t)ksym_addr);
    if (rc) {
        pr_err(KH_TEST_TAG "ksyms_init failed: %d\n", rc);
        return rc;
    }

    /* 2. log — init early so subsequent failures can print diagnostics */
    rc = log_init();
    if (rc) {
        pr_err(KH_TEST_TAG "log_init failed: %d\n", rc);
        return rc;
    }

    /* 2b. sync (RCU + spinlock for chain ops; no-op when CONFIG_KH_CHAIN_RCU=n) */
    rc = sync_init();
    if (rc) {
        pr_err(KH_TEST_TAG "sync_init failed: %d\n", rc);
        return rc;
    }

    /* 3. pgtable — not fatal: set_memory mode works without it */
    rc = kh_pgtable_init();
    if (rc) {
        pr_info(KH_TEST_TAG "kh_pgtable_init failed (%d) — PTE mode unavailable, "
                "using set_memory mode only\n", rc);
        /* Continue: set_memory mode doesn't need page table walking */
    }

    /* 4. write_insts (set_memory_rw/ro/x resolution) */
    {
        extern void kh_write_insts_init(void);
        kh_write_insts_init();
    }

    /* 5. hook_mem */
    rc = kmod_hook_mem_init();
    if (rc) {
        pr_err(KH_TEST_TAG "kmod_hook_mem_init failed: %d\n", rc);
        return rc;
    }

    return 0;
}

/*
 * kh_subsystem_cleanup — tear down hook_mem if it was initialised.
 */
static void kh_subsystem_cleanup(void)
{
    if (kh_initialized) {
        extern void kh_write_insts_cleanup(void);
        kh_write_insts_cleanup();
        kmod_hook_mem_cleanup();
        kh_initialized = 0;
    }
}
#endif /* !KH_SDK_MODE */

/* -------------------------------------------------------------------------
 * Module init / exit
 * ---------------------------------------------------------------------- */

static int __init kh_test_init(void)
{
#if !defined(KH_SDK_MODE)
    int rc;
#endif


#if defined(KH_SDK_MODE)
    pr_info(KH_TEST_TAG "Build: SDK (Mode B)\n");
#elif defined(KMOD_FREESTANDING)
    pr_info(KH_TEST_TAG "Build: freestanding (Mode A)\n");
#else
    pr_info(KH_TEST_TAG "Build: Kbuild (Mode C)\n");
#endif
    /* Reset counters */
    tests_run    = 0;
    tests_passed = 0;
    tests_failed = 0;

    /* ------------------------------------------------------------------
     * Phase 1: Infrastructure
     * ---------------------------------------------------------------- */
    pr_info(KH_TEST_TAG "--- Phase 1: Infrastructure ---\n");
    test_framework_sanity();
    test_vmalloc_available();

#if !defined(KH_SDK_MODE)
    /* ------------------------------------------------------------------
     * Phase 3: Subsystem initialisation
     * ---------------------------------------------------------------- */
    pr_info(KH_TEST_TAG "--- Phase 3: Subsystem init ---\n");
    rc = kh_subsystem_init();
    if (rc) {
        pr_err(KH_TEST_TAG
               "Subsystem init FAILED (%d) — skipping hook tests\n", rc);
        goto results;
    }
    kh_initialized = 1;
    pr_info(KH_TEST_TAG "Subsystem init OK\n");
#endif

    /* ------------------------------------------------------------------
     * Phase 4: Hook tests
     *
     * Uses the write mode auto-selected by kh_write_insts_init().
     * PTE mode is only used as fallback on kernels without set_memory.
     * ---------------------------------------------------------------- */
    pr_info(KH_TEST_TAG "--- Phase 4: Hook tests ---\n");
    test_inline_hook_basic();
    test_hook_wrap_before_after();
    test_hook_wrap_skip_origin();
    test_hook_wrap_arg_passthrough();
    test_hook_uninstall_restore();
    test_hook_chain_priority();

    pr_info(KH_TEST_TAG "--- Phase 4b: Function pointer hook tests ---\n");
    test_fp_hook_basic();
    test_fp_hook_wrap_before_after();
    test_fp_hook_chain_priority();
    test_fp_hook_skip_origin();
    test_fp_hook_uninstall_cleanup();
    test_fp_hook_real_kernel_fp();

    /* ------------------------------------------------------------------
     * Phase 5: Security mechanism functional tests
     * ---------------------------------------------------------------- */
    pr_info(KH_TEST_TAG "--- Phase 5: Security mechanism tests ---\n");
    test_kcfi_hook_and_call();
    test_pac_hook_restore();
    test_bti_indirect_call();
    test_scs_stack_integrity();

    /* ------------------------------------------------------------------
     * Phase 5b: Real system function hook chain tests
     *
     * These tests resolve real kernel functions via ksyms_lookup() and
     * verify hook chain installation, priority ordering, dynamic
     * add/remove, and cleanup — without invoking the hooked functions.
     * ---------------------------------------------------------------- */
    pr_info(KH_TEST_TAG "--- Phase 5b: Real system function hook chain tests ---\n");
    test_getpid_single_hook();
    test_faccessat_chain_priority();
    test_filp_open_skip_origin();
    test_vfs_read_write_hook();
    test_dynamic_add_remove();

    /* ------------------------------------------------------------------
     * Phase 5c: Stress tests
     * ---------------------------------------------------------------- */
    pr_info(KH_TEST_TAG "--- Phase 5c: Stress tests ---\n");
    test_stress_chain_fill_drain();
    test_stress_rapid_hook_unhook();

    /* ------------------------------------------------------------------
     * Phase 5d: Concurrency tests
     * ---------------------------------------------------------------- */
#if defined(CONFIG_KH_CHAIN_RCU)
    pr_info(KH_TEST_TAG "--- Phase 5d: Concurrency tests ---\n");
    test_concurrent_add_remove();
#else
    pr_info(KH_TEST_TAG "--- Phase 5d: Concurrency tests (SKIPPED) ---\n");
    KH_SKIP("concurrent_add_remove (requires CONFIG_KH_CHAIN_RCU build flag)");
#endif

#if !defined(KH_SDK_MODE)
results:
#endif
    pr_info(KH_TEST_TAG "=== Results: %d run, %d passed, %d failed ===\n",
            tests_run, tests_passed, tests_failed);

    if (tests_failed > 0)
        pr_err(KH_TEST_TAG "SOME TESTS FAILED\n");
    else
        pr_info(KH_TEST_TAG "ALL TESTS PASSED\n");

    return 0;  /* always return 0 so the module loads (for dmesg parsing) */
}

static void __exit kh_test_exit(void)
{
#if !defined(KH_SDK_MODE)
    kh_subsystem_cleanup();
#endif
    pr_info(KH_TEST_TAG "module unloaded\n");
}

module_init(kh_test_init);
module_exit(kh_test_exit);
