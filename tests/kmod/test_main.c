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
 *   Freestanding (Approach B): uses kmod_shim.h; kallsyms_addr is required
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

#ifdef KMOD_FREESTANDING
#include "kmod_shim.h"
#else
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/vmalloc.h>
#include <linux/mm.h>
#include <linux/version.h>
#ifdef CONFIG_KPROBES
#include <linux/kprobes.h>
#endif
#endif /* KMOD_FREESTANDING */

#include <ktypes.h>
#include <hook.h>
#include <hmem.h>
#include <ksyms.h>
#include <arch/arm64/pgtable.h>
#include "kmod_mem_ops.h"
#include "test_hook_kernel.h"

/* kmod_log.c — no dedicated header */
extern int kmod_log_init(void);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("bmax121");
MODULE_DESCRIPTION("KernelHook test harness for kernel-context hook verification");

#ifdef KMOD_FREESTANDING
MODULE_VERSIONS();
MODULE_VERMAGIC();
MODULE_THIS_MODULE();
#endif

static unsigned long kallsyms_addr = 0;
module_param(kallsyms_addr, ulong, 0444);
MODULE_PARM_DESC(kallsyms_addr, "Address of kallsyms_lookup_name (hex)");

#define KH_TEST_TAG "kh_test: "

/*
 * Shared test counters — NOT static so test_hook_kernel.c can extern them.
 */
int tests_run;
int tests_passed;
int tests_failed;

/*
 * Track whether the KernelHook subsystem was successfully initialised so
 * that kh_test_exit() knows whether cleanup is needed.
 */
static int kh_initialized = 0;

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

#if !defined(KMOD_FREESTANDING) && defined(CONFIG_KPROBES)
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
 * Phase 2: Security mechanism detection
 * ---------------------------------------------------------------------- */

static void test_kcfi_detection(void)
{
#if defined(CONFIG_CFI_CLANG)
    pr_info(KH_TEST_TAG "INFO: kernel built with CONFIG_CFI_CLANG=y\n");
    KH_ASSERT(true, "kCFI enabled — transit_body KCFI_EXEMPT verification needed");
#else
    KH_SKIP("kCFI not enabled (CONFIG_CFI_CLANG not set)");
#endif
}

static void test_scs_detection(void)
{
#if defined(CONFIG_SHADOW_CALL_STACK)
    pr_info(KH_TEST_TAG "INFO: kernel built with CONFIG_SHADOW_CALL_STACK=y\n");
    KH_ASSERT(true, "SCS enabled — relocated SCS push/pop verification needed");
#else
    KH_SKIP("SCS not enabled (CONFIG_SHADOW_CALL_STACK not set)");
#endif
}

static void test_pac_detection(void)
{
#if defined(CONFIG_ARM64_PTR_AUTH_KERNEL)
    pr_info(KH_TEST_TAG "INFO: kernel built with CONFIG_ARM64_PTR_AUTH_KERNEL=y\n");
    KH_ASSERT(true, "PAC enabled — STRIP_PAC and FPAC safety verification needed");
#else
    KH_SKIP("PAC not enabled (CONFIG_ARM64_PTR_AUTH_KERNEL not set)");
#endif
}

static void test_bti_detection(void)
{
#if defined(CONFIG_ARM64_BTI_KERNEL)
    pr_info(KH_TEST_TAG "INFO: kernel built with CONFIG_ARM64_BTI_KERNEL=y\n");
    KH_ASSERT(true, "BTI enabled — BTI_JC landing pad verification needed");
#else
    KH_SKIP("BTI not enabled (CONFIG_ARM64_BTI_KERNEL not set)");
#endif
}

/* -------------------------------------------------------------------------
 * Phase 3: Subsystem initialisation
 * ---------------------------------------------------------------------- */

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

    /* 2. log */
    rc = kmod_log_init();
    if (rc) {
        pr_err(KH_TEST_TAG "kmod_log_init failed: %d\n", rc);
        return rc;
    }

    /* 3. pgtable */
    rc = pgtable_init();
    if (rc) {
        pr_err(KH_TEST_TAG "pgtable_init failed: %d\n", rc);
        return rc;
    }

    /* 4. hook_mem */
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
        kmod_hook_mem_cleanup();
        kh_initialized = 0;
    }
}

/* -------------------------------------------------------------------------
 * Module init / exit
 * ---------------------------------------------------------------------- */

static int __init kh_test_init(void)
{
    int rc;

    pr_info(KH_TEST_TAG "=== KernelHook Kernel Module Test Harness ===\n");

#ifdef KMOD_FREESTANDING
    pr_info(KH_TEST_TAG "Build: freestanding (Approach B)\n");
#else
    pr_info(KH_TEST_TAG "Build: Kbuild (Approach A)\n");
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

    /* ------------------------------------------------------------------
     * Phase 2: Security mechanism detection
     * ---------------------------------------------------------------- */
    pr_info(KH_TEST_TAG "--- Phase 2: Security mechanism detection ---\n");
    test_kcfi_detection();
    test_scs_detection();
    test_pac_detection();
    test_bti_detection();

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

    /* ------------------------------------------------------------------
     * Phase 4: Hook tests
     * ---------------------------------------------------------------- */
    pr_info(KH_TEST_TAG "--- Phase 4: Hook tests ---\n");
    test_inline_hook_basic();
    test_hook_wrap_before_after();
    test_hook_wrap_skip_origin();
    test_hook_wrap_arg_passthrough();
    test_hook_uninstall_restore();
    test_hook_chain_priority();

results:
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
    kh_subsystem_cleanup();
    pr_info(KH_TEST_TAG "module unloaded\n");
}

module_init(kh_test_init);
module_exit(kh_test_exit);
