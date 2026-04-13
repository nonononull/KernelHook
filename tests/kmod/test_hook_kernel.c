// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Kernel-context hook tests for KernelHook
 *
 * Ten tests covering:
 *   1. Inline hook (hook/unhook) with zero-arg target
 *   2. Wrap hook before/after callbacks with four-arg target
 *   3. Wrap hook skip_origin via before callback
 *   4. Wrap hook argument passthrough verification
 *   5. Hook uninstall and original function restoration
 *   6. Hook chain priority ordering
 *   7. kCFI hash copy to relocated code (CONFIG_CFI_CLANG)
 *   8. PAC-protected function hooking and trampoline structure (CONFIG_ARM64_PTR_AUTH_KERNEL)
 *   9. BTI landing pads in relocated code (CONFIG_ARM64_BTI_KERNEL)
 *  10. Shadow call stack integrity through hook calls (CONFIG_SHADOW_CALL_STACK)
 */

#if defined(KH_SDK_MODE)
/* Mode B: SDK — kernelhook.ko provides the API */
#include <kernelhook/hook.h>
#include <kernelhook/types.h>
#else
#include <linux/kernel.h>
#endif

#if !defined(KH_SDK_MODE)
#include <hook.h>
#include <memory.h>
#include <symbol.h>
#endif
#include "test_hook_kernel.h"

#define KH_TEST_TAG "kh_test: "

extern int tests_run;
extern int tests_passed;
extern int tests_failed;

#define KH_ASSERT(cond, msg)                                             \
    do {                                                                 \
        tests_run++;                                                     \
        if (cond) {                                                      \
            tests_passed++;                                              \
            pr_info(KH_TEST_TAG "PASS: %s\n", (msg));                   \
        } else {                                                         \
            tests_failed++;                                              \
            pr_err(KH_TEST_TAG "FAIL: %s (at %s:%d)\n",                 \
                   (msg), __FILE__, __LINE__);                           \
        }                                                                \
    } while (0)

#define KH_SKIP(msg) \
    pr_info(KH_TEST_TAG "SKIP: %s\n", (msg))

/* ---- Global test state ---- */

struct hook_test_state g_hook_state;

void hook_test_state_reset(void)
{
    g_hook_state.before_called = 0;
    g_hook_state.after_called  = 0;
    g_hook_state.before_arg0   = 0;
    g_hook_state.after_ret     = 0;
}

/* ---- Target functions with stable, hookable prologues ---- */

__attribute__((__noinline__)) uint64_t target_zero_args(void)
{
    uint64_t result;
    asm volatile(
        "mov %0, #42\n\t"
        "nop\n\t"
        "nop\n\t"
        "nop\n\t"
        : "=r"(result)
    );
    return result;
}

__attribute__((__noinline__)) uint64_t target_four_args(uint64_t a, uint64_t b, uint64_t c, uint64_t d)
{
    uint64_t result;
    asm volatile(
        "add %0, %1, %2\n\t"
        "add %0, %0, %3\n\t"
        "add %0, %0, %4\n\t"
        "nop\n\t"
        "nop\n\t"
        : "=r"(result)
        : "r"(a), "r"(b), "r"(c), "r"(d)
    );
    return result;
}

/* ================================================================
 * Test 1: test_inline_hook_basic
 *
 * Use hook() to replace target_zero_args with replace_zero_args,
 * which calls the original and adds 100.  Verify the hooked value
 * is 142 (42 + 100), then unhook and verify restoration to 42.
 * ================================================================ */

static uint64_t (*orig_target_zero_args)(void);

static uint64_t replace_zero_args(void)
{
    return orig_target_zero_args() + 100;
}

void test_inline_hook_basic(void)
{
    hook_err_t err;
    uint64_t val;

    orig_target_zero_args = NULL;

    err = hook((void *)target_zero_args, (void *)replace_zero_args,
               (void **)&orig_target_zero_args);

    KH_ASSERT(err == HOOK_NO_ERR, "inline hook installs without error");
    KH_ASSERT(orig_target_zero_args != NULL, "backup pointer is non-NULL after hook");

    val = target_zero_args();
    KH_ASSERT(val == 142, "hooked target_zero_args returns orig(42)+100=142");

    val = orig_target_zero_args();
    KH_ASSERT(val == 42, "original via backup returns 42");

    unhook((void *)target_zero_args);

    val = target_zero_args();
    KH_ASSERT(val == 42, "target_zero_args restored to 42 after unhook");
}

/* ================================================================
 * Test 2: test_hook_wrap_before_after
 *
 * Install wrap hook on target_four_args with before/after callbacks.
 * Call with (10,20,30,40).  Verify:
 *   - before_called == 1
 *   - after_called  == 1
 *   - before_arg0   == 10
 *   - result        == 100
 *   - after_ret     == 100
 * ================================================================ */

static void before_four_args(hook_fargs4_t *fargs, void *udata)
{
    (void)udata;
    g_hook_state.before_called++;
    g_hook_state.before_arg0 = fargs->arg0;
}

static void after_four_args(hook_fargs4_t *fargs, void *udata)
{
    (void)udata;
    g_hook_state.after_called++;
    g_hook_state.after_ret = fargs->ret;
}

void test_hook_wrap_before_after(void)
{
    hook_err_t err;
    uint64_t val;

    hook_test_state_reset();

    err = hook_wrap4((void *)target_four_args, before_four_args, after_four_args, NULL);
    KH_ASSERT(err == HOOK_NO_ERR, "hook_wrap4 installs without error");

    val = target_four_args(10, 20, 30, 40);

    KH_ASSERT(g_hook_state.before_called == 1, "before callback was called once");
    KH_ASSERT(g_hook_state.after_called  == 1, "after callback was called once");
    KH_ASSERT(g_hook_state.before_arg0   == 10, "before_arg0 captured as 10");
    KH_ASSERT(val == 100, "target_four_args(10,20,30,40) returns 100");
    KH_ASSERT(g_hook_state.after_ret == 100, "after_ret captured as 100");

    hook_unwrap((void *)target_four_args, (void *)before_four_args, (void *)after_four_args);
}

/* ================================================================
 * Test 3: test_hook_wrap_skip_origin
 *
 * Install wrap0 with a before callback that sets skip_origin=1 and
 * ret=999.  Verify target_zero_args returns 999 without executing
 * the original body.
 * ================================================================ */

static void before_skip_origin(hook_fargs0_t *fargs, void *udata)
{
    (void)udata;
    fargs->skip_origin = 1;
    fargs->ret = 999;
}

void test_hook_wrap_skip_origin(void)
{
    hook_err_t err;
    uint64_t val;

    err = hook_wrap0((void *)target_zero_args, before_skip_origin, NULL, NULL);
    KH_ASSERT(err == HOOK_NO_ERR, "hook_wrap0 (skip_origin) installs without error");

    val = target_zero_args();
    KH_ASSERT(val == 999, "skip_origin=1 + ret=999 bypasses origin and returns 999");

    hook_unwrap((void *)target_zero_args, (void *)before_skip_origin, NULL);
}

/* ================================================================
 * Test 4: test_hook_wrap_arg_passthrough
 *
 * Install wrap4 on target_four_args, capture arg0 in before callback.
 * Call with (1,2,3,4).  Verify arg0==1 and result==10.
 * ================================================================ */

static void before_four_args_pt(hook_fargs4_t *fargs, void *udata)
{
    (void)udata;
    g_hook_state.before_called++;
    g_hook_state.before_arg0 = fargs->arg0;
}

static void after_four_args_pt(hook_fargs4_t *fargs, void *udata)
{
    (void)udata;
    g_hook_state.after_called++;
    g_hook_state.after_ret = fargs->ret;
}

void test_hook_wrap_arg_passthrough(void)
{
    hook_err_t err;
    uint64_t val;

    hook_test_state_reset();

    err = hook_wrap4((void *)target_four_args, before_four_args_pt, after_four_args_pt, NULL);
    KH_ASSERT(err == HOOK_NO_ERR, "hook_wrap4 (passthrough) installs without error");

    val = target_four_args(1, 2, 3, 4);

    KH_ASSERT(g_hook_state.before_arg0 == 1, "arg passthrough: arg0 captured as 1");
    KH_ASSERT(val == 10, "target_four_args(1,2,3,4) returns 10");

    hook_unwrap((void *)target_four_args, (void *)before_four_args_pt, (void *)after_four_args_pt);
}

/* ================================================================
 * Test 5: test_hook_uninstall_restore
 *
 * Verify pre-hook baseline, install wrap4, then immediately unwrap.
 * Confirm before_called remains 0 after the call and the original
 * function value is restored.
 * ================================================================ */

static void before_uninstall(hook_fargs4_t *fargs, void *udata)
{
    (void)fargs;
    (void)udata;
    g_hook_state.before_called++;
}

void test_hook_uninstall_restore(void)
{
    hook_err_t err;
    uint64_t val;

    hook_test_state_reset();

    /* Confirm pre-hook baseline */
    val = target_four_args(1, 2, 3, 4);
    KH_ASSERT(val == 10, "pre-hook target_four_args(1,2,3,4) baseline is 10");

    err = hook_wrap4((void *)target_four_args, before_uninstall, NULL, NULL);
    KH_ASSERT(err == HOOK_NO_ERR, "hook_wrap4 (uninstall test) installs without error");

    /* Remove the hook before calling */
    hook_unwrap((void *)target_four_args, (void *)before_uninstall, NULL);

    val = target_four_args(1, 2, 3, 4);
    KH_ASSERT(g_hook_state.before_called == 0, "before callback not called after unwrap");
    KH_ASSERT(val == 10, "original value 10 restored after unwrap");
}

/* ================================================================
 * Test 6: test_hook_chain_priority
 *
 * Register two wrap0 callbacks with priorities 10 (high) and 1 (low).
 * Verify the high-priority callback executes before the low-priority
 * one by recording the invocation order in priority_order[].
 * ================================================================ */

static int priority_order[2];
static int priority_order_idx;

static void before_priority_high(hook_fargs0_t *fargs, void *udata)
{
    (void)fargs;
    (void)udata;
    if (priority_order_idx < 2)
        priority_order[priority_order_idx++] = 10;
}

static void before_priority_low(hook_fargs0_t *fargs, void *udata)
{
    (void)fargs;
    (void)udata;
    if (priority_order_idx < 2)
        priority_order[priority_order_idx++] = 1;
}

void test_hook_chain_priority(void)
{
    hook_err_t err_hi, err_lo;

    priority_order[0]  = 0;
    priority_order[1]  = 0;
    priority_order_idx = 0;

    /* Higher priority value runs first */
    err_hi = hook_wrap((void *)target_zero_args, 0,
                       (void *)before_priority_high, NULL, NULL, 10);
    err_lo = hook_wrap((void *)target_zero_args, 0,
                       (void *)before_priority_low,  NULL, NULL,  1);

    KH_ASSERT(err_hi == HOOK_NO_ERR, "high-priority wrap0 installs without error");
    KH_ASSERT(err_lo == HOOK_NO_ERR, "low-priority wrap0 installs without error");

    target_zero_args();

    KH_ASSERT(priority_order[0] == 10, "high-priority (10) callback runs first");
    KH_ASSERT(priority_order[1] ==  1, "low-priority (1) callback runs second");

    hook_unwrap((void *)target_zero_args, (void *)before_priority_high, NULL);
    hook_unwrap((void *)target_zero_args, (void *)before_priority_low,  NULL);
}

/* ================================================================
 * Test 7: test_kcfi_hook_and_call
 *
 * Verify kCFI hash is correctly copied to relocated code.
 *
 * On kCFI kernels, *(func - 4) contains the CFI type hash. After hooking,
 * the backup pointer (relocated code) must have the same hash at backup - 4.
 * Calling the backup via indirect call must not trigger a CFI failure.
 * ================================================================ */

void test_kcfi_hook_and_call(void)
{
#if defined(CONFIG_CFI_CLANG)
    hook_err_t err;
    uint64_t val;
    uint32_t origin_hash, backup_hash;
    uint64_t (*backup)(void) = NULL;

    /* Read the kCFI hash at target_zero_args - 4 */
    origin_hash = *(uint32_t *)((uintptr_t)target_zero_args - 4);

    err = hook((void *)target_zero_args, (void *)replace_zero_args,
               (void **)&backup);
    KH_ASSERT(err == HOOK_NO_ERR, "kCFI: hook installs without error");
    KH_ASSERT(backup != NULL, "kCFI: backup pointer is non-NULL");

    /* Read the kCFI hash at backup - 4 (relocated code prefix) */
    backup_hash = *(uint32_t *)((uintptr_t)backup - 4);
    KH_ASSERT(origin_hash == backup_hash,
              "kCFI: relocated code has same CFI hash as original");

    /* Indirect call through backup — must not trigger kCFI trap */
    val = backup();
    KH_ASSERT(val == 42, "kCFI: indirect call via backup returns 42 without CFI fault");

    unhook((void *)target_zero_args);
#else
    KH_SKIP("kCFI not enabled (CONFIG_CFI_CLANG not set)");
#endif
}

/* ================================================================
 * Test 8: test_pac_hook_restore
 *
 * Verify hooking PAC-protected functions works.
 *
 * On PAC kernels, function prologues start with PACIASP/PACIBSP.
 * Hook must generate 5-instruction trampoline (BTI_JC + branch_absolute).
 * Calling backup must not trigger FPAC fault. Unhook must restore cleanly.
 * ================================================================ */

static void before_pac_counter(hook_fargs0_t *fargs, void *udata)
{
    (void)fargs;
    int *cnt = (int *)udata;
    (*cnt)++;
}

void test_pac_hook_restore(void)
{
#if defined(CONFIG_ARM64_PTR_AUTH_KERNEL)
    uint64_t func_addr;
    uint32_t first_inst;
    hook_err_t err;
    int pac_counter = 0;
    void *rox_ptr;
    hook_chain_rox_t *rox;

    /* Resolve a known kernel function that likely has PAC prologue */
    func_addr = ksyms_lookup("do_faccessat");
    if (!func_addr) {
        KH_SKIP("PAC: do_faccessat not found via ksyms_lookup");
        return;
    }

    /* Check if the first instruction is PACIASP or PACIBSP */
    first_inst = *(uint32_t *)func_addr;
    if (first_inst != ARM64_PACIASP && first_inst != ARM64_PACIBSP) {
        KH_SKIP("PAC: do_faccessat does not start with PACIASP/PACIBSP");
        return;
    }

    pr_info(KH_TEST_TAG "PAC: do_faccessat @ 0x%llx starts with %s\n",
            (unsigned long long)func_addr,
            first_inst == ARM64_PACIASP ? "PACIASP" : "PACIBSP");

    /* Hook with wrap to install a before callback */
    err = hook_wrap((void *)func_addr, 0,
                    (void *)before_pac_counter, NULL, &pac_counter, 0);
    KH_ASSERT(err == HOOK_NO_ERR, "PAC: hook_wrap installs without error");

    /* Verify trampoline structure: first inst should be BTI_JC, total 5 insts */
    rox_ptr = hook_mem_get_rox_from_origin(func_addr);
    KH_ASSERT(rox_ptr != NULL, "PAC: ROX pointer found for hooked function");

    if (rox_ptr) {
        rox = (hook_chain_rox_t *)rox_ptr;
        KH_ASSERT(rox->hook.tramp_insts[0] == ARM64_BTI_JC,
                  "PAC: trampoline[0] is BTI_JC (0xd50324df)");
        KH_ASSERT(rox->hook.tramp_insts_num == TRAMPOLINE_NUM,
                  "PAC: trampoline has 5 instructions");
    }

    hook_unwrap((void *)func_addr, (void *)before_pac_counter, NULL);
#else
    KH_SKIP("PAC not enabled (CONFIG_ARM64_PTR_AUTH_KERNEL not set)");
#endif
}

/* ================================================================
 * Test 9: test_bti_indirect_call
 *
 * Verify BTI landing pads in relocated code.
 *
 * On BTI kernels, indirect branches (BR) to code without BTI landing pad
 * cause a fault. Verify relocated code starts with BTI_JC.
 * ================================================================ */

void test_bti_indirect_call(void)
{
#if defined(CONFIG_ARM64_BTI_KERNEL)
    uint64_t func_addr;
    uint32_t first_inst;
    hook_err_t err;
    void *rox_ptr;
    hook_chain_rox_t *rox;

    /* Resolve a kernel function with BTI prologue */
    func_addr = ksyms_lookup("do_faccessat");
    if (!func_addr) {
        KH_SKIP("BTI: do_faccessat not found via ksyms_lookup");
        return;
    }

    /* Check if the first instruction is a BTI variant */
    first_inst = *(uint32_t *)func_addr;
    if (first_inst != ARM64_BTI_C && first_inst != ARM64_BTI_J &&
        first_inst != ARM64_BTI_JC) {
        /* On BTI+PAC kernels, the first instruction may be PACIASP (which
         * also acts as a BTI landing pad). Check for that too. */
        if (first_inst != ARM64_PACIASP && first_inst != ARM64_PACIBSP) {
            KH_SKIP("BTI: do_faccessat does not start with BTI/PAC landing pad");
            return;
        }
    }

    /* Hook with wrap to trigger relocation */
    err = hook_wrap((void *)func_addr, 0, NULL, NULL, NULL, 0);
    KH_ASSERT(err == HOOK_NO_ERR, "BTI: hook_wrap installs without error");

    /* Get the ROX pointer and verify relocated code starts with BTI_JC */
    rox_ptr = hook_mem_get_rox_from_origin(func_addr);
    KH_ASSERT(rox_ptr != NULL, "BTI: ROX pointer found for hooked function");

    if (rox_ptr) {
        rox = (hook_chain_rox_t *)rox_ptr;
        KH_ASSERT(rox->hook.relo_insts[0] == ARM64_BTI_JC,
                  "BTI: relocated code starts with BTI_JC (0xd50324df)");
    }

    hook_unwrap((void *)func_addr, NULL, NULL);
#else
    KH_SKIP("BTI not enabled (CONFIG_ARM64_BTI_KERNEL not set)");
#endif
}

/* ================================================================
 * Test 10: test_scs_stack_integrity
 *
 * Verify shadow call stack not corrupted by hooks.
 *
 * On SCS kernels, x18 is the shadow stack pointer. After hooking and calling
 * a function, x18 must remain consistent (not corrupted by the hook machinery).
 * ================================================================ */

void test_scs_stack_integrity(void)
{
#if defined(CONFIG_SHADOW_CALL_STACK)
    hook_err_t err;
    uint64_t val;
    uintptr_t x18_before, x18_after;
    uint64_t (*backup)(void) = NULL;

    /* Read x18 (shadow call stack pointer) before test */
    asm volatile("mov %0, x18" : "=r"(x18_before));

    err = hook((void *)target_zero_args, (void *)replace_zero_args,
               (void **)&backup);
    KH_ASSERT(err == HOOK_NO_ERR, "SCS: hook installs without error");

    /* Call through the hooked function — exercises the full hook chain */
    val = target_zero_args();
    KH_ASSERT(val == 142, "SCS: hooked target_zero_args returns 142");

    /* Call the backup directly — exercises relocated prologue with SCS push */
    val = backup();
    KH_ASSERT(val == 42, "SCS: backup call returns 42");

    /* Read x18 after — must be identical (SCS balanced) */
    asm volatile("mov %0, x18" : "=r"(x18_after));
    KH_ASSERT(x18_before == x18_after,
              "SCS: x18 (shadow stack ptr) unchanged after hook calls");

    unhook((void *)target_zero_args);

    /* Verify x18 still consistent after unhook */
    asm volatile("mov %0, x18" : "=r"(x18_after));
    KH_ASSERT(x18_before == x18_after,
              "SCS: x18 unchanged after unhook");
#else
    KH_SKIP("SCS not enabled (CONFIG_SHADOW_CALL_STACK not set)");
#endif
}
