// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Kernel-context hook tests for KernelHook
 *
 * Six tests covering:
 *   1. Inline hook (hook/unhook) with zero-arg target
 *   2. Wrap hook before/after callbacks with four-arg target
 *   3. Wrap hook skip_origin via before callback
 *   4. Wrap hook argument passthrough verification
 *   5. Hook uninstall and original function restoration
 *   6. Hook chain priority ordering
 */

#if defined(KH_SDK_MODE)
/* Mode B: SDK — kernelhook.ko provides the API */
#include <kernelhook/hook.h>
#include <kernelhook/types.h>
#elif defined(KMOD_FREESTANDING)
/* Mode A: freestanding shim */
#include "shim.h"
#else
/* Mode C: standard kernel headers */
#include <linux/kernel.h>
#endif

#if !defined(KH_SDK_MODE)
#include <hook.h>
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
