/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * FP hook edge case tests: nested hooks, wrap/unwrap cycle,
 * multiple targets, chain priority, and fp_get_origin_func.
 */

#include "test_framework.h"
#include <hook.h>
#include <hmem.h>
#include <hook_mem_user.h>
#include <string.h>

/* ---- Setup/teardown ---- */

static void hook_setup(void)
{
    int rc = hook_mem_user_init();
    ASSERT_EQ(rc, 0);
}

static void hook_teardown(void)
{
    hook_mem_user_cleanup();
}

/* ---- Execution order tracking ---- */

#define MAX_ORDER 16
static int exec_order[MAX_ORDER];
static int exec_count;

static void reset_order(void)
{
    memset(exec_order, 0, sizeof(exec_order));
    exec_count = 0;
}

static void record_id(int id)
{
    if (exec_count < MAX_ORDER)
        exec_order[exec_count++] = id;
}

/* ============================================================
 * Test 1: fp_nested_hooks
 * Two FP targets A and B, where A's implementation calls B.
 * Both hooked with fp_hook_wrap. Call A, verify both before
 * callbacks fire.
 * ============================================================ */

__attribute__((noinline))
static int fp_impl_b(int x)
{
    asm volatile("nop\n\tnop\n\tnop");
    return x * 2;
}

static int (*fp_b)(int) = fp_impl_b;

__attribute__((noinline))
static int fp_impl_a(int x)
{
    asm volatile("nop\n\tnop\n\tnop");
    return fp_b(x) + 1;
}

static int (*fp_a)(int) = fp_impl_a;

static int nested_before_a_called;
static int nested_before_b_called;

static void nested_before_a(hook_fargs1_t *fargs, void *udata)
{
    (void)fargs; (void)udata;
    nested_before_a_called = 1;
}

static void nested_before_b(hook_fargs1_t *fargs, void *udata)
{
    (void)fargs; (void)udata;
    nested_before_b_called = 1;
}

TEST(fp_nested_hooks)
{
    hook_setup();
    nested_before_a_called = 0;
    nested_before_b_called = 0;
    fp_a = fp_impl_a;
    fp_b = fp_impl_b;

    hook_err_t rc;
    rc = fp_hook_wrap_pri((uintptr_t)&fp_a, 1,
                          (void *)nested_before_a, NULL, NULL, 0);
    ASSERT_EQ(rc, HOOK_NO_ERR);

    rc = fp_hook_wrap_pri((uintptr_t)&fp_b, 1,
                          (void *)nested_before_b, NULL, NULL, 0);
    ASSERT_EQ(rc, HOOK_NO_ERR);

    /* Call A — A's impl calls B internally */
    int result = fp_a(5);
    ASSERT_EQ(result, 11); /* fp_impl_b(5) = 10, + 1 = 11 */
    ASSERT_TRUE(nested_before_a_called);
    ASSERT_TRUE(nested_before_b_called);

    fp_hook_unwrap((uintptr_t)&fp_a, (void *)nested_before_a, NULL);
    fp_hook_unwrap((uintptr_t)&fp_b, (void *)nested_before_b, NULL);
    hook_teardown();
}

/* ============================================================
 * Test 2: fp_hook_wrap_unwrap_cycle
 * fp_hook_wrap a target, call it (verify callback fires),
 * fp_hook_unwrap, call again (verify original behavior
 * restored, no callback).
 * ============================================================ */

__attribute__((noinline))
static int fp_cycle_impl(int a, int b)
{
    asm volatile("nop\n\tnop\n\tnop");
    return a + b;
}

static int (*fp_cycle)(int, int) = fp_cycle_impl;

static int cycle_before_called;

static void cycle_before(hook_fargs2_t *fargs, void *udata)
{
    (void)fargs; (void)udata;
    cycle_before_called = 1;
}

TEST(fp_hook_wrap_unwrap_cycle)
{
    hook_setup();
    cycle_before_called = 0;
    fp_cycle = fp_cycle_impl;

    hook_err_t rc = fp_hook_wrap_pri((uintptr_t)&fp_cycle, 2,
                                     (void *)cycle_before, NULL, NULL, 0);
    ASSERT_EQ(rc, HOOK_NO_ERR);

    int result = fp_cycle(3, 4);
    ASSERT_EQ(result, 7);
    ASSERT_TRUE(cycle_before_called);

    fp_hook_unwrap((uintptr_t)&fp_cycle, (void *)cycle_before, NULL);

    /* After unwrap, callback must not fire */
    cycle_before_called = 0;
    result = fp_cycle(10, 20);
    ASSERT_EQ(result, 30);
    ASSERT_FALSE(cycle_before_called);

    hook_teardown();
}

/* ============================================================
 * Test 3: fp_multiple_targets
 * Hook 3 different FP targets independently, call each,
 * verify each callback fires independently.
 * ============================================================ */

__attribute__((noinline))
static int fp_mt_impl1(int x) { asm volatile("nop\n\tnop\n\tnop"); return x + 1; }
__attribute__((noinline))
static int fp_mt_impl2(int x) { asm volatile("nop\n\tnop\n\tnop"); return x + 2; }
__attribute__((noinline))
static int fp_mt_impl3(int x) { asm volatile("nop\n\tnop\n\tnop"); return x + 3; }

static int (*fp_mt1)(int) = fp_mt_impl1;
static int (*fp_mt2)(int) = fp_mt_impl2;
static int (*fp_mt3)(int) = fp_mt_impl3;

static int mt_called1, mt_called2, mt_called3;

static void mt_before1(hook_fargs1_t *fargs, void *udata) { (void)fargs; (void)udata; mt_called1 = 1; }
static void mt_before2(hook_fargs1_t *fargs, void *udata) { (void)fargs; (void)udata; mt_called2 = 1; }
static void mt_before3(hook_fargs1_t *fargs, void *udata) { (void)fargs; (void)udata; mt_called3 = 1; }

TEST(fp_multiple_targets)
{
    hook_setup();
    mt_called1 = mt_called2 = mt_called3 = 0;
    fp_mt1 = fp_mt_impl1;
    fp_mt2 = fp_mt_impl2;
    fp_mt3 = fp_mt_impl3;

    hook_err_t rc;
    rc = fp_hook_wrap_pri((uintptr_t)&fp_mt1, 1,
                          (void *)mt_before1, NULL, NULL, 0);
    ASSERT_EQ(rc, HOOK_NO_ERR);
    rc = fp_hook_wrap_pri((uintptr_t)&fp_mt2, 1,
                          (void *)mt_before2, NULL, NULL, 0);
    ASSERT_EQ(rc, HOOK_NO_ERR);
    rc = fp_hook_wrap_pri((uintptr_t)&fp_mt3, 1,
                          (void *)mt_before3, NULL, NULL, 0);
    ASSERT_EQ(rc, HOOK_NO_ERR);

    int r1 = fp_mt1(10);
    ASSERT_EQ(r1, 11);
    ASSERT_TRUE(mt_called1);
    ASSERT_FALSE(mt_called2);
    ASSERT_FALSE(mt_called3);

    int r2 = fp_mt2(10);
    ASSERT_EQ(r2, 12);
    ASSERT_TRUE(mt_called2);
    ASSERT_FALSE(mt_called3);

    int r3 = fp_mt3(10);
    ASSERT_EQ(r3, 13);
    ASSERT_TRUE(mt_called3);

    fp_hook_unwrap((uintptr_t)&fp_mt1, (void *)mt_before1, NULL);
    fp_hook_unwrap((uintptr_t)&fp_mt2, (void *)mt_before2, NULL);
    fp_hook_unwrap((uintptr_t)&fp_mt3, (void *)mt_before3, NULL);
    hook_teardown();
}

/* ============================================================
 * Test 4: fp_chain_priority
 * fp_hook_wrap_pri with priorities 10, 0, -5. Call target.
 * Verify callbacks execute in priority order (highest first).
 * ============================================================ */

__attribute__((noinline))
static int fp_prio_impl(int a, int b)
{
    asm volatile("nop\n\tnop\n\tnop");
    return a + b;
}

static int (*fp_prio)(int, int) = fp_prio_impl;

static void prio_before10(hook_fargs2_t *fargs, void *udata) { (void)fargs; (void)udata; record_id(10); }
static void prio_before0(hook_fargs2_t *fargs, void *udata)  { (void)fargs; (void)udata; record_id(0); }
static void prio_before_n5(hook_fargs2_t *fargs, void *udata){ (void)fargs; (void)udata; record_id(-5); }

TEST(fp_chain_priority)
{
    hook_setup();
    reset_order();
    fp_prio = fp_prio_impl;

    hook_err_t rc;
    rc = fp_hook_wrap_pri((uintptr_t)&fp_prio, 2,
                          (void *)prio_before10, NULL, NULL, 10);
    ASSERT_EQ(rc, HOOK_NO_ERR);
    rc = fp_hook_wrap_pri((uintptr_t)&fp_prio, 2,
                          (void *)prio_before0, NULL, NULL, 0);
    ASSERT_EQ(rc, HOOK_NO_ERR);
    rc = fp_hook_wrap_pri((uintptr_t)&fp_prio, 2,
                          (void *)prio_before_n5, NULL, NULL, -5);
    ASSERT_EQ(rc, HOOK_NO_ERR);

    int result = fp_prio(3, 4);
    ASSERT_EQ(result, 7);

    ASSERT_EQ(exec_count, 3);
    ASSERT_EQ(exec_order[0], 10);
    ASSERT_EQ(exec_order[1], 0);
    ASSERT_EQ(exec_order[2], -5);

    fp_hook_unwrap((uintptr_t)&fp_prio, (void *)prio_before10, NULL);
    fp_hook_unwrap((uintptr_t)&fp_prio, (void *)prio_before0, NULL);
    fp_hook_unwrap((uintptr_t)&fp_prio, (void *)prio_before_n5, NULL);
    hook_teardown();
}

/* ============================================================
 * Test 5: fp_get_origin_func
 * fp_hook_wrap a target, in the before callback save
 * fargs->chain. After the call, use fp_get_origin_func() to
 * get the original function, call it directly, verify result.
 * ============================================================ */

__attribute__((noinline))
static int fp_origin_impl(int a, int b)
{
    asm volatile("nop\n\tnop\n\tnop");
    return a * b;
}

static int (*fp_origin)(int, int) = fp_origin_impl;

static void *saved_fp_chain;

static void origin_before(hook_fargs2_t *fargs, void *udata)
{
    (void)udata;
    saved_fp_chain = fargs->chain;
}

TEST(fp_get_origin_func)
{
    hook_setup();
    saved_fp_chain = NULL;
    fp_origin = fp_origin_impl;

    hook_err_t rc = fp_hook_wrap_pri((uintptr_t)&fp_origin, 2,
                                     (void *)origin_before, NULL, NULL, 0);
    ASSERT_EQ(rc, HOOK_NO_ERR);

    int result = fp_origin(6, 7);
    ASSERT_EQ(result, 42);
    ASSERT_NOT_NULL(saved_fp_chain);

    /* Use fp_get_origin_func to retrieve the original function */
    hook_fargs2_t fake_fargs;
    memset(&fake_fargs, 0, sizeof(fake_fargs));
    fake_fargs.chain = saved_fp_chain;

    int (*orig)(int, int) = (int (*)(int, int))fp_get_origin_func(&fake_fargs);
    ASSERT_NOT_NULL(orig);

    /* Call the original directly */
    int direct_result = orig(4, 5);
    ASSERT_EQ(direct_result, 20);

    fp_hook_unwrap((uintptr_t)&fp_origin, (void *)origin_before, NULL);
    hook_teardown();
}

int main(void)
{
    return RUN_ALL_TESTS();
}
