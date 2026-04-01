/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Integration tests: hook chains, unwrap, and local storage.
 * Tests multi-callback chains, priority ordering, per-item local,
 * wrap_get_origin_func, and function pointer hooks.
 */

#include "test_framework.h"
#include <hook.h>
#include <hmem.h>
#include <hook_mem_user.h>
#include <platform.h>
#include <string.h>

/* ---- Target functions ---- */

/* Padded with nops so each function is >= 16 bytes (the trampoline size). */
__attribute__((noinline))
int target_func(int a, int b)
{
    asm volatile("nop\n\tnop\n\tnop");
    return a + b;
}

/* Function pointer target for fp_hook tests */
__attribute__((noinline))
static int fp_target_impl(int a, int b)
{
    asm volatile("nop\n\tnop\n\tnop");
    return a * b;
}

static int (*fp_target)(int, int) = fp_target_impl;

/* Volatile function pointer prevents compiler from eliminating calls
 * via interprocedural constant propagation in Release builds. */
static int (*volatile call_func)(int, int) = target_func;

/* ---- Execution order tracking ---- */

#define MAX_ORDER 16
static int exec_order[MAX_ORDER];
static int exec_count;

static void reset_order(void)
{
    memset(exec_order, 0, sizeof(exec_order));
    exec_count = 0;
}

static void record(int id)
{
    if (exec_count < MAX_ORDER)
        exec_order[exec_count++] = id;
}

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

/* ---- Callbacks with different IDs ---- */

static void before_id10(hook_fargs2_t *fargs, void *udata)
{
    (void)fargs; (void)udata;
    record(10);
}

static void before_id0(hook_fargs2_t *fargs, void *udata)
{
    (void)fargs; (void)udata;
    record(0);
}

static void before_id_neg5(hook_fargs2_t *fargs, void *udata)
{
    (void)fargs; (void)udata;
    record(-5);
}

/* ---- Local storage callbacks ---- */

static uint64_t local_from_after;
static hook_local_t *local_ptr_A;
static hook_local_t *local_ptr_B;

static void before_set_local(hook_fargs2_t *fargs, void *udata)
{
    (void)udata;
    fargs->local->data0 = 0xBEEF;
    local_ptr_A = fargs->local;
}

static void after_read_local(hook_fargs2_t *fargs, void *udata)
{
    (void)udata;
    local_from_after = fargs->local->data0;
}

static void before_set_local_B(hook_fargs2_t *fargs, void *udata)
{
    (void)udata;
    fargs->local->data0 = 0xCAFE;
    local_ptr_B = fargs->local;
}

static void after_read_local_B(hook_fargs2_t *fargs, void *udata)
{
    (void)udata;
    /* Just record we were called */
}

/* ---- FP hook callbacks ---- */

static int fp_before_called;
static int fp_after_called;
static uint64_t fp_captured_ret;

static void fp_before(hook_fargs2_t *fargs, void *udata)
{
    (void)fargs; (void)udata;
    fp_before_called = 1;
}

static void fp_after(hook_fargs2_t *fargs, void *udata)
{
    (void)udata;
    fp_after_called = 1;
    fp_captured_ret = fargs->ret;
}

/* ---- Tests ---- */

TEST(chain_priority_execution_order)
{
    hook_setup();
    reset_order();

    /* Hook with 3 before callbacks at priorities 10, 0, -5 */
    hook_err_t rc;
    rc = hook_wrap_pri((void *)target_func, 2,
                        (void *)before_id10, NULL, NULL, 10);
    ASSERT_EQ(rc, HOOK_NO_ERR);

    rc = hook_wrap_pri((void *)target_func, 2,
                        (void *)before_id0, NULL, NULL, 0);
    ASSERT_EQ(rc, HOOK_NO_ERR);

    rc = hook_wrap_pri((void *)target_func, 2,
                        (void *)before_id_neg5, NULL, NULL, -5);
    ASSERT_EQ(rc, HOOK_NO_ERR);

    int result = call_func(3, 4);
    ASSERT_EQ(result, 7);

    /* Verify execution order matches priority (10 first, -5 last) */
    ASSERT_EQ(exec_count, 3);
    ASSERT_EQ(exec_order[0], 10);
    ASSERT_EQ(exec_order[1], 0);
    ASSERT_EQ(exec_order[2], -5);

    hook_unwrap((void *)target_func, (void *)before_id10, NULL);
    hook_unwrap((void *)target_func, (void *)before_id0, NULL);
    hook_unwrap((void *)target_func, (void *)before_id_neg5, NULL);
    hook_teardown();
}

TEST(chain_unwrap_removes_one)
{
    hook_setup();
    reset_order();

    hook_wrap_pri((void *)target_func, 2,
                   (void *)before_id10, NULL, NULL, 10);
    hook_wrap_pri((void *)target_func, 2,
                   (void *)before_id0, NULL, NULL, 0);
    hook_wrap_pri((void *)target_func, 2,
                   (void *)before_id_neg5, NULL, NULL, -5);

    /* Remove middle-priority callback */
    hook_unwrap_remove((void *)target_func, (void *)before_id0, NULL, 0);

    call_func(1, 1);

    /* Only 10 and -5 should fire */
    ASSERT_EQ(exec_count, 2);
    ASSERT_EQ(exec_order[0], 10);
    ASSERT_EQ(exec_order[1], -5);

    hook_unwrap((void *)target_func, (void *)before_id10, NULL);
    hook_unwrap((void *)target_func, (void *)before_id_neg5, NULL);
    hook_teardown();
}

TEST(chain_local_persists_before_to_after)
{
    hook_setup();
    local_from_after = 0;
    local_ptr_A = NULL;

    hook_err_t rc = hook_wrap_pri((void *)target_func, 2,
                                   (void *)before_set_local,
                                   (void *)after_read_local, NULL, 0);
    ASSERT_EQ(rc, HOOK_NO_ERR);

    call_func(1, 2);

    /* After callback should see 0xBEEF set by before callback */
    ASSERT_EQ(local_from_after, (uint64_t)0xBEEF);

    hook_unwrap((void *)target_func,
                (void *)before_set_local, (void *)after_read_local);
    hook_teardown();
}

TEST(chain_local_isolated_between_items)
{
    hook_setup();
    local_ptr_A = NULL;
    local_ptr_B = NULL;

    /* Two chain items on same function */
    hook_wrap_pri((void *)target_func, 2,
                   (void *)before_set_local, (void *)after_read_local,
                   NULL, 10);
    hook_wrap_pri((void *)target_func, 2,
                   (void *)before_set_local_B, (void *)after_read_local_B,
                   NULL, 0);

    call_func(1, 2);

    /* Each item should have its own local storage */
    ASSERT_NOT_NULL(local_ptr_A);
    ASSERT_NOT_NULL(local_ptr_B);
    ASSERT_NE((uintptr_t)local_ptr_A, (uintptr_t)local_ptr_B);

    /* A's local has 0xBEEF, B's has 0xCAFE */
    ASSERT_EQ(local_ptr_A->data0, (uint64_t)0xBEEF);
    ASSERT_EQ(local_ptr_B->data0, (uint64_t)0xCAFE);

    hook_unwrap((void *)target_func,
                (void *)before_set_local, (void *)after_read_local);
    hook_unwrap((void *)target_func,
                (void *)before_set_local_B, (void *)after_read_local_B);
    hook_teardown();
}

/* Callback that saves the chain pointer for wrap_get_origin_func test */
static void *saved_chain;

static void before_save_chain(hook_fargs2_t *fargs, void *udata)
{
    (void)udata;
    saved_chain = fargs->chain;
}

TEST(chain_wrap_get_origin_func)
{
    hook_setup();
    saved_chain = NULL;

    hook_err_t rc = hook_wrap_pri((void *)target_func, 2,
                                   (void *)before_save_chain, NULL, NULL, 0);
    ASSERT_EQ(rc, HOOK_NO_ERR);

    /* Call to populate saved_chain */
    call_func(5, 10);
    ASSERT_NOT_NULL(saved_chain);

    /* Get origin function pointer and call it directly */
    hook_fargs2_t fake_fargs;
    fake_fargs.chain = saved_chain;
    int (*origin)(int, int) = (int (*)(int, int))wrap_get_origin_func(&fake_fargs);
    ASSERT_NOT_NULL(origin);

    int result = origin(100, 200);
    ASSERT_EQ(result, 300);

    hook_unwrap((void *)target_func, (void *)before_save_chain, NULL);
    hook_teardown();
}

TEST(chain_fp_hook_wrap)
{
    hook_setup();
    fp_before_called = 0;
    fp_after_called = 0;
    fp_captured_ret = 0;

    /* Reset fp_target in case previous tests changed it */
    fp_target = fp_target_impl;

    uintptr_t fp_addr = (uintptr_t)&fp_target;

    hook_err_t rc = fp_hook_wrap_pri(fp_addr, 2,
                                      (void *)fp_before, (void *)fp_after,
                                      NULL, 0);
    ASSERT_EQ(rc, HOOK_NO_ERR);

    /* Call through the function pointer */
    int result = fp_target(6, 7);
    ASSERT_EQ(result, 42);
    ASSERT_TRUE(fp_before_called);
    ASSERT_TRUE(fp_after_called);
    ASSERT_EQ(fp_captured_ret, (uint64_t)42);

    fp_hook_unwrap(fp_addr, (void *)fp_before, (void *)fp_after);
    hook_teardown();
}

int main(void)
{
    return RUN_ALL_TESTS();
}
