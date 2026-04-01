/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Integration tests: basic in-process hooking.
 * Hooks real compiled functions and verifies callback invocation.
 */

#include "test_framework.h"
#include <hook.h>
#include <hmem.h>
#include <hook_mem_user.h>
#include <string.h>

/* ---- Target functions (must not be inlined) ----
 * Padded with nops so each function is >= 16 bytes (the trampoline size).
 * Without padding, Release-mode 8-byte functions cause the trampoline
 * to overwrite the adjacent function. */

__attribute__((noinline))
int target_add(int a, int b)
{
    asm volatile("nop\n\tnop\n\tnop");
    return a + b;
}

__attribute__((noinline))
int target_nop(void)
{
    asm volatile("nop\n\tnop\n\tnop");
    return 42;
}

__attribute__((noinline))
uint64_t target_8args(uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3,
                       uint64_t a4, uint64_t a5, uint64_t a6, uint64_t a7)
{
    /* Already large enough, but pad for safety */
    asm volatile("nop\n\tnop\n\tnop");
    return a0 + a1 + a2 + a3 + a4 + a5 + a6 + a7;
}

/* Volatile function pointers prevent the compiler from eliminating calls
 * via interprocedural constant propagation / dead-code elimination. */
static int (*volatile call_add)(int, int) = target_add;
static int (*volatile call_nop)(void) = target_nop;
static uint64_t (*volatile call_8args)(uint64_t, uint64_t, uint64_t,
                                        uint64_t, uint64_t, uint64_t,
                                        uint64_t, uint64_t) = target_8args;

/* ---- Shared state for callback verification ---- */

static int before_called;
static int after_called;
static uint64_t captured_arg0;
static uint64_t captured_arg1;
static uint64_t captured_ret;
static int should_skip_origin;
static uint64_t skip_ret_value;

static void reset_state(void)
{
    before_called = 0;
    after_called = 0;
    captured_arg0 = 0;
    captured_arg1 = 0;
    captured_ret = 0;
    should_skip_origin = 0;
    skip_ret_value = 0;
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

/* ---- Callbacks ---- */

static void before_capture_args(hook_fargs2_t *fargs, void *udata)
{
    (void)udata;
    before_called = 1;
    captured_arg0 = fargs->arg0;
    captured_arg1 = fargs->arg1;
    if (should_skip_origin) {
        fargs->skip_origin = 1;
        fargs->ret = skip_ret_value;
    }
}

static void after_capture_ret(hook_fargs2_t *fargs, void *udata)
{
    (void)udata;
    after_called = 1;
    captured_ret = fargs->ret;
}

static void after_modify_ret(hook_fargs2_t *fargs, void *udata)
{
    (void)udata;
    after_called = 1;
    fargs->ret = 999;
}

static void before_nop(hook_fargs0_t *fargs, void *udata)
{
    (void)fargs;
    (void)udata;
    before_called = 1;
}

static void after_nop(hook_fargs0_t *fargs, void *udata)
{
    (void)fargs;
    (void)udata;
    after_called = 1;
}

/* 8-arg callbacks */
static uint64_t captured_args[8];

static void before_8args(hook_fargs8_t *fargs, void *udata)
{
    (void)udata;
    before_called = 1;
    for (int i = 0; i < 8; i++)
        captured_args[i] = fargs->args[i];
}

static void after_8args(hook_fargs8_t *fargs, void *udata)
{
    (void)udata;
    after_called = 1;
    captured_ret = fargs->ret;
}

/* ---- Tests ---- */

TEST(hook_basic_before_captures_args)
{
    hook_setup();
    reset_state();

    hook_err_t rc = hook_wrap(
        (void *)target_add, 2,
        (void *)before_capture_args, NULL, NULL, 0);
    ASSERT_EQ(rc, HOOK_NO_ERR);

    int result = call_add(10, 20);
    ASSERT_EQ(result, 30);
    ASSERT_TRUE(before_called);
    ASSERT_EQ(captured_arg0, 10);
    ASSERT_EQ(captured_arg1, 20);

    hook_unwrap((void *)target_add,
                (void *)before_capture_args, NULL);
    hook_teardown();
}

TEST(hook_basic_after_captures_ret)
{
    hook_setup();
    reset_state();

    hook_err_t rc = hook_wrap(
        (void *)target_add, 2,
        NULL, (void *)after_capture_ret, NULL, 0);
    ASSERT_EQ(rc, HOOK_NO_ERR);

    int result = call_add(7, 3);
    ASSERT_EQ(result, 10);
    ASSERT_TRUE(after_called);
    ASSERT_EQ(captured_ret, 10);

    hook_unwrap((void *)target_add,
                NULL, (void *)after_capture_ret);
    hook_teardown();
}

TEST(hook_basic_after_modifies_ret)
{
    hook_setup();
    reset_state();

    hook_err_t rc = hook_wrap(
        (void *)target_add, 2,
        NULL, (void *)after_modify_ret, NULL, 0);
    ASSERT_EQ(rc, HOOK_NO_ERR);

    int result = call_add(1, 2);
    /* After callback sets ret = 999 */
    ASSERT_EQ(result, 999);
    ASSERT_TRUE(after_called);

    hook_unwrap((void *)target_add,
                NULL, (void *)after_modify_ret);
    hook_teardown();
}

TEST(hook_basic_skip_origin)
{
    hook_setup();
    reset_state();
    should_skip_origin = 1;
    skip_ret_value = 777;

    hook_err_t rc = hook_wrap(
        (void *)target_add, 2,
        (void *)before_capture_args, NULL, NULL, 0);
    ASSERT_EQ(rc, HOOK_NO_ERR);

    int result = call_add(100, 200);
    /* skip_origin = 1, so original not called, ret = 777 */
    ASSERT_EQ(result, 777);
    ASSERT_TRUE(before_called);

    hook_unwrap((void *)target_add,
                (void *)before_capture_args, NULL);
    hook_teardown();
}

TEST(hook_basic_nop_0args)
{
    hook_setup();
    reset_state();

    hook_err_t rc = hook_wrap(
        (void *)target_nop, 0,
        (void *)before_nop, (void *)after_nop, NULL, 0);
    ASSERT_EQ(rc, HOOK_NO_ERR);

    int result = call_nop();
    ASSERT_EQ(result, 42);
    ASSERT_TRUE(before_called);
    ASSERT_TRUE(after_called);

    hook_unwrap((void *)target_nop,
                (void *)before_nop, (void *)after_nop);
    hook_teardown();
}

TEST(hook_basic_8args)
{
    hook_setup();
    reset_state();
    memset(captured_args, 0, sizeof(captured_args));

    hook_err_t rc = hook_wrap(
        (void *)target_8args, 8,
        (void *)before_8args, (void *)after_8args, NULL, 0);
    ASSERT_EQ(rc, HOOK_NO_ERR);

    uint64_t result = call_8args(1, 2, 3, 4, 5, 6, 7, 8);
    ASSERT_EQ(result, (uint64_t)36);
    ASSERT_TRUE(before_called);
    ASSERT_TRUE(after_called);
    ASSERT_EQ(captured_ret, (uint64_t)36);

    /* Verify all 8 args were captured */
    for (int i = 0; i < 8; i++)
        ASSERT_EQ(captured_args[i], (uint64_t)(i + 1));

    hook_unwrap((void *)target_8args,
                (void *)before_8args, (void *)after_8args);
    hook_teardown();
}

int main(void)
{
    return RUN_ALL_TESTS();
}
