/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Typed wrapper tests: verifies all 13 hook_wrapN arities (0-12).
 * Each test calls hook_wrapN, invokes via a volatile function pointer,
 * asserts both callbacks fired, and checks the captured return value.
 */

#include "test_framework.h"
#include <hook.h>
#include <hmem.h>
#include <hook_mem_user.h>

/* ---- Shared callback-state ---- */

static int g_before_called;
static int g_after_called;
static uint64_t g_captured_ret;

static void reset_state(void)
{
    g_before_called  = 0;
    g_after_called   = 0;
    g_captured_ret   = 0;
}

/* ====================================================================
 * Arity 0
 * ==================================================================== */

__attribute__((noinline))
static uint64_t target_0(void)
{
    asm volatile("nop\n\tnop\n\tnop");
    return 42;
}

static uint64_t (*volatile call_0)(void) = target_0;

static void before_0(hook_fargs0_t *fargs, void *udata)
{
    (void)fargs;
    (void)udata;
    g_before_called = 1;
}

static void after_0(hook_fargs0_t *fargs, void *udata)
{
    (void)udata;
    g_after_called  = 1;
    g_captured_ret  = fargs->ret;
}

TEST(wrap0)
{
    int rc = hook_mem_user_init();
    ASSERT_EQ(rc, 0);
    reset_state();

    hook_err_t err = hook_wrap0((void *)target_0, before_0, after_0, NULL);
    ASSERT_EQ(err, HOOK_NO_ERR);

    uint64_t result = call_0();
    ASSERT_EQ(result, (uint64_t)42);
    ASSERT_TRUE(g_before_called);
    ASSERT_TRUE(g_after_called);
    ASSERT_EQ(g_captured_ret, (uint64_t)42);

    hook_unwrap((void *)target_0, (void *)before_0, (void *)after_0);
    hook_mem_user_cleanup();
}

/* ====================================================================
 * Arities 1-4  (hook_fargs4_t)
 * ==================================================================== */

/* --- Arity 1 --- */

__attribute__((noinline))
static uint64_t target_1(uint64_t a0)
{
    asm volatile("nop\n\tnop\n\tnop");
    return a0;
}
static uint64_t (*volatile call_1)(uint64_t) = target_1;

static void before_1(hook_fargs4_t *fargs, void *udata)
{
    (void)fargs;
    (void)udata;
    g_before_called = 1;
}
static void after_1(hook_fargs4_t *fargs, void *udata)
{
    (void)udata;
    g_after_called = 1;
    g_captured_ret = fargs->ret;
}

TEST(wrap1)
{
    int rc = hook_mem_user_init();
    ASSERT_EQ(rc, 0);
    reset_state();

    hook_err_t err = hook_wrap1((void *)target_1, before_1, after_1, NULL);
    ASSERT_EQ(err, HOOK_NO_ERR);

    uint64_t result = call_1(10);
    ASSERT_EQ(result, (uint64_t)10);
    ASSERT_TRUE(g_before_called);
    ASSERT_TRUE(g_after_called);
    ASSERT_EQ(g_captured_ret, (uint64_t)10);

    hook_unwrap((void *)target_1, (void *)before_1, (void *)after_1);
    hook_mem_user_cleanup();
}

/* --- Arity 2 --- */

__attribute__((noinline))
static uint64_t target_2(uint64_t a0, uint64_t a1)
{
    asm volatile("nop\n\tnop\n\tnop");
    return a0 + a1;
}
static uint64_t (*volatile call_2)(uint64_t, uint64_t) = target_2;

static void before_2(hook_fargs4_t *fargs, void *udata)
{
    (void)fargs;
    (void)udata;
    g_before_called = 1;
}
static void after_2(hook_fargs4_t *fargs, void *udata)
{
    (void)udata;
    g_after_called = 1;
    g_captured_ret = fargs->ret;
}

TEST(wrap2)
{
    int rc = hook_mem_user_init();
    ASSERT_EQ(rc, 0);
    reset_state();

    hook_err_t err = hook_wrap2((void *)target_2, before_2, after_2, NULL);
    ASSERT_EQ(err, HOOK_NO_ERR);

    uint64_t result = call_2(3, 7);
    ASSERT_EQ(result, (uint64_t)10);
    ASSERT_TRUE(g_before_called);
    ASSERT_TRUE(g_after_called);
    ASSERT_EQ(g_captured_ret, (uint64_t)10);

    hook_unwrap((void *)target_2, (void *)before_2, (void *)after_2);
    hook_mem_user_cleanup();
}

/* --- Arity 3 --- */

__attribute__((noinline))
static uint64_t target_3(uint64_t a0, uint64_t a1, uint64_t a2)
{
    asm volatile("nop\n\tnop\n\tnop");
    return a0 + a1 + a2;
}
static uint64_t (*volatile call_3)(uint64_t, uint64_t, uint64_t) = target_3;

static void before_3(hook_fargs4_t *fargs, void *udata)
{
    (void)fargs;
    (void)udata;
    g_before_called = 1;
}
static void after_3(hook_fargs4_t *fargs, void *udata)
{
    (void)udata;
    g_after_called = 1;
    g_captured_ret = fargs->ret;
}

TEST(wrap3)
{
    int rc = hook_mem_user_init();
    ASSERT_EQ(rc, 0);
    reset_state();

    hook_err_t err = hook_wrap3((void *)target_3, before_3, after_3, NULL);
    ASSERT_EQ(err, HOOK_NO_ERR);

    uint64_t result = call_3(1, 2, 3);
    ASSERT_EQ(result, (uint64_t)6);
    ASSERT_TRUE(g_before_called);
    ASSERT_TRUE(g_after_called);
    ASSERT_EQ(g_captured_ret, (uint64_t)6);

    hook_unwrap((void *)target_3, (void *)before_3, (void *)after_3);
    hook_mem_user_cleanup();
}

/* --- Arity 4 --- */

__attribute__((noinline))
static uint64_t target_4(uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3)
{
    asm volatile("nop\n\tnop\n\tnop");
    return a0 + a1 + a2 + a3;
}
static uint64_t (*volatile call_4)(uint64_t, uint64_t, uint64_t, uint64_t) = target_4;

static void before_4(hook_fargs4_t *fargs, void *udata)
{
    (void)fargs;
    (void)udata;
    g_before_called = 1;
}
static void after_4(hook_fargs4_t *fargs, void *udata)
{
    (void)udata;
    g_after_called = 1;
    g_captured_ret = fargs->ret;
}

TEST(wrap4)
{
    int rc = hook_mem_user_init();
    ASSERT_EQ(rc, 0);
    reset_state();

    hook_err_t err = hook_wrap4((void *)target_4, before_4, after_4, NULL);
    ASSERT_EQ(err, HOOK_NO_ERR);

    uint64_t result = call_4(1, 2, 3, 4);
    ASSERT_EQ(result, (uint64_t)10);
    ASSERT_TRUE(g_before_called);
    ASSERT_TRUE(g_after_called);
    ASSERT_EQ(g_captured_ret, (uint64_t)10);

    hook_unwrap((void *)target_4, (void *)before_4, (void *)after_4);
    hook_mem_user_cleanup();
}

/* ====================================================================
 * Arities 5-8  (hook_fargs8_t)
 * ==================================================================== */

/* --- Arity 5 --- */

__attribute__((noinline))
static uint64_t target_5(uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3,
                          uint64_t a4)
{
    asm volatile("nop\n\tnop\n\tnop");
    return a0 + a1 + a2 + a3 + a4;
}
static uint64_t (*volatile call_5)(uint64_t, uint64_t, uint64_t, uint64_t,
                                    uint64_t) = target_5;

static void before_5(hook_fargs8_t *fargs, void *udata)
{
    (void)fargs;
    (void)udata;
    g_before_called = 1;
}
static void after_5(hook_fargs8_t *fargs, void *udata)
{
    (void)udata;
    g_after_called = 1;
    g_captured_ret = fargs->ret;
}

TEST(wrap5)
{
    int rc = hook_mem_user_init();
    ASSERT_EQ(rc, 0);
    reset_state();

    hook_err_t err = hook_wrap5((void *)target_5, before_5, after_5, NULL);
    ASSERT_EQ(err, HOOK_NO_ERR);

    uint64_t result = call_5(1, 2, 3, 4, 5);
    ASSERT_EQ(result, (uint64_t)15);
    ASSERT_TRUE(g_before_called);
    ASSERT_TRUE(g_after_called);
    ASSERT_EQ(g_captured_ret, (uint64_t)15);

    hook_unwrap((void *)target_5, (void *)before_5, (void *)after_5);
    hook_mem_user_cleanup();
}

/* --- Arity 6 --- */

__attribute__((noinline))
static uint64_t target_6(uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3,
                          uint64_t a4, uint64_t a5)
{
    asm volatile("nop\n\tnop\n\tnop");
    return a0 + a1 + a2 + a3 + a4 + a5;
}
static uint64_t (*volatile call_6)(uint64_t, uint64_t, uint64_t, uint64_t,
                                    uint64_t, uint64_t) = target_6;

static void before_6(hook_fargs8_t *fargs, void *udata)
{
    (void)fargs;
    (void)udata;
    g_before_called = 1;
}
static void after_6(hook_fargs8_t *fargs, void *udata)
{
    (void)udata;
    g_after_called = 1;
    g_captured_ret = fargs->ret;
}

TEST(wrap6)
{
    int rc = hook_mem_user_init();
    ASSERT_EQ(rc, 0);
    reset_state();

    hook_err_t err = hook_wrap6((void *)target_6, before_6, after_6, NULL);
    ASSERT_EQ(err, HOOK_NO_ERR);

    uint64_t result = call_6(1, 2, 3, 4, 5, 6);
    ASSERT_EQ(result, (uint64_t)21);
    ASSERT_TRUE(g_before_called);
    ASSERT_TRUE(g_after_called);
    ASSERT_EQ(g_captured_ret, (uint64_t)21);

    hook_unwrap((void *)target_6, (void *)before_6, (void *)after_6);
    hook_mem_user_cleanup();
}

/* --- Arity 7 --- */

__attribute__((noinline))
static uint64_t target_7(uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3,
                          uint64_t a4, uint64_t a5, uint64_t a6)
{
    asm volatile("nop\n\tnop\n\tnop");
    return a0 + a1 + a2 + a3 + a4 + a5 + a6;
}
static uint64_t (*volatile call_7)(uint64_t, uint64_t, uint64_t, uint64_t,
                                    uint64_t, uint64_t, uint64_t) = target_7;

static void before_7(hook_fargs8_t *fargs, void *udata)
{
    (void)fargs;
    (void)udata;
    g_before_called = 1;
}
static void after_7(hook_fargs8_t *fargs, void *udata)
{
    (void)udata;
    g_after_called = 1;
    g_captured_ret = fargs->ret;
}

TEST(wrap7)
{
    int rc = hook_mem_user_init();
    ASSERT_EQ(rc, 0);
    reset_state();

    hook_err_t err = hook_wrap7((void *)target_7, before_7, after_7, NULL);
    ASSERT_EQ(err, HOOK_NO_ERR);

    uint64_t result = call_7(1, 2, 3, 4, 5, 6, 7);
    ASSERT_EQ(result, (uint64_t)28);
    ASSERT_TRUE(g_before_called);
    ASSERT_TRUE(g_after_called);
    ASSERT_EQ(g_captured_ret, (uint64_t)28);

    hook_unwrap((void *)target_7, (void *)before_7, (void *)after_7);
    hook_mem_user_cleanup();
}

/* --- Arity 8 --- */

__attribute__((noinline))
static uint64_t target_8(uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3,
                          uint64_t a4, uint64_t a5, uint64_t a6, uint64_t a7)
{
    asm volatile("nop\n\tnop\n\tnop");
    return a0 + a1 + a2 + a3 + a4 + a5 + a6 + a7;
}
static uint64_t (*volatile call_8)(uint64_t, uint64_t, uint64_t, uint64_t,
                                    uint64_t, uint64_t, uint64_t,
                                    uint64_t) = target_8;

static void before_8(hook_fargs8_t *fargs, void *udata)
{
    (void)fargs;
    (void)udata;
    g_before_called = 1;
}
static void after_8(hook_fargs8_t *fargs, void *udata)
{
    (void)udata;
    g_after_called = 1;
    g_captured_ret = fargs->ret;
}

TEST(wrap8)
{
    int rc = hook_mem_user_init();
    ASSERT_EQ(rc, 0);
    reset_state();

    hook_err_t err = hook_wrap8((void *)target_8, before_8, after_8, NULL);
    ASSERT_EQ(err, HOOK_NO_ERR);

    uint64_t result = call_8(1, 2, 3, 4, 5, 6, 7, 8);
    ASSERT_EQ(result, (uint64_t)36);
    ASSERT_TRUE(g_before_called);
    ASSERT_TRUE(g_after_called);
    ASSERT_EQ(g_captured_ret, (uint64_t)36);

    hook_unwrap((void *)target_8, (void *)before_8, (void *)after_8);
    hook_mem_user_cleanup();
}

/* ====================================================================
 * Arities 9-12  (hook_fargs12_t)
 * ==================================================================== */

/* --- Arity 9 --- */

__attribute__((noinline))
static uint64_t target_9(uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3,
                          uint64_t a4, uint64_t a5, uint64_t a6, uint64_t a7,
                          uint64_t a8)
{
    asm volatile("nop\n\tnop\n\tnop");
    return a0 + a1 + a2 + a3 + a4 + a5 + a6 + a7 + a8;
}
static uint64_t (*volatile call_9)(uint64_t, uint64_t, uint64_t, uint64_t,
                                    uint64_t, uint64_t, uint64_t, uint64_t,
                                    uint64_t) = target_9;

static void before_9(hook_fargs12_t *fargs, void *udata)
{
    (void)fargs;
    (void)udata;
    g_before_called = 1;
}
static void after_9(hook_fargs12_t *fargs, void *udata)
{
    (void)udata;
    g_after_called = 1;
    g_captured_ret = fargs->ret;
}

TEST(wrap9)
{
    int rc = hook_mem_user_init();
    ASSERT_EQ(rc, 0);
    reset_state();

    hook_err_t err = hook_wrap9((void *)target_9, before_9, after_9, NULL);
    ASSERT_EQ(err, HOOK_NO_ERR);

    uint64_t result = call_9(1, 2, 3, 4, 5, 6, 7, 8, 9);
    ASSERT_EQ(result, (uint64_t)45);
    ASSERT_TRUE(g_before_called);
    ASSERT_TRUE(g_after_called);
    ASSERT_EQ(g_captured_ret, (uint64_t)45);

    hook_unwrap((void *)target_9, (void *)before_9, (void *)after_9);
    hook_mem_user_cleanup();
}

/* --- Arity 10 --- */

__attribute__((noinline))
static uint64_t target_10(uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3,
                           uint64_t a4, uint64_t a5, uint64_t a6, uint64_t a7,
                           uint64_t a8, uint64_t a9)
{
    asm volatile("nop\n\tnop\n\tnop");
    return a0 + a1 + a2 + a3 + a4 + a5 + a6 + a7 + a8 + a9;
}
static uint64_t (*volatile call_10)(uint64_t, uint64_t, uint64_t, uint64_t,
                                     uint64_t, uint64_t, uint64_t, uint64_t,
                                     uint64_t, uint64_t) = target_10;

static void before_10(hook_fargs12_t *fargs, void *udata)
{
    (void)fargs;
    (void)udata;
    g_before_called = 1;
}
static void after_10(hook_fargs12_t *fargs, void *udata)
{
    (void)udata;
    g_after_called = 1;
    g_captured_ret = fargs->ret;
}

TEST(wrap10)
{
    int rc = hook_mem_user_init();
    ASSERT_EQ(rc, 0);
    reset_state();

    hook_err_t err = hook_wrap10((void *)target_10, before_10, after_10, NULL);
    ASSERT_EQ(err, HOOK_NO_ERR);

    uint64_t result = call_10(1, 2, 3, 4, 5, 6, 7, 8, 9, 10);
    ASSERT_EQ(result, (uint64_t)55);
    ASSERT_TRUE(g_before_called);
    ASSERT_TRUE(g_after_called);
    ASSERT_EQ(g_captured_ret, (uint64_t)55);

    hook_unwrap((void *)target_10, (void *)before_10, (void *)after_10);
    hook_mem_user_cleanup();
}

/* --- Arity 11 --- */

__attribute__((noinline))
static uint64_t target_11(uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3,
                           uint64_t a4, uint64_t a5, uint64_t a6, uint64_t a7,
                           uint64_t a8, uint64_t a9, uint64_t a10)
{
    asm volatile("nop\n\tnop\n\tnop");
    return a0 + a1 + a2 + a3 + a4 + a5 + a6 + a7 + a8 + a9 + a10;
}
static uint64_t (*volatile call_11)(uint64_t, uint64_t, uint64_t, uint64_t,
                                     uint64_t, uint64_t, uint64_t, uint64_t,
                                     uint64_t, uint64_t, uint64_t) = target_11;

static void before_11(hook_fargs12_t *fargs, void *udata)
{
    (void)fargs;
    (void)udata;
    g_before_called = 1;
}
static void after_11(hook_fargs12_t *fargs, void *udata)
{
    (void)udata;
    g_after_called = 1;
    g_captured_ret = fargs->ret;
}

TEST(wrap11)
{
    int rc = hook_mem_user_init();
    ASSERT_EQ(rc, 0);
    reset_state();

    hook_err_t err = hook_wrap11((void *)target_11, before_11, after_11, NULL);
    ASSERT_EQ(err, HOOK_NO_ERR);

    uint64_t result = call_11(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11);
    ASSERT_EQ(result, (uint64_t)66);
    ASSERT_TRUE(g_before_called);
    ASSERT_TRUE(g_after_called);
    ASSERT_EQ(g_captured_ret, (uint64_t)66);

    hook_unwrap((void *)target_11, (void *)before_11, (void *)after_11);
    hook_mem_user_cleanup();
}

/* --- Arity 12 --- */

__attribute__((noinline))
static uint64_t target_12(uint64_t a0, uint64_t a1, uint64_t a2,  uint64_t a3,
                           uint64_t a4, uint64_t a5, uint64_t a6,  uint64_t a7,
                           uint64_t a8, uint64_t a9, uint64_t a10, uint64_t a11)
{
    asm volatile("nop\n\tnop\n\tnop");
    return a0 + a1 + a2 + a3 + a4 + a5 + a6 + a7 + a8 + a9 + a10 + a11;
}
static uint64_t (*volatile call_12)(uint64_t, uint64_t, uint64_t, uint64_t,
                                     uint64_t, uint64_t, uint64_t, uint64_t,
                                     uint64_t, uint64_t, uint64_t,
                                     uint64_t) = target_12;

static void before_12(hook_fargs12_t *fargs, void *udata)
{
    (void)fargs;
    (void)udata;
    g_before_called = 1;
}
static void after_12(hook_fargs12_t *fargs, void *udata)
{
    (void)udata;
    g_after_called = 1;
    g_captured_ret = fargs->ret;
}

TEST(wrap12)
{
    int rc = hook_mem_user_init();
    ASSERT_EQ(rc, 0);
    reset_state();

    hook_err_t err = hook_wrap12((void *)target_12, before_12, after_12, NULL);
    ASSERT_EQ(err, HOOK_NO_ERR);

    uint64_t result = call_12(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12);
    ASSERT_EQ(result, (uint64_t)78);
    ASSERT_TRUE(g_before_called);
    ASSERT_TRUE(g_after_called);
    ASSERT_EQ(g_captured_ret, (uint64_t)78);

    hook_unwrap((void *)target_12, (void *)before_12, (void *)after_12);
    hook_mem_user_cleanup();
}

int main(void)
{
    return RUN_ALL_TESTS();
}
