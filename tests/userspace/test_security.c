/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Integration tests: real compiler-generated BTI+PAC prologues (US-013)
 *
 * Unlike test_interaction.c (which uses naked/.inst for precise control),
 * this file is compiled with -mbranch-protection=standard so the compiler
 * itself generates BTI and/or PAC prologue instructions.  This verifies
 * that hook_prepare correctly detects and handles real-world prologues.
 *
 * On Apple clang with -mbranch-protection=standard:
 *   - Leaf functions get BTI C prologue
 *   - Non-leaf functions get PACIASP prologue (PACIASP acts as BTI landing pad)
 *
 * Tests skip gracefully if the compiler does not support -mbranch-protection.
 */

#include "test_framework.h"
#include <hook.h>
#include <hmem.h>
#include <hook_mem_user.h>

#ifndef HAS_BRANCH_PROTECTION
/* Compiler does not support -mbranch-protection=standard */
TEST(security_skip_no_branch_protection)
{
    SKIP_TEST("compiler does not support -mbranch-protection=standard");
}

int main(void)
{
    return RUN_ALL_TESTS();
}

#else /* HAS_BRANCH_PROTECTION */

/* ---- Target functions ----
 * Compiled with -mbranch-protection=standard, the compiler will generate
 * BTI C (leaf) or PACIASP (non-leaf) prologues automatically.
 * NOP padding ensures enough instructions for the 4/5-instruction trampoline.
 *
 * On Android, aligned(4096) + non-static ensures the target lands on its
 * own page, preventing same-page mprotect issues with library code. */

#ifdef __ANDROID__
#define SEC_TARGET __attribute__((noinline, visibility("hidden"), aligned(4096)))
#else
#define SEC_TARGET __attribute__((noinline))
#endif

SEC_TARGET
int target_leaf_add(int a, int b)
{
    asm volatile("nop\n\tnop\n\tnop\n\tnop");
    return a + b;
}

/* Non-leaf: calls target_leaf_add to force a stack frame and PACIASP */
SEC_TARGET
int target_nonleaf_add(int a, int b)
{
    asm volatile("nop\n\tnop\n\tnop\n\tnop");
    return target_leaf_add(a, b);
}

/* Volatile function pointers prevent inlining/optimization */
static int (*volatile call_leaf)(int, int) = target_leaf_add;
static int (*volatile call_nonleaf)(int, int) = target_nonleaf_add;

/* ---- Callback state ---- */

static int before_called;
static int after_called;
static uint64_t captured_arg0;
static uint64_t captured_arg1;
static uint64_t captured_ret;

static void reset_state(void)
{
    before_called = 0;
    after_called = 0;
    captured_arg0 = 0;
    captured_arg1 = 0;
    captured_ret = 0;
}

/* ---- Callbacks ---- */

static void before_cb(hook_fargs2_t *fargs, void *udata)
{
    (void)udata;
    before_called = 1;
    captured_arg0 = fargs->arg0;
    captured_arg1 = fargs->arg1;
}

static void after_cb(hook_fargs2_t *fargs, void *udata)
{
    (void)udata;
    after_called = 1;
    captured_ret = fargs->ret;
}

/* ---- Tests ---- */

/* Simple hook on a BTI+PAC function: hook, call, verify return value */
TEST(security_simple_hook_leaf)
{
    int rc = hook_mem_user_init();
    ASSERT_EQ(rc, 0);
    reset_state();

    /* Unhooked baseline */
    int result = call_leaf(10, 20);
    ASSERT_EQ(result, 30);

    /* Hook with before callback only */
    hook_err_t err = hook_wrap_pri(
        (void *)target_leaf_add, 2,
        (void *)before_cb, NULL, NULL, 0);
    ASSERT_EQ(err, HOOK_NO_ERR);

    /* Call hooked function and verify original still executes */
    result = call_leaf(3, 7);
    ASSERT_EQ(result, 10);
    ASSERT_TRUE(before_called);
    ASSERT_EQ(captured_arg0, 3);
    ASSERT_EQ(captured_arg1, 7);

    hook_unwrap((void *)target_leaf_add, (void *)before_cb, NULL);
    hook_mem_user_cleanup();
}

/* Chain hook on BTI+PAC function with before/after callbacks */
TEST(security_chain_hook_leaf)
{
    int rc = hook_mem_user_init();
    ASSERT_EQ(rc, 0);
    reset_state();

    hook_err_t err = hook_wrap_pri(
        (void *)target_leaf_add, 2,
        (void *)before_cb, (void *)after_cb, NULL, 0);
    ASSERT_EQ(err, HOOK_NO_ERR);

    int result = call_leaf(11, 22);
    ASSERT_EQ(result, 33);
    ASSERT_TRUE(before_called);
    ASSERT_TRUE(after_called);
    ASSERT_EQ(captured_arg0, 11);
    ASSERT_EQ(captured_arg1, 22);
    ASSERT_EQ(captured_ret, 33);

    hook_unwrap((void *)target_leaf_add,
                (void *)before_cb, (void *)after_cb);
    hook_mem_user_cleanup();
}

/* Unhook restores original function correctly */
TEST(security_unhook_restores)
{
    int rc = hook_mem_user_init();
    ASSERT_EQ(rc, 0);
    reset_state();

    hook_err_t err = hook_wrap_pri(
        (void *)target_leaf_add, 2,
        (void *)before_cb, (void *)after_cb, NULL, 0);
    ASSERT_EQ(err, HOOK_NO_ERR);

    /* Verify hooked call works */
    int result = call_leaf(5, 5);
    ASSERT_EQ(result, 10);
    ASSERT_TRUE(before_called);

    /* Unhook */
    hook_unwrap((void *)target_leaf_add,
                (void *)before_cb, (void *)after_cb);

    /* Verify restored: callbacks should NOT fire */
    reset_state();
    result = call_leaf(100, 200);
    ASSERT_EQ(result, 300);
    ASSERT_FALSE(before_called);
    ASSERT_FALSE(after_called);

    hook_mem_user_cleanup();
}

/* Verify trampoline has BTI_JC at position 0 after hooking */
TEST(security_trampoline_has_bti_jc)
{
    int rc = hook_mem_user_init();
    ASSERT_EQ(rc, 0);

    hook_err_t err = hook_wrap_pri(
        (void *)target_leaf_add, 2,
        (void *)before_cb, NULL, NULL, 0);
    ASSERT_EQ(err, HOOK_NO_ERR);

    /* Read the first instruction at the hooked function's address.
     * After hooking, the trampoline overwrites the prologue.
     * If the original had BTI/PAC, tramp[0] should be BTI_JC. */
    uint32_t first_inst = *(volatile uint32_t *)target_leaf_add;
    ASSERT_EQ(first_inst, ARM64_BTI_JC);

    hook_unwrap((void *)target_leaf_add, (void *)before_cb, NULL);
    hook_mem_user_cleanup();
}

/* Hook a non-leaf function (PACIASP prologue) */
TEST(security_nonleaf_hook)
{
    int rc = hook_mem_user_init();
    ASSERT_EQ(rc, 0);
    reset_state();

    /* Unhooked baseline */
    int result = call_nonleaf(4, 6);
    ASSERT_EQ(result, 10);

    hook_err_t err = hook_wrap_pri(
        (void *)target_nonleaf_add, 2,
        (void *)before_cb, (void *)after_cb, NULL, 0);
    ASSERT_EQ(err, HOOK_NO_ERR);

    result = call_nonleaf(15, 25);
    ASSERT_EQ(result, 40);
    ASSERT_TRUE(before_called);
    ASSERT_TRUE(after_called);
    ASSERT_EQ(captured_ret, 40);

    /* Verify trampoline has BTI_JC (PACIASP triggers 5-inst trampoline) */
    uint32_t first_inst = *(volatile uint32_t *)target_nonleaf_add;
    ASSERT_EQ(first_inst, ARM64_BTI_JC);

    hook_unwrap((void *)target_nonleaf_add,
                (void *)before_cb, (void *)after_cb);
    hook_mem_user_cleanup();
}

int main(void)
{
    return RUN_ALL_TESTS();
}

#endif /* HAS_BRANCH_PROTECTION */
