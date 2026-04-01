/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Integration tests: multi-mechanism security interactions (US-011)
 *
 * Tests pairwise interactions between ARM64 security mechanisms during
 * real hook/call/unhook cycles.  Uses naked functions with .inst to
 * emit specific prologue sequences.
 *
 * Pairwise interaction matrix:
 *
 * +----------+--------+---------+--------+
 * |          |  BTI   |   PAC   |  SCS   |
 * +----------+--------+---------+--------+
 * | BTI      |   --   | Tested  | [note] |
 * | PAC      | Tested |   --    | [note] |
 * | SCS      | [note] | [note]  |   --   |
 * +----------+--------+---------+--------+
 *
 * [note] SCS pairwise tests (BTI+SCS, PAC+SCS) are skipped on macOS
 *        because X18 is platform-reserved.  SCS instructions are
 *        relocated via relo_ignore; push/pop pairs balance naturally
 *        through the call chain.  Unit tests in test_reloc.c verify
 *        SCS relocation at the instruction level.
 *
 * Individual mechanism tests:
 * - BTI only:  BTI C prologue -> 5-inst trampoline (BTI_JC + branch)
 * - PAC only:  PACIASP/AUTIASP -> 5-inst trampoline, FPAC-safe
 * - BTI+PAC:   BTI C + PACIASP -> 5-inst trampoline (standard combo)
 *
 * FPAC safety: The transit_body BLR to relocated code sets LR, and the
 * relocated PACIASP signs it with SP.  The jump-back to the original
 * function body preserves both LR and SP, so AUTIASP succeeds.  See
 * transit.c FPAC safety invariant comment for details.
 */

#include "test_framework.h"
#include <hook.h>
#include <hmem.h>
#include <hook_mem_user.h>

/* ---- Target functions with security mechanism prologues ----
 *
 * Each is a naked function with .inst directives for precise prologue
 * control.  Padded with NOPs to provide 5 instructions for the
 * trampoline to overwrite.  AUTIASP matches PACIASP where applicable. */

__attribute__((noinline, naked))
int target_bti_only(int a, int b)
{
    asm volatile(
        ".inst 0xd503245f\n\t"  /* BTI C */
        "nop\n\t"
        "nop\n\t"
        "nop\n\t"
        "nop\n\t"
        "add w0, w0, w1\n\t"
        "ret\n\t"
    );
}

__attribute__((noinline, naked))
int target_pac_only(int a, int b)
{
    asm volatile(
        ".inst 0xd503233f\n\t"  /* PACIASP */
        "nop\n\t"
        "nop\n\t"
        "nop\n\t"
        "nop\n\t"
        "add w0, w0, w1\n\t"
        ".inst 0xd50323bf\n\t"  /* AUTIASP */
        "ret\n\t"
    );
}

/* BTI+PAC combo: equivalent to -mbranch-protection=standard */
__attribute__((noinline, naked))
int target_bti_pac(int a, int b)
{
    asm volatile(
        ".inst 0xd503245f\n\t"  /* BTI C */
        ".inst 0xd503233f\n\t"  /* PACIASP */
        "nop\n\t"
        "nop\n\t"
        "nop\n\t"
        "add w0, w0, w1\n\t"
        ".inst 0xd50323bf\n\t"  /* AUTIASP */
        "ret\n\t"
    );
}

/* Volatile function pointers prevent IPA/DCE optimizations */
static int (*volatile call_bti_only)(int, int) = target_bti_only;
static int (*volatile call_pac_only)(int, int) = target_pac_only;
static int (*volatile call_bti_pac)(int, int) = target_bti_pac;

/* ---- Shared callback state ---- */

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

TEST(interaction_bti_only)
{
    int rc = hook_mem_user_init();
    ASSERT_EQ(rc, 0);
    reset_state();

    /* Verify unhooked baseline */
    int result = call_bti_only(10, 20);
    ASSERT_EQ(result, 30);

    /* Hook */
    hook_err_t err = hook_wrap(
        (void *)target_bti_only, 2,
        (void *)before_cb, (void *)after_cb, NULL, 0);
    ASSERT_EQ(err, HOOK_NO_ERR);

    /* Call hooked function */
    result = call_bti_only(3, 7);
    ASSERT_EQ(result, 10);
    ASSERT_TRUE(before_called);
    ASSERT_TRUE(after_called);
    ASSERT_EQ(captured_arg0, 3);
    ASSERT_EQ(captured_arg1, 7);
    ASSERT_EQ(captured_ret, 10);

    /* Unhook and verify restoration */
    hook_unwrap((void *)target_bti_only,
                (void *)before_cb, (void *)after_cb);
    reset_state();
    result = call_bti_only(100, 200);
    ASSERT_EQ(result, 300);
    ASSERT_FALSE(before_called);

    hook_mem_user_cleanup();
}

TEST(interaction_pac_only)
{
    int rc = hook_mem_user_init();
    ASSERT_EQ(rc, 0);
    reset_state();

    /* Verify unhooked baseline */
    int result = call_pac_only(5, 15);
    ASSERT_EQ(result, 20);

    /* Hook */
    hook_err_t err = hook_wrap(
        (void *)target_pac_only, 2,
        (void *)before_cb, (void *)after_cb, NULL, 0);
    ASSERT_EQ(err, HOOK_NO_ERR);

    /* Call hooked function */
    result = call_pac_only(11, 22);
    ASSERT_EQ(result, 33);
    ASSERT_TRUE(before_called);
    ASSERT_TRUE(after_called);
    ASSERT_EQ(captured_arg0, 11);
    ASSERT_EQ(captured_arg1, 22);
    ASSERT_EQ(captured_ret, 33);

    /* Unhook and verify restoration */
    hook_unwrap((void *)target_pac_only,
                (void *)before_cb, (void *)after_cb);
    reset_state();
    result = call_pac_only(50, 60);
    ASSERT_EQ(result, 110);
    ASSERT_FALSE(before_called);

    hook_mem_user_cleanup();
}

TEST(interaction_bti_pac_combo)
{
    int rc = hook_mem_user_init();
    ASSERT_EQ(rc, 0);
    reset_state();

    /* Verify unhooked baseline */
    int result = call_bti_pac(8, 12);
    ASSERT_EQ(result, 20);

    /* Hook (simulates -mbranch-protection=standard) */
    hook_err_t err = hook_wrap(
        (void *)target_bti_pac, 2,
        (void *)before_cb, (void *)after_cb, NULL, 0);
    ASSERT_EQ(err, HOOK_NO_ERR);

    /* Call hooked function */
    result = call_bti_pac(40, 2);
    ASSERT_EQ(result, 42);
    ASSERT_TRUE(before_called);
    ASSERT_TRUE(after_called);
    ASSERT_EQ(captured_arg0, 40);
    ASSERT_EQ(captured_arg1, 2);
    ASSERT_EQ(captured_ret, 42);

    /* Unhook and verify restoration */
    hook_unwrap((void *)target_bti_pac,
                (void *)before_cb, (void *)after_cb);
    reset_state();
    result = call_bti_pac(99, 1);
    ASSERT_EQ(result, 100);
    ASSERT_FALSE(before_called);

    hook_mem_user_cleanup();
}

int main(void)
{
    return RUN_ALL_TESTS();
}
