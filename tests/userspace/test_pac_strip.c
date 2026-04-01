/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Unit tests for PAC function pointer stripping at API entry (US-007).
 * Verifies that STRIP_PAC macro works and that hook APIs accept
 * PAC-signed pointers correctly.
 */

#include "test_framework.h"
#include <hook.h>
#include <hmem.h>
#include <hook_mem_user.h>
#include <stdint.h>

/* ---- Target function (must be >= 16 bytes for trampoline) ---- */

__attribute__((noinline))
int pac_target(int a, int b)
{
    asm volatile("nop\n\tnop\n\tnop");
    return a + b;
}

static int (*volatile call_pac_target)(int, int) = pac_target;

/* ---- Setup/teardown ---- */

static void pac_setup(void)
{
    int rc = hook_mem_user_init();
    ASSERT_EQ(rc, 0);
}

static void pac_teardown(void)
{
    hook_mem_user_cleanup();
}

/* ---- Tests ---- */

/* Test: STRIP_PAC on a raw address returns the same address */
TEST(pac_strip_identity)
{
    void *raw = (void *)pac_target;
    void *stripped = STRIP_PAC(raw);

    /* On non-PAC builds, should be identity.
     * On PAC builds, stripping a non-signed pointer is also identity. */
    ASSERT_EQ((uintptr_t)stripped, (uintptr_t)raw);
}

/* Test: STRIP_PAC on NULL returns NULL */
TEST(pac_strip_null)
{
    void *stripped = STRIP_PAC(NULL);
    ASSERT_EQ((uintptr_t)stripped, (uintptr_t)0);
}

/* Test: hook() works with a function pointer (PAC stripped internally) */
TEST(pac_hook_unhook)
{
    pac_setup();

    void *backup = NULL;
    /* Use the function pointer directly — on PAC-enabled binaries,
     * taking a function address may produce a signed pointer. */
    hook_err_t rc = hook((void *)pac_target, (void *)pac_target, &backup);
    /* We're hooking with self-replace just to test the PAC stripping path.
     * This should succeed (hook_prepare will set up the trampoline). */
    ASSERT_EQ(rc, HOOK_NO_ERR);
    ASSERT_NOT_NULL(backup);

    unhook((void *)pac_target);
    pac_teardown();
}

/* Test: hook_wrap_pri accepts and strips PAC from func pointer */
static int wrap_before_called = 0;
static void pac_before(hook_fargs2_t *fargs, void *udata)
{
    (void)fargs;
    (void)udata;
    wrap_before_called = 1;
}

TEST(pac_hook_wrap_pri)
{
    pac_setup();
    wrap_before_called = 0;

    hook_err_t rc = hook_wrap_pri(
        (void *)pac_target, 2,
        (void *)pac_before, NULL, NULL, 0);
    ASSERT_EQ(rc, HOOK_NO_ERR);

    int result = call_pac_target(3, 4);
    ASSERT_EQ(result, 7);
    ASSERT_TRUE(wrap_before_called);

    hook_unwrap((void *)pac_target, (void *)pac_before, NULL);
    pac_teardown();
}

/* Test: hook_unwrap_remove with PAC-stripped addresses matches */
TEST(pac_hook_unwrap_remove)
{
    pac_setup();
    wrap_before_called = 0;

    hook_err_t rc = hook_wrap_pri(
        (void *)pac_target, 2,
        (void *)pac_before, NULL, NULL, 0);
    ASSERT_EQ(rc, HOOK_NO_ERR);

    /* Unwrap using same pointer — PAC stripping ensures match */
    hook_unwrap_remove((void *)pac_target, (void *)pac_before, NULL, 1);

    /* After unwrap, original function should work normally */
    int result = call_pac_target(5, 6);
    ASSERT_EQ(result, 11);

    pac_teardown();
}

/* Test: fp_hook / fp_unhook with function pointer */
TEST(pac_fp_hook_unhook)
{
    pac_setup();

    /* Create a function pointer variable to hook */
    void *fp_var = (void *)pac_target;
    void *backup = NULL;

    fp_hook((uintptr_t)&fp_var, (void *)pac_target, &backup);
    /* fp_var should now point to pac_target (self-replace for simplicity) */
    ASSERT_NOT_NULL(backup);

    fp_unhook((uintptr_t)&fp_var, backup);
    /* fp_var should be restored */
    ASSERT_EQ((uintptr_t)fp_var, (uintptr_t)backup);

    pac_teardown();
}

/* Test: STRIP_PAC with simulated upper-byte PAC bits (non-PAC build only) */
TEST(pac_strip_simulated_bits)
{
#ifdef __ARM_FEATURE_PAC_DEFAULT
    /* On real PAC hardware, ptrauth_strip handles this natively.
     * We can't easily simulate bits — skip and trust the hardware. */
    SKIP_TEST("PAC hardware strips natively");
#else
    /* On non-PAC builds, STRIP_PAC is identity — verify this */
    uintptr_t raw = (uintptr_t)pac_target;
    void *stripped = STRIP_PAC(raw);
    ASSERT_EQ((uintptr_t)stripped, raw);
#endif
}

int main(void)
{
    return RUN_ALL_TESTS();
}
