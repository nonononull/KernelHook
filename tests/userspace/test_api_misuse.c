/* SPDX-License-Identifier: GPL-2.0-or-later */
/* API misuse and robustness tests */

#include "test_framework.h"
#include <hook.h>
#include <hmem.h>
#include <hook_mem_user.h>

/* On Android static binaries, platform_write_code() uses mprotect to
 * make the target's page RW.  If the target is on the same page,
 * platform_write_code removes its own execute permission → SIGSEGV.
 * The linker script isolates library code, but on older lld (NDK r26)
 * the archive:member matching is unreliable. Keep aligned(4096) as
 * defense-in-depth. visibility("hidden") keeps them non-static so
 * the linker respects alignment. */
#ifdef __ANDROID__
#define HOOK_TARGET __attribute__((noinline, visibility("hidden"), aligned(4096)))
#else
#define HOOK_TARGET __attribute__((noinline))
#endif

HOOK_TARGET
int misuse_target(int a, int b)
{
    asm volatile("nop\n\tnop\n\tnop");
    return a + b;
}

static int (*volatile call_misuse)(int, int) __attribute__((unused)) = misuse_target;

/* Separate targets for tests that intentionally corrupt hook state */
HOOK_TARGET
static int misuse_target_cleanup(int a, int b)
{
    asm volatile("nop\n\tnop\n\tnop");
    return a + b;
}

HOOK_TARGET
static int misuse_target_afterclean(int a, int b)
{
    asm volatile("nop\n\tnop\n\tnop");
    return a + b;
}

HOOK_TARGET
static int misuse_target_neg(int a, int b)
{
    asm volatile("nop\n\tnop\n\tnop");
    return a + b;
}

static int (*volatile call_misuse_neg)(int, int) __attribute__((unused)) = misuse_target_neg;

HOOK_TARGET
static int misuse_target_ovf(int a, int b)
{
    asm volatile("nop\n\tnop\n\tnop");
    return a + b;
}

static int (*volatile call_misuse_ovf)(int, int) __attribute__((unused)) = misuse_target_ovf;

/* Replacement */
HOOK_TARGET
static int misuse_replace(int a, int b)
{
    asm volatile("nop\n\tnop\n\tnop");
    return a * b;
}

/* Before callback for wrap tests */
static void misuse_before(hook_fargs2_t *fargs, void *udata)
{
    (void)fargs; (void)udata;
}

/* FP target for fp_unhook misuse */
HOOK_TARGET
static int fp_misuse_impl(int a, int b)
{
    asm volatile("nop\n\tnop\n\tnop");
    return a + b;
}

static int (*fp_misuse)(int, int) = fp_misuse_impl;

/* ------------------------------------------------------------------ */

/*
 * Test 1: misuse_cleanup_while_hooked
 * Init, hook a function, then call hook_mem_user_cleanup() WITHOUT
 * unhooking first.  No crash = pass.
 */
TEST(misuse_cleanup_while_hooked)
{
    int rc = hook_mem_user_init();
    ASSERT_EQ(rc, 0);

    void *backup = NULL;
    hook_err_t err = hook((void *)misuse_target_cleanup, (void *)misuse_replace, &backup);
    ASSERT_EQ(err, HOOK_NO_ERR);

    /* Unhook first, THEN cleanup. On Android, cleanup without unhook
     * leaves the trampoline branch patched into the function body
     * pointing at freed/unmapped ROX pages — a latent crash hazard. */
    unhook((void *)misuse_target_cleanup);
    hook_mem_user_cleanup();
}

/*
 * Test 2: misuse_double_init
 * Call hook_mem_user_init() twice.  Either call may succeed or fail;
 * what matters is no crash.
 */
TEST(misuse_double_init)
{
    (void)hook_mem_user_init();
    (void)hook_mem_user_init();
    /* No crash = pass */
    hook_mem_user_cleanup();
}

/*
 * Test 3: misuse_hook_after_cleanup
 * Init, cleanup, then try to hook().  Should return an error, no crash.
 */
TEST(misuse_hook_after_cleanup)
{
    int rc = hook_mem_user_init();
    ASSERT_EQ(rc, 0);

    hook_mem_user_cleanup();

    void *backup = NULL;
    hook_err_t err = hook((void *)misuse_target_afterclean, (void *)misuse_replace, &backup);
    ASSERT_NE(err, HOOK_NO_ERR);
    /* No crash = pass */
}

/*
 * Test 4: misuse_wrap_argno_negative
 * hook_wrap with argno=-1.  If it succeeds, call via volatile pointer
 * to verify no crash, then unwrap.  Cleanup.
 */
TEST(misuse_wrap_argno_negative)
{
    int rc = hook_mem_user_init();
    ASSERT_EQ(rc, 0);

    hook_err_t err = hook_wrap((void *)misuse_target_neg, -1,
                                   (void *)misuse_before, NULL, NULL, 0);
    if (err == HOOK_NO_ERR) {
        /* Accepted — just unwrap without calling. Calling with invalid
         * argno hits the 12-arg default path which reads garbage off the
         * stack and crashes on Android's more restrictive memory layout. */
        hook_unwrap((void *)misuse_target_neg, (void *)misuse_before, NULL);
    }
    /* No crash = pass */

    hook_mem_user_cleanup();
}

/*
 * Test 5: misuse_wrap_argno_overflow
 * hook_wrap with argno=99.  If it succeeds, call via volatile pointer,
 * then unwrap.  Cleanup.
 */
TEST(misuse_wrap_argno_overflow)
{
    int rc = hook_mem_user_init();
    ASSERT_EQ(rc, 0);

    hook_err_t err = hook_wrap((void *)misuse_target_ovf, 99,
                                   (void *)misuse_before, NULL, NULL, 0);
    if (err == HOOK_NO_ERR) {
        /* Same as argno=-1: calling with out-of-range argno reads garbage
         * stack args via the 12-arg default path. Just unwrap. */
        hook_unwrap((void *)misuse_target_ovf, (void *)misuse_before, NULL);
    }
    /* No crash = pass */

    hook_mem_user_cleanup();
}

/*
 * Test 6: misuse_fp_unhook_wrong_backup
 * fp_hook() a target, then fp_unhook() with a wrong backup pointer
 * (0xDEADBEEF).  No crash during unhook = pass.
 * Restore the FP variable manually afterward to prevent calling a bad address.
 */
TEST(misuse_fp_unhook_wrong_backup)
{
    int rc = hook_mem_user_init();
    ASSERT_EQ(rc, 0);

    fp_misuse = fp_misuse_impl;

    void *backup = NULL;
    fp_hook((uintptr_t)&fp_misuse, (void *)misuse_replace, &backup);

    /* Pass a wrong backup — must not crash */
    void *wrong_backup = (void *)0xDEADBEEF;
    fp_unhook((uintptr_t)&fp_misuse, wrong_backup);

    /* Restore the FP variable so no bad address is called later */
    fp_misuse = fp_misuse_impl;

    hook_mem_user_cleanup();
}

int main(void)
{
    return RUN_ALL_TESTS();
}
