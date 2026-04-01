/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Verify library code is page-isolated from test (user) code.
 *
 * These tests confirm that the linker script (GNU ld) or order file (macOS)
 * successfully places library .text in its own page-aligned region, so
 * platform_write_code() never removes execute permission from its own page.
 */

#include "test_framework.h"
#include <hook.h>
#include <hmem.h>
#include <hook_mem_user.h>
#include <platform.h>

/* External symbols from kh_section_fence.c */
extern void __kh_text_fence_head(void);
extern void __kh_text_fence_tail(void);

/* External symbol from the library — representative of library .text */
extern int platform_write_code(uint64_t addr, const void *data, uint64_t size);

/* A local target function — representative of user .text.
 * On Android, aligned(4096) + visibility("hidden") ensures it lands on
 * its own page, preventing same-page mprotect issues with library code. */
#ifdef __ANDROID__
__attribute__((noinline, visibility("hidden"), aligned(4096)))
#else
__attribute__((noinline))
#endif
int local_target(int a, int b)
{
    asm volatile("nop\n\tnop\n\tnop");
    return a + b;
}

static int (*volatile call_local)(int, int) = local_target;

/* Helper: check if two addresses are on the same page */
static int same_page(uint64_t a, uint64_t b)
{
    uint64_t ps = platform_page_size();
    return (a & ~(ps - 1)) == (b & ~(ps - 1));
}

TEST(page_isolation_fence_head_aligned)
{
    uint64_t addr = (uint64_t)__kh_text_fence_head;
    uint64_t ps = platform_page_size();
    ASSERT_EQ(addr % ps, 0);
}

TEST(page_isolation_fence_tail_aligned)
{
    uint64_t addr = (uint64_t)__kh_text_fence_tail;
    uint64_t ps = platform_page_size();
    ASSERT_EQ(addr % ps, 0);
}

TEST(page_isolation_library_not_on_user_page)
{
    uint64_t lib_addr = (uint64_t)platform_write_code;
    uint64_t user_addr = (uint64_t)local_target;
    ASSERT_FALSE(same_page(lib_addr, user_addr));
}

TEST(page_isolation_fence_head_not_on_user_page)
{
    uint64_t fence_addr = (uint64_t)__kh_text_fence_head;
    uint64_t user_addr = (uint64_t)local_target;
    ASSERT_FALSE(same_page(fence_addr, user_addr));
}

/* ---- Callback for hook_wrap ---- */
static int hook_before_called;

static void isolation_before(hook_fargs2_t *fargs, void *udata)
{
    (void)fargs;
    (void)udata;
    hook_before_called = 1;
}

TEST(page_isolation_functional_after_hook)
{
    /* Verify that hooking a local target works without SIGSEGV.
     * This is the actual scenario that used to crash on Android. */
    int rc = hook_mem_user_init();
    ASSERT_EQ(rc, 0);
    hook_before_called = 0;

    /* Baseline */
    ASSERT_EQ(call_local(3, 7), 10);

    /* Hook — this calls platform_write_code on local_target's page.
     * If isolation failed, this would SIGSEGV. */
    hook_err_t ret = hook_wrap(
        (void *)local_target, 2,
        (void *)isolation_before, NULL, NULL, 0);
    ASSERT_EQ(ret, HOOK_NO_ERR);

    /* Call through hook */
    ASSERT_EQ(call_local(3, 7), 10);
    ASSERT_TRUE(hook_before_called);

    /* Unwrap */
    hook_unwrap((void *)local_target,
                (void *)isolation_before, NULL);
    ASSERT_EQ(call_local(3, 7), 10);

    hook_mem_user_cleanup();
}

int main(void)
{
    return RUN_ALL_TESTS();
}
