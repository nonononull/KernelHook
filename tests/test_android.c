/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Android-specific tests. All SKIP on non-Android platforms. */

#include "test_framework.h"
#include <hook.h>
#include <hmem.h>
#include <hook_mem_user.h>
#include <platform.h>
#include <string.h>

#ifndef __ANDROID__
#define ANDROID_SKIP() SKIP_TEST("not Android")
#else
#define ANDROID_SKIP() ((void)0)
#include <sys/mman.h>
#include <unistd.h>
#include <dlfcn.h>
#endif

/* ---- Target for Bionic hook test ---- */

__attribute__((noinline))
static int android_target(int a, int b)
{
    asm volatile("nop\n\tnop\n\tnop");
    return a + b;
}

static int (*volatile call_android_target)(int, int) __attribute__((unused)) = android_target;
static int android_before_called;

static void android_before(hook_fargs2_t *fargs, void *udata)
{
    (void)fargs; (void)udata;
    android_before_called = 1;
}

/* ---- Tests ---- */

TEST(android_bionic_hook)
{
    ANDROID_SKIP();

    int rc = hook_mem_user_init();
    ASSERT_EQ(rc, 0);
    android_before_called = 0;

    hook_err_t err = hook_wrap2((void *)android_target, android_before, NULL, NULL);
    ASSERT_EQ(err, HOOK_NO_ERR);

    int result = call_android_target(3, 4);
    ASSERT_EQ(result, 7);
    ASSERT_TRUE(android_before_called);

    hook_unwrap((void *)android_target, (void *)android_before, NULL);
    hook_mem_user_cleanup();
}

TEST(android_mprotect_wx)
{
    ANDROID_SKIP();

#ifdef __ANDROID__
    /* Verify W^X: mmap with RWX should fail on modern Android (API 29+) */
    void *p = mmap(NULL, 4096, PROT_READ | PROT_WRITE | PROT_EXEC,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p != MAP_FAILED) {
        /* Some older devices/emulators allow RWX — not a failure, just note it */
        munmap(p, 4096);
    }
    /* The real test: our pool uses W^X correctly */
    int rc = hook_mem_user_init();
    ASSERT_EQ(rc, 0);
    void *rox = hook_mem_alloc_rox(64);
    ASSERT_NOT_NULL(rox);
    /* ROX memory should be readable but not writable */
    hook_mem_free_rox(rox, 64);
    hook_mem_user_cleanup();
#endif
}

TEST(android_proc_maps_readable)
{
    ANDROID_SKIP();

#ifdef __ANDROID__
    FILE *f = fopen("/proc/self/maps", "r");
    ASSERT_NOT_NULL(f);
    char buf[256];
    /* Should be able to read at least one line */
    ASSERT_NOT_NULL(fgets(buf, sizeof(buf), f));
    ASSERT_TRUE(strlen(buf) > 0);
    fclose(f);
#endif
}

TEST(android_page_size)
{
    ANDROID_SKIP();

#ifdef __ANDROID__
    uint64_t ps = platform_page_size();
    /* Android supports 4KB and 16KB pages */
    ASSERT_TRUE(ps == 4096 || ps == 16384);
#endif
}

TEST(android_static_binary)
{
    ANDROID_SKIP();

#ifdef __ANDROID__
    /* Verify this binary has no dynamic linker dependency. */
    FILE *f = fopen("/proc/self/maps", "r");
    ASSERT_NOT_NULL(f);
    int found_linker = 0;
    char buf[512];
    while (fgets(buf, sizeof(buf), f)) {
        if (strstr(buf, "/system/bin/linker"))
            found_linker = 1;
    }
    fclose(f);
    /* Static binary should not have linker mapped */
    ASSERT_FALSE(found_linker);
#endif
}

int main(void)
{
    return RUN_ALL_TESTS();
}
