/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Minimal test framework for KernelHook userspace tests.
 * No external dependencies. Auto-registers tests via __attribute__((constructor)).
 */
#ifndef TEST_FRAMEWORK_H
#define TEST_FRAMEWORK_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <setjmp.h>

/* --- Color output --- */
#define TF_RED     "\033[31m"
#define TF_GREEN   "\033[32m"
#define TF_YELLOW  "\033[33m"
#define TF_RESET   "\033[0m"

/* --- Internal state --- */
#define TF_MAX_TESTS 256

typedef void (*tf_test_fn)(void);

typedef struct {
    const char *name;
    tf_test_fn  fn;
} tf_test_entry;

static tf_test_entry tf_tests[TF_MAX_TESTS];
static int tf_test_count = 0;

static jmp_buf tf_jmp;
static int tf_current_failed;
static int tf_current_skipped;
static const char *tf_skip_reason;

static inline void tf_register(const char *name, tf_test_fn fn)
{
    if (tf_test_count < TF_MAX_TESTS) {
        tf_tests[tf_test_count].name = name;
        tf_tests[tf_test_count].fn = fn;
        tf_test_count++;
    }
}

/* --- TEST macro --- */
#define TF_CONCAT_(a, b) a##b
#define TF_CONCAT(a, b)  TF_CONCAT_(a, b)

#define TEST(name)                                                      \
    static void test_##name(void);                                      \
    __attribute__((constructor))                                        \
    static void TF_CONCAT(tf_register_, name)(void)                    \
    {                                                                   \
        tf_register(#name, test_##name);                                \
    }                                                                   \
    static void test_##name(void)

/* --- SKIP_TEST --- */
#define SKIP_TEST(reason) do {                                          \
        tf_current_skipped = 1;                                         \
        tf_skip_reason = (reason);                                      \
        longjmp(tf_jmp, 2);                                             \
    } while (0)

/* --- Assertion helpers --- */
#define TF_FAIL(fmt, ...) do {                                          \
        fprintf(stderr, "  " TF_RED "FAIL" TF_RESET " %s:%d: " fmt "\n", \
                __FILE__, __LINE__, ##__VA_ARGS__);                     \
        tf_current_failed = 1;                                          \
        longjmp(tf_jmp, 1);                                             \
    } while (0)

#define ASSERT_TRUE(cond) do {                                          \
        if (!(cond))                                                    \
            TF_FAIL("ASSERT_TRUE(%s)", #cond);                         \
    } while (0)

#define ASSERT_FALSE(cond) do {                                         \
        if ((cond))                                                     \
            TF_FAIL("ASSERT_FALSE(%s)", #cond);                        \
    } while (0)

#define ASSERT_EQ(a, b) do {                                            \
        __typeof__(a) _a = (a);                                         \
        __typeof__(b) _b = (b);                                         \
        if (_a != _b)                                                   \
            TF_FAIL("ASSERT_EQ(%s, %s): %lld != %lld",                \
                    #a, #b, (long long)_a, (long long)_b);             \
    } while (0)

#define ASSERT_NE(a, b) do {                                            \
        __typeof__(a) _a = (a);                                         \
        __typeof__(b) _b = (b);                                         \
        if (_a == _b)                                                   \
            TF_FAIL("ASSERT_NE(%s, %s): both == %lld",                \
                    #a, #b, (long long)_a);                            \
    } while (0)

#define ASSERT_NULL(ptr) do {                                           \
        if ((ptr) != NULL)                                              \
            TF_FAIL("ASSERT_NULL(%s): got %p", #ptr, (void *)(ptr));   \
    } while (0)

#define ASSERT_NOT_NULL(ptr) do {                                       \
        if ((ptr) == NULL)                                              \
            TF_FAIL("ASSERT_NOT_NULL(%s): got NULL", #ptr);            \
    } while (0)

/* --- Test runner --- */
#define RUN_ALL_TESTS() tf_run_all_tests()

static inline int tf_run_all_tests(void)
{
    int passed = 0, failed = 0, skipped = 0;

    printf("Running %d test(s)...\n", tf_test_count);

    for (int i = 0; i < tf_test_count; i++) {
        tf_current_failed = 0;
        tf_current_skipped = 0;
        tf_skip_reason = NULL;

        int jval = setjmp(tf_jmp);
        if (jval == 0) {
            tf_tests[i].fn();
        }
        /* jval == 1: assertion failed (tf_current_failed already set) */
        /* jval == 2: test skipped (tf_current_skipped already set) */

        if (tf_current_skipped) {
            printf("  " TF_YELLOW "SKIP" TF_RESET " %s: %s\n",
                   tf_tests[i].name, tf_skip_reason ? tf_skip_reason : "");
            skipped++;
        } else if (tf_current_failed) {
            printf("  " TF_RED "FAIL" TF_RESET " %s\n", tf_tests[i].name);
            failed++;
        } else {
            printf("  " TF_GREEN "PASS" TF_RESET " %s\n", tf_tests[i].name);
            passed++;
        }
    }

    printf("\n%d passed, %d failed, %d skipped\n", passed, failed, skipped);

    return failed > 0 ? 1 : 0;
}

#endif /* TEST_FRAMEWORK_H */
