/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Smoke test for the test framework itself.
 * Validates TEST(), ASSERT_*, SKIP_TEST, and RUN_ALL_TESTS macros.
 */
#include "test_framework.h"

TEST(assert_true_passes)
{
    ASSERT_TRUE(1 == 1);
}

TEST(assert_false_passes)
{
    ASSERT_FALSE(0);
}

TEST(assert_eq_passes)
{
    ASSERT_EQ(42, 42);
}

TEST(assert_ne_passes)
{
    ASSERT_NE(1, 2);
}

TEST(assert_null_passes)
{
    ASSERT_NULL(NULL);
}

TEST(assert_not_null_passes)
{
    int x = 0;
    ASSERT_NOT_NULL(&x);
}

TEST(skip_test_example)
{
#ifdef FORCE_SKIP
    SKIP_TEST("demonstrating skip");
#endif
    ASSERT_TRUE(1);
}

int main(void)
{
    return RUN_ALL_TESTS();
}
