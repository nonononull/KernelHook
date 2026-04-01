/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Unit tests for hook chain add/remove and priority sorting logic.
 * Operates directly on hook_chain_rw_t without installing hooks.
 */

#include "test_framework.h"
#include <hook.h>
#include <string.h>

/* ---- Helpers ---- */

/* Dummy callback functions (never called, just used as identity markers) */
static void before_A(void) {}
static void before_B(void) {}
static void before_C(void) {}
static void after_A(void) {}
static void after_B(void) {}
static void after_C(void) {}

static hook_chain_rw_t rw;

static void chain_setup(void)
{
    memset(&rw, 0, sizeof(rw));
    rw.chain_items_max = HOOK_CHAIN_NUM;
    rw.sorted_count = 0;
}

/* ---- Tests ---- */

TEST(chain_add_single)
{
    chain_setup();

    hook_err_t rc = hook_chain_add(&rw, (void *)before_A, (void *)after_A,
                                    NULL, 10);
    ASSERT_EQ(rc, HOOK_NO_ERR);
    ASSERT_EQ(rw.sorted_count, 1);
    ASSERT_EQ(rw.sorted_indices[0], 0);
    ASSERT_EQ(rw.occupied_mask & 1, 1);
    ASSERT_EQ(rw.items[0].priority, 10);
    ASSERT_EQ(rw.items[0].before, (void *)before_A);
    ASSERT_EQ(rw.items[0].after, (void *)after_A);
}

TEST(chain_priority_sorting)
{
    chain_setup();

    /* Add 3 callbacks with priorities 10, 0, 5 */
    hook_err_t rc;
    rc = hook_chain_add(&rw, (void *)before_A, (void *)after_A, NULL, 10);
    ASSERT_EQ(rc, HOOK_NO_ERR);
    rc = hook_chain_add(&rw, (void *)before_B, (void *)after_B, NULL, 0);
    ASSERT_EQ(rc, HOOK_NO_ERR);
    rc = hook_chain_add(&rw, (void *)before_C, (void *)after_C, NULL, 5);
    ASSERT_EQ(rc, HOOK_NO_ERR);

    ASSERT_EQ(rw.sorted_count, 3);

    /* Sorted order should be descending: 10, 5, 0 */
    int32_t idx0 = rw.sorted_indices[0];
    int32_t idx1 = rw.sorted_indices[1];
    int32_t idx2 = rw.sorted_indices[2];

    ASSERT_EQ(rw.items[idx0].priority, 10);
    ASSERT_EQ(rw.items[idx1].priority, 5);
    ASSERT_EQ(rw.items[idx2].priority, 0);
}

TEST(chain_remove_middle)
{
    chain_setup();

    hook_chain_add(&rw, (void *)before_A, (void *)after_A, NULL, 10);
    hook_chain_add(&rw, (void *)before_B, (void *)after_B, NULL, 5);
    hook_chain_add(&rw, (void *)before_C, (void *)after_C, NULL, 0);

    ASSERT_EQ(rw.sorted_count, 3);

    /* Remove middle-priority callback (priority 5) */
    hook_chain_remove(&rw, (void *)before_B, (void *)after_B);

    ASSERT_EQ(rw.sorted_count, 2);

    /* Remaining order: 10, 0 */
    int32_t idx0 = rw.sorted_indices[0];
    int32_t idx1 = rw.sorted_indices[1];
    ASSERT_EQ(rw.items[idx0].priority, 10);
    ASSERT_EQ(rw.items[idx1].priority, 0);
}

TEST(chain_overflow)
{
    chain_setup();

    /* Fill all HOOK_CHAIN_NUM (8) slots */
    for (int i = 0; i < HOOK_CHAIN_NUM; i++) {
        hook_err_t rc = hook_chain_add(&rw, (void *)(uintptr_t)(i + 1),
                                        (void *)(uintptr_t)(i + 100),
                                        NULL, i);
        ASSERT_EQ(rc, HOOK_NO_ERR);
    }

    ASSERT_EQ(rw.sorted_count, HOOK_CHAIN_NUM);

    /* Next add should fail with HOOK_CHAIN_FULL */
    hook_err_t rc = hook_chain_add(&rw, (void *)before_A, (void *)after_A,
                                    NULL, 99);
    ASSERT_EQ(rc, HOOK_CHAIN_FULL);
}

TEST(chain_add_remove_interleaved)
{
    chain_setup();

    /* Add A(10), B(5) */
    hook_chain_add(&rw, (void *)before_A, (void *)after_A, NULL, 10);
    hook_chain_add(&rw, (void *)before_B, (void *)after_B, NULL, 5);
    ASSERT_EQ(rw.sorted_count, 2);

    /* Remove A */
    hook_chain_remove(&rw, (void *)before_A, (void *)after_A);
    ASSERT_EQ(rw.sorted_count, 1);
    ASSERT_EQ(rw.items[rw.sorted_indices[0]].priority, 5);

    /* Add C(20) — should go into freed slot */
    hook_chain_add(&rw, (void *)before_C, (void *)after_C, NULL, 20);
    ASSERT_EQ(rw.sorted_count, 2);

    /* Order: 20, 5 */
    ASSERT_EQ(rw.items[rw.sorted_indices[0]].priority, 20);
    ASSERT_EQ(rw.items[rw.sorted_indices[1]].priority, 5);

    /* Remove both */
    hook_chain_remove(&rw, (void *)before_C, (void *)after_C);
    hook_chain_remove(&rw, (void *)before_B, (void *)after_B);
    ASSERT_EQ(rw.sorted_count, 0);
}

TEST(chain_remove_nonexistent)
{
    chain_setup();

    hook_chain_add(&rw, (void *)before_A, (void *)after_A, NULL, 10);
    ASSERT_EQ(rw.sorted_count, 1);

    /* Remove something that was never added — should be a no-op */
    hook_chain_remove(&rw, (void *)before_B, (void *)after_B);
    ASSERT_EQ(rw.sorted_count, 1);

    /* Original item still intact */
    ASSERT_EQ(rw.items[rw.sorted_indices[0]].before, (void *)before_A);
}

int main(void)
{
    return RUN_ALL_TESTS();
}
