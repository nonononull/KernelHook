/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Memory layout diagnostic: captures struct sizes and block counts.
 * Values are updated as optimizations land. */

#include "test_framework.h"
#include <hook.h>
#include <hmem.h>
#include <hook_mem_user.h>
#include <stddef.h>

#define BLOCK_SIZE 64
#define BLOCKS(sz) (((sz) + BLOCK_SIZE - 1) / BLOCK_SIZE)

TEST(mem_sizes_transit_buffer)
{
    /* transit[TRANSIT_INST_NUM] = 36 * 4 = 144 bytes */
    ASSERT_EQ(TRANSIT_INST_NUM, 36);
    ASSERT_EQ(sizeof(((hook_chain_rox_t *)0)->transit), (size_t)144);
}

TEST(mem_sizes_hook_chain_rox)
{
    /* hook_t(280) + rw ptr(8) + transit(144) = 432, aligned 64 → 448 → actual 432 */
    ASSERT_EQ(sizeof(hook_chain_rox_t), (size_t)432);
    ASSERT_EQ(BLOCKS(sizeof(hook_chain_rox_t)), (size_t)7);
}

TEST(mem_sizes_hook_chain_rw)
{
    /* metadata(56) + items[8](512) = 568 */
    ASSERT_EQ(sizeof(hook_chain_rw_t), (size_t)568);
    ASSERT_EQ(BLOCKS(sizeof(hook_chain_rw_t)), (size_t)9);
}

TEST(mem_sizes_fp_hook_chain_rox)
{
    ASSERT_EQ(sizeof(fp_hook_chain_rox_t), (size_t)176);
    ASSERT_EQ(BLOCKS(sizeof(fp_hook_chain_rox_t)), (size_t)3);
}

TEST(mem_sizes_fp_hook_chain_rw)
{
    /* metadata(88) + items[16](1024) = 1112 */
    ASSERT_EQ(sizeof(fp_hook_chain_rw_t), (size_t)1112);
    ASSERT_EQ(BLOCKS(sizeof(fp_hook_chain_rw_t)), (size_t)18);
}

TEST(mem_sizes_hook_chain_item)
{
    /* before(8) + after(8) + udata(8) + priority(4) + pad(4) + local(32) = 64 */
    ASSERT_EQ(sizeof(hook_chain_item_t), (size_t)64);
    ASSERT_EQ(sizeof(hook_local_t), (size_t)32);
}

TEST(mem_sizes_total_per_hook)
{
    size_t inline_rox = BLOCKS(sizeof(hook_chain_rox_t)) * BLOCK_SIZE;
    size_t inline_rw  = BLOCKS(sizeof(hook_chain_rw_t)) * BLOCK_SIZE;
    ASSERT_EQ(inline_rox + inline_rw, (size_t)1024);

    size_t fp_rox = BLOCKS(sizeof(fp_hook_chain_rox_t)) * BLOCK_SIZE;
    size_t fp_rw  = BLOCKS(sizeof(fp_hook_chain_rw_t)) * BLOCK_SIZE;
    ASSERT_EQ(fp_rox + fp_rw, (size_t)1344);
}

int main(void)
{
    return RUN_ALL_TESTS();
}
