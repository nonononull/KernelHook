/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Consolidated unit tests for struct layout, bitmap operations,
 * and instruction generation changes (US-012).
 *
 * Verifies:
 *   - Struct sizes (hook_chain_item_t == 64, hook_local_t == 32)
 *   - Bitmap chain_add slot finding via __builtin_ctz
 *   - Bitmap chain_remove bit clearing
 *   - Bitmap chain_all_empty (mask == 0)
 *   - rebuild_sorted priority ordering with bitmap
 *   - BR-based trampoline (0xd61f0220 not 0xD65F0220)
 *   - BTI-only prologue detection
 *   - BTI+PAC combo prologue detection
 *   - SCS push instruction in prologue
 *   - PAC-stripped address identity
 */

#include "test_framework.h"
#include <hook.h>
#include <insn.h>
#include <stdint.h>
#include <string.h>

/* ==== Section 1: Struct layout tests ==== */

TEST(sizeof_hook_chain_item_t)
{
    ASSERT_EQ((int)sizeof(hook_chain_item_t), 64);
}

TEST(sizeof_hook_local_t)
{
    ASSERT_EQ((int)sizeof(hook_local_t), 32);
}

/* ==== Section 2: Bitmap chain operations ==== */

static void before_X(void) {}
static void before_Y(void) {}
static void before_Z(void) {}
static void after_X(void) {}
static void after_Y(void) {}
static void after_Z(void) {}

static hook_chain_rw_t rw;

static void bitmap_setup(void)
{
    memset(&rw, 0, sizeof(rw));
    rw.chain_items_max = HOOK_CHAIN_NUM;
    rw.sorted_count = 0;
}

TEST(bitmap_chain_add_finds_slot_via_ctz)
{
    bitmap_setup();

    /* First add should go to slot 0 (ctz(~0x0000) = 0) */
    hook_err_t rc = hook_chain_add(&rw, (void *)before_X, (void *)after_X, NULL, 10);
    ASSERT_EQ(rc, HOOK_NO_ERR);
    ASSERT_EQ(rw.occupied_mask & 1, 1);
    ASSERT_EQ(rw.items[0].before, (void *)before_X);

    /* Second add should go to slot 1 (ctz(~0x0001) = 1) */
    rc = hook_chain_add(&rw, (void *)before_Y, (void *)after_Y, NULL, 5);
    ASSERT_EQ(rc, HOOK_NO_ERR);
    ASSERT_EQ(rw.occupied_mask & 2, 2);
    ASSERT_EQ(rw.items[1].before, (void *)before_Y);

    /* Third add should go to slot 2 (ctz(~0x0003) = 2) */
    rc = hook_chain_add(&rw, (void *)before_Z, (void *)after_Z, NULL, 1);
    ASSERT_EQ(rc, HOOK_NO_ERR);
    ASSERT_EQ(rw.occupied_mask & 4, 4);
    ASSERT_EQ(rw.items[2].before, (void *)before_Z);

    /* Mask should have bits 0, 1, 2 set */
    ASSERT_EQ(rw.occupied_mask, (uint16_t)0x0007);
}

TEST(bitmap_chain_remove_clears_bit)
{
    bitmap_setup();

    hook_chain_add(&rw, (void *)before_X, (void *)after_X, NULL, 10);
    hook_chain_add(&rw, (void *)before_Y, (void *)after_Y, NULL, 5);
    hook_chain_add(&rw, (void *)before_Z, (void *)after_Z, NULL, 1);

    ASSERT_EQ(rw.occupied_mask, (uint16_t)0x0007);

    /* Remove middle item (slot 1) */
    hook_chain_remove(&rw, (void *)before_Y, (void *)after_Y);

    /* Bit 1 should be cleared: 0b101 = 0x0005 */
    ASSERT_EQ(rw.occupied_mask, (uint16_t)0x0005);
    ASSERT_EQ(rw.sorted_count, 2);

    /* Next add should reuse slot 1 (ctz(~0x0005) = 1) */
    hook_err_t rc = hook_chain_add(&rw, (void *)before_Y, (void *)after_Y, NULL, 20);
    ASSERT_EQ(rc, HOOK_NO_ERR);
    ASSERT_EQ(rw.occupied_mask, (uint16_t)0x0007);
    ASSERT_EQ(rw.items[1].priority, 20);
}

TEST(bitmap_chain_all_empty)
{
    bitmap_setup();

    /* Empty chain: mask == 0 */
    ASSERT_EQ(rw.occupied_mask, (uint16_t)0);

    /* Add one item */
    hook_chain_add(&rw, (void *)before_X, (void *)after_X, NULL, 0);
    ASSERT_NE(rw.occupied_mask, (uint16_t)0);

    /* Remove it */
    hook_chain_remove(&rw, (void *)before_X, (void *)after_X);
    ASSERT_EQ(rw.occupied_mask, (uint16_t)0);
}

TEST(bitmap_rebuild_sorted_priority_ordering)
{
    bitmap_setup();

    /* Add items with priorities: 1, 100, 50 in slots 0, 1, 2 */
    hook_chain_add(&rw, (void *)before_X, (void *)after_X, NULL, 1);
    hook_chain_add(&rw, (void *)before_Y, (void *)after_Y, NULL, 100);
    hook_chain_add(&rw, (void *)before_Z, (void *)after_Z, NULL, 50);

    ASSERT_EQ(rw.sorted_count, 3);

    /* Sorted order should be descending: 100, 50, 1 */
    ASSERT_EQ(rw.items[rw.sorted_indices[0]].priority, 100);
    ASSERT_EQ(rw.items[rw.sorted_indices[1]].priority, 50);
    ASSERT_EQ(rw.items[rw.sorted_indices[2]].priority, 1);

    /* Remove the highest priority item, verify re-sort */
    hook_chain_remove(&rw, (void *)before_Y, (void *)after_Y);
    ASSERT_EQ(rw.sorted_count, 2);
    ASSERT_EQ(rw.items[rw.sorted_indices[0]].priority, 50);
    ASSERT_EQ(rw.items[rw.sorted_indices[1]].priority, 1);
}

/* ==== Section 3: Instruction generation tests ==== */

static uint32_t origin_code[TRAMPOLINE_NUM] __attribute__((aligned(16)));

static void setup_hook(hook_t *h, uint32_t i0, uint32_t i1, uint32_t i2, uint32_t i3)
{
    memset(h, 0, sizeof(*h));
    origin_code[0] = i0;
    origin_code[1] = i1;
    origin_code[2] = i2;
    origin_code[3] = i3;
    h->func_addr    = (uint64_t)origin_code;
    h->origin_addr  = (uint64_t)origin_code;
    h->replace_addr = (uint64_t)origin_code;
    h->relo_addr    = (uint64_t)h->relo_insts;
}

TEST(br_trampoline_not_ret)
{
    hook_t h;
    /* Regular non-BTI/PAC prologue: 4-instruction trampoline */
    uint32_t mov_inst = 0xd2800000; /* MOV X0, #0 */
    setup_hook(&h, mov_inst, ARM64_NOP, ARM64_NOP, ARM64_NOP);

    hook_err_t rc = hook_prepare(&h);
    ASSERT_EQ(rc, HOOK_NO_ERR);
    ASSERT_EQ(h.tramp_insts_num, 4);

    /* tramp[0] = LDR X17, #8; tramp[1] = BR X17 (NOT RET X17) */
    ASSERT_EQ(h.tramp_insts[0], (uint32_t)0x58000051); /* LDR X17, #8 */
    ASSERT_EQ(h.tramp_insts[1], (uint32_t)0xd61f0220); /* BR X17 */
    ASSERT_NE(h.tramp_insts[1], (uint32_t)0xD65F0220); /* NOT RET X17 */

    /* Jump-back in relo also uses BR X17, not RET X17 */
    int jb_idx = h.relo_insts_num - 4; /* branch_absolute is last 4 instructions */
    ASSERT_EQ(h.relo_insts[jb_idx + 1], (uint32_t)0xd61f0220); /* BR X17 */
}

TEST(bti_only_prologue_detected)
{
    hook_t h;
    /* BTI C at offset 0, no PAC at offset 1 */
    setup_hook(&h, ARM64_BTI_C, ARM64_NOP, ARM64_NOP, ARM64_NOP);
    origin_code[4] = ARM64_NOP;

    hook_err_t rc = hook_prepare(&h);
    ASSERT_EQ(rc, HOOK_NO_ERR);

    /* 5-instruction trampoline with BTI_JC prefix */
    ASSERT_EQ(h.tramp_insts_num, 5);
    ASSERT_EQ(h.tramp_insts[0], ARM64_BTI_JC);
    ASSERT_EQ(h.tramp_insts[1], (uint32_t)0x58000051); /* LDR X17, #8 */
    ASSERT_EQ(h.tramp_insts[2], (uint32_t)0xd61f0220); /* BR X17 */

    /* BTI_C preserved in relocated code */
    ASSERT_EQ(h.relo_insts[2], ARM64_BTI_C);
}

TEST(bti_pac_combo_prologue_detected)
{
    hook_t h;
    /* BTI JC at offset 0, PACIASP at offset 1 */
    setup_hook(&h, ARM64_BTI_JC, ARM64_PACIASP, ARM64_NOP, ARM64_NOP);
    origin_code[4] = ARM64_NOP;

    hook_err_t rc = hook_prepare(&h);
    ASSERT_EQ(rc, HOOK_NO_ERR);

    /* 5-instruction trampoline with BTI_JC prefix */
    ASSERT_EQ(h.tramp_insts_num, 5);
    ASSERT_EQ(h.tramp_insts[0], ARM64_BTI_JC);

    /* Both BTI and PACIASP preserved in relocated code */
    ASSERT_EQ(h.relo_insts[2], ARM64_BTI_JC);
    ASSERT_EQ(h.relo_insts[4], ARM64_PACIASP);
}

TEST(scs_push_detected_in_prologue)
{
    hook_t h;
    /* SCS push at offset 0 — not BTI/PAC, so standard 4-inst trampoline */
    setup_hook(&h, ARM64_SCS_PUSH, ARM64_NOP, ARM64_NOP, ARM64_NOP);

    hook_err_t rc = hook_prepare(&h);
    ASSERT_EQ(rc, HOOK_NO_ERR);

    ASSERT_EQ(h.tramp_insts_num, 4);

    /* SCS push relocated as-is via relo_ignore */
    ASSERT_EQ(h.relo_insts[2], ARM64_SCS_PUSH);
    ASSERT_EQ(h.relo_insts[3], ARM64_NOP); /* relo_ignore padding */
}

/* ==== Section 4: PAC stripping ==== */

__attribute__((noinline))
static int pac_test_func(int a, int b)
{
    asm volatile("nop\n\tnop\n\tnop");
    return a + b;
}

TEST(pac_stripped_address_matches_raw)
{
    void *raw = (void *)pac_test_func;
    void *stripped = STRIP_PAC(raw);
    ASSERT_EQ((uintptr_t)stripped, (uintptr_t)raw);
}

TEST(pac_strip_null_is_null)
{
    void *stripped = STRIP_PAC(NULL);
    ASSERT_EQ((uintptr_t)stripped, (uintptr_t)0);
}

int main(void)
{
    return RUN_ALL_TESTS();
}
