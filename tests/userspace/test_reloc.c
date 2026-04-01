/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Unit tests for ARM64 instruction relocation engine.
 * Uses hand-crafted uint32_t instruction words, not compiled code.
 */

#include "test_framework.h"
#include <hook.h>
#include <insn.h>
#include <stdint.h>
#include <string.h>

/* ---- Helper: set up a hook_t with one test instruction at position 0, NOPs elsewhere ---- */

static uint32_t origin_code[TRAMPOLINE_NUM] __attribute__((aligned(16)));

static void setup_hook(hook_t *h, uint32_t test_inst)
{
    memset(h, 0, sizeof(*h));

    /* Place test instruction at position 0, NOPs at 1-3 */
    origin_code[0] = test_inst;
    origin_code[1] = ARM64_NOP;
    origin_code[2] = ARM64_NOP;
    origin_code[3] = ARM64_NOP;

    h->func_addr    = (uint64_t)origin_code;
    h->origin_addr  = (uint64_t)origin_code;
    h->replace_addr = (uint64_t)origin_code; /* just needs to be non-NULL */
    h->relo_addr    = (uint64_t)h->relo_insts;
}

/* Helper: set up with 4 specific instructions */
static void setup_hook_4(hook_t *h, uint32_t i0, uint32_t i1, uint32_t i2, uint32_t i3)
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

/*
 * After hook_prepare with branch_absolute trampoline (4 insts), relo_insts layout:
 *   [0]: BTI_JC (0xd50324df)
 *   [1]: NOP
 *   [2 .. 2+relo_len-1]: relocated instruction 0
 *   [2+relo_len .. ]: relocated instruction 1 (NOP -> relo_ignore = 2 insts)
 *   ... etc for instructions 2, 3
 *   [...]: branch_absolute jump back (4 insts)
 */

/* ---- Test: B (unconditional branch) relocation ---- */

TEST(relo_b_unconditional)
{
    hook_t h;
    /* B +0x100: INST_B | (0x100/4) = 0x14000000 | 0x40 */
    uint32_t inst = 0x14000040;
    setup_hook(&h, inst);

    hook_err_t rc = hook_prepare(&h);
    ASSERT_EQ(rc, HOOK_NO_ERR);

    /* Verify original instruction was backed up */
    ASSERT_EQ(h.origin_insts[0], inst);

    /* relo_insts[0] = BTI_JC, [1] = NOP */
    ASSERT_EQ(h.relo_insts[0], ARM64_BTI_JC);
    ASSERT_EQ(h.relo_insts[1], ARM64_NOP);

    /* B relocation produces 6 instructions starting at index 2:
     * [2]: LDR X17, #8
     * [3]: B #12
     * [4]: addr_lo
     * [5]: addr_hi
     * [6]: RET X17
     * [7]: NOP
     */
    uint64_t target = (uint64_t)origin_code + 0x100;
    ASSERT_EQ(h.relo_insts[2], (uint32_t)0x58000051); /* LDR X17, #8 */
    ASSERT_EQ(h.relo_insts[3], (uint32_t)0x14000003); /* B #12 */
    ASSERT_EQ(h.relo_insts[4], (uint32_t)(target & 0xFFFFFFFF));
    ASSERT_EQ(h.relo_insts[5], (uint32_t)(target >> 32));
    ASSERT_EQ(h.relo_insts[6], (uint32_t)0xD65F0220); /* RET X17 */
    ASSERT_EQ(h.relo_insts[7], ARM64_NOP);
}

/* ---- Test: BL (branch-and-link) relocation ---- */

TEST(relo_bl)
{
    hook_t h;
    /* BL +0x200: INST_BL | (0x200/4) = 0x94000000 | 0x80 */
    uint32_t inst = 0x94000080;
    setup_hook(&h, inst);

    hook_err_t rc = hook_prepare(&h);
    ASSERT_EQ(rc, HOOK_NO_ERR);

    ASSERT_EQ(h.origin_insts[0], inst);

    /* BL relocation produces 8 instructions at index 2:
     * [2]: LDR X17, #8
     * [3]: B #12
     * [4]: addr_lo
     * [5]: addr_hi
     * [6]: ADR X30, . (0x1000001E)
     * [7]: ADD X30, X30, #12 (0x910033DE)
     * [8]: RET X17
     * [9]: NOP
     */
    uint64_t target = (uint64_t)origin_code + 0x200;
    ASSERT_EQ(h.relo_insts[2], (uint32_t)0x58000051);
    ASSERT_EQ(h.relo_insts[3], (uint32_t)0x14000003);
    ASSERT_EQ(h.relo_insts[4], (uint32_t)(target & 0xFFFFFFFF));
    ASSERT_EQ(h.relo_insts[5], (uint32_t)(target >> 32));
    ASSERT_EQ(h.relo_insts[6], (uint32_t)0x1000001E); /* ADR X30, . */
    ASSERT_EQ(h.relo_insts[7], (uint32_t)0x910033DE); /* ADD X30, X30, #12 */
    ASSERT_EQ(h.relo_insts[8], (uint32_t)0xD65F0220); /* RET X17 */
    ASSERT_EQ(h.relo_insts[9], ARM64_NOP);
}

/* ---- Test: ADR relocation ---- */

TEST(relo_adr)
{
    hook_t h;
    /* ADR X0, +0x100:
     * imm = 0x100. immhi = imm >> 2 = 0x40. immlo = imm & 3 = 0.
     * inst = INST_ADR | (immhi << 5) | (immlo << 29) | Rd
     *      = 0x10000000 | (0x40 << 5) | 0 | 0
     *      = 0x10000800
     */
    uint32_t inst = 0x10000800;
    setup_hook(&h, inst);

    hook_err_t rc = hook_prepare(&h);
    ASSERT_EQ(rc, HOOK_NO_ERR);

    /* ADR relocation produces 4 instructions at index 2:
     * [2]: LDR X0, #8  (0x58000040 | Xd=0)
     * [3]: B #12 (0x14000003)
     * [4]: addr_lo
     * [5]: addr_hi
     */
    uint64_t target = (uint64_t)origin_code + 0x100;
    ASSERT_EQ(h.relo_insts[2], (uint32_t)0x58000040); /* LDR X0, #8 */
    ASSERT_EQ(h.relo_insts[3], (uint32_t)0x14000003); /* B #12 */
    ASSERT_EQ(h.relo_insts[4], (uint32_t)(target & 0xFFFFFFFF));
    ASSERT_EQ(h.relo_insts[5], (uint32_t)(target >> 32));
}

/* ---- Test: ADRP relocation ---- */

TEST(relo_adrp)
{
    hook_t h;
    /* ADRP X1, +0x2000 (2 pages forward):
     * imm = 0x2000 >> 12 = 2. immhi = 2 >> 2 = 0. immlo = 2 & 3 = 2.
     * inst = INST_ADRP | (immlo << 29) | (immhi << 5) | Rd
     *      = 0x90000000 | (2 << 29) | 0 | 1
     *      = 0xD0000001
     */
    uint32_t inst = 0xD0000001;
    setup_hook(&h, inst);

    hook_err_t rc = hook_prepare(&h);
    ASSERT_EQ(rc, HOOK_NO_ERR);

    /* ADRP relocation produces 4 instructions at index 2:
     * [2]: LDR X1, #8  (0x58000040 | Xd=1)
     * [3]: B #12
     * [4]: addr_lo
     * [5]: addr_hi
     */
    /* ADRP target = (inst_addr & ~0xFFF) + sign_extend(immhi:immlo, 21) << 12 */
    uint64_t inst_addr = (uint64_t)origin_code;
    uint64_t target = (inst_addr & 0xFFFFFFFFFFFFF000ULL) + 0x2000;
    ASSERT_EQ(h.relo_insts[2], (uint32_t)0x58000041); /* LDR X1, #8 */
    ASSERT_EQ(h.relo_insts[3], (uint32_t)0x14000003); /* B #12 */
    ASSERT_EQ(h.relo_insts[4], (uint32_t)(target & 0xFFFFFFFF));
    ASSERT_EQ(h.relo_insts[5], (uint32_t)(target >> 32));
}

/* ---- Test: LDR literal (64-bit GPR) relocation ---- */

TEST(relo_ldr_literal_64)
{
    hook_t h;
    /* LDR X2, +0x80:
     * imm19 = 0x80 / 4 = 0x20
     * inst = INST_LDR_64 | (imm19 << 5) | Rt
     *      = 0x58000000 | (0x20 << 5) | 2
     *      = 0x58000402
     */
    uint32_t inst = 0x58000402;
    setup_hook(&h, inst);

    hook_err_t rc = hook_prepare(&h);
    ASSERT_EQ(rc, HOOK_NO_ERR);

    /* LDR 64-bit relocation produces 6 instructions at index 2:
     * [2]: LDR X2, #16 (0x58000080 | Rt=2)
     * [3]: LDR X2, [X2] (0xF9400000 | Rt | (Rt << 5))
     * [4]: B #16 (0x14000004)
     * [5]: NOP
     * [6]: addr_lo
     * [7]: addr_hi
     */
    uint64_t target = (uint64_t)origin_code + 0x80;
    ASSERT_EQ(h.relo_insts[2], (uint32_t)0x58000082); /* LDR X2, #16 */
    ASSERT_EQ(h.relo_insts[3], (uint32_t)(0xF9400000 | 2 | (2 << 5))); /* LDR X2, [X2] */
    ASSERT_EQ(h.relo_insts[4], (uint32_t)0x14000004); /* B #16 */
    ASSERT_EQ(h.relo_insts[5], ARM64_NOP);
    ASSERT_EQ(h.relo_insts[6], (uint32_t)(target & 0xFFFFFFFF));
    ASSERT_EQ(h.relo_insts[7], (uint32_t)(target >> 32));
}

/* ---- Test: LDR literal (SIMD 128-bit) relocation ---- */

TEST(relo_ldr_literal_simd128)
{
    hook_t h;
    /* LDR Q5, +0x40:
     * imm19 = 0x40 / 4 = 0x10
     * inst = INST_LDR_SIMD_128 | (imm19 << 5) | Rt
     *      = 0x9C000000 | (0x10 << 5) | 5
     *      = 0x9C000205
     */
    uint32_t inst = 0x9C000205;
    setup_hook(&h, inst);

    hook_err_t rc = hook_prepare(&h);
    ASSERT_EQ(rc, HOOK_NO_ERR);

    /* SIMD LDR relocation produces 8 instructions at index 2:
     * [2]: STP X16, X17, [SP, -0x10]  (0xA93F47F0)
     * [3]: LDR X17, #20              (0x580000B1)
     * [4]: LDR Qt, [X17]             (0x3DC00220 | Rt)
     * [5]: LDR X17, [SP, -0x8]       (0xF85F83F1)
     * [6]: B #16                     (0x14000004)
     * [7]: NOP
     * [8]: addr_lo
     * [9]: addr_hi
     */
    uint64_t target = (uint64_t)origin_code + 0x40;
    ASSERT_EQ(h.relo_insts[2], (uint32_t)0xA93F47F0); /* STP X16, X17, [SP, -0x10] */
    ASSERT_EQ(h.relo_insts[3], (uint32_t)0x580000B1); /* LDR X17, #20 */
    ASSERT_EQ(h.relo_insts[4], (uint32_t)(0x3DC00220u | 5)); /* LDR Q5, [X17] */
    ASSERT_EQ(h.relo_insts[5], (uint32_t)0xF85F83F1); /* LDR X17, [SP, -0x8] */
    ASSERT_EQ(h.relo_insts[6], (uint32_t)0x14000004); /* B #16 */
    ASSERT_EQ(h.relo_insts[7], ARM64_NOP);
    ASSERT_EQ(h.relo_insts[8], (uint32_t)(target & 0xFFFFFFFF));
    ASSERT_EQ(h.relo_insts[9], (uint32_t)(target >> 32));
}

/* ---- Test: CBZ relocation ---- */

TEST(relo_cbz)
{
    hook_t h;
    /* CBZ X3, +0x40:
     * imm19 = 0x40 / 4 = 0x10
     * inst = INST_CBZ | (imm19 << 5) | Rt
     *      = 0x34000000 | (0x10 << 5) | 3
     *      = 0x34000203
     * Note: bit 31 = 0 for 32-bit (W register) variant. For 64-bit: 0xB4000203.
     * Using 32-bit variant here.
     */
    uint32_t inst = 0x34000203;
    setup_hook(&h, inst);

    hook_err_t rc = hook_prepare(&h);
    ASSERT_EQ(rc, HOOK_NO_ERR);

    /* CBZ relocation produces 6 instructions at index 2:
     * [2]: CBZ Rt, #8  => (inst & 0xFF00001F) | 0x40
     * [3]: B #20 (0x14000005)
     * [4]: LDR X17, #8 (0x58000051)
     * [5]: RET X17 (0xD65F0220)
     * [6]: addr_lo
     * [7]: addr_hi
     */
    uint64_t target = (uint64_t)origin_code + 0x40;
    uint32_t expected_cbz = (inst & 0xFF00001F) | 0x40;
    ASSERT_EQ(h.relo_insts[2], expected_cbz);
    ASSERT_EQ(h.relo_insts[3], (uint32_t)0x14000005); /* B #20 */
    ASSERT_EQ(h.relo_insts[4], (uint32_t)0x58000051); /* LDR X17, #8 */
    ASSERT_EQ(h.relo_insts[5], (uint32_t)0xD65F0220); /* RET X17 */
    ASSERT_EQ(h.relo_insts[6], (uint32_t)(target & 0xFFFFFFFF));
    ASSERT_EQ(h.relo_insts[7], (uint32_t)(target >> 32));
}

/* ---- Test: CBNZ relocation ---- */

TEST(relo_cbnz)
{
    hook_t h;
    /* CBNZ W5, +0x80:
     * imm19 = 0x80 / 4 = 0x20
     * inst = INST_CBNZ | (imm19 << 5) | Rt
     *      = 0x35000000 | (0x20 << 5) | 5
     *      = 0x35000405
     */
    uint32_t inst = 0x35000405;
    setup_hook(&h, inst);

    hook_err_t rc = hook_prepare(&h);
    ASSERT_EQ(rc, HOOK_NO_ERR);

    uint64_t target = (uint64_t)origin_code + 0x80;
    uint32_t expected_cbnz = (inst & 0xFF00001F) | 0x40;
    ASSERT_EQ(h.relo_insts[2], expected_cbnz);
    ASSERT_EQ(h.relo_insts[3], (uint32_t)0x14000005);
    ASSERT_EQ(h.relo_insts[4], (uint32_t)0x58000051);
    ASSERT_EQ(h.relo_insts[5], (uint32_t)0xD65F0220);
    ASSERT_EQ(h.relo_insts[6], (uint32_t)(target & 0xFFFFFFFF));
    ASSERT_EQ(h.relo_insts[7], (uint32_t)(target >> 32));
}

/* ---- Test: TBZ relocation ---- */

TEST(relo_tbz)
{
    hook_t h;
    /* TBZ X4, #3, +0x20:
     * bit_pos = 3 (b40=3, b5=0): bits 23:19 = bit_pos[4:0], bit 31 = bit_pos[5]
     * imm14 = 0x20 / 4 = 8
     * inst = INST_TBZ | (bit_pos << 19) | (imm14 << 5) | Rt
     *      = 0x36000000 | (3 << 19) | (8 << 5) | 4
     *      = 0x36000000 | 0x180000 | 0x100 | 4
     *      = 0x36180104
     */
    uint32_t inst = 0x36180104;
    setup_hook(&h, inst);

    hook_err_t rc = hook_prepare(&h);
    ASSERT_EQ(rc, HOOK_NO_ERR);

    /* TBZ relocation produces 6 instructions at index 2:
     * [2]: TBZ Rt, #bit, #8 => (inst & 0xFFF8001F) | 0x40
     * [3]: B #20 (0x14000005)
     * [4]: LDR X17, #8 (0x58000051)
     * [5]: BR X17 (0xd61f0220)
     * [6]: addr_lo
     * [7]: addr_hi
     */
    uint64_t target = (uint64_t)origin_code + 0x20;
    uint32_t expected_tbz = (inst & 0xFFF8001F) | 0x40;
    ASSERT_EQ(h.relo_insts[2], expected_tbz);
    ASSERT_EQ(h.relo_insts[3], (uint32_t)0x14000005);
    ASSERT_EQ(h.relo_insts[4], (uint32_t)0x58000051);
    ASSERT_EQ(h.relo_insts[5], (uint32_t)0xd61f0220); /* BR X17 */
    ASSERT_EQ(h.relo_insts[6], (uint32_t)(target & 0xFFFFFFFF));
    ASSERT_EQ(h.relo_insts[7], (uint32_t)(target >> 32));
}

/* ---- Test: TBNZ relocation ---- */

TEST(relo_tbnz)
{
    hook_t h;
    /* TBNZ W6, #7, +0x10:
     * imm14 = 0x10 / 4 = 4
     * inst = INST_TBNZ | (7 << 19) | (4 << 5) | 6
     *      = 0x37000000 | 0x380000 | 0x80 | 6
     *      = 0x37380086
     */
    uint32_t inst = 0x37380086;
    setup_hook(&h, inst);

    hook_err_t rc = hook_prepare(&h);
    ASSERT_EQ(rc, HOOK_NO_ERR);

    uint64_t target = (uint64_t)origin_code + 0x10;
    uint32_t expected_tbnz = (inst & 0xFFF8001F) | 0x40;
    ASSERT_EQ(h.relo_insts[2], expected_tbnz);
    ASSERT_EQ(h.relo_insts[3], (uint32_t)0x14000005);
    ASSERT_EQ(h.relo_insts[4], (uint32_t)0x58000051);
    ASSERT_EQ(h.relo_insts[5], (uint32_t)0xd61f0220);
    ASSERT_EQ(h.relo_insts[6], (uint32_t)(target & 0xFFFFFFFF));
    ASSERT_EQ(h.relo_insts[7], (uint32_t)(target >> 32));
}

/* ---- Test: NOP passes through unchanged (relo_ignore) ---- */

TEST(relo_nop_passthrough)
{
    hook_t h;
    setup_hook(&h, ARM64_NOP);

    hook_err_t rc = hook_prepare(&h);
    ASSERT_EQ(rc, HOOK_NO_ERR);

    /* relo_ignore produces: [inst, NOP]. For NOP input, both are NOP. */
    ASSERT_EQ(h.relo_insts[2], ARM64_NOP);
    ASSERT_EQ(h.relo_insts[3], ARM64_NOP);
}

/* ---- Test: hook_prepare with known 4-instruction sequence ---- */

TEST(relo_hook_prepare_4insts)
{
    hook_t h;

    /* Construct a realistic 4-instruction prologue:
     *   [0]: ADR X0, +0x100   (4 relo insts)
     *   [1]: NOP               (2 relo insts)
     *   [2]: NOP               (2 relo insts)
     *   [3]: NOP               (2 relo insts)
     *
     * Total relo: BTI+NOP(2) + ADR(4) + NOP(2) + NOP(2) + NOP(2) + branch_absolute(4) = 16
     */
    uint32_t adr_inst = 0x10000800; /* ADR X0, +0x100 */
    setup_hook_4(&h, adr_inst, ARM64_NOP, ARM64_NOP, ARM64_NOP);

    hook_err_t rc = hook_prepare(&h);
    ASSERT_EQ(rc, HOOK_NO_ERR);

    /* Verify trampoline was generated (branch_absolute = 4 instructions) */
    ASSERT_EQ(h.tramp_insts_num, 4);

    /* Verify all 4 original instructions were backed up */
    ASSERT_EQ(h.origin_insts[0], adr_inst);
    ASSERT_EQ(h.origin_insts[1], ARM64_NOP);
    ASSERT_EQ(h.origin_insts[2], ARM64_NOP);
    ASSERT_EQ(h.origin_insts[3], ARM64_NOP);

    /* Verify BTI header */
    ASSERT_EQ(h.relo_insts[0], ARM64_BTI_JC);
    ASSERT_EQ(h.relo_insts[1], ARM64_NOP);

    /* Verify ADR relocation at index 2 */
    uint64_t adr_target = (uint64_t)origin_code + 0x100;
    ASSERT_EQ(h.relo_insts[2], (uint32_t)0x58000040); /* LDR X0, #8 */
    ASSERT_EQ(h.relo_insts[3], (uint32_t)0x14000003); /* B #12 */
    ASSERT_EQ(h.relo_insts[4], (uint32_t)(adr_target & 0xFFFFFFFF));
    ASSERT_EQ(h.relo_insts[5], (uint32_t)(adr_target >> 32));

    /* NOP relocations at indices 6, 8, 10 */
    ASSERT_EQ(h.relo_insts[6], ARM64_NOP);
    ASSERT_EQ(h.relo_insts[7], ARM64_NOP);
    ASSERT_EQ(h.relo_insts[8], ARM64_NOP);
    ASSERT_EQ(h.relo_insts[9], ARM64_NOP);
    ASSERT_EQ(h.relo_insts[10], ARM64_NOP);
    ASSERT_EQ(h.relo_insts[11], ARM64_NOP);

    /* branch_absolute jump back at index 12:
     * back_dst = origin_addr + tramp_insts_num * 4 = origin_code + 16
     */
    uint64_t back_dst = (uint64_t)origin_code + h.tramp_insts_num * 4;
    ASSERT_EQ(h.relo_insts[12], (uint32_t)0x58000051); /* LDR X17, #8 */
    ASSERT_EQ(h.relo_insts[13], (uint32_t)0xd61f0220); /* BR X17 */
    ASSERT_EQ(h.relo_insts[14], (uint32_t)(back_dst & 0xFFFFFFFF));
    ASSERT_EQ(h.relo_insts[15], (uint32_t)(back_dst >> 32));

    /* Total relo_insts_num: 2 + 4 + 2 + 2 + 2 + 4 = 16 */
    ASSERT_EQ(h.relo_insts_num, 16);
}

/* ---- Test: PAC-only prologue detection ---- */

TEST(relo_pac_only_prologue)
{
    hook_t h;
    /* PACIASP at offset 0, NOPs for rest */
    setup_hook_4(&h, ARM64_PACIASP, ARM64_NOP, ARM64_NOP, ARM64_NOP);
    /* Set 5th instruction (TRAMPOLINE_NUM=5) */
    origin_code[4] = ARM64_NOP;

    hook_err_t rc = hook_prepare(&h);
    ASSERT_EQ(rc, HOOK_NO_ERR);

    /* 5-instruction trampoline: BTI_JC + branch_absolute */
    ASSERT_EQ(h.tramp_insts_num, 5);
    ASSERT_EQ(h.tramp_insts[0], ARM64_BTI_JC);
    ASSERT_EQ(h.tramp_insts[1], (uint32_t)0x58000051); /* LDR X17, #8 */
    ASSERT_EQ(h.tramp_insts[2], (uint32_t)0xd61f0220); /* BR X17 */

    /* PACIASP relocated as-is via relo_ignore */
    ASSERT_EQ(h.relo_insts[0], ARM64_BTI_JC); /* relo BTI header */
    ASSERT_EQ(h.relo_insts[2], ARM64_PACIASP); /* relocated PACIASP */
}

/* ---- Test: BTI-only prologue detection ---- */

TEST(relo_bti_only_prologue)
{
    hook_t h;
    /* BTI C at offset 0, no PAC at offset 1 */
    setup_hook_4(&h, ARM64_BTI_C, ARM64_NOP, ARM64_NOP, ARM64_NOP);
    origin_code[4] = ARM64_NOP;

    hook_err_t rc = hook_prepare(&h);
    ASSERT_EQ(rc, HOOK_NO_ERR);

    ASSERT_EQ(h.tramp_insts_num, 5);
    ASSERT_EQ(h.tramp_insts[0], ARM64_BTI_JC);
    ASSERT_EQ(h.tramp_insts[1], (uint32_t)0x58000051); /* LDR X17, #8 */
    ASSERT_EQ(h.tramp_insts[2], (uint32_t)0xd61f0220); /* BR X17 */

    /* BTI_C relocated as-is */
    ASSERT_EQ(h.relo_insts[2], ARM64_BTI_C);
}

/* ---- Test: BTI + PAC combo prologue detection ---- */

TEST(relo_bti_pac_combo_prologue)
{
    hook_t h;
    /* BTI JC at offset 0, PACIASP at offset 1 */
    setup_hook_4(&h, ARM64_BTI_JC, ARM64_PACIASP, ARM64_NOP, ARM64_NOP);
    origin_code[4] = ARM64_NOP;

    hook_err_t rc = hook_prepare(&h);
    ASSERT_EQ(rc, HOOK_NO_ERR);

    ASSERT_EQ(h.tramp_insts_num, 5);
    ASSERT_EQ(h.tramp_insts[0], ARM64_BTI_JC);

    /* Both BTI and PAC relocated */
    ASSERT_EQ(h.relo_insts[2], ARM64_BTI_JC);   /* relocated BTI */
    ASSERT_EQ(h.relo_insts[4], ARM64_PACIASP);  /* relocated PACIASP */
}

/* ---- Test: SCS push in prologue — relocated via relo_ignore ---- */

TEST(relo_scs_push_prologue)
{
    hook_t h;
    /* SCS push (str x30, [x18], #8) at offset 0, NOPs for rest.
     * SCS push is not BTI/PAC, so we get a standard 4-instruction trampoline.
     * The SCS instruction is relocated normally via relo_ignore. */
    setup_hook(&h, ARM64_SCS_PUSH);

    hook_err_t rc = hook_prepare(&h);
    ASSERT_EQ(rc, HOOK_NO_ERR);

    /* Standard 4-instruction trampoline (no BTI/PAC prefix) */
    ASSERT_EQ(h.tramp_insts_num, 4);
    ASSERT_EQ(h.tramp_insts[0], (uint32_t)0x58000051); /* LDR X17, #8 */

    /* SCS push relocated as-is via relo_ignore at relo_insts[2] */
    ASSERT_EQ(h.relo_insts[0], ARM64_BTI_JC); /* relo BTI header */
    ASSERT_EQ(h.relo_insts[2], ARM64_SCS_PUSH); /* relocated SCS push */
    ASSERT_EQ(h.relo_insts[3], ARM64_NOP);      /* relo_ignore padding */
}

/* ---- Test: BTI + PAC + SCS combo prologue — all relocated ---- */

TEST(relo_bti_pac_scs_prologue)
{
    hook_t h;
    /* BTI JC at offset 0, PACIASP at offset 1, SCS push at offset 2, NOP at 3.
     * BTI at offset 0 triggers 5-instruction trampoline. */
    setup_hook_4(&h, ARM64_BTI_JC, ARM64_PACIASP, ARM64_SCS_PUSH, ARM64_NOP);
    origin_code[4] = ARM64_NOP;

    hook_err_t rc = hook_prepare(&h);
    ASSERT_EQ(rc, HOOK_NO_ERR);

    ASSERT_EQ(h.tramp_insts_num, 5);
    ASSERT_EQ(h.tramp_insts[0], ARM64_BTI_JC);

    /* All three security instructions relocated as-is via relo_ignore */
    ASSERT_EQ(h.relo_insts[2], ARM64_BTI_JC);    /* relocated BTI */
    ASSERT_EQ(h.relo_insts[4], ARM64_PACIASP);   /* relocated PACIASP */
    ASSERT_EQ(h.relo_insts[6], ARM64_SCS_PUSH);  /* relocated SCS push */
}

/* ---- Test: No BTI/PAC prologue — unchanged 4-inst trampoline ---- */

TEST(relo_no_bti_pac_prologue)
{
    hook_t h;
    /* Regular MOV instruction, not BTI/PAC */
    uint32_t mov_inst = 0xd2800000; /* MOV X0, #0 */
    setup_hook(&h, mov_inst);

    hook_err_t rc = hook_prepare(&h);
    ASSERT_EQ(rc, HOOK_NO_ERR);

    ASSERT_EQ(h.tramp_insts_num, 4);
    /* No BTI_JC prefix in trampoline */
    ASSERT_EQ(h.tramp_insts[0], (uint32_t)0x58000051); /* LDR X17, #8 */
}

int main(void)
{
    return RUN_ALL_TESTS();
}
