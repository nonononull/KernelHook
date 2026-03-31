/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2026 bmax121.
 * ARM64 instruction relocation engine
 */

#include <hook.h>
#include <insn.h>
#include <pgtable.h>
#include <export.h>
#include <log.h>

typedef uint32_t inst_type_t;
typedef uint32_t inst_mask_t;

static inst_mask_t masks[] = {
    MASK_B,      MASK_BC,        MASK_BL,       MASK_ADR,         MASK_ADRP,        MASK_LDR_32,
    MASK_LDR_64, MASK_LDRSW_LIT, MASK_PRFM_LIT, MASK_LDR_SIMD_32, MASK_LDR_SIMD_64, MASK_LDR_SIMD_128,
    MASK_CBZ,    MASK_CBNZ,      MASK_TBZ,      MASK_TBNZ,        MASK_IGNORE,
};

static inst_type_t types[] = {
    INST_B,      INST_BC,        INST_BL,       INST_ADR,         INST_ADRP,        INST_LDR_32,
    INST_LDR_64, INST_LDRSW_LIT, INST_PRFM_LIT, INST_LDR_SIMD_32, INST_LDR_SIMD_64, INST_LDR_SIMD_128,
    INST_CBZ,    INST_CBNZ,      INST_TBZ,      INST_TBNZ,        INST_IGNORE,
};

/* Relocated instruction lengths (in uint32_t units) per instruction type */
static int32_t relo_len[] = { 6, 8, 8, 4, 4, 6, 6, 6, 8, 8, 8, 8, 6, 6, 6, 6, 2 };

#define RELO_TYPE_COUNT (sizeof(relo_len) / sizeof(relo_len[0]))

static int is_in_tramp(hook_t *hook, uint64_t addr)
{
    uint64_t tramp_start = hook->origin_addr;
    uint64_t tramp_end = tramp_start + hook->tramp_insts_num * 4;
    if (addr >= tramp_start && addr < tramp_end) {
        return 1;
    }
    return 0;
}

static uint64_t relo_in_tramp(hook_t *hook, uint64_t addr)
{
    if (!is_in_tramp(hook, addr)) return addr;
    uint64_t tramp_start = hook->origin_addr;
    uint32_t addr_inst_index = (addr - tramp_start) / 4;
    uint64_t fix_addr = hook->relo_addr;
    for (uint32_t i = 0; i < addr_inst_index; i++) {
        inst_type_t inst = hook->origin_insts[i];
        for (uint32_t j = 0; j < RELO_TYPE_COUNT; j++) {
            if ((inst & masks[j]) == types[j]) {
                fix_addr += relo_len[j] * 4;
                break;
            }
        }
    }
    return fix_addr;
}

static __noinline hook_err_t relo_b(hook_t *hook, uint64_t inst_addr, uint32_t inst, inst_type_t type)
{
    uint32_t *buf = hook->relo_insts + hook->relo_insts_num;
    uint64_t imm64;
    if (type == INST_BC) {
        uint64_t imm19 = bits32(inst, 23, 5);
        imm64 = sign64_extend(imm19 << 2u, 21u);
    } else {
        uint64_t imm26 = bits32(inst, 25, 0);
        imm64 = sign64_extend(imm26 << 2u, 28u);
    }
    uint64_t addr = inst_addr + imm64;
    addr = relo_in_tramp(hook, addr);

    uint32_t idx = 0;
    if (type == INST_BC) {
        buf[idx++] = (inst & 0xFF00001F) | 0x40u; /* B.<cond> #8 */
        buf[idx++] = 0x14000006; /* B #24 */
    }
    buf[idx++] = 0x58000051; /* LDR X17, #8 */
    buf[idx++] = 0x14000003; /* B #12 */
    buf[idx++] = addr & 0xFFFFFFFF;
    buf[idx++] = addr >> 32u;
    if (type == INST_BL) {
        buf[idx++] = 0x1000001E; /* ADR X30, . */
        buf[idx++] = 0x910033DE; /* ADD X30, X30, #12 */
        buf[idx++] = 0xD65F0220; /* RET X17 */
    } else {
        buf[idx++] = 0xD65F0220; /* RET X17 */
    }
    buf[idx++] = ARM64_NOP;
    return HOOK_NO_ERR;
}

static __noinline hook_err_t relo_adr(hook_t *hook, uint64_t inst_addr, uint32_t inst, inst_type_t type)
{
    uint32_t *buf = hook->relo_insts + hook->relo_insts_num;

    uint32_t xd = bits32(inst, 4, 0);
    uint64_t immlo = bits32(inst, 30, 29);
    uint64_t immhi = bits32(inst, 23, 5);
    uint64_t addr;

    if (type == INST_ADR) {
        addr = inst_addr + sign64_extend((immhi << 2u) | immlo, 21u);
    } else {
        addr = (inst_addr + sign64_extend((immhi << 14u) | (immlo << 12u), 33u)) & 0xFFFFFFFFFFFFF000;
        if (is_in_tramp(hook, addr)) return HOOK_BAD_RELO;
    }
    buf[0] = 0x58000040u | xd; /* LDR Xd, #8 */
    buf[1] = 0x14000003; /* B #12 */
    buf[2] = addr & 0xFFFFFFFF;
    buf[3] = addr >> 32u;
    return HOOK_NO_ERR;
}

static __noinline hook_err_t relo_ldr(hook_t *hook, uint64_t inst_addr, uint32_t inst, inst_type_t type)
{
    uint32_t *buf = hook->relo_insts + hook->relo_insts_num;

    uint32_t rt = bits32(inst, 4, 0);
    uint64_t imm19 = bits32(inst, 23, 5);
    uint64_t offset = sign64_extend((imm19 << 2u), 21u);
    uint64_t addr = inst_addr + offset;

    if (is_in_tramp(hook, addr) && type != INST_PRFM_LIT) return HOOK_BAD_RELO;

    addr = relo_in_tramp(hook, addr);

    if (type == INST_LDR_32 || type == INST_LDR_64 || type == INST_LDRSW_LIT) {
        buf[0] = 0x58000080u | rt; /* LDR Xt, #16 */
        if (type == INST_LDR_32) {
            buf[1] = 0xB9400000 | rt | (rt << 5u); /* LDR Wt, [Xt] */
        } else if (type == INST_LDR_64) {
            buf[1] = 0xF9400000 | rt | (rt << 5u); /* LDR Xt, [Xt] */
        } else {
            buf[1] = 0xB9800000 | rt | (rt << 5u); /* LDRSW Xt, [Xt] */
        }
        buf[2] = 0x14000004; /* B #16 (skip NOP + addr data) */
        buf[3] = ARM64_NOP;
        buf[4] = addr & 0xFFFFFFFF;
        buf[5] = addr >> 32u;
    } else {
        buf[0] = 0xA93F47F0; /* STP X16, X17, [SP, -0x10] */
        buf[1] = 0x580000B1; /* LDR X17, #20 */
        if (type == INST_PRFM_LIT) {
            buf[2] = 0xF9800220 | rt; /* PRFM Rt, [X17] */
        } else if (type == INST_LDR_SIMD_32) {
            buf[2] = 0xBD400220 | rt; /* LDR St, [X17] */
        } else if (type == INST_LDR_SIMD_64) {
            buf[2] = 0xFD400220 | rt; /* LDR Dt, [X17] */
        } else {
            buf[2] = 0x3DC00220u | rt; /* LDR Qt, [X17] */
        }
        buf[3] = 0xF85F83F1; /* LDR X17, [SP, -0x8] */
        buf[4] = 0x14000004; /* B #16 (skip NOP + addr data) */
        buf[5] = ARM64_NOP;
        buf[6] = addr & 0xFFFFFFFF;
        buf[7] = addr >> 32u;
    }
    return HOOK_NO_ERR;
}

static __noinline hook_err_t relo_cb(hook_t *hook, uint64_t inst_addr, uint32_t inst, inst_type_t type)
{
    uint32_t *buf = hook->relo_insts + hook->relo_insts_num;
    (void)type;

    uint64_t imm19 = bits32(inst, 23, 5);
    uint64_t offset = sign64_extend((imm19 << 2u), 21u);
    uint64_t addr = inst_addr + offset;
    addr = relo_in_tramp(hook, addr);

    buf[0] = (inst & 0xFF00001F) | 0x40u; /* CB(N)Z Rt, #8 */
    buf[1] = 0x14000005; /* B #20 */
    buf[2] = 0x58000051; /* LDR X17, #8 */
    buf[3] = 0xD65F0220; /* RET X17 */
    buf[4] = addr & 0xFFFFFFFF;
    buf[5] = addr >> 32u;
    return HOOK_NO_ERR;
}

static __noinline hook_err_t relo_tb(hook_t *hook, uint64_t inst_addr, uint32_t inst, inst_type_t type)
{
    uint32_t *buf = hook->relo_insts + hook->relo_insts_num;
    (void)type;

    uint64_t imm14 = bits32(inst, 18, 5);
    uint64_t offset = sign64_extend((imm14 << 2u), 16u);
    uint64_t addr = inst_addr + offset;
    addr = relo_in_tramp(hook, addr);

    buf[0] = (inst & 0xFFF8001F) | 0x40u; /* TB(N)Z Rt, #<imm>, #8 */
    buf[1] = 0x14000005; /* B #20 */
    buf[2] = 0x58000051; /* LDR X17, #8 */
    buf[3] = 0xd61f0220; /* BR X17 */
    buf[4] = addr & 0xFFFFFFFF;
    buf[5] = addr >> 32u;
    return HOOK_NO_ERR;
}

static __noinline hook_err_t relo_ignore(hook_t *hook, uint64_t inst_addr, uint32_t inst, inst_type_t type)
{
    uint32_t *buf = hook->relo_insts + hook->relo_insts_num;
    (void)inst_addr;
    (void)type;
    buf[0] = inst;
    buf[1] = ARM64_NOP;
    return HOOK_NO_ERR;
}

static __noinline hook_err_t relocate_inst(hook_t *hook, uint64_t inst_addr, uint32_t inst)
{
    hook_err_t rc = HOOK_NO_ERR;
    inst_type_t it = INST_IGNORE;
    int len = 1;

    for (uint32_t j = 0; j < RELO_TYPE_COUNT; j++) {
        if ((inst & masks[j]) == types[j]) {
            it = types[j];
            len = relo_len[j];
            break;
        }
    }

    switch (it) {
    case INST_B:
    case INST_BC:
    case INST_BL:
        rc = relo_b(hook, inst_addr, inst, it);
        break;
    case INST_ADR:
    case INST_ADRP:
        rc = relo_adr(hook, inst_addr, inst, it);
        break;
    case INST_LDR_32:
    case INST_LDR_64:
    case INST_LDRSW_LIT:
    case INST_PRFM_LIT:
    case INST_LDR_SIMD_32:
    case INST_LDR_SIMD_64:
    case INST_LDR_SIMD_128:
        rc = relo_ldr(hook, inst_addr, inst, it);
        break;
    case INST_CBZ:
    case INST_CBNZ:
        rc = relo_cb(hook, inst_addr, inst, it);
        break;
    case INST_TBZ:
    case INST_TBNZ:
        rc = relo_tb(hook, inst_addr, inst, it);
        break;
    case INST_IGNORE:
    default:
        rc = relo_ignore(hook, inst_addr, inst, it);
        break;
    }

    if (hook->relo_insts_num + len > RELOCATE_INST_NUM)
        return HOOK_BAD_RELO;

    hook->relo_insts_num += len;

    return rc;
}

hook_err_t hook_prepare(hook_t *hook)
{
    if (is_bad_address((void *)hook->func_addr)) return HOOK_BAD_ADDRESS;
    if (is_bad_address((void *)hook->origin_addr)) return HOOK_BAD_ADDRESS;
    if (is_bad_address((void *)hook->replace_addr)) return HOOK_BAD_ADDRESS;
    if (is_bad_address((void *)hook->relo_addr)) return HOOK_BAD_ADDRESS;

    for (int i = 0; i < TRAMPOLINE_NUM; i++) {
        hook->origin_insts[i] = *((uint32_t *)hook->origin_addr + i);
    }

    uint32_t first = hook->origin_insts[0];
    int is_bti = (first == ARM64_BTI_C || first == ARM64_BTI_J || first == ARM64_BTI_JC);
    int is_pac = (first == ARM64_PACIASP || first == ARM64_PACIBSP);

    if (is_bti || is_pac) {
        /* BTI-only, PAC-only, or BTI+PAC combo: 5-instruction trampoline
         * tramp[0] = BTI_JC (preserves landing pad at hooked function entry)
         * tramp[1..4] = branch_absolute to replace_addr */
        hook->tramp_insts[0] = ARM64_BTI_JC;
        hook->tramp_insts_num = 1 + branch_from_to(&hook->tramp_insts[1],
                                                     hook->origin_addr, hook->replace_addr);
    } else {
        /* Non-BTI/non-PAC: standard 4-instruction trampoline */
        hook->tramp_insts_num = branch_from_to(hook->tramp_insts,
                                                hook->origin_addr, hook->replace_addr);
    }

    for (uint32_t i = 0; i < sizeof(hook->relo_insts) / sizeof(hook->relo_insts[0]); i++) {
        hook->relo_insts[i] = ARM64_NOP;
    }

    uint32_t *bti = hook->relo_insts + hook->relo_insts_num;
    bti[0] = ARM64_BTI_JC;
    bti[1] = ARM64_NOP;
    hook->relo_insts_num += 2;

    for (int i = 0; i < hook->tramp_insts_num; i++) {
        uint64_t inst_addr = hook->origin_addr + i * 4;
        uint32_t inst = hook->origin_insts[i];
        hook_err_t relo_res = relocate_inst(hook, inst_addr, inst);
        if (relo_res) {
            return HOOK_BAD_RELO;
        }
    }

    uint64_t back_src_addr = hook->relo_addr + hook->relo_insts_num * 4;
    uint64_t back_dst_addr = hook->origin_addr + hook->tramp_insts_num * 4;
    uint32_t *buf = hook->relo_insts + hook->relo_insts_num;
    hook->relo_insts_num += branch_from_to(buf, back_src_addr, back_dst_addr);

#ifndef __USERSPACE__
    /* Copy the original function's kCFI type hash to the relocated code
     * prefix. kCFI checks *(target - 4) before every BLR; placing the
     * hash at _relo_cfi_hash (immediately before relo_insts[0]) allows
     * the backup pointer returned by hook() to pass CFI validation.
     * On non-kCFI kernels this is harmless — just 4 bytes of data.
     * In userspace there is no kCFI, and origin_addr may not have
     * readable memory at -4, so skip. */
    hook->_relo_cfi_hash = *(uint32_t *)(hook->origin_addr - 4);
#endif

    return HOOK_NO_ERR;
}
KP_EXPORT_SYMBOL(hook_prepare);

#ifndef __USERSPACE__
static void write_insts_at(uint64_t va, uint32_t *insts, int32_t count)
{
    uint64_t *entry = pgtable_entry_kernel(va);
    if (!entry) {
        logke("write_insts_at: pgtable_entry_kernel(%llx) returned NULL",
              (unsigned long long)va);
        return;
    }
    uint64_t ori_prot = *entry;
    logki("write_insts_at: va=%llx pte=%llx count=%d before[0]=%x",
          (unsigned long long)va, (unsigned long long)ori_prot,
          count, *(uint32_t *)va);
    modify_entry_kernel(va, entry, (ori_prot | PTE_DBM) & ~PTE_RDONLY);
    for (int32_t i = 0; i < count; i++)
        *((uint32_t *)va + i) = insts[i];
    logki("write_insts_at: after write, [0]=%x expected=%x",
          *(uint32_t *)va, insts[0]);
    /* Flush icache using inline asm to avoid kCFI issues with ksyms
     * function pointers. IC IVAU invalidates by VA to PoU. */
    {
        uint64_t addr;
        for (addr = va; addr < va + (uint64_t)count * 4; addr += 4)
            asm volatile("ic ivau, %0" :: "r"(addr) : "memory");
        asm volatile("dsb ish\n\tisb" ::: "memory");
    }
    modify_entry_kernel(va, entry, ori_prot);
}

void hook_install(hook_t *hook)
{
    write_insts_at(hook->origin_addr, hook->tramp_insts, hook->tramp_insts_num);
}
KP_EXPORT_SYMBOL(hook_install);

void hook_uninstall(hook_t *hook)
{
    write_insts_at(hook->origin_addr, hook->origin_insts, hook->tramp_insts_num);
}
KP_EXPORT_SYMBOL(hook_uninstall);
#endif /* !__USERSPACE__ */
