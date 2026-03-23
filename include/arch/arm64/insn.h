/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2026 bmax121.
 */

#ifndef _KP_ARM64_INSN_H_
#define _KP_ARM64_INSN_H_

#include <ktypes.h>

#define HOOK_INTO_BRANCH_FUNC

/* Branch instruction generation */
int32_t branch_relative(uint32_t *buf, uint64_t src_addr, uint64_t dst_addr);
int32_t branch_absolute(uint32_t *buf, uint64_t addr);
int32_t ret_absolute(uint32_t *buf, uint64_t addr);
int32_t branch_from_to(uint32_t *tramp_buf, uint64_t src_addr, uint64_t dst_addr);

/* Follow B/BTI chains to find real function entry */
#ifdef HOOK_INTO_BRANCH_FUNC
uint64_t branch_func_addr(uint64_t addr);
#endif

/* ARM64 instruction constants */
#define INST_B          0x14000000
#define INST_BC         0x54000000
#define INST_BL         0x94000000
#define INST_ADR        0x10000000
#define INST_ADRP       0x90000000
#define INST_LDR_32     0x18000000
#define INST_LDR_64     0x58000000
#define INST_LDRSW_LIT  0x98000000
#define INST_PRFM_LIT   0xD8000000
#define INST_LDR_SIMD_32  0x1C000000
#define INST_LDR_SIMD_64  0x5C000000
#define INST_LDR_SIMD_128 0x9C000000
#define INST_CBZ        0x34000000
#define INST_CBNZ       0x35000000
#define INST_TBZ        0x36000000
#define INST_TBNZ       0x37000000
#define INST_HINT       0xD503201F
#define INST_IGNORE     0x0

#define MASK_B          0xFC000000
#define MASK_BC         0xFF000010
#define MASK_BL         0xFC000000
#define MASK_ADR        0x9F000000
#define MASK_ADRP       0x9F000000
#define MASK_LDR_32     0xFF000000
#define MASK_LDR_64     0xFF000000
#define MASK_LDRSW_LIT  0xFF000000
#define MASK_PRFM_LIT   0xFF000000
#define MASK_LDR_SIMD_32  0xFF000000
#define MASK_LDR_SIMD_64  0xFF000000
#define MASK_LDR_SIMD_128 0xFF000000
#define MASK_CBZ        0x7F000000u
#define MASK_CBNZ       0x7F000000u
#define MASK_TBZ        0x7F000000u
#define MASK_TBNZ       0x7F000000u
#define MASK_HINT       0xFFFFF01F
#define MASK_IGNORE     0x0

/* Bit manipulation helpers */
#define bits32(n, high, low) ((uint32_t)((n) << (31u - (high))) >> (31u - (high) + (low)))
#define bit(n, st) (((n) >> (st)) & 1)
static inline uint64_t sign64_extend(uint64_t val, uint32_t len)
{
    if ((val >> (len - 1)) & 1)
        return val | (0xFFFFFFFFFFFFFFFF << len);
    return val;
}

#endif /* _KP_ARM64_INSN_H_ */
