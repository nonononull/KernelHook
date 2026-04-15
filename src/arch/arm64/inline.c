/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2026 bmax121.
 * ARM64 instruction relocation engine
 */

#include <hook.h>
#include <insn.h>
#include <pgtable.h>
#include <kh_log.h>
#include <symbol.h>
#ifndef __USERSPACE__
#include <linux/set_memory.h>
#endif

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

static int is_in_tramp(hook_t *hook, uintptr_t addr)
{
    uintptr_t tramp_start = hook->origin_addr;
    uintptr_t tramp_end = tramp_start + hook->tramp_insts_num * 4;
    if (addr >= tramp_start && addr < tramp_end) {
        return 1;
    }
    return 0;
}

static uintptr_t relo_in_tramp(hook_t *hook, uintptr_t addr)
{
    if (!is_in_tramp(hook, addr)) return addr;
    uintptr_t tramp_start = hook->origin_addr;
    uint32_t addr_inst_index = (addr - tramp_start) / 4;
    uintptr_t fix_addr = hook->relo_addr;
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

static __attribute__((__noinline__)) hook_err_t relo_b(hook_t *hook, uintptr_t inst_addr, uint32_t inst, inst_type_t type)
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
    uintptr_t addr = inst_addr + imm64;
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

static __attribute__((__noinline__)) hook_err_t relo_adr(hook_t *hook, uintptr_t inst_addr, uint32_t inst, inst_type_t type)
{
    uint32_t *buf = hook->relo_insts + hook->relo_insts_num;

    uint32_t xd = bits32(inst, 4, 0);
    uint64_t immlo = bits32(inst, 30, 29);
    uint64_t immhi = bits32(inst, 23, 5);
    uintptr_t addr;

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

static __attribute__((__noinline__)) hook_err_t relo_ldr(hook_t *hook, uintptr_t inst_addr, uint32_t inst, inst_type_t type)
{
    uint32_t *buf = hook->relo_insts + hook->relo_insts_num;

    uint32_t rt = bits32(inst, 4, 0);
    uint64_t imm19 = bits32(inst, 23, 5);
    uint64_t offset = sign64_extend((imm19 << 2u), 21u);
    uintptr_t addr = inst_addr + offset;

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

static __attribute__((__noinline__)) hook_err_t relo_cb(hook_t *hook, uintptr_t inst_addr, uint32_t inst, inst_type_t type)
{
    uint32_t *buf = hook->relo_insts + hook->relo_insts_num;
    (void)type;

    uint64_t imm19 = bits32(inst, 23, 5);
    uint64_t offset = sign64_extend((imm19 << 2u), 21u);
    uintptr_t addr = inst_addr + offset;
    addr = relo_in_tramp(hook, addr);

    buf[0] = (inst & 0xFF00001F) | 0x40u; /* CB(N)Z Rt, #8 */
    buf[1] = 0x14000005; /* B #20 */
    buf[2] = 0x58000051; /* LDR X17, #8 */
    buf[3] = 0xD65F0220; /* RET X17 */
    buf[4] = addr & 0xFFFFFFFF;
    buf[5] = addr >> 32u;
    return HOOK_NO_ERR;
}

static __attribute__((__noinline__)) hook_err_t relo_tb(hook_t *hook, uintptr_t inst_addr, uint32_t inst, inst_type_t type)
{
    uint32_t *buf = hook->relo_insts + hook->relo_insts_num;
    (void)type;

    uint64_t imm14 = bits32(inst, 18, 5);
    uint64_t offset = sign64_extend((imm14 << 2u), 16u);
    uintptr_t addr = inst_addr + offset;
    addr = relo_in_tramp(hook, addr);

    buf[0] = (inst & 0xFFF8001F) | 0x40u; /* TB(N)Z Rt, #<imm>, #8 */
    buf[1] = 0x14000005; /* B #20 */
    buf[2] = 0x58000051; /* LDR X17, #8 */
    buf[3] = 0xd61f0220; /* BR X17 */
    buf[4] = addr & 0xFFFFFFFF;
    buf[5] = addr >> 32u;
    return HOOK_NO_ERR;
}

static __attribute__((__noinline__)) hook_err_t relo_ignore(hook_t *hook, uintptr_t inst_addr, uint32_t inst, inst_type_t type)
{
    uint32_t *buf = hook->relo_insts + hook->relo_insts_num;
    (void)inst_addr;
    (void)type;
    buf[0] = inst;
    buf[1] = ARM64_NOP;
    return HOOK_NO_ERR;
}

static __attribute__((__noinline__)) hook_err_t relocate_inst(hook_t *hook, uintptr_t inst_addr, uint32_t inst)
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

    /* Bounds check BEFORE writing to prevent buffer overflow */
    if (hook->relo_insts_num + len > RELOCATE_INST_NUM)
        return HOOK_BAD_RELO;

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

    {
        uint32_t i;
        for (i = 0; i < sizeof(hook->relo_insts) / sizeof(hook->relo_insts[0]); i++)
            hook->relo_insts[i] = ARM64_NOP;
    }

    uint32_t *bti = hook->relo_insts + hook->relo_insts_num;
    bti[0] = ARM64_BTI_JC;
    bti[1] = ARM64_NOP;
    hook->relo_insts_num += 2;

    {
    int i;
    for (i = 0; i < hook->tramp_insts_num; i++) {
        uintptr_t inst_addr = hook->origin_addr + i * 4;
        uint32_t inst = hook->origin_insts[i];
        hook_err_t relo_res = relocate_inst(hook, inst_addr, inst);
        if (relo_res) {
            return HOOK_BAD_RELO;
        }
    }
    }

    uintptr_t back_src_addr = hook->relo_addr + hook->relo_insts_num * 4;
    uintptr_t back_dst_addr = hook->origin_addr + hook->tramp_insts_num * 4;
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
    if (!is_bad_address((void *)(hook->origin_addr - 4)))
        hook->_relo_cfi_hash = *(uint32_t *)(hook->origin_addr - 4);
#endif

    return HOOK_NO_ERR;
}

#ifndef __USERSPACE__

/* ---- Write mode: linear mapping (default) ----
 *
 * ARM64 kernels maintain two VA mappings to the same physical memory:
 *   1. Kernel image mapping (KIMAGE_VADDR) — code is RX (read-only + exec)
 *   2. Linear mapping (PAGE_OFFSET)        — all DRAM, typically RW
 *
 * To patch code: convert target VA → PA → linear mapping VA, then write
 * through the linear mapping. No PTE modification needed.
 *
 * Caveat: kernels with rodata_full=1 mark linear mapping as RO too.
 * In that case, fall back to set_memory_rw/ro/x.
 */

/* ---- Write mode: set_memory (fallback) ----
 *
 * Uses kernel's set_memory_rw/ro/x (resolved via ksyms) to temporarily
 * make the target page writable, write, then restore permissions.
 * Works on all kernels but has a race window where other CPUs see RW.
 */

typedef int (*set_memory_fn_t)(unsigned long addr, int numpages);
static set_memory_fn_t kh_set_memory_rw;
static set_memory_fn_t kh_set_memory_ro;
static set_memory_fn_t kh_set_memory_x;

/* 0 = PTE modification (fallback), 1 = set_memory (default when available) */
static int kh_write_mode = 0;

/* Alias-page mechanism for kernel-text patching (primary path).
 * Mirrors KernelPatch kernel/base/hotpatch.c. vmalloc'd at init;
 * at patch time the alias PTE is rewritten to point at the target
 * text's physical page, we call aarch64_insn_patch_text_nosync
 * through the alias VA (which lives in vmalloc RW area), then
 * restore the original alias PTE. alias_pte == 0 means the alias
 * path is unavailable and we must fall through to PTE-direct. */
static void *kh_alias_page = NULL;
static uint64_t *kh_alias_entry = NULL;
static uint64_t kh_alias_pte = 0;
static uint64_t kh_table_pa_mask = 0;

#ifdef KMOD_FREESTANDING
/* Spinlock serializes the alias PTE rewrite + patch + restore sequence.
 * kh_alias_entry is a single global PTE; concurrent hook_install on
 * different target functions would otherwise race and cause
 * aarch64_insn_patch_text_nosync to write to the wrong target. */
typedef struct {
    volatile int locked;
} kh_alias_spin_t;
static kh_alias_spin_t kh_alias_lock;

static inline void kh_alias_lock_acquire(unsigned long *flags)
{
    /* Disable IRQs to prevent re-entry via softirq/interrupt. Matches
     * Linux spin_lock_irqsave semantics without dragging in the kernel's
     * spinlock type (freestanding headers may not have it). */
    unsigned long f;
    asm volatile("mrs %0, daif" : "=r"(f));
    asm volatile("msr daifset, #0xf" ::: "memory");
    *flags = f;
    while (__atomic_exchange_n(&kh_alias_lock.locked, 1, __ATOMIC_ACQUIRE))
        asm volatile("yield" ::: "memory");
}

static inline void kh_alias_lock_release(unsigned long flags)
{
    __atomic_store_n(&kh_alias_lock.locked, 0, __ATOMIC_RELEASE);
    asm volatile("msr daif, %0" :: "r"(flags) : "memory");
}
#else
#include <linux/spinlock.h>
static DEFINE_SPINLOCK(kh_alias_lock);
#define kh_alias_lock_acquire(flags_ptr) spin_lock_irqsave(&kh_alias_lock, *(flags_ptr))
#define kh_alias_lock_release(flags) spin_unlock_irqrestore(&kh_alias_lock, flags)
#endif

typedef int (*aarch64_insn_patch_text_nosync_fn_t)(void *addr, uint32_t insn);
static aarch64_insn_patch_text_nosync_fn_t kh_aarch64_insn_patch_text_nosync = NULL;

typedef void *(*vmalloc_fn_t)(unsigned long size);
typedef void (*vfree_fn_t)(const void *addr);
static vmalloc_fn_t kh_vmalloc = NULL;
static vfree_fn_t kh_vfree = NULL;

#ifndef KMOD_FREESTANDING
/* Forward decl for kbuild mode — prototype matches arch/arm64/kernel/patching.c.
 * Symbol is EXPORT_SYMBOL_GPL so we can take its address. */
extern int aarch64_insn_patch_text_nosync(void *addr, u32 insn);
#endif

__attribute__((no_sanitize("kcfi")))
static void kh_alias_init(void)
{
#ifdef KMOD_FREESTANDING
    kh_vmalloc = (vmalloc_fn_t)(uintptr_t)ksyms_lookup("vmalloc");
    kh_vfree = (vfree_fn_t)(uintptr_t)ksyms_lookup("vfree");
    kh_aarch64_insn_patch_text_nosync = (aarch64_insn_patch_text_nosync_fn_t)(uintptr_t)
        ksyms_lookup("aarch64_insn_patch_text_nosync");
#else
    kh_vmalloc = (vmalloc_fn_t)vmalloc;
    kh_vfree = (vfree_fn_t)vfree;
    kh_aarch64_insn_patch_text_nosync = (aarch64_insn_patch_text_nosync_fn_t)
        aarch64_insn_patch_text_nosync;
#endif

    kh_table_pa_mask = (((1UL << (48 - page_shift)) - 1) << page_shift);

    if (!kh_vmalloc || !kh_aarch64_insn_patch_text_nosync) {
        pr_warn("alias: symbols missing (vmalloc=%llx patch_text=%llx); "
                "alias path disabled, will use fallback",
                (unsigned long long)(uintptr_t)kh_vmalloc,
                (unsigned long long)(uintptr_t)kh_aarch64_insn_patch_text_nosync);
        return;
    }

    kh_alias_page = kh_vmalloc(page_size);
    if (!kh_alias_page) {
        pr_err("alias: vmalloc failed");
        return;
    }

    kh_alias_entry = pgtable_entry_kernel((uintptr_t)kh_alias_page);
    if (kh_alias_entry) {
        uint64_t pte = *kh_alias_entry;
        if ((pte & 0x3) != 0x3) {
            pr_warn("alias: entry %llx is not a leaf PTE; alias path disabled",
                    (unsigned long long)pte);
        } else if (pte & PTE_CONT) {
            pr_warn("alias: entry %llx has PTE_CONT set; rewriting a single "
                    "PTE in a CONT group violates the ARM contiguous-hint "
                    "protocol. Alias path disabled.",
                    (unsigned long long)pte);
        } else {
            kh_alias_pte = pte;
        }
    }

    pr_info("alias: page=%llx entry=%llx pte=%llx table_pa_mask=%llx",
            (unsigned long long)(uintptr_t)kh_alias_page,
            (unsigned long long)(uintptr_t)kh_alias_entry,
            (unsigned long long)kh_alias_pte,
            (unsigned long long)kh_table_pa_mask);
}

__attribute__((no_sanitize("kcfi")))
static int write_insts_via_alias(uintptr_t va, uint32_t *insts, int32_t count)
{
    if (!kh_alias_page || !kh_alias_pte || !kh_aarch64_insn_patch_text_nosync)
        return -1;  /* alias path unavailable; signal fallback */

    for (int32_t i = 0; i < count; i++) {
        uintptr_t target = va + (uintptr_t)i * 4;
        uint64_t phys = pgtable_phys_kernel(target);
        if (!phys) return -1;

        unsigned long flags;
        kh_alias_lock_acquire(&flags);

        *kh_alias_entry = (kh_alias_pte & ~kh_table_pa_mask) |
                          (phys & ~(uint64_t)(page_size - 1));
        asm volatile("dsb ish" ::: "memory");
        kh_flush_tlb_kernel_page((uintptr_t)kh_alias_page);

        void *alias_va = (void *)((uintptr_t)kh_alias_page +
                                  (target & (page_size - 1)));
        int rc = kh_aarch64_insn_patch_text_nosync(alias_va, insts[i]);

        *kh_alias_entry = kh_alias_pte;
        asm volatile("dsb ish" ::: "memory");
        kh_flush_tlb_kernel_page((uintptr_t)kh_alias_page);

        kh_alias_lock_release(flags);

        if (rc) return rc;
    }
    return 0;
}

/* Called from kmod init after ksyms resolution */
__attribute__((no_sanitize("kcfi")))
void kh_write_insts_init(void)
{
#ifdef KMOD_FREESTANDING
    /* Freestanding: resolve set_memory_* via runtime ksyms lookup. */
    kh_set_memory_rw = (set_memory_fn_t)(uintptr_t)ksyms_lookup("set_memory_rw");
    kh_set_memory_ro = (set_memory_fn_t)(uintptr_t)ksyms_lookup("set_memory_ro");
    kh_set_memory_x  = (set_memory_fn_t)(uintptr_t)ksyms_lookup("set_memory_x");
    if (!kh_set_memory_x)
        kh_set_memory_x = (set_memory_fn_t)(uintptr_t)ksyms_lookup("set_memory_exec");

    /* Prefer set_memory when available; fall back to direct PTE modification */
    kh_write_mode = (kh_set_memory_rw && kh_set_memory_ro) ? 1 : 0;
#else
    /* Kbuild: kernel provides set_memory_rw/ro/x as EXPORT_SYMBOL.
     * Use them directly — no ksyms indirection, and the PTE-modification
     * path (kh_write_mode == 0) is not reachable because it depends on
     * pgtable_entry_kernel() which is a stub in kbuild mode. */
    kh_set_memory_rw = (set_memory_fn_t)set_memory_rw;
    kh_set_memory_ro = (set_memory_fn_t)set_memory_ro;
    kh_set_memory_x  = (set_memory_fn_t)set_memory_x;
    kh_write_mode = 1;
#endif
    pr_info("write_insts: mode=%s", kh_write_mode ? "set_memory" : "pte_modify");

    pr_info("write_insts: set_memory rw=%llx ro=%llx x=%llx",
          (unsigned long long)(uintptr_t)kh_set_memory_rw,
          (unsigned long long)(uintptr_t)kh_set_memory_ro,
          (unsigned long long)(uintptr_t)kh_set_memory_x);

    /* Must run after pgtable_init (for page_shift, kh_phys_to_virt,
     * kernel_pgd) and after symbol resolution. */
    kh_alias_init();
}

/* Free the vmalloc'd alias page. Must be called from the module exit path
 * to avoid leaking a page of virtual address space on rmmod. Callers MUST
 * ensure no concurrent hook_install calls are in flight before calling this.
 * (In practice, all hooks should have been uninstalled before module exit.) */
__attribute__((no_sanitize("kcfi")))
void kh_write_insts_cleanup(void)
{
#ifdef KMOD_FREESTANDING
    if (kh_alias_page && kh_vfree) {
        kh_vfree(kh_alias_page);
        kh_alias_page = NULL;
        kh_alias_entry = NULL;
        kh_alias_pte = 0;
    }
#else
    if (kh_alias_page) {
        vfree(kh_alias_page);
        kh_alias_page = NULL;
        kh_alias_entry = NULL;
        kh_alias_pte = 0;
    }
#endif
}

__attribute__((no_sanitize("kcfi")))
static void write_insts_via_pte(uintptr_t va, uint32_t *insts, int32_t count)
{
    /* PTE mode: directly modify the page table entry to clear
     * PTE_RDONLY, write instructions, then restore the original PTE.
     * This is the KernelPatch approach — works on all kernels
     * regardless of rodata_full or set_memory availability, and on
     * kernel-image VAs where set_memory_rw refuses (kernel text is
     * not in vmalloc area, so set_memory's find_vm_area returns NULL
     * and the call returns -EINVAL). */
    uint64_t *entry = pgtable_entry_kernel(va);
    if (!entry)
        return;
    uint64_t ori_pte = *entry;

    /* Clear PTE_RDONLY + set PTE_DBM, then flush TLB for this VA. */
    *entry = (ori_pte | PTE_DBM) & ~PTE_RDONLY;
    kh_flush_tlb_kernel_page(va);

    for (int32_t i = 0; i < count; i++)
        *((uint32_t *)va + i) = insts[i];

    /* Restore original PTE and flush TLB */
    *entry = ori_pte;
    kh_flush_tlb_kernel_page(va);
}

__attribute__((no_sanitize("kcfi")))
static void write_insts_at(uintptr_t va, uint32_t *insts, int32_t count)
{
    /* Primary: alias-page + aarch64_insn_patch_text_nosync (KP path).
     * aarch64_insn_patch_text_nosync handles icache internally. */
    if (write_insts_via_alias(va, insts, count) == 0)
        return;

    /* Fallback 1: set_memory (for vmalloc-backed pages only). */
    if (kh_write_mode == 1 && kh_set_memory_rw && kh_set_memory_ro) {
        unsigned long page_va = va & ~(page_size - 1);
        if (kh_set_memory_rw(page_va, 1) == 0) {
            for (int32_t i = 0; i < count; i++)
                *((uint32_t *)va + i) = insts[i];
            kh_set_memory_ro(page_va, 1);
            if (kh_set_memory_x)
                kh_set_memory_x(page_va, 1);
            goto flush_icache;
        }
    }

    /* Fallback 2: direct PTE modification. */
    write_insts_via_pte(va, insts, count);

flush_icache:
    /* Fallback paths do not flush icache themselves; do it here. */
    for (uintptr_t addr = va; addr < va + (uintptr_t)count * 4; addr += 4)
        asm volatile("ic ivau, %0" :: "r"(addr) : "memory");
    asm volatile("dsb ish\n\tisb" ::: "memory");
}

void hook_install(hook_t *hook)
{
    write_insts_at(hook->origin_addr, hook->tramp_insts, hook->tramp_insts_num);
}

void hook_uninstall(hook_t *hook)
{
    write_insts_at(hook->origin_addr, hook->origin_insts, hook->tramp_insts_num);
}
#endif /* !__USERSPACE__ */
