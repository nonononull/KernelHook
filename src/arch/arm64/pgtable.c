/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2026 bmax121.
 *
 * ARM64 page table walker and PTE permission modifier for freestanding
 * (Mode A) and kbuild (Mode C) kernel builds.
 *
 * Build modes: shared
 * Depends on: pgtable.h, symbol.h (ksyms_lookup for runtime PTE helpers)
 * Notes: TLBI sequence must stay dsb(ishst) -> tlbi vaale1is -> dsb(ish) -> isb
 *   (vaale1is = VA, All ASIDs, EL1, IS — see CLAUDE.md TLBI correctness).
 *   Ported from KernelPatch kernel/patch/common/hotpatch.c; see
 *   docs/audits/kp-port-audit-2026-04-15.md for deviations.
 */

#include <types.h>
#include <kh_log.h>
#include <pgtable.h>
#include <kh_strategy.h>

#ifdef KMOD_FREESTANDING
/* Everything below is the freestanding (Mode A) raw-page-table machine.
 * In kbuild mode (Mode C) we don't need any of it — kernel already
 * provides set_memory_rw/ro/x (called directly from inline.c) and
 * kh_pgtable_init/entry/modify_entry_kernel are stubs. See the #else
 * branch at the end of this file. */

#include <symbol.h>

/* Runtime page configuration */
uint64_t kh_page_shift = 12; /* Default 4K pages */
uint64_t page_size = 4096;
uint64_t page_level = 4;  /* 4-level by default for 4K pages */

/* Kernel VA layout */
uint64_t kimage_voffset = 0;
uint64_t phys_offset = 0;
uint64_t kh_page_offset = 0;

/* Resolved flush function pointers */
flush_tlb_kernel_page_func_t flush_tlb_kernel_page;
flush_tlb_kernel_range_func_t flush_tlb_kernel_range;
flush_icache_all_func_t flush_icache_all;
flush_icache_range_func_t flush_icache_range;
flush_dcache_area_func_t __flush_dcache_area;

/* Kernel pgd base pointer */
static uint64_t kernel_pgd;

/* Kernel function types for symbol resolution */
typedef uint64_t (*read_sysreg_func_t)(void);

/* Detect page size from TCR_EL1.TG1 field.  Safe to call early —
 * only reads a system register, no ksyms needed. */
static void detect_page_size(void)
{
    uint64_t tcr;
    asm volatile("mrs %0, tcr_el1" : "=r"(tcr));
    uint64_t tg1 = (tcr >> 30) & 3;
    switch (tg1) {
    case 1: kh_page_shift = 14; page_size = 16384; break;  /* 16K */
    case 3: kh_page_shift = 16; page_size = 65536; break;  /* 64K */
    default: kh_page_shift = 12; page_size = 4096; break;   /* 4K */
    }
    /* Note: log may not be initialized yet — caller should log if needed */
}

int kh_pgtable_init(void)
{
    const char *pgd_source = "none";

    /* Detect page size first — other components need this even if
     * the rest of kh_pgtable_init fails (e.g., set_memory mode). */
    detect_page_size();
    pr_info("pgtable: page_size=%llu kh_page_shift=%llu",
          (unsigned long long)page_size, (unsigned long long)kh_page_shift);

    /* Detect page-table levels + PAGE_OFFSET from TCR_EL1.T1SZ BEFORE any
     * ksyms lookups. PAGE_OFFSET is the kernel VA lower bound; we need it
     * to validate resolved symbol addresses below. Computing it from
     * hardware registers (no ksyms) keeps this ordering safe.
     *
     * T1SZ = 64 - VA_BITS. VA_BITS determines pgtable levels:
     *   39-bit VA, 4K  (T1SZ=25) → 3 levels, PAGE_OFFSET=0xFFFFFF8000000000
     *   47-bit VA, 16K (T1SZ=17) → 4 levels, PAGE_OFFSET=0xFFFF800000000000
     *   48-bit VA, 4K  (T1SZ=16) → 4 levels, PAGE_OFFSET=0xFFFF000000000000
     *   52-bit VA, 4K  (T1SZ=12) → 4 levels + FEAT_LPA2 */
    {
        uint64_t tcr;
        asm volatile("mrs %0, tcr_el1" : "=r"(tcr));
        uint64_t t1sz = (tcr >> 16) & 0x3f;
        uint64_t va_bits = 64 - t1sz;
        /* levels = ceil((va_bits - kh_page_shift) / (kh_page_shift - 3)) */
        uint64_t pxd_bits = kh_page_shift - 3; /* bits per level: 9 for 4KB */
        page_level = (va_bits - kh_page_shift + pxd_bits - 1) / pxd_bits;
        /* PAGE_OFFSET = sign-extension of bit (VA_BITS - 1) */
        kh_page_offset = ~((1ULL << va_bits) - 1);
        pr_info("pgtable: TCR_EL1=%llx T1SZ=%llu VA_BITS=%llu page_level=%llu PAGE_OFFSET=%llx",
              (unsigned long long)tcr, (unsigned long long)t1sz,
              (unsigned long long)va_bits, (unsigned long long)page_level,
              (unsigned long long)kh_page_offset);
    }

    /* Resolve flush functions via ksyms. These pointers are DIAGNOSTIC-only
     * — all TLB/icache/dcache maintenance in this module uses inline asm
     * (kh_flush_tlb_kernel_page's `tlbi vaale1is`, `ic ivau` loops in
     * inline.c, `dc civac` loops in pgtable_entry/pgtable_phys_kernel).
     * Newer GKI kernels (e.g. android16 6.12.58) do not export these via
     * kallsyms, but we never call the resolved pointers, so keep the
     * lookups non-fatal. They remain for `dmesg` diagnostics. */
    flush_tlb_kernel_page = (flush_tlb_kernel_page_func_t)(uintptr_t)ksyms_lookup("flush_tlb_kernel_page");
    flush_tlb_kernel_range = (flush_tlb_kernel_range_func_t)(uintptr_t)ksyms_lookup("flush_tlb_kernel_range");
    flush_icache_all = (flush_icache_all_func_t)(uintptr_t)ksyms_lookup("flush_icache_all");
    flush_icache_range = (flush_icache_range_func_t)(uintptr_t)ksyms_lookup("flush_icache_range");
    __flush_dcache_area = (flush_dcache_area_func_t)(uintptr_t)ksyms_lookup("__flush_dcache_area");

    if (!__flush_dcache_area)
        __flush_dcache_area = (flush_dcache_area_func_t)(uintptr_t)ksyms_lookup("dcache_clean_inval_poc");

    pr_info("pgtable: flush_tlb_kernel_page=%llx flush_icache_all=%llx flush_icache_range=%llx dcache=%llx",
          (unsigned long long)(uintptr_t)flush_tlb_kernel_page,
          (unsigned long long)(uintptr_t)flush_icache_all,
          (unsigned long long)(uintptr_t)flush_icache_range,
          (unsigned long long)(uintptr_t)__flush_dcache_area);

    /* Resolve kimage_voffset via strategy registry (SP-7 Task 20 rewire).
     * The registry walks priority-ordered strategies and returns the first
     * success; kh_strategy_dump() prints the full attempt log on failure. */
    int rc = kh_strategy_resolve("kimage_voffset", &kimage_voffset, sizeof(kimage_voffset));
    if (rc) {
        pr_err("pgtable: FATAL: cannot resolve kimage_voffset (rc=%d)", rc);
        kh_strategy_dump();
        return -1;
    }
    pr_info("pgtable: kimage_voffset value=%llx", (unsigned long long)kimage_voffset);

    /* Validate kimage_voffset is in kernel VA range */
    if (kimage_voffset == 0) {
        pr_err("pgtable: kimage_voffset is zero — invalid");
        return -1;
    }

    /* Resolve memstart_addr (PHYS_OFFSET = DRAM base physical address).
     * Non-fatal: if no strategy succeeds we assume PHYS_OFFSET=0 (matches
     * prior behavior for kernels that don't export memstart_addr). */
    rc = kh_strategy_resolve("memstart_addr", &phys_offset, sizeof(phys_offset));
    if (rc == 0) {
        pr_info("pgtable: memstart_addr=%llx (PHYS_OFFSET)", (unsigned long long)phys_offset);
    } else {
        pr_warn("pgtable: memstart_addr unresolved (rc=%d), assuming PHYS_OFFSET=0", rc);
        phys_offset = 0;
    }

    /* Resolve swapper_pg_dir for kernel page table walks.
     * Do NOT fall back to init_mm — its pgd field offset varies
     * across kernel versions and cannot be safely read at offset 0. */
    rc = kh_strategy_resolve("swapper_pg_dir", &kernel_pgd, sizeof(kernel_pgd));
    if (rc == 0 && kernel_pgd) {
        pgd_source = "swapper_pg_dir";
    } else {
        pr_err("pgtable: FATAL: cannot resolve swapper_pg_dir (rc=%d)", rc);
        kh_strategy_dump();
        return -1;
    }

    /* Validate kernel_pgd is in kernel VA range. Use the PAGE_OFFSET we
     * computed from TCR_EL1 above so this works across all ARM64 VA_BITS
     * (39/47/48/52) and page sizes (4K/16K/64K). A hardcoded 39-bit
     * lower bound (0xffffff8000000000) previously rejected valid pgd
     * addresses on 16K/4-level kernels — e.g. GKI android16 6.12.58 on
     * Pixel_37 AVD where swapper_pg_dir sits at 0xffffc00082054000. */
    if (kernel_pgd < kh_page_offset) {
        pr_err("pgtable: kernel_pgd=%llx below PAGE_OFFSET=%llx (not in kernel VA range)",
              (unsigned long long)kernel_pgd,
              (unsigned long long)kh_page_offset);
        return -1;
    }

    pr_info("pgtable: init ok, pgd=0x%llx (%s) voffset=0x%llx kh_page_shift=%llu levels=%llu",
          (unsigned long long)kernel_pgd, pgd_source,
          (unsigned long long)kimage_voffset,
          (unsigned long long)kh_page_shift,
          (unsigned long long)page_level);

    return 0;
}

/* Exempt from kCFI: calls flush functions resolved via ksyms at runtime.
 * Their CFI type hashes won't match the module's compiled-in hashes. */
__attribute__((no_sanitize("kcfi")))
uint64_t *pgtable_entry(uint64_t pgd, uint64_t va)
{
    uint64_t pxd_bits = kh_page_shift - 3;
    uint64_t pxd_ptrs = 1UL << pxd_bits;
    uint64_t pxd_va = pgd;
    uint64_t pxd_pa = kh_virt_to_phys(pxd_va);
    uint64_t pxd_entry_va = 0;
    uint64_t block_lv = 0;

    /* Sanity check: pgd and VA must be in kernel address space.
     * Use kh_page_offset (computed from VA_BITS) as the lower bound. */
    uint64_t kva_min = kh_page_offset ? kh_page_offset : 0xffffff8000000000ULL;
    if (pxd_va < kva_min || va < kva_min) {
        pr_err("pgtable_entry: invalid addr pgd=%llx va=%llx",
              (unsigned long long)pxd_va, (unsigned long long)va);
        return 0;
    }

    /* Flush dcache for the page table page to ensure we read current PTEs.
     * Use inline asm DC CIVAC loop instead of __flush_dcache_area to avoid
     * kCFI type mismatch when calling kernel functions via ksyms. */
    {
        uint64_t line;
        for (line = pxd_va; line < pxd_va + page_size; line += 64)
            asm volatile("dc civac, %0" :: "r"(line) : "memory");
        asm volatile("dsb ish" ::: "memory");
    }

    for (int64_t lv = 4 - (int64_t)page_level; lv < 4; lv++) {
        uint64_t pxd_shift = (kh_page_shift - 3) * (uint64_t)(4 - lv) + 3;
        uint64_t pxd_index = (va >> pxd_shift) & (pxd_ptrs - 1);
        pxd_entry_va = pxd_va + pxd_index * 8;
        if (!pxd_entry_va)
            return 0;
        uint64_t pxd_desc = *((uint64_t *)pxd_entry_va);
        if ((pxd_desc & 0x3) == 0x3) {
            /* Table descriptor */
            pxd_pa = pxd_desc & (((1UL << (48 - kh_page_shift)) - 1) << kh_page_shift);
        } else if ((pxd_desc & 0x3) == 0x1) {
            /* Block descriptor */
            uint64_t block_bits = (uint64_t)(3 - lv) * pxd_bits + kh_page_shift;
            pxd_pa = pxd_desc & (((1UL << (48 - block_bits)) - 1) << block_bits);
            block_lv = (uint64_t)lv;
        } else {
            /* Invalid descriptor */
            return 0;
        }

        pxd_va = kh_phys_to_virt(pxd_pa);
        if (block_lv)
            break;
    }

    return (uint64_t *)pxd_entry_va;
}

uint64_t *pgtable_entry_kernel(uint64_t va)
{
    return pgtable_entry(kernel_pgd, va);
}

/* Walk an arbitrary pgd VA to find the physical address backing va.
 * Parameterised version of pgtable_phys_kernel: takes pgd_va instead of
 * using the file-local kernel_pgd. Used by strategies that walk arbitrary
 * page directories. Returns 0 on invalid walk. */
__attribute__((no_sanitize("kcfi")))
uint64_t kh_walk_va_to_pa(uint64_t pgd_va, uint64_t va)
{
    uint64_t pxd_bits = kh_page_shift - 3;
    uint64_t pxd_ptrs = 1UL << pxd_bits;
    uint64_t pxd_pa = 0;
    uint64_t pxd_va = pgd_va;

    uint64_t kva_min = kh_page_offset ? kh_page_offset : 0xffffff8000000000ULL;
    if (pxd_va < kva_min || va < kva_min)
        return 0;

    for (uint64_t line = pxd_va; line < pxd_va + page_size; line += 64)
        asm volatile("dc civac, %0" :: "r"(line) : "memory");
    asm volatile("dsb ish" ::: "memory");

    for (int64_t lv = 4 - (int64_t)page_level; lv < 4; lv++) {
        uint64_t pxd_shift = pxd_bits * (uint64_t)(4 - lv) + 3;
        uint64_t pxd_index = (va >> pxd_shift) & (pxd_ptrs - 1);
        uint64_t pxd_desc = ((uint64_t *)pxd_va)[pxd_index];
        uint8_t kind = pxd_desc & 0x3;
        if (kind == 0x3) {
            pxd_pa = pxd_desc & (((1UL << (48 - kh_page_shift)) - 1) << kh_page_shift);
        } else if (kind == 0x1) {
            uint64_t bits = (uint64_t)(3 - lv) * pxd_bits;
            uint64_t block_bits = bits + kh_page_shift;
            pxd_pa = (pxd_desc & (((1UL << (48 - block_bits)) - 1) << block_bits)) +
                     (va & (((1UL << bits) - 1) << kh_page_shift));
            break;
        } else {
            return 0;
        }
        pxd_va = kh_phys_to_virt(pxd_pa);
    }
    return pxd_pa ? pxd_pa + (va & (page_size - 1)) : 0;
}

/* Compute physical address backing a kernel VA by walking kernel page tables.
 * Thin wrapper around kh_walk_va_to_pa that uses the file-local kernel_pgd.
 * Mirrors KernelPatch kernel/base/start.c:176-202. Handles mid-level
 * BLOCK descriptors (computes pa = block_pa + (va & (block_size - 1))).
 * Returns 0 on invalid walk. */
__attribute__((no_sanitize("kcfi")))
uint64_t pgtable_phys_kernel(uint64_t va)
{
    return kh_walk_va_to_pa(kernel_pgd, va);
}

void modify_entry_kernel(uint64_t va, uint64_t *entry, uint64_t value)
{
    if (!pte_valid_cont(*entry) && !pte_valid_cont(value)) {
        *entry = value;
        kh_flush_tlb_kernel_page(va);
        return;
    }

    /* Handle contiguous PTE: update all entries in the contiguous group */
    uint64_t table_pa_mask = (((1UL << (48 - kh_page_shift)) - 1) << kh_page_shift);
    uint64_t prot = value & ~table_pa_mask;
    uint64_t *p = (uint64_t *)((uintptr_t)entry & ~(sizeof(*entry) * CONT_PTES - 1));
    for (int i = 0; i < CONT_PTES; ++i, ++p)
        *p = (*p & table_pa_mask) | prot;

    *entry = value;
    va &= CONT_PTE_MASK;
    /* Flush all pages in the contiguous group */
    for (int i = 0; i < CONT_PTES; i++)
        kh_flush_tlb_kernel_page(va + (uint64_t)i * page_size);
}

#else /* !KMOD_FREESTANDING — kbuild mode stubs */

/* Mode C (kbuild): kernel provides real page table manipulation
 * through set_memory_rw/ro/x which inline.c uses directly. None of
 * the raw page-table walking machinery above is needed. Provide stubs
 * so the symbols still exist for main.c's kernelhook_init() call. */

int kh_pgtable_init(void)
{
    /* Nothing to resolve — kernel headers give us everything at compile
     * time, and set_memory_* are EXPORT_SYMBOL'd. */
    return 0;
}

uint64_t *pgtable_entry(uint64_t pgd, uint64_t va)
{
    (void)pgd;
    (void)va;
    /* Not used in kbuild mode — inline.c's kh_write_mode is forced to
     * the set_memory path. */
    return (uint64_t *)0;
}

uint64_t *pgtable_entry_kernel(uint64_t va)
{
    (void)va;
    return (uint64_t *)0;
}

uint64_t kh_walk_va_to_pa(uint64_t pgd_va, uint64_t va)
{
    (void)pgd_va;
    (void)va;
    return 0;
}

uint64_t pgtable_phys_kernel(uint64_t va)
{
    (void)va;
    return 0;
}

void modify_entry_kernel(uint64_t va, uint64_t *entry, uint64_t value)
{
    (void)va;
    (void)entry;
    (void)value;
}

#endif /* KMOD_FREESTANDING */
