/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2026 bmax121.
 * ARM64 page table walking and permission modification.
 */

#include <ktypes.h>
#include <log.h>
#include <pgtable.h>

#ifdef KMOD_FREESTANDING
/* Everything below is the freestanding (Mode A) raw-page-table machine.
 * In kbuild mode (Mode C) we don't need any of it — kernel already
 * provides set_memory_rw/ro/x (called directly from inline.c) and
 * pgtable_init/entry/modify_entry_kernel are stubs. See the #else
 * branch at the end of this file. */

#include <ksyms.h>

/* Runtime page configuration */
uint64_t page_shift = 12; /* Default 4K pages */
uint64_t page_size = 4096;
uint64_t page_level = 4;  /* 4-level by default for 4K pages */

/* Kernel VA layout */
uint64_t kimage_voffset = 0;
uint64_t phys_offset = 0;
uint64_t page_offset = 0;

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
    case 1: page_shift = 14; page_size = 16384; break;  /* 16K */
    case 3: page_shift = 16; page_size = 65536; break;  /* 64K */
    default: page_shift = 12; page_size = 4096; break;   /* 4K */
    }
    /* Note: log may not be initialized yet — caller should log if needed */
}

int pgtable_init(void)
{
    const char *pgd_source = "none";

    /* Detect page size first — other components need this even if
     * the rest of pgtable_init fails (e.g., set_memory mode). */
    detect_page_size();
    logki("pgtable: page_size=%llu page_shift=%llu",
          (unsigned long long)page_size, (unsigned long long)page_shift);

    /* Resolve flush functions via ksyms */
    flush_tlb_kernel_page = (flush_tlb_kernel_page_func_t)(uintptr_t)ksyms_lookup_cache("flush_tlb_kernel_page");
    flush_tlb_kernel_range = (flush_tlb_kernel_range_func_t)(uintptr_t)ksyms_lookup_cache("flush_tlb_kernel_range");
    flush_icache_all = (flush_icache_all_func_t)(uintptr_t)ksyms_lookup_cache("flush_icache_all");
    flush_icache_range = (flush_icache_range_func_t)(uintptr_t)ksyms_lookup_cache("flush_icache_range");
    __flush_dcache_area = (flush_dcache_area_func_t)(uintptr_t)ksyms_lookup_cache("__flush_dcache_area");

    if (!__flush_dcache_area)
        __flush_dcache_area = (flush_dcache_area_func_t)(uintptr_t)ksyms_lookup_cache("dcache_clean_inval_poc");

    logki("pgtable: flush_tlb_kernel_page=%llx flush_icache_all=%llx flush_icache_range=%llx dcache=%llx",
          (unsigned long long)(uintptr_t)flush_tlb_kernel_page,
          (unsigned long long)(uintptr_t)flush_icache_all,
          (unsigned long long)(uintptr_t)flush_icache_range,
          (unsigned long long)(uintptr_t)__flush_dcache_area);

    if (!flush_tlb_kernel_page || !__flush_dcache_area) {
        logke("pgtable: failed to resolve required flush symbols");
        return -1;
    }

    /* Resolve kimage_voffset - kernel exports this as a variable */
    uint64_t *voffset_ptr = (uint64_t *)(uintptr_t)ksyms_lookup_cache("kimage_voffset");
    logki("pgtable: kimage_voffset sym=%llx", (unsigned long long)(uintptr_t)voffset_ptr);
    if (voffset_ptr) {
        kimage_voffset = *voffset_ptr;
        logki("pgtable: kimage_voffset value=%llx", (unsigned long long)kimage_voffset);
    } else {
        logke("pgtable: failed to resolve kimage_voffset");
        return -1;
    }

    /* Validate kimage_voffset is in kernel VA range */
    if (kimage_voffset == 0) {
        logke("pgtable: kimage_voffset is zero — invalid");
        return -1;
    }

    /* Resolve memstart_addr (PHYS_OFFSET = DRAM base physical address) */
    uint64_t *memstart_ptr = (uint64_t *)(uintptr_t)ksyms_lookup_cache("memstart_addr");
    if (memstart_ptr) {
        phys_offset = *memstart_ptr;
        logki("pgtable: memstart_addr=%llx (PHYS_OFFSET)", (unsigned long long)phys_offset);
    } else {
        logkw("pgtable: memstart_addr not found, assuming PHYS_OFFSET=0");
    }

    /* Resolve swapper_pg_dir for kernel page table walks.
     * Do NOT fall back to init_mm — its pgd field offset varies
     * across kernel versions and cannot be safely read at offset 0. */
    kernel_pgd = ksyms_lookup_cache("swapper_pg_dir");
    if (kernel_pgd) {
        pgd_source = "swapper_pg_dir";
    } else {
        logke("pgtable: swapper_pg_dir not found — cannot walk kernel page tables");
        return -1;
    }

    /* Validate kernel_pgd is in kernel VA range.
     * Kernel VA starts at 0xffffff8000000000 for 39-bit VA,
     * 0xffff000000000000 for 48-bit VA. Use the lower bound. */
    if (kernel_pgd < 0xffffff8000000000ULL) {
        logke("pgtable: kernel_pgd=%llx looks invalid (not in kernel VA range)",
              (unsigned long long)kernel_pgd);
        return -1;
    }

    /* Detect page table levels from TCR_EL1.T1SZ.
     * T1SZ = 64 - VA_BITS. VA_BITS determines pgtable levels:
     *   39-bit VA (T1SZ=25) → 3 levels (PGD/PMD/PTE)
     *   48-bit VA (T1SZ=16) → 4 levels (PGD/PUD/PMD/PTE)
     *   52-bit VA (T1SZ=12) → 4 levels + FEAT_LPA2 */
    {
        uint64_t tcr;
        asm volatile("mrs %0, tcr_el1" : "=r"(tcr));
        uint64_t t1sz = (tcr >> 16) & 0x3f;
        uint64_t va_bits = 64 - t1sz;
        /* levels = ceil((va_bits - page_shift) / (page_shift - 3)) */
        uint64_t pxd_bits = page_shift - 3; /* bits per level: 9 for 4KB */
        page_level = (va_bits - page_shift + pxd_bits - 1) / pxd_bits;
        /* PAGE_OFFSET = sign-extension of bit (VA_BITS - 1)
         * For 39-bit: 0xFFFFFF8000000000, for 48-bit: 0xFFFF000000000000 */
        page_offset = ~((1ULL << va_bits) - 1);
        logki("pgtable: TCR_EL1=%llx T1SZ=%llu VA_BITS=%llu page_level=%llu PAGE_OFFSET=%llx",
              (unsigned long long)tcr, (unsigned long long)t1sz,
              (unsigned long long)va_bits, (unsigned long long)page_level,
              (unsigned long long)page_offset);
    }

    logki("pgtable: init ok, pgd=0x%llx (%s) voffset=0x%llx page_shift=%llu levels=%llu",
          (unsigned long long)kernel_pgd, pgd_source,
          (unsigned long long)kimage_voffset,
          (unsigned long long)page_shift,
          (unsigned long long)page_level);

    return 0;
}

/* Exempt from kCFI: calls flush functions resolved via ksyms at runtime.
 * Their CFI type hashes won't match the module's compiled-in hashes. */
__attribute__((no_sanitize("kcfi")))
uint64_t *pgtable_entry(uint64_t pgd, uint64_t va)
{
    uint64_t pxd_bits = page_shift - 3;
    uint64_t pxd_ptrs = 1UL << pxd_bits;
    uint64_t pxd_va = pgd;
    uint64_t pxd_pa = kh_virt_to_phys(pxd_va);
    uint64_t pxd_entry_va = 0;
    uint64_t block_lv = 0;

    /* Sanity check: pgd and VA must be in kernel address space.
     * Use page_offset (computed from VA_BITS) as the lower bound. */
    uint64_t kva_min = page_offset ? page_offset : 0xffffff8000000000ULL;
    if (pxd_va < kva_min || va < kva_min) {
        logke("pgtable_entry: invalid addr pgd=%llx va=%llx",
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
        uint64_t pxd_shift = (page_shift - 3) * (uint64_t)(4 - lv) + 3;
        uint64_t pxd_index = (va >> pxd_shift) & (pxd_ptrs - 1);
        pxd_entry_va = pxd_va + pxd_index * 8;
        if (!pxd_entry_va)
            return 0;
        uint64_t pxd_desc = *((uint64_t *)pxd_entry_va);
        if ((pxd_desc & 0x3) == 0x3) {
            /* Table descriptor */
            pxd_pa = pxd_desc & (((1UL << (48 - page_shift)) - 1) << page_shift);
        } else if ((pxd_desc & 0x3) == 0x1) {
            /* Block descriptor */
            uint64_t block_bits = (uint64_t)(3 - lv) * pxd_bits + page_shift;
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

/* Inline TLB flush using TLBI instruction instead of kernel function pointers
 * to avoid kCFI type mismatch. TLBI VALE1IS flushes the TLB entry for the
 * given VA at EL1 (inner-shareable). */
static inline void kh_flush_tlb_kernel_page(uint64_t va)
{
    /* TLBI VALE1IS operand: bits[43:0] = VA[55:12], bits[63:48] = ASID.
     * Kernel pages use ASID 0. Must mask upper bits to avoid
     * sign-extension of kernel VAs leaking into the ASID field. */
    uint64_t addr = (va >> 12) & ((1ULL << 44) - 1);
    asm volatile("tlbi vale1is, %0" :: "r"(addr) : "memory");
    asm volatile("dsb ish" ::: "memory");
    asm volatile("isb" ::: "memory");
}

void modify_entry_kernel(uint64_t va, uint64_t *entry, uint64_t value)
{
    if (!pte_valid_cont(*entry) && !pte_valid_cont(value)) {
        *entry = value;
        kh_flush_tlb_kernel_page(va);
        return;
    }

    /* Handle contiguous PTE: update all entries in the contiguous group */
    uint64_t table_pa_mask = (((1UL << (48 - page_shift)) - 1) << page_shift);
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

int pgtable_init(void)
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

void modify_entry_kernel(uint64_t va, uint64_t *entry, uint64_t value)
{
    (void)va;
    (void)entry;
    (void)value;
}

#endif /* KMOD_FREESTANDING */
