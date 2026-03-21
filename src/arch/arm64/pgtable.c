/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 * ARM64 page table walking and permission modification.
 */

#include <ktypes.h>
#include <ksyms.h>
#include <log.h>
#include <export.h>
#include <pgtable.h>

/* Runtime page configuration */
uint64_t page_shift = 12; /* Default 4K pages */
uint64_t page_size = 4096;
uint64_t page_level = 4;  /* 4-level by default for 4K pages */

/* Kernel VA layout */
uint64_t kimage_voffset = 0;
uint64_t phys_offset = 0;

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

int pgtable_init(void)
{
    /* Resolve flush functions via ksyms */
    flush_tlb_kernel_page = (flush_tlb_kernel_page_func_t)(uintptr_t)ksyms_lookup_cache("flush_tlb_kernel_page");
    flush_tlb_kernel_range = (flush_tlb_kernel_range_func_t)(uintptr_t)ksyms_lookup_cache("flush_tlb_kernel_range");
    flush_icache_all = (flush_icache_all_func_t)(uintptr_t)ksyms_lookup_cache("flush_icache_all");
    flush_icache_range = (flush_icache_range_func_t)(uintptr_t)ksyms_lookup_cache("flush_icache_range");
    __flush_dcache_area = (flush_dcache_area_func_t)(uintptr_t)ksyms_lookup_cache("__flush_dcache_area");

    if (!__flush_dcache_area) {
        /* Newer kernels renamed it to dcache_clean_inval_poc */
        __flush_dcache_area = (flush_dcache_area_func_t)(uintptr_t)ksyms_lookup_cache("dcache_clean_inval_poc");
    }

    if (!flush_tlb_kernel_page || !__flush_dcache_area) {
        logke("pgtable: failed to resolve required flush symbols");
        return -1;
    }

    /* Resolve kimage_voffset - kernel exports this as a variable */
    uint64_t *voffset_ptr = (uint64_t *)(uintptr_t)ksyms_lookup_cache("kimage_voffset");
    if (voffset_ptr) {
        kimage_voffset = *voffset_ptr;
    } else {
        logke("pgtable: failed to resolve kimage_voffset");
        return -1;
    }

    /* Resolve swapper_pg_dir for kernel page table walks */
    kernel_pgd = ksyms_lookup_cache("swapper_pg_dir");
    if (!kernel_pgd) {
        /* Try init_mm.pgd */
        uint64_t init_mm_addr = ksyms_lookup_cache("init_mm");
        if (init_mm_addr) {
            /* pgd is the first field of mm_struct */
            kernel_pgd = *(uint64_t *)init_mm_addr;
        }
    }
    if (!kernel_pgd) {
        logke("pgtable: failed to resolve kernel pgd");
        return -1;
    }

    /* Determine page size from TCR_EL1.TG0 or use default.
     * In freestanding env, we read page shift from kernel config.
     * For now, try to resolve from kernel exported variable. */
    /* page_shift/page_size/page_level stay at defaults (4K, 4-level)
     * unless explicitly overridden by the caller. */

    logki("pgtable: init ok, pgd=0x%llx voffset=0x%llx page_shift=%llu",
          (unsigned long long)kernel_pgd,
          (unsigned long long)kimage_voffset,
          (unsigned long long)page_shift);

    return 0;
}

uint64_t *pgtable_entry(uint64_t pgd, uint64_t va)
{
    uint64_t pxd_bits = page_shift - 3;
    uint64_t pxd_ptrs = 1UL << pxd_bits;
    uint64_t pxd_va = pgd;
    uint64_t pxd_pa = virt_to_phys(pxd_va);
    uint64_t pxd_entry_va = 0;
    uint64_t block_lv = 0;

    /* Flush dcache for the page table page to ensure we read current PTEs */
    __flush_dcache_area((void *)pxd_va, page_size);

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
            /* Invalid */
            return 0;
        }

        pxd_va = phys_to_virt(pxd_pa);
        if (block_lv)
            break;
    }

    return (uint64_t *)pxd_entry_va;
}
KP_EXPORT_SYMBOL(pgtable_entry);

uint64_t *pgtable_entry_kernel(uint64_t va)
{
    return pgtable_entry(kernel_pgd, va);
}
KP_EXPORT_SYMBOL(pgtable_entry_kernel);

void modify_entry_kernel(uint64_t va, uint64_t *entry, uint64_t value)
{
    if (!pte_valid_cont(*entry) && !pte_valid_cont(value)) {
        *entry = value;
        flush_tlb_kernel_page(va);
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
    if (flush_tlb_kernel_range)
        flush_tlb_kernel_range(va, va + CONT_PTES * page_size);
    else
        flush_tlb_kernel_page(va);
}
KP_EXPORT_SYMBOL(modify_entry_kernel);
