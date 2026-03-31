/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2026 bmax121.
 * ARM64 page table walking and permission modification.
 */

#ifndef _KP_ARM64_PGTABLE_H_
#define _KP_ARM64_PGTABLE_H_

#include <ktypes.h>

/* PTE attribute bits */
#define PTE_RDONLY      (1UL << 7)  /* AP[2] read-only */
#define PTE_DBM         (1UL << 51) /* Dirty Bit Modifier */
#define PTE_VALID       (1UL << 0)
#define PTE_TYPE_PAGE   (3UL << 0)
#define PTE_CONT        (1UL << 52) /* Contiguous PTE */

/* Contiguous PTE support */
#define CONT_PTES       16
#define CONT_PTE_MASK   (~((uint64_t)(CONT_PTES - 1) << 12))

/* Runtime page configuration (set during pgtable_init) */
extern uint64_t page_shift;
extern uint64_t page_size;
extern uint64_t page_level;

/* Resolved kernel function pointers */
typedef void (*flush_tlb_kernel_page_func_t)(uint64_t addr);
typedef void (*flush_tlb_kernel_range_func_t)(uint64_t start, uint64_t end);
typedef void (*flush_icache_all_func_t)(void);
typedef void (*flush_icache_range_func_t)(uint64_t start, uint64_t end);
typedef void (*flush_dcache_area_func_t)(void *addr, size_t len);

extern flush_tlb_kernel_page_func_t flush_tlb_kernel_page;
extern flush_tlb_kernel_range_func_t flush_tlb_kernel_range;
extern flush_icache_all_func_t flush_icache_all;
extern flush_icache_range_func_t flush_icache_range;
extern flush_dcache_area_func_t __flush_dcache_area;

/* Address translation.
 * kimage_voffset: kernel image VA - PA (for kernel text mapping).
 * phys_offset:    PHYS_OFFSET (memstart_addr, DRAM base PA).
 * page_offset:    PAGE_OFFSET (linear map VA base, computed from VA_BITS).
 *
 * For page table walking we use the linear mapping (PAGE_OFFSET),
 * not the kernel image mapping (kimage_voffset). */
extern uint64_t kimage_voffset;
extern uint64_t phys_offset;
extern uint64_t page_offset;

static inline uint64_t virt_to_phys(uint64_t va)
{
    return va - page_offset + phys_offset;
}

static inline uint64_t phys_to_virt(uint64_t pa)
{
    return pa - phys_offset + page_offset;
}

/* PTE helpers */
static inline int pte_valid_cont(uint64_t pte)
{
    return (pte & (PTE_VALID | PTE_CONT)) == (PTE_VALID | PTE_CONT);
}

/* Page table operations */
int pgtable_init(void);
uint64_t *pgtable_entry(uint64_t pgd, uint64_t va);
uint64_t *pgtable_entry_kernel(uint64_t va);
void modify_entry_kernel(uint64_t va, uint64_t *entry, uint64_t value);

#endif /* _KP_ARM64_PGTABLE_H_ */
