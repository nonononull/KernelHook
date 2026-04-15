/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2026 bmax121.
 * ARM64 page table walking and permission modification.
 *
 * Dual-path header:
 * - Freestanding (Mode A): we reconstruct arm64 constants and expose
 *   runtime-resolved function pointers, because we have no access to
 *   asm/ headers.
 * - Kbuild (Mode C): we pull real kernel headers. PTE_RDONLY / PTE_DBM
 *   / etc. come from asm/pgtable-hwdef.h with the same hardware-fixed
 *   values. `page_size` is aliased to kernel's compile-time PAGE_SIZE
 *   so inline.c consumers keep working without source changes.
 */

#ifndef _KP_ARM64_PGTABLE_H_
#define _KP_ARM64_PGTABLE_H_

#include <types.h>

/* In userspace builds none of the kernel PTE/TLB infrastructure is
 * available or needed — inline.c gates all write_insts_* functions
 * behind #ifndef __USERSPACE__. Expose only <types.h> above. */
#ifndef __USERSPACE__

#ifdef KMOD_FREESTANDING

/* PTE attribute bits (duplicate arm64 hardware constants — values are
 * architecturally fixed) */
#define PTE_RDONLY      (1UL << 7)  /* AP[2] read-only */
#define PTE_DBM         (1UL << 51) /* Dirty Bit Modifier */
#define PTE_VALID       (1UL << 0)
#define PTE_TYPE_PAGE   (3UL << 0)
#define PTE_CONT        (1UL << 52) /* Contiguous PTE */

/* Contiguous PTE support */
#define CONT_PTES       16
#define CONT_PTE_MASK   (~((uint64_t)(CONT_PTES - 1) << 12))

/* Runtime page configuration (set during kh_pgtable_init) */
extern uint64_t page_shift;
extern uint64_t page_size;
extern uint64_t page_level;

/* Resolved kernel function pointers (freestanding only — runtime ksyms) */
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
 * KernelHook-private names to avoid name collisions with kernel's
 * real virt_to_phys/phys_to_virt (which take void*, not uint64_t).
 * Only pgtable.c itself uses these — no external callers.
 */
extern uint64_t kimage_voffset;
extern uint64_t phys_offset;
extern uint64_t page_offset;

static inline uint64_t kh_virt_to_phys(uint64_t va)
{
    return va - page_offset + phys_offset;
}

static inline uint64_t kh_phys_to_virt(uint64_t pa)
{
    return pa - phys_offset + page_offset;
}

/* PTE helpers */
static inline int pte_valid_cont(uint64_t pte)
{
    return (pte & (PTE_VALID | PTE_CONT)) == (PTE_VALID | PTE_CONT);
}

#else /* !KMOD_FREESTANDING — Mode C (real kernel headers) */

#include <linux/types.h>
#include <asm/pgtable.h>
#include <asm/pgtable-hwdef.h>
#include <asm/tlbflush.h>
#include <asm/cacheflush.h>
#include <asm/set_memory.h>

/* In freestanding mode `page_size` is a runtime-detected uint64_t
 * variable. In kbuild mode kernel provides compile-time PAGE_SIZE —
 * alias it so consumers like inline.c write_insts_at() don't need
 * per-mode conditionals. */
#define page_size ((uint64_t)PAGE_SIZE)
#define page_shift ((uint64_t)PAGE_SHIFT)

#endif /* KMOD_FREESTANDING */

/* Page table operations — declared in both modes.
 * Freestanding: implemented in pgtable.c via raw walking.
 * Kbuild: stubbed in pgtable.c (kh_pgtable_init returns 0; the PTE
 * modification path in inline.c is disabled by forcing
 * kh_write_mode = 1 to use kernel's set_memory_rw/ro/x API). */
int kh_pgtable_init(void);
uint64_t *pgtable_entry(uint64_t pgd, uint64_t va);
uint64_t *pgtable_entry_kernel(uint64_t va);
uint64_t pgtable_phys_kernel(uint64_t va);
void modify_entry_kernel(uint64_t va, uint64_t *entry, uint64_t value);

/* Flush TLB for a single kernel VA. Matches KernelPatch
 * kernel/include/pgtable.h flush_tlb_kernel_page:
 *   pre-TLBI dsb(ishst) to order the preceding PTE store,
 *   tlbi vaale1is (VA All ASIDs, EL1, Inner Shareable — ASID-agnostic,
 *   correct for kernel global pages),
 *   post-TLBI dsb(ish) + isb() to complete the TLB maintenance. */
static inline void kh_flush_tlb_kernel_page(uint64_t va)
{
    uint64_t addr = (va >> 12) & ((1ULL << 44) - 1);
    asm volatile("dsb ishst" ::: "memory");
    asm volatile("tlbi vaale1is, %0" :: "r"(addr) : "memory");
    asm volatile("dsb ish" ::: "memory");
    asm volatile("isb" ::: "memory");
}

#endif /* !__USERSPACE__ */

#endif /* _KP_ARM64_PGTABLE_H_ */
