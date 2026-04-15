/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2026 bmax121.
 *
 * macOS / Apple Silicon platform backend.
 *
 * Code page patching uses vm_remap + VM_FLAGS_OVERWRITE to atomically
 * replace code pages. The ROX pool starts as RW, is transitioned to RX at
 * init, and uses vm_protect(VM_PROT_COPY) + mprotect for write windows.
 */

#ifdef __APPLE__

#include <platform.h>
#include <sys/mman.h>
#include <unistd.h>
#include <mach/mach.h>
#include <libkern/OSCacheControl.h>

uint64_t platform_page_size(void)
{
    static uint64_t cached;
    if (!cached)
        cached = (uint64_t)sysconf(_SC_PAGE_SIZE);
    return cached;
}

/* ROX pool: allocate initially RW so code can be written before the pool
 * is transitioned to RX by hook_mem_init (via set_memory_ro + set_memory_x).
 * Subsequent write windows use vm_protect(VM_PROT_COPY) to get a writable
 * CoW copy of the page, then mprotect back to PROT_READ|PROT_EXEC. */
void *platform_alloc_rox(uint64_t size)
{
    void *p = mmap(NULL, size, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    return (p == MAP_FAILED) ? NULL : p;
}

void *platform_alloc_rw(uint64_t size)
{
    void *p = mmap(NULL, size, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    return (p == MAP_FAILED) ? NULL : p;
}

void platform_free(void *ptr, uint64_t size)
{
    if (ptr)
        munmap(ptr, size);
}

int platform_set_rw(uint64_t addr, uint64_t size)
{
    mach_port_t task = mach_task_self();
    /* VM_PROT_COPY creates a CoW writable copy of the page(s), allowing
     * writes to pages that were previously made read-only or read-execute
     * via mprotect. This is the correct approach for ROX pool pages on
     * macOS — mprotect alone cannot re-add PROT_WRITE after it was removed
     * because max_prot may not include write. VM_PROT_COPY bypasses this. */
    kern_return_t kr = vm_protect(task, (vm_address_t)addr, (vm_size_t)size,
                                  FALSE,
                                  VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
    return kr == KERN_SUCCESS ? 0 : -1;
}

int platform_set_ro(uint64_t addr, uint64_t size)
{
    return mprotect((void *)addr, (size_t)size, PROT_READ);
}

int platform_set_rx(uint64_t addr, uint64_t size)
{
    return mprotect((void *)addr, (size_t)size, PROT_READ | PROT_EXEC);
}

int platform_write_code(uint64_t addr, const void *data, uint64_t size)
{
    uint64_t ps = platform_page_size();
    uint64_t start = addr & ~(ps - 1);
    uint64_t end = (addr + size - 1) & ~(ps - 1);
    uint64_t prot_size = (end - start) + ps;
    uint64_t offset = addr - start;

    mach_port_t task = mach_task_self();

    /* On Apple Silicon, __TEXT pages have max_prot = R|X (no write).
     * Strategy: copy page(s) to a writable scratch buffer, patch there,
     * make scratch R|X, then vm_remap it over the original mapping. */
    void *scratch = mmap(NULL, prot_size, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (scratch == MAP_FAILED)
        return -1;

    __builtin_memcpy(scratch, (void *)start, prot_size);
    __builtin_memcpy((char *)scratch + offset, data, size);

    mprotect(scratch, prot_size, PROT_READ | PROT_EXEC);

    vm_address_t target_addr = (vm_address_t)start;
    vm_prot_t cur_prot, max_prot;
    kern_return_t kr = vm_remap(task, &target_addr, (vm_size_t)prot_size, 0,
                                 VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE,
                                 task, (vm_address_t)scratch, FALSE,
                                 &cur_prot, &max_prot, VM_INHERIT_NONE);

    munmap(scratch, prot_size);
    if (kr != KERN_SUCCESS)
        return -1;

    sys_icache_invalidate((void *)addr, (size_t)size);
    return 0;
}

void platform_flush_icache(uint64_t addr, uint64_t size)
{
    sys_icache_invalidate((void *)addr, (size_t)size);
}

#endif /* __APPLE__ */
