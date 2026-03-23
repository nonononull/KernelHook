/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2026 bmax121.
 */

#ifdef __APPLE__

#include <platform.h>
#include <sys/mman.h>
#include <unistd.h>
#include <libkern/OSCacheControl.h>

uint64_t platform_page_size(void)
{
    return (uint64_t)sysconf(_SC_PAGE_SIZE);
}

void *platform_alloc_rox(uint64_t size)
{
    /* Allocate as RW initially; callers use platform_set_rx to enable exec.
     * MAP_JIT + pthread_jit_write_protect_np requires entitlements that
     * development/unsigned binaries lack, so we use mprotect instead. */
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
    return mprotect((void *)addr, (size_t)size, PROT_READ | PROT_WRITE);
}

int platform_set_ro(uint64_t addr, uint64_t size)
{
    return mprotect((void *)addr, (size_t)size, PROT_READ);
}

int platform_set_rx(uint64_t addr, uint64_t size)
{
    return mprotect((void *)addr, (size_t)size, PROT_READ | PROT_EXEC);
}

void platform_flush_icache(uint64_t addr, uint64_t size)
{
    sys_icache_invalidate((void *)addr, (size_t)size);
}

#endif /* __APPLE__ */
