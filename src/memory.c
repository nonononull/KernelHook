/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2026 bmax121.
 * Memory management: bitmap allocator with separate ROX and RW pools.
 */

#include <types.h>
#include <memory.h>
#include <hook.h>
#include <kh_log.h>

/* Pool configuration */
#define ROX_POOL_SIZE       (1024 * 1024)   /* 1MB */
#define RW_POOL_SIZE        (512 * 1024)    /* 512KB */
#define BLOCK_SIZE          64              /* 64 bytes per block */

#define ROX_TOTAL_BLOCKS    (ROX_POOL_SIZE / BLOCK_SIZE)
#define RW_TOTAL_BLOCKS     (RW_POOL_SIZE / BLOCK_SIZE)

#define ROX_BITMAP_SIZE     ((ROX_TOTAL_BLOCKS + 7) / 8)
#define RW_BITMAP_SIZE      ((RW_TOTAL_BLOCKS + 7) / 8)

/* Cached page size, set once during init */
static uintptr_t hmem_page_size = 4096;

/* Page alignment helpers */
#define PAGE_ALIGN_DOWN(addr) ((addr) & ~(hmem_page_size - 1))
#define PAGE_ALIGN_UP(addr)   (((addr) + hmem_page_size - 1) & ~(hmem_page_size - 1))
#define PAGES_IN_RANGE(start, end) ((int)(((end) - (start)) / hmem_page_size))

/* ---- bitmap_pool_t ---- */

typedef struct {
    uintptr_t pool_base;
    uintptr_t pool_size;
    uint8_t *bitmap;
    uint32_t total_blocks;
    uint32_t used_blocks;
    uint32_t block_size;
    hook_mem_ops_t ops;
} bitmap_pool_t;

/* Static pools and their bitmaps */
static bitmap_pool_t g_rox_pool;
static bitmap_pool_t g_rw_pool;

static uint8_t rox_bitmap[ROX_BITMAP_SIZE];
static uint8_t rw_bitmap[RW_BITMAP_SIZE];

/* ---- Origin-address lookup table ---- */

#define ORIGIN_MAP_MAX 128

struct origin_map_entry {
    uintptr_t origin_addr;
    void *rox_ptr;
};

static struct origin_map_entry origin_map[ORIGIN_MAP_MAX];
static int32_t origin_map_count = 0;

/* ---- Bit operations ---- */

static inline void bitmap_set(uint8_t *bm, uint32_t bit)
{
    bm[bit / 8] |= (uint8_t)(1 << (bit % 8));
}

static inline void bitmap_clear(uint8_t *bm, uint32_t bit)
{
    bm[bit / 8] &= (uint8_t)~(1 << (bit % 8));
}

static inline int bitmap_test(const uint8_t *bm, uint32_t bit)
{
    return (bm[bit / 8] >> (bit % 8)) & 1;
}

/* ---- Bitmap allocator core ---- */

static int bitmap_find_free(bitmap_pool_t *pool, uint32_t blocks_needed)
{
    uint32_t consecutive = 0;
    int start = -1;
    uint32_t total = pool->total_blocks;
    const uint8_t *bm = pool->bitmap;

    for (uint32_t i = 0; i < total; ) {
        /* Fast skip: if current byte is fully used, skip 8 bits at once */
        if (consecutive == 0 && (i & 7) == 0 && i + 8 <= total && bm[i / 8] == 0xFF) {
            i += 8;
            continue;
        }
        if (!bitmap_test(bm, i)) {
            if (consecutive == 0)
                start = (int)i;
            consecutive++;
            if (consecutive >= blocks_needed)
                return start;
        } else {
            consecutive = 0;
            start = -1;
        }
        i++;
    }
    return -1;
}

static void *bitmap_alloc(bitmap_pool_t *pool, size_t size)
{
    if (!pool->pool_base || size == 0)
        return NULL;

    uint32_t blocks_needed = (uint32_t)((size + pool->block_size - 1) / pool->block_size);
    int start = bitmap_find_free(pool, blocks_needed);
    if (start < 0)
        return NULL;

    for (uint32_t i = 0; i < blocks_needed; i++)
        bitmap_set(pool->bitmap, (uint32_t)start + i);

    pool->used_blocks += blocks_needed;

    void *ptr = (void *)(pool->pool_base + (uintptr_t)start * pool->block_size);
    return ptr;
}

static void bitmap_free(bitmap_pool_t *pool, void *ptr, size_t size)
{
    if (!pool->pool_base || !ptr || size == 0)
        return;

    uintptr_t addr = (uintptr_t)ptr;
    if (addr < pool->pool_base || addr >= pool->pool_base + pool->pool_size)
        return;

    uint32_t start_block = (uint32_t)((addr - pool->pool_base) / pool->block_size);
    uint32_t blocks = (uint32_t)((size + pool->block_size - 1) / pool->block_size);

    for (uint32_t i = 0; i < blocks; i++)
        bitmap_clear(pool->bitmap, start_block + i);

    if (pool->used_blocks >= blocks)
        pool->used_blocks -= blocks;
    else
        pool->used_blocks = 0;
}

/* ---- Pool init/cleanup helpers ---- */

KCFI_EXEMPT
static int pool_init(bitmap_pool_t *pool, uint8_t *bitmap, uint32_t bitmap_size,
                     uintptr_t pool_size, const hook_mem_ops_t *ops, const char *label)
{
    if (!ops || !ops->alloc) {
        pr_err("hmem: %s pool has no allocator", label);
        return -1;
    }

    pool->ops = *ops;

    void *base = ops->alloc(pool_size);
    if (!base) {
        pr_err("hmem: failed to allocate %s pool", label);
        return -1;
    }

    /* Pool pages from mmap(MAP_ANONYMOUS) are already zeroed.
     * Only the bitmap needs clearing (it's a static array that may
     * contain stale data from a previous init/cleanup cycle). */
    __builtin_memset(bitmap, 0, bitmap_size);

    /* Ensure ROX pool has correct permissions (RX). */
    if (ops->set_memory_ro && ops->set_memory_x) {
        uint32_t numpages = (uint32_t)(pool_size / hmem_page_size);
        ops->set_memory_ro((uintptr_t)base, numpages);
        ops->set_memory_x((uintptr_t)base, numpages);
    }

    pool->pool_base = (uintptr_t)base;
    pool->pool_size = pool_size;
    pool->bitmap = bitmap;
    pool->total_blocks = (uint32_t)(pool_size / BLOCK_SIZE);
    pool->used_blocks = 0;
    pool->block_size = BLOCK_SIZE;

    pr_info("hmem: %s pool at 0x%llx, size %llu", label,
          (unsigned long long)pool->pool_base, (unsigned long long)pool_size);
    return 0;
}

KCFI_EXEMPT
static void pool_cleanup(bitmap_pool_t *pool)
{
    if (!pool->pool_base)
        return;
    if (pool->ops.free)
        pool->ops.free((void *)pool->pool_base);
    pool->pool_base = 0;
}

/* ---- Public API ---- */

int hook_mem_init(const hook_mem_ops_t *rox_ops, const hook_mem_ops_t *rw_ops, uintptr_t page_sz)
{
    if (page_sz)
        hmem_page_size = page_sz;

    int rc = pool_init(&g_rox_pool, rox_bitmap, ROX_BITMAP_SIZE,
                       ROX_POOL_SIZE, rox_ops, "ROX");
    if (rc)
        return rc;

    rc = pool_init(&g_rw_pool, rw_bitmap, RW_BITMAP_SIZE,
                   RW_POOL_SIZE, rw_ops, "RW");
    if (rc) {
        pool_cleanup(&g_rox_pool);
        return rc;
    }

    pr_info("hmem: memory manager initialized");
    return 0;
}

void hook_mem_cleanup(void)
{
    pool_cleanup(&g_rox_pool);
    pool_cleanup(&g_rw_pool);
    origin_map_count = 0;
    pr_info("hmem: memory manager cleaned up");
}

uintptr_t hook_mem_rox_pool_base(void)
{
    return g_rox_pool.pool_base;
}

uintptr_t hook_mem_rox_pool_size(void)
{
    return g_rox_pool.pool_size;
}

void *hook_mem_alloc_rox(size_t size)
{
    return bitmap_alloc(&g_rox_pool, size);
}

void *hook_mem_alloc_rw(size_t size)
{
    return bitmap_alloc(&g_rw_pool, size);
}

void hook_mem_free_rox(void *ptr, size_t size)
{
    bitmap_free(&g_rox_pool, ptr, size);
}

void hook_mem_free_rw(void *ptr, size_t size)
{
    bitmap_free(&g_rw_pool, ptr, size);
}

KCFI_EXEMPT
int hook_mem_rox_write_enable(void *ptr, size_t size)
{
    if (!ptr || size == 0)
        return -1;

    uintptr_t addr = (uintptr_t)ptr;
    uintptr_t ps = PAGE_ALIGN_DOWN(addr);
    uintptr_t pe = PAGE_ALIGN_UP(addr + size);
    int numpages = PAGES_IN_RANGE(ps, pe);

    if (g_rox_pool.ops.set_memory_rw)
        return g_rox_pool.ops.set_memory_rw(ps, numpages);

    pr_warn("hmem: set_memory_rw not available, fallback needed");
    return -1;
}

KCFI_EXEMPT
int hook_mem_rox_write_disable(void *ptr, size_t size)
{
    if (!ptr || size == 0)
        return -1;

    uintptr_t addr = (uintptr_t)ptr;
    uintptr_t ps = PAGE_ALIGN_DOWN(addr);
    uintptr_t pe = PAGE_ALIGN_UP(addr + size);
    int numpages = PAGES_IN_RANGE(ps, pe);

    int rc = 0;

    if (g_rox_pool.ops.set_memory_ro) {
        rc = g_rox_pool.ops.set_memory_ro(ps, numpages);
        if (rc)
            return rc;
    }

    if (g_rox_pool.ops.set_memory_x) {
        rc = g_rox_pool.ops.set_memory_x(ps, numpages);
        if (rc)
            return rc;
    }

    if (!g_rox_pool.ops.set_memory_ro && !g_rox_pool.ops.set_memory_x) {
        pr_warn("hmem: set_memory_ro/x not available, fallback needed");
        return -1;
    }

    return 0;
}

int hook_mem_register_origin(uintptr_t origin_addr, void *rox_ptr)
{
    if (!origin_addr || !rox_ptr)
        return -1;

    for (int32_t i = 0; i < origin_map_count; i++) {
        if (origin_map[i].origin_addr == origin_addr) {
            origin_map[i].rox_ptr = rox_ptr;
            return 0;
        }
    }

    if (origin_map_count >= ORIGIN_MAP_MAX) {
        pr_warn("hmem: origin map full (%d entries)", ORIGIN_MAP_MAX);
        return -1;
    }

    origin_map[origin_map_count].origin_addr = origin_addr;
    origin_map[origin_map_count].rox_ptr = rox_ptr;
    origin_map_count++;
    return 0;
}

void hook_mem_unregister_origin(uintptr_t origin_addr)
{
    for (int32_t i = 0; i < origin_map_count; i++) {
        if (origin_map[i].origin_addr == origin_addr) {
            /* Swap with last entry */
            origin_map[i] = origin_map[origin_map_count - 1];
            origin_map_count--;
            return;
        }
    }
}

void *hook_mem_get_rox_from_origin(uintptr_t origin_addr)
{
    if (!origin_addr)
        return NULL;

    for (int32_t i = 0; i < origin_map_count; i++) {
        if (origin_map[i].origin_addr == origin_addr)
            return origin_map[i].rox_ptr;
    }
    return NULL;
}

void *hook_mem_get_rw_from_origin(uintptr_t origin_addr)
{
    hook_chain_rox_t *rox = (hook_chain_rox_t *)hook_mem_get_rox_from_origin(origin_addr);
    if (rox && rox->rw)
        return rox->rw;
    return NULL;
}

uint32_t hook_mem_rox_used_blocks(void)
{
    return g_rox_pool.used_blocks;
}

uint32_t hook_mem_rw_used_blocks(void)
{
    return g_rw_pool.used_blocks;
}

