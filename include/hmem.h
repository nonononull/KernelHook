/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2026 bmax121.
 */

#ifndef _KP_HMEM_H_
#define _KP_HMEM_H_

#include <ktypes.h>

/* External allocator/permission callbacks.
 * alloc must return page-aligned memory. */
typedef struct {
    void *(*alloc)(uint64_t size);
    void (*free)(void *ptr);
    int (*set_memory_rw)(uint64_t addr, int numpages);
    int (*set_memory_ro)(uint64_t addr, int numpages);
    int (*set_memory_x)(uint64_t addr, int numpages);
} hook_mem_ops_t;

int hook_mem_init(const hook_mem_ops_t *rox_ops, const hook_mem_ops_t *rw_ops, uint64_t page_sz);
void hook_mem_cleanup(void);

void *hook_mem_alloc_rox(size_t size);
void *hook_mem_alloc_rw(size_t size);

void hook_mem_free_rox(void *ptr, size_t size);
void hook_mem_free_rw(void *ptr, size_t size);

int hook_mem_rox_write_enable(void *ptr, size_t size);
int hook_mem_rox_write_disable(void *ptr, size_t size);

void hook_mem_register_origin(uint64_t origin_addr, void *rox_ptr);
void hook_mem_unregister_origin(uint64_t origin_addr);
void *hook_mem_get_rox_from_origin(uint64_t origin_addr);
void *hook_mem_get_rw_from_origin(uint64_t origin_addr);

#endif /* _KP_HMEM_H_ */
