/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2026 bmax121.
 */

#include <ktypes.h>
#include <ksyms.h>
#include <log.h>
#include <export.h>

#define KSYM_CACHE_MAX 64

typedef uint64_t (*kallsyms_lookup_name_func_t)(const char *name);

static kallsyms_lookup_name_func_t kallsyms_lookup_name_fn = NULL;

struct ksym_cache_entry {
    const char *name;
    uint64_t addr;
};

static struct ksym_cache_entry ksym_cache[KSYM_CACHE_MAX];
static int32_t ksym_cache_count = 0;

static int kp_strcmp(const char *a, const char *b)
{
    while (*a && *a == *b) {
        a++;
        b++;
    }
    return (unsigned char)*a - (unsigned char)*b;
}

int ksyms_init(uint64_t kallsyms_lookup_name_addr)
{
    if (!kallsyms_lookup_name_addr)
        return -1;
    kallsyms_lookup_name_fn = (kallsyms_lookup_name_func_t)kallsyms_lookup_name_addr;
    return 0;
}

uint64_t ksyms_lookup(const char *name)
{
    if (!kallsyms_lookup_name_fn || !name)
        return 0;
    return kallsyms_lookup_name_fn(name);
}

/*
 * Cached symbol lookup. NOTE: name must have static lifetime (e.g. string
 * literal) — the pointer is stored directly in the cache without copying.
 */
uint64_t ksyms_lookup_cache(const char *name)
{
    if (!name)
        return 0;

    for (int32_t i = 0; i < ksym_cache_count; i++) {
        if (kp_strcmp(ksym_cache[i].name, name) == 0)
            return ksym_cache[i].addr;
    }

    uint64_t addr = ksyms_lookup(name);
    if (addr && ksym_cache_count < KSYM_CACHE_MAX) {
        ksym_cache[ksym_cache_count].name = name;
        ksym_cache[ksym_cache_count].addr = addr;
        ksym_cache_count++;
    } else if (addr && ksym_cache_count >= KSYM_CACHE_MAX) {
        logkw("ksyms: cache full (%d entries), lookup for '%s' not cached", KSYM_CACHE_MAX, name);
    }

    return addr;
}

KP_EXPORT_SYMBOL(ksyms_init);
KP_EXPORT_SYMBOL(ksyms_lookup);
KP_EXPORT_SYMBOL(ksyms_lookup_cache);
