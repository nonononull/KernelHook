/* src/kh_strategy.c */
/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Strategy registry: link-time collection, priority sort, resolve loop,
 * per-cap cycle detection, cache-on-first-success.
 *
 * Build modes: shared (__USERSPACE__, kbuild, freestanding)
 * Depends on: kh_strategy.h, kh_log.h, string.h / linux/string.h
 */

#include <kh_strategy.h>
#include <kh_log.h>

#ifdef __USERSPACE__
#include <string.h>
#include <stdio.h>
#else
#include <symbol.h>
#endif

/* ---- Section iteration: platform-specific anchor symbols ----
 *
 * ELF (Linux / kernel module): ld synthesises __start___kh_strategies and
 * __stop___kh_strategies around any section named ".kh_strategies".
 *
 * Mach-O (macOS host build): ld64 does NOT auto-synthesise those symbols.
 * It does, however, synthesise section$start$<seg>$<sect> / section$end$...
 * when those symbols are referenced — see Apple ld(1) "Special Symbols".
 * KH_STRATEGY_SECTION is "__DATA,__kh_strategies" on macOS (defined in
 * kh_strategy.h), so the anchors live in segment __DATA, section
 * __kh_strategies.
 */
#ifdef __APPLE__
extern struct kh_strategy __kh_strat_start
    __asm("section$start$__DATA$__kh_strategies");
extern struct kh_strategy __kh_strat_end
    __asm("section$end$__DATA$__kh_strategies");
#define KH_STRAT_ITER_BEGIN (&__kh_strat_start)
#define KH_STRAT_ITER_END   (&__kh_strat_end)
#else
extern struct kh_strategy __start___kh_strategies[];
extern struct kh_strategy __stop___kh_strategies[];
#define KH_STRAT_ITER_BEGIN (__start___kh_strategies)
#define KH_STRAT_ITER_END   (__stop___kh_strategies)
#endif

#define KH_STRAT_MAX_CAPS    32
#define KH_STRAT_MAX_PER_CAP 8

/* cache_buf holds at most 64 bytes.  uint8_t is portable across all three
 * build modes: types.h typedefs it from <stdint.h> in userspace and from
 * __UINT8_TYPE__ in freestanding; kbuild gets it from <linux/types.h>. */
struct cap_slot {
    const char         *name;
    struct kh_strategy *by_prio[KH_STRAT_MAX_PER_CAP];
    int                 num;
    bool                in_flight;
    bool                cached;
    uint8_t             cache_buf[64];
    size_t              cache_size;
    const char         *last_winner;
    const char         *forced;
    int                 inject_fail_count[KH_STRAT_MAX_PER_CAP];
};

static struct cap_slot g_caps[KH_STRAT_MAX_CAPS];
static int             g_cap_count;
static bool            g_initialized;

/* ---- Internal helpers ---- */

static struct cap_slot *find_cap(const char *name)
{
    for (int i = 0; i < g_cap_count; i++)
        if (!strcmp(g_caps[i].name, name))
            return &g_caps[i];
    return NULL;
}

static struct cap_slot *find_or_create_cap(const char *name)
{
    struct cap_slot *c = find_cap(name);
    if (c)
        return c;
    if (g_cap_count >= KH_STRAT_MAX_CAPS)
        return NULL;
    c = &g_caps[g_cap_count++];
    c->name = name;
    return c;
}

/* Insertion sort: lower priority number = higher priority = earlier in array. */
static void insert_by_priority(struct cap_slot *c, struct kh_strategy *s)
{
    int i;
    for (i = c->num; i > 0 && c->by_prio[i - 1]->priority > s->priority; i--)
        c->by_prio[i] = c->by_prio[i - 1];
    c->by_prio[i] = s;
    c->num++;
}

static int find_strategy_idx(struct cap_slot *c, const char *name)
{
    for (int i = 0; i < c->num; i++)
        if (!strcmp(c->by_prio[i]->name, name))
            return i;
    return -1;
}

/* ---- Public API ---- */

int kh_strategy_init(void)
{
    if (g_initialized)
        return 0;

    g_cap_count = 0;

    for (struct kh_strategy *s = KH_STRAT_ITER_BEGIN;
         s < KH_STRAT_ITER_END; s++) {
        struct cap_slot *c = find_or_create_cap(s->capability);
        if (!c) {
            pr_err("[kh_strategy] capability table full, dropping %s:%s",
                   s->capability, s->name);
            continue;
        }
        if (c->num >= KH_STRAT_MAX_PER_CAP) {
            pr_err("[kh_strategy] too many strategies for %s, dropping %s",
                   s->capability, s->name);
            continue;
        }
        insert_by_priority(c, s);
    }

    g_initialized = true;
    pr_info("[kh_strategy] initialized: %d capabilities", g_cap_count);
    return 0;
}

int kh_strategy_resolve(const char *capability, void *out, size_t out_size)
{
    struct cap_slot *c = find_cap(capability);
    if (!c)
        return KH_STRAT_ENODATA;

    /* Cache hit — serve without re-running strategies. */
    if (c->cached && out_size <= sizeof(c->cache_buf)) {
        memcpy(out, c->cache_buf, c->cache_size);
        return 0;
    }

    /* Recursive call while already resolving this capability = cycle. */
    if (c->in_flight)
        return KH_STRAT_EDEADLK;
    c->in_flight = true;

    int rc = KH_STRAT_ENODATA;

    if (c->forced) {
        /* Forced strategy: bypass ordering and inject_fail. */
        int i = find_strategy_idx(c, c->forced);
        if (i >= 0)
            rc = c->by_prio[i]->resolve(out, out_size);
    } else {
        for (int i = 0; i < c->num; i++) {
            struct kh_strategy *s = c->by_prio[i];
            if (!s->enabled)
                continue;
            if (c->inject_fail_count[i] > 0) {
                c->inject_fail_count[i]--;
                continue;
            }
            rc = s->resolve(out, out_size);
            if (rc == 0) {
                c->last_winner = s->name;
                break;
            }
        }
    }

    if (rc == 0) {
        c->cached     = true;
        c->cache_size = out_size;
        memcpy(c->cache_buf, out, out_size);
    }

    c->in_flight = false;
    /* All non-zero rc values collapse to ENODATA per Task 4 contract. */
    return (rc == 0) ? 0 : KH_STRAT_ENODATA;
}

void kh_strategy_set_enabled(const char *cap, const char *name, bool enabled)
{
    struct cap_slot *c = find_cap(cap);
    if (!c)
        return;
    int i = find_strategy_idx(c, name);
    if (i >= 0)
        c->by_prio[i]->enabled = enabled;
}

void kh_strategy_force(const char *cap, const char *name)
{
    struct cap_slot *c = find_cap(cap);
    if (!c)
        return;
    c->forced = name;   /* NULL clears a prior force */
    c->cached = false;  /* invalidate cache so forced strategy runs */
}

void kh_strategy_inject_fail(const char *cap, const char *name, int count)
{
    struct cap_slot *c = find_cap(cap);
    if (!c)
        return;
    int i = find_strategy_idx(c, name);
    if (i >= 0)
        c->inject_fail_count[i] = count;
}

int kh_strategy_run_consistency_check(void)
{
    /* Stub — Task 5 implements full cross-cap consistency validation. */
    return 0;
}

void kh_strategy_dump(void)
{
    for (int ci = 0; ci < g_cap_count; ci++) {
        struct cap_slot *c = &g_caps[ci];
        for (int i = 0; i < c->num; i++) {
            pr_info("[kh_strategy] %s:%s prio=%d enabled=%d",
                    c->name, c->by_prio[i]->name,
                    c->by_prio[i]->priority, c->by_prio[i]->enabled);
        }
    }
}

void kh_strategy_for_each(const char *cap,
                          void (*fn)(const char *name, void *ctx),
                          void *ctx)
{
    struct cap_slot *c = find_cap(cap);
    if (!c)
        return;
    for (int i = 0; i < c->num; i++)
        fn(c->by_prio[i]->name, ctx);
}
