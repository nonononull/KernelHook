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
#include <linux/string.h>
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

    /* Cache hit — serve without re-running strategies.
     * Require exact size match: if caller asks for a different size than what
     * was cached, treat as miss to avoid silent partial reads. */
    if (c->cached && out_size == c->cache_size && out_size <= sizeof(c->cache_buf)) {
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
        /* Only cache when result fits in cache_buf; oversize results succeed
         * but skip caching — next resolve re-runs strategies. */
        if (out_size <= sizeof(c->cache_buf)) {
            c->cached     = true;
            c->cache_size = out_size;
            memcpy(c->cache_buf, out, out_size);
        }
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
    int mismatches = 0;

    for (int ci = 0; ci < g_cap_count; ci++) {
        struct cap_slot *c = &g_caps[ci];
        uint8_t first_buf[64];
        size_t first_size = 0;
        bool have_first = false;

        for (int i = 0; i < c->num; i++) {
            struct kh_strategy *s = c->by_prio[i];
            if (!s->enabled)
                continue;
            /* Guard against stack overflow: skip strategies whose out_size
             * exceeds the local buf capacity (matches cache-write guard). */
            if (s->out_size > sizeof(first_buf)) {
                pr_warn("[kh_strategy] consistency: %s:%s out_size %zu exceeds buf",
                        c->name, s->name, s->out_size);
                continue;
            }
            uint8_t buf[64];
            int rc = s->resolve(buf, s->out_size);
            if (rc != 0)
                continue;
            if (!have_first) {
                memcpy(first_buf, buf, s->out_size);
                first_size = s->out_size;
                have_first = true;
            } else if (first_size != s->out_size ||
                       memcmp(first_buf, buf, s->out_size) != 0) {
                pr_warn("[kh_strategy] consistency mismatch in %s: %s diverged",
                        c->name, s->name);
                mismatches++;
                break;  /* one mismatch per cap */
            }
        }
    }
    return mismatches;
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

/* ---- Kernel-only module-parameter CSV parsers and debugfs interface ----
 *
 * These helpers are compiled only in kernel builds (freestanding and kbuild).
 * Each parser decodes a comma-separated list of "capability:strategyname"
 * tokens (or "capability:strategyname:count" for inject_fail) and calls the
 * appropriate registry mutator.
 *
 * Called from kh_strategy_boot() immediately after kh_strategy_init().
 * The `csv` pointer is the raw module_param string; it is never NULL-checked
 * after entry (checked at top of each function).
 */
#ifndef __USERSPACE__
/* linux/string.h is already included above for the kernel build path.
 * linux/kernel.h provides kstrtol for the inject_fail parser.
 * linux/debugfs.h provides debugfs_create_dir/_file/_remove_recursive and
 *   the ABI-safe struct file_operations shim (4 stable fields + padding).
 * linux/uaccess.h provides copy_from_user/copy_to_user and __user annotation.
 * linux/module.h provides THIS_MODULE. */
#include <linux/kernel.h>
#include <linux/debugfs.h>
#include <linux/uaccess.h>
#include <linux/module.h>

/*
 * kh_strategy_apply_disable_list — parse "cap:name,cap:name,..." and
 * call kh_strategy_set_enabled(cap, name, false) for each token.
 */
void kh_strategy_apply_disable_list(const char *csv)
{
    if (!csv || !*csv)
        return;

    char buf[256];
    strlcpy(buf, csv, sizeof(buf));

    char *p = buf;
    while (p && *p) {
        char *comma = strchr(p, ',');
        if (comma)
            *comma = '\0';

        char *colon = strchr(p, ':');
        if (colon) {
            *colon = '\0';
            kh_strategy_set_enabled(p, colon + 1, false);
        }

        p = comma ? comma + 1 : NULL;
    }
}

/*
 * kh_strategy_apply_force_list — parse "cap:name,cap:name,..." and
 * call kh_strategy_force(cap, name) for each token.
 * Pass name "none" to clear a prior force (maps to NULL).
 */
void kh_strategy_apply_force_list(const char *csv)
{
    if (!csv || !*csv)
        return;

    char buf[256];
    strlcpy(buf, csv, sizeof(buf));

    char *p = buf;
    while (p && *p) {
        char *comma = strchr(p, ',');
        if (comma)
            *comma = '\0';

        char *colon = strchr(p, ':');
        if (colon) {
            *colon = '\0';
            /* Empty name after colon (e.g. "cap:" with nothing) clears a prior force — maps to NULL. */
            const char *name = (*(colon + 1) == '\0') ? NULL : colon + 1;
            kh_strategy_force(p, name);
        }

        p = comma ? comma + 1 : NULL;
    }
}

/*
 * kh_strategy_apply_inject_list — parse "cap:name:count,..." and
 * call kh_strategy_inject_fail(cap, name, count) for each token.
 * Format: capability:strategyname:decimal_count
 * Tokens missing the second colon or with count=0 are silently ignored.
 */
void kh_strategy_apply_inject_list(const char *csv)
{
    if (!csv || !*csv)
        return;

    char buf[256];
    strlcpy(buf, csv, sizeof(buf));

    char *p = buf;
    while (p && *p) {
        char *comma = strchr(p, ',');
        if (comma)
            *comma = '\0';

        /* Expect cap:name:count */
        char *colon1 = strchr(p, ':');
        if (colon1) {
            *colon1 = '\0';
            char *colon2 = strchr(colon1 + 1, ':');
            if (colon2) {
                *colon2 = '\0';
                long count = 0;
                if (kstrtol(colon2 + 1, 10, &count) == 0 && count > 0)
                    kh_strategy_inject_fail(p, colon1 + 1, (int)count);
            }
        }

        p = comma ? comma + 1 : NULL;
    }
}

/* ---- debugfs interface (kernel-mode only) ----
 *
 * ABI-safe design notes: we ONLY use the 4 stable LP64 ARM64 fields of struct
 * file_operations (owner @ 0, llseek @ 8, read @ 16, write @ 24). These are
 * frozen ABI in every Linux kernel since the introduction of file_operations
 * — re-ordering them would break every module ever built. Late fields
 * (open / release / iopoll / splice_eof / uring_cmd / etc.) shift between
 * 5.10 and 6.12; we avoid them entirely.
 *
 * Mounted at /sys/kernel/debug/kernelhook/:
 *   strategies  (0444 read)  — dumps all capabilities + strategies, one per line
 *   disable     (0200 write) — "cap:name" disables a strategy
 *   enable      (0200 write) — "cap:name" re-enables a strategy
 *   force       (0200 write) — "cap:name" forces a strategy; "cap:" clears force
 *
 * Read endpoint ("strategies"): direct .read handler with lazy snapshot +
 * *ppos slicing (no seq_file / single_open).
 * Write endpoints (disable/enable/force): direct .write handler.
 *
 * kh_strategy_debugfs_cleanup() must be called from module_exit to avoid an
 * Oops when a userspace process accesses the file after rmmod.
 */

static struct dentry *kh_debug_dir;

/* Lazy-built snapshot of the strategies table.  Rebuilt on first read at
 * *ppos == 0.  Multiple concurrent reads race on this global buffer —
 * acceptable for a debug interface. */
#define KH_STRATEGIES_BUFSZ 4096
static char kh_strategies_buf[KH_STRATEGIES_BUFSZ];
static size_t kh_strategies_len;

static void rebuild_strategies_buf(void)
{
    size_t off = 0;
    int n;

    for (int ci = 0; ci < g_cap_count && off < sizeof(kh_strategies_buf); ci++) {
        struct cap_slot *c = &g_caps[ci];
        for (int i = 0; i < c->num && off < sizeof(kh_strategies_buf); i++) {
            struct kh_strategy *s = c->by_prio[i];
            const char *winner = (c->last_winner && !strcmp(c->last_winner, s->name))
                                 ? "Y" : "";
            n = snprintf(kh_strategies_buf + off,
                         sizeof(kh_strategies_buf) - off,
                         "%-32s %-24s prio=%d enabled=%d winner=%s\n",
                         c->name, s->name, s->priority, s->enabled, winner);
            if (n < 0)
                break;
            if ((size_t)n >= sizeof(kh_strategies_buf) - off) {
                off = sizeof(kh_strategies_buf);
                break;
            }
            off += n;
        }
    }
    kh_strategies_len = off;
}

static ssize_t strategies_read(struct file *f, char __user *u,
                               size_t len, loff_t *ppos)
{
    size_t avail, to_copy;
    (void)f;
    if (*ppos == 0)
        rebuild_strategies_buf();
    if (*ppos >= (loff_t)kh_strategies_len)
        return 0;  /* EOF */
    avail = kh_strategies_len - (size_t)*ppos;
    to_copy = len < avail ? len : avail;
    if (copy_to_user(u, kh_strategies_buf + *ppos, to_copy))
        return -EFAULT;
    *ppos += to_copy;
    return (ssize_t)to_copy;
}

static const struct file_operations strategies_fops = {
    .owner = THIS_MODULE,
    .read  = strategies_read,
};

/* Helper: parse "cap:name" from a write buffer. Strips trailing newline.
 * Returns 0 on success with *cap and *name pointing into buf
 * (NUL-terminated in place); -EINVAL on parse failure. */
static int parse_cap_name(char *buf, size_t len, char **cap, char **name)
{
    char *colon;
    if (len > 0 && buf[len - 1] == '\n')
        buf[--len] = '\0';
    colon = strchr(buf, ':');
    if (!colon)
        return -EINVAL;
    *colon = '\0';
    *cap  = buf;
    *name = colon + 1;
    return 0;
}

static ssize_t disable_write(struct file *f, const char __user *u,
                             size_t len, loff_t *ppos)
{
    char buf[256];
    char *cap, *name;
    int rc;
    (void)f; (void)ppos;
    if (len >= sizeof(buf)) return -EINVAL;
    if (copy_from_user(buf, u, len)) return -EFAULT;
    buf[len] = '\0';
    rc = parse_cap_name(buf, len, &cap, &name);
    if (rc) return rc;
    kh_strategy_set_enabled(cap, name, false);
    return (ssize_t)len;
}

static ssize_t enable_write(struct file *f, const char __user *u,
                            size_t len, loff_t *ppos)
{
    char buf[256];
    char *cap, *name;
    int rc;
    (void)f; (void)ppos;
    if (len >= sizeof(buf)) return -EINVAL;
    if (copy_from_user(buf, u, len)) return -EFAULT;
    buf[len] = '\0';
    rc = parse_cap_name(buf, len, &cap, &name);
    if (rc) return rc;
    kh_strategy_set_enabled(cap, name, true);
    return (ssize_t)len;
}

static ssize_t force_write(struct file *f, const char __user *u,
                           size_t len, loff_t *ppos)
{
    char buf[256];
    char *cap, *name;
    int rc;
    (void)f; (void)ppos;
    if (len >= sizeof(buf)) return -EINVAL;
    if (copy_from_user(buf, u, len)) return -EFAULT;
    buf[len] = '\0';
    rc = parse_cap_name(buf, len, &cap, &name);
    if (rc) return rc;
    /* Empty name (e.g. "cap:") clears a prior force — maps to NULL. */
    kh_strategy_force(cap, (*name == '\0') ? NULL : name);
    return (ssize_t)len;
}

static const struct file_operations disable_fops = {
    .owner = THIS_MODULE, .write = disable_write,
};
static const struct file_operations enable_fops = {
    .owner = THIS_MODULE, .write = enable_write,
};
static const struct file_operations force_fops = {
    .owner = THIS_MODULE, .write = force_write,
};

void kh_strategy_debugfs_init(void)
{
    kh_debug_dir = debugfs_create_dir("kernelhook", NULL);
    if (IS_ERR_OR_NULL(kh_debug_dir)) {
        kh_debug_dir = NULL;
        return;
    }
    debugfs_create_file("strategies", 0444, kh_debug_dir, NULL, &strategies_fops);
    debugfs_create_file("disable",    0200, kh_debug_dir, NULL, &disable_fops);
    debugfs_create_file("enable",     0200, kh_debug_dir, NULL, &enable_fops);
    debugfs_create_file("force",      0200, kh_debug_dir, NULL, &force_fops);
}

void kh_strategy_debugfs_cleanup(void)
{
    if (kh_debug_dir) {
        debugfs_remove_recursive(kh_debug_dir);
        kh_debug_dir = NULL;
    }
}

#endif /* __USERSPACE__ */
