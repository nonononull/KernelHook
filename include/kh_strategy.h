/* include/kh_strategy.h */
/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef KH_STRATEGY_H
#define KH_STRATEGY_H

#include <types.h>

/* Maximum length of a strategy or capability name string in CSV-parsed
 * module parameters (e.g. kh_disable="cap:name,..."). Reserved for
 * Task 6's parse helpers; unused at this point. */
#define KH_STRATEGY_NAME_MAX 32

typedef int (*kh_strategy_fn_t)(void *out, size_t out_size);

struct kh_strategy {
    const char       *capability;
    const char       *name;
    int               priority;        /* 0 = highest */
    bool              enabled;
    bool              is_fallback;     /* if true, skip in consistency check
                                          (best-effort heuristic that is not
                                          expected to agree byte-for-byte with
                                          the natural winner — e.g. walker
                                          approximations, current-task fallbacks) */
    kh_strategy_fn_t  resolve;
    size_t            out_size;
};

/* Section where every KH_STRATEGY_DECLARE instance is emitted at link
 * time.  Linker-provided __start_/__stop_ symbols make the section
 * iterable (ELF).  Mach-O rejects single-component section names, so
 * the host test build uses the segmented form "__DATA,__kh_strategies".
 * The kernel module link honors ".kh_strategies" via kmod/lds/kmod.lds. */
#ifdef __APPLE__
#define KH_STRATEGY_SECTION "__DATA,__kh_strategies"
#else
#define KH_STRATEGY_SECTION ".kh_strategies"
#endif

/* In userspace Debug builds, AddressSanitizer inserts redzone padding between
 * adjacent globals in the same section, breaking pointer-stride iteration.
 * no_sanitize("address") on each declared global suppresses that padding so
 * KH_STRAT_ITER_BEGIN..END can walk entries as a flat array.
 * This attribute is a no-op in kernel (freestanding / kbuild) builds. */
#ifdef __USERSPACE__
#define KH_STRATEGY_ASAN_ATTR __attribute__((no_sanitize("address")))
#else
#define KH_STRATEGY_ASAN_ATTR
#endif

#define KH_STRATEGY_DECLARE(cap, nm, prio, fn, outsize)                \
    static struct kh_strategy __kh_strat_##cap##_##nm                  \
    __used __section(KH_STRATEGY_SECTION) KH_STRATEGY_ASAN_ATTR = {   \
        .capability = #cap,                                            \
        .name = #nm,                                                   \
        .priority = (prio),                                            \
        .enabled = true,                                               \
        .is_fallback = false,                                          \
        .resolve = (fn),                                               \
        .out_size = (outsize),                                         \
    }

/* _FALLBACK variant: strategy is a best-effort heuristic that may
 * legitimately return a different value from the natural winner on
 * some kernels. Excluded from kh_consistency_check comparisons so
 * expected divergence does not taint the kernel. Still participates
 * in normal resolve-fallback chain. */
#define KH_STRATEGY_DECLARE_FALLBACK(cap, nm, prio, fn, outsize)       \
    static struct kh_strategy __kh_strat_##cap##_##nm                  \
    __used __section(KH_STRATEGY_SECTION) KH_STRATEGY_ASAN_ATTR = {   \
        .capability = #cap,                                            \
        .name = #nm,                                                   \
        .priority = (prio),                                            \
        .enabled = true,                                               \
        .is_fallback = true,                                           \
        .resolve = (fn),                                               \
        .out_size = (outsize),                                         \
    }

/* Capability expectation types. Used by kh_strategy_run_consistency_check
 * to decide whether to compare strategy outputs. Mirrors the types in
 * tests/golden/strategy_matrix/expectations.yaml. */
enum kh_cap_expectation {
    KH_EXPECT_UNKNOWN = 0,  /* capability not in table; default to EQUAL */
    KH_EXPECT_EQUAL,        /* scalar_all_strategies_equal */
    KH_EXPECT_ANY_VALID,    /* function_pointer_any_valid */
    KH_EXPECT_MAY_VARY,     /* probed_may_vary */
    KH_EXPECT_PROCEDURAL,   /* procedural_only */
};

/* Public API */
int  kh_strategy_init(void);
int  kh_strategy_resolve(const char *capability, void *out, size_t out_size);
void kh_strategy_set_enabled(const char *cap, const char *name, bool enabled);
/* `cap` and `name` must point to string literals or otherwise live
 * for the module's lifetime — the registry stores the pointer, does
 * not copy. Pass NULL as name to clear a prior force. */
void kh_strategy_force(const char *cap, const char *name);
/* `cap` and `name` storage lifetime same as kh_strategy_force. `count`
 * is the number of upcoming resolve attempts to inject a failure on. */
void kh_strategy_inject_fail(const char *cap, const char *name, int count);
int  kh_strategy_run_consistency_check(void);                /* returns mismatch count; 0 = all agree */
void kh_strategy_dump(void);                                 /* dmesg all slots */
void kh_strategy_for_each(const char *cap,
                          void (*fn)(const char *name, void *ctx),
                          void *ctx);

/* Error codes returned by kh_strategy_resolve */
#define KH_STRAT_OK        0
#define KH_STRAT_ENODATA   (-61)   /* no strategy succeeded */
#define KH_STRAT_EDEADLK   (-35)   /* recursive cycle detected */

#endif /* KH_STRATEGY_H */
