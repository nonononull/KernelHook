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

#define KH_STRATEGY_DECLARE(cap, nm, prio, fn, outsize)                \
    static struct kh_strategy __kh_strat_##cap##_##nm                  \
    __used __section(KH_STRATEGY_SECTION) = {                          \
        .capability = #cap,                                            \
        .name = #nm,                                                   \
        .priority = (prio),                                            \
        .enabled = true,                                               \
        .resolve = (fn),                                               \
        .out_size = (outsize),                                         \
    }

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
int  kh_strategy_run_consistency_check(void);                /* 0 = all caps agree */
void kh_strategy_dump(void);                                 /* dmesg all slots */
void kh_strategy_for_each(const char *cap,
                          void (*fn)(const char *name, void *ctx),
                          void *ctx);

/* Error codes returned by kh_strategy_resolve */
#define KH_STRAT_OK        0
#define KH_STRAT_ENODATA   (-61)   /* no strategy succeeded */
#define KH_STRAT_EDEADLK   (-35)   /* recursive cycle detected */

#endif /* KH_STRATEGY_H */
