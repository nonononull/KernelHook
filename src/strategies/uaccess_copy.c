/* src/strategies/uaccess_copy.c */
/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * SP-7 Capabilities: copy_to_user (this file; Task 14).
 * copy_from_user will be appended in Task 15 (sharing the same file).
 *
 * Each strategy resolves a DIFFERENT function-pointer target for the
 * `copy_to_user` kernel operation, trying naming variants that drift
 * across GKI generations:
 *   prio 0: _copy_to_user          (current GKI export with underscore)
 *   prio 1: copy_to_user           (older export name)
 *   prio 2: __arch_copy_to_user    (arm64 arch-level symbol)
 *   prio 3: inline_ldtr_sttr       (our own inline sttr impl, gated on
 *                                   register_ex_table being resolvable)
 *
 * The registry stores the selected function pointer; consumers in
 * src/uaccess.c (Task 15/16 rewire) resolve once then call through it.
 *
 * Build modes: freestanding + kbuild (not userspace -- kernel-only).
 */

#include <kh_strategy.h>
#include <kh_log.h>
#include <types.h>

#ifdef __USERSPACE__
#else

#include <symbol.h>
#include <linux/uaccess.h>   /* __user annotation */

typedef unsigned long (*copy_to_user_fn)(void __user *to, const void *from, unsigned long n);

static int strat_to_copy_to_user(void *out, size_t sz)
{
    if (sz != sizeof(copy_to_user_fn)) return -22;
    uint64_t a = ksyms_lookup("_copy_to_user");
    if (!a) return KH_STRAT_ENODATA;
    *(copy_to_user_fn *)out = (copy_to_user_fn)(uintptr_t)a;
    return 0;
}

static int strat_to_sym_copy_to_user(void *out, size_t sz)
{
    if (sz != sizeof(copy_to_user_fn)) return -22;
    uint64_t a = ksyms_lookup("copy_to_user");
    if (!a) return KH_STRAT_ENODATA;
    *(copy_to_user_fn *)out = (copy_to_user_fn)(uintptr_t)a;
    return 0;
}

static int strat_to_arch_copy_to_user(void *out, size_t sz)
{
    if (sz != sizeof(copy_to_user_fn)) return -22;
    uint64_t a = ksyms_lookup("__arch_copy_to_user");
    if (!a) return KH_STRAT_ENODATA;
    *(copy_to_user_fn *)out = (copy_to_user_fn)(uintptr_t)a;
    return 0;
}

/* Stub inline copy_to_user. Task 16 will replace the body with a real
 * sttr-based implementation + ex_table fixups. For SP-7 bring-up this
 * returns `n` (meaning no bytes copied) so the outer caller sees the
 * same failure signal as an unresolvable kernel symbol. */
unsigned long kh_inline_copy_to_user(void __user *to, const void *from, unsigned long n)
{
    (void)to; (void)from;
    return n;
}

static int strat_to_inline_sttr(void *out, size_t sz)
{
    if (sz != sizeof(copy_to_user_fn)) return -22;

    /* Gate the inline path on register_ex_table being resolvable. Until
     * Task 16 registers that capability, this resolver returns ENODATA and
     * the registry falls through (there is no prio 4 -- resolve fails). */
    uint64_t dummy = 0;
    int rc = kh_strategy_resolve("register_ex_table", &dummy, sizeof(dummy));
    if (rc) return rc;

    *(copy_to_user_fn *)out = kh_inline_copy_to_user;
    return 0;
}

KH_STRATEGY_DECLARE(copy_to_user, _copy_to_user,       0, strat_to_copy_to_user,      sizeof(copy_to_user_fn));
KH_STRATEGY_DECLARE(copy_to_user, copy_to_user_sym,    1, strat_to_sym_copy_to_user,  sizeof(copy_to_user_fn));
KH_STRATEGY_DECLARE(copy_to_user, __arch_copy_to_user, 2, strat_to_arch_copy_to_user, sizeof(copy_to_user_fn));
KH_STRATEGY_DECLARE(copy_to_user, inline_ldtr_sttr,    3, strat_to_inline_sttr,       sizeof(copy_to_user_fn));

#endif /* !__USERSPACE__ */
