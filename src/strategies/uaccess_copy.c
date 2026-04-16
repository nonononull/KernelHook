/* src/strategies/uaccess_copy.c */
/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * SP-7 Capabilities: copy_to_user (Task 14), copy_from_user (Task 15),
 * and register_ex_table (Task 16).
 *
 * copy_to_user strategies (prio 0-3):
 *   prio 0: _copy_to_user          (current GKI export with underscore)
 *   prio 1: copy_to_user           (older export name)
 *   prio 2: __arch_copy_to_user    (arm64 arch-level symbol)
 *   prio 3: inline_ldtr_sttr       (our ARMv8.1+ sttr impl, gated on
 *                                   register_ex_table succeeding)
 *
 * copy_from_user strategies (prio 0-3):
 *   prio 0: _copy_from_user
 *   prio 1: copy_from_user
 *   prio 2: __arch_copy_from_user
 *   prio 3: inline_ldtr             (our ARMv8.1+ ldtr impl, gated on
 *                                    register_ex_table succeeding)
 *
 * register_ex_table strategies (prio 0-1):
 *   prio 0: probe_extable           (verify kernel loaded our __ex_table
 *                                    section by calling search_exception_tables
 *                                    on the sttrb fault-site address)
 *   prio 1: give_up                 (logs warning, returns -ENOTSUPP/-95)
 *
 * Inline implementations (kh_inline_copy_to/from_user):
 *   Use ARMv8.1+ `msr pan, #0` to disable Privileged Access Never, then
 *   sttrb/ldtrb for unprivileged EL0 stores/loads at EL1, then `msr pan, #1`
 *   to restore PAN. Each fault site has a corresponding __ex_table entry
 *   (EX_TYPE_FIXUP=1) that restores PAN and returns remaining byte count.
 *
 *   The kernel module loader automatically reads the __ex_table ELF section
 *   from the .ko and registers entries into THIS_MODULE->extable at insmod
 *   time (kernel/module/main.c: find_module_sections). No manual struct
 *   module manipulation is needed.
 *
 * Design choice — Approach 1 (search_exception_tables verify):
 *   strat_probe_extable calls search_exception_tables(kh_sttr_insn_site)
 *   via ksyms to verify end-to-end registration, rather than directly
 *   poking struct module fields (Approach 2). This avoids struct module
 *   layout assumptions entirely. The module_extable_off / module_numex_off
 *   module params in kh_strategy_boot.c are a documented escape hatch
 *   (default 0 = unused) for kernels where search_exception_tables is
 *   not exported.
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

/* ========================================================================
 * SP-7 Capability: copy_to_user (Task 14)
 * ======================================================================== */

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

/*
 * kh_inline_copy_to_user — ARMv8.1+ sttrb-based unprivileged store loop.
 *
 * Clears PAN (Privileged Access Never) with `msr pan, #0` so EL1 can
 * access EL0-mapped addresses via unprivileged store instructions.
 * Copies byte-by-byte using sttrb. Restores PAN with `msr pan, #1` on
 * both success and fault-fixup paths.
 *
 * Exception table (EX_TYPE_FIXUP=1): a fault on the sttrb instruction
 * causes the kernel's exception handler to jump to kh_sttr_fixup, which
 * restores PAN and falls through to the return path with rem = remaining.
 * The __ex_table entry is registered automatically at insmod time.
 *
 * Returns bytes NOT copied (0 on success, 1..n on fault).
 *
 * Constraint mapping: %0=to_a (in-out), %1=frm_a (in-out), %2=rem (in-out),
 * %3=scratch (early-clobber output, holds the loaded byte in w-view).
 * The scratch is "=&r" (early-clobber) so the compiler never aliases it
 * with %0/%1/%2.
 *
 * Global labels kh_sttr_insn_site and kh_sttr_fixup are needed so that:
 * (a) the __ex_table entry can reference kh_sttr_fixup by name from the
 *     pushsection (cross-section forward reference), and
 * (b) C code can take &kh_sttr_insn_site as an extern char[] to pass
 *     to search_exception_tables() for verification.
 *
 * __attribute__((noinline)): prevents the compiler from inlining this
 * function, which would duplicate the global asm labels and cause a
 * multiple-definition error at link time.
 */
__attribute__((noinline))
unsigned long kh_inline_copy_to_user(void __user *to, const void *from, unsigned long n)
{
    unsigned long to_a  = (unsigned long)(uintptr_t)to;
    unsigned long frm_a = (unsigned long)(uintptr_t)from;
    unsigned long rem   = n;
    unsigned long scratch;  /* scratch register for the loaded byte */

    __asm__ volatile(
        "    msr pan, #0\n"              /* clear PAN: EL1 can now touch EL0 pages */
        "1:  cbz %2, 2f\n"               /* loop: exit if remaining == 0 */
        "    ldrb %w3, [%1], #1\n"       /* load byte from kernel src, advance src */
        "kh_sttr_insn_site:\n"
        "    sttrb %w3, [%0]\n"          /* unprivileged byte store to user (may fault) */
        "    add %0, %0, #1\n"           /* advance dest pointer */
        "    sub %2, %2, #1\n"           /* decrement remaining count */
        "    b 1b\n"
        "2:  msr pan, #1\n"              /* restore PAN — success path */
        "    b 3f\n"
        "kh_sttr_fixup:\n"
        "    msr pan, #1\n"              /* restore PAN — fault fixup path */
        "3:\n"
        /* Exception table entry for the sttrb fault site.
         * Linux 5.4+ format (12 bytes):
         *   int  insn  = (faulting_pc   - &entry.insn)  — PC-relative
         *   int  fixup = (fixup_label   - &entry.fixup) — PC-relative
         *   short type = 1 (EX_TYPE_FIXUP: just jump to fixup)
         *   short data = 0
         *
         * At runtime: entry.insn + kh_sttr_insn_site - &entry.insn
         *           = kh_sttr_insn_site (the faulting PC).
         * search_exception_tables(kh_sttr_insn_site) returns non-NULL if
         * the kernel module loader found and registered this section. */
        ".pushsection __ex_table, \"a\"\n"
        "    .long (kh_sttr_insn_site - .)\n"  /* PC-rel offset to fault insn */
        "    .long (kh_sttr_fixup - .)\n"       /* PC-rel offset to fixup */
        "    .short 1\n"                         /* EX_TYPE_FIXUP */
        "    .short 0\n"                         /* data */
        ".popsection\n"
        : "+r" (to_a), "+r" (frm_a), "+r" (rem), "=&r" (scratch)
        : /* no additional inputs — all operands are in-out */
        : "memory"
    );
    (void)scratch;
    return rem;
}

/* kh_sttr_insn_site — global asm label defined in kh_inline_copy_to_user.
 * Extern char[] declaration makes it addressable from C; used by
 * strat_probe_extable to verify __ex_table registration without needing
 * struct module field offsets. */
extern char kh_sttr_insn_site[];

static int strat_to_inline_sttr(void *out, size_t sz)
{
    if (sz != sizeof(copy_to_user_fn)) return -22;

    /* Gate on register_ex_table: inline path is only safe when the kernel's
     * module loader has registered our __ex_table entries (otherwise a bad
     * user pointer causes an unhandled page fault instead of a clean fixup). */
    int dummy = 0;
    int rc = kh_strategy_resolve("register_ex_table", &dummy, sizeof(dummy));
    if (rc) return rc;

    *(copy_to_user_fn *)out = kh_inline_copy_to_user;
    return 0;
}

KH_STRATEGY_DECLARE(copy_to_user, _copy_to_user,       0, strat_to_copy_to_user,      sizeof(copy_to_user_fn));
KH_STRATEGY_DECLARE(copy_to_user, copy_to_user_sym,    1, strat_to_sym_copy_to_user,  sizeof(copy_to_user_fn));
KH_STRATEGY_DECLARE(copy_to_user, __arch_copy_to_user, 2, strat_to_arch_copy_to_user, sizeof(copy_to_user_fn));
KH_STRATEGY_DECLARE(copy_to_user, inline_ldtr_sttr,    3, strat_to_inline_sttr,       sizeof(copy_to_user_fn));

/* ========================================================================
 * SP-7 Capability: copy_from_user (Task 15)
 *
 * Symmetric to copy_to_user. Same 4-strategy shape with naming variants:
 *   prio 0: _copy_from_user
 *   prio 1: copy_from_user
 *   prio 2: __arch_copy_from_user
 *   prio 3: inline_ldtr (our own ldtrb impl, gated on register_ex_table)
 * ======================================================================== */

typedef unsigned long (*copy_from_user_fn)(void *to, const void __user *from, unsigned long n);

static int strat_from_copy_from_user(void *out, size_t sz)
{
    if (sz != sizeof(copy_from_user_fn)) return -22;
    uint64_t a = ksyms_lookup("_copy_from_user");
    if (!a) return KH_STRAT_ENODATA;
    *(copy_from_user_fn *)out = (copy_from_user_fn)(uintptr_t)a;
    return 0;
}

static int strat_from_sym_copy_from_user(void *out, size_t sz)
{
    if (sz != sizeof(copy_from_user_fn)) return -22;
    uint64_t a = ksyms_lookup("copy_from_user");
    if (!a) return KH_STRAT_ENODATA;
    *(copy_from_user_fn *)out = (copy_from_user_fn)(uintptr_t)a;
    return 0;
}

static int strat_from_arch_copy_from_user(void *out, size_t sz)
{
    if (sz != sizeof(copy_from_user_fn)) return -22;
    uint64_t a = ksyms_lookup("__arch_copy_from_user");
    if (!a) return KH_STRAT_ENODATA;
    *(copy_from_user_fn *)out = (copy_from_user_fn)(uintptr_t)a;
    return 0;
}

/*
 * kh_inline_copy_from_user — ARMv8.1+ ldtrb-based unprivileged load loop.
 *
 * Symmetric to kh_inline_copy_to_user. Clears PAN, reads byte-by-byte
 * from the user address using ldtrb (unprivileged load), stores into the
 * kernel destination buffer, restores PAN.
 *
 * Exception table entry for kh_ldtr_insn_site: on ldtrb fault, jump to
 * kh_ldtr_fixup which restores PAN and returns remaining byte count.
 *
 * Returns bytes NOT copied (0 on success, 1..n on fault).
 *
 * Constraint mapping: %0=to_a (in-out), %1=frm_a (in-out), %2=rem (in-out),
 * %3=scratch (early-clobber output). __attribute__((noinline)) prevents
 * label duplication.
 */
__attribute__((noinline))
unsigned long kh_inline_copy_from_user(void *to, const void __user *from, unsigned long n)
{
    unsigned long to_a  = (unsigned long)(uintptr_t)to;
    unsigned long frm_a = (unsigned long)(uintptr_t)from;
    unsigned long rem   = n;
    unsigned long scratch;

    __asm__ volatile(
        "    msr pan, #0\n"              /* clear PAN: EL1 can now touch EL0 pages */
        "1:  cbz %2, 2f\n"               /* loop: exit if remaining == 0 */
        "kh_ldtr_insn_site:\n"
        "    ldtrb %w3, [%1]\n"          /* unprivileged byte load from user (may fault) */
        "    add %1, %1, #1\n"           /* advance src pointer */
        "    strb %w3, [%0], #1\n"       /* store byte to kernel dest, advance dest */
        "    sub %2, %2, #1\n"           /* decrement remaining count */
        "    b 1b\n"
        "2:  msr pan, #1\n"              /* restore PAN — success path */
        "    b 3f\n"
        "kh_ldtr_fixup:\n"
        "    msr pan, #1\n"              /* restore PAN — fault fixup path */
        "3:\n"
        /* Exception table entry for the ldtrb fault site. Same 12-byte
         * format as the sttrb entry above. */
        ".pushsection __ex_table, \"a\"\n"
        "    .long (kh_ldtr_insn_site - .)\n"
        "    .long (kh_ldtr_fixup - .)\n"
        "    .short 1\n"                  /* EX_TYPE_FIXUP */
        "    .short 0\n"
        ".popsection\n"
        : "+r" (to_a), "+r" (frm_a), "+r" (rem), "=&r" (scratch)
        : /* no additional inputs */
        : "memory"
    );
    (void)scratch;
    return rem;
}

static int strat_from_inline_ldtr(void *out, size_t sz)
{
    if (sz != sizeof(copy_from_user_fn)) return -22;

    /* Gate on register_ex_table: same reasoning as strat_to_inline_sttr. */
    int dummy = 0;
    int rc = kh_strategy_resolve("register_ex_table", &dummy, sizeof(dummy));
    if (rc) return rc;

    *(copy_from_user_fn *)out = kh_inline_copy_from_user;
    return 0;
}

KH_STRATEGY_DECLARE(copy_from_user, _copy_from_user,       0, strat_from_copy_from_user,      sizeof(copy_from_user_fn));
KH_STRATEGY_DECLARE(copy_from_user, copy_from_user_sym,    1, strat_from_sym_copy_from_user,  sizeof(copy_from_user_fn));
KH_STRATEGY_DECLARE(copy_from_user, __arch_copy_from_user, 2, strat_from_arch_copy_from_user, sizeof(copy_from_user_fn));
KH_STRATEGY_DECLARE(copy_from_user, inline_ldtr,           3, strat_from_inline_ldtr,         sizeof(copy_from_user_fn));

/* ========================================================================
 * SP-7 Capability: register_ex_table (Task 16)
 *
 * Procedural capability (out_size = sizeof(int), value unused — the
 * return code 0 / non-zero is the meaningful result).
 *
 * Strategy 0 (probe_extable): verify our __ex_table ELF section was
 *   registered by the kernel module loader at insmod time. Calls
 *   search_exception_tables(kh_sttr_insn_site) via ksyms. Returns 0
 *   if the entry is found (meaning the sttrb fault has a registered
 *   fixup), KH_STRAT_ENODATA otherwise.
 *
 *   This approach (Approach 1) avoids struct module offset knowledge by
 *   verifying end-to-end through the kernel's own search function. The
 *   alternative (Approach 2: loader-injected struct module.extable and
 *   num_exentries offsets) is wired as escape-hatch module params in
 *   kh_strategy_boot.c but is not the active code path here.
 *
 * Strategy 1 (give_up): log a warning and return -ENOTSUPP (-95).
 *   Reached only if probe_extable fails (e.g., search_exception_tables
 *   not exported, or __ex_table section was stripped from the .ko).
 * ======================================================================== */

/* search_exception_tables(pc) — kernel function. Returns const struct
 * exception_table_entry* or NULL. We only test for NULL vs non-NULL
 * so we use void* as the return type to avoid a struct definition. */
typedef const void *(*search_exception_tables_fn_t)(unsigned long pc);

__attribute__((no_sanitize("kcfi")))
static int strat_probe_extable(void *out, size_t sz)
{
    if (sz != sizeof(int)) return -22;

    /* Look up search_exception_tables via ksyms — ksyms_lookup over
     * extern to avoid MODVERSIONS CRC fragility (see CLAUDE.md). */
    uint64_t fn_addr = ksyms_lookup("search_exception_tables");
    if (!fn_addr) {
        pr_warn("[register_ex_table] search_exception_tables not in kallsyms"
                " — cannot probe extable registration\n");
        return KH_STRAT_ENODATA;
    }

    search_exception_tables_fn_t fn =
        (search_exception_tables_fn_t)(uintptr_t)fn_addr;

    /* kh_sttr_insn_site is the address of the sttrb instruction in
     * kh_inline_copy_to_user. If the kernel module loader found our
     * __ex_table section, fn() returns a non-NULL entry pointer. */
    const void *entry = fn((unsigned long)(uintptr_t)kh_sttr_insn_site);
    if (!entry) {
        pr_warn("[register_ex_table] __ex_table entry for kh_sttr_insn_site"
                " not found — module loader may have skipped our section\n");
        return KH_STRAT_ENODATA;
    }

    pr_info("[register_ex_table] extable probe OK: entry=%p\n", entry);
    *(int *)out = 0;
    return 0;
}

static int strat_give_up(void *out, size_t sz)
{
    if (sz != sizeof(int)) return -22;
    pr_warn("[register_ex_table] all extable registration strategies"
            " failed — inline ldtr/sttr uaccess unavailable on this kernel\n");
    (void)out;
    return -95;  /* -ENOTSUPP */
}

KH_STRATEGY_DECLARE(register_ex_table, probe_extable, 0, strat_probe_extable, sizeof(int));
KH_STRATEGY_DECLARE(register_ex_table, give_up,       1, strat_give_up,       sizeof(int));

#endif /* !__USERSPACE__ */
