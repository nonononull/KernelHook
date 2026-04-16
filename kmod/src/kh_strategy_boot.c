/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * kh_strategy_boot.c — module-parameter glue for the strategy registry.
 *
 * Freestanding mode (KMOD_FREESTANDING):
 *   Defines module_param slots for kh_disable, kh_force, kh_inject_fail,
 *   and kh_consistency_check.  kh_strategy_boot() calls kh_strategy_init(),
 *   applies each non-empty CSV parameter, and optionally runs the consistency
 *   check (tainting the kernel on mismatch via add_taint).
 *
 * kbuild / SDK mode (!KMOD_FREESTANDING):
 *   Module params are owned by the consumer module.  kh_strategy_boot() just
 *   calls kh_strategy_init() so the boot sequence is uniform for callers.
 */

#include <kh_strategy.h>
#include <kh_log.h>

/* Forward declarations for the CSV parse helpers in src/kh_strategy.c
 * (compiled as part of _KH_CORE_SRCS in kmod.mk). */
extern void kh_strategy_apply_disable_list(const char *csv);
extern void kh_strategy_apply_force_list(const char *csv);
extern void kh_strategy_apply_inject_list(const char *csv);

#ifdef KMOD_FREESTANDING

/* linux/module.h pulls in shim.h in freestanding mode, providing
 * module_param, MODULE_PARM_DESC, module_init, etc. */
#include <linux/module.h>
#include <linux/kernel.h>

/* TAINT_CRAP, LOCKDEP_STILL_OK, add_taint extern: provided by linux/kernel.h
 * (shim defines them for freestanding; real header defines them for kbuild). */

/* ---- Module parameters (freestanding mode) ----
 *
 * All params are load-time only (perm=0444: read-only after load).
 * Writing them at runtime would create a TOCTOU race between the parse
 * and the registry state, so 0444 is intentional.
 *
 * kh_disable:           "cap:name,cap:name,..."  — disable strategies
 * kh_force:             "cap:name,cap:name,..."  — force specific strategies
 * kh_inject_fail:       "cap:name:count,..."     — inject N failures
 * kh_consistency_check: 1 = run check at init; 0 = skip (default)
 */
static char *kh_disable           = "";
static char *kh_force             = "";
static char *kh_inject_fail       = "";
static int   kh_consistency_check = 0;

module_param(kh_disable,          charp, 0444);
MODULE_PARM_DESC(kh_disable,
    "Comma-separated cap:name pairs to disable at load time");

module_param(kh_force,            charp, 0444);
MODULE_PARM_DESC(kh_force,
    "Comma-separated cap:name pairs to force at load time");

module_param(kh_inject_fail,      charp, 0444);
MODULE_PARM_DESC(kh_inject_fail,
    "Comma-separated cap:name:count tuples to inject failures");

module_param(kh_consistency_check, int,  0444);
MODULE_PARM_DESC(kh_consistency_check,
    "Set to 1 to run strategy consistency check at init (taints on mismatch)");

/* Strategy capability "kimage_voffset" / loader_inject reads this global.
 * Set via insmod iomem_textpa=<kernel kimage_voffset value>. When not
 * provided, stays 0 and the loader_inject strategy falls through. */
/* uint64_t and unsigned long are both 64-bit on LP64 ARM64 (our only
 * target), so the `ulong` module_param setter writes the full value
 * correctly. A 32-bit host would need a different writer, but this
 * project is ARM64-only (see CMakeLists.txt top-level architecture
 * guard). */
extern uint64_t kh_loader_injected_kimage_voffset;
module_param_named(iomem_textpa, kh_loader_injected_kimage_voffset, ulong, 0444);
MODULE_PARM_DESC(iomem_textpa,
    "kimage_voffset value injected from loader (kernel_text_VA - kernel_text_PA)");

/* Strategy capability "memstart_addr" / dtb_parse reads this global.
 * Set via insmod iomem_memstart=<DTB-derived DRAM base PA>. Loader
 * (tools/kmod_loader/kmod_loader.c) auto-injects this by walking
 * /proc/device-tree/memory@.../reg (the literal DT path has a slash-star-
 * slash glob that would close this block comment, so the literal is
 * elided in text). When loader did not or could not parse DTB, stays 0
 * and dtb_parse falls through. */
/* ulong / uint64_t type equivalence: same LP64 ARM64 assumption as
 * iomem_textpa above. */
extern uint64_t kh_loader_injected_memstart;
module_param_named(iomem_memstart, kh_loader_injected_memstart, ulong, 0444);
MODULE_PARM_DESC(iomem_memstart,
    "DRAM base PA (PHYS_OFFSET / memstart_addr) injected from DTB at load time");

/* ---- register_ex_table escape-hatch module params ----
 *
 * The primary register_ex_table strategy (probe_extable) uses
 * search_exception_tables() to verify __ex_table registration — no struct
 * module offsets required (Approach 1 in uaccess_copy.c). These params are
 * an escape hatch for future use if a kernel does not export
 * search_exception_tables and direct struct module probing is needed instead.
 *
 * Default 0 = unused (Approach 1 active). Non-zero values may be passed via
 * kmod_loader --module-extable-off=HEX --module-numex-off=HEX to enable the
 * direct struct module path (not yet implemented; reserved for Task 21+).
 *
 * BTF path (parsing /sys/kernel/btf/vmlinux for struct module field offsets)
 * is deferred to a future task; manual CLI override is the supported method.
 */
uint64_t kh_loader_module_extable_off;
module_param_named(module_extable_off, kh_loader_module_extable_off, ulong, 0444);
MODULE_PARM_DESC(module_extable_off,
    "Offset of struct module.extable pointer field (escape hatch; 0=use probe_extable)");

uint64_t kh_loader_module_numex_off;
module_param_named(module_numex_off, kh_loader_module_numex_off, ulong, 0444);
MODULE_PARM_DESC(module_numex_off,
    "Offset of struct module.num_exentries field (escape hatch; 0=use probe_extable)");

/*
 * kh_strategy_boot — called early in kernelhook_init(), after
 * kmod_compat_init() so kallsyms is available, before hook memory init.
 *
 * Returns 0 on success.  Currently always succeeds; consistency-check
 * mismatches taint but do not abort load.
 */
int kh_strategy_boot(void)
{
    int rc;

    rc = kh_strategy_init();
    if (rc) {
        pr_err("[kh_strategy] init failed (%d)\n", rc);
        return rc;
    }

    /* Apply module-parameter overrides in order:
     *   1. disable  — remove strategies from consideration
     *   2. force    — pin a specific strategy per capability
     *   3. inject   — schedule artificial failures for testing
     */
    kh_strategy_apply_disable_list(kh_disable);
    kh_strategy_apply_force_list(kh_force);
    kh_strategy_apply_inject_list(kh_inject_fail);

    /* Always init in freestanding mode — cross-compiled .ko targets kernels
     * that have debugfs. */
    {
        extern void kh_strategy_debugfs_init(void);
        kh_strategy_debugfs_init();
    }

    if (kh_consistency_check) {
        int mis = kh_strategy_run_consistency_check();
        if (mis > 0) {
            pr_warn("[kh_strategy] consistency check: %d mismatch(es) — tainting kernel\n",
                    mis);
            /* TAINT_CRAP signals that a module is doing something unusual.
             * LOCKDEP_STILL_OK = 1: lockdep can still be used after this taint. */
            add_taint(TAINT_CRAP, LOCKDEP_STILL_OK);
        } else {
            pr_info("[kh_strategy] consistency check: all strategies agree\n");
        }
    }

    return 0;
}

#else /* !KMOD_FREESTANDING — kbuild / SDK mode */

/*
 * In SDK mode, the consumer module owns its own module_param slots.
 * kh_strategy_boot() is a thin wrapper so main.c's boot sequence is uniform.
 */
int kh_strategy_boot(void)
{
    int rc = kh_strategy_init();
    if (rc)
        return rc;

#if IS_ENABLED(CONFIG_DEBUG_FS)
    {
        extern void kh_strategy_debugfs_init(void);
        kh_strategy_debugfs_init();
    }
#endif

    return 0;
}

#endif /* KMOD_FREESTANDING */
