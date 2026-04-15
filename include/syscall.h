/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2026 bmax121.
 *
 * KernelHook syscall-level hook API. Ported from
 * ref/KernelPatch/kernel/patch/common/syscall.c, 64-bit only
 * (no compat / AArch32 paths).
 */

#ifndef _KH_SYSCALL_H_
#define _KH_SYSCALL_H_

#include <types.h>
#include <hook.h>

/* Globals populated by kh_syscall_init(). */
extern uintptr_t *kh_sys_call_table;
extern int        kh_has_syscall_wrapper;

/*
 * Resolve sys_call_table + detect wrapper ABI via kallsyms.
 * Must be called AFTER ksyms_init(). Returns 0 on success — a
 * non-resolvable sys_call_table is NOT treated as fatal (inline-hook
 * fallback remains available), but kh_sys_call_table will be NULL.
 */
int kh_syscall_init(void);

/*
 * Install / remove a hook on syscall number `nr`.
 *
 * When kh_has_syscall_wrapper==1 (all modern arm64 kernels, incl. Pixel
 * 6 GKI 6.1), the syscall entry is the pt_regs wrapper stub — the
 * physical hook is always 1-arg (`pt_regs *`). Callers pass the
 * semantic argno; we rewrite to 1 internally when wrapper is detected.
 * Callbacks should use kh_syscall_argn_p() to reach pt_regs->regs[N].
 */
hook_err_t kh_hook_syscalln(int nr, int narg, void *before, void *after, void *udata);
void       kh_unhook_syscalln(int nr, void *before, void *after);

/* In-kernel syscall invocation (wrapper-aware). */
long kh_raw_syscall0(long nr);
long kh_raw_syscall1(long nr, long a0);
long kh_raw_syscall2(long nr, long a0, long a1);
long kh_raw_syscall3(long nr, long a0, long a1, long a2);
long kh_raw_syscall4(long nr, long a0, long a1, long a2, long a3);
long kh_raw_syscall5(long nr, long a0, long a1, long a2, long a3, long a4);
long kh_raw_syscall6(long nr, long a0, long a1, long a2, long a3, long a4, long a5);

/*
 * Resolve the per-syscall entry address (prefers sys_call_table, falls
 * back to __arm64_sys_<name> / <name> / <name>.cfi / <name>.cfi_jt
 * via kallsyms). Returns 0 when unresolvable.
 */
uintptr_t kh_syscalln_addr(int nr);
uintptr_t kh_syscalln_name_addr(int nr);

/*
 * Pointer to syscall arg N inside a hook_fargs<M>_t pointer `args`.
 *
 * When kh_has_syscall_wrapper: args->arg0 holds `struct pt_regs *`,
 *   whose first field is `unsigned long regs[31]`. The real syscall
 *   args live at pt_regs->regs[N] — that's offset 8*N from the start
 *   of the struct. We return a pointer to that slot so callers can
 *   both read and overwrite the arg before the origin runs. The
 *   physical hook MUST be installed with narg==1 (arg0 = pt_regs*).
 *
 * When !wrapper: args->argN is the direct arg; we return its address.
 *
 * N must be a compile-time constant 0..7.
 */
#define kh_syscall_argn_p(args, N)                                            \
    (kh_has_syscall_wrapper                                                   \
        ? ((void *)(((uint64_t *)(uintptr_t)((hook_fargs1_t *)(args))->arg0)  \
                    + (N)))                                                   \
        : ((void *)&((hook_fargs8_t *)(args))->args[(N)]))

#endif /* _KH_SYSCALL_H_ */
