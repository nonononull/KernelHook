/* SPDX-License-Identifier: GPL-2.0-or-later */
/* /system/bin/kh_root demo (P4 was kh_root demo) -- kh_hook execve/faccessat/fstatat to
 * unconditionally elevate any caller of "/system/bin/kh_root" to uid=0
 * and redirect the execve to /system/bin/sh.
 *
 * Mirrors ref/KernelPatch/kernel/patch/common/sucompat.c, simplified:
 *   - No kstorage / allowlist: any caller -> uid=0
 *   - No scontext change (SELinux label stays shell)
 *   - Single hardcoded magic path
 *   - 64-bit only, no compat
 *
 * IMPLEMENTATION NOTE: we kh_hook __arm64_sys_<name> via inline kh_hook
 * (kh_hook_wrap) rather than via kh_hook_syscalln(). Reasons:
 *   1. sys_call_table on Pixel 6 GKI 6.1 lives in __ro_after_init and
 *      cannot be written without temporarily clearing PTE_RDONLY.
 *   2. Even if we make the table writable, kCFI on invoke_syscall
 *      enforces a type-id check on each indirect call: the trampoline
 *      from kh_fp_hook_wrap doesn't carry the kCFI hash that
 *      __arm64_sys_<name> functions do, so the call faults with
 *      "CFI failure at invoke_syscall+0x50/0x11c (target: ...,
 *      expected type: 0xb02b34d9)".
 *   3. KernelPatch's sucompat.c uses inline hooks on __arm64_sys_<name>
 *      for the same reason.
 *
 * Inline hooks splice instructions into the function prologue, so the
 * caller's BLR still lands on the original symbol address (kCFI-checked
 * normally) and the trampoline runs invisibly.
 */

#include <types.h>
#include <kh_log.h>
#include <kh_hook.h>
#include <symbol.h>
#include <syscall.h>
#include <uaccess.h>
#include "demo_kh_root.h"

#ifndef KMOD_FREESTANDING
#include <linux/cred.h>
#include <linux/sched.h>
#endif

/* ARM64 canonical syscall numbers (from <uapi/asm-generic/unistd.h>).
 * Hardcoded to keep this TU freestanding-friendly. */
#ifndef __NR_execve
#define __NR_execve         221
#endif
#ifndef __NR_faccessat
#define __NR_faccessat      48
#endif
#ifndef __NR3264_fstatat
#define __NR3264_fstatat    79   /* aka __NR_newfstatat on arm64 */
#endif

static const char kh_root_path[] = "/system/bin/kh_root";
static const char kh_sh_path[]   = "/system/bin/sh";

/* Kernel 6.1 signature: struct cred *prepare_kernel_cred(struct task_struct *).
 * Passing NULL yields full-root creds. */
struct task_struct;
struct cred;
typedef struct cred *(*prepare_kernel_cred_fn)(struct task_struct *);
typedef int          (*commit_creds_fn)(struct cred *);

static prepare_kernel_cred_fn kh_prepare_kernel_cred = NULL;
static commit_creds_fn        kh_commit_creds        = NULL;

/* Resolved __arm64_sys_<name> addresses (or fallback variants). 0 == not
 * installed. We snapshot at install time so uninstall hits the exact
 * same address even if kh_syscall_name_table caching mutates. */
static uintptr_t kh_addr_execve    = 0;
static uintptr_t kh_addr_faccessat = 0;
static uintptr_t kh_addr_fstatat   = 0;

static int kh_root_installed = 0;

/* Compare a kernel string to a user-visible filename by copying a bounded
 * prefix from userspace. Returns 1 if equal (and NUL-terminated),
 * 0 otherwise.  Tolerates faulty user pointers (kh_strncpy_from_user
 * returns <=0 on EFAULT). */
__attribute__((no_sanitize("kcfi")))
static int match_user_path(const void *u_filename, const char *target)
{
    char buf[64];  /* kh_root_path is 20 chars; 64 is plenty */
    long n = kh_strncpy_from_user(buf, u_filename, sizeof(buf));
    if (n <= 0) return 0;
    int i = 0;
    while (target[i] && buf[i] == target[i]) i++;
    return target[i] == '\0' && buf[i] == '\0';
}

/* before_execve: the wrapper signature is `long fn(struct pt_regs *)`;
 * arg0 of the syscall (the filename pointer) lives at pt_regs->regs[0].
 * If it matches /system/bin/kh_root, elevate creds to root and rewrite
 * the regs[0] slot to point at /system/bin/sh on the user stack so the
 * kernel proceeds with a real shell exec. */
__attribute__((no_sanitize("kcfi")))
static void kh_before_execve(kh_hook_fargs1_t *args, void *udata)
{
    (void)udata;
    void **u_filename_p = (void **)kh_syscall_argn_p(args, 0);
    if (!*u_filename_p) return;
    if (!match_user_path(*u_filename_p, kh_root_path)) return;

    if (!kh_prepare_kernel_cred || !kh_commit_creds) return;
    struct cred *new = kh_prepare_kernel_cred(NULL);
    if (!new) return;
    kh_commit_creds(new);

    /* Redirect filename to /system/bin/sh so the kernel continues to
     * the real execve and the caller actually gets a shell. */
    void *uptr = kh_copy_to_user_stack(kh_sh_path, sizeof(kh_sh_path));
    if ((long)uptr > 0) *u_filename_p = uptr;

    pr_info("[KH/demo] kh_root elevated -> uid=0 -> sh\n");
}

/* before_path_arg1: shared callback for faccessat / fstatat where
 * the user-visible filename is at syscall arg index 1. We don't elevate
 * here -- only fake "this path exists" by redirecting target to sh.
 * This makes shell `test -x /system/bin/kh_root` and `access(2)` succeed
 * even when no binary exists at that path. */
__attribute__((no_sanitize("kcfi")))
static void kh_before_path_arg1(kh_hook_fargs1_t *args, void *udata)
{
    (void)udata;
    void **u_filename_p = (void **)kh_syscall_argn_p(args, 1);
    if (!*u_filename_p) return;
    if (!match_user_path(*u_filename_p, kh_root_path)) return;

    void *uptr = kh_copy_to_user_stack(kh_sh_path, sizeof(kh_sh_path));
    if ((long)uptr > 0) *u_filename_p = uptr;
}

__attribute__((no_sanitize("kcfi")))
int kh_root_install(void)
{
    kh_prepare_kernel_cred = (prepare_kernel_cred_fn)(uintptr_t)
        ksyms_lookup("prepare_kernel_cred");
    kh_commit_creds = (commit_creds_fn)(uintptr_t)
        ksyms_lookup("commit_creds");
    if (!kh_prepare_kernel_cred || !kh_commit_creds) {
        pr_warn("kh_root: prepare_kernel_cred=%llx commit_creds=%llx -- "
                "SKIP demo\n",
                (unsigned long long)(uintptr_t)kh_prepare_kernel_cred,
                (unsigned long long)(uintptr_t)kh_commit_creds);
        return -1;
    }

    /* Resolve __arm64_sys_<name> entry addresses. kh_syscalln_name_addr
     * tries __arm64_<name>{.cfi_jt,.cfi,""} and bare <name> in order. */
    kh_addr_execve    = kh_syscalln_name_addr(__NR_execve);
    kh_addr_faccessat = kh_syscalln_name_addr(__NR_faccessat);
    kh_addr_fstatat   = kh_syscalln_name_addr(__NR3264_fstatat);

    pr_info("[KH/demo] entry addrs: execve=%llx faccessat=%llx fstatat=%llx\n",
            (unsigned long long)kh_addr_execve,
            (unsigned long long)kh_addr_faccessat,
            (unsigned long long)kh_addr_fstatat);

    if (!kh_addr_execve || !kh_addr_faccessat || !kh_addr_fstatat) {
        pr_warn("kh_root: failed to resolve one or more syscall entry "
                "symbols -- SKIP demo\n");
        return -1;
    }

    /* Inline-kh_hook the __arm64_sys_<name> wrappers. argno=1 because the
     * wrappers all have the pt_regs* signature; our callbacks reach
     * the actual syscall args via kh_syscall_argn_p() which indexes
     * pt_regs->regs[N]. */
    kh_hook_err_t e1 = kh_hook_wrap((void *)kh_addr_execve,    1,
        (void *)kh_before_execve,    NULL, NULL, 0);
    kh_hook_err_t e2 = kh_hook_wrap((void *)kh_addr_faccessat, 1,
        (void *)kh_before_path_arg1, NULL, NULL, 0);
    kh_hook_err_t e3 = kh_hook_wrap((void *)kh_addr_fstatat,   1,
        (void *)kh_before_path_arg1, NULL, NULL, 0);

    pr_info("[KH/demo] hooks installed: execve=%d faccessat=%d fstatat=%d\n",
            e1, e2, e3);

    if (e1 != HOOK_NO_ERR || e2 != HOOK_NO_ERR || e3 != HOOK_NO_ERR) {
        /* Mark installed so uninstall() actually removes whatever did
         * register, then bail. */
        kh_root_installed = 1;
        kh_root_uninstall();
        return -1;
    }
    kh_root_installed = 1;
    return 0;
}

__attribute__((no_sanitize("kcfi")))
void kh_root_uninstall(void)
{
    if (!kh_root_installed) return;
    if (kh_addr_execve)
        kh_hook_unwrap((void *)kh_addr_execve,    (void *)kh_before_execve,    NULL);
    if (kh_addr_faccessat)
        kh_hook_unwrap((void *)kh_addr_faccessat, (void *)kh_before_path_arg1, NULL);
    if (kh_addr_fstatat)
        kh_hook_unwrap((void *)kh_addr_fstatat,   (void *)kh_before_path_arg1, NULL);
    kh_addr_execve = kh_addr_faccessat = kh_addr_fstatat = 0;
    kh_root_installed = 0;
}
