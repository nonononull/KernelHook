/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2026 bmax121.
 *
 * User-pointer helpers. Trimmed port of KernelPatch
 * kernel/patch/common/utils.c — only what Phase 5b / Phase 6 need.
 *
 * Freestanding notes:
 *   - No <asm/current.h>, <linux/cred.h>, <linux/sched.h>, <asm/ptrace.h>
 *     available. We derive `current` from sp_el0 (stable on ARM64 GKI
 *     5.10+ with CONFIG_THREAD_INFO_IN_TASK=y).
 *   - task_struct layout is opaque: `cred` offset is probed at init by
 *     scanning init_task for a pointer value equal to &init_cred.
 *   - `stack` offset is probed the same way against init_thread_union
 *     when that symbol resolves; otherwise we fall back to the GKI-6.x
 *     constant 0x20.
 *   - pt_regs sizeof(=0x150) and THREAD_SIZE(=16384) are hardcoded to
 *     the arm64-LP64 values that have been stable since 5.10.
 *
 * Kbuild mode uses the real kernel headers + direct calls.
 */

#include <types.h>
#include <kh_log.h>
#include <symbol.h>
#include <uaccess.h>

#ifdef KMOD_FREESTANDING
/* No kernel headers. Define the minimum. */

/* Opaque forward decls — we only ever touch memory through probed
 * offsets, never via struct member access. */
struct task_struct;
struct cred;
struct pt_regs;

/* ARM64 arch constants (stable on GKI 5.10+). */
#define KH_THREAD_SIZE   16384UL
#define KH_PT_REGS_SIZE  0x150UL  /* sizeof(struct pt_regs) on arm64 6.x */

/* sp_el0 holds `current` on modern ARM64 kernels. */
__attribute__((always_inline))
static inline struct task_struct *kh_get_current(void)
{
    uint64_t sp_el0;
    asm volatile("mrs %0, sp_el0" : "=r"(sp_el0));
    return (struct task_struct *)(uintptr_t)sp_el0;
}

#else  /* Kbuild */

#include <linux/uaccess.h>
#include <linux/cred.h>
#include <linux/sched.h>
#include <linux/sched/task_stack.h>
#include <asm/ptrace.h>
#include <asm/current.h>

#define KH_THREAD_SIZE   THREAD_SIZE
#define KH_PT_REGS_SIZE  (sizeof(struct pt_regs))

static inline struct task_struct *kh_get_current(void)
{
    return current;
}

#endif /* KMOD_FREESTANDING */

/* ---- ksyms-resolved primitives ---- */

typedef long          (*kh_strncpy_from_user_fn_t)(char *, const void *, long);
typedef unsigned long (*kh_copy_to_user_fn_t)(void *, const void *, unsigned long);

static kh_strncpy_from_user_fn_t kh_strncpy_from_user_fn = NULL;
static kh_copy_to_user_fn_t      kh_copy_to_user_fn      = NULL;

/* Offsets into task_struct / cred, probed at init. 0 = unresolved
 * (except cred_uid which is hardcoded to 4 on modern kernels). */
static unsigned int kh_cred_offset       = 0;      /* task_struct.cred */
static unsigned int kh_cred_uid_offset   = 4;      /* cred.uid (stable) */
static unsigned int kh_stack_offset      = 0x20;   /* task_struct.stack default */
static int          kh_stack_offset_probed = 0;    /* 1 if probe succeeded */

/* ---- public API ---- */

__attribute__((no_sanitize("kcfi")))
long kh_strncpy_from_user(char *dest, const void *src_user, long count)
{
    if (!kh_strncpy_from_user_fn || !dest || !src_user || count <= 0)
        return -1;

    long rc = kh_strncpy_from_user_fn(dest, src_user, count);
    if (rc >= count) {
        /* kernel's strncpy_from_user() never returns > count, but
         * guard anyway; truncate and NUL-terminate. */
        rc = count;
        dest[rc - 1] = '\0';
    } else if (rc > 0) {
        /* kernel returns length EXCLUDING the NUL terminator; dest[rc]
         * is already the NUL. Adjust to include NUL to match KP. */
        rc++;
    }
    return rc;
}

__attribute__((no_sanitize("kcfi")))
int kh_copy_to_user(void *to_user, const void *from, int n)
{
    if (!kh_copy_to_user_fn) return n;  /* signal "nothing copied" */
    if (!to_user || !from || n <= 0) return n;
    return (int)kh_copy_to_user_fn(to_user, from, (unsigned long)n);
}

/* Derive current task's pt_regs pointer via task->stack + THREAD_SIZE
 * - sizeof(pt_regs). Equivalent to task_pt_regs(current). Depends on
 * task_struct.stack offset being correct. */
__attribute__((no_sanitize("kcfi")))
static void *kh_current_pt_regs_ptr(void)
{
    struct task_struct *task = kh_get_current();
    if (!task) return NULL;
    uintptr_t stack = *(uintptr_t *)((uintptr_t)task + kh_stack_offset);
    if (!stack) return NULL;
    return (void *)(stack + KH_THREAD_SIZE - KH_PT_REGS_SIZE);
}

__attribute__((no_sanitize("kcfi")))
void *kh_copy_to_user_stack(const void *data, int len)
{
    if (!data || len <= 0) return (void *)(long)-22; /* -EINVAL */

    void *regs = kh_current_pt_regs_ptr();
    if (!regs) return (void *)(long)-14; /* -EFAULT */

    /* pt_regs layout: unsigned long regs[31]; unsigned long sp; ...
     * sp is at offset 31*8 = 0xf8. */
    uintptr_t sp = *(uintptr_t *)((uintptr_t)regs + 31 * 8);
    if (!sp) return (void *)(long)-14;

    sp -= (uintptr_t)len;
    sp &= ~((uintptr_t)7);  /* 8-byte align */

    int not_copied = kh_copy_to_user((void *)sp, data, len);
    if (not_copied) return (void *)(long)-14;
    return (void *)sp;
}

__attribute__((no_sanitize("kcfi")))
kh_uid_t kh_current_uid(void)
{
    if (!kh_cred_offset) return 0;
    struct task_struct *task = kh_get_current();
    if (!task) return 0;
    void *cred = *(void **)((uintptr_t)task + kh_cred_offset);
    if (!cred) return 0;
    return *(kh_uid_t *)((uintptr_t)cred + kh_cred_uid_offset);
}

/* ---- init-time probing ---- */

/* Scan init_task[0..0x1000] in 8-byte strides for a pointer equal to
 * `target`. Returns the offset on success, 0 on failure. */
__attribute__((no_sanitize("kcfi")))
static unsigned int probe_pointer_offset(uintptr_t base, uintptr_t target,
                                         unsigned int max)
{
    for (unsigned int off = 0; off < max; off += 8) {
        uintptr_t val = *(uintptr_t *)(base + off);
        if (val == target)
            return off;
    }
    return 0;
}

__attribute__((no_sanitize("kcfi")))
static int probe_task_struct_offsets(void)
{
    uintptr_t init_task_addr = (uintptr_t)ksyms_lookup("init_task");
    if (!init_task_addr) {
        pr_warn("uaccess: init_task not resolvable — offset probes skipped\n");
        return -1;
    }

    /* cred offset: find *(init_task + N) == &init_cred */
    uintptr_t init_cred_addr = (uintptr_t)ksyms_lookup("init_cred");
    if (init_cred_addr) {
        unsigned int off = probe_pointer_offset(init_task_addr,
                                                init_cred_addr, 0x1000);
        if (off) {
            kh_cred_offset = off;
            pr_info("uaccess: task_struct.cred offset = 0x%x\n", off);
        } else {
            pr_warn("uaccess: could not locate cred offset in init_task\n");
        }
    } else {
        pr_warn("uaccess: init_cred not resolvable — cred offset unknown\n");
    }

    /* stack offset: find *(init_task + N) == &init_thread_union (or
     * init_stack, depending on kernel). Fall back to 0x20 on failure. */
    uintptr_t init_stack_addr = (uintptr_t)ksyms_lookup("init_thread_union");
    if (!init_stack_addr)
        init_stack_addr = (uintptr_t)ksyms_lookup("init_stack");

    if (init_stack_addr) {
        unsigned int off = probe_pointer_offset(init_task_addr,
                                                init_stack_addr, 0x200);
        if (off) {
            kh_stack_offset = off;
            kh_stack_offset_probed = 1;
            pr_info("uaccess: task_struct.stack offset = 0x%x (probed)\n", off);
        } else {
            pr_info("uaccess: task_struct.stack offset = 0x%x (default)\n",
                    kh_stack_offset);
        }
    } else {
        pr_info("uaccess: init_thread_union unresolved, stack offset = 0x%x (default)\n",
                kh_stack_offset);
    }

    return kh_cred_offset ? 0 : -1;
}

__attribute__((no_sanitize("kcfi")))
int kh_uaccess_init(void)
{
#ifdef KMOD_FREESTANDING
    kh_strncpy_from_user_fn = (kh_strncpy_from_user_fn_t)(uintptr_t)
        ksyms_lookup("strncpy_from_user");

    /* Try in order: _copy_to_user, copy_to_user, __arch_copy_to_user.
     * GKI 6.1 arm64 only exports __arch_copy_to_user — the arch-specific
     * primitive that copy_to_user() eventually calls. Same ABI: returns
     * bytes NOT copied. Skips access_ok() + KASAN checks, which is fine
     * for us since we originate user pointers from pt_regs (already
     * validated by entry path) or from current's own SP. */
    kh_copy_to_user_fn = (kh_copy_to_user_fn_t)(uintptr_t)
        ksyms_lookup("_copy_to_user");
    if (!kh_copy_to_user_fn)
        kh_copy_to_user_fn = (kh_copy_to_user_fn_t)(uintptr_t)
            ksyms_lookup("copy_to_user");
    if (!kh_copy_to_user_fn)
        kh_copy_to_user_fn = (kh_copy_to_user_fn_t)(uintptr_t)
            ksyms_lookup("__arch_copy_to_user");
#else
    /* In kbuild, strncpy_from_user / copy_to_user may be macros that
     * expand to inlines with access_ok() checks. Take their addresses
     * through (intentional) cast — kernel headers declare them as
     * plain functions on arm64. */
    kh_strncpy_from_user_fn = (kh_strncpy_from_user_fn_t)&strncpy_from_user;
    kh_copy_to_user_fn      = (kh_copy_to_user_fn_t)&_copy_to_user;
#endif

    pr_info("uaccess: strncpy_from_user=%llx copy_to_user=%llx\n",
            (unsigned long long)(uintptr_t)kh_strncpy_from_user_fn,
            (unsigned long long)(uintptr_t)kh_copy_to_user_fn);

    if (!kh_strncpy_from_user_fn || !kh_copy_to_user_fn) {
        pr_warn("uaccess: required uaccess symbols missing\n");
        /* Continue to probe offsets anyway — kh_current_uid may still
         * be usable even without userspace copy primitives. */
    }

    probe_task_struct_offsets();

    /* cred.uid offset = 4 on all modern kernels (struct cred starts
     * with atomic_t usage; uid comes immediately after). Hardcoded. */
    kh_cred_uid_offset = 4;

    return (kh_strncpy_from_user_fn && kh_copy_to_user_fn) ? 0 : -1;
}
