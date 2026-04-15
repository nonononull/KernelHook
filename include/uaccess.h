/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2026 bmax121.
 *
 * KernelHook user-pointer helpers — trimmed port of KernelPatch
 * kernel/patch/common/utils.c. Provides the minimum primitives that
 * syscall hooks (Phase 5b, Phase 6) need to read and rewrite userspace
 * strings.
 */

#ifndef _KH_UACCESS_H_
#define _KH_UACCESS_H_

#include <types.h>

/*
 * uid_t: not declared by <types.h>. In freestanding, neither is it
 * provided by any shim header; in kbuild <linux/types.h> defines it.
 * Provide a local alias in both modes — redeclaring uid_t with the
 * same underlying type is harmless (C11 typedef redefinition rule).
 */
#ifdef KMOD_FREESTANDING
typedef uint32_t kh_uid_t;
#else
#include <linux/types.h>  /* uid_t — kernel uses __kernel_uid32_t = u32 */
typedef uid_t kh_uid_t;
#endif

/* Copy a NUL-terminated string from userspace into `dest`. Returns
 * bytes copied INCLUDING the NUL terminator on success (KP semantics),
 * 0 or negative on error. `count` includes space for NUL. */
long kh_strncpy_from_user(char *dest, const void *src_user, long count);

/* Copy `n` bytes from kernel `from` to user `to`. Kernel semantics:
 * returns number of bytes NOT copied (0 == full success). */
int kh_copy_to_user(void *to_user, const void *from, int n);

/* Write `len` bytes of `data` onto current task's user stack at
 * SP - aligned(len). Returns resulting __user pointer on success, or
 * a value where `(long)rc < 0` is true on failure. Caller must run
 * in current's process context with a valid user mm. */
void *kh_copy_to_user_stack(const void *data, int len);

/* Read current task's uid via probed task_struct.cred offset.
 * Returns 0 when the offset could not be resolved (safe default). */
kh_uid_t kh_current_uid(void);

/* Resolve ksyms + probe task_struct.cred offset. Idempotent. Returns
 * 0 on success, <0 if required symbols (strncpy_from_user /
 * copy_to_user) could not be resolved. */
int kh_uaccess_init(void);

#endif /* _KH_UACCESS_H_ */
