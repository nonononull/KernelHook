/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2026 bmax121.
 *
 * 64-bit ARM64 syscall name table. Port of
 * ref/KernelPatch/kernel/patch/common/sysname.c:syscall_name_table,
 * compat table dropped.
 *
 * The table is indexed directly by syscall number. Entries with
 * name==NULL are reserved/unused slots. Names carry the `sys_` prefix
 * matching what the kernel emits as kallsyms symbols — the probe in
 * src/platform/syscall.c prepends `__arm64_` and tries `.cfi` /
 * `.cfi_jt` suffixes to cover CFI-jump-table builds (Pixel GKI 6.1).
 */

#ifndef _KH_SYSCALL_NAMES_H_
#define _KH_SYSCALL_NAMES_H_

#include <types.h>

/* Table capacity — matches KernelPatch (covers __NR_cachestat = 451). */
#define KH_SYSCALL_NAME_TABLE_SIZE 460

struct kh_syscall_name_entry {
    const char *name;   /* "sys_openat" etc.; NULL for reserved slots */
    uintptr_t   addr;   /* lazy-filled by kh_syscalln_name_addr() */
};

extern struct kh_syscall_name_entry
    kh_syscall_name_table[KH_SYSCALL_NAME_TABLE_SIZE];

#endif /* _KH_SYSCALL_NAMES_H_ */
