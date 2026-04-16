/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2026 bmax121.
 *
 * Internal ARM64 inline-hook helpers exposed for use by strategy modules.
 *
 * Build modes: shared (freestanding + kbuild + userspace stub)
 * Depends on: types.h
 */

#ifndef KH_ARCH_ARM64_INLINE_H
#define KH_ARCH_ARM64_INLINE_H

#include <types.h>

/*
 * write_insts_via_alias — write one or more instructions to kernel text
 * via the vmalloc alias-page PTE-swap path.
 *
 * Bypasses __ro_after_init on GKI kernel text by mapping an alias VA
 * to the same physical page as the target text VA, then writing through
 * aarch64_insn_patch_text_nosync. In kbuild mode the write sequence is
 * wrapped in stop_machine() to prevent other CPUs from observing
 * intermediate trampoline states during multi-instruction patches.
 *
 * Returns 0 on success, -1 if the alias path is unavailable (signals
 * caller to try the set_memory or direct-PTE fallback).
 */
int write_insts_via_alias(uintptr_t va, uint32_t *insts, int32_t count);

#endif /* KH_ARCH_ARM64_INLINE_H */
