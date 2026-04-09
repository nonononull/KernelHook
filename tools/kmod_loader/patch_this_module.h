/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef _KH_PATCH_THIS_MODULE_H_
#define _KH_PATCH_THIS_MODULE_H_

#include <stdint.h>
#include <stdio.h>

/* NOTE: This header requires a hosted C environment (<stdio.h>/fprintf).
 * Do NOT include from freestanding (kernel-module) translation units. */

/* kver_preset mirrors the struct in tools/kmod_loader/kmod_loader.c:47.
 * Defined here so both kmod_loader.c and the unit test link without
 * pulling the full loader. Field order/types MUST stay in sync with
 * that definition — kmod_loader.c should include this header and
 * REMOVE its local definition to guarantee a single source of truth. */
struct kver_preset {
    int      major;
    int      minor;
    uint32_t mod_size;
    uint32_t init_off;
    uint32_t exit_off;
};

/* Shrink the sh_size of a .gnu.linkonce.this_module section header
 * (pointed to by sh_size_ptr) to match the running kernel's
 * sizeof(struct module), taken from a resolved preset.
 *
 * The signature takes an unsigned long long * rather than an
 * Elf64_Shdr * deliberately — it avoids a dependency on <elf.h>,
 * which is missing on macOS hosts. The caller (patch_module_layout
 * in kmod_loader.c) passes &this_mod->sh_size, where sh_size has
 * type Elf64_Xword. On Linux NDK and glibc/musl, Elf64_Xword resolves
 * to `unsigned long long` via the kernel's __u64 typedef — matching
 * this parameter type exactly and avoiding a -Wincompatible-pointer-
 * types warning that would otherwise fire on aarch64 LP64 where
 * uint64_t is `unsigned long`.
 *
 * Required by Android 15 GKI 6.6+ downstream kernels, which enforce
 * that the .gnu.linkonce.this_module section size exactly equals
 * sizeof(struct module) at load time and reject otherwise with
 * -ENOEXEC. Safe on older kernels because we never zero the section
 * and the kernel loader on pre-6.6 does not check the size.
 *
 * Defensive: if either init_off or exit_off would land outside the
 * shrunk range, we refuse and leave sh_size untouched (the kernel
 * will then still reject, surfacing a clear error).
 *
 * Contract: callers are expected to pass a preset whose init_off and
 * exit_off have been fully resolved (non-zero) by the resolver chain
 * before calling. The helper does NOT distinguish "legitimate offset
 * of zero" from "unresolved / zero-initialized". All realistic GKI
 * ARM64 presets have init_off and exit_off well above struct
 * module.name (offset 24), so a zero value here indicates a resolver
 * bug rather than a real kernel.
 *
 * Return:
 *   1  shrink applied — caller may log a trace line
 *   0  no-op (preset->mod_size is zero, or current sh_size already <= target)
 *  -1  refused — a relocation target would be cut off by the shrink
 */
static inline int
maybe_shrink_this_module_sh_size(unsigned long long *sh_size_ptr,
                                 const struct kver_preset *preset)
{
    if (!sh_size_ptr || !preset) return 0;
    if (preset->mod_size == 0) return 0;
    if (*sh_size_ptr <= preset->mod_size) return 0;

    uint32_t rela_max = preset->init_off;
    if (preset->exit_off > rela_max) rela_max = preset->exit_off;

    /* Reloc writes an 8-byte pointer at r_offset. We use a literal 8
     * rather than sizeof(void *) because this check reasons about the
     * ARM64 target's relocation width, not the build host's pointer
     * size — sizeof(void *) would be wrong if this helper were ever
     * compiled on a 32-bit host. */
    if ((unsigned long long)rela_max + 8ULL > preset->mod_size) {
        fprintf(stderr,
            "kmod_loader: sh_size shrink refused: reloc target 0x%x would exceed "
            "0x%x (current 0x%llx)\n",
            rela_max, preset->mod_size, *sh_size_ptr);
        return -1;
    }

    fprintf(stderr,
        "kmod_loader: shrink this_module sh_size 0x%llx -> 0x%x\n",
        *sh_size_ptr, preset->mod_size);
    *sh_size_ptr = preset->mod_size;
    return 1;
}

#endif /* _KH_PATCH_THIS_MODULE_H_ */
