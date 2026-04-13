/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * KernelHook public API exports.
 *
 * This file is the human-readable source of truth for what is exported.
 * It MUST stay in sync with kmod/exports.manifest — enforced by
 * scripts/lint_exports.sh at build time.
 *
 * In freestanding mode (KMOD_FREESTANDING) KH_EXPORT is a no-op:
 *   the actual __ksymtab_xxx / __kcrctab_xxx sections are populated by
 *   kmod/generated/kh_exports.S (emitted by tools/kh_crc).
 *
 * In kbuild mode (Deliverable C, separate spec) KH_EXPORT resolves to
 *   the standard EXPORT_SYMBOL() macro.
 */

#include <hook.h>
#include <memory.h>
#include <symbol.h>
#include <linux/export.h>

#define KH_EXPORT(sym) EXPORT_SYMBOL(sym)

KH_EXPORT(hook_prepare);
KH_EXPORT(hook_install);
KH_EXPORT(hook_uninstall);

KH_EXPORT(hook);
KH_EXPORT(unhook);

KH_EXPORT(hook_chain_add);
KH_EXPORT(hook_chain_remove);
KH_EXPORT(hook_wrap);
KH_EXPORT(hook_unwrap_remove);
KH_EXPORT(hook_chain_setup_transit);

KH_EXPORT(fp_hook);
KH_EXPORT(fp_unhook);
KH_EXPORT(fp_hook_wrap);
KH_EXPORT(fp_hook_unwrap);
KH_EXPORT(fp_hook_chain_setup_transit);

KH_EXPORT(ksyms_lookup);
