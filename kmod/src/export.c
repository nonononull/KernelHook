/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Export KernelHook API symbols for use by other kernel modules.
 */

#include <hook.h>
#include <hmem.h>
#include <ksyms.h>
#include <export.h>

KP_EXPORT_SYMBOL(hook);
KP_EXPORT_SYMBOL(unhook);

KP_EXPORT_SYMBOL(hook_wrap0);
KP_EXPORT_SYMBOL(hook_wrap1);
KP_EXPORT_SYMBOL(hook_wrap2);
KP_EXPORT_SYMBOL(hook_wrap3);
KP_EXPORT_SYMBOL(hook_wrap4);
KP_EXPORT_SYMBOL(hook_wrap5);
KP_EXPORT_SYMBOL(hook_wrap6);
KP_EXPORT_SYMBOL(hook_wrap7);
KP_EXPORT_SYMBOL(hook_wrap8);
KP_EXPORT_SYMBOL(hook_wrap9);
KP_EXPORT_SYMBOL(hook_wrap10);
KP_EXPORT_SYMBOL(hook_wrap11);
KP_EXPORT_SYMBOL(hook_wrap12);
KP_EXPORT_SYMBOL(hook_unwrap);
KP_EXPORT_SYMBOL(hook_wrap_pri);

KP_EXPORT_SYMBOL(fp_hook);
KP_EXPORT_SYMBOL(fp_unhook);
KP_EXPORT_SYMBOL(fp_hook_wrap_pri);
KP_EXPORT_SYMBOL(fp_hook_unwrap);
KP_EXPORT_SYMBOL(fp_get_origin_func);

KP_EXPORT_SYMBOL(ksyms_lookup);
KP_EXPORT_SYMBOL(ksyms_lookup_cache);
