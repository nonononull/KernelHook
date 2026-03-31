/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * KernelHook SDK — public API for kernel module developers.
 *
 * Usage:
 *   #include <kernelhook/hook.h>
 *
 * Your module must depend on kernelhook.ko being loaded.
 *
 * Kernel source references:
 *   kallsyms_lookup_name: https://elixir.bootlin.com/linux/v6.1/source/kernel/kallsyms.c#L234
 *   set_memory_x:         https://elixir.bootlin.com/linux/v6.1/source/arch/arm64/mm/pageattr.c
 *   struct module:         https://elixir.bootlin.com/linux/v6.1/source/include/linux/module.h
 */
#ifndef _KERNELHOOK_HOOK_H_
#define _KERNELHOOK_HOOK_H_

#include <ktypes.h>
#include <hook.h>
#include <ksyms.h>

#endif
