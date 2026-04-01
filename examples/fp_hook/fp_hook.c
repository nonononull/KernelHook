/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * fp_hook.c — Function pointer hooking example.
 *
 * Demonstrates fp_hook / fp_unhook / fp_get_origin_func:
 *   - Define a struct with a function pointer callback
 *   - Hook it with a replacement function
 *   - Call the original via a backup pointer
 *   - Unhook on exit
 */

#if defined(KH_SDK_MODE)
/* Mode B: SDK — kernelhook.ko provides the API */
#include <kernelhook/hook.h>
#include <kernelhook/types.h>
#elif defined(KMOD_FREESTANDING)
/* Mode A: freestanding shim */
#include "../../kmod/shim/kmod_shim.h"
#include <ktypes.h>
#include <hook.h>
#include <ksyms.h>
#include <log.h>
#include <hmem.h>
#include <arch/arm64/pgtable.h>
#include "../../kmod/src/compat.h"
#include "../../kmod/src/mem_ops.h"
#else
/* Mode C: standard kernel headers */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <ktypes.h>
#include <hook.h>
#include <ksyms.h>
#include <log.h>
#include <hmem.h>
#include <arch/arm64/pgtable.h>
#endif

MODULE_LICENSE("GPL");
MODULE_AUTHOR("bmax121");
MODULE_DESCRIPTION("KernelHook fp_hook example: function pointer hooking");

#ifdef KMOD_FREESTANDING
MODULE_VERSIONS();
MODULE_VERMAGIC();
MODULE_THIS_MODULE();
#endif

#if !defined(KH_SDK_MODE)
static unsigned long kallsyms_addr = 0;
module_param(kallsyms_addr, ulong, 0444);
MODULE_PARM_DESC(kallsyms_addr, "Address of kallsyms_lookup_name (hex, required)");
#endif

/* ---- Demo struct with function pointer ---- */

struct demo_ops {
	int (*callback)(int x, int y);
};

static void *backup_func = NULL;

static int __attribute__((noinline)) original_callback(int x, int y)
{
	return x + y;
}

static int replacement_callback(int x, int y)
{
	logki("fp_hook: replacement called with x=%d y=%d", x, y);
	/* Call original via backup pointer */
	if (backup_func) {
		int orig_result = ((int (*)(int, int))backup_func)(x, y);
		logki("fp_hook: original returned %d, we return %d", orig_result, x * y);
	}
	return x * y;
}

static struct demo_ops ops = {
	.callback = original_callback,
};

/* ---- Module init / exit ---- */

static int __init fp_hook_init(void)
{
	int result;

#if !defined(KH_SDK_MODE)
	result = kmod_compat_init(kallsyms_addr);
	if (result) {
		pr_err("fp_hook: compat init failed (%d)\n", result);
		return 0;
	}

	result = kmod_hook_mem_init();
	if (result) {
		logke("fp_hook: hook_mem init failed (%d)", result);
		return 0;
	}

	result = pgtable_init();
	if (result) {
		logke("fp_hook: pgtable_init failed (%d)", result);
		kmod_hook_mem_cleanup();
		return 0;
	}

	{
		extern void kh_write_insts_init(void);
		kh_write_insts_init();
	}
#endif

	/* Call original before hooking */
	result = ops.callback(3, 4);
	logki("fp_hook: before hook: ops.callback(3,4) = %d", result);

	/* Hook the function pointer */
	fp_hook((uintptr_t)&ops.callback, replacement_callback, &backup_func);
	logki("fp_hook: function pointer hooked, backup=%llx",
	      (unsigned long long)(uintptr_t)backup_func);

	/* Call through the struct — replacement should run */
	result = ops.callback(3, 4);
	logki("fp_hook: after hook: ops.callback(3,4) = %d", result);

	return 0;
}

static void __exit fp_hook_exit(void)
{
	if (backup_func) {
		fp_unhook((uintptr_t)&ops.callback, backup_func);
		backup_func = NULL;
		logki("fp_hook: unhooked");
	}

	/* Verify original is restored */
	int result = ops.callback(3, 4);
	logki("fp_hook: after unhook: ops.callback(3,4) = %d", result);

#if !defined(KH_SDK_MODE)
	kmod_hook_mem_cleanup();
#endif
}

module_init(fp_hook_init);
module_exit(fp_hook_exit);
