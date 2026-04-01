/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * hook_chain.c — Hook chain with priority ordering example.
 *
 * Demonstrates hook_wrap with multiple callbacks at different priorities.
 * Three before-callbacks are registered with priorities 0, 50, 100
 * (in arbitrary order) to show that priority controls execution order,
 * not registration order.
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
MODULE_DESCRIPTION("KernelHook hook_chain example: multiple callbacks with priority ordering");

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

static void *hooked_func = NULL;

/* ---- Before callbacks at different priorities ---- */

static void before_high_priority(hook_fargs4_t *fargs, void *udata)
{
	logki("hook_chain: [priority 0] HIGH priority before callback");
}

static void before_medium_priority(hook_fargs4_t *fargs, void *udata)
{
	logki("hook_chain: [priority 50] MEDIUM priority before callback");
}

static void before_low_priority(hook_fargs4_t *fargs, void *udata)
{
	logki("hook_chain: [priority 100] LOW priority before callback");
}

/* ---- After callback ---- */

static void after_callback(hook_fargs4_t *fargs, void *udata)
{
	logki("hook_chain: after callback, ret=%lld", (long long)fargs->ret);
}

/* ---- Module init / exit ---- */

static int __init hook_chain_init(void)
{
	int rc;
	void *target;
	hook_err_t err;

#if !defined(KH_SDK_MODE)
	rc = kmod_compat_init(kallsyms_addr);
	if (rc) {
		pr_err("hook_chain: compat init failed (%d)\n", rc);
		return 0;
	}

	rc = kmod_hook_mem_init();
	if (rc) {
		logke("hook_chain: hook_mem init failed (%d)", rc);
		return 0;
	}

	rc = pgtable_init();
	if (rc) {
		logke("hook_chain: pgtable_init failed (%d)", rc);
		kmod_hook_mem_cleanup();
		return 0;
	}

	{
		extern void kh_write_insts_init(void);
		kh_write_insts_init();
	}
#endif

	/* Resolve target */
	target = (void *)ksyms_lookup("do_sys_openat2");
	if (!target)
		target = (void *)ksyms_lookup("do_sys_open");
	if (!target) {
		logke("hook_chain: target function not found");
#if !defined(KH_SDK_MODE)
		kmod_hook_mem_cleanup();
#endif
		return 0;
	}

	/*
	 * Register 3 before callbacks in arbitrary order (medium, low, high)
	 * to demonstrate that priority controls execution order.
	 * Lower priority number = higher priority = runs first.
	 */
	err = hook_wrap(target, 4, (void *)before_medium_priority, NULL, NULL, 50);
	if (err != HOOK_NO_ERR) {
		logke("hook_chain: hook_wrap medium failed (%d)", (int)err);
#if !defined(KH_SDK_MODE)
		kmod_hook_mem_cleanup();
#endif
		return 0;
	}

	err = hook_wrap(target, 4, (void *)before_low_priority, (void *)after_callback, NULL, 100);
	if (err != HOOK_NO_ERR) {
		logke("hook_chain: hook_wrap low failed (%d)", (int)err);
		hook_unwrap(target, (void *)before_medium_priority, NULL);
#if !defined(KH_SDK_MODE)
		kmod_hook_mem_cleanup();
#endif
		return 0;
	}

	err = hook_wrap(target, 4, (void *)before_high_priority, NULL, NULL, 0);
	if (err != HOOK_NO_ERR) {
		logke("hook_chain: hook_wrap high failed (%d)", (int)err);
		hook_unwrap(target, (void *)before_medium_priority, NULL);
		hook_unwrap(target, (void *)before_low_priority, (void *)after_callback);
#if !defined(KH_SDK_MODE)
		kmod_hook_mem_cleanup();
#endif
		return 0;
	}

	hooked_func = target;
	logki("hook_chain: registered 3 before callbacks + 1 after callback at %llx",
	      (unsigned long long)(uintptr_t)target);
	logki("hook_chain: execution order will be: high(0) -> medium(50) -> low(100)");
	return 0;
}

static void __exit hook_chain_exit(void)
{
	if (hooked_func) {
		hook_unwrap(hooked_func, (void *)before_high_priority, NULL);
		hook_unwrap(hooked_func, (void *)before_medium_priority, NULL);
		hook_unwrap(hooked_func, (void *)before_low_priority, (void *)after_callback);
		hooked_func = NULL;
		logki("hook_chain: all callbacks removed");
	}
#if !defined(KH_SDK_MODE)
	kmod_hook_mem_cleanup();
#endif
}

module_init(hook_chain_init);
module_exit(hook_chain_exit);
