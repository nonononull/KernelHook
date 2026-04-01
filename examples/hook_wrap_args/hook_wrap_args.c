/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * hook_wrap_args.c — Argument inspection and return value override example.
 *
 * Demonstrates hook_wrap4 with both before and after callbacks:
 *   - before: log arg0-arg3
 *   - after: log original return value, then override with 0
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
MODULE_DESCRIPTION("KernelHook hook_wrap_args example: inspect args and override return value");

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

/* ---- Before callback: inspect arguments ---- */

/*
 * do_sys_openat2(int dfd, const char __user *filename,
 *                struct open_how *how)
 *
 * arg0 = dfd, arg1 = filename, arg2 = how pointer, arg3 = (unused)
 */
static void openat2_before(hook_fargs4_t *fargs, void *udata)
{
	logki("hook_wrap_args: BEFORE arg0(dfd)=%lld arg1(filename)=%llx "
	      "arg2(how)=%llx arg3=%llx",
	      (long long)fargs->arg0,
	      (unsigned long long)fargs->arg1,
	      (unsigned long long)fargs->arg2,
	      (unsigned long long)fargs->arg3);
}

/* ---- After callback: inspect and override return value ---- */

static void openat2_after(hook_fargs4_t *fargs, void *udata)
{
	logki("hook_wrap_args: AFTER original ret=%lld, overriding with 0",
	      (long long)fargs->ret);
	fargs->ret = 0;
}

/* ---- Module init / exit ---- */

static int __init hook_wrap_args_init(void)
{
	int rc;
	void *target;
	hook_err_t err;

#if !defined(KH_SDK_MODE)
	rc = kmod_compat_init(kallsyms_addr);
	if (rc) {
		pr_err("hook_wrap_args: compat init failed (%d)\n", rc);
		return 0;
	}

	rc = kmod_hook_mem_init();
	if (rc) {
		logke("hook_wrap_args: hook_mem init failed (%d)", rc);
		return 0;
	}

	rc = pgtable_init();
	if (rc) {
		logke("hook_wrap_args: pgtable_init failed (%d)", rc);
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
		logke("hook_wrap_args: target function not found");
#if !defined(KH_SDK_MODE)
		kmod_hook_mem_cleanup();
#endif
		return 0;
	}

	err = hook_wrap4(target, openat2_before, openat2_after, NULL);
	if (err != HOOK_NO_ERR) {
		logke("hook_wrap_args: hook_wrap4 failed (%d)", (int)err);
#if !defined(KH_SDK_MODE)
		kmod_hook_mem_cleanup();
#endif
		return 0;
	}

	hooked_func = target;
	logki("hook_wrap_args: hooked do_sys_open* at %llx",
	      (unsigned long long)(uintptr_t)target);
	return 0;
}

static void __exit hook_wrap_args_exit(void)
{
	if (hooked_func) {
		hook_unwrap(hooked_func, (void *)openat2_before, (void *)openat2_after);
		hooked_func = NULL;
		logki("hook_wrap_args: unhooked");
	}
#if !defined(KH_SDK_MODE)
	kmod_hook_mem_cleanup();
#endif
}

module_init(hook_wrap_args_init);
module_exit(hook_wrap_args_exit);
