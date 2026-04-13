/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * ksyms_lookup.c — Runtime symbol resolution example.
 *
 * Demonstrates ksyms_lookup() and ksyms_lookup():
 *   - Look up multiple kernel symbols
 *   - Show cached vs uncached lookup
 *   - Handle nonexistent symbols gracefully
 *
 * This example does NOT need hook_mem_init or pgtable_init —
 * only kmod_compat_init for ksyms resolution.
 */

#if defined(KH_SDK_MODE)
/* Mode B: SDK — kernelhook.ko provides the API */
#include <kernelhook/hook.h>
#include <kernelhook/types.h>
#elif defined(KMOD_FREESTANDING)
/* Mode A: freestanding shim */
#include "../../kmod/shim/shim.h"
#include <types.h>
#include <hook.h>
#include <symbol.h>
#include "../../kmod/src/compat.h"
#else
/* Mode C: standard kernel headers */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <types.h>
#include <hook.h>
#include <symbol.h>
#endif

MODULE_LICENSE("GPL");
MODULE_AUTHOR("bmax121");
MODULE_DESCRIPTION("KernelHook ksyms_lookup example: runtime symbol resolution");

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

/* ---- Module init / exit ---- */

static int __init ksyms_lookup_init(void)
{
	uint64_t addr;

#if !defined(KH_SDK_MODE)
	int rc = kmod_compat_init(kallsyms_addr);
	if (rc) {
		pr_err("ksyms_lookup: compat init failed (%d)\n", rc);
		return 0;
	}
#endif

	/* Look up well-known kernel symbols */
	addr = ksyms_lookup("vfs_read");
	pr_info("ksyms_lookup: vfs_read = %llx", (unsigned long long)addr);

	addr = ksyms_lookup("vfs_write");
	pr_info("ksyms_lookup: vfs_write = %llx", (unsigned long long)addr);

	addr = ksyms_lookup("do_sys_openat2");
	pr_info("ksyms_lookup: do_sys_openat2 = %llx", (unsigned long long)addr);

	/* Another symbol lookup */
	addr = ksyms_lookup("vfs_read");
	pr_info("ksyms_lookup: vfs_read = %llx", (unsigned long long)addr);

	/* Nonexistent symbol — should return 0 */
	addr = ksyms_lookup("this_symbol_does_not_exist_xyz");
	pr_info("ksyms_lookup: nonexistent symbol = %llx (expected 0)",
	      (unsigned long long)addr);

	pr_info("ksyms_lookup: all lookups complete");
	return 0;
}

static void __exit ksyms_lookup_exit(void)
{
	pr_info("ksyms_lookup: module unloaded");
}

module_init(ksyms_lookup_init);
module_exit(ksyms_lookup_exit);
