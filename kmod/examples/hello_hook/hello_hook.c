/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * hello_hook.c — minimal KernelHook example module.
 *
 * Hooks do_sys_openat2 (or do_sys_open on older kernels) and logs
 * the filename pointer on every open syscall.
 *
 * Build:
 *   cd kmod/examples/hello_hook && make module
 *
 * Load (requires kallsyms_lookup_name address):
 *   insmod hello_hook.ko kallsyms_addr=0x<addr>
 */

#ifdef KMOD_FREESTANDING
#include "../../shim/kmod_shim.h"
#else
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#endif

#include <ktypes.h>
#include <hook.h>
#include <ksyms.h>
#include <log.h>
#include <hmem.h>

#include <arch/arm64/pgtable.h>

#include "../../src/compat.h"
#include "../../src/mem_ops.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("bmax121");
MODULE_DESCRIPTION("KernelHook hello_hook example: log every open syscall");

#ifdef KMOD_FREESTANDING
MODULE_VERSIONS();
MODULE_VERMAGIC();
MODULE_THIS_MODULE();
#endif

static unsigned long kallsyms_addr = 0;
module_param(kallsyms_addr, ulong, 0444);
MODULE_PARM_DESC(kallsyms_addr, "Address of kallsyms_lookup_name (hex, required)");

/* The function we hooked — saved for unhook on exit */
static void *hooked_func = NULL;

/* ---- Before callback ---- */

/*
 * do_sys_openat2(int dfd, const char __user *filename,
 *                struct open_how *how)
 *
 * arg0 = dfd, arg1 = filename ptr, arg2 = open_how ptr
 * We only need the filename, so hook_wrap4 (≥4 regs captured) is
 * sufficient — arg1 is the user-space filename pointer.
 */
static void open_before(hook_fargs4_t *fargs, void *udata)
{
    /* arg1 is the user-space filename pointer */
    const char *filename = (const char *)fargs->arg1;
    logki("hello_hook: open called, filename ptr=%llx", (unsigned long long)(uintptr_t)filename);
}

/* ---- Module init / exit ---- */

static int __init hello_hook_init(void)
{
    int rc;

    rc = kmod_compat_init(kallsyms_addr);
    if (rc) {
        pr_err("hello_hook: compat init failed (%d)\n", rc);
        return rc;
    }

    rc = kmod_hook_mem_init();
    if (rc) {
        logke("hello_hook: hook_mem init failed (%d)", rc);
        return rc;
    }

    rc = pgtable_init();
    if (rc) {
        logke("hello_hook: pgtable_init failed (%d)", rc);
        kmod_hook_mem_cleanup();
        return rc;
    }

    /* Resolve set_memory_* for trampoline installation */
    {
        extern void kh_write_insts_init(void);
        kh_write_insts_init();
    }

    /* Resolve target — prefer do_sys_openat2 (kernel ≥ 5.6), fall back to
     * do_sys_open (older kernels). */
    void *target = (void *)ksyms_lookup("do_sys_openat2");
    if (!target)
        target = (void *)ksyms_lookup("do_sys_open");
    if (!target) {
        logke("hello_hook: do_sys_openat2 / do_sys_open not found");
        kmod_hook_mem_cleanup();
        return -ENOENT;
    }

    hook_err_t err = hook_wrap4(target, open_before, NULL, NULL);
    if (err != HOOK_NO_ERR) {
        logke("hello_hook: hook_wrap4 failed (%d)", (int)err);
        kmod_hook_mem_cleanup();
        return -1;
    }

    hooked_func = target;
    logki("hello_hook: hooked do_sys_open* at %llx", (unsigned long long)(uintptr_t)target);
    return 0;
}

static void __exit hello_hook_exit(void)
{
    if (hooked_func) {
        hook_unwrap(hooked_func, open_before, NULL);
        hooked_func = NULL;
        logki("hello_hook: unhooked");
    }
    kmod_hook_mem_cleanup();
}

module_init(hello_hook_init);
module_exit(hello_hook_exit);
