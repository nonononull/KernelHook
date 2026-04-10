// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * kbuild_hello_main.c — Mode C (kbuild) SDK consumer example.
 *
 * Unlike examples/hello_hook/ which statically links the KernelHook
 * core library into its own .ko, this module depends on an externally
 * built kernelhook.ko being loaded at insmod time. The Kbuild file
 * wires the dependency via KBUILD_EXTRA_SYMBOLS pointing at
 * kmod/Module.symvers (see the sibling Kbuild file).
 *
 * Build:
 *   # 1. Build kernelhook.ko first (produces kmod/Module.symvers):
 *   make -C $KERNEL_SRC M=$(pwd)/kmod modules
 *   # 2. Then build this consumer against those symbols:
 *   make -C $KERNEL_SRC M=$(pwd)/examples/kbuild_hello \
 *        KBUILD_EXTRA_SYMBOLS=$(pwd)/kmod/Module.symvers modules
 *
 * Load order at runtime:
 *   insmod kernelhook.ko kallsyms_addr=0x<addr>  # (or rely on kprobes fallback)
 *   insmod kbuild_hello.ko
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>

#include <ktypes.h>
#include <hook.h>
#include <ksyms.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("bmax121");
MODULE_DESCRIPTION("KernelHook kbuild SDK consumer example: log every vfs_open");

/* Saved target for unhook on exit */
static void *hooked_func;

/*
 * vfs_open(const struct path *path, struct file *file)
 *
 * arg0 = path, arg1 = file
 * Available since Linux 4.x — chosen over do_sys_openat2 for portability
 * (consistent with Plan 2 Ring 3 test which also hooks vfs_open).
 */
static void vfs_open_before(hook_fargs2_t *fargs, void *udata)
{
    pr_info("kbuild_hello: vfs_open path=%llx file=%llx\n",
            (unsigned long long)fargs->arg0,
            (unsigned long long)fargs->arg1);
}

static int __init kbuild_hello_init(void)
{
    void *target = (void *)ksyms_lookup("vfs_open");
    hook_err_t err;

    if (!target) {
        pr_err("kbuild_hello: vfs_open not found\n");
        return -ENOENT;
    }

    err = hook_wrap2(target, vfs_open_before, NULL, NULL);
    if (err != HOOK_NO_ERR) {
        pr_err("kbuild_hello: hook_wrap2 failed (%d)\n", (int)err);
        return -EIO;
    }

    hooked_func = target;
    pr_info("kbuild_hello: hooked vfs_open at %llx\n",
            (unsigned long long)(uintptr_t)target);
    return 0;
}

static void __exit kbuild_hello_exit(void)
{
    if (hooked_func) {
        hook_unwrap(hooked_func, vfs_open_before, NULL);
        hooked_func = NULL;
        pr_info("kbuild_hello: unhooked\n");
    }
}

module_init(kbuild_hello_init);
module_exit(kbuild_hello_exit);
