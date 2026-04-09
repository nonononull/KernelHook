/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Ring 2 test: minimal freestanding importer (SDK mode).
 *
 * Built via kmod_sdk.mk — core library is NOT linked in. Instead, the module
 * references hook_wrap + ksyms_lookup as undefined symbols that the running
 * kernel resolves against a loaded kernelhook.ko. KH_DECLARE_VERSIONS() emits
 * the __versions entries with frozen CRCs from <kernelhook/kh_symvers.h>.
 */

#include "shim.h"
#include <ktypes.h>
#include <kernelhook/kh_symvers.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("bmax121");
MODULE_DESCRIPTION("KernelHook Ring 2 importer test");

/* Re-declare the two symbols we reference. Signatures match include/hook.h /
 * include/ksyms.h, but we avoid including them so this TU stays minimal. */
extern uint64_t ksyms_lookup(const char *name);
extern int hook_wrap(void *func, int argno, void *before, void *after,
                     void *udata, int priority);

static int __init importer_init(void)
{
    uint64_t addr = ksyms_lookup("do_sys_openat2");
    pr_info("export_link_test importer: do_sys_openat2 = 0x%llx\n",
            (unsigned long long)addr);
    /* Force an UND reference to hook_wrap so the symbol survives linking.
     * We never actually call it — addr==0 path returns before reaching it. */
    if (addr == 0) {
        (void)hook_wrap((void *)(uintptr_t)addr, 4, 0, 0, 0, 0);
        return -1;
    }
    return 0;
}

static void __exit importer_exit(void)
{
    pr_info("export_link_test importer: unloaded\n");
}

MODULE_VERSIONS();
KH_DECLARE_VERSIONS();
MODULE_VERMAGIC();
MODULE_THIS_MODULE();

module_init(importer_init);
module_exit(importer_exit);
