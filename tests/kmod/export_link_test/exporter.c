/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Ring 2 / Ring 3 test: minimal freestanding exporter.
 *
 * Built through the full kmod.mk pipeline, so the resulting .ko pulls in
 * kmod/src/export.c + the kh_crc-generated kh_exports.S. That populates the
 * __ksymtab / __ksymtab_strings / __kcrctab sections with the real entries
 * (hook_wrap, ksyms_lookup, ...) that Ring 2's verify_elf.sh checks.
 *
 * The init path bootstraps ksyms (via kmod_compat_init) so that when
 * importer.ko later calls ksyms_lookup("do_sys_openat2") it resolves to a
 * real address instead of 0. No hooking is done here — the module exists
 * purely to validate the export pipeline at the ELF level (Ring 2) and
 * that cross-module symbol resolution works at load time (Ring 3).
 */

#include "shim.h"
#include <ktypes.h>
#include <ksyms.h>
#include "../../../kmod/src/compat.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("bmax121");
MODULE_DESCRIPTION("KernelHook export_link_test exporter");

MODULE_VERSIONS();
MODULE_VERMAGIC();
MODULE_THIS_MODULE();

/* Force into .data (not .bss) so kmod_loader's patch_elf_symbol can
 * write the resolved value to the file-backed section. BSS is NOBITS
 * and is zeroed by the kernel at module load time, defeating the patch. */
static unsigned long kallsyms_addr __attribute__((used, section(".data"))) = 0;
module_param(kallsyms_addr, ulong, 0444);
MODULE_PARM_DESC(kallsyms_addr, "Address of kallsyms_lookup_name (hex, required)");

static int __init exporter_init(void)
{
    int rc = kmod_compat_init(kallsyms_addr);
    if (rc) {
        pr_err("export_link_test exporter: compat init failed (%d)\n", rc);
        return rc;
    }
    pr_info("export_link_test exporter: loaded\n");
    return 0;
}

static void __exit exporter_exit(void)
{
    pr_info("export_link_test exporter: unloaded\n");
}

module_init(exporter_init);
module_exit(exporter_exit);
