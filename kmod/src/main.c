/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * kernelhook.ko — ARM64 function hooking kernel module.
 *
 * Usage:
 *   insmod kernelhook.ko [kallsyms_addr=0x...]
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>

#include <types.h>
#include <hook.h>
#include <sync.h>
#include <memory.h>
#include <symbol.h>
#include <linux/printk.h>

#include <arch/arm64/pgtable.h>

#include "compat.h"
#include "mem_ops.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("bmax121");
MODULE_DESCRIPTION("KernelHook: ARM64 function hooking framework");

#ifdef KMOD_FREESTANDING
MODULE_VERSIONS();
MODULE_VERMAGIC();
MODULE_THIS_MODULE();
#endif

/* Force into .data (not .bss) so kmod_loader's patch_elf_symbol can write
 * the resolved address into the file-backed section. See exporter.c for the
 * full rationale (Plan 2 M-E T17 fix). */
static unsigned long kallsyms_addr __attribute__((used, section(".data"))) = 0;
module_param(kallsyms_addr, ulong, 0444);
MODULE_PARM_DESC(kallsyms_addr, "Address of kallsyms_lookup_name (hex, required for freestanding builds)");

extern void hook_chain_setup_transit(hook_chain_rox_t *rox);
extern void fp_hook_chain_setup_transit(fp_hook_chain_rox_t *rox);
extern void kh_write_insts_init(void);
extern void kh_write_insts_cleanup(void);

static int kh_initialized = 0;

static int __init kernelhook_init(void)
{
    int rc;

    pr_info("kernelhook: loading...\n");

    rc = kmod_compat_init(kallsyms_addr);
    if (rc) {
        pr_err("kernelhook: compat init failed (%d)\n", rc);
        return rc;
    }

    rc = kmod_hook_mem_init();
    if (rc) {
        pr_err("kernelhook: hook_mem init failed (%d)", rc);
        return rc;
    }

    /* Initialize page table walker — required for hook_install() to
     * modify kernel code pages via PTE manipulation. */
    rc = kh_pgtable_init();
    if (rc) {
        pr_err("kernelhook: kh_pgtable_init failed (%d)", rc);
        kmod_hook_mem_cleanup();
        return rc;
    }

    /* Resolve set_memory_rw/ro/x for write_insts_at */
    kh_write_insts_init();

    rc = sync_init();
    if (rc) {
        pr_err("kernelhook: sync init failed (%d)\n", rc);
        kmod_hook_mem_cleanup();
        return rc;
    }

    kh_initialized = 1;
    pr_info("kernelhook: loaded successfully (kernel %d.%d.%d)",
          kmod_kernel_major, kmod_kernel_minor, kmod_kernel_patch);

    return 0;
}

/*
 * IMPORTANT: Consumer modules MUST call hook_unwrap()/unhook() for all
 * their hooks before kernelhook.ko is unloaded. This module does not
 * track or teardown hooks registered by other modules.
 */
static void __exit kernelhook_exit(void)
{
    if (kh_initialized) {
        sync_cleanup();
        kh_write_insts_cleanup();
        kmod_hook_mem_cleanup();
        pr_info("kernelhook: unloaded");
    }
}

module_init(kernelhook_init);
module_exit(kernelhook_exit);
