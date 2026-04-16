/* src/strategies/kimage_voffset.c */
/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * SP-7 Capability: kimage_voffset
 *
 * Three fallback strategies for resolving the kernel image virtual-to-
 * physical offset (kimage_voffset = kernel_image_VA - kernel_image_PA):
 *   1. kallsyms         - direct lookup of the exported variable
 *   2. text_va_minus_pa - walk swapper_pg_dir for _text's PA and subtract
 *   3. loader_inject    - user-supplied value via iomem_textpa module_param
 *
 * Build modes: freestanding + kbuild (not userspace -- kernel-only).
 */

#include <kh_strategy.h>
#include <kh_log.h>
#include <types.h>

#ifdef __USERSPACE__
/* kimage_voffset strategies are kernel-only (require ksyms + ttbr1 walks).
 * In userspace builds the translation unit compiles to nothing. */
#else

#include <symbol.h>
#include <arch/arm64/pgtable.h>

/* Loader-injected PA of kernel text. When the kmod loader parses the
 * DTB / /proc/iomem and passes iomem_textpa=0x..., module_param writes
 * the kimage_voffset here. When no loader is configured, this stays 0
 * and the strategy falls through. Public (not static) because
 * module_param in kh_strategy_boot.c references it via extern. */
uint64_t kh_loader_injected_kimage_voffset;

static int strat_kallsyms(void *out, size_t sz)
{
    if (sz != sizeof(uint64_t)) return -22;
    uint64_t a = ksyms_lookup("kimage_voffset");
    if (!a) return KH_STRAT_ENODATA;
    *(uint64_t *)out = *(uint64_t *)a;
    return 0;
}

static int strat_text_va_minus_pa(void *out, size_t sz)
{
    if (sz != sizeof(uint64_t)) return -22;

    uint64_t text_va = ksyms_lookup("_text");
    if (!text_va) return KH_STRAT_ENODATA;

    /* Walk the kernel pgd for _text's backing PA. Use the registry for
     * swapper_pg_dir so we benefit from whichever strategy resolved it. */
    uint64_t pgd = 0;
    int rc = kh_strategy_resolve("swapper_pg_dir", &pgd, sizeof(pgd));
    if (rc) return rc;

    uint64_t pa = kh_walk_va_to_pa(pgd, text_va);
    if (!pa) return -14;   /* -EFAULT: walk failed */

    *(uint64_t *)out = text_va - pa;
    return 0;
}

static int strat_loader_inject(void *out, size_t sz)
{
    if (sz != sizeof(uint64_t)) return -22;
    if (!kh_loader_injected_kimage_voffset) return KH_STRAT_ENODATA;
    *(uint64_t *)out = kh_loader_injected_kimage_voffset;
    return 0;
}

KH_STRATEGY_DECLARE(kimage_voffset, kallsyms,         0, strat_kallsyms,         sizeof(uint64_t));
KH_STRATEGY_DECLARE(kimage_voffset, text_va_minus_pa, 1, strat_text_va_minus_pa, sizeof(uint64_t));
KH_STRATEGY_DECLARE(kimage_voffset, loader_inject,    2, strat_loader_inject,    sizeof(uint64_t));

#endif /* !__USERSPACE__ */
