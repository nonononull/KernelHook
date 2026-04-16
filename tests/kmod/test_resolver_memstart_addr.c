/* tests/kmod/test_resolver_memstart_addr.c */
/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <types.h>
#include "test_resolver_common.h"

int test_resolver_memstart_addr(void) {
    uint64_t via_kallsyms = 0, via_dtb = 0, via_dma = 0;
    kh_strategy_force("memstart_addr", "kallsyms");
    int k_ok = kh_strategy_resolve("memstart_addr", &via_kallsyms, sizeof(via_kallsyms));
    kh_strategy_force("memstart_addr", "dtb_parse");
    int d_ok = kh_strategy_resolve("memstart_addr", &via_dtb, sizeof(via_dtb));
    kh_strategy_force("memstart_addr", "dma_phys_limit");
    int m_ok = kh_strategy_resolve("memstart_addr", &via_dma, sizeof(via_dma));
    kh_strategy_force("memstart_addr", NULL);

    /* At least one strategy must succeed on any supported device. */
    if (k_ok != 0 && d_ok != 0 && m_ok != 0) {
        KH_TEST_ASSERT("memstart_addr", 0,
                       "all three strategies failed -- at least one must succeed on any supported device");
    }

    /* kallsyms reads the kernel's runtime memstart_addr variable; dtb_parse
     * reads the same DRAM base PA the kernel parsed from DTB at early boot
     * (via the loader's /proc/device-tree/memory@*... walk). They trace
     * back to the same DTB source so they must agree when both succeed. */
    if (k_ok == 0 && d_ok == 0) {
        KH_TEST_ASSERT("memstart_addr", via_kallsyms == via_dtb,
                       "kallsyms and dtb_parse disagree");
    }
    /* dma_phys_limit is a rough 128MB-rounded heuristic -- just range-validate. */
    if (m_ok == 0) {
        KH_TEST_ASSERT("memstart_addr", via_dma != 0, "dma_phys_limit returned 0");
    }
    KH_TEST_PASS("memstart_addr");
    return 0;
}
