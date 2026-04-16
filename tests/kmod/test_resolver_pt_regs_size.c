/* tests/kmod/test_resolver_pt_regs_size.c */
/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <types.h>
#include "test_resolver_common.h"

int test_resolver_pt_regs_size(void)
{
    uint64_t v = 0;
    int rc = kh_strategy_resolve("pt_regs_size", &v, sizeof(v));
    KH_TEST_ASSERT("pt_regs_size", rc == 0, "no strategy succeeded");
    KH_TEST_ASSERT("pt_regs_size", v >= 0x100 && v <= 0x200, "pt_regs_size out of range");
    KH_TEST_PASS("pt_regs_size");
    return 0;
}
