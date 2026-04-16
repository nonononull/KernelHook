/* tests/kmod/test_resolver_kimage_voffset.c */
/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <types.h>
#include "test_resolver_common.h"

int test_resolver_kimage_voffset(void) {
    uint64_t golden = 0;
    int rc = kh_strategy_resolve("kimage_voffset", &golden, sizeof(golden));
    KH_TEST_ASSERT("kimage_voffset", rc == 0, "no strategy succeeded");
    KH_TEST_ASSERT("kimage_voffset", golden != 0, "returned 0");

    const char *names[] = {"kallsyms", "text_va_minus_pa", "loader_inject"};
    int i;
    for (i = 0; i < 3; i++) {
        uint64_t v = 0;
        kh_strategy_force("kimage_voffset", names[i]);
        rc = kh_strategy_resolve("kimage_voffset", &v, sizeof(v));
        if (rc == 0) {
            KH_TEST_ASSERT("kimage_voffset", v == golden,
                           "strategy value disagrees with natural winner");
        }
    }
    kh_strategy_force("kimage_voffset", NULL);
    KH_TEST_PASS("kimage_voffset");
    return 0;
}
