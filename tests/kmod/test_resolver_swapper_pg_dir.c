/* tests/kmod/test_resolver_swapper_pg_dir.c */
/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <types.h>
#include "test_resolver_common.h"

int test_resolver_swapper_pg_dir(void) {
    uint64_t golden = 0;
    int rc = kh_strategy_resolve("swapper_pg_dir", &golden, sizeof(golden));
    KH_TEST_ASSERT("swapper_pg_dir", rc == 0, "no strategy succeeded");
    KH_TEST_ASSERT("swapper_pg_dir", golden != 0, "returned NULL");

    const char *names[] = {"kallsyms", "init_mm_pgd", "ttbr1_walk", "pg_end_anchor"};
    int i;
    for (i = 0; i < 4; i++) {
        uint64_t v = 0;
        kh_strategy_force("swapper_pg_dir", names[i]);
        rc = kh_strategy_resolve("swapper_pg_dir", &v, sizeof(v));
        if (rc == 0) {
            KH_TEST_ASSERT("swapper_pg_dir", v == golden,
                           "strategy value disagrees with natural winner");
        }
    }
    kh_strategy_force("swapper_pg_dir", NULL);
    KH_TEST_PASS("swapper_pg_dir");
    return 0;
}
