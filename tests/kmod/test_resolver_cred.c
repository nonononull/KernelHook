/* tests/kmod/test_resolver_cred.c */
/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <types.h>
#include "test_resolver_common.h"

int test_resolver_cred(void) {
    uint64_t via_kallsyms = 0, via_current = 0, via_init_task = 0;

    kh_strategy_force("init_cred", "kallsyms_init_cred");
    int k_ok = kh_strategy_resolve("init_cred", &via_kallsyms, sizeof(via_kallsyms));

    kh_strategy_force("init_cred", "current_task_walk");
    int c_ok = kh_strategy_resolve("init_cred", &via_current, sizeof(via_current));

    kh_strategy_force("init_cred", "init_task_walk");
    int i_ok = kh_strategy_resolve("init_cred", &via_init_task, sizeof(via_init_task));

    kh_strategy_force("init_cred", NULL);

    /* At least one path must succeed for any supported kernel. */
    if (k_ok != 0 && c_ok != 0 && i_ok != 0) {
        KH_TEST_ASSERT("init_cred", 0,
                       "all three strategies failed on init_cred");
    }

    /* kallsyms_init_cred and init_task_walk BOTH refer to init_task's cred
     * (kallsyms_init_cred returns the init_cred symbol's address, which IS
     * init_task.cred). They MUST agree when both succeed. */
    if (k_ok == 0 && i_ok == 0) {
        KH_TEST_ASSERT("init_cred", via_kallsyms == via_init_task,
                       "kallsyms_init_cred and init_task_walk disagree");
    }

    /* current_task_walk returns CURRENT's cred, which is insmod's (as root
     * via su on the test device). insmod's cred is NOT init_cred. We only
     * sanity-check that the returned pointer is non-zero and looks like a
     * kernel VA -- that tells us the walker found something plausible, not
     * that it matches init. */
    if (c_ok == 0) {
        KH_TEST_ASSERT("init_cred", via_current != 0,
                       "current_task_walk returned NULL");
        KH_TEST_ASSERT("init_cred", via_current >= 0xffff000000000000ULL,
                       "current_task_walk returned non-kernel VA");
    }

    KH_TEST_PASS("init_cred");
    return 0;
}
