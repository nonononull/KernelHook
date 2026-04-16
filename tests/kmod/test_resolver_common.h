/* tests/kmod/test_resolver_common.h */
/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef KH_TEST_RESOLVER_COMMON_H
#define KH_TEST_RESOLVER_COMMON_H

#include <kh_strategy.h>
#include <kh_log.h>

/* EINVAL may not be visible in all build modes. In freestanding builds
 * only shim.h (included via linux/module.h) defines it; in kbuild it
 * comes from linux/errno.h. Provide a fallback so this header compiles
 * in any translation unit that doesn't pull in those transitively. */
#ifndef EINVAL
#define EINVAL 22
#endif

#define KH_TEST_ASSERT(cap_name, cond, msg) do { \
    if (!(cond)) { \
        pr_err("[test_resolver_%s] FAIL: %s", cap_name, msg); \
        return -EINVAL; \
    } \
} while (0)

#define KH_TEST_PASS(cap_name) \
    pr_info("[test_resolver_%s] PASS", cap_name)

#endif
