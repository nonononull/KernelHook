/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Kernel log backend: wire kp_log_func to printk.
 * Freestanding: resolved via ksyms at runtime.
 * Kbuild: direct printk reference.
 */

#ifdef KMOD_FREESTANDING
#include "kmod_shim.h"
#include <hook.h>
#include <ksyms.h>
#else
#include <linux/kernel.h>
#endif

#include <stdarg.h>
#include <log.h>

log_func_t kp_log_func = NULL;

/* vprintk for KCFI-safe variadic forwarding */
typedef int (*vprintk_func_t)(const char *fmt, va_list args);
static vprintk_func_t kp_vprintk_func = NULL;

KCFI_EXEMPT
int kp_log_call(const char *fmt, ...)
{
    if (!kp_vprintk_func && !kp_log_func) return 0;
    va_list args;
    va_start(args, fmt);
    int ret;
    if (kp_vprintk_func) {
        ret = kp_vprintk_func(fmt, args);
    } else {
        ret = kp_log_func(fmt, args);
    }
    va_end(args);
    return ret;
}

int kmod_log_init(void)
{
#ifdef KMOD_FREESTANDING
    kp_vprintk_func = (vprintk_func_t)(uintptr_t)ksyms_lookup("vprintk");
    kp_log_func = (log_func_t)(uintptr_t)ksyms_lookup("_printk");
    if (!kp_log_func)
        kp_log_func = (log_func_t)(uintptr_t)ksyms_lookup("printk");
    if (!kp_log_func && !kp_vprintk_func) return -1;
#else
    kp_log_func = (log_func_t)printk;
#endif
    return 0;
}
