/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Test-environment adaptation of the kernel log backend.
 * This file is NOT a copy of src/log.c — it provides the same interface
 * but is tailored for the test module's dual freestanding+kbuild build paths.
 * Kept separate to avoid polluting the core library with test-only code paths.
 */
/*
 * Kernel log backend for test module.
 * Freestanding: resolved via ksyms at runtime.
 * Kbuild: direct printk reference + module_param for log_level.
 *
 * SDK mode (kmod_sdk.mk) gets its log_level from the shim's
 * <linux/printk.h> as a TU-local static; this file contributes
 * nothing in that mode and is guarded out entirely.
 */

#ifndef KH_SDK_MODE

#include <linux/printk.h>
#if __has_include(<linux/stdarg.h>)
#include <linux/stdarg.h>
#else
#include <stdarg.h>
#endif
#include <symbol.h>

/* hook.h provides KCFI_EXEMPT */
#include <hook.h>

/* LOG_INFO is defined by the freestanding shim printk.h but not by the
 * real kernel <linux/printk.h>.  Define it here for kbuild builds. */
#ifndef LOG_INFO
#define LOG_INFO  6
#define LOG_ERR   3
#define LOG_WARN  4
#define LOG_DEBUG 7
#endif

int log_level = LOG_INFO;

#ifdef KMOD_FREESTANDING

/* vprintk for KCFI-safe variadic forwarding */
typedef int (*vprintk_func_t)(const char *fmt, va_list args);
static vprintk_func_t kh_vprintk_func = NULL;

KCFI_EXEMPT
int printk(const char *fmt, ...)
{
    if (!kh_vprintk_func) return 0;
    va_list args;
    va_start(args, fmt);
    int ret = kh_vprintk_func(fmt, args);
    va_end(args);
    return ret;
}

int log_init(void)
{
    kh_vprintk_func = (vprintk_func_t)(uintptr_t)ksyms_lookup("vprintk");
    if (!kh_vprintk_func)
        return -1;
    return 0;
}

#else /* Kbuild */

#include <linux/moduleparam.h>
module_param(log_level, int, 0644);
MODULE_PARM_DESC(log_level, "Runtime log level (3=err 4=warn 6=info 7=debug)");

int log_init(void)
{
    return 0;
}

#endif /* KMOD_FREESTANDING */

#endif /* !KH_SDK_MODE */
