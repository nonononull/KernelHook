/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2026 bmax121.
 * Userspace log function definition.
 * Separated from core_user.c to avoid pulling the entire hook chain
 * when only the logging subsystem is needed (e.g., hmem.c).
 */

#include <stdio.h>
#include <stdarg.h>
#include <log.h>

log_func_t kp_log_func = (log_func_t)0;

/* Userspace kp_log_call: use vprintf (no kCFI concerns in userspace) */
int kp_log_call(const char *fmt, ...)
{
    if (!kp_log_func) return 0;
    va_list args;
    va_start(args, fmt);
    int ret = vprintf(fmt, args);
    va_end(args);
    return ret;
}
