/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2026 bmax121.
 * Userspace log function definition.
 * Separated from core_user.c to avoid pulling the entire hook chain
 * when only the logging subsystem is needed (e.g., hmem.c).
 */

#include <log.h>

log_func_t kp_log_func = (log_func_t)0;
