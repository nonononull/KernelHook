/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2026 bmax121.
 */

#ifndef _KP_LOG_H_
#define _KP_LOG_H_

#include <ktypes.h>

/* Log function pointer, resolved via ksyms at init time (printk or similar) */
typedef int (*log_func_t)(const char *fmt, ...);

extern log_func_t kp_log_func;

/* KCFI-safe wrapper: kp_log_func is a ksyms-resolved function pointer.
 * On kernels with CONFIG_CFI_ICALL_NORMALIZE_INTEGERS, the kCFI hash
 * won't match.  Route all calls through this exempt wrapper. */
int kp_log_call(const char *fmt, ...) __attribute__((format(printf, 1, 2)));

#define logkv(fmt, ...) do { if (kp_log_func) kp_log_call("[KH/V] " fmt "\n", ##__VA_ARGS__); } while (0)
#define logki(fmt, ...) do { if (kp_log_func) kp_log_call("[KH/I] " fmt "\n", ##__VA_ARGS__); } while (0)
#define logke(fmt, ...) do { if (kp_log_func) kp_log_call("[KH/E] " fmt "\n", ##__VA_ARGS__); } while (0)
#define logkw(fmt, ...) do { if (kp_log_func) kp_log_call("[KH/W] " fmt "\n", ##__VA_ARGS__); } while (0)
#define logkd(fmt, ...) do { if (kp_log_func) kp_log_call("[KH/D] " fmt "\n", ##__VA_ARGS__); } while (0)

#endif /* _KP_LOG_H_ */
