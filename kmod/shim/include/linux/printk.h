/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Fake <linux/printk.h> for freestanding .ko builds.
 *
 * Full-runtime modules (kmod.mk) link kmod/src/log.c which defines
 * `log_level` and a `printk` wrapper around ksyms-resolved vprintk.
 *
 * SDK modules (kmod_sdk.mk) don't link the core runtime, so the
 * pr_xxx macros expand directly to the kernel's `_printk` (whose
 * CRC is registered via MODULE_VERSIONS). A TU-local `log_level`
 * provides per-module runtime filtering without creating an UND
 * dependency on the exporter.
 */

#ifndef _FAKE_LINUX_PRINTK_H
#define _FAKE_LINUX_PRINTK_H

#define LOG_ERR     3
#define LOG_WARN    4
#define LOG_INFO    6
#define LOG_DEBUG   7

#ifndef CONFIG_LOG_LEVEL
#define CONFIG_LOG_LEVEL LOG_INFO
#endif

#ifdef KH_SDK_MODE
/* SDK build: use kernel's _printk directly. No exporter dependency. */
extern int _printk(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
static int log_level __attribute__((unused)) = LOG_INFO;
#define KH_PRINTK(fmt, ...) _printk(fmt, ##__VA_ARGS__)
#else
/* Full-runtime build: resolves to ksyms-backed vprintk via log.c. */
extern int log_level;
int printk(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
#define KH_PRINTK(fmt, ...) printk(fmt, ##__VA_ARGS__)
#endif

#define pr_err(fmt, ...)   do { if (LOG_ERR   <= CONFIG_LOG_LEVEL && \
    LOG_ERR   <= log_level) KH_PRINTK("[KH/E] " fmt "\n", ##__VA_ARGS__); } while (0)
#define pr_warn(fmt, ...)  do { if (LOG_WARN  <= CONFIG_LOG_LEVEL && \
    LOG_WARN  <= log_level) KH_PRINTK("[KH/W] " fmt "\n", ##__VA_ARGS__); } while (0)
#define pr_info(fmt, ...)  do { if (LOG_INFO  <= CONFIG_LOG_LEVEL && \
    LOG_INFO  <= log_level) KH_PRINTK("[KH/I] " fmt "\n", ##__VA_ARGS__); } while (0)
#define pr_debug(fmt, ...) do { if (LOG_DEBUG <= CONFIG_LOG_LEVEL && \
    LOG_DEBUG <= log_level) KH_PRINTK("[KH/D] " fmt "\n", ##__VA_ARGS__); } while (0)

#endif /* _FAKE_LINUX_PRINTK_H */
