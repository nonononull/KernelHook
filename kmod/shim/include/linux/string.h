/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Fake <linux/string.h> for freestanding .ko builds.
 *
 * In freestanding mode (-DKMOD_FREESTANDING), the compiler's
 * -I kmod/shim/include resolves this instead of the real kernel header.
 * In kbuild mode, this file is never on the include path.
 */

#ifndef _FAKE_LINUX_STRING_H
#define _FAKE_LINUX_STRING_H

/* The compiler may lower __builtin_memcpy/memset to real function calls,
 * so we need linkable declarations. The kernel exports these symbols. */
extern void *memset(void *s, int c, unsigned long n);
extern void *memcpy(void *dst, const void *src, unsigned long n);
extern void *memmove(void *dst, const void *src, unsigned long n);
extern int   memcmp(const void *s1, const void *s2, unsigned long n);
extern int   strcmp(const char *s1, const char *s2);
extern int   strncmp(const char *s1, const char *s2, unsigned long n);
extern char *strchr(const char *s, int c);
/* strlcpy: copies at most size-1 bytes, NUL-terminates, returns src length. */
extern unsigned long strlcpy(char *dest, const char *src, unsigned long size);

/* snprintf: format into a fixed-size buffer; kernel-exported symbol. */
extern int snprintf(char *buf, unsigned long size, const char *fmt, ...)
    __attribute__((format(printf, 3, 4)));

#endif /* _FAKE_LINUX_STRING_H */
