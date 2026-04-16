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
extern int   strcmp(const char *s1, const char *s2);
extern int   strncmp(const char *s1, const char *s2, unsigned long n);

#endif /* _FAKE_LINUX_STRING_H */
