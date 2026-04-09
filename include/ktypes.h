/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2026 bmax121.
 */

#ifndef _KP_KTYPES_H_
#define _KP_KTYPES_H_

#ifdef __USERSPACE__

#include <stdint.h>
#include <stddef.h>

#elif defined(__KERNEL__) && !defined(KMOD_FREESTANDING)
/*
 * Mode C (kbuild) — real Linux kernel headers already provide all of the
 * fixed-width integer types via <linux/types.h> (which pulls in
 * <asm/int-ll64.h> where u64 = unsigned long long, i.e. different from
 * clang's __UINT64_TYPE__ = unsigned long on arm64 LP64). Re-typedef'ing
 * uint64_t here would be a strict-typedef redefinition error.
 *
 * Forward to the kernel's canonical types and skip our freestanding
 * redefinitions entirely.
 */
#include <linux/types.h>
#include <linux/stddef.h>
#include <linux/compiler.h>      /* __always_inline, __noinline, __packed, ... */
#include <linux/compiler_attributes.h>

#else /* freestanding .ko (no kernel headers) */

typedef __UINT8_TYPE__ uint8_t;
typedef __UINT16_TYPE__ uint16_t;
typedef __UINT32_TYPE__ uint32_t;
typedef __UINT64_TYPE__ uint64_t;

typedef __INT8_TYPE__ int8_t;
typedef __INT16_TYPE__ int16_t;
typedef __INT32_TYPE__ int32_t;
typedef __INT64_TYPE__ int64_t;

typedef __UINTPTR_TYPE__ uintptr_t;
typedef __SIZE_TYPE__ size_t;

#ifndef NULL
#define NULL ((void *)0)
#endif

#endif /* __USERSPACE__ */

/* ---- Attribute macros ----
 * Defined in ALL modes (freestanding, kbuild, userspace). Each is
 * #ifndef-guarded so if kernel headers (linux/compiler_attributes.h)
 * or libc already provided them, we defer to those. In kbuild mode
 * our ktypes.h only forwards to <linux/types.h>/<linux/stddef.h>
 * which do NOT always pull in compiler_attributes.h transitively,
 * so code like `static __noinline` would otherwise expand to bare
 * `__noinline__` tokens and break parsing.
 */

#ifndef __always_inline
#define __always_inline inline __attribute__((always_inline))
#endif

#ifndef __packed
#define __packed __attribute__((packed))
#endif

#ifndef __aligned
#define __aligned(x) __attribute__((aligned(x)))
#endif

#ifndef __section
#define __section(x) __attribute__((section(x)))
#endif

#ifndef __used
#define __used __attribute__((used))
#endif

/* Note: do NOT define a macro named `__unused` — Linux kernel uses
 * `__unused` as a plain struct-field identifier in uapi headers
 * (e.g. struct __sysctl_args.__unused[4]), and a macro substitution
 * would break parsing. Use the standard kernel spelling
 * `__maybe_unused` instead. */
#ifndef __maybe_unused
#define __maybe_unused __attribute__((unused))
#endif

#ifndef __weak
#define __weak __attribute__((weak))
#endif

#ifndef __noinline
#define __noinline __attribute__((noinline))
#endif

#ifndef offsetof
#define offsetof(TYPE, MEMBER) __builtin_offsetof(TYPE, MEMBER)
#endif

#endif /* _KP_KTYPES_H_ */
