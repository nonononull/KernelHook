/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2026 bmax121.
 */

#ifndef _KP_KTYPES_H_
#define _KP_KTYPES_H_

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

#ifndef __unused
#define __unused __attribute__((unused))
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
