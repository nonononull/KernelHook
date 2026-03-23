/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2026 bmax121.
 */

#ifndef _KP_EXPORT_H_
#define _KP_EXPORT_H_

#include <ktypes.h>

typedef struct
{
    const char *name;
    uint64_t addr;
} kp_symbol_t;

#ifdef __USERSPACE__
/* Kernel symbol export is not needed in userspace builds. */
#define KP_EXPORT_SYMBOL(sym)
#else
#define KP_EXPORT_SYMBOL(sym)                                              \
    static const char __kp_sym_name_##sym[] __section(".rodata")           \
        __used = #sym;                                                     \
    static const kp_symbol_t __kp_sym_##sym __section(".kp.symbol")        \
        __used __aligned(8) = { .name = __kp_sym_name_##sym,               \
                                .addr = (uint64_t)&sym }
#endif

#endif /* _KP_EXPORT_H_ */
