/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2026 bmax121.
 */

#ifndef _KP_HOOK_H_
#define _KP_HOOK_H_

#include <ktypes.h>

typedef enum
{
    HOOK_NO_ERR = 0,
    HOOK_BAD_ADDRESS = 4095,
    HOOK_DUPLICATED = 4094,
    HOOK_NO_MEM = 4093,
    HOOK_BAD_RELO = 4092,
    HOOK_TRANSIT_NO_MEM = 4091,
    HOOK_CHAIN_FULL = 4090,
} hook_err_t;

enum hook_type
{
    NONE = 0,
    INLINE,
    INLINE_CHAIN,
    FUNCTION_POINTER_CHAIN,
};

typedef int8_t chain_item_state;

#define CHAIN_ITEM_STATE_EMPTY 0
#define CHAIN_ITEM_STATE_READY 1
#define CHAIN_ITEM_STATE_BUSY 2

#define local_container_of(ptr, type, member) ({ (type *)((char *)(ptr) - offsetof(type, member)); })

#define HOOK_MEM_REGION_NUM 4
#define TRAMPOLINE_NUM 4
#define RELOCATE_INST_NUM (TRAMPOLINE_NUM * 8 + 8)

#define HOOK_CHAIN_NUM 0x10
#define TRANSIT_INST_NUM 0x60

#define FP_HOOK_CHAIN_NUM 0x20

#define ARM64_NOP 0xd503201f
#define ARM64_BTI_C 0xd503245f
#define ARM64_BTI_J 0xd503249f
#define ARM64_BTI_JC 0xd50324df

#define HOOK_LOCAL_DATA_NUM 8

/* ---- Core hook_t (inline hook state) ---- */

typedef struct
{
    /* in */
    uint64_t func_addr;
    uint64_t origin_addr;
    uint64_t replace_addr;
    uint64_t relo_addr;
    /* out */
    int32_t tramp_insts_num;
    int32_t relo_insts_num;
    uint32_t origin_insts[TRAMPOLINE_NUM] __aligned(8);
    uint32_t tramp_insts[TRAMPOLINE_NUM] __aligned(8);
    uint32_t relo_insts[RELOCATE_INST_NUM] __aligned(8);
} hook_t __aligned(8);

/* ---- Per-item local storage ---- */

typedef struct
{
    union
    {
        struct
        {
            uint64_t data0;
            uint64_t data1;
            uint64_t data2;
            uint64_t data3;
            uint64_t data4;
            uint64_t data5;
            uint64_t data6;
            uint64_t data7;
        };
        uint64_t data[HOOK_LOCAL_DATA_NUM];
    };
} hook_local_t;

/* ---- Hook fargs: local is now a pointer ---- */

#define HOOK_FARGS_COMMON                                                                    \
    void *chain;                                                                             \
    int skip_origin;                                                                         \
    hook_local_t *local;                                                                     \
    uint64_t ret;

typedef struct
{
    HOOK_FARGS_COMMON
} hook_fargs0_t __aligned(8);

typedef struct
{
    HOOK_FARGS_COMMON
    union
    {
        struct { uint64_t arg0; uint64_t arg1; uint64_t arg2; uint64_t arg3; };
        uint64_t args[4];
    };
} hook_fargs4_t __aligned(8);

typedef hook_fargs4_t hook_fargs1_t;
typedef hook_fargs4_t hook_fargs2_t;
typedef hook_fargs4_t hook_fargs3_t;

typedef struct
{
    HOOK_FARGS_COMMON
    union
    {
        struct {
            uint64_t arg0; uint64_t arg1; uint64_t arg2; uint64_t arg3;
            uint64_t arg4; uint64_t arg5; uint64_t arg6; uint64_t arg7;
        };
        uint64_t args[8];
    };
} hook_fargs8_t __aligned(8);

typedef hook_fargs8_t hook_fargs5_t;
typedef hook_fargs8_t hook_fargs6_t;
typedef hook_fargs8_t hook_fargs7_t;

typedef struct
{
    HOOK_FARGS_COMMON
    union
    {
        struct {
            uint64_t arg0; uint64_t arg1; uint64_t arg2; uint64_t arg3;
            uint64_t arg4; uint64_t arg5; uint64_t arg6; uint64_t arg7;
            uint64_t arg8; uint64_t arg9; uint64_t arg10; uint64_t arg11;
        };
        uint64_t args[12];
    };
} hook_fargs12_t __aligned(8);

typedef hook_fargs12_t hook_fargs9_t;
typedef hook_fargs12_t hook_fargs10_t;
typedef hook_fargs12_t hook_fargs11_t;

/* ---- Callback typedefs (generated) ---- */

#define _HOOK_DEFINE_CB_TYPEDEF(N) \
    typedef void (*hook_chain##N##_callback)(hook_fargs##N##_t *fargs, void *udata);

_HOOK_DEFINE_CB_TYPEDEF(0)
_HOOK_DEFINE_CB_TYPEDEF(1)
_HOOK_DEFINE_CB_TYPEDEF(2)
_HOOK_DEFINE_CB_TYPEDEF(3)
_HOOK_DEFINE_CB_TYPEDEF(4)
_HOOK_DEFINE_CB_TYPEDEF(5)
_HOOK_DEFINE_CB_TYPEDEF(6)
_HOOK_DEFINE_CB_TYPEDEF(7)
_HOOK_DEFINE_CB_TYPEDEF(8)
_HOOK_DEFINE_CB_TYPEDEF(9)
_HOOK_DEFINE_CB_TYPEDEF(10)
_HOOK_DEFINE_CB_TYPEDEF(11)
_HOOK_DEFINE_CB_TYPEDEF(12)

/* ---- Per-chain-item data (AoS layout for cache locality) ---- */

typedef struct
{
    chain_item_state state;
    int32_t priority;
    void *udata;
    void *before;
    void *after;
    hook_local_t local;
} hook_chain_item_t __aligned(8);

/* ---- ROX/RW split: inline hook chain ---- */

struct hook_chain_rw;

typedef struct
{
    hook_t hook;
    struct hook_chain_rw *rw;
    uint32_t transit[TRANSIT_INST_NUM];
} hook_chain_rox_t __aligned(64);

typedef struct hook_chain_rw
{
    hook_chain_rox_t *rox;
    int32_t chain_items_max;
    int32_t argno;
    int32_t sorted_indices[HOOK_CHAIN_NUM];
    int32_t sorted_count;
    hook_chain_item_t items[HOOK_CHAIN_NUM];
} hook_chain_rw_t __aligned(8);

/* ---- Function pointer hook ---- */

typedef struct
{
    uintptr_t fp_addr;
    uint64_t replace_addr;
    uint64_t origin_fp;
} fp_hook_t __aligned(8);

/* ---- ROX/RW split: function pointer hook chain ---- */

struct fp_hook_chain_rw;

typedef struct
{
    fp_hook_t hook;
    struct fp_hook_chain_rw *rw;
    uint32_t transit[TRANSIT_INST_NUM];
} fp_hook_chain_rox_t __aligned(64);

typedef struct fp_hook_chain_rw
{
    fp_hook_chain_rox_t *rox;
    int32_t chain_items_max;
    int32_t argno;
    int32_t sorted_indices[FP_HOOK_CHAIN_NUM];
    int32_t sorted_count;
    hook_chain_item_t items[FP_HOOK_CHAIN_NUM];
} fp_hook_chain_rw_t __aligned(8);

/* ---- Utility ---- */

#ifdef __USERSPACE__
static inline int is_bad_address(void *addr)
{
    return addr == (void *)0;
}
#else
static inline int is_bad_address(void *addr)
{
    return ((uint64_t)addr & 0x8000000000000000) != 0x8000000000000000;
}
#endif

/* ---- Hook prepare / install / uninstall ---- */

hook_err_t hook_prepare(hook_t *hook);
void hook_install(hook_t *hook);
void hook_uninstall(hook_t *hook);

/* ---- Inline hook API ---- */

hook_err_t hook(void *func, void *replace, void **backup);
void unhook(void *func);

hook_err_t hook_chain_add(hook_chain_rw_t *rw, void *before, void *after, void *udata, int32_t priority);
void hook_chain_remove(hook_chain_rw_t *rw, void *before, void *after);

hook_err_t hook_wrap_pri(void *func, int32_t argno, void *before, void *after, void *udata, int32_t priority);

static inline hook_err_t hook_wrap(void *func, int32_t argno, void *before, void *after, void *udata)
{
    return hook_wrap_pri(func, argno, before, after, udata, 0);
}

void hook_unwrap_remove(void *func, void *before, void *after, int remove);

static inline void hook_unwrap(void *func, void *before, void *after)
{
    hook_unwrap_remove(func, before, after, 1);
}

/* ---- Origin function access ---- */

static inline void *wrap_get_origin_func(void *hook_args)
{
    hook_fargs0_t *args = (hook_fargs0_t *)hook_args;
    hook_chain_rox_t *rox = (hook_chain_rox_t *)args->chain;
    return (void *)rox->hook.relo_addr;
}

/* ---- Function pointer hook API ---- */

void fp_hook(uintptr_t fp_addr, void *replace, void **backup);
void fp_unhook(uintptr_t fp_addr, void *backup);

hook_err_t fp_hook_wrap_pri(uintptr_t fp_addr, int32_t argno, void *before, void *after, void *udata, int32_t priority);

static inline hook_err_t fp_hook_wrap(uintptr_t fp_addr, int32_t argno, void *before, void *after, void *udata)
{
    return fp_hook_wrap_pri(fp_addr, argno, before, after, udata, 0);
}

void fp_hook_unwrap(uintptr_t fp_addr, void *before, void *after);

static inline void *fp_get_origin_func(void *hook_args)
{
    hook_fargs0_t *args = (hook_fargs0_t *)hook_args;
    fp_hook_chain_rox_t *rox = (fp_hook_chain_rox_t *)args->chain;
    return (void *)rox->hook.origin_fp;
}

/* ---- Transit buffer setup (userspace) ---- */

void hook_chain_setup_transit(hook_chain_rox_t *rox);
void fp_hook_chain_setup_transit(fp_hook_chain_rox_t *rox);

/* ---- Chain install/uninstall helpers ---- */

static inline void hook_chain_install(hook_chain_rox_t *rox)
{
    hook_install(&rox->hook);
}

static inline void hook_chain_uninstall(hook_chain_rox_t *rox)
{
    hook_uninstall(&rox->hook);
}

/* ---- Typed convenience wrappers (generated via X-macro) ---- */

#define _HOOK_WRAP_VARIANTS(N)                                                                     \
    static inline hook_err_t hook_wrap##N(void *func, hook_chain##N##_callback before,             \
        hook_chain##N##_callback after, void *udata) {                                             \
        return hook_wrap(func, N, (void *)before, (void *)after, udata);                           \
    }                                                                                              \
    static inline hook_err_t hook_wrap_pri##N(void *func, hook_chain##N##_callback before,         \
        hook_chain##N##_callback after, void *udata, int32_t priority) {                           \
        return hook_wrap_pri(func, N, (void *)before, (void *)after, udata, priority);             \
    }                                                                                              \
    static inline hook_err_t fp_hook_wrap##N(uintptr_t fp_addr, hook_chain##N##_callback before,   \
        hook_chain##N##_callback after, void *udata) {                                             \
        return fp_hook_wrap(fp_addr, N, (void *)before, (void *)after, udata);                     \
    }                                                                                              \
    static inline hook_err_t fp_hook_wrap_pri##N(uintptr_t fp_addr,                                \
        hook_chain##N##_callback before, hook_chain##N##_callback after,                            \
        void *udata, int32_t priority) {                                                           \
        return fp_hook_wrap_pri(fp_addr, N, (void *)before, (void *)after, udata, priority);       \
    }

_HOOK_WRAP_VARIANTS(0)
_HOOK_WRAP_VARIANTS(1)
_HOOK_WRAP_VARIANTS(2)
_HOOK_WRAP_VARIANTS(3)
_HOOK_WRAP_VARIANTS(4)
_HOOK_WRAP_VARIANTS(5)
_HOOK_WRAP_VARIANTS(6)
_HOOK_WRAP_VARIANTS(7)
_HOOK_WRAP_VARIANTS(8)
_HOOK_WRAP_VARIANTS(9)
_HOOK_WRAP_VARIANTS(10)
_HOOK_WRAP_VARIANTS(11)
_HOOK_WRAP_VARIANTS(12)

#endif /* _KP_HOOK_H_ */
