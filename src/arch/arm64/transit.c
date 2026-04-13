/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2026 bmax121.
 * ARM64 universal transit stub and callback dispatch.
 *
 * Single naked asm stub + single C body, parameterized by rw->argno.
 *
 * Transit buffer layout (set up during hook installation):
 *   transit[0..1] = uint64_t self-pointer to containing hook_chain_rox_t
 *   transit[2..]  = copied stub machine code
 *
 * Installation:
 *   *(uint64_t *)&rox->transit[0] = (uint64_t)rox;
 *   memcpy(&rox->transit[2], _transit, (uintptr_t)_transit_end - (uintptr_t)_transit);
 */

#include <types.h>
#include <hook.h>
#include <sync.h>

/* Platform-appropriate section attribute for transit stubs.
 *
 * These stubs are never executed in-place — they are memcpy'd into
 * transit buffers (ROX pool).  They contain embedded absolute addresses
 * (.quad) which would create illegal text-relocations in a code section
 * on macOS.  Placing them in a data section avoids that. */
#ifdef __APPLE__
#define TRANSIT_SECTION __attribute__((naked, used, section("__DATA,__transit")))
/* macOS Mach-O C symbols have a leading underscore. Raw asm references
 * must include it explicitly. */
#define ASM_SYM(name) "_" #name
#else
#define TRANSIT_SECTION __attribute__((naked, used, section(".transit.data")))
#define ASM_SYM(name) #name
#endif

#define CALL_BEFORES(rw, fargs_ptr)                                                          \
    do {                                                                                     \
        for (int32_t _si = 0; _si < (rw)->sorted_count; _si++) {                            \
            int32_t _idx = (rw)->sorted_indices[_si];                                        \
            hook_chain_item_t *_item = &(rw)->items[_idx];                                   \
            __builtin_memset(&_item->local, 0, sizeof(hook_local_t));                        \
            (fargs_ptr)->local = &_item->local;                                              \
            hook_chain12_callback _func = (hook_chain12_callback)_item->before;              \
            if (_func) _func((hook_fargs12_t *)(fargs_ptr), _item->udata);                  \
        }                                                                                    \
    } while (0)

#define CALL_AFTERS(rw, fargs_ptr)                                                           \
    do {                                                                                     \
        for (int32_t _si = (rw)->sorted_count - 1; _si >= 0; _si--) {                       \
            int32_t _idx = (rw)->sorted_indices[_si];                                        \
            hook_chain_item_t *_item = &(rw)->items[_idx];                                   \
            (fargs_ptr)->local = &_item->local;                                              \
            hook_chain12_callback _func = (hook_chain12_callback)_item->after;               \
            if (_func) _func((hook_fargs12_t *)(fargs_ptr), _item->udata);                  \
        }                                                                                    \
    } while (0)

/* ---- Origin function typedefs ---- */

typedef uint64_t (*origin0_t)(void);
typedef uint64_t (*origin4_t)(uint64_t, uint64_t, uint64_t, uint64_t);
typedef uint64_t (*origin8_t)(uint64_t, uint64_t, uint64_t, uint64_t,
                               uint64_t, uint64_t, uint64_t, uint64_t);
typedef uint64_t (*origin12_t)(uint64_t, uint64_t, uint64_t, uint64_t,
                                uint64_t, uint64_t, uint64_t, uint64_t,
                                uint64_t, uint64_t, uint64_t, uint64_t);

/* ---- Unified C body ----
 *
 * All transit calls dispatch here. The stub always passes 14 parameters
 * (rox, rw, arg0..arg11). For low-argno hooks, the unused arg params
 * contain harmless garbage — they are ignored based on rw->argno.
 *
 * FPAC safety invariant:
 *   On ARMv8.3+ with FEAT_FPAC, a failed AUTIASP/AUTIBSP raises an
 *   immediate synchronous exception instead of producing a poisoned
 *   pointer.  PACIASP signs LR using SP as the context/modifier, and
 *   AUTIASP at the function epilogue must see the *same* SP value.
 *
 *   The relocated code at relo_addr may begin with a PACIASP from the
 *   original function prologue.  This function calls relo_addr via a
 *   standard C indirect call (BLR), so the compiler guarantees SP is
 *   ABI-aligned and stable at the call site.  The relocated PACIASP
 *   signs LR (return-to-transit_body) with that SP.  The relocated code
 *   then branches (not calls) back into the original function body,
 *   preserving SP.  The original epilogue's AUTIASP sees the same SP
 *   because the function's STP/LDP frame setup and teardown are fully
 *   contained within the relocated+original code flow.
 *
 *   Critical requirement: transit_body must NOT modify SP between the
 *   BLR to relo_addr and the point where relocated code begins executing.
 *   Since relo_addr is called as a normal C function pointer, the compiler
 *   upholds this invariant automatically.
 */

KCFI_EXEMPT __attribute__((__used__, __noinline__))
uint64_t transit_body(hook_chain_rox_t *rox, hook_chain_rw_t *rw,
                      uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3,
                      uint64_t a4, uint64_t a5, uint64_t a6, uint64_t a7,
                      uint64_t a8, uint64_t a9, uint64_t a10, uint64_t a11)
{
    int32_t argno = rw->argno;

    hook_fargs12_t fargs;
    fargs.skip_origin = 0;
    fargs.chain = rox;
    fargs.local = NULL;
    fargs.ret = 0;
    fargs.arg0 = a0;   fargs.arg1 = a1;   fargs.arg2 = a2;   fargs.arg3 = a3;
    fargs.arg4 = a4;   fargs.arg5 = a5;   fargs.arg6 = a6;   fargs.arg7 = a7;
    fargs.arg8 = a8;   fargs.arg9 = a9;   fargs.arg10 = a10; fargs.arg11 = a11;

    sync_read_lock();

    CALL_BEFORES(rw, &fargs);

    if (!fargs.skip_origin) {
        uintptr_t fn = rox->hook.relo_addr;
        /* FPAC safety: each BLR below is the point where SP must be stable.
         * The relocated code at fn may begin with PACIASP, which signs LR
         * using the current SP.  Do not insert SP-modifying code between
         * here and the BLR.  See FPAC safety invariant comment above. */
        switch (argno) {
        case 0:
            fargs.ret = ((origin0_t)fn)();
            break;
        case 1: case 2: case 3: case 4:
            fargs.ret = ((origin4_t)fn)(
                fargs.arg0, fargs.arg1, fargs.arg2, fargs.arg3);
            break;
        case 5: case 6: case 7: case 8:
            fargs.ret = ((origin8_t)fn)(
                fargs.arg0, fargs.arg1, fargs.arg2, fargs.arg3,
                fargs.arg4, fargs.arg5, fargs.arg6, fargs.arg7);
            break;
        default:
            fargs.ret = ((origin12_t)fn)(
                fargs.arg0, fargs.arg1, fargs.arg2, fargs.arg3,
                fargs.arg4, fargs.arg5, fargs.arg6, fargs.arg7,
                fargs.arg8, fargs.arg9, fargs.arg10, fargs.arg11);
            break;
        }
    }

    CALL_AFTERS(rw, &fargs);

    sync_read_unlock();

    return fargs.ret;
}

/* ==== Universal naked asm stub ====
 *
 * Placed in .transit.text — this is the single template copied into every
 * hook's transit buffer, regardless of argno.
 *
 * The stub:
 *   1. Loads rox self-pointer from transit[0..1]  (3 instructions, O(1))
 *   2. Loads rw from rox->rw
 *   3. Saves frame, pushes potential stack args (arg6..arg11)
 *   4. Shifts x0-x5 → x2-x7, prepends rox/rw as x0/x1
 *   5. Branches to transit_body via embedded absolute address literal
 *
 * For argno < 12, some pushed "args" are garbage from the caller's
 * registers/stack. This is safe: the body ignores them based on rw->argno,
 * and the kernel stack is always valid memory.
 *
 * Register usage:
 *   x16 (IP0): rox pointer, then body function address
 *   x17 (IP1): rw pointer (then available as shifted arg)
 *   x9-x12:    scratch for loading caller's stack args (caller-saved)
 */

TRANSIT_SECTION
uint64_t _transit(void)
{
    asm volatile(
        /* BTI landing pad for BR-based trampoline */
        "bti  jc\n\t"
        /* O(1) rox/rw lookup from self-pointer at transit[0..1] */
        "adr  x16, .\n\t"                  /* x16 = &transit[3] (after bti)  */
        "sub  x16, x16, #12\n\t"           /* x16 = &transit[0]              */
        "ldr  x16, [x16]\n\t"              /* x16 = rox                      */
        "mov  x17, %[rwoff]\n\t"           /* x17 = offsetof(rox, rw)        */
        "ldr  x17, [x16, x17]\n\t"         /* x17 = rw                       */
        /* save frame */
        "stp  x29, x30, [sp, #-16]!\n\t"
        "mov  x29, sp\n\t"
        /* load potential arg8-11 from caller's stack (above our frame) */
        "ldp  x9,  x10, [x29, #16]\n\t"
        "ldp  x11, x12, [x29, #32]\n\t"
        /* push 6 stack args for body params 9-14: arg6..arg11 */
        "stp  x11, x12, [sp, #-16]!\n\t"   /* arg10, arg11                   */
        "stp  x9,  x10, [sp, #-16]!\n\t"   /* arg8,  arg9                    */
        "stp  x6,  x7,  [sp, #-16]!\n\t"   /* arg6,  arg7                    */
        /* shift x0-x5 → x2-x7, prepend rox/rw */
        "mov  x7, x5\n\t"
        "mov  x6, x4\n\t"
        "mov  x5, x3\n\t"
        "mov  x4, x2\n\t"
        "mov  x3, x1\n\t"
        "mov  x2, x0\n\t"
        "mov  x0, x16\n\t"                 /* rox                            */
        "mov  x1, x17\n\t"                 /* rw                             */
        /* absolute branch to body via embedded literal */
        "ldr  x16, 0f\n\t"
        "blr  x16\n\t"
        /* cleanup: 48 bytes stack args + 16 bytes frame */
        "add  sp, sp, #48\n\t"
        "ldp  x29, x30, [sp], #16\n\t"
        "ret\n\t"
        ".align 3\n\t"
        "0: .quad " ASM_SYM(transit_body) "\n\t"
        /* End marker: must be in the same section, immediately after the stub */
        ".globl " ASM_SYM(_transit_end) "\n\t"
        ASM_SYM(_transit_end) ":\n\t"
        :
        : [rwoff] "i" ((int)__builtin_offsetof(hook_chain_rox_t, rw))
    );
}

/* ==== Function pointer hook transit ====
 *
 * Separate body + stub for fp_hook_chain_rox_t / fp_hook_chain_rw_t,
 * which have different field layouts (different sorted_indices/items sizes
 * and origin call via origin_fp instead of relo_addr).
 */

KCFI_EXEMPT __attribute__((__used__, __noinline__))
uint64_t fp_transit_body(fp_hook_chain_rox_t *rox, fp_hook_chain_rw_t *rw,
                         uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3,
                         uint64_t a4, uint64_t a5, uint64_t a6, uint64_t a7,
                         uint64_t a8, uint64_t a9, uint64_t a10, uint64_t a11)
{
    int32_t argno = rw->argno;

    hook_fargs12_t fargs;
    fargs.skip_origin = 0;
    fargs.chain = rox;
    fargs.local = NULL;
    fargs.ret = 0;
    fargs.arg0 = a0;   fargs.arg1 = a1;   fargs.arg2 = a2;   fargs.arg3 = a3;
    fargs.arg4 = a4;   fargs.arg5 = a5;   fargs.arg6 = a6;   fargs.arg7 = a7;
    fargs.arg8 = a8;   fargs.arg9 = a9;   fargs.arg10 = a10; fargs.arg11 = a11;

    sync_read_lock();

    CALL_BEFORES(rw, &fargs);

    if (!fargs.skip_origin) {
        /* Note: fp_transit_body is exempt from the FPAC SP invariant
         * documented in transit_body — function pointer hooks call the
         * original function (origin_fp) which enters at its own natural
         * entry point with its own PAC context, not relocated code. */
        uintptr_t fn = rox->hook.origin_fp;
        switch (argno) {
        case 0:
            fargs.ret = ((origin0_t)fn)();
            break;
        case 1: case 2: case 3: case 4:
            fargs.ret = ((origin4_t)fn)(
                fargs.arg0, fargs.arg1, fargs.arg2, fargs.arg3);
            break;
        case 5: case 6: case 7: case 8:
            fargs.ret = ((origin8_t)fn)(
                fargs.arg0, fargs.arg1, fargs.arg2, fargs.arg3,
                fargs.arg4, fargs.arg5, fargs.arg6, fargs.arg7);
            break;
        default:
            fargs.ret = ((origin12_t)fn)(
                fargs.arg0, fargs.arg1, fargs.arg2, fargs.arg3,
                fargs.arg4, fargs.arg5, fargs.arg6, fargs.arg7,
                fargs.arg8, fargs.arg9, fargs.arg10, fargs.arg11);
            break;
        }
    }

    CALL_AFTERS(rw, &fargs);

    sync_read_unlock();

    return fargs.ret;
}

TRANSIT_SECTION
uint64_t _fp_transit(void)
{
    asm volatile(
        "bti  jc\n\t"
        "adr  x16, .\n\t"
        "sub  x16, x16, #12\n\t"
        "ldr  x16, [x16]\n\t"
        "mov  x17, %[rwoff]\n\t"
        "ldr  x17, [x16, x17]\n\t"
        "stp  x29, x30, [sp, #-16]!\n\t"
        "mov  x29, sp\n\t"
        "ldp  x9,  x10, [x29, #16]\n\t"
        "ldp  x11, x12, [x29, #32]\n\t"
        "stp  x11, x12, [sp, #-16]!\n\t"
        "stp  x9,  x10, [sp, #-16]!\n\t"
        "stp  x6,  x7,  [sp, #-16]!\n\t"
        "mov  x7, x5\n\t"
        "mov  x6, x4\n\t"
        "mov  x5, x3\n\t"
        "mov  x4, x2\n\t"
        "mov  x3, x1\n\t"
        "mov  x2, x0\n\t"
        "mov  x0, x16\n\t"
        "mov  x1, x17\n\t"
        "ldr  x16, 0f\n\t"
        "blr  x16\n\t"
        "add  sp, sp, #48\n\t"
        "ldp  x29, x30, [sp], #16\n\t"
        "ret\n\t"
        ".align 3\n\t"
        "0: .quad " ASM_SYM(fp_transit_body) "\n\t"
        ".globl " ASM_SYM(_fp_transit_end) "\n\t"
        ASM_SYM(_fp_transit_end) ":\n\t"
        :
        : [rwoff] "i" ((int)__builtin_offsetof(fp_hook_chain_rox_t, rw))
    );
}
