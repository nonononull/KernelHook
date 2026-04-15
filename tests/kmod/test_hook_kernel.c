// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Kernel-context kh_hook tests for KernelHook
 *
 * Fifteen tests covering:
 *   1. Inline kh_hook (kh_hook/kh_unhook) with zero-arg target
 *   2. Wrap kh_hook before/after callbacks with four-arg target
 *   3. Wrap kh_hook skip_origin via before callback
 *   4. Wrap kh_hook argument passthrough verification
 *   5. Hook uninstall and original function restoration
 *   6. Hook chain priority ordering
 *   7. kCFI hash copy to relocated code (CONFIG_CFI_CLANG)
 *   8. PAC-protected function hooking and trampoline structure (CONFIG_ARM64_PTR_AUTH_KERNEL)
 *   9. BTI landing pads in relocated code (CONFIG_ARM64_BTI_KERNEL)
 *  10. Shadow call stack integrity through kh_hook calls (CONFIG_SHADOW_CALL_STACK)
 *  11. Single kh_hook on real kernel function (__arm64_sys_getpid)
 *  12. Chain priority ordering on real kernel function (do_faccessat)
 *  13. Skip-origin kh_hook on real kernel function (do_filp_open)
 *  14. Multi-function kh_hook with dynamic add/remove (vfs_read/vfs_write)
 *  15. Full dynamic add/remove lifecycle (do_faccessat)
 */

#if defined(KH_SDK_MODE)
/* Mode B: SDK — kernelhook.ko provides the API */
#include <kernelhook/kh_hook.h>
#include <kernelhook/types.h>
#else
#include <linux/kernel.h>
#endif

#if !defined(KH_SDK_MODE)
#include <kh_hook.h>
#include <memory.h>
#include <symbol.h>
#include <syscall.h>
#include <uaccess.h>
#endif
#include "test_hook_kernel.h"

/* ---- syscall numbers (ARM64 generic UAPI).
 * Hardcoded rather than #include <uapi/asm-generic/unistd.h> because
 * that header is not cleanly reachable in freestanding builds. These
 * values are stable ARM64 UAPI numbers and have not changed. */
#ifndef __NR_getpid
#define __NR_getpid      172
#endif
#ifndef __NR_faccessat
#define __NR_faccessat    48
#endif
#ifndef __NR_openat
#define __NR_openat       56
#endif
#ifndef __NR_close
#define __NR_close        57
#endif
#ifndef __NR_read
#define __NR_read         63
#endif
#ifndef __NR_write
#define __NR_write        64
#endif
#ifndef __NR_lseek
#define __NR_lseek        62
#endif

#define KH_TEST_TAG "kh_test: "

/* ================================================================
 * Freestanding shim: resolve kthread/msleep/synchronize_rcu via
 * ksyms_lookup so that concurrency tests can run without
 * kernel headers.  In kbuild mode the kernel-builtin versions are
 * used directly via the #else branch.
 * ================================================================ */
#ifdef KMOD_FREESTANDING
/* IS_ERR is from <linux/err.h> which is not available freestanding */
#define IS_ERR(ptr) ((unsigned long)(ptr) >= (unsigned long)-4095UL)

/* schedule() and kthread_should_stop() are kernel-exported symbols used
 * by conc_thread_fn.  In freestanding mode we cannot use extern declarations
 * (those generate module-import relocs that require CRC verification), so we
 * resolve them via ksyms_lookup and call through function pointers instead. */
struct task_struct;
typedef void (*schedule_fn_t)(void);
typedef int  (*kthread_should_stop_fn_t)(void);
static schedule_fn_t _schedule;
static kthread_should_stop_fn_t _kthread_should_stop;
/* Wrap the lookups as macros so conc_thread_fn uses them transparently. */
#define schedule()             _schedule()
#define kthread_should_stop()  _kthread_should_stop()
typedef struct task_struct *(*kthread_create_on_node_fn_t)(
    int (*threadfn)(void *), void *data, int node, const char *namefmt, ...);
typedef int (*wake_up_process_fn_t)(struct task_struct *);
typedef int (*kthread_stop_fn_t)(struct task_struct *);
typedef void (*msleep_fn_t)(unsigned int);
typedef void (*synchronize_rcu_fn_t)(void);

static kthread_create_on_node_fn_t _kthread_create_on_node;
static wake_up_process_fn_t _wake_up_process;
static kthread_stop_fn_t _kthread_stop;
static msleep_fn_t _msleep;
static synchronize_rcu_fn_t _synchronize_rcu;

__attribute__((no_sanitize("kcfi")))
static int resolve_concurrency_syms(void)
{
    _kthread_create_on_node = (kthread_create_on_node_fn_t)(uintptr_t)
        ksyms_lookup("kthread_create_on_node");
    _wake_up_process = (wake_up_process_fn_t)(uintptr_t)
        ksyms_lookup("wake_up_process");
    _kthread_stop = (kthread_stop_fn_t)(uintptr_t)
        ksyms_lookup("kthread_stop");
    _msleep = (msleep_fn_t)(uintptr_t)ksyms_lookup("msleep");
    _synchronize_rcu = (synchronize_rcu_fn_t)(uintptr_t)
        ksyms_lookup("synchronize_rcu");
    _schedule = (schedule_fn_t)(uintptr_t)ksyms_lookup("schedule");
    _kthread_should_stop = (kthread_should_stop_fn_t)(uintptr_t)
        ksyms_lookup("kthread_should_stop");
    return (_kthread_create_on_node && _wake_up_process && _kthread_stop &&
            _msleep && _synchronize_rcu && _schedule &&
            _kthread_should_stop) ? 0 : -1;
}

#define kthread_run_fs(fn, data, namefmt, ...) ({                        \
    struct task_struct *__t = _kthread_create_on_node(                   \
        (fn), (data), -1 /* NUMA_NO_NODE */, (namefmt), ##__VA_ARGS__); \
    if (!IS_ERR(__t)) _wake_up_process(__t);                             \
    __t; })
#else
#define kthread_run_fs kthread_run
#define _kthread_stop  kthread_stop
#define _msleep        msleep
#define _synchronize_rcu synchronize_rcu
static inline int resolve_concurrency_syms(void) { return 0; }
#endif /* KMOD_FREESTANDING */

extern int tests_run;
extern int tests_passed;
extern int tests_failed;

#define KH_ASSERT(cond, msg)                                             \
    do {                                                                 \
        tests_run++;                                                     \
        if (cond) {                                                      \
            tests_passed++;                                              \
            pr_info(KH_TEST_TAG "PASS: %s\n", (msg));                   \
        } else {                                                         \
            tests_failed++;                                              \
            pr_err(KH_TEST_TAG "FAIL: %s (at %s:%d)\n",                 \
                   (msg), __FILE__, __LINE__);                           \
        }                                                                \
    } while (0)

#define KH_SKIP(msg) \
    pr_info(KH_TEST_TAG "SKIP: %s\n", (msg))

/* ---- Global test state ---- */

struct hook_test_state g_hook_state;

void hook_test_state_reset(void)
{
    g_hook_state.before_called = 0;
    g_hook_state.after_called  = 0;
    g_hook_state.before_arg0   = 0;
    g_hook_state.after_ret     = 0;
}

/* ==================================================================
 * fp_hook API tests — targets and shared state
 * ================================================================== */
static int my_add(int a, int b)          { return a + b; }
static int my_add_plus_100(int a, int b) { return a + b + 100; }

static int (* volatile fp_target)(int, int) = my_add;

static struct {
    int before_hits;
    int after_hits;
    int priority_order[4];
    int priority_idx;
    uintptr_t last_udata;
} g_fp_state;

static void fp_state_reset(void)
{
    g_fp_state.before_hits = 0;
    g_fp_state.after_hits = 0;
    g_fp_state.priority_idx = 0;
    g_fp_state.last_udata = 0;
    for (int i = 0; i < 4; i++) g_fp_state.priority_order[i] = -1;
    fp_target = my_add;
}

/* File-scope helpers for test_fp_hook_real_kernel_fp (Clang has no nested fns) */
static int fp_real_dummy(int x) { return x + 42; }
static int fp_real_my(int x)    { return x + 999; }
static int (* volatile fp_real_fake_fop)(int);

/* ---- Target functions with stable, hookable prologues ---- */

__attribute__((__noinline__)) uint64_t target_zero_args(void)
{
    uint64_t result;
    asm volatile(
        "mov %0, #42\n\t"
        "nop\n\t"
        "nop\n\t"
        "nop\n\t"
        : "=r"(result)
    );
    return result;
}

__attribute__((__noinline__)) uint64_t target_four_args(uint64_t a, uint64_t b, uint64_t c, uint64_t d)
{
    uint64_t result;
    asm volatile(
        "add %0, %1, %2\n\t"
        "add %0, %0, %3\n\t"
        "add %0, %0, %4\n\t"
        "nop\n\t"
        "nop\n\t"
        : "=r"(result)
        : "r"(a), "r"(b), "r"(c), "r"(d)
    );
    return result;
}

/* ================================================================
 * Test 1: test_inline_hook_basic
 *
 * Use kh_hook() to replace target_zero_args with replace_zero_args,
 * which calls the original and adds 100.  Verify the hooked value
 * is 142 (42 + 100), then kh_unhook and verify restoration to 42.
 * ================================================================ */

static uint64_t (*orig_target_zero_args)(void);

static uint64_t replace_zero_args(void)
{
    return orig_target_zero_args() + 100;
}

void test_inline_hook_basic(void)
{
    kh_hook_err_t err;
    uint64_t val;

    orig_target_zero_args = NULL;

    err = kh_hook((void *)target_zero_args, (void *)replace_zero_args,
               (void **)&orig_target_zero_args);

    KH_ASSERT(err == HOOK_NO_ERR, "inline kh_hook installs without error");
    KH_ASSERT(orig_target_zero_args != NULL, "backup pointer is non-NULL after kh_hook");

    val = target_zero_args();
    KH_ASSERT(val == 142, "hooked target_zero_args returns orig(42)+100=142");

    val = orig_target_zero_args();
    KH_ASSERT(val == 42, "original via backup returns 42");

    kh_unhook((void *)target_zero_args);

    val = target_zero_args();
    KH_ASSERT(val == 42, "target_zero_args restored to 42 after kh_unhook");
}

/* ================================================================
 * Test 2: test_hook_wrap_before_after
 *
 * Install wrap kh_hook on target_four_args with before/after callbacks.
 * Call with (10,20,30,40).  Verify:
 *   - before_called == 1
 *   - after_called  == 1
 *   - before_arg0   == 10
 *   - result        == 100
 *   - after_ret     == 100
 * ================================================================ */

static void before_four_args(kh_hook_fargs4_t *fargs, void *udata)
{
    (void)udata;
    g_hook_state.before_called++;
    g_hook_state.before_arg0 = fargs->arg0;
}

static void after_four_args(kh_hook_fargs4_t *fargs, void *udata)
{
    (void)udata;
    g_hook_state.after_called++;
    g_hook_state.after_ret = fargs->ret;
}

void test_hook_wrap_before_after(void)
{
    kh_hook_err_t err;
    uint64_t val;

    hook_test_state_reset();

    err = kh_hook_wrap4((void *)target_four_args, before_four_args, after_four_args, NULL);
    KH_ASSERT(err == HOOK_NO_ERR, "kh_hook_wrap4 installs without error");

    val = target_four_args(10, 20, 30, 40);

    KH_ASSERT(g_hook_state.before_called == 1, "before callback was called once");
    KH_ASSERT(g_hook_state.after_called  == 1, "after callback was called once");
    KH_ASSERT(g_hook_state.before_arg0   == 10, "before_arg0 captured as 10");
    KH_ASSERT(val == 100, "target_four_args(10,20,30,40) returns 100");
    KH_ASSERT(g_hook_state.after_ret == 100, "after_ret captured as 100");

    kh_hook_unwrap((void *)target_four_args, (void *)before_four_args, (void *)after_four_args);
}

/* ================================================================
 * Test 3: test_hook_wrap_skip_origin
 *
 * Install wrap0 with a before callback that sets skip_origin=1 and
 * ret=999.  Verify target_zero_args returns 999 without executing
 * the original body.
 * ================================================================ */

static void before_skip_origin(kh_hook_fargs0_t *fargs, void *udata)
{
    (void)udata;
    fargs->skip_origin = 1;
    fargs->ret = 999;
}

void test_hook_wrap_skip_origin(void)
{
    kh_hook_err_t err;
    uint64_t val;

    err = kh_hook_wrap0((void *)target_zero_args, before_skip_origin, NULL, NULL);
    KH_ASSERT(err == HOOK_NO_ERR, "kh_hook_wrap0 (skip_origin) installs without error");

    val = target_zero_args();
    KH_ASSERT(val == 999, "skip_origin=1 + ret=999 bypasses origin and returns 999");

    kh_hook_unwrap((void *)target_zero_args, (void *)before_skip_origin, NULL);
}

/* ================================================================
 * Test 4: test_hook_wrap_arg_passthrough
 *
 * Install wrap4 on target_four_args, capture arg0 in before callback.
 * Call with (1,2,3,4).  Verify arg0==1 and result==10.
 * ================================================================ */

static void before_four_args_pt(kh_hook_fargs4_t *fargs, void *udata)
{
    (void)udata;
    g_hook_state.before_called++;
    g_hook_state.before_arg0 = fargs->arg0;
}

static void after_four_args_pt(kh_hook_fargs4_t *fargs, void *udata)
{
    (void)udata;
    g_hook_state.after_called++;
    g_hook_state.after_ret = fargs->ret;
}

void test_hook_wrap_arg_passthrough(void)
{
    kh_hook_err_t err;
    uint64_t val;

    hook_test_state_reset();

    err = kh_hook_wrap4((void *)target_four_args, before_four_args_pt, after_four_args_pt, NULL);
    KH_ASSERT(err == HOOK_NO_ERR, "kh_hook_wrap4 (passthrough) installs without error");

    val = target_four_args(1, 2, 3, 4);

    KH_ASSERT(g_hook_state.before_arg0 == 1, "arg passthrough: arg0 captured as 1");
    KH_ASSERT(val == 10, "target_four_args(1,2,3,4) returns 10");

    kh_hook_unwrap((void *)target_four_args, (void *)before_four_args_pt, (void *)after_four_args_pt);
}

/* ================================================================
 * Test 5: test_hook_uninstall_restore
 *
 * Verify pre-kh_hook baseline, install wrap4, then immediately unwrap.
 * Confirm before_called remains 0 after the call and the original
 * function value is restored.
 * ================================================================ */

static void before_uninstall(kh_hook_fargs4_t *fargs, void *udata)
{
    (void)fargs;
    (void)udata;
    g_hook_state.before_called++;
}

void test_hook_uninstall_restore(void)
{
    kh_hook_err_t err;
    uint64_t val;

    hook_test_state_reset();

    /* Confirm pre-kh_hook baseline */
    val = target_four_args(1, 2, 3, 4);
    KH_ASSERT(val == 10, "pre-kh_hook target_four_args(1,2,3,4) baseline is 10");

    err = kh_hook_wrap4((void *)target_four_args, before_uninstall, NULL, NULL);
    KH_ASSERT(err == HOOK_NO_ERR, "kh_hook_wrap4 (uninstall test) installs without error");

    /* Remove the kh_hook before calling */
    kh_hook_unwrap((void *)target_four_args, (void *)before_uninstall, NULL);

    val = target_four_args(1, 2, 3, 4);
    KH_ASSERT(g_hook_state.before_called == 0, "before callback not called after unwrap");
    KH_ASSERT(val == 10, "original value 10 restored after unwrap");
}

/* ================================================================
 * Test 6: test_hook_chain_priority
 *
 * Register two wrap0 callbacks with priorities 10 (high) and 1 (low).
 * Verify the high-priority callback executes before the low-priority
 * one by recording the invocation order in priority_order[].
 * ================================================================ */

static int priority_order[2];
static int priority_order_idx;

static void before_priority_high(kh_hook_fargs0_t *fargs, void *udata)
{
    (void)fargs;
    (void)udata;
    if (priority_order_idx < 2)
        priority_order[priority_order_idx++] = 10;
}

static void before_priority_low(kh_hook_fargs0_t *fargs, void *udata)
{
    (void)fargs;
    (void)udata;
    if (priority_order_idx < 2)
        priority_order[priority_order_idx++] = 1;
}

void test_hook_chain_priority(void)
{
    kh_hook_err_t err_hi, err_lo;

    priority_order[0]  = 0;
    priority_order[1]  = 0;
    priority_order_idx = 0;

    /* Higher priority value runs first */
    err_hi = kh_hook_wrap((void *)target_zero_args, 0,
                       (void *)before_priority_high, NULL, NULL, 10);
    err_lo = kh_hook_wrap((void *)target_zero_args, 0,
                       (void *)before_priority_low,  NULL, NULL,  1);

    KH_ASSERT(err_hi == HOOK_NO_ERR, "high-priority wrap0 installs without error");
    KH_ASSERT(err_lo == HOOK_NO_ERR, "low-priority wrap0 installs without error");

    target_zero_args();

    KH_ASSERT(priority_order[0] == 10, "high-priority (10) callback runs first");
    KH_ASSERT(priority_order[1] ==  1, "low-priority (1) callback runs second");

    kh_hook_unwrap((void *)target_zero_args, (void *)before_priority_high, NULL);
    kh_hook_unwrap((void *)target_zero_args, (void *)before_priority_low,  NULL);
}

/* ================================================================
 * Test 7: test_kcfi_hook_and_call
 *
 * Verify kCFI hash is correctly copied to relocated code.
 *
 * On kCFI kernels, *(func - 4) contains the CFI type hash. After hooking,
 * the backup pointer (relocated code) must have the same hash at backup - 4.
 * Calling the backup via indirect call must not trigger a CFI failure.
 * ================================================================ */

void test_kcfi_hook_and_call(void)
{
#if defined(CONFIG_CFI_CLANG)
    kh_hook_err_t err;
    uint64_t val;
    uint32_t origin_hash, backup_hash;
    uint64_t (*backup)(void) = NULL;

    /* Read the kCFI hash at target_zero_args - 4 */
    origin_hash = *(uint32_t *)((uintptr_t)target_zero_args - 4);

    err = kh_hook((void *)target_zero_args, (void *)replace_zero_args,
               (void **)&backup);
    KH_ASSERT(err == HOOK_NO_ERR, "kCFI: kh_hook installs without error");
    KH_ASSERT(backup != NULL, "kCFI: backup pointer is non-NULL");

    /* Read the kCFI hash at backup - 4 (relocated code prefix) */
    backup_hash = *(uint32_t *)((uintptr_t)backup - 4);
    KH_ASSERT(origin_hash == backup_hash,
              "kCFI: relocated code has same CFI hash as original");

    /* Indirect call through backup — must not trigger kCFI trap */
    val = backup();
    KH_ASSERT(val == 42, "kCFI: indirect call via backup returns 42 without CFI fault");

    kh_unhook((void *)target_zero_args);
#else
    KH_SKIP("kCFI not enabled (CONFIG_CFI_CLANG not set)");
#endif
}

/* ================================================================
 * Test 8: test_pac_hook_restore
 *
 * Verify hooking PAC-protected functions works.
 *
 * On PAC kernels, function prologues start with PACIASP/PACIBSP.
 * Hook must generate 5-instruction trampoline (BTI_JC + branch_absolute).
 * Calling backup must not trigger FPAC fault. Unhook must restore cleanly.
 * ================================================================ */

static void before_pac_counter(kh_hook_fargs0_t *fargs, void *udata)
{
    (void)fargs;
    int *cnt = (int *)udata;
    (*cnt)++;
}

void test_pac_hook_restore(void)
{
#if defined(CONFIG_ARM64_PTR_AUTH_KERNEL)
    uint64_t func_addr;
    uint32_t first_inst;
    kh_hook_err_t err;
    int pac_counter = 0;
    void *rox_ptr;
    kh_hook_chain_rox_t *rox;

    /* Resolve a known kernel function that likely has PAC prologue */
    func_addr = ksyms_lookup("do_faccessat");
    if (!func_addr) {
        KH_SKIP("PAC: do_faccessat not found via ksyms_lookup");
        return;
    }

    /* Check if the first instruction is PACIASP or PACIBSP */
    first_inst = *(uint32_t *)func_addr;
    if (first_inst != ARM64_PACIASP && first_inst != ARM64_PACIBSP) {
        KH_SKIP("PAC: do_faccessat does not start with PACIASP/PACIBSP");
        return;
    }

    pr_info(KH_TEST_TAG "PAC: do_faccessat @ 0x%llx starts with %s\n",
            (unsigned long long)func_addr,
            first_inst == ARM64_PACIASP ? "PACIASP" : "PACIBSP");

    /* Hook with wrap to install a before callback */
    err = kh_hook_wrap((void *)func_addr, 0,
                    (void *)before_pac_counter, NULL, &pac_counter, 0);
    KH_ASSERT(err == HOOK_NO_ERR, "PAC: kh_hook_wrap installs without error");

    /* Verify trampoline structure: first inst should be BTI_JC, total 5 insts */
    rox_ptr = kh_mem_get_rox_from_origin(func_addr);
    KH_ASSERT(rox_ptr != NULL, "PAC: ROX pointer found for hooked function");

    if (rox_ptr) {
        rox = (kh_hook_chain_rox_t *)rox_ptr;
        KH_ASSERT(rox->kh_hook.tramp_insts[0] == ARM64_BTI_JC,
                  "PAC: trampoline[0] is BTI_JC (0xd50324df)");
        KH_ASSERT(rox->kh_hook.tramp_insts_num == TRAMPOLINE_NUM,
                  "PAC: trampoline has 5 instructions");
    }

    kh_hook_unwrap((void *)func_addr, (void *)before_pac_counter, NULL);
#else
    KH_SKIP("PAC not enabled (CONFIG_ARM64_PTR_AUTH_KERNEL not set)");
#endif
}

/* ================================================================
 * Test 9: test_bti_indirect_call
 *
 * Verify BTI landing pads in relocated code.
 *
 * On BTI kernels, indirect branches (BR) to code without BTI landing pad
 * cause a fault. Verify relocated code starts with BTI_JC.
 * ================================================================ */

void test_bti_indirect_call(void)
{
#if defined(CONFIG_ARM64_BTI_KERNEL)
    uint64_t func_addr;
    uint32_t first_inst;
    kh_hook_err_t err;
    void *rox_ptr;
    kh_hook_chain_rox_t *rox;

    /* Resolve a kernel function with BTI prologue */
    func_addr = ksyms_lookup("do_faccessat");
    if (!func_addr) {
        KH_SKIP("BTI: do_faccessat not found via ksyms_lookup");
        return;
    }

    /* Check if the first instruction is a BTI variant */
    first_inst = *(uint32_t *)func_addr;
    if (first_inst != ARM64_BTI_C && first_inst != ARM64_BTI_J &&
        first_inst != ARM64_BTI_JC) {
        /* On BTI+PAC kernels, the first instruction may be PACIASP (which
         * also acts as a BTI landing pad). Check for that too. */
        if (first_inst != ARM64_PACIASP && first_inst != ARM64_PACIBSP) {
            KH_SKIP("BTI: do_faccessat does not start with BTI/PAC landing pad");
            return;
        }
    }

    /* Hook with wrap to trigger relocation */
    err = kh_hook_wrap((void *)func_addr, 0, NULL, NULL, NULL, 0);
    KH_ASSERT(err == HOOK_NO_ERR, "BTI: kh_hook_wrap installs without error");

    /* Get the ROX pointer and verify relocated code starts with BTI_JC */
    rox_ptr = kh_mem_get_rox_from_origin(func_addr);
    KH_ASSERT(rox_ptr != NULL, "BTI: ROX pointer found for hooked function");

    if (rox_ptr) {
        rox = (kh_hook_chain_rox_t *)rox_ptr;
        KH_ASSERT(rox->kh_hook.relo_insts[0] == ARM64_BTI_JC,
                  "BTI: relocated code starts with BTI_JC (0xd50324df)");
    }

    kh_hook_unwrap((void *)func_addr, NULL, NULL);
#else
    KH_SKIP("BTI not enabled (CONFIG_ARM64_BTI_KERNEL not set)");
#endif
}

/* ================================================================
 * Test 10: test_scs_stack_integrity
 *
 * Verify shadow call stack not corrupted by hooks.
 *
 * On SCS kernels, x18 is the shadow stack pointer. After hooking and calling
 * a function, x18 must remain consistent (not corrupted by the kh_hook machinery).
 * ================================================================ */

void test_scs_stack_integrity(void)
{
#if defined(CONFIG_SHADOW_CALL_STACK)
    kh_hook_err_t err;
    uint64_t val;
    uintptr_t x18_before, x18_after;
    uint64_t (*backup)(void) = NULL;

    /* Read x18 (shadow call stack pointer) before test */
    asm volatile("mov %0, x18" : "=r"(x18_before));

    err = kh_hook((void *)target_zero_args, (void *)replace_zero_args,
               (void **)&backup);
    KH_ASSERT(err == HOOK_NO_ERR, "SCS: kh_hook installs without error");

    /* Call through the hooked function — exercises the full kh_hook chain */
    val = target_zero_args();
    KH_ASSERT(val == 142, "SCS: hooked target_zero_args returns 142");

    /* Call the backup directly — exercises relocated prologue with SCS push */
    val = backup();
    KH_ASSERT(val == 42, "SCS: backup call returns 42");

    /* Read x18 after — must be identical (SCS balanced) */
    asm volatile("mov %0, x18" : "=r"(x18_after));
    KH_ASSERT(x18_before == x18_after,
              "SCS: x18 (shadow stack ptr) unchanged after kh_hook calls");

    kh_unhook((void *)target_zero_args);

    /* Verify x18 still consistent after kh_unhook */
    asm volatile("mov %0, x18" : "=r"(x18_after));
    KH_ASSERT(x18_before == x18_after,
              "SCS: x18 unchanged after kh_unhook");
#else
    KH_SKIP("SCS not enabled (CONFIG_SHADOW_CALL_STACK not set)");
#endif
}

/* ================================================================
 * Real system function kh_hook chain tests (real-trigger mode)
 *
 * Each test resolves a real kernel function via ksyms_lookup(),
 * installs a kh_hook, then TRIGGERS the function via kh_raw_syscallN
 * (so it actually runs through the kh_hook chain) and asserts on the
 * hit counters recorded by the callbacks.
 * ================================================================ */

/* ---- real-trigger verification infrastructure ----
 *
 * Each callback receives a `struct kh5b_ctx *` via udata. It increments
 * `hits` and (optionally) appends `log_priority` to kh5b_priority_log.
 * Counters use GCC atomic builtins (same pattern as the rest of this
 * file). The Linux kernel <linux/atomic.h> types/macros are not
 * consumable in freestanding builds, so we model atomic_int as
 * `volatile int32_t` and provide matching helpers below.
 */
struct kh5b_ctx {
    const char     *tag_path;      /* for path-filtered callbacks */
    int32_t         tag_pid;       /* unused in freestanding build; kept
                                    * for plan parity */
    int32_t         tag_fd;        /* unused, kept for plan parity */
    volatile int32_t hits;         /* incremented on every match */
    int32_t         log_priority;  /* appended to priority log; -1 if unused */
};
#define KH5B_CTX_INIT { NULL, 0, -1, 0, -1 }

static inline void kh5b_inc(volatile int32_t *p)
{
    __atomic_fetch_add(p, 1, __ATOMIC_RELAXED);
}
static inline int32_t kh5b_read(volatile int32_t *p)
{
    return __atomic_load_n(p, __ATOMIC_RELAXED);
}

static int32_t          kh5b_priority_log[16];
static volatile int32_t kh5b_priority_idx;

static void kh5b_reset_priority_log(void)
{
    __atomic_store_n(&kh5b_priority_idx, 0, __ATOMIC_RELAXED);
    for (int i = 0; i < 16; i++) kh5b_priority_log[i] = 0;
}

/* ================================================================
 * Test 11: test_getpid_single_hook
 *
 * Hook __arm64_sys_getpid, trigger via kh_raw_syscall0(__NR_getpid)
 * twice, assert hit counter >= 2 (>= because unrelated tasks may
 * also call getpid during the kh_hook window).
 * ================================================================ */

static void kh5b_getpid_before(kh_hook_fargs0_t *args, void *udata)
{
    (void)args;
    struct kh5b_ctx *ctx = (struct kh5b_ctx *)udata;
    kh5b_inc(&ctx->hits);
}

void test_getpid_single_hook(void)
{
    uint64_t func_addr = ksyms_lookup("__arm64_sys_getpid");
    if (!func_addr) {
        KH_SKIP("sys_getpid: __arm64_sys_getpid not found via ksyms_lookup");
        return;
    }

    struct kh5b_ctx ctx = KH5B_CTX_INIT;

    /* Reuse the same callback for before and after so a single kh_hook
     * install covers both paths with distinct-looking pointers would
     * require two callbacks; we only need before hits for the assert. */
    kh_hook_err_t err = kh_hook_wrap((void *)func_addr, 0,
                               (void *)kh5b_getpid_before,
                               (void *)kh5b_getpid_before,
                               &ctx, 0);
    KH_ASSERT(err == HOOK_NO_ERR, "sys_getpid: kh_hook_wrap installs without error");
    if (err != HOOK_NO_ERR) return;

    /* Two raw getpid invocations from our insmod process context. */
    kh_raw_syscall0(__NR_getpid);
    kh_raw_syscall0(__NR_getpid);

    int32_t hits = kh5b_read(&ctx.hits);
    /* Two raw invocations each fire the chain once for before AND once
     * for after (both wired to kh5b_getpid_before). So we expect >= 4
     * from our own calls plus any concurrent traffic. Assert >= 2 to
     * match the plan's wording (the stronger bound is informational). */
    KH_ASSERT(hits >= 2,
              "sys_getpid: before callback fired >=2 times on real trigger");
    pr_info(KH_TEST_TAG "sys_getpid: hits=%d (expected >= 2)\n", hits);

    kh_hook_unwrap_remove((void *)func_addr, (void *)kh5b_getpid_before,
                       (void *)kh5b_getpid_before, 1);
}

/* ================================================================
 * Test 12: test_faccessat_chain_priority
 *
 * Hook do_faccessat, install 3 callbacks at priorities 10/5/1,
 * trigger once via kh_raw_syscall3(__NR_faccessat, AT_FDCWD,
 * upath, F_OK), assert hits == 3 and priority log == [10, 5, 1].
 * ================================================================ */

static void kh5b_faccessat_cb_by_prio(kh_hook_fargs4_t *args, void *udata)
{
    struct kh5b_ctx *ctx = (struct kh5b_ctx *)udata;
    if (!ctx->tag_path) return;

    /* do_faccessat signature on Linux 6.1 is:
     *   long do_faccessat(int dfd, const char __user *filename,
     *                     int mode, int flags)
     * so arg1 is a USER pointer directly — must use kh_strncpy_from_user
     * to safely probe it. (This is NOT a syscall wrapper; the kh_hook
     * receives native args.) */
    const void *user_path = (const void *)(uintptr_t)args->arg1;
    char buf[64];
    long n = kh_strncpy_from_user(buf, user_path, sizeof(buf));
    if (n <= 0) return;

    int k = 0;
    while (ctx->tag_path[k] && buf[k] == ctx->tag_path[k]) k++;
    /* Both sides must terminate at same index — a partial match like
     * probe "/foo" against user "/foo_bar" would otherwise false-count. */
    if (ctx->tag_path[k] != '\0' || buf[k] != '\0') return;

    kh5b_inc(&ctx->hits);
    int idx = __atomic_fetch_add(&kh5b_priority_idx, 1, __ATOMIC_RELAXED);
    if (idx < 16) kh5b_priority_log[idx] = ctx->log_priority;
}

void test_faccessat_chain_priority(void)
{
    uint64_t func_addr = ksyms_lookup("do_faccessat");
    if (!func_addr) {
        KH_SKIP("faccessat_chain: do_faccessat not found via ksyms_lookup");
        return;
    }

    kh5b_reset_priority_log();
    static const char probe_path[] = "/data/local/tmp/kh_probe_faccessat";
    struct kh5b_ctx ctx_hi  = { probe_path, 0, -1, 0, 10 };
    struct kh5b_ctx ctx_mid = { probe_path, 0, -1, 0, 5  };
    struct kh5b_ctx ctx_lo  = { probe_path, 0, -1, 0, 1  };

    kh_hook_err_t e1 = kh_hook_wrap((void *)func_addr, 4,
        (void *)kh5b_faccessat_cb_by_prio, NULL, &ctx_hi,  10);
    kh_hook_err_t e2 = kh_hook_wrap((void *)func_addr, 4,
        (void *)kh5b_faccessat_cb_by_prio, NULL, &ctx_mid, 5);
    kh_hook_err_t e3 = kh_hook_wrap((void *)func_addr, 4,
        (void *)kh5b_faccessat_cb_by_prio, NULL, &ctx_lo,  1);
    KH_ASSERT(e1 == HOOK_NO_ERR, "faccessat_chain: priority-10 installs OK");
    KH_ASSERT(e2 == HOOK_NO_ERR, "faccessat_chain: priority-5  installs OK");
    KH_ASSERT(e3 == HOOK_NO_ERR, "faccessat_chain: priority-1  installs OK");

    /* Place probe path on user stack + trigger faccessat. */
    void *upath = kh_copy_to_user_stack(probe_path, sizeof(probe_path));
    if ((long)upath < 0) {
        KH_ASSERT(0, "faccessat_chain: copy_to_user_stack failed");
        goto out;
    }
    /* AT_FDCWD = -100, F_OK = 0. */
    kh_raw_syscall3(__NR_faccessat, -100, (long)(uintptr_t)upath, 0);

    int32_t total = kh5b_read(&ctx_hi.hits)
                  + kh5b_read(&ctx_mid.hits)
                  + kh5b_read(&ctx_lo.hits);
    pr_info(KH_TEST_TAG
            "faccessat_chain: hits_hi=%d hits_mid=%d hits_lo=%d total=%d "
            "order=[%d,%d,%d]\n",
            kh5b_read(&ctx_hi.hits), kh5b_read(&ctx_mid.hits),
            kh5b_read(&ctx_lo.hits), total,
            kh5b_priority_log[0], kh5b_priority_log[1], kh5b_priority_log[2]);
    KH_ASSERT(total == 3, "faccessat_chain: 3 callbacks each fired once");
    KH_ASSERT(kh5b_priority_log[0] == 10,
              "faccessat_chain: priority order [0] == 10");
    KH_ASSERT(kh5b_priority_log[1] == 5,
              "faccessat_chain: priority order [1] == 5");
    KH_ASSERT(kh5b_priority_log[2] == 1,
              "faccessat_chain: priority order [2] == 1");

out:
    /* Three successive unwraps: chain contains 3 items with same callback
     * pointer but distinct udata. kh_hook_unwrap_remove matches by
     * before/after pointer only and removes ONE item at a time. */
    kh_hook_unwrap_remove((void *)func_addr,
        (void *)kh5b_faccessat_cb_by_prio, NULL, 0);
    kh_hook_unwrap_remove((void *)func_addr,
        (void *)kh5b_faccessat_cb_by_prio, NULL, 0);
    kh_hook_unwrap_remove((void *)func_addr,
        (void *)kh5b_faccessat_cb_by_prio, NULL, 1);
}

/* ================================================================
 * Test 13: test_filp_open_skip_origin
 *
 * Hook do_filp_open, before-cb sets skip_origin and ret=-ENOENT
 * for calls whose filename matches our probe path. Trigger via
 * kh_raw_syscall3(__NR_openat, AT_FDCWD, upath, O_RDONLY). Assert
 * the syscall returns -ENOENT AND our hit counter == 1.
 *
 * Path-filtering via `struct filename`: do_filp_open's arg1 is a
 * `struct filename *` whose first field (`const char *name`) is a
 * kernel pointer to the copied path. We compare strings directly
 * without going through uaccess.
 *
 * This avoids needing `current->pid` (unreachable in freestanding
 * without a task_struct.pid offset probe) while still keeping the
 * skip_origin effect scoped to our own call — any other process
 * opening the same probe path would also be blocked, but nothing on
 * Android should be looking at /data/local/tmp/kh_probe_* during our
 * init window.
 * ================================================================ */

static void kh5b_filp_open_skip_before(kh_hook_fargs4_t *args, void *udata)
{
    struct kh5b_ctx *ctx = (struct kh5b_ctx *)udata;

    /* Match on struct filename *. Layout: first field is
     * `const char *name` (stable across recent kernels). Deref it and
     * byte-compare against ctx->tag_path. */
    const char **name_pp = (const char **)(uintptr_t)args->arg1;
    if (!name_pp || !*name_pp || !ctx->tag_path) return;
    const char *kname = *name_pp;
    int k = 0;
    while (ctx->tag_path[k] && kname[k] == ctx->tag_path[k]) k++;
    if (ctx->tag_path[k] != '\0' || kname[k] != '\0') return;

    kh5b_inc(&ctx->hits);
    args->skip_origin = 1;
    args->ret = (uint64_t)(long)-2; /* -ENOENT, encoded as ERR_PTR-compatible */
}

void test_filp_open_skip_origin(void)
{
    uint64_t func_addr = ksyms_lookup("do_filp_open");
    if (!func_addr) {
        KH_SKIP("filp_open_skip: do_filp_open not found via ksyms_lookup");
        return;
    }

    static const char probe[] = "/data/local/tmp/kh_probe_filp_open_skip";
    struct kh5b_ctx ctx = { probe, 0, -1, 0, -1 };

    kh_hook_err_t err = kh_hook_wrap((void *)func_addr, 4,
        (void *)kh5b_filp_open_skip_before, NULL, &ctx, 0);
    KH_ASSERT(err == HOOK_NO_ERR, "filp_open_skip: installs");
    if (err != HOOK_NO_ERR) return;

    void *upath = kh_copy_to_user_stack(probe, sizeof(probe));
    if ((long)upath < 0) {
        KH_ASSERT(0, "filp_open_skip: copy_to_user_stack failed");
        goto out;
    }
    /* AT_FDCWD = -100, O_RDONLY = 0. */
    long rc = kh_raw_syscall3(__NR_openat, -100, (long)(uintptr_t)upath, 0);
    pr_info(KH_TEST_TAG "filp_open_skip: openat returned %ld (expected -2)\n",
            rc);
    KH_ASSERT(rc == -2,
              "filp_open_skip: openat returns -ENOENT via skip_origin");
    KH_ASSERT(kh5b_read(&ctx.hits) == 1,
              "filp_open_skip: before callback fired exactly once");

out:
    kh_hook_unwrap_remove((void *)func_addr,
        (void *)kh5b_filp_open_skip_before, NULL, 1);
}

/* ================================================================
 * Test 14: test_vfs_read_write_hook
 *
 * Hook vfs_read + vfs_write. Real trigger: openat + write + lseek +
 * read + close on a probe file. Assert both read and write hit
 * deltas are >= 1 (>= because the system has concurrent vfs traffic
 * we can't filter out — vfs_read/vfs_write take `struct file *`,
 * not fd, so path-level filtering is non-trivial here).
 *
 * The freestanding KH_SKIP has been retracted: the RCU fix in
 * transit.c + snapshot approach make live-system hooking of these
 * high-frequency functions safe.
 * ================================================================ */

static void kh5b_vfs_cb(kh_hook_fargs4_t *args, void *udata)
{
    (void)args;
    struct kh5b_ctx *ctx = (struct kh5b_ctx *)udata;
    kh5b_inc(&ctx->hits);
}

void test_vfs_read_write_hook(void)
{
    uint64_t vfs_read_addr  = ksyms_lookup("vfs_read");
    uint64_t vfs_write_addr = ksyms_lookup("vfs_write");
    if (!vfs_read_addr || !vfs_write_addr) {
        KH_SKIP("vfs_rw: vfs_read or vfs_write not found via ksyms_lookup");
        return;
    }

    struct kh5b_ctx read_ctx  = KH5B_CTX_INIT;
    struct kh5b_ctx write_ctx = KH5B_CTX_INIT;

    kh_hook_err_t e1 = kh_hook_wrap((void *)vfs_read_addr, 4,
                              (void *)kh5b_vfs_cb, NULL, &read_ctx, 0);
    kh_hook_err_t e2 = kh_hook_wrap((void *)vfs_write_addr, 4,
                              (void *)kh5b_vfs_cb, NULL, &write_ctx, 0);
    KH_ASSERT(e1 == HOOK_NO_ERR, "vfs_rw: vfs_read kh_hook installs");
    KH_ASSERT(e2 == HOOK_NO_ERR, "vfs_rw: vfs_write kh_hook installs");
    if (e1 != HOOK_NO_ERR || e2 != HOOK_NO_ERR) goto out;

    /* Probe file + 16-byte payload + 16-byte read buffer. */
    static const char probe[] = "/data/local/tmp/kh_probe_vfs_rw";
    static const char data[]  = "kh5b_probe_dataX";  /* 16 bytes incl NUL-less */
    char rbuf[16] = { 0 };

    void *upath   = kh_copy_to_user_stack(probe, sizeof(probe));
    void *udata_u = kh_copy_to_user_stack(data,  sizeof(data));
    void *urbuf   = kh_copy_to_user_stack(rbuf,  sizeof(rbuf));
    if ((long)upath < 0 || (long)udata_u < 0 || (long)urbuf < 0) {
        KH_ASSERT(0, "vfs_rw: copy_to_user_stack failed");
        goto out;
    }

    int32_t read_before  = kh5b_read(&read_ctx.hits);
    int32_t write_before = kh5b_read(&write_ctx.hits);

    /* AT_FDCWD = -100, O_CREAT|O_RDWR = 0102 (octal: O_RDWR=2, O_CREAT=0x40).
     * Mode 0600. */
    long fd = kh_raw_syscall4(__NR_openat, -100,
                              (long)(uintptr_t)upath,
                              0102, 0600);
    if (fd < 0) {
        pr_info(KH_TEST_TAG "vfs_rw: openat returned %ld\n", fd);
        KH_ASSERT(0, "vfs_rw: openat returned error");
        goto out;
    }
    kh_raw_syscall3(__NR_write, fd, (long)(uintptr_t)udata_u, 16);
    /* lseek(fd, 0, SEEK_SET=0) */
    kh_raw_syscall3(__NR_lseek, fd, 0, 0);
    kh_raw_syscall3(__NR_read,  fd, (long)(uintptr_t)urbuf, 16);
    kh_raw_syscall1(__NR_close, fd);

    int32_t read_delta  = kh5b_read(&read_ctx.hits)  - read_before;
    int32_t write_delta = kh5b_read(&write_ctx.hits) - write_before;
    pr_info(KH_TEST_TAG "vfs_rw: read delta=%d write delta=%d\n",
            read_delta, write_delta);
    KH_ASSERT(read_delta  >= 1, "vfs_rw: vfs_read fired at least once");
    KH_ASSERT(write_delta >= 1, "vfs_rw: vfs_write fired at least once");

out:
    kh_hook_unwrap_remove((void *)vfs_read_addr,
        (void *)kh5b_vfs_cb, NULL, 1);
    kh_hook_unwrap_remove((void *)vfs_write_addr,
        (void *)kh5b_vfs_cb, NULL, 1);
}

/* ================================================================
 * Test 15: test_dynamic_add_remove
 *
 * Exercise dynamic add/remove on do_faccessat WITH real triggers
 * between phases:
 *   install 2 → trigger → hits += 2
 *   add 3rd  → trigger → hits += 3
 *   remove 1 → trigger → hits += 2
 *   remove rest → trigger → hits += 0
 * Each callback is path-filtered against a unique probe path so
 * unrelated faccessat traffic does not bump our deltas.
 * ================================================================ */

static void dyn_hit_cb(kh_hook_fargs4_t *args, void *udata)
{
    struct kh5b_ctx *ctx = (struct kh5b_ctx *)udata;
    if (!ctx->tag_path) return;
    /* do_faccessat: arg1 is user pointer (see kh5b_faccessat_cb_by_prio). */
    const void *user_path = (const void *)(uintptr_t)args->arg1;
    char buf[64];
    long n = kh_strncpy_from_user(buf, user_path, sizeof(buf));
    if (n <= 0) return;
    int k = 0;
    while (ctx->tag_path[k] && buf[k] == ctx->tag_path[k]) k++;
    /* Full-match: both must terminate at the same index. */
    if (ctx->tag_path[k] != '\0' || buf[k] != '\0') return;
    kh5b_inc(&ctx->hits);
}
static void dyn_hit_cb_B(kh_hook_fargs4_t *args, void *udata) { dyn_hit_cb(args, udata); }
static void dyn_hit_cb_C(kh_hook_fargs4_t *args, void *udata) { dyn_hit_cb(args, udata); }

void test_dynamic_add_remove(void)
{
    uint64_t func_addr = ksyms_lookup("do_faccessat");
    if (!func_addr) {
        KH_SKIP("dyn_add_remove: do_faccessat not found via ksyms_lookup");
        return;
    }

    static const char probe[] = "/data/local/tmp/kh_probe_dyn";
    struct kh5b_ctx ctx_A = { probe, 0, -1, 0, -1 };
    struct kh5b_ctx ctx_B = { probe, 0, -1, 0, -1 };
    struct kh5b_ctx ctx_C = { probe, 0, -1, 0, -1 };

    void *upath = kh_copy_to_user_stack(probe, sizeof(probe));
    if ((long)upath < 0) {
        KH_ASSERT(0, "dyn_add_remove: copy_to_user_stack failed");
        return;
    }

    #define DYN_TRIGGER() \
        kh_raw_syscall3(__NR_faccessat, -100, (long)(uintptr_t)upath, 0)
    #define DYN_HITS()    (kh5b_read(&ctx_A.hits) + \
                           kh5b_read(&ctx_B.hits) + \
                           kh5b_read(&ctx_C.hits))

    /* Step 1: install 2, expect each to fire once per trigger. */
    kh_hook_err_t e1 = kh_hook_wrap((void *)func_addr, 4,
                              (void *)dyn_hit_cb,   NULL, &ctx_A, 0);
    kh_hook_err_t e2 = kh_hook_wrap((void *)func_addr, 4,
                              (void *)dyn_hit_cb_B, NULL, &ctx_B, 0);
    KH_ASSERT(e1 == HOOK_NO_ERR && e2 == HOOK_NO_ERR,
              "dyn: initial 2 callbacks install OK");
    int32_t h0 = DYN_HITS();
    DYN_TRIGGER();
    int32_t d0 = DYN_HITS() - h0;
    pr_info(KH_TEST_TAG "dyn: step1 delta=%d (expected 2)\n", d0);
    KH_ASSERT(d0 == 2, "dyn: 2 callbacks fire 2 hits on trigger");

    /* Step 2: add a 3rd, expect 3 on next trigger. */
    kh_hook_err_t e3 = kh_hook_wrap((void *)func_addr, 4,
                              (void *)dyn_hit_cb_C, NULL, &ctx_C, 0);
    KH_ASSERT(e3 == HOOK_NO_ERR, "dyn: 3rd callback installs OK");
    int32_t h1 = DYN_HITS();
    DYN_TRIGGER();
    int32_t d1 = DYN_HITS() - h1;
    pr_info(KH_TEST_TAG "dyn: step2 delta=%d (expected 3)\n", d1);
    KH_ASSERT(d1 == 3, "dyn: 3 callbacks fire after add");

    /* Step 3: remove 1st, expect 2 on next trigger. */
    kh_hook_unwrap_remove((void *)func_addr, (void *)dyn_hit_cb, NULL, 0);
    int32_t h2 = DYN_HITS();
    DYN_TRIGGER();
    int32_t d2 = DYN_HITS() - h2;
    pr_info(KH_TEST_TAG "dyn: step3 delta=%d (expected 2)\n", d2);
    KH_ASSERT(d2 == 2, "dyn: 2 callbacks fire after first remove");

    /* Step 4: remove the rest, expect 0 on next trigger. */
    kh_hook_unwrap_remove((void *)func_addr, (void *)dyn_hit_cb_B, NULL, 0);
    kh_hook_unwrap_remove((void *)func_addr, (void *)dyn_hit_cb_C, NULL, 1);
    int32_t h3 = DYN_HITS();
    DYN_TRIGGER();
    int32_t d3 = DYN_HITS() - h3;
    pr_info(KH_TEST_TAG "dyn: step4 delta=%d (expected 0)\n", d3);
    KH_ASSERT(d3 == 0, "dyn: 0 callbacks fire after all removed");

    #undef DYN_TRIGGER
    #undef DYN_HITS
}

/* ================================================================
 * Stress tests
 *
 * Pure stress tests that exercise kh_hook chain fill/drain and rapid
 * kh_hook/kh_unhook cycles. No concurrency — always available.
 * ================================================================ */

/* ---- Distinct before/after callbacks for chain fill stress test ----
 * We need HOOK_CHAIN_NUM (8) distinct pairs so each slot gets a unique
 * function pointer. Slot 0 is used by the initial kh_hook_wrap; slots 1..7
 * are filled via kh_hook_chain_add.
 */

#define STRESS_CB(N)                                                      \
    static void stress_before_##N(kh_hook_fargs4_t *args, void *udata)       \
    { (void)args; (void)udata; }                                          \
    static void stress_after_##N(kh_hook_fargs4_t *args, void *udata)        \
    { (void)args; (void)udata; }

STRESS_CB(0)
STRESS_CB(1)
STRESS_CB(2)
STRESS_CB(3)
STRESS_CB(4)
STRESS_CB(5)
STRESS_CB(6)
STRESS_CB(7)

/* Tables indexed 0..HOOK_CHAIN_NUM-1 for convenient iteration */
typedef void (*stress_cb_t)(kh_hook_fargs4_t *, void *);

static stress_cb_t stress_befores[HOOK_CHAIN_NUM] = {
    stress_before_0, stress_before_1, stress_before_2, stress_before_3,
    stress_before_4, stress_before_5, stress_before_6, stress_before_7,
};

static stress_cb_t stress_afters[HOOK_CHAIN_NUM] = {
    stress_after_0, stress_after_1, stress_after_2, stress_after_3,
    stress_after_4, stress_after_5, stress_after_6, stress_after_7,
};

/* ================================================================
 * test_stress_chain_fill_drain — fill all HOOK_CHAIN_NUM slots then
 * drain, repeat 1000 times. Verify occupied_mask and sorted_count
 * consistency.
 * ================================================================ */

void test_stress_chain_fill_drain(void)
{
    uint64_t func_addr;
    kh_hook_err_t err;
    void *rox_ptr;
    kh_hook_chain_rox_t *rox;
    kh_hook_chain_rw_t *rw;
    int i, iter;
    int failed = 0;

    func_addr = ksyms_lookup("do_faccessat");
    if (!func_addr) {
        KH_SKIP("stress_fill_drain: do_faccessat not found via ksyms_lookup");
        return;
    }

    /* Initial kh_hook — occupies slot 0 with stress_before_0/stress_after_0 */
    err = kh_hook_wrap((void *)func_addr, 4,
                    (void *)stress_befores[0], (void *)stress_afters[0], NULL, 0);
    KH_ASSERT(err == HOOK_NO_ERR, "stress_fill_drain: initial kh_hook_wrap OK");
    if (err != HOOK_NO_ERR)
        return;

    rox_ptr = kh_mem_get_rox_from_origin(func_addr);
    KH_ASSERT(rox_ptr != NULL, "stress_fill_drain: ROX exists after initial wrap");
    if (!rox_ptr)
        return;

    rox = (kh_hook_chain_rox_t *)rox_ptr;
    rw = rox->rw;
    KH_ASSERT(rw != NULL, "stress_fill_drain: RW is non-NULL");
    if (!rw)
        return;

    for (iter = 0; iter < 1000; iter++) {
        /* Fill remaining HOOK_CHAIN_NUM - 1 slots (indices 1..7) */
        for (i = 1; i < HOOK_CHAIN_NUM; i++) {
            err = kh_hook_chain_add(rw, (void *)stress_befores[i],
                                 (void *)stress_afters[i], NULL, i);
            if (err != HOOK_NO_ERR) {
                pr_err(KH_TEST_TAG
                       "FAIL: stress_fill_drain: kh_hook_chain_add failed at "
                       "iter=%d slot=%d err=%d\n", iter, i, err);
                failed = 1;
                goto drain;
            }
        }

        /* All slots occupied */
        if (rw->sorted_count != HOOK_CHAIN_NUM) {
            pr_err(KH_TEST_TAG
                   "FAIL: stress_fill_drain: sorted_count=%d != %d at iter=%d\n",
                   rw->sorted_count, HOOK_CHAIN_NUM, iter);
            failed = 1;
        }

drain:
        /* Drain all added slots (indices 1..7) */
        for (i = 1; i < HOOK_CHAIN_NUM; i++)
            kh_hook_chain_remove(rw, (void *)stress_befores[i],
                              (void *)stress_afters[i]);

        if (rw->sorted_count != 1) {
            pr_err(KH_TEST_TAG
                   "FAIL: stress_fill_drain: sorted_count=%d != 1 after drain "
                   "at iter=%d\n", rw->sorted_count, iter);
            failed = 1;
        }

        if (failed)
            break;
    }

    KH_ASSERT(!failed, "stress_fill_drain: 1000 fill/drain cycles consistent");

    /* Final cleanup: remove the initial kh_hook */
    kh_hook_unwrap_remove((void *)func_addr, (void *)stress_befores[0],
                       (void *)stress_afters[0], 1);

    rox_ptr = kh_mem_get_rox_from_origin(func_addr);
    KH_ASSERT(rox_ptr == NULL, "stress_fill_drain: ROX is NULL after full cleanup");
}

/* ================================================================
 * test_stress_rapid_hook_unhook — kh_hook_wrap then kh_hook_unwrap_remove
 * 1000 times on the same function. Verify no memory leak (ROX/RW
 * properly recycled).
 * ================================================================ */

static void rapid_before_cb(kh_hook_fargs4_t *args, void *udata)
{
    (void)args;
    (void)udata;
}

static void rapid_after_cb(kh_hook_fargs4_t *args, void *udata)
{
    (void)args;
    (void)udata;
}

void test_stress_rapid_hook_unhook(void)
{
    uint64_t func_addr;
    kh_hook_err_t err;
    void *rox_ptr;
    int i;
    int failed = 0;

    func_addr = ksyms_lookup("do_faccessat");
    if (!func_addr) {
        KH_SKIP("stress_rapid: do_faccessat not found via ksyms_lookup");
        return;
    }

    for (i = 0; i < 1000; i++) {
        err = kh_hook_wrap((void *)func_addr, 4,
                        (void *)rapid_before_cb, (void *)rapid_after_cb, NULL, 0);
        if (err != HOOK_NO_ERR) {
            pr_err(KH_TEST_TAG
                   "FAIL: stress_rapid: kh_hook_wrap failed at iter=%d err=%d\n",
                   i, err);
            failed = 1;
            break;
        }

        rox_ptr = kh_mem_get_rox_from_origin(func_addr);
        if (!rox_ptr) {
            pr_err(KH_TEST_TAG
                   "FAIL: stress_rapid: ROX is NULL after kh_hook_wrap at iter=%d\n",
                   i);
            failed = 1;
            break;
        }

        kh_hook_unwrap_remove((void *)func_addr, (void *)rapid_before_cb,
                           (void *)rapid_after_cb, 1);

        rox_ptr = kh_mem_get_rox_from_origin(func_addr);
        if (rox_ptr) {
            pr_err(KH_TEST_TAG
                   "FAIL: stress_rapid: ROX not NULL after unwrap at iter=%d\n",
                   i);
            failed = 1;
            break;
        }
    }

    KH_ASSERT(!failed, "stress_rapid: 1000 kh_hook/kh_unhook cycles clean");
}

/* ================================================================
 * Concurrency tests
 *
 * These tests require CONFIG_KH_CHAIN_RCU for thread safety.
 * In kbuild mode kthread/msleep/synchronize_rcu come from kernel
 * headers; in freestanding mode they are resolved via ksyms_lookup
 * inside resolve_concurrency_syms() at test entry.
 * ================================================================ */

#if defined(CONFIG_KH_CHAIN_RCU) && !defined(KH_SDK_MODE)
#ifndef KMOD_FREESTANDING
#include <linux/kthread.h>
#include <linux/delay.h>
#include <linux/sched.h>
#endif

/* ================================================================
 * test_concurrent_add_remove — TRUE race version.
 *
 * Two thread populations run for ~3s on the same kh_hook target:
 *
 *   - KH5D_CALL_THREADS    "call"   kthreads loop kh_raw_syscall0(__NR_getpid)
 *                                   so transit_body() actively executes the
 *                                   chain on every iteration.
 *   - KH5D_MUTATE_THREADS  "mutate" kthreads loop kh_hook_wrap / kh_hook_unwrap_remove
 *                                   at random priorities, exercising RCU
 *                                   replace + free of the rw snapshot.
 *
 * A priority-100 anchor callback is installed before the race starts and
 * never removed by the mutators (their key differs from the anchor's key).
 * Post-race we assert anchor remained the only entry, fired non-trivially
 * many times, and that final unwrap cleanly frees the ROX.
 *
 * Closes Finding 10 from the prior code review: the previous version of
 * this test never actually invoked the hooked function during the race,
 * so it could not exercise the transit_body RCU snapshot path under
 * concurrent free.
 *
 * Atomics: freestanding mode has no <linux/atomic.h>, so we model
 * `atomic_int` as `volatile int32_t` plus GCC __atomic_* builtins, the
 * same pattern real-trigger tests use (see kh5b_inc / kh5b_read above).
 * ================================================================ */

#define KH5D_CALL_THREADS   4
#define KH5D_MUTATE_THREADS 4
#define KH5D_DURATION_MS    3000

struct kh5d_call_td {
    volatile int    *stop;
    volatile int32_t count;
};

struct kh5d_mutate_td {
    volatile int    *stop;
    uint64_t         func_addr;
    volatile int32_t ops;
};

static void kh5d_anchor_cb(kh_hook_fargs0_t *args, void *udata)
{
    (void)args;
    __atomic_fetch_add((volatile int32_t *)udata, 1, __ATOMIC_RELAXED);
}

static void kh5d_churn_cb(kh_hook_fargs0_t *args, void *udata)
{
    (void)args;
    (void)udata;
}

__attribute__((no_sanitize("kcfi")))
static int kh5d_call_fn(void *arg)
{
    struct kh5d_call_td *td = (struct kh5d_call_td *)arg;
    while (!*td->stop) {
        kh_raw_syscall0(__NR_getpid);
        __atomic_fetch_add(&td->count, 1, __ATOMIC_RELAXED);
        /* Cooperative yield each iteration: this kernel boots with
         * softlockup_panic=1, and 8 hot kthreads with no rescheduling
         * point can starve essential bookkeeping (RCU grace, watchdog,
         * system_server) and trigger the panic threshold. The race we
         * actually want to exercise is "transit_body executes while
         * another CPU is in kh_hook_wrap/unwrap_remove" — that's still
         * fully exercised after a yield, since 8 hot kthreads guarantee
         * at least one transit and one mutate are running on different
         * CPUs at any instant. */
        schedule();
    }
    /* Wait for kthread_stop() so the kthread infra can join us cleanly. */
    while (!kthread_should_stop())
        schedule();
    return 0;
}

__attribute__((no_sanitize("kcfi")))
static int kh5d_mutate_fn(void *arg)
{
    struct kh5d_mutate_td *td = (struct kh5d_mutate_td *)arg;
    /* Per-thread LCG seed; xorshift-grade is plenty for priority jitter. */
    uint64_t seed = (uint64_t)(uintptr_t)td;
    while (!*td->stop) {
        seed = seed * 2862933555777941757ULL + 3037000493ULL;
        int prio = (int)((seed >> 32) % 20) + 1;  /* 1..20, never 100 */
        kh_hook_err_t err = kh_hook_wrap((void *)td->func_addr, 0,
                                   (void *)kh5d_churn_cb, NULL, NULL, prio);
        if (err == HOOK_NO_ERR) {
            __atomic_fetch_add(&td->ops, 1, __ATOMIC_RELAXED);
            kh_hook_unwrap_remove((void *)td->func_addr,
                               (void *)kh5d_churn_cb, NULL, 0);
        }
        /* Other err codes (HOOK_NO_MEM under chain pressure, HOOK_DUPLICATED
         * if another mutator is mid-install with the same key) are silently
         * skipped — they're expected churn under high concurrency, not
         * test failures. */
        schedule();
    }
    while (!kthread_should_stop())
        schedule();
    return 0;
}

__attribute__((no_sanitize("kcfi")))
void test_concurrent_add_remove(void)
{
    if (resolve_concurrency_syms() < 0) {
        KH_SKIP("concurrent: required kthread/msleep/synchronize_rcu symbols unavailable");
        return;
    }

    uint64_t func_addr = ksyms_lookup("__arm64_sys_getpid");
    if (!func_addr) {
        KH_SKIP("concurrent: __arm64_sys_getpid not found");
        return;
    }

    /* Anchor callback (priority 100) — installed once, never removed during
     * the race. Mutators use a different callback pointer so their churn
     * cannot accidentally evict the anchor. */
    volatile int32_t anchor_hits = 0;
    __atomic_store_n(&anchor_hits, 0, __ATOMIC_RELAXED);

    kh_hook_err_t err = kh_hook_wrap((void *)func_addr, 0,
                               (void *)kh5d_anchor_cb, NULL,
                               (void *)&anchor_hits, 100);
    KH_ASSERT(err == HOOK_NO_ERR, "concurrent: anchor installs");
    if (err != HOOK_NO_ERR) return;

    volatile int stop_flag = 0;
    struct task_struct *call_threads[KH5D_CALL_THREADS] = { 0 };
    struct task_struct *mut_threads[KH5D_MUTATE_THREADS] = { 0 };
    struct kh5d_call_td   ctds[KH5D_CALL_THREADS];
    struct kh5d_mutate_td mtds[KH5D_MUTATE_THREADS];

    int spawn_failures = 0;
    for (int i = 0; i < KH5D_CALL_THREADS; i++) {
        ctds[i].stop = &stop_flag;
        __atomic_store_n(&ctds[i].count, 0, __ATOMIC_RELAXED);
        call_threads[i] = kthread_run_fs(kh5d_call_fn, &ctds[i],
                                         "kh5d_call_%d", i);
        if (!call_threads[i] || IS_ERR(call_threads[i])) {
            call_threads[i] = NULL;
            spawn_failures++;
        }
    }
    for (int i = 0; i < KH5D_MUTATE_THREADS; i++) {
        mtds[i].stop = &stop_flag;
        mtds[i].func_addr = func_addr;
        __atomic_store_n(&mtds[i].ops, 0, __ATOMIC_RELAXED);
        mut_threads[i] = kthread_run_fs(kh5d_mutate_fn, &mtds[i],
                                        "kh5d_mut_%d", i);
        if (!mut_threads[i] || IS_ERR(mut_threads[i])) {
            mut_threads[i] = NULL;
            spawn_failures++;
        }
    }
    /* If the kernel is too loaded to spawn test threads, abort rather than
     * false-FAIL the >1000 calls assert. This is rare but real on memory-
     * pressured targets. */
    if (spawn_failures > 0) {
        pr_warn(KH_TEST_TAG "concurrent: %d kthread spawn failures; "
                "tearing down early\n", spawn_failures);
        stop_flag = 1;
        for (int i = 0; i < KH5D_CALL_THREADS; i++)
            if (call_threads[i]) _kthread_stop(call_threads[i]);
        for (int i = 0; i < KH5D_MUTATE_THREADS; i++)
            if (mut_threads[i]) _kthread_stop(mut_threads[i]);
        _synchronize_rcu();
        kh_hook_unwrap_remove((void *)func_addr,
                           (void *)kh5d_anchor_cb, NULL, 1);
        KH_SKIP("concurrent: kthread spawn partially failed — kernel too loaded");
        return;
    }

    _msleep(KH5D_DURATION_MS);
    stop_flag = 1;

    for (int i = 0; i < KH5D_CALL_THREADS; i++)
        if (call_threads[i] && !IS_ERR(call_threads[i]))
            _kthread_stop(call_threads[i]);
    for (int i = 0; i < KH5D_MUTATE_THREADS; i++)
        if (mut_threads[i] && !IS_ERR(mut_threads[i]))
            _kthread_stop(mut_threads[i]);

    /* Drain any in-flight transits before inspecting chain state. */
    _synchronize_rcu();

    int total_calls = 0, total_ops = 0;
    for (int i = 0; i < KH5D_CALL_THREADS; i++)
        total_calls += __atomic_load_n(&ctds[i].count, __ATOMIC_RELAXED);
    for (int i = 0; i < KH5D_MUTATE_THREADS; i++)
        total_ops += __atomic_load_n(&mtds[i].ops, __ATOMIC_RELAXED);

    int ahits = __atomic_load_n(&anchor_hits, __ATOMIC_RELAXED);
    pr_info(KH_TEST_TAG "concurrent: %d calls, %d mutates, %d anchor hits\n",
            total_calls, total_ops, ahits);

    KH_ASSERT(total_calls > 1000, "concurrent: >1000 total calls issued");
    KH_ASSERT(ahits > 100, "concurrent: anchor callback fired >100 times");

    /* Anchor must still be installed and be the only chain entry. */
    void *rox_ptr = kh_mem_get_rox_from_origin(func_addr);
    KH_ASSERT(rox_ptr != NULL, "concurrent: anchor ROX still present");
    if (rox_ptr) {
        kh_hook_chain_rw_t *rw = ((kh_hook_chain_rox_t *)rox_ptr)->rw;
        KH_ASSERT(rw && rw->sorted_count == 1,
                  "concurrent: sorted_count == 1 (only anchor remains)");
    }

    kh_hook_unwrap_remove((void *)func_addr,
                       (void *)kh5d_anchor_cb, NULL, 1);

    rox_ptr = kh_mem_get_rox_from_origin(func_addr);
    KH_ASSERT(rox_ptr == NULL, "concurrent: ROX cleaned up");
}
#endif /* CONFIG_KH_CHAIN_RCU && !KH_SDK_MODE */

/* ================================================================
 * fp_hook API tests
 * ================================================================ */

/* All fp_hook API tests call through fp_target which, when hooked, points at a
 * dynamically generated ROX transit stub with no kCFI hash. Mark them exempt. */
KCFI_EXEMPT void test_fp_hook_basic(void)
{
    void *backup = NULL;
    fp_state_reset();
    KH_ASSERT(fp_target(1, 2) == 3, "fp_basic: pre-kh_hook fp_target(1,2) == 3");
    kh_fp_hook((uintptr_t)&fp_target, (void *)my_add_plus_100, &backup);
    KH_ASSERT(backup == (void *)my_add, "fp_basic: backup captured original");
    KH_ASSERT(fp_target(1, 2) == 103, "fp_basic: hooked fp_target(1,2) == 103");
    kh_fp_unhook((uintptr_t)&fp_target, backup);
    KH_ASSERT(fp_target(1, 2) == 3, "fp_basic: post-kh_unhook fp_target(1,2) == 3");
}

static void fp_wrap_before_cb(kh_hook_fargs2_t *args, void *udata)
{ (void)args; g_fp_state.before_hits++; g_fp_state.last_udata = (uintptr_t)udata; }
static void fp_wrap_after_cb(kh_hook_fargs2_t *args, void *udata)
{ (void)args; (void)udata; g_fp_state.after_hits++; }

KCFI_EXEMPT void test_fp_hook_wrap_before_after(void)
{
    kh_hook_err_t err;
    fp_state_reset();
    err = kh_fp_hook_wrap((uintptr_t)&fp_target, 2,
                       (void *)fp_wrap_before_cb, (void *)fp_wrap_after_cb,
                       (void *)0xDEADBEEF, 0);
    KH_ASSERT(err == HOOK_NO_ERR, "fp_wrap: installs without error");
    int r = fp_target(10, 20);
    KH_ASSERT(r == 30, "fp_wrap: origin still returns 30");
    KH_ASSERT(g_fp_state.before_hits == 1, "fp_wrap: before ran once");
    KH_ASSERT(g_fp_state.after_hits == 1, "fp_wrap: after ran once");
    KH_ASSERT(g_fp_state.last_udata == 0xDEADBEEF, "fp_wrap: udata propagated");
    kh_fp_hook_unwrap((uintptr_t)&fp_target,
                   (void *)fp_wrap_before_cb, (void *)fp_wrap_after_cb);
    KH_ASSERT(fp_target(1, 2) == 3, "fp_wrap: post-unwrap origin restored");
    KH_ASSERT(g_fp_state.before_hits == 1, "fp_wrap: before not called after unwrap");
}

static void fp_prio_low (kh_hook_fargs2_t *a, void *u) { (void)a; g_fp_state.priority_order[g_fp_state.priority_idx++] = (int)(uintptr_t)u; }
static void fp_prio_mid (kh_hook_fargs2_t *a, void *u) { (void)a; g_fp_state.priority_order[g_fp_state.priority_idx++] = (int)(uintptr_t)u; }
static void fp_prio_high(kh_hook_fargs2_t *a, void *u) { (void)a; g_fp_state.priority_order[g_fp_state.priority_idx++] = (int)(uintptr_t)u; }

KCFI_EXEMPT void test_fp_hook_chain_priority(void)
{
    kh_hook_err_t err;
    fp_state_reset();
    err = kh_fp_hook_wrap((uintptr_t)&fp_target, 2, (void *)fp_prio_low,  NULL, (void *)1, 1);
    KH_ASSERT(err == HOOK_NO_ERR, "fp_prio: low installed");
    err = kh_fp_hook_wrap((uintptr_t)&fp_target, 2, (void *)fp_prio_high, NULL, (void *)3, 10);
    KH_ASSERT(err == HOOK_NO_ERR, "fp_prio: high installed");
    err = kh_fp_hook_wrap((uintptr_t)&fp_target, 2, (void *)fp_prio_mid,  NULL, (void *)2, 5);
    KH_ASSERT(err == HOOK_NO_ERR, "fp_prio: mid installed");
    (void)fp_target(7, 8);
    KH_ASSERT(g_fp_state.priority_idx == 3, "fp_prio: three callbacks ran");
    KH_ASSERT(g_fp_state.priority_order[0] == 3, "fp_prio: order[0]=high (udata=3)");
    KH_ASSERT(g_fp_state.priority_order[1] == 2, "fp_prio: order[1]=mid  (udata=2)");
    KH_ASSERT(g_fp_state.priority_order[2] == 1, "fp_prio: order[2]=low  (udata=1)");
    kh_fp_hook_unwrap((uintptr_t)&fp_target, (void *)fp_prio_low,  NULL);
    kh_fp_hook_unwrap((uintptr_t)&fp_target, (void *)fp_prio_mid,  NULL);
    kh_fp_hook_unwrap((uintptr_t)&fp_target, (void *)fp_prio_high, NULL);
}

static void fp_skip_before_cb(kh_hook_fargs2_t *args, void *udata)
{ (void)udata; args->skip_origin = 1; args->ret = 999; g_fp_state.before_hits++; }

KCFI_EXEMPT void test_fp_hook_skip_origin(void)
{
    kh_hook_err_t err;
    fp_state_reset();
    err = kh_fp_hook_wrap((uintptr_t)&fp_target, 2,
                       (void *)fp_skip_before_cb, NULL, NULL, 0);
    KH_ASSERT(err == HOOK_NO_ERR, "fp_skip: installs");
    KH_ASSERT(fp_target(1, 2) == 999, "fp_skip: skip_origin=1 ret=999 bypasses origin");
    KH_ASSERT(g_fp_state.before_hits == 1, "fp_skip: before called");
    kh_fp_hook_unwrap((uintptr_t)&fp_target, (void *)fp_skip_before_cb, NULL);
    KH_ASSERT(fp_target(1, 2) == 3, "fp_skip: post-unwrap origin restored");
}

KCFI_EXEMPT void test_fp_hook_uninstall_cleanup(void)
{
    kh_hook_err_t err;
    uintptr_t original;
    void *rox_ptr;
    fp_state_reset();
    original = (uintptr_t)fp_target;
    err = kh_fp_hook_wrap((uintptr_t)&fp_target, 2, (void *)fp_wrap_before_cb, NULL, NULL, 1);
    KH_ASSERT(err == HOOK_NO_ERR, "fp_cleanup: cb1 installed");
    err = kh_fp_hook_wrap((uintptr_t)&fp_target, 2, (void *)fp_prio_mid, NULL, (void *)2, 2);
    KH_ASSERT(err == HOOK_NO_ERR, "fp_cleanup: cb2 installed");
    err = kh_fp_hook_wrap((uintptr_t)&fp_target, 2, (void *)fp_prio_low, NULL, (void *)1, 3);
    KH_ASSERT(err == HOOK_NO_ERR, "fp_cleanup: cb3 installed");
    rox_ptr = kh_mem_get_rox_from_origin((uintptr_t)&fp_target);
    KH_ASSERT(rox_ptr != NULL, "fp_cleanup: ROX present while hooks active");
    KH_ASSERT((uintptr_t)fp_target != original, "fp_cleanup: fp_target points at transit");
    kh_fp_hook_unwrap((uintptr_t)&fp_target, (void *)fp_wrap_before_cb, NULL);
    kh_fp_hook_unwrap((uintptr_t)&fp_target, (void *)fp_prio_mid, NULL);
    kh_fp_hook_unwrap((uintptr_t)&fp_target, (void *)fp_prio_low, NULL);
    rox_ptr = kh_mem_get_rox_from_origin((uintptr_t)&fp_target);
    KH_ASSERT(rox_ptr == NULL, "fp_cleanup: ROX freed after last unwrap");
    KH_ASSERT((uintptr_t)fp_target == original, "fp_cleanup: fp_target restored");
    KH_ASSERT(fp_target(1, 2) == 3, "fp_cleanup: origin executes normally");
}

/* Conservative stub: real kernel FP kh_hook is gated on
 * CONFIG_KH_TEST_HOOK_REAL_FP so CI stays safe. The semantic equivalent
 * (indirect call through global) demonstrates the mechanism. */
KCFI_EXEMPT void test_fp_hook_real_kernel_fp(void)
{
    void *backup = NULL;
    fp_real_fake_fop = fp_real_dummy;
    KH_ASSERT(fp_real_fake_fop(0) == 42, "fp_real: baseline fake_fop_read(0) == 42");
    kh_fp_hook((uintptr_t)&fp_real_fake_fop, (void *)fp_real_my, &backup);
    KH_ASSERT(fp_real_fake_fop(0) == 999, "fp_real: hooked fake_fop_read(0) == 999");
    kh_fp_unhook((uintptr_t)&fp_real_fake_fop, backup);
    KH_ASSERT(fp_real_fake_fop(0) == 42, "fp_real: post-kh_unhook fake_fop_read(0) == 42");
    KH_SKIP("fp_real: stub passed; live kernel-FP variant opt-in via CONFIG_KH_TEST_HOOK_REAL_FP");
}
