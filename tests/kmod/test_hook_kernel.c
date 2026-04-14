// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Kernel-context hook tests for KernelHook
 *
 * Fifteen tests covering:
 *   1. Inline hook (hook/unhook) with zero-arg target
 *   2. Wrap hook before/after callbacks with four-arg target
 *   3. Wrap hook skip_origin via before callback
 *   4. Wrap hook argument passthrough verification
 *   5. Hook uninstall and original function restoration
 *   6. Hook chain priority ordering
 *   7. kCFI hash copy to relocated code (CONFIG_CFI_CLANG)
 *   8. PAC-protected function hooking and trampoline structure (CONFIG_ARM64_PTR_AUTH_KERNEL)
 *   9. BTI landing pads in relocated code (CONFIG_ARM64_BTI_KERNEL)
 *  10. Shadow call stack integrity through hook calls (CONFIG_SHADOW_CALL_STACK)
 *  11. Single hook on real kernel function (__arm64_sys_getpid)
 *  12. Chain priority ordering on real kernel function (do_faccessat)
 *  13. Skip-origin hook on real kernel function (do_filp_open)
 *  14. Multi-function hook with dynamic add/remove (vfs_read/vfs_write)
 *  15. Full dynamic add/remove lifecycle (do_faccessat)
 */

#if defined(KH_SDK_MODE)
/* Mode B: SDK — kernelhook.ko provides the API */
#include <kernelhook/hook.h>
#include <kernelhook/types.h>
#else
#include <linux/kernel.h>
#endif

#if !defined(KH_SDK_MODE)
#include <hook.h>
#include <memory.h>
#include <symbol.h>
#endif
#include "test_hook_kernel.h"

#define KH_TEST_TAG "kh_test: "

/* ================================================================
 * Freestanding shim: resolve kthread/msleep/synchronize_rcu via
 * ksyms_lookup so that Phase 5d concurrency tests can run without
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
 * Use hook() to replace target_zero_args with replace_zero_args,
 * which calls the original and adds 100.  Verify the hooked value
 * is 142 (42 + 100), then unhook and verify restoration to 42.
 * ================================================================ */

static uint64_t (*orig_target_zero_args)(void);

static uint64_t replace_zero_args(void)
{
    return orig_target_zero_args() + 100;
}

void test_inline_hook_basic(void)
{
    hook_err_t err;
    uint64_t val;

    orig_target_zero_args = NULL;

    err = hook((void *)target_zero_args, (void *)replace_zero_args,
               (void **)&orig_target_zero_args);

    KH_ASSERT(err == HOOK_NO_ERR, "inline hook installs without error");
    KH_ASSERT(orig_target_zero_args != NULL, "backup pointer is non-NULL after hook");

    val = target_zero_args();
    KH_ASSERT(val == 142, "hooked target_zero_args returns orig(42)+100=142");

    val = orig_target_zero_args();
    KH_ASSERT(val == 42, "original via backup returns 42");

    unhook((void *)target_zero_args);

    val = target_zero_args();
    KH_ASSERT(val == 42, "target_zero_args restored to 42 after unhook");
}

/* ================================================================
 * Test 2: test_hook_wrap_before_after
 *
 * Install wrap hook on target_four_args with before/after callbacks.
 * Call with (10,20,30,40).  Verify:
 *   - before_called == 1
 *   - after_called  == 1
 *   - before_arg0   == 10
 *   - result        == 100
 *   - after_ret     == 100
 * ================================================================ */

static void before_four_args(hook_fargs4_t *fargs, void *udata)
{
    (void)udata;
    g_hook_state.before_called++;
    g_hook_state.before_arg0 = fargs->arg0;
}

static void after_four_args(hook_fargs4_t *fargs, void *udata)
{
    (void)udata;
    g_hook_state.after_called++;
    g_hook_state.after_ret = fargs->ret;
}

void test_hook_wrap_before_after(void)
{
    hook_err_t err;
    uint64_t val;

    hook_test_state_reset();

    err = hook_wrap4((void *)target_four_args, before_four_args, after_four_args, NULL);
    KH_ASSERT(err == HOOK_NO_ERR, "hook_wrap4 installs without error");

    val = target_four_args(10, 20, 30, 40);

    KH_ASSERT(g_hook_state.before_called == 1, "before callback was called once");
    KH_ASSERT(g_hook_state.after_called  == 1, "after callback was called once");
    KH_ASSERT(g_hook_state.before_arg0   == 10, "before_arg0 captured as 10");
    KH_ASSERT(val == 100, "target_four_args(10,20,30,40) returns 100");
    KH_ASSERT(g_hook_state.after_ret == 100, "after_ret captured as 100");

    hook_unwrap((void *)target_four_args, (void *)before_four_args, (void *)after_four_args);
}

/* ================================================================
 * Test 3: test_hook_wrap_skip_origin
 *
 * Install wrap0 with a before callback that sets skip_origin=1 and
 * ret=999.  Verify target_zero_args returns 999 without executing
 * the original body.
 * ================================================================ */

static void before_skip_origin(hook_fargs0_t *fargs, void *udata)
{
    (void)udata;
    fargs->skip_origin = 1;
    fargs->ret = 999;
}

void test_hook_wrap_skip_origin(void)
{
    hook_err_t err;
    uint64_t val;

    err = hook_wrap0((void *)target_zero_args, before_skip_origin, NULL, NULL);
    KH_ASSERT(err == HOOK_NO_ERR, "hook_wrap0 (skip_origin) installs without error");

    val = target_zero_args();
    KH_ASSERT(val == 999, "skip_origin=1 + ret=999 bypasses origin and returns 999");

    hook_unwrap((void *)target_zero_args, (void *)before_skip_origin, NULL);
}

/* ================================================================
 * Test 4: test_hook_wrap_arg_passthrough
 *
 * Install wrap4 on target_four_args, capture arg0 in before callback.
 * Call with (1,2,3,4).  Verify arg0==1 and result==10.
 * ================================================================ */

static void before_four_args_pt(hook_fargs4_t *fargs, void *udata)
{
    (void)udata;
    g_hook_state.before_called++;
    g_hook_state.before_arg0 = fargs->arg0;
}

static void after_four_args_pt(hook_fargs4_t *fargs, void *udata)
{
    (void)udata;
    g_hook_state.after_called++;
    g_hook_state.after_ret = fargs->ret;
}

void test_hook_wrap_arg_passthrough(void)
{
    hook_err_t err;
    uint64_t val;

    hook_test_state_reset();

    err = hook_wrap4((void *)target_four_args, before_four_args_pt, after_four_args_pt, NULL);
    KH_ASSERT(err == HOOK_NO_ERR, "hook_wrap4 (passthrough) installs without error");

    val = target_four_args(1, 2, 3, 4);

    KH_ASSERT(g_hook_state.before_arg0 == 1, "arg passthrough: arg0 captured as 1");
    KH_ASSERT(val == 10, "target_four_args(1,2,3,4) returns 10");

    hook_unwrap((void *)target_four_args, (void *)before_four_args_pt, (void *)after_four_args_pt);
}

/* ================================================================
 * Test 5: test_hook_uninstall_restore
 *
 * Verify pre-hook baseline, install wrap4, then immediately unwrap.
 * Confirm before_called remains 0 after the call and the original
 * function value is restored.
 * ================================================================ */

static void before_uninstall(hook_fargs4_t *fargs, void *udata)
{
    (void)fargs;
    (void)udata;
    g_hook_state.before_called++;
}

void test_hook_uninstall_restore(void)
{
    hook_err_t err;
    uint64_t val;

    hook_test_state_reset();

    /* Confirm pre-hook baseline */
    val = target_four_args(1, 2, 3, 4);
    KH_ASSERT(val == 10, "pre-hook target_four_args(1,2,3,4) baseline is 10");

    err = hook_wrap4((void *)target_four_args, before_uninstall, NULL, NULL);
    KH_ASSERT(err == HOOK_NO_ERR, "hook_wrap4 (uninstall test) installs without error");

    /* Remove the hook before calling */
    hook_unwrap((void *)target_four_args, (void *)before_uninstall, NULL);

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

static void before_priority_high(hook_fargs0_t *fargs, void *udata)
{
    (void)fargs;
    (void)udata;
    if (priority_order_idx < 2)
        priority_order[priority_order_idx++] = 10;
}

static void before_priority_low(hook_fargs0_t *fargs, void *udata)
{
    (void)fargs;
    (void)udata;
    if (priority_order_idx < 2)
        priority_order[priority_order_idx++] = 1;
}

void test_hook_chain_priority(void)
{
    hook_err_t err_hi, err_lo;

    priority_order[0]  = 0;
    priority_order[1]  = 0;
    priority_order_idx = 0;

    /* Higher priority value runs first */
    err_hi = hook_wrap((void *)target_zero_args, 0,
                       (void *)before_priority_high, NULL, NULL, 10);
    err_lo = hook_wrap((void *)target_zero_args, 0,
                       (void *)before_priority_low,  NULL, NULL,  1);

    KH_ASSERT(err_hi == HOOK_NO_ERR, "high-priority wrap0 installs without error");
    KH_ASSERT(err_lo == HOOK_NO_ERR, "low-priority wrap0 installs without error");

    target_zero_args();

    KH_ASSERT(priority_order[0] == 10, "high-priority (10) callback runs first");
    KH_ASSERT(priority_order[1] ==  1, "low-priority (1) callback runs second");

    hook_unwrap((void *)target_zero_args, (void *)before_priority_high, NULL);
    hook_unwrap((void *)target_zero_args, (void *)before_priority_low,  NULL);
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
    hook_err_t err;
    uint64_t val;
    uint32_t origin_hash, backup_hash;
    uint64_t (*backup)(void) = NULL;

    /* Read the kCFI hash at target_zero_args - 4 */
    origin_hash = *(uint32_t *)((uintptr_t)target_zero_args - 4);

    err = hook((void *)target_zero_args, (void *)replace_zero_args,
               (void **)&backup);
    KH_ASSERT(err == HOOK_NO_ERR, "kCFI: hook installs without error");
    KH_ASSERT(backup != NULL, "kCFI: backup pointer is non-NULL");

    /* Read the kCFI hash at backup - 4 (relocated code prefix) */
    backup_hash = *(uint32_t *)((uintptr_t)backup - 4);
    KH_ASSERT(origin_hash == backup_hash,
              "kCFI: relocated code has same CFI hash as original");

    /* Indirect call through backup — must not trigger kCFI trap */
    val = backup();
    KH_ASSERT(val == 42, "kCFI: indirect call via backup returns 42 without CFI fault");

    unhook((void *)target_zero_args);
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

static void before_pac_counter(hook_fargs0_t *fargs, void *udata)
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
    hook_err_t err;
    int pac_counter = 0;
    void *rox_ptr;
    hook_chain_rox_t *rox;

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
    err = hook_wrap((void *)func_addr, 0,
                    (void *)before_pac_counter, NULL, &pac_counter, 0);
    KH_ASSERT(err == HOOK_NO_ERR, "PAC: hook_wrap installs without error");

    /* Verify trampoline structure: first inst should be BTI_JC, total 5 insts */
    rox_ptr = hook_mem_get_rox_from_origin(func_addr);
    KH_ASSERT(rox_ptr != NULL, "PAC: ROX pointer found for hooked function");

    if (rox_ptr) {
        rox = (hook_chain_rox_t *)rox_ptr;
        KH_ASSERT(rox->hook.tramp_insts[0] == ARM64_BTI_JC,
                  "PAC: trampoline[0] is BTI_JC (0xd50324df)");
        KH_ASSERT(rox->hook.tramp_insts_num == TRAMPOLINE_NUM,
                  "PAC: trampoline has 5 instructions");
    }

    hook_unwrap((void *)func_addr, (void *)before_pac_counter, NULL);
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
    hook_err_t err;
    void *rox_ptr;
    hook_chain_rox_t *rox;

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
    err = hook_wrap((void *)func_addr, 0, NULL, NULL, NULL, 0);
    KH_ASSERT(err == HOOK_NO_ERR, "BTI: hook_wrap installs without error");

    /* Get the ROX pointer and verify relocated code starts with BTI_JC */
    rox_ptr = hook_mem_get_rox_from_origin(func_addr);
    KH_ASSERT(rox_ptr != NULL, "BTI: ROX pointer found for hooked function");

    if (rox_ptr) {
        rox = (hook_chain_rox_t *)rox_ptr;
        KH_ASSERT(rox->hook.relo_insts[0] == ARM64_BTI_JC,
                  "BTI: relocated code starts with BTI_JC (0xd50324df)");
    }

    hook_unwrap((void *)func_addr, NULL, NULL);
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
 * a function, x18 must remain consistent (not corrupted by the hook machinery).
 * ================================================================ */

void test_scs_stack_integrity(void)
{
#if defined(CONFIG_SHADOW_CALL_STACK)
    hook_err_t err;
    uint64_t val;
    uintptr_t x18_before, x18_after;
    uint64_t (*backup)(void) = NULL;

    /* Read x18 (shadow call stack pointer) before test */
    asm volatile("mov %0, x18" : "=r"(x18_before));

    err = hook((void *)target_zero_args, (void *)replace_zero_args,
               (void **)&backup);
    KH_ASSERT(err == HOOK_NO_ERR, "SCS: hook installs without error");

    /* Call through the hooked function — exercises the full hook chain */
    val = target_zero_args();
    KH_ASSERT(val == 142, "SCS: hooked target_zero_args returns 142");

    /* Call the backup directly — exercises relocated prologue with SCS push */
    val = backup();
    KH_ASSERT(val == 42, "SCS: backup call returns 42");

    /* Read x18 after — must be identical (SCS balanced) */
    asm volatile("mov %0, x18" : "=r"(x18_after));
    KH_ASSERT(x18_before == x18_after,
              "SCS: x18 (shadow stack ptr) unchanged after hook calls");

    unhook((void *)target_zero_args);

    /* Verify x18 still consistent after unhook */
    asm volatile("mov %0, x18" : "=r"(x18_after));
    KH_ASSERT(x18_before == x18_after,
              "SCS: x18 unchanged after unhook");
#else
    KH_SKIP("SCS not enabled (CONFIG_SHADOW_CALL_STACK not set)");
#endif
}

/* ================================================================
 * Phase 5b: Real system function hook chain tests
 *
 * These tests resolve real kernel functions via ksyms_lookup() and
 * exercise the hook chain machinery (install, priority ordering,
 * dynamic add/remove, cleanup) without invoking the hooked functions.
 * ================================================================ */

/* ---- Shared infrastructure ---- */

static volatile int32_t sys_hook_before_count;
static volatile int32_t sys_hook_after_count;
static int32_t sys_priority_log[16];
static volatile int32_t sys_priority_idx;

static void sys_reset_counters(void)
{
    __atomic_store_n(&sys_hook_before_count, 0, __ATOMIC_RELAXED);
    __atomic_store_n(&sys_hook_after_count, 0, __ATOMIC_RELAXED);
    __atomic_store_n(&sys_priority_idx, 0, __ATOMIC_RELAXED);
    __builtin_memset(sys_priority_log, 0, sizeof(sys_priority_log));
}

/* ---- Before/after callback templates ---- */

/* 0-arg before callback — increments counter, logs priority from udata */
static void sys_before_cb_0arg(hook_fargs0_t *args, void *udata)
{
    (void)args;
    __atomic_fetch_add(&sys_hook_before_count, 1, __ATOMIC_RELAXED);
    int idx = __atomic_fetch_add(&sys_priority_idx, 1, __ATOMIC_RELAXED);
    if (idx < 16)
        sys_priority_log[idx] = (int32_t)(uintptr_t)udata;
}

/* 0-arg after callback — increments counter */
static void sys_after_cb_0arg(hook_fargs0_t *args, void *udata)
{
    (void)args;
    (void)udata;
    __atomic_fetch_add(&sys_hook_after_count, 1, __ATOMIC_RELAXED);
}

/* 4-arg before callback — increments counter, logs priority from udata */
static void sys_before_cb_4arg(hook_fargs4_t *args, void *udata)
{
    (void)args;
    __atomic_fetch_add(&sys_hook_before_count, 1, __ATOMIC_RELAXED);
    int idx = __atomic_fetch_add(&sys_priority_idx, 1, __ATOMIC_RELAXED);
    if (idx < 16)
        sys_priority_log[idx] = (int32_t)(uintptr_t)udata;
}

/* 4-arg after callback — increments counter */
static void sys_after_cb_4arg(hook_fargs4_t *args, void *udata)
{
    (void)args;
    (void)udata;
    __atomic_fetch_add(&sys_hook_after_count, 1, __ATOMIC_RELAXED);
}

/* Additional named callbacks for distinct registration in multi-chain tests */
static void sys_before_cb_4arg_B(hook_fargs4_t *args, void *udata)
{
    (void)args;
    __atomic_fetch_add(&sys_hook_before_count, 1, __ATOMIC_RELAXED);
    int idx = __atomic_fetch_add(&sys_priority_idx, 1, __ATOMIC_RELAXED);
    if (idx < 16)
        sys_priority_log[idx] = (int32_t)(uintptr_t)udata;
}

static void sys_after_cb_4arg_B(hook_fargs4_t *args, void *udata)
{
    (void)args;
    (void)udata;
    __atomic_fetch_add(&sys_hook_after_count, 1, __ATOMIC_RELAXED);
}

static void sys_before_cb_4arg_C(hook_fargs4_t *args, void *udata)
{
    (void)args;
    __atomic_fetch_add(&sys_hook_before_count, 1, __ATOMIC_RELAXED);
    int idx = __atomic_fetch_add(&sys_priority_idx, 1, __ATOMIC_RELAXED);
    if (idx < 16)
        sys_priority_log[idx] = (int32_t)(uintptr_t)udata;
}

static void sys_after_cb_4arg_C(hook_fargs4_t *args, void *udata)
{
    (void)args;
    (void)udata;
    __atomic_fetch_add(&sys_hook_after_count, 1, __ATOMIC_RELAXED);
}

/* 4-arg skip-origin before callback */
static void sys_skip_before_cb_4arg(hook_fargs4_t *args, void *udata)
{
    (void)udata;
    args->skip_origin = 1;
    args->ret = 0xDEAD;
}

/* ================================================================
 * Test 11: test_getpid_single_hook
 *
 * Resolve __arm64_sys_getpid (argno=0). Verify hook installation
 * creates proper data structures and unhook cleans up.
 * ================================================================ */

void test_getpid_single_hook(void)
{
    uint64_t func_addr;
    hook_err_t err;
    void *rox_ptr;

    func_addr = ksyms_lookup("__arm64_sys_getpid");
    if (!func_addr) {
        KH_SKIP("sys_getpid: __arm64_sys_getpid not found via ksyms_lookup");
        return;
    }

    sys_reset_counters();

    err = hook_wrap((void *)func_addr, 0,
                    (void *)sys_before_cb_0arg, (void *)sys_after_cb_0arg, NULL, 0);
    KH_ASSERT(err == HOOK_NO_ERR, "sys_getpid: hook_wrap installs without error");

    /* Verify hook data structures exist */
    rox_ptr = hook_mem_get_rox_from_origin(func_addr);
    KH_ASSERT(rox_ptr != NULL, "sys_getpid: ROX pointer exists after hook_wrap");

    if (rox_ptr) {
        hook_chain_rox_t *rox = (hook_chain_rox_t *)rox_ptr;
        hook_chain_rw_t *rw = rox->rw;
        KH_ASSERT(rw != NULL, "sys_getpid: RW pointer is non-NULL");
        if (rw) {
            KH_ASSERT(rw->sorted_count == 1, "sys_getpid: sorted_count == 1");
            KH_ASSERT(rw->argno == 0, "sys_getpid: argno == 0");
        }
    }

    /* Unhook and verify cleanup */
    hook_unwrap_remove((void *)func_addr, (void *)sys_before_cb_0arg,
                       (void *)sys_after_cb_0arg, 1);

    rox_ptr = hook_mem_get_rox_from_origin(func_addr);
    KH_ASSERT(rox_ptr == NULL, "sys_getpid: ROX pointer is NULL after cleanup");
}

/* ================================================================
 * Test 12: test_faccessat_chain_priority
 *
 * Resolve do_faccessat (argno=4). Install 3 callbacks at different
 * priorities and verify the sorted order in the RW structure.
 * ================================================================ */

void test_faccessat_chain_priority(void)
{
    uint64_t func_addr;
    hook_err_t err1, err2, err3;
    void *rox_ptr;

    func_addr = ksyms_lookup("do_faccessat");
    if (!func_addr) {
        KH_SKIP("faccessat_chain: do_faccessat not found via ksyms_lookup");
        return;
    }

    sys_reset_counters();

    /* Install 3 callbacks at priorities 10, 5, 1 */
    err1 = hook_wrap((void *)func_addr, 4,
                     (void *)sys_before_cb_4arg, (void *)sys_after_cb_4arg,
                     (void *)(uintptr_t)10, 10);
    err2 = hook_wrap((void *)func_addr, 4,
                     (void *)sys_before_cb_4arg_B, (void *)sys_after_cb_4arg_B,
                     (void *)(uintptr_t)5, 5);
    err3 = hook_wrap((void *)func_addr, 4,
                     (void *)sys_before_cb_4arg_C, (void *)sys_after_cb_4arg_C,
                     (void *)(uintptr_t)1, 1);

    KH_ASSERT(err1 == HOOK_NO_ERR, "faccessat_chain: priority-10 installs OK");
    KH_ASSERT(err2 == HOOK_NO_ERR, "faccessat_chain: priority-5 installs OK");
    KH_ASSERT(err3 == HOOK_NO_ERR, "faccessat_chain: priority-1 installs OK");

    /* Verify chain count and sorted order */
    rox_ptr = hook_mem_get_rox_from_origin(func_addr);
    KH_ASSERT(rox_ptr != NULL, "faccessat_chain: ROX pointer exists");

    if (rox_ptr) {
        hook_chain_rox_t *rox = (hook_chain_rox_t *)rox_ptr;
        hook_chain_rw_t *rw = rox->rw;
        KH_ASSERT(rw != NULL, "faccessat_chain: RW pointer is non-NULL");
        if (rw) {
            KH_ASSERT(rw->sorted_count == 3, "faccessat_chain: sorted_count == 3");

            /* Verify descending priority order in sorted_indices */
            int32_t p0 = rw->items[rw->sorted_indices[0]].priority;
            int32_t p1 = rw->items[rw->sorted_indices[1]].priority;
            int32_t p2 = rw->items[rw->sorted_indices[2]].priority;
            KH_ASSERT(p0 >= p1 && p1 >= p2,
                      "faccessat_chain: priorities sorted descending (10 >= 5 >= 1)");
            KH_ASSERT(p0 == 10, "faccessat_chain: highest priority is 10");
            KH_ASSERT(p2 == 1, "faccessat_chain: lowest priority is 1");
        }
    }

    /* Remove all 3 callbacks */
    hook_unwrap_remove((void *)func_addr, (void *)sys_before_cb_4arg,
                       (void *)sys_after_cb_4arg, 0);
    hook_unwrap_remove((void *)func_addr, (void *)sys_before_cb_4arg_B,
                       (void *)sys_after_cb_4arg_B, 0);
    hook_unwrap_remove((void *)func_addr, (void *)sys_before_cb_4arg_C,
                       (void *)sys_after_cb_4arg_C, 1);

    /* Verify cleanup */
    rox_ptr = hook_mem_get_rox_from_origin(func_addr);
    KH_ASSERT(rox_ptr == NULL, "faccessat_chain: ROX is NULL after full cleanup");
}

/* ================================================================
 * Test 13: test_filp_open_skip_origin
 *
 * Resolve do_filp_open (argno=4). Verify hook_wrap succeeds and
 * the skip_origin callback is correctly wired into the chain.
 * ================================================================ */

void test_filp_open_skip_origin(void)
{
    uint64_t func_addr;
    hook_err_t err;
    void *rox_ptr;

    func_addr = ksyms_lookup("do_filp_open");
    if (!func_addr) {
        KH_SKIP("filp_open_skip: do_filp_open not found via ksyms_lookup");
        return;
    }

    err = hook_wrap((void *)func_addr, 4,
                    (void *)sys_skip_before_cb_4arg, NULL, NULL, 0);
    KH_ASSERT(err == HOOK_NO_ERR, "filp_open_skip: hook_wrap installs without error");

    /* Verify hook structures */
    rox_ptr = hook_mem_get_rox_from_origin(func_addr);
    KH_ASSERT(rox_ptr != NULL, "filp_open_skip: ROX pointer exists");

    if (rox_ptr) {
        hook_chain_rox_t *rox = (hook_chain_rox_t *)rox_ptr;
        hook_chain_rw_t *rw = rox->rw;
        KH_ASSERT(rw != NULL, "filp_open_skip: RW pointer is non-NULL");
        if (rw) {
            KH_ASSERT(rw->sorted_count == 1, "filp_open_skip: sorted_count == 1");
            /* Verify the before callback is our skip function */
            int idx = rw->sorted_indices[0];
            KH_ASSERT(rw->items[idx].before == (void *)sys_skip_before_cb_4arg,
                      "filp_open_skip: before callback is sys_skip_before_cb_4arg");
            KH_ASSERT(rw->items[idx].after == NULL,
                      "filp_open_skip: after callback is NULL");
        }
    }

    hook_unwrap_remove((void *)func_addr, (void *)sys_skip_before_cb_4arg, NULL, 1);

    rox_ptr = hook_mem_get_rox_from_origin(func_addr);
    KH_ASSERT(rox_ptr == NULL, "filp_open_skip: ROX is NULL after cleanup");
}

/* ================================================================
 * Test 14: test_vfs_read_write_hook
 *
 * Resolve vfs_read and vfs_write. Verify hook installation on both
 * and dynamic add/remove of chain items.
 * ================================================================ */

/* Additional named callbacks for vfs tests */
static void vfs_before_cb_A(hook_fargs4_t *args, void *udata)
{
    (void)args;
    (void)udata;
}

static void vfs_after_cb_A(hook_fargs4_t *args, void *udata)
{
    (void)args;
    (void)udata;
}

static void vfs_before_cb_B(hook_fargs4_t *args, void *udata)
{
    (void)args;
    (void)udata;
}

static void vfs_after_cb_B(hook_fargs4_t *args, void *udata)
{
    (void)args;
    (void)udata;
}

static void vfs_before_cb_C(hook_fargs4_t *args, void *udata)
{
    (void)args;
    (void)udata;
}

static void vfs_after_cb_C(hook_fargs4_t *args, void *udata)
{
    (void)args;
    (void)udata;
}

void test_vfs_read_write_hook(void)
{
    uint64_t vfs_read_addr, vfs_write_addr;
    hook_err_t err;
    void *rox_ptr;

    vfs_read_addr = ksyms_lookup("vfs_read");
    vfs_write_addr = ksyms_lookup("vfs_write");

    if (!vfs_read_addr || !vfs_write_addr) {
        KH_SKIP("vfs_rw: vfs_read or vfs_write not found via ksyms_lookup");
        return;
    }

#ifdef KMOD_FREESTANDING
    /* Skip vfs_read/vfs_write hooking in freestanding/device mode: these
     * functions are called concurrently by every process on the system.
     * A concurrent call during hook installation triggers an Oops inside
     * rcu_note_context_switch which corrupts RCU state and causes
     * subsequent synchronize_rcu() calls to hang indefinitely, blocking
     * module init forever and eventually triggering the hardware watchdog. */
    KH_SKIP("vfs_rw: skipped in freestanding mode (concurrent-call RCU hazard on live system)");
    return;
#endif

    /* Install hooks on both vfs_read and vfs_write */
    err = hook_wrap((void *)vfs_read_addr, 4,
                    (void *)vfs_before_cb_A, (void *)vfs_after_cb_A, NULL, 0);
    KH_ASSERT(err == HOOK_NO_ERR, "vfs_rw: vfs_read hook installs OK");

    err = hook_wrap((void *)vfs_write_addr, 4,
                    (void *)vfs_before_cb_B, (void *)vfs_after_cb_B, NULL, 0);
    KH_ASSERT(err == HOOK_NO_ERR, "vfs_rw: vfs_write hook installs OK");

    /* Verify both have ROX entries */
    rox_ptr = hook_mem_get_rox_from_origin(vfs_read_addr);
    KH_ASSERT(rox_ptr != NULL, "vfs_rw: vfs_read ROX exists");
    rox_ptr = hook_mem_get_rox_from_origin(vfs_write_addr);
    KH_ASSERT(rox_ptr != NULL, "vfs_rw: vfs_write ROX exists");

    /* Dynamic add: add 2nd callback to vfs_read */
    err = hook_wrap((void *)vfs_read_addr, 4,
                    (void *)vfs_before_cb_C, (void *)vfs_after_cb_C, NULL, 5);
    KH_ASSERT(err == HOOK_NO_ERR, "vfs_rw: vfs_read 2nd callback installs OK");

    rox_ptr = hook_mem_get_rox_from_origin(vfs_read_addr);
    if (rox_ptr) {
        hook_chain_rw_t *rw = ((hook_chain_rox_t *)rox_ptr)->rw;
        KH_ASSERT(rw && rw->sorted_count == 2,
                  "vfs_rw: vfs_read sorted_count == 2 after add");
    }

    /* Dynamic remove: remove 1st callback from vfs_read */
    hook_unwrap_remove((void *)vfs_read_addr, (void *)vfs_before_cb_A,
                       (void *)vfs_after_cb_A, 0);

    rox_ptr = hook_mem_get_rox_from_origin(vfs_read_addr);
    if (rox_ptr) {
        hook_chain_rw_t *rw = ((hook_chain_rox_t *)rox_ptr)->rw;
        KH_ASSERT(rw && rw->sorted_count == 1,
                  "vfs_rw: vfs_read sorted_count == 1 after remove");
    }

    /* Full cleanup */
    hook_unwrap_remove((void *)vfs_read_addr, (void *)vfs_before_cb_C,
                       (void *)vfs_after_cb_C, 1);
    hook_unwrap_remove((void *)vfs_write_addr, (void *)vfs_before_cb_B,
                       (void *)vfs_after_cb_B, 1);

    rox_ptr = hook_mem_get_rox_from_origin(vfs_read_addr);
    KH_ASSERT(rox_ptr == NULL, "vfs_rw: vfs_read ROX is NULL after cleanup");
    rox_ptr = hook_mem_get_rox_from_origin(vfs_write_addr);
    KH_ASSERT(rox_ptr == NULL, "vfs_rw: vfs_write ROX is NULL after cleanup");
}

/* ================================================================
 * Test 15: test_dynamic_add_remove
 *
 * Using do_faccessat (or any resolved function), exercise the full
 * dynamic add/remove lifecycle: install 2, add 3rd, verify count,
 * remove 1st, verify count, remove remaining, verify empty.
 * ================================================================ */

/* Named callbacks for dynamic add/remove test */
static void dyn_before_cb_A(hook_fargs4_t *args, void *udata)
{
    (void)args;
    (void)udata;
}

static void dyn_after_cb_A(hook_fargs4_t *args, void *udata)
{
    (void)args;
    (void)udata;
}

static void dyn_before_cb_B(hook_fargs4_t *args, void *udata)
{
    (void)args;
    (void)udata;
}

static void dyn_after_cb_B(hook_fargs4_t *args, void *udata)
{
    (void)args;
    (void)udata;
}

static void dyn_before_cb_C(hook_fargs4_t *args, void *udata)
{
    (void)args;
    (void)udata;
}

static void dyn_after_cb_C(hook_fargs4_t *args, void *udata)
{
    (void)args;
    (void)udata;
}

void test_dynamic_add_remove(void)
{
    uint64_t func_addr;
    hook_err_t err;
    void *rox_ptr;
    hook_chain_rw_t *rw;

    func_addr = ksyms_lookup("do_faccessat");
    if (!func_addr) {
        KH_SKIP("dyn_add_remove: do_faccessat not found via ksyms_lookup");
        return;
    }

    /* Step 1: Install 2 callbacks */
    err = hook_wrap((void *)func_addr, 4,
                    (void *)dyn_before_cb_A, (void *)dyn_after_cb_A,
                    NULL, 1);
    KH_ASSERT(err == HOOK_NO_ERR, "dyn_add_remove: 1st callback installs OK");

    err = hook_wrap((void *)func_addr, 4,
                    (void *)dyn_before_cb_B, (void *)dyn_after_cb_B,
                    NULL, 2);
    KH_ASSERT(err == HOOK_NO_ERR, "dyn_add_remove: 2nd callback installs OK");

    /* Step 2: Verify sorted_count == 2 */
    rox_ptr = hook_mem_get_rox_from_origin(func_addr);
    KH_ASSERT(rox_ptr != NULL, "dyn_add_remove: ROX exists after 2 installs");
    if (rox_ptr) {
        rw = ((hook_chain_rox_t *)rox_ptr)->rw;
        KH_ASSERT(rw && rw->sorted_count == 2,
                  "dyn_add_remove: sorted_count == 2");
    }

    /* Step 3: Add 3rd callback */
    err = hook_wrap((void *)func_addr, 4,
                    (void *)dyn_before_cb_C, (void *)dyn_after_cb_C,
                    NULL, 3);
    KH_ASSERT(err == HOOK_NO_ERR, "dyn_add_remove: 3rd callback installs OK");

    /* Step 4: Verify sorted_count == 3 */
    rox_ptr = hook_mem_get_rox_from_origin(func_addr);
    if (rox_ptr) {
        rw = ((hook_chain_rox_t *)rox_ptr)->rw;
        KH_ASSERT(rw && rw->sorted_count == 3,
                  "dyn_add_remove: sorted_count == 3 after add");
    }

    /* Step 5: Remove 1st callback */
    hook_unwrap_remove((void *)func_addr, (void *)dyn_before_cb_A,
                       (void *)dyn_after_cb_A, 0);

    /* Step 6: Verify sorted_count == 2 */
    rox_ptr = hook_mem_get_rox_from_origin(func_addr);
    if (rox_ptr) {
        rw = ((hook_chain_rox_t *)rox_ptr)->rw;
        KH_ASSERT(rw && rw->sorted_count == 2,
                  "dyn_add_remove: sorted_count == 2 after remove");
    }

    /* Step 7: Remove remaining callbacks */
    hook_unwrap_remove((void *)func_addr, (void *)dyn_before_cb_B,
                       (void *)dyn_after_cb_B, 0);
    hook_unwrap_remove((void *)func_addr, (void *)dyn_before_cb_C,
                       (void *)dyn_after_cb_C, 1);

    /* Step 8: Verify empty */
    rox_ptr = hook_mem_get_rox_from_origin(func_addr);
    KH_ASSERT(rox_ptr == NULL, "dyn_add_remove: ROX is NULL after full cleanup");
}

/* ================================================================
 * Phase 5c: Stress tests
 *
 * Pure stress tests that exercise hook chain fill/drain and rapid
 * hook/unhook cycles. No concurrency — always available.
 * ================================================================ */

/* ---- Distinct before/after callbacks for chain fill stress test ----
 * We need HOOK_CHAIN_NUM (8) distinct pairs so each slot gets a unique
 * function pointer. Slot 0 is used by the initial hook_wrap; slots 1..7
 * are filled via hook_chain_add.
 */

#define STRESS_CB(N)                                                      \
    static void stress_before_##N(hook_fargs4_t *args, void *udata)       \
    { (void)args; (void)udata; }                                          \
    static void stress_after_##N(hook_fargs4_t *args, void *udata)        \
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
typedef void (*stress_cb_t)(hook_fargs4_t *, void *);

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
    hook_err_t err;
    void *rox_ptr;
    hook_chain_rox_t *rox;
    hook_chain_rw_t *rw;
    int i, iter;
    int failed = 0;

    func_addr = ksyms_lookup("do_faccessat");
    if (!func_addr) {
        KH_SKIP("stress_fill_drain: do_faccessat not found via ksyms_lookup");
        return;
    }

    /* Initial hook — occupies slot 0 with stress_before_0/stress_after_0 */
    err = hook_wrap((void *)func_addr, 4,
                    (void *)stress_befores[0], (void *)stress_afters[0], NULL, 0);
    KH_ASSERT(err == HOOK_NO_ERR, "stress_fill_drain: initial hook_wrap OK");
    if (err != HOOK_NO_ERR)
        return;

    rox_ptr = hook_mem_get_rox_from_origin(func_addr);
    KH_ASSERT(rox_ptr != NULL, "stress_fill_drain: ROX exists after initial wrap");
    if (!rox_ptr)
        return;

    rox = (hook_chain_rox_t *)rox_ptr;
    rw = rox->rw;
    KH_ASSERT(rw != NULL, "stress_fill_drain: RW is non-NULL");
    if (!rw)
        return;

    for (iter = 0; iter < 1000; iter++) {
        /* Fill remaining HOOK_CHAIN_NUM - 1 slots (indices 1..7) */
        for (i = 1; i < HOOK_CHAIN_NUM; i++) {
            err = hook_chain_add(rw, (void *)stress_befores[i],
                                 (void *)stress_afters[i], NULL, i);
            if (err != HOOK_NO_ERR) {
                pr_err(KH_TEST_TAG
                       "FAIL: stress_fill_drain: hook_chain_add failed at "
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
            hook_chain_remove(rw, (void *)stress_befores[i],
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

    /* Final cleanup: remove the initial hook */
    hook_unwrap_remove((void *)func_addr, (void *)stress_befores[0],
                       (void *)stress_afters[0], 1);

    rox_ptr = hook_mem_get_rox_from_origin(func_addr);
    KH_ASSERT(rox_ptr == NULL, "stress_fill_drain: ROX is NULL after full cleanup");
}

/* ================================================================
 * test_stress_rapid_hook_unhook — hook_wrap then hook_unwrap_remove
 * 1000 times on the same function. Verify no memory leak (ROX/RW
 * properly recycled).
 * ================================================================ */

static void rapid_before_cb(hook_fargs4_t *args, void *udata)
{
    (void)args;
    (void)udata;
}

static void rapid_after_cb(hook_fargs4_t *args, void *udata)
{
    (void)args;
    (void)udata;
}

void test_stress_rapid_hook_unhook(void)
{
    uint64_t func_addr;
    hook_err_t err;
    void *rox_ptr;
    int i;
    int failed = 0;

    func_addr = ksyms_lookup("do_faccessat");
    if (!func_addr) {
        KH_SKIP("stress_rapid: do_faccessat not found via ksyms_lookup");
        return;
    }

    for (i = 0; i < 1000; i++) {
        err = hook_wrap((void *)func_addr, 4,
                        (void *)rapid_before_cb, (void *)rapid_after_cb, NULL, 0);
        if (err != HOOK_NO_ERR) {
            pr_err(KH_TEST_TAG
                   "FAIL: stress_rapid: hook_wrap failed at iter=%d err=%d\n",
                   i, err);
            failed = 1;
            break;
        }

        rox_ptr = hook_mem_get_rox_from_origin(func_addr);
        if (!rox_ptr) {
            pr_err(KH_TEST_TAG
                   "FAIL: stress_rapid: ROX is NULL after hook_wrap at iter=%d\n",
                   i);
            failed = 1;
            break;
        }

        hook_unwrap_remove((void *)func_addr, (void *)rapid_before_cb,
                           (void *)rapid_after_cb, 1);

        rox_ptr = hook_mem_get_rox_from_origin(func_addr);
        if (rox_ptr) {
            pr_err(KH_TEST_TAG
                   "FAIL: stress_rapid: ROX not NULL after unwrap at iter=%d\n",
                   i);
            failed = 1;
            break;
        }
    }

    KH_ASSERT(!failed, "stress_rapid: 1000 hook/unhook cycles clean");
}

/* ================================================================
 * Phase 5d: Concurrency tests
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

#define CONC_NUM_THREADS 4
#define CONC_ITERS_PER_THREAD 1000

/* Per-thread distinct before/after callbacks (need unique pointers) */
#define CONC_CB(N)                                                         \
    static void conc_before_##N(hook_fargs4_t *args, void *udata)          \
    { (void)args; (void)udata; }                                           \
    static void conc_after_##N(hook_fargs4_t *args, void *udata)           \
    { (void)args; (void)udata; }

CONC_CB(0)
CONC_CB(1)
CONC_CB(2)
CONC_CB(3)

static stress_cb_t conc_befores[CONC_NUM_THREADS] = {
    conc_before_0, conc_before_1, conc_before_2, conc_before_3,
};

static stress_cb_t conc_afters[CONC_NUM_THREADS] = {
    conc_after_0, conc_after_1, conc_after_2, conc_after_3,
};

struct conc_thread_data {
    hook_chain_rw_t *rw;
    int thread_id;
    int iters_completed;
    int errors;
    volatile int *stop_flag;
};

__attribute__((no_sanitize("kcfi")))
static int conc_thread_fn(void *data)
{
    struct conc_thread_data *td = (struct conc_thread_data *)data;
    hook_err_t err;
    int i;

    for (i = 0; i < CONC_ITERS_PER_THREAD; i++) {
        if (*td->stop_flag)
            break;

        err = hook_chain_add(td->rw,
                             (void *)conc_befores[td->thread_id],
                             (void *)conc_afters[td->thread_id],
                             NULL, td->thread_id);
        if (err != HOOK_NO_ERR && err != HOOK_DUPLICATED &&
            err != HOOK_CHAIN_FULL) {
            td->errors++;
            break;
        }

        /* Let other threads run */
        schedule();

        hook_chain_remove(td->rw,
                          (void *)conc_befores[td->thread_id],
                          (void *)conc_afters[td->thread_id]);

        td->iters_completed++;
    }

    /* kthread_stop() will set kthread_should_stop(), wait for it */
    while (!kthread_should_stop())
        schedule();

    return 0;
}

/* ================================================================
 * test_concurrent_add_remove — multiple kernel threads simultaneously
 * add and remove chain items. Verify no crash and consistent state
 * after.
 *
 * Requires CONFIG_KH_CHAIN_RCU for thread safety.
 * ================================================================ */

/* Initial callback for the base hook_wrap */
static void conc_initial_before(hook_fargs4_t *args, void *udata)
{
    (void)args;
    (void)udata;
}

static void conc_initial_after(hook_fargs4_t *args, void *udata)
{
    (void)args;
    (void)udata;
}

__attribute__((no_sanitize("kcfi")))
void test_concurrent_add_remove(void)
{
    uint64_t func_addr;
    hook_err_t err;
    void *rox_ptr;
    hook_chain_rox_t *rox;
    hook_chain_rw_t *rw;
    struct task_struct *threads[CONC_NUM_THREADS];
    struct conc_thread_data td[CONC_NUM_THREADS];
    volatile int stop_flag = 0;
    int i;
    int all_ok = 1;

    if (resolve_concurrency_syms() < 0) {
        KH_SKIP("concurrent: required kthread/msleep/synchronize_rcu symbols unavailable");
        return;
    }

    func_addr = ksyms_lookup("do_faccessat");
    if (!func_addr) {
        KH_SKIP("concurrent: do_faccessat not found via ksyms_lookup");
        return;
    }

    /* Create the base hook chain */
    err = hook_wrap((void *)func_addr, 4,
                    (void *)conc_initial_before, (void *)conc_initial_after,
                    NULL, 0);
    KH_ASSERT(err == HOOK_NO_ERR, "concurrent: initial hook_wrap OK");
    if (err != HOOK_NO_ERR)
        return;

    rox_ptr = hook_mem_get_rox_from_origin(func_addr);
    if (!rox_ptr) {
        KH_ASSERT(0, "concurrent: ROX exists after initial wrap");
        return;
    }
    rox = (hook_chain_rox_t *)rox_ptr;
    rw = rox->rw;

    /* Initialize thread data and launch threads */
    for (i = 0; i < CONC_NUM_THREADS; i++) {
        td[i].rw = rw;
        td[i].thread_id = i;
        td[i].iters_completed = 0;
        td[i].errors = 0;
        td[i].stop_flag = &stop_flag;
    }

    for (i = 0; i < CONC_NUM_THREADS; i++) {
        threads[i] = kthread_run_fs(conc_thread_fn, &td[i],
                                    "kh_conc_test_%d", i);
        if (IS_ERR(threads[i])) {
            pr_err(KH_TEST_TAG
                   "concurrent: failed to create thread %d\n", i);
            threads[i] = NULL;
            all_ok = 0;
        }
    }

    /* Let threads run for ~2 seconds */
    _msleep(2000);
    stop_flag = 1;

    /* Stop all threads */
    for (i = 0; i < CONC_NUM_THREADS; i++) {
        if (threads[i])
            _kthread_stop(threads[i]);
    }

    /* Check results */
    for (i = 0; i < CONC_NUM_THREADS; i++) {
        if (td[i].errors) {
            pr_err(KH_TEST_TAG
                   "concurrent: thread %d had %d errors in %d iters\n",
                   i, td[i].errors, td[i].iters_completed);
            all_ok = 0;
        } else {
            pr_info(KH_TEST_TAG
                    "concurrent: thread %d completed %d iters OK\n",
                    i, td[i].iters_completed);
        }
    }

    KH_ASSERT(all_ok, "concurrent: all threads completed without errors");

    /* Verify consistent state: only the initial callback should remain */
    KH_ASSERT(rw->sorted_count == 1,
              "concurrent: sorted_count == 1 after all threads stopped");

    /* Cleanup */
    hook_unwrap_remove((void *)func_addr, (void *)conc_initial_before,
                       (void *)conc_initial_after, 1);

    rox_ptr = hook_mem_get_rox_from_origin(func_addr);
    KH_ASSERT(rox_ptr == NULL, "concurrent: ROX is NULL after cleanup");
}

#endif /* CONFIG_KH_CHAIN_RCU && !KH_SDK_MODE */
