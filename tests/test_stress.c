/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Integration tests: stress and edge cases.
 * Hook/unhook cycles, chain exhaustion, concurrency, nested hooks,
 * and branch-prologue hooking.
 */

#include "test_framework.h"
#include <hook.h>
#include <hmem.h>
#include <hook_mem_user.h>
#include <string.h>
#include <pthread.h>

/* ---- Target functions ---- */

/* Padded with nops so each function is >= 16 bytes (the trampoline size). */
__attribute__((noinline))
int stress_target(int a, int b)
{
    asm volatile("nop\n\tnop\n\tnop");
    return a + b;
}

/* Two functions for nested hook test.
 * Padded with nops to ensure each is >= 16 bytes (the trampoline size).
 * Without padding, Release-mode 8-byte functions cause the trampoline
 * to overwrite the adjacent function. */
__attribute__((noinline))
int nested_A(int x)
{
    asm volatile("nop\n\tnop\n\tnop");
    return x + 1;
}

__attribute__((noinline))
int nested_B(int x)
{
    asm volatile("nop\n\tnop\n\tnop");
    return x * 2;
}

/* Function with a branch in its prologue — defined in asm to guarantee
 * the first instruction is a B (branch). */
#ifdef __APPLE__
#define ASM_SYM(x) "_" #x
#else
#define ASM_SYM(x) #x
#endif

asm(
    ".globl " ASM_SYM(branch_prologue_func) "\n"
    ".p2align 2\n"
    ASM_SYM(branch_prologue_func) ":\n"
    "    b 1f\n"
    "    nop\n"
    "1:\n"
    "    mov w0, #77\n"
    "    ret\n"
);
int branch_prologue_func(void);

/* Volatile function pointers prevent the compiler from eliminating calls
 * via interprocedural constant propagation in Release builds. */
static int (*volatile call_stress)(int, int) = stress_target;
static int (*volatile call_nested_A)(int) = nested_A;
static int (*volatile call_nested_B)(int) = nested_B;
static int (*volatile call_branch)(void) = branch_prologue_func;

/* ---- Setup/teardown ---- */

static void hook_setup(void)
{
    int rc = hook_mem_user_init();
    ASSERT_EQ(rc, 0);
}

static void hook_teardown(void)
{
    hook_mem_user_cleanup();
}

/* ---- Dummy callbacks ---- */

static void dummy_before(hook_fargs2_t *fargs, void *udata)
{
    (void)fargs; (void)udata;
}

static void dummy_after(hook_fargs2_t *fargs, void *udata)
{
    (void)fargs; (void)udata;
}

/* ---- Tests ---- */

TEST(stress_hook_unhook_1000)
{
    hook_setup();

    uint32_t rox_before = hook_mem_rox_used_blocks();
    uint32_t rw_before = hook_mem_rw_used_blocks();

    for (int i = 0; i < 1000; i++) {
        hook_err_t rc = hook_wrap_pri((void *)stress_target, 2,
                                       (void *)dummy_before, (void *)dummy_after,
                                       NULL, 0);
        ASSERT_EQ(rc, HOOK_NO_ERR);

        /* Verify function still works while hooked */
        int result = call_stress(i, 1);
        ASSERT_EQ(result, i + 1);

        hook_unwrap((void *)stress_target,
                    (void *)dummy_before, (void *)dummy_after);
    }

    /* Verify no memory leak */
    ASSERT_EQ(hook_mem_rox_used_blocks(), rox_before);
    ASSERT_EQ(hook_mem_rw_used_blocks(), rw_before);

    hook_teardown();
}

TEST(stress_fill_chain_slots)
{
    hook_setup();

    /* Use distinct callback addresses for each slot */
    void *befores[HOOK_CHAIN_NUM];
    void *afters[HOOK_CHAIN_NUM];

    /* First, install the hook to create the chain */
    hook_err_t rc = hook_wrap_pri((void *)stress_target, 2,
                                   (void *)dummy_before, (void *)dummy_after,
                                   NULL, 0);
    ASSERT_EQ(rc, HOOK_NO_ERR);
    befores[0] = (void *)dummy_before;
    afters[0] = (void *)dummy_after;

    /* Fill remaining slots with unique addresses (use offsets into dummy_before) */
    for (int i = 1; i < HOOK_CHAIN_NUM; i++) {
        void *b = (void *)((uintptr_t)dummy_before + i);
        void *a = (void *)((uintptr_t)dummy_after + i);
        rc = hook_wrap_pri((void *)stress_target, 2, b, a, NULL, i);
        ASSERT_EQ(rc, HOOK_NO_ERR);
        befores[i] = b;
        afters[i] = a;
    }

    /* Next add should fail */
    rc = hook_wrap_pri((void *)stress_target, 2,
                        (void *)((uintptr_t)dummy_before + HOOK_CHAIN_NUM),
                        (void *)((uintptr_t)dummy_after + HOOK_CHAIN_NUM),
                        NULL, 99);
    ASSERT_EQ(rc, HOOK_CHAIN_FULL);

    /* Remove all */
    for (int i = 0; i < HOOK_CHAIN_NUM; i++)
        hook_unwrap((void *)stress_target, befores[i], afters[i]);

    hook_teardown();
}

/* ---- Concurrent invocation test ---- */

/* Simple barrier for portability (macOS lacks pthread_barrier_t) */
static pthread_mutex_t bar_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t bar_cond = PTHREAD_COND_INITIALIZER;
static int bar_count;
static int bar_target;

static void bar_init(int n)
{
    bar_count = 0;
    bar_target = n;
}

static void bar_wait(void)
{
    pthread_mutex_lock(&bar_mutex);
    bar_count++;
    if (bar_count >= bar_target)
        pthread_cond_broadcast(&bar_cond);
    else
        while (bar_count < bar_target)
            pthread_cond_wait(&bar_cond, &bar_mutex);
    pthread_mutex_unlock(&bar_mutex);
}

struct thread_data {
    int thread_id;
    int iterations;
    int success;
};

static void before_local_set(hook_fargs2_t *fargs, void *udata)
{
    (void)udata;
    /* Store thread-specific data in local storage */
    fargs->local->data0 = (uint64_t)fargs->arg0;
}

static void *thread_func(void *arg)
{
    struct thread_data *td = (struct thread_data *)arg;
    td->success = 1;

    bar_wait();

    for (int i = 0; i < td->iterations; i++) {
        /* Each thread passes its thread_id as arg0 */
        int result = call_stress(td->thread_id, i);
        if (result != td->thread_id + i)
            td->success = 0;
    }

    return NULL;
}

TEST(stress_concurrent_4threads)
{
    hook_setup();

    hook_err_t rc = hook_wrap_pri((void *)stress_target, 2,
                                   (void *)before_local_set,
                                   NULL, NULL, 0);
    ASSERT_EQ(rc, HOOK_NO_ERR);

    #define NUM_THREADS 4
    #define ITERATIONS 500

    bar_init(NUM_THREADS);

    pthread_t threads[NUM_THREADS];
    struct thread_data tdata[NUM_THREADS];

    for (int i = 0; i < NUM_THREADS; i++) {
        tdata[i].thread_id = (i + 1) * 1000;
        tdata[i].iterations = ITERATIONS;
        tdata[i].success = 0;
        pthread_create(&threads[i], NULL, thread_func, &tdata[i]);
    }

    for (int i = 0; i < NUM_THREADS; i++)
        pthread_join(threads[i], NULL);


    /* Verify all threads completed successfully */
    for (int i = 0; i < NUM_THREADS; i++)
        ASSERT_TRUE(tdata[i].success);

    hook_unwrap((void *)stress_target,
                (void *)before_local_set, NULL);
    hook_teardown();
}

/* ---- Nested hooks test ---- */

static int nested_A_hooked;
static int nested_B_hooked;

static void before_nested_A(hook_fargs1_t *fargs, void *udata)
{
    (void)udata;
    nested_A_hooked = 1;
    /* Call nested_B from inside A's before callback */
    int b_result = call_nested_B((int)fargs->arg0);
    /* Store B's result for verification */
    fargs->local->data0 = (uint64_t)b_result;
}

static void before_nested_B(hook_fargs1_t *fargs, void *udata)
{
    (void)fargs; (void)udata;
    nested_B_hooked = 1;
}

TEST(stress_nested_hooks)
{
    hook_setup();
    nested_A_hooked = 0;
    nested_B_hooked = 0;

    /* Hook both functions */
    hook_err_t rc;
    rc = hook_wrap_pri((void *)nested_A, 1,
                        (void *)before_nested_A, NULL, NULL, 0);
    ASSERT_EQ(rc, HOOK_NO_ERR);

    rc = hook_wrap_pri((void *)nested_B, 1,
                        (void *)before_nested_B, NULL, NULL, 0);
    ASSERT_EQ(rc, HOOK_NO_ERR);

    int result = call_nested_A(5);

    /* nested_A should return 5+1 = 6 */
    ASSERT_EQ(result, 6);
    /* Both hooks should have fired */
    ASSERT_TRUE(nested_A_hooked);
    ASSERT_TRUE(nested_B_hooked);

    hook_unwrap((void *)nested_A, (void *)before_nested_A, NULL);
    hook_unwrap((void *)nested_B, (void *)before_nested_B, NULL);
    hook_teardown();
}

/* ---- Branch prologue test ---- */

static int branch_prologue_hooked;

static void before_branch_prologue(hook_fargs0_t *fargs, void *udata)
{
    (void)fargs; (void)udata;
    branch_prologue_hooked = 1;
}

TEST(stress_branch_prologue)
{
    hook_setup();
    branch_prologue_hooked = 0;

    /* Verify the function works before hooking */
    int orig = call_branch();
    ASSERT_EQ(orig, 77);

    hook_err_t rc = hook_wrap_pri((void *)branch_prologue_func, 0,
                                   (void *)before_branch_prologue, NULL,
                                   NULL, 0);
    ASSERT_EQ(rc, HOOK_NO_ERR);

    int result = call_branch();
    ASSERT_EQ(result, 77);
    ASSERT_TRUE(branch_prologue_hooked);

    hook_unwrap((void *)branch_prologue_func,
                (void *)before_branch_prologue, NULL);

    /* Verify function works after unhooking */
    int post = call_branch();
    ASSERT_EQ(post, 77);

    hook_teardown();
}

int main(void)
{
    return RUN_ALL_TESTS();
}
