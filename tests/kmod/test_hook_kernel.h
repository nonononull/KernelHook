/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef _TEST_HOOK_KERNEL_H_
#define _TEST_HOOK_KERNEL_H_

#include <types.h>
#include <hook.h>

__attribute__((__noinline__)) uint64_t target_zero_args(void);
__attribute__((__noinline__)) uint64_t target_four_args(uint64_t a, uint64_t b, uint64_t c, uint64_t d);

struct hook_test_state {
    int before_called;
    int after_called;
    uint64_t before_arg0;
    uint64_t after_ret;
};

extern struct hook_test_state g_hook_state;
void hook_test_state_reset(void);

void test_inline_hook_basic(void);
void test_hook_wrap_before_after(void);
void test_hook_wrap_skip_origin(void);
void test_hook_wrap_arg_passthrough(void);
void test_hook_uninstall_restore(void);
void test_hook_chain_priority(void);

/* Security mechanism functional tests */
void test_kcfi_hook_and_call(void);
void test_pac_hook_restore(void);
void test_bti_indirect_call(void);
void test_scs_stack_integrity(void);

#endif /* _TEST_HOOK_KERNEL_H_ */
