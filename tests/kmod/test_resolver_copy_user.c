/* tests/kmod/test_resolver_copy_user.c */
/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <types.h>
#include <linux/uaccess.h>
#include "test_resolver_common.h"

/* ---- forward declarations for inline copy fns (defined in uaccess_copy.c) */
extern unsigned long kh_inline_copy_to_user(void __user *to, const void *from,
                                             unsigned long n);
extern unsigned long kh_inline_copy_from_user(void *to, const void __user *from,
                                               unsigned long n);

/* ---- vmalloc shim (freestanding builds have no vmalloc header) ---------- */
#ifdef KMOD_FREESTANDING
extern void *vmalloc(unsigned long size);
extern void  vfree(const void *addr);
#else
#include <linux/vmalloc.h>
#include <linux/string.h>
#endif

/* ---- memcmp shim --------------------------------------------------------
 * In freestanding mode memcmp is provided by kmod/shim/shim_libc.c and
 * declared in kmod/shim/shim.h, which is not included here. Declare it
 * as extern so we can use it without pulling in the whole shim header. */
#ifdef KMOD_FREESTANDING
extern int memcmp(const void *s1, const void *s2, unsigned long n);
extern void *memset(void *s, int c, unsigned long n);
#endif

/* ========================================================================
 * test_resolver_copy_user
 *
 * Part A (resolution): verify copy_to_user and copy_from_user capabilities
 *   resolve to non-NULL function pointers.
 *
 * Part B (fault-path verification): when register_ex_table succeeded, pass
 *   a deliberately-invalid __user pointer (0xdeadbeef) to the inline functions.
 *   The sttrb/ldtrb at that address generates a permission fault; if the
 *   __ex_table was correctly registered with EX_TYPE_UACCESS_ERR_ZERO, the
 *   kernel fault handler jumps to our fixup label, which restores PAN and
 *   returns `rem` (non-zero = bytes not copied). This validates end-to-end:
 *   ex_table section emission, linker script inclusion, kernel module-loader
 *   pickup, EX_TYPE dispatch, fixup PC computation, and PAN restore. It does
 *   NOT attempt a happy-path copy because ldtr/sttr at EL1 apply EL0
 *   permission checks, and vmalloc pages (PAGE_KERNEL, no PTE_USER) are not
 *   accessible via these instructions — that would always fault regardless.
 * ======================================================================== */
int test_resolver_copy_user(void) {
    typedef unsigned long (*to_t)(void __user *, const void *, unsigned long);
    typedef unsigned long (*from_t)(void *, const void __user *, unsigned long);

    to_t   ftu = (to_t)0;
    from_t ffu = (from_t)0;

    /* ---- Part A: resolution ---- */
    int rc1 = kh_strategy_resolve("copy_to_user",   &ftu, sizeof(ftu));
    int rc2 = kh_strategy_resolve("copy_from_user", &ffu, sizeof(ffu));

    KH_TEST_ASSERT("copy_user", rc1 == 0, "copy_to_user unresolved");
    KH_TEST_ASSERT("copy_user", ftu != (to_t)0,
                   "copy_to_user resolved to NULL fn pointer");
    KH_TEST_ASSERT("copy_user", rc2 == 0, "copy_from_user unresolved");
    KH_TEST_ASSERT("copy_user", ffu != (from_t)0,
                   "copy_from_user resolved to NULL fn pointer");

    /* ---- Part B: fault-path test for inline path ----
     *
     * Check whether register_ex_table succeeded. If it did, the ex_table
     * entries are registered and we can validate them by triggering a
     * controlled fault on a deliberately-invalid user pointer. */
    {
        int extable_result = -1;
        int erc = kh_strategy_resolve("register_ex_table",
                                      &extable_result, sizeof(extable_result));
        if (erc != 0) {
            pr_info("[test_resolver_copy_user] inline fault-path test SKIPPED"
                    " (register_ex_table rc=%d)\n", erc);
            goto part_b_done;
        }

#define KH_COPY_TEST_SIZE 64
        /* Kernel-side scratch buffer for copy_from_user destination. */
        unsigned char *kernel_dst = (unsigned char *)vmalloc(KH_COPY_TEST_SIZE);
        unsigned char  kernel_src[KH_COPY_TEST_SIZE];
        for (int i = 0; i < KH_COPY_TEST_SIZE; i++)
            kernel_src[i] = (unsigned char)(i ^ 0xA5u);

        /* Deliberately-bogus user pointer: canonical kernel VA. sttrb /
         * ldtrb from EL1 use EL0 permission checks (AP[1]) and kernel-only
         * pages always have AP[1]=0, so this guarantees a permission fault
         * regardless of the insmod process's userspace mmap layout.
         * (0xdeadbeef would usually fault too but is technically mappable
         * by a sufficiently creative PIE/ASLR layout.) */
        void __user *bad_user = (void __user *)(uintptr_t)0xffff800000000000UL;

        /* Test kh_inline_copy_to_user: fault on sttrb, fixup returns rem > 0. */
        unsigned long rem_to = kh_inline_copy_to_user(
            bad_user, kernel_src, KH_COPY_TEST_SIZE);

        KH_TEST_ASSERT("copy_user",
                       rem_to > 0,
                       "inline_copy_to_user: fixup did not return rem>0 on bad ptr");

        pr_info("[test_resolver_copy_user] inline_copy_to_user fault-path:"
                " rem=%lu (expected >0, fixup fired OK)\n", rem_to);

        /* Test kh_inline_copy_from_user: fault on ldtrb, fixup returns rem > 0. */
        unsigned long rem_from = kh_inline_copy_from_user(
            kernel_dst ? (void *)kernel_dst : (void *)kernel_src,
            (const void __user *)bad_user, KH_COPY_TEST_SIZE);

        KH_TEST_ASSERT("copy_user",
                       rem_from > 0,
                       "inline_copy_from_user: fixup did not return rem>0 on bad ptr");

        pr_info("[test_resolver_copy_user] inline_copy_from_user fault-path:"
                " rem=%lu (expected >0, fixup fired OK)\n", rem_from);

        if (kernel_dst)
            vfree(kernel_dst);
#undef KH_COPY_TEST_SIZE
    }
part_b_done:

    KH_TEST_PASS("copy_user");
    return 0;
}
