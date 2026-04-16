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
 * Part B (behavioral, inline path): when kh_force has forced the inline
 *   path (copy_to_user:inline_ldtr_sttr and copy_from_user:inline_ldtr),
 *   call the inline functions directly with a vmalloc buffer cast to
 *   __user and verify bytes are transferred correctly.
 *
 *   Rationale: in __init context, current is the insmod process running
 *   at EL1. vmalloc pages are EL1-accessible kernel memory. With PAN
 *   disabled (msr pan, #0), sttrb/ldtrb at EL1 with a kernel VA work
 *   correctly — unprivileged instructions at EL1 behave like EL0 with
 *   respect to PAN but still use EL1 page table mappings, so they can
 *   access any kernel-mapped VA. The test verifies the byte-copy loop
 *   and the zero-on-success return value.
 *
 *   If register_ex_table fails (i.e., probe_extable returns ENODATA),
 *   the inline strategies are not reachable via the registry, and the
 *   direct-call behavioral test is also skipped.
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

    /* ---- Part B: behavioral test for inline path ----
     *
     * Check whether register_ex_table succeeded. If it did, the inline
     * strategies are usable and we call them directly (not through the
     * registry, to isolate the asm from resolver caching). */
    {
        int extable_result = -1;
        int erc = kh_strategy_resolve("register_ex_table",
                                      &extable_result, sizeof(extable_result));
        if (erc != 0) {
            pr_info("[test_resolver_copy_user] inline behavioral test SKIPPED"
                    " (register_ex_table rc=%d)\n", erc);
            goto part_b_done;
        }

#define KH_COPY_TEST_SIZE 64
        /* Allocate two kernel buffers. Cast to __user for the inline
         * functions — PAN is cleared inside the asm so EL1 kernel VAs
         * are accessible via sttrb/ldtrb. This is safe in __init context
         * (single-threaded, no concurrent TLBI). */
        unsigned char *src_buf = (unsigned char *)vmalloc(KH_COPY_TEST_SIZE);
        unsigned char *dst_buf = (unsigned char *)vmalloc(KH_COPY_TEST_SIZE);

        if (!src_buf || !dst_buf) {
            pr_warn("[test_resolver_copy_user] vmalloc failed, skipping"
                    " inline behavioral test\n");
            if (src_buf) vfree(src_buf);
            if (dst_buf) vfree(dst_buf);
            goto part_b_done;
        }

        /* Fill src with a recognizable pattern. Zero dst. */
        for (int i = 0; i < KH_COPY_TEST_SIZE; i++)
            src_buf[i] = (unsigned char)(i ^ 0xA5u);
        memset(dst_buf, 0, KH_COPY_TEST_SIZE);

        /* Test kh_inline_copy_to_user: kernel src -> "user" dst.
         * rem == 0 means all bytes were stored. */
        unsigned long rem_to = kh_inline_copy_to_user(
            (void __user *)dst_buf, src_buf, KH_COPY_TEST_SIZE);

        KH_TEST_ASSERT("copy_user",
                       rem_to == 0,
                       "inline_copy_to_user: non-zero bytes not copied");
        KH_TEST_ASSERT("copy_user",
                       memcmp(src_buf, dst_buf, KH_COPY_TEST_SIZE) == 0,
                       "inline_copy_to_user: dest does not match src");

        pr_info("[test_resolver_copy_user] inline_copy_to_user: rem=%lu"
                " pattern_ok=%d\n",
                rem_to,
                (memcmp(src_buf, dst_buf, KH_COPY_TEST_SIZE) == 0));

        /* Test kh_inline_copy_from_user: "user" src -> kernel dst. */
        memset(dst_buf, 0, KH_COPY_TEST_SIZE);

        unsigned long rem_from = kh_inline_copy_from_user(
            dst_buf, (const void __user *)src_buf, KH_COPY_TEST_SIZE);

        KH_TEST_ASSERT("copy_user",
                       rem_from == 0,
                       "inline_copy_from_user: non-zero bytes not copied");
        KH_TEST_ASSERT("copy_user",
                       memcmp(src_buf, dst_buf, KH_COPY_TEST_SIZE) == 0,
                       "inline_copy_from_user: dest does not match src");

        pr_info("[test_resolver_copy_user] inline_copy_from_user: rem=%lu"
                " pattern_ok=%d\n",
                rem_from,
                (memcmp(src_buf, dst_buf, KH_COPY_TEST_SIZE) == 0));

        vfree(src_buf);
        vfree(dst_buf);
#undef KH_COPY_TEST_SIZE
    }
part_b_done:

    KH_TEST_PASS("copy_user");
    return 0;
}
