/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Page-alignment sentinels to isolate library .text.
 *
 * On macOS (ld64), these are placed at the head and tail of library code
 * via -order_file.  On GNU ld, the linker script handles isolation, but
 * the sentinels still provide __kh_text_fence_head/tail symbols for
 * verification in tests.
 */

#include "kh_page_align.h"

__attribute__((used, aligned(KH_PAGE_ALIGN), noinline))
void __kh_text_fence_head(void)
{
    asm volatile("");
}

__attribute__((used, aligned(KH_PAGE_ALIGN), noinline))
void __kh_text_fence_tail(void)
{
    asm volatile("");
}
