/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Unit tests for maybe_shrink_this_module_sh_size.
 *
 * The helper takes an unsigned long long* pointing at the Shdr.sh_size
 * field (Elf64_Xword resolves to __u64 == unsigned long long on all
 * target platforms), so tests can fabricate it with no <elf.h>
 * dependency — this file compiles cleanly on macOS with TEST_CC=cc. */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "../patch_this_module.h"

static void test_shrink_applies_when_resolved_smaller(void)
{
    unsigned long long sh_size = 0x800;
    struct kver_preset p = { .mod_size = 0x600,
                             .init_off = 0x188,
                             .exit_off = 0x5b8 };
    int rc = maybe_shrink_this_module_sh_size(&sh_size, &p);
    assert(rc == 1);
    assert(sh_size == 0x600);
    printf("  shrink_applies_when_resolved_smaller: OK\n");
}

static void test_shrink_noop_when_resolved_zero(void)
{
    unsigned long long sh_size = 0x800;
    struct kver_preset p = { .mod_size = 0, .init_off = 0x140, .exit_off = 0x3d8 };
    int rc = maybe_shrink_this_module_sh_size(&sh_size, &p);
    assert(rc == 0);
    assert(sh_size == 0x800);
    printf("  shrink_noop_when_resolved_zero: OK\n");
}

static void test_shrink_noop_when_resolved_larger(void)
{
    unsigned long long sh_size = 0x400;
    struct kver_preset p = { .mod_size = 0x600, .init_off = 0x140, .exit_off = 0x3d8 };
    int rc = maybe_shrink_this_module_sh_size(&sh_size, &p);
    assert(rc == 0);
    assert(sh_size == 0x400);
    printf("  shrink_noop_when_resolved_larger: OK\n");
}

static void test_shrink_refused_when_reloc_would_be_cut(void)
{
    unsigned long long sh_size = 0x800;
    /* init_off 0x200 is past the requested mod_size 0x100 — refuse. */
    struct kver_preset p = { .mod_size = 0x100, .init_off = 0x200, .exit_off = 0x40 };
    int rc = maybe_shrink_this_module_sh_size(&sh_size, &p);
    assert(rc == -1);
    assert(sh_size == 0x800);
    printf("  shrink_refused_when_reloc_would_be_cut: OK\n");
}

static void test_shrink_refused_when_exit_reloc_would_be_cut(void)
{
    unsigned long long sh_size = 0x800;
    /* init_off ok but exit_off past mod_size — refuse. */
    struct kver_preset p = { .mod_size = 0x200, .init_off = 0x40, .exit_off = 0x300 };
    int rc = maybe_shrink_this_module_sh_size(&sh_size, &p);
    assert(rc == -1);
    assert(sh_size == 0x800);
    printf("  shrink_refused_when_exit_reloc_would_be_cut: OK\n");
}

static void test_shrink_allows_exact_fit(void)
{
    /* mod_size just barely covers exit_off + 8 bytes. */
    unsigned long long sh_size = 0x800;
    struct kver_preset p = { .mod_size = 0x600,
                             .init_off = 0x188,
                             .exit_off = 0x5f8 };
    int rc = maybe_shrink_this_module_sh_size(&sh_size, &p);
    assert(rc == 1);
    assert(sh_size == 0x600);
    printf("  shrink_allows_exact_fit: OK\n");
}

static void test_shrink_noop_when_sh_size_equals_mod_size(void)
{
    /* Already correctly sized — no-op path, exercises the <= branch. */
    unsigned long long sh_size = 0x600;
    struct kver_preset p = { .mod_size = 0x600,
                             .init_off = 0x188,
                             .exit_off = 0x5b8 };
    int rc = maybe_shrink_this_module_sh_size(&sh_size, &p);
    assert(rc == 0);
    assert(sh_size == 0x600);
    printf("  shrink_noop_when_sh_size_equals_mod_size: OK\n");
}

static void test_shrink_null_inputs(void)
{
    /* NULL sh_size_ptr or NULL preset — both early-return 0. */
    struct kver_preset p = { .mod_size = 0x600,
                             .init_off = 0x188,
                             .exit_off = 0x5b8 };
    assert(maybe_shrink_this_module_sh_size(NULL, &p) == 0);
    unsigned long long sh_size = 0x800;
    assert(maybe_shrink_this_module_sh_size(&sh_size, NULL) == 0);
    assert(sh_size == 0x800);
    printf("  shrink_null_inputs: OK\n");
}

int main(void)
{
    test_shrink_applies_when_resolved_smaller();
    test_shrink_noop_when_resolved_zero();
    test_shrink_noop_when_resolved_larger();
    test_shrink_refused_when_reloc_would_be_cut();
    test_shrink_refused_when_exit_reloc_would_be_cut();
    test_shrink_allows_exact_fit();
    test_shrink_null_inputs();
    test_shrink_noop_when_sh_size_equals_mod_size();
    printf("patch_this_module_test: OK\n");
    return 0;
}
