/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * kh_crc — KernelHook freestanding EXPORT_SYMBOL CRC generator.
 *
 * Reads kmod/exports.manifest, emits one of:
 *   --mode=asm       → assembly populating __ksymtab_*\/__kcrctab_*
 *   --mode=header    → C header with KH_DECLARE_VERSIONS() macro
 *   --mode=symvers   → Module.symvers-compatible text
 *   --mode=self-test → run internal unit tests and exit
 *
 * Design: see docs/superpowers/specs/2026-04-09-freestanding-export-symbol-and-runtime-loader-design.md §6.3
 * Contracts 1-5: the CRC algorithm is FROZEN at v1. Do not change canonicalize()
 * or the CRC32 parameters without creating kh_crc_v2.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define KH_CRC_VERSION "1"

/* ---- CRC32 (IEEE 802.3, reflected, poly 0xedb88320, init ~0, xorout ~0) ----
 * Identical output to Python's binascii.crc32 and zlib.crc32.
 * FROZEN at v1 (Contract 4). Do not modify. */

static uint32_t crc32_table[256];
static int crc32_table_init_done = 0;

static void crc32_init(void)
{
    uint32_t i, j, c;
    if (crc32_table_init_done) return;
    for (i = 0; i < 256; i++) {
        c = i;
        for (j = 0; j < 8; j++)
            c = (c & 1) ? (0xedb88320u ^ (c >> 1)) : (c >> 1);
        crc32_table[i] = c;
    }
    crc32_table_init_done = 1;
}

static uint32_t crc32_bytes(const unsigned char *data, size_t len)
{
    uint32_t c = 0xffffffffu;
    size_t i;
    crc32_init();
    for (i = 0; i < len; i++)
        c = crc32_table[(c ^ data[i]) & 0xff] ^ (c >> 8);
    return c ^ 0xffffffffu;
}

static uint32_t crc32_string(const char *s)
{
    return crc32_bytes((const unsigned char *)s, strlen(s));
}

static void usage(const char *argv0)
{
    fprintf(stderr,
        "Usage: %s --mode=<asm|header|symvers|self-test> "
        "[--manifest=<path>] [--output=<path>]\n",
        argv0);
    exit(2);
}

static int self_test_crc32(void)
{
    /* Known CRC32/IEEE values — cross-checked with python -c "import binascii; print(hex(binascii.crc32(b'...')))" */
    struct { const char *s; uint32_t expected; } cases[] = {
        { "",              0x00000000u },
        { "a",             0xe8b7be43u },
        { "abc",           0x352441c2u },
        { "hello world",   0x0d4a1185u },
        { "unhook(x)->v",  0u },  /* computed in Task 6, placeholder now */
    };
    size_t n = sizeof(cases) / sizeof(cases[0]);
    size_t i;
    int failed = 0;
    for (i = 0; i < n - 1; i++) {   /* skip last entry (placeholder) */
        uint32_t got = crc32_string(cases[i].s);
        if (got != cases[i].expected) {
            fprintf(stderr, "FAIL crc32(\"%s\"): got 0x%08x expected 0x%08x\n",
                    cases[i].s, got, cases[i].expected);
            failed++;
        }
    }
    if (failed == 0)
        printf("crc32: OK (%zu cases)\n", n - 1);
    return failed;
}

int main(int argc, char **argv)
{
    int i;
    const char *mode = NULL;
    for (i = 1; i < argc; i++) {
        if (strncmp(argv[i], "--mode=", 7) == 0) mode = argv[i] + 7;
    }
    if (!mode) usage(argv[0]);
    if (strcmp(mode, "self-test") == 0) {
        int rc = 0;
        rc |= self_test_crc32();
        return rc ? 1 : 0;
    }
    fprintf(stderr, "unknown mode: %s\n", mode);
    return 2;
}
