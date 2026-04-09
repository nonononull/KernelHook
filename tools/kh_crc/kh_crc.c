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
#include <unistd.h>

#define KH_CRC_VERSION "1"

/* ---- Token → ABI class mapping (FROZEN at v1, Contract 4) ---- */

/* Returns the single-character ABI class for a token, or 0 if unknown.
 * v = void, w = 32-bit (word), x = 64-bit (extended word or pointer-sized).
 */
static char abi_class(const char *token)
{
    if (strcmp(token, "void") == 0) return 'v';
    if (strcmp(token, "i32")  == 0) return 'w';
    if (strcmp(token, "u32")  == 0) return 'w';
    if (strcmp(token, "enum") == 0) return 'w';
    if (strcmp(token, "i64")  == 0) return 'x';
    if (strcmp(token, "u64")  == 0) return 'x';
    if (strcmp(token, "uptr") == 0) return 'x';
    if (strcmp(token, "ptr")  == 0) return 'x';
    if (strcmp(token, "pptr") == 0) return 'x';
    return 0;
}

/* Write the canonical CRC input string for a symbol into `out`.
 *   "<name>(<arg_classes>)-><ret_class>"
 * Example: "hook_wrap(x,w,x,x,x,w)->w"
 * Returns 0 on success, -1 on any invalid token or buffer overflow.
 *
 * Buffer accounting: each write to `out` is checked for both the
 * error return and full truncation before `pos` is advanced. Truncation
 * is treated as a hard error so Contract 4 (algorithm freeze) cannot
 * silently produce host/libc-dependent output. In practice callers size
 * out generously and truncation never occurs, but the defensive check
 * turns that from an assumption into a verifiable property. */

/* Append a single character safely. Returns 0 on success, -1 on overflow. */
static int canon_putc(char *out, size_t out_size, size_t *pos, char c,
                      const char *name)
{
    if (*pos + 1 >= out_size) {
        fprintf(stderr, "canonicalize: output buffer overflow for '%s'\n", name);
        return -1;
    }
    out[(*pos)++] = c;
    out[*pos] = '\0';
    return 0;
}

/* Append a null-terminated string safely. Returns 0 on success, -1 on overflow. */
static int canon_puts(char *out, size_t out_size, size_t *pos, const char *s,
                      const char *name)
{
    size_t len = strlen(s);
    if (*pos + len >= out_size) {
        fprintf(stderr, "canonicalize: output buffer overflow for '%s'\n", name);
        return -1;
    }
    memcpy(out + *pos, s, len);
    *pos += len;
    out[*pos] = '\0';
    return 0;
}

static int canonicalize(const char *name, const char *ret_tok,
                        char arg_toks[][16], int nargs,
                        char *out, size_t out_size)
{
    char ret_c = abi_class(ret_tok);
    int i;
    size_t pos = 0;

    if (ret_c == 0) {
        fprintf(stderr, "canonicalize: unknown return token '%s' for symbol '%s'\n",
                ret_tok, name);
        return -1;
    }
    if (out_size == 0) return -1;
    out[0] = '\0';

    if (canon_puts(out, out_size, &pos, name, name) != 0) return -1;
    if (canon_putc(out, out_size, &pos, '(', name) != 0) return -1;
    for (i = 0; i < nargs; i++) {
        char c = abi_class(arg_toks[i]);
        if (c == 0) {
            fprintf(stderr, "canonicalize: unknown arg token '%s' in symbol '%s'\n",
                    arg_toks[i], name);
            return -1;
        }
        if (c == 'v') {
            fprintf(stderr, "canonicalize: 'void' is not valid as an argument (symbol '%s')\n",
                    name);
            return -1;
        }
        if (i > 0 && canon_putc(out, out_size, &pos, ',', name) != 0) return -1;
        if (canon_putc(out, out_size, &pos, c, name) != 0) return -1;
    }
    if (canon_puts(out, out_size, &pos, ")->", name) != 0) return -1;
    if (canon_putc(out, out_size, &pos, ret_c, name) != 0) return -1;
    return 0;
}

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

/* ---- Manifest parser ---- */

#define KH_MAX_ARGS    16
#define KH_MAX_NAME    64
#define KH_MAX_TOKEN   16
#define KH_MAX_ENTRIES 128

typedef struct {
    char name[KH_MAX_NAME];
    char ret_tok[KH_MAX_TOKEN];
    char arg_toks[KH_MAX_ARGS][KH_MAX_TOKEN];
    int  nargs;
} kh_entry_t;

/* Strip leading/trailing whitespace in place. Returns pointer into original buffer. */
static char *strip(char *s)
{
    char *end;
    while (*s == ' ' || *s == '\t') s++;
    if (*s == '\0') return s;
    end = s + strlen(s) - 1;
    while (end >= s && (*end == ' ' || *end == '\t' || *end == '\n' || *end == '\r')) {
        *end = '\0';
        if (end == s) break;
        end--;
    }
    return s;
}

/* Parse one non-comment, non-empty line. Returns 0 on success, -1 on parse error. */
static int parse_line(const char *filename, int lineno, char *line, kh_entry_t *out)
{
    char *p, *name, *ret, *args;
    char *colon1, *colon2;

    colon1 = strchr(line, ':');
    if (!colon1) {
        fprintf(stderr, "%s:%d: missing first ':'\n", filename, lineno);
        return -1;
    }
    *colon1 = '\0';
    colon2 = strchr(colon1 + 1, ':');
    if (!colon2) {
        fprintf(stderr, "%s:%d: missing second ':'\n", filename, lineno);
        return -1;
    }
    *colon2 = '\0';

    name = strip(line);
    ret  = strip(colon1 + 1);
    args = strip(colon2 + 1);

    if (*name == '\0' || *ret == '\0') {
        fprintf(stderr, "%s:%d: empty name or return type\n", filename, lineno);
        return -1;
    }
    if (strlen(name) >= KH_MAX_NAME) {
        fprintf(stderr, "%s:%d: name too long: '%s'\n", filename, lineno, name);
        return -1;
    }
    if (strlen(ret) >= KH_MAX_TOKEN) {
        fprintf(stderr, "%s:%d: return token too long: '%s'\n", filename, lineno, ret);
        return -1;
    }

    memset(out, 0, sizeof(*out));
    strncpy(out->name, name, sizeof(out->name) - 1);
    strncpy(out->ret_tok, ret, sizeof(out->ret_tok) - 1);
    out->nargs = 0;

    /* Parse comma-separated arg list.
     *
     * An entirely empty args field (nothing after the second ':') means
     * "no arguments" → nargs=0. This is the ONLY case in which empty is
     * allowed. Once the field is non-empty, every comma-separated slot
     * must contain a non-empty token: malformed forms like "ptr,,i32",
     * "ptr," and ",ptr" are rejected. Silently accepting them would let
     * manifest typos produce a DIFFERENT signature than intended and
     * freeze the wrong CRC forever (Contract 3/4). */
    p = args;
    if (*p != '\0') {
        for (;;) {
            char *comma = strchr(p, ',');
            char *tok;
            if (comma) *comma = '\0';
            tok = strip(p);
            if (*tok == '\0') {
                fprintf(stderr, "%s:%d: empty argument token in arg list\n",
                        filename, lineno);
                return -1;
            }
            if (out->nargs >= KH_MAX_ARGS) {
                fprintf(stderr, "%s:%d: too many args (max %d)\n",
                        filename, lineno, KH_MAX_ARGS);
                return -1;
            }
            if (strlen(tok) >= KH_MAX_TOKEN) {
                fprintf(stderr, "%s:%d: arg token too long: '%s'\n",
                        filename, lineno, tok);
                return -1;
            }
            strncpy(out->arg_toks[out->nargs], tok, KH_MAX_TOKEN - 1);
            out->nargs++;
            if (!comma) break;
            p = comma + 1;
        }
    }
    return 0;
}

/* Parse a whole manifest file. On success fills entries[], sets *nentries, returns 0. */
static int parse_manifest(const char *path, kh_entry_t *entries, int max_entries, int *nentries)
{
    FILE *f = fopen(path, "r");
    char line[1024];
    int lineno = 0;
    int count = 0;

    if (!f) {
        fprintf(stderr, "parse_manifest: cannot open '%s'\n", path);
        return -1;
    }

    while (fgets(line, sizeof(line), f) != NULL) {
        char *s;
        lineno++;
        s = strip(line);
        if (*s == '\0' || *s == '#') continue;
        if (count >= max_entries) {
            fprintf(stderr, "%s:%d: too many entries (max %d)\n",
                    path, lineno, max_entries);
            fclose(f);
            return -1;
        }
        if (parse_line(path, lineno, s, &entries[count]) != 0) {
            fclose(f);
            return -1;
        }
        count++;
    }
    fclose(f);
    *nentries = count;
    return 0;
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
        { "unhook(x)->v",  0x335ffb6au },
    };
    size_t n = sizeof(cases) / sizeof(cases[0]);
    size_t i;
    int failed = 0;
    for (i = 0; i < n; i++) {
        uint32_t got = crc32_string(cases[i].s);
        if (got != cases[i].expected) {
            fprintf(stderr, "FAIL crc32(\"%s\"): got 0x%08x expected 0x%08x\n",
                    cases[i].s, got, cases[i].expected);
            failed++;
        }
    }
    if (failed == 0)
        printf("crc32: OK (%zu cases)\n", n);
    return failed;
}

static int self_test_canonicalize(void)
{
    struct case_t {
        const char *name;
        const char *ret;
        const char *args[8];
        int nargs;
        const char *expected;
    } cases[] = {
        { "unhook",       "void", { "ptr" }, 1, "unhook(x)->v" },
        { "hook_prepare", "enum", { "ptr" }, 1, "hook_prepare(x)->w" },
        { "hook_wrap",    "enum", { "ptr", "i32", "ptr", "ptr", "ptr", "i32" }, 6,
                                       "hook_wrap(x,w,x,x,x,w)->w" },
        { "ksyms_lookup", "u64",  { "ptr" }, 1, "ksyms_lookup(x)->x" },
        { "fp_hook",      "void", { "uptr", "ptr", "pptr" }, 3, "fp_hook(x,x,x)->v" },
    };
    size_t n = sizeof(cases) / sizeof(cases[0]);
    size_t i;
    int failed = 0;
    char buf[256];
    char argtoks[8][16];

    for (i = 0; i < n; i++) {
        int j;
        for (j = 0; j < cases[i].nargs; j++) {
            strncpy(argtoks[j], cases[i].args[j], sizeof(argtoks[j]) - 1);
            argtoks[j][sizeof(argtoks[j]) - 1] = '\0';
        }
        if (canonicalize(cases[i].name, cases[i].ret, argtoks, cases[i].nargs,
                         buf, sizeof(buf)) != 0) {
            fprintf(stderr, "FAIL canonicalize(%s): returned error\n", cases[i].name);
            failed++;
            continue;
        }
        if (strcmp(buf, cases[i].expected) != 0) {
            fprintf(stderr, "FAIL canonicalize(%s): got '%s' expected '%s'\n",
                    cases[i].name, buf, cases[i].expected);
            failed++;
        }
    }
    if (failed == 0)
        printf("canonicalize: OK (%zu cases)\n", n);
    return failed;
}

static int self_test_parser(void)
{
    const char *tmpname = "/tmp/kh_crc_parse_test.txt";
    FILE *f = fopen(tmpname, "w");
    kh_entry_t entries[16];
    int n = 0;
    int failed = 0;
    if (!f) { perror("tmpfile"); return 1; }
    fputs(
        "# comment\n"
        "\n"
        "hook_wrap : enum : ptr, i32, ptr, ptr, ptr, i32\n"
        "unhook    : void : ptr\n"
        "ksyms_lookup:u64:ptr\n"     /* whitespace-robust */
        "no_args : void :\n"          /* empty arg list */
        , f);
    fclose(f);

    if (parse_manifest(tmpname, entries, 16, &n) != 0) {
        fprintf(stderr, "FAIL parse_manifest\n");
        return 1;
    }
    if (n != 4) { fprintf(stderr, "FAIL nentries=%d expected 4\n", n); failed++; }
    if (strcmp(entries[0].name, "hook_wrap") != 0) {
        fprintf(stderr, "FAIL entries[0].name=%s\n", entries[0].name); failed++;
    }
    if (entries[0].nargs != 6) {
        fprintf(stderr, "FAIL entries[0].nargs=%d\n", entries[0].nargs); failed++;
    }
    if (strcmp(entries[0].arg_toks[1], "i32") != 0) {
        fprintf(stderr, "FAIL entries[0].arg_toks[1]=%s\n", entries[0].arg_toks[1]); failed++;
    }
    if (strcmp(entries[1].name, "unhook") != 0) { failed++; }
    if (strcmp(entries[2].name, "ksyms_lookup") != 0) { failed++; }
    if (entries[3].nargs != 0) { failed++; }

    unlink(tmpname);
    if (failed == 0) printf("parser: OK (4 cases)\n");
    return failed;
}

/* ---- Output emitters ---- */

/* Emit a Module.symvers-like text format:
 *   0x<crc>\t<name>\tkernelhook\tEXPORT_SYMBOL\t(none)
 * Consumed by tools/kh_crc/tests/run_tests.sh for golden regression. */
static int emit_symvers(kh_entry_t *entries, int n, FILE *out)
{
    int i;
    char canon[256];
    for (i = 0; i < n; i++) {
        uint32_t crc;
        if (canonicalize(entries[i].name, entries[i].ret_tok,
                         entries[i].arg_toks,
                         entries[i].nargs, canon, sizeof(canon)) != 0)
            return -1;
        crc = crc32_string(canon);
        fprintf(out, "0x%08x\t%s\tkernelhook\tEXPORT_SYMBOL\t(none)\n",
                crc, entries[i].name);
    }
    return 0;
}

/* Emit a C header defining KH_DECLARE_VERSIONS(). Consumer .ko's include
 * this header and invoke the macro to populate __versions. */
static int emit_header(kh_entry_t *entries, int n, FILE *out)
{
    int i;
    char canon[256];
    fprintf(out,
        "/* SPDX-License-Identifier: GPL-2.0-or-later */\n"
        "/* Generated by tools/kh_crc. DO NOT EDIT.\n"
        " * Source: kmod/exports.manifest\n"
        " * Contract 4 (algorithm freeze): CRC values here are stable forever. */\n"
        "#ifndef _KERNELHOOK_KH_SYMVERS_H_\n"
        "#define _KERNELHOOK_KH_SYMVERS_H_\n"
        "\n"
        "/* Relies on _MODVER_ENTRY from kmod/shim/shim.h being in scope. */\n"
        "\n"
        "#define KH_DECLARE_VERSIONS() \\\n");
    for (i = 0; i < n; i++) {
        uint32_t crc;
        if (canonicalize(entries[i].name, entries[i].ret_tok,
                         entries[i].arg_toks,
                         entries[i].nargs, canon, sizeof(canon)) != 0)
            return -1;
        crc = crc32_string(canon);
        fprintf(out,
            "    _MODVER_ENTRY(__modver_kh_%s, 0x%08xu, \"%s\")%s\n",
            entries[i].name, crc, entries[i].name,
            (i == n - 1) ? "" : "; \\");
    }
    fprintf(out,
        "\n"
        "#endif /* _KERNELHOOK_KH_SYMVERS_H_ */\n");
    return 0;
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
        rc |= self_test_canonicalize();
        rc |= self_test_parser();
        return rc ? 1 : 0;
    }

    {
        /* Shared setup for asm/header/symvers modes. */
        kh_entry_t entries[KH_MAX_ENTRIES];
        int n = 0;
        const char *manifest_path = "kmod/exports.manifest";
        const char *output_path = NULL;
        FILE *out;
        int rc;

        for (i = 1; i < argc; i++) {
            if (strncmp(argv[i], "--manifest=", 11) == 0)
                manifest_path = argv[i] + 11;
            else if (strncmp(argv[i], "--output=", 9) == 0)
                output_path = argv[i] + 9;
        }

        if (parse_manifest(manifest_path, entries, KH_MAX_ENTRIES, &n) != 0)
            return 1;

        if (output_path) {
            out = fopen(output_path, "w");
            if (!out) { perror(output_path); return 1; }
        } else {
            out = stdout;
        }

        if (strcmp(mode, "symvers") == 0)      rc = emit_symvers(entries, n, out);
        else if (strcmp(mode, "header") == 0)  rc = emit_header(entries, n, out);
        else if (strcmp(mode, "asm") == 0)     { fprintf(stderr, "--mode=asm implemented in next task\n"); rc = -1; }
        else { fprintf(stderr, "unknown mode: %s\n", mode); rc = -1; }

        if (out != stdout) fclose(out);
        return rc ? 1 : 0;
    }
}
