// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Adaptive kernel module loader for KernelHook freestanding .ko modules.
 *
 * Dynamically patches the module binary before loading to adapt to the
 * running kernel's struct module layout, symbol CRCs, and vermagic.
 *
 * Patches applied:
 *   1. .gnu.linkonce.this_module section size → sizeof(struct module)
 *   2. init/exit relocation offsets in .rela.gnu.linkonce.this_module
 *   3. __versions CRC values (extracted from kernel Image)
 *   4. .modinfo vermagic string
 *
 * Usage: kmod_loader <module.ko> [param=value ...]
 */

#include "resolver.h"

#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/utsname.h>
#include <dirent.h>
#include <unistd.h>

#ifndef __NR_finit_module
#define __NR_finit_module 273
#endif
#ifndef __NR_init_module
#define __NR_init_module 105
#endif

#define MODULE_INIT_IGNORE_MODVERSIONS 1
#define MODULE_INIT_IGNORE_VERMAGIC    2

/* ---- Kernel version presets ----
 *
 * Struct module layout for GKI ARM64 kernels. Derived from AOSP source.
 * Fields: major, minor, sizeof(struct module), offsetof(init), offsetof(exit).
 */
struct kver_preset {
    int major, minor;
    uint32_t mod_size;
    uint32_t init_off;
    uint32_t exit_off;
};

/* ARM64 kernel struct module layout presets.
 * 4.x: pre-GKI, computed from AOSP source (unverified).
 * 5.x+: GKI with ANDROID_KABI_RESERVE=y, ANDROID_VENDOR_OEM_DATA=y. */
static const struct kver_preset presets[] = {
    /* Linux 4.x — pre-GKI, no ANDROID_KABI_RESERVE on most builds.
     * Offsets computed from AOSP source; unverified on real devices. */
    { 4, 4,  0x340, 0x158, 0x2d0 },  /* AVD android-28 verified */
    { 4, 9,  0x358, 0x150, 0x2e8 },
    { 4, 14, 0x370, 0x150, 0x2f8 },  /* AVD android-29, init verified via disasm */
    { 4, 19, 0x390, 0x168, 0x318 },
    /* Linux 5.x — ANDROID_KABI_RESERVE inflates struct module */
    { 5, 4,  0x400, 0x178, 0x340 },  /* AVD android-30 verified (exit was 0x350→0x340) */
    { 5, 10, 0x440, 0x190, 0x3c8 },  /* AVD android12-5.10 verified */
    { 5, 15, 0x3c0, 0x178, 0x378 },  /* AVD android13-5.15 verified */
    /* Linux 6.x — kCFI replaces shadow CFI */
    { 6, 1,  0x400, 0x140, 0x3d8 },  /* AVD android14-6.1 verified */
    { 6, 6,  0x600, 0x188, 0x5b8 },  /* AVD android15-6.6 verified */
    { 6, 12, 0x640, 0x188, 0x5f8 },  /* AVD API 37 (16K pages) verified */
};
#define NUM_PRESETS (sizeof(presets) / sizeof(presets[0]))

/* ---- Persistent probe state ----
 *
 * Stored in a dedicated ELF section of the kmod_loader binary itself.
 * Read as a normal variable; written back via pwrite(open(argv[0])).
 * Survives reboots (crash recovery) without external files. */

#define PROBE_MAGIC 0x4B4D5052  /* "KMPR" */
#define PROBE_IDLE  0xFF

struct probe_state {
    uint32_t magic;
    uint32_t version_hash;
    uint32_t found_init;
    uint32_t found_exit;
    uint32_t confirmed;
    uint32_t tried_mask;
    uint32_t crash_mask;
    uint32_t probing_idx;
};

/* Non-zero init keeps this in .data (not .bss) so probe_persist() can
 * pwrite to its file offset. probing_idx = PROBE_IDLE = no probe in progress. */
static struct probe_state g_probe __attribute__((aligned(8))) = {
    .probing_idx = PROBE_IDLE
};

static uint32_t hash_version(const char *release)
{
    uint32_t h = 5381;
    while (*release)
        h = h * 33 + (unsigned char)*release++;
    return h;
}

/* Persist g_probe to a companion file next to the kmod_loader binary.
 * Writing to self fails with ETXTBSY on Linux (text file busy). */
static int probe_persist(const char *self_path)
{
    /* Derive companion path: /path/to/kmod_loader → /path/to/.kmod_probe */
    char path[512];
    strncpy(path, self_path, sizeof(path) - 1);
    path[sizeof(path) - 1] = '\0';
    char *slash = strrchr(path, '/');
    if (slash)
        snprintf(slash + 1, sizeof(path) - (slash + 1 - path), ".kmod_probe");
    else
        snprintf(path, sizeof(path), ".kmod_probe");

    g_probe.magic = PROBE_MAGIC;
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) return -1;
    ssize_t ret = write(fd, &g_probe, sizeof(g_probe));
    fsync(fd);
    close(fd);
    return (ret == sizeof(g_probe)) ? 0 : -1;
}

/* Load persisted probe state from companion file. */
static void probe_load(const char *self_path)
{
    char path[512];
    strncpy(path, self_path, sizeof(path) - 1);
    path[sizeof(path) - 1] = '\0';
    char *slash = strrchr(path, '/');
    if (slash)
        snprintf(slash + 1, sizeof(path) - (slash + 1 - path), ".kmod_probe");
    else
        snprintf(path, sizeof(path), ".kmod_probe");

    int fd = open(path, O_RDONLY);
    if (fd < 0) return;
    if (read(fd, &g_probe, sizeof(g_probe)) != (ssize_t)sizeof(g_probe))
        memset(&g_probe, 0, sizeof(g_probe)); /* invalidate partial read */
    close(fd);
}

/* ---- ELF helpers ---- */

typedef Elf64_Ehdr Ehdr;
typedef Elf64_Shdr Shdr;
typedef Elf64_Rela Rela;

static const char *elf_shname(const uint8_t *buf, const Ehdr *eh, int idx)
{
    const Shdr *shstrtab = (const Shdr *)(buf + eh->e_shoff + eh->e_shstrndx * eh->e_shentsize);
    return (const char *)(buf + shstrtab->sh_offset + idx);
}

static Shdr *elf_find_section(uint8_t *buf, const Ehdr *eh, const char *name)
{
    for (int i = 0; i < eh->e_shnum; i++) {
        Shdr *sh = (Shdr *)(buf + eh->e_shoff + i * eh->e_shentsize);
        if (strcmp(elf_shname(buf, eh, sh->sh_name), name) == 0)
            return sh;
    }
    return NULL;
}

/* ---- Parse kernel version from uname ---- */

static int parse_kver(int *major, int *minor)
{
    struct utsname u;
    if (uname(&u) < 0) return -1;
    if (sscanf(u.release, "%d.%d", major, minor) != 2) return -1;
    return 0;
}

const char *get_vermagic(void)
{
    static char vm[256];
    struct utsname u;
    if (uname(&u) < 0) return NULL;

    /* Common GKI vermagic flags. TODO: detect from loaded modules. */
    snprintf(vm, sizeof(vm), "%s SMP preempt mod_unload modversions aarch64", u.release);
    return vm;
}

/* ---- Find best preset for kernel version ---- */

/* Exact major.minor match — no "nearest lower" fallback.
 * Unknown versions fall through to disasm/probe methods. */
static const struct kver_preset *find_preset(int major, int minor)
{
    for (int i = 0; i < (int)NUM_PRESETS; i++) {
        if (presets[i].major == major && presets[i].minor == minor)
            return &presets[i];
    }
    return NULL;
}

/* Best-effort nearest preset (for exit offset fallback when init is probed). */
static const struct kver_preset *find_nearest_preset(int major, int minor)
{
    const struct kver_preset *best = NULL;
    for (int i = 0; i < (int)NUM_PRESETS; i++) {
        if (presets[i].major < major ||
            (presets[i].major == major && presets[i].minor <= minor))
            best = &presets[i];
    }
    return best;
}

/* ---- ELF symbol patching ----
 *
 * Patch a global variable's value directly in the module's ELF data section.
 * This avoids module_param callbacks that trigger CFI on shadow-CFI kernels.
 */
static int patch_elf_symbol(uint8_t *mod, size_t mod_alloc_size,
                            const Ehdr *eh, const char *sym_name,
                            uint64_t value)
{
    /* Find .symtab and .strtab */
    Shdr *symtab_sh = NULL, *strtab_sh = NULL;
    for (int i = 0; i < eh->e_shnum; i++) {
        Shdr *sh = (Shdr *)(mod + eh->e_shoff + i * eh->e_shentsize);
        if (sh->sh_type == SHT_SYMTAB && sh->sh_link < eh->e_shnum) {
            symtab_sh = sh;
            strtab_sh = (Shdr *)(mod + eh->e_shoff +
                                 sh->sh_link * eh->e_shentsize);
            break;
        }
    }
    if (!symtab_sh || !strtab_sh) return -1;

    int num_syms = symtab_sh->sh_size / symtab_sh->sh_entsize;
    Elf64_Sym *syms = (Elf64_Sym *)(mod + symtab_sh->sh_offset);
    const char *strs = (const char *)(mod + strtab_sh->sh_offset);

    for (int i = 0; i < num_syms; i++) {
        if (strcmp(strs + syms[i].st_name, sym_name) != 0) continue;
        if (syms[i].st_shndx == SHN_UNDEF || syms[i].st_shndx >= eh->e_shnum)
            continue;

        /* Found: write value to the section at the symbol's offset */
        if (syms[i].st_shndx >= eh->e_shnum) continue;
        Shdr *sec = (Shdr *)(mod + eh->e_shoff +
                             syms[i].st_shndx * eh->e_shentsize);
        uint64_t offset = sec->sh_offset + syms[i].st_value;
        if (offset + sizeof(value) > mod_alloc_size) continue;
        memcpy(mod + offset, &value, sizeof(value));
        return 0;
    }
    return -1;
}

/* ---- CRC resolution (multi-method) ----
 *
 * Priority:
 *   1. --crc command-line overrides
 *   2. /proc/kallsyms __crc_<sym> (old kernels: address = CRC value)
 *   3. Vendor .ko files on device (__versions section)
 *   4. Boot partition kernel Image (ksymtab/kcrctab parsing)
 *   5. finit_module IGNORE_MODVERSIONS (handled in load step)
 */

/* CRC override table from --crc args */
#define MAX_CRC_OVERRIDES 16
static struct { char name[56]; uint32_t crc; } crc_overrides[MAX_CRC_OVERRIDES];
static int num_crc_overrides = 0;

/* Read a kernel virtual address from /proc/kallsyms */
static uint64_t ksym_addr(const char *name)
{
    FILE *f = fopen("/proc/kallsyms", "r");
    if (!f) return 0;
    char line[256];
    uint64_t addr = 0;
    while (fgets(line, sizeof(line), f)) {
        char sname[128];
        uint64_t saddr;
        char stype;
        if (sscanf(line, "%llx %c %127s", (unsigned long long *)&saddr, &stype, sname) == 3) {
            if (strcmp(sname, name) == 0) {
                addr = saddr;
                break;
            }
        }
    }
    fclose(f);
    return addr;
}

/* Method 1: --crc command-line override */
static int crc_from_override(const char *sym, uint32_t *out)
{
    for (int i = 0; i < num_crc_overrides; i++) {
        if (strcmp(crc_overrides[i].name, sym) == 0) {
            *out = crc_overrides[i].crc;
            return 0;
        }
    }
    return -1;
}

/* Method 2: /proc/kallsyms __crc_<sym> (address IS the CRC on old kernels) */
int crc_from_kallsyms(const char *sym, uint32_t *out)
{
    char crc_name[128];
    snprintf(crc_name, sizeof(crc_name), "__crc_%s", sym);
    uint64_t addr = ksym_addr(crc_name);
    if (addr && addr < 0x100000000ULL) {
        /* On old kernels, __crc_* "address" is the CRC value itself (< 32-bit) */
        *out = (uint32_t)addr;
        return 0;
    }
    return -1;
}

/* Parse a single .ko file, extract CRC for `sym` from its __versions
 * section. Returns 0 on success (sym found), -1 on failure. Stateless;
 * unlike crc_from_vendor_ko this does NOT cache. Used by the resolver's
 * strategy_probe_loaded_module to target a specific .ko path.
 */
int crc_from_vendor_ko_file(const char *path, const char *sym, uint32_t *out)
{
    int rc = -1;
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    struct stat st;
    if (fstat(fd, &st) < 0 || st.st_size <= 0 || st.st_size > 8 * 1024 * 1024) {
        close(fd);
        return -1;
    }
    uint8_t *buf = malloc(st.st_size);
    if (!buf) { close(fd); return -1; }
    if (read(fd, buf, st.st_size) != st.st_size) goto done;
    if (st.st_size < (off_t)sizeof(Ehdr)) goto done;
    Ehdr *keh = (Ehdr *)buf;
    if (memcmp(keh->e_ident, ELFMAG, SELFMAG) != 0) goto done;
    Shdr *ver = elf_find_section(buf, keh, "__versions");
    if (!ver || ver->sh_size == 0) goto done;
    int n = ver->sh_size / 64;
    for (int i = 0; i < n; i++) {
        uint8_t *ent = buf + ver->sh_offset + i * 64;
        const char *ename = (const char *)(ent + 8);
        if (strncmp(ename, sym, 55) == 0 && ename[strlen(sym)] == '\0') {
            uint32_t crc;
            memcpy(&crc, ent, 4);
            *out = crc;
            rc = 0;
            break;
        }
    }
done:
    free(buf);
    close(fd);
    return rc;
}

/* Method 3: Scan vendor .ko files for __versions CRC */
int crc_from_vendor_ko(const char *sym, uint32_t *out)
{
    /* Common paths where vendor modules live */
    static const char *ko_dirs[] = {
        "/vendor_dlkm/lib/modules",
        "/vendor/lib/modules",
        "/system/lib/modules",
        "/odm/lib/modules",
        "/lib/modules",
        NULL
    };
    /* Cache: read one .ko file and extract ALL its CRCs */
    static uint8_t *ko_buf = NULL;
    static int ko_loaded = 0;
    static struct { char name[56]; uint32_t crc; } ko_crcs[64];
    static int ko_crc_count = 0;

    if (!ko_loaded) {
        ko_loaded = 1;
        /* Find first readable .ko */
        for (int d = 0; ko_dirs[d]; d++) {
            char cmd[256];
            snprintf(cmd, sizeof(cmd), "ls %s/*.ko 2>/dev/null", ko_dirs[d]);
            FILE *fp = popen(cmd, "r");
            if (!fp) continue;
            char path[256];
            while (fgets(path, sizeof(path), fp)) {
                path[strcspn(path, "\n")] = 0;
                int fd = open(path, O_RDONLY);
                if (fd < 0) continue;
                struct stat st;
                if (fstat(fd, &st) < 0 || st.st_size > 2 * 1024 * 1024) {
                    close(fd);
                    continue;
                }
                ko_buf = malloc(st.st_size);
                if (!ko_buf) { close(fd); continue; }
                if (read(fd, ko_buf, st.st_size) != st.st_size) {
                    free(ko_buf); ko_buf = NULL; close(fd); continue;
                }
                close(fd);

                /* Parse ELF __versions */
                if (st.st_size < (off_t)sizeof(Ehdr)) { free(ko_buf); ko_buf = NULL; continue; }
                Ehdr *keh = (Ehdr *)ko_buf;
                if (memcmp(keh->e_ident, ELFMAG, SELFMAG) != 0) {
                    free(ko_buf); ko_buf = NULL; continue;
                }
                Shdr *ver = elf_find_section(ko_buf, keh, "__versions");
                if (ver && ver->sh_size > 0) {
                    int n = ver->sh_size / 64;
                    if (n > 64) n = 64;
                    for (int i = 0; i < n; i++) {
                        uint8_t *ent = ko_buf + ver->sh_offset + i * 64;
                        memcpy(&ko_crcs[ko_crc_count].crc, ent, 4);
                        strncpy(ko_crcs[ko_crc_count].name, (char *)(ent + 8), 55);
                        ko_crcs[ko_crc_count].name[55] = 0;
                        ko_crc_count++;
                    }
                    fprintf(stderr, "kmod_loader: CRC source: %s (%d entries)\n",
                            path, ko_crc_count);
                    pclose(fp);
                    goto ko_done;
                }
                free(ko_buf); ko_buf = NULL;
            }
            pclose(fp);
        }
    ko_done:;
    }

    for (int i = 0; i < ko_crc_count; i++) {
        if (strcmp(ko_crcs[i].name, sym) == 0) {
            *out = ko_crcs[i].crc;
            return 0;
        }
    }
    return -1;
}

/* Method 4: Boot partition kernel Image → ksymtab/kcrctab */
static ssize_t read_at(const char *path, void *buf, size_t len, off_t offset)
{
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    if (lseek(fd, offset, SEEK_SET) < 0) { close(fd); return -1; }
    ssize_t n = read(fd, buf, len);
    close(fd);
    return n;
}

int crc_from_boot_image(const char *sym, uint32_t *out)
{
    /* Cache the kernel image across calls */
    static uint8_t *img = NULL;
    static size_t img_size = 0;
    static int img_loaded = 0;
    static uint64_t text_va, ksymtab_va, ksymtab_end, kcrctab_va;
    static uint64_t ksymtab_gpl, ksymtab_gpl_end, kcrctab_gpl;

    if (!img_loaded) {
        img_loaded = 1;

        text_va = ksym_addr("_text");
        ksymtab_va = ksym_addr("__start___ksymtab");
        ksymtab_end = ksym_addr("__stop___ksymtab");
        kcrctab_va = ksym_addr("__start___kcrctab");
        ksymtab_gpl = ksym_addr("__start___ksymtab_gpl");
        ksymtab_gpl_end = ksym_addr("__stop___ksymtab_gpl");
        kcrctab_gpl = ksym_addr("__start___kcrctab_gpl");

        if (!text_va || !ksymtab_va || !ksymtab_end || !kcrctab_va)
            return -1;

        /* Find boot partition */
        static const char *paths[] = {
            "/dev/block/by-name/boot",
            "/dev/block/by-name/boot_a",
            "/dev/block/by-name/boot_b",
            "/dev/block/bootdevice/by-name/boot",
            NULL
        };
        const char *path = NULL;
        struct stat st;
        for (int i = 0; paths[i]; i++) {
            if (stat(paths[i], &st) == 0) { path = paths[i]; break; }
        }
        if (!path) return -1;

        uint8_t hdr[4096];
        if (read_at(path, hdr, sizeof(hdr), 0) < (ssize_t)sizeof(hdr)) return -1;
        if (memcmp(hdr, "ANDROID!", 8) != 0) return -1;

        uint32_t kernel_size = *(uint32_t *)(hdr + 8);
        uint32_t page_size = *(uint32_t *)(hdr + 36);
        if (!kernel_size || !page_size) return -1;

        img = malloc(kernel_size);
        if (!img) return -1;
        if (read_at(path, img, kernel_size, page_size) != (ssize_t)kernel_size) {
            free(img); img = NULL; return -1;
        }

        /* Must be raw ARM64 Image (not gzip) */
        if (kernel_size <= 64 || memcmp(img + 56, "ARM\x64", 4) != 0) {
            free(img); img = NULL; return -1;
        }

        img_size = kernel_size;
        fprintf(stderr, "kmod_loader: CRC source: boot partition %s\n", path);
    }

    if (!img) return -1;

    /* Search ksymtab for the symbol, then read CRC from kcrctab */
    uint64_t st_off = ksymtab_va - text_va;
    uint64_t ct_off = kcrctab_va - text_va;
    uint64_t st_end = ksymtab_end - text_va;
    int n = (st_end - st_off) / 12;

    for (int i = 0; i < n; i++) {
        uint64_t off = st_off + (uint64_t)i * 12;
        if (off + 12 > img_size) break;
        int32_t name_off;
        memcpy(&name_off, img + off + 4, 4);
        uint64_t na = off + 4 + (int64_t)name_off;
        if (na >= img_size) continue;
        if (strcmp((char *)(img + na), sym) == 0) {
            uint64_t co = ct_off + (uint64_t)i * 4;
            if (co + 4 > img_size) return -1;
            memcpy(out, img + co, 4);
            return 0;
        }
    }

    /* Try GPL ksymtab */
    if (ksymtab_gpl && kcrctab_gpl) {
        st_off = ksymtab_gpl - text_va;
        ct_off = kcrctab_gpl - text_va;
        st_end = ksymtab_gpl_end - text_va;
        n = (st_end - st_off) / 12;
        for (int i = 0; i < n; i++) {
            uint64_t off = st_off + (uint64_t)i * 12;
            if (off + 12 > img_size) break;
            int32_t name_off;
            memcpy(&name_off, img + off + 4, 4);
            uint64_t na = off + 4 + (int64_t)name_off;
            if (na >= img_size) continue;
            if (strcmp((char *)(img + na), sym) == 0) {
                uint64_t co = ct_off + (uint64_t)i * 4;
                if (co + 4 > img_size) return -1;
                memcpy(out, img + co, 4);
                return 0;
            }
        }
    }

    return -1;
}

/* Resolve CRC for a symbol using all methods in priority order */
static int resolve_crc(const char *sym, uint32_t *out)
{
    if (crc_from_override(sym, out) == 0) return 0;
    if (crc_from_kallsyms(sym, out) == 0) return 0;
    if (crc_from_vendor_ko(sym, out) == 0) return 0;
    if (crc_from_boot_image(sym, out) == 0) return 0;
    return -1;
}

/* Patch all CRC values in __versions */
/* ---- kCFI hash patching ----
 *
 * kCFI embeds a 4-byte type hash immediately before each function entry.
 * do_one_initcall() checks init_module's hash; the exit path checks
 * cleanup_module's hash.  When CONFIG_CFI_ICALL_NORMALIZE_INTEGERS=y
 * (6.12+), the hash algorithm changes.  Our module may be compiled with
 * a different hash variant than the running kernel.
 *
 * Fix: extract the correct hashes from a vendor .ko (compiled with the
 * kernel's own toolchain) and patch them into our module.
 */

/* Get file offset of the kCFI hash for a named function in an ELF.
 * Returns the file offset of the 4 bytes before the function entry,
 * or 0 on failure. */
static uint64_t elf_kcfi_hash_offset(const uint8_t *mod, const Ehdr *eh,
                                      const char *func_name)
{
    Shdr *symtab_sh = NULL;
    for (int i = 0; i < eh->e_shnum; i++) {
        Shdr *sh = (Shdr *)(mod + eh->e_shoff + i * eh->e_shentsize);
        if (sh->sh_type == SHT_SYMTAB) { symtab_sh = sh; break; }
    }
    if (!symtab_sh || symtab_sh->sh_link >= eh->e_shnum) return 0;

    Shdr *strtab_sh = (Shdr *)(mod + eh->e_shoff +
                                symtab_sh->sh_link * eh->e_shentsize);
    int num_syms = symtab_sh->sh_size / symtab_sh->sh_entsize;
    Elf64_Sym *syms = (Elf64_Sym *)(mod + symtab_sh->sh_offset);
    const char *strs = (const char *)(mod + strtab_sh->sh_offset);

    for (int i = 0; i < num_syms; i++) {
        if (strcmp(strs + syms[i].st_name, func_name) != 0) continue;
        if (syms[i].st_shndx == SHN_UNDEF || syms[i].st_shndx >= eh->e_shnum)
            continue;

        Shdr *sec = (Shdr *)(mod + eh->e_shoff +
                             syms[i].st_shndx * eh->e_shentsize);
        uint64_t func_file_off = sec->sh_offset + syms[i].st_value;
        if (func_file_off < 4) return 0;  /* no room for hash prefix */
        return func_file_off - 4;
    }
    return 0;
}

/* Extract kCFI hash value for a function from a vendor .ko.
 * Returns 0 on failure, or the hash value (which may itself be 0 in
 * theory, but never in practice because kCFI hashes are non-trivial). */
static uint32_t vendor_kcfi_hash(const uint8_t *ko, const Ehdr *keh,
                                  const char *func_name)
{
    uint64_t off = elf_kcfi_hash_offset(ko, keh, func_name);
    if (!off) return 0;
    uint32_t hash;
    memcpy(&hash, ko + off, 4);
    return hash;
}

/* Patch kCFI hashes in module from vendor .ko reference.
 * Scans /vendor/lib/modules/ for a .ko that has both init_module and
 * cleanup_module symbols, extracts their kCFI hashes, and patches ours. */
static int patch_kcfi_hashes(uint8_t *mod, size_t mod_size, const Ehdr *eh)
{
    /* Find init_module and cleanup_module hash offsets in our module */
    uint64_t our_init_off = elf_kcfi_hash_offset(mod, eh, "init_module");
    uint64_t our_exit_off = elf_kcfi_hash_offset(mod, eh, "cleanup_module");
    if (!our_init_off && !our_exit_off) return 0;  /* no symbols to patch */

    /* Try to find a vendor .ko with matching symbols */
    static const char *vendor_dirs[] = {
        "/vendor/lib/modules",
        "/vendor_dlkm/lib/modules",
        NULL
    };

    for (int d = 0; vendor_dirs[d]; d++) {
        DIR *dp = opendir(vendor_dirs[d]);
        if (!dp) continue;

        struct dirent *de;
        while ((de = readdir(dp)) != NULL) {
            size_t nlen = strlen(de->d_name);
            if (nlen < 4 || strcmp(de->d_name + nlen - 3, ".ko") != 0)
                continue;

            char path[512];
            snprintf(path, sizeof(path), "%s/%s", vendor_dirs[d], de->d_name);
            int fd = open(path, O_RDONLY);
            if (fd < 0) continue;

            struct stat st;
            if (fstat(fd, &st) < 0 || st.st_size < 256) {
                close(fd);
                continue;
            }

            uint8_t *ko = malloc(st.st_size);
            if (!ko) { close(fd); continue; }
            if (read(fd, ko, st.st_size) != st.st_size) {
                free(ko); close(fd); continue;
            }
            close(fd);

            Ehdr *keh = (Ehdr *)ko;
            if (memcmp(keh->e_ident, ELFMAG, SELFMAG) != 0) {
                free(ko); continue;
            }

            /* Extract hashes from vendor module */
            uint32_t ref_init_hash = vendor_kcfi_hash(ko, keh, "init_module");
            uint32_t ref_exit_hash = vendor_kcfi_hash(ko, keh, "cleanup_module");
            free(ko);

            if (!ref_init_hash && !ref_exit_hash) continue;

            /* Patch our module's kCFI hashes */
            int patched = 0;
            if (our_init_off && ref_init_hash &&
                our_init_off + 4 <= mod_size) {
                uint32_t old;
                memcpy(&old, mod + our_init_off, 4);
                if (old != ref_init_hash) {
                    memcpy(mod + our_init_off, &ref_init_hash, 4);
                    fprintf(stderr, "kmod_loader: kCFI init_module: "
                            "0x%08x -> 0x%08x (from %s)\n",
                            old, ref_init_hash, de->d_name);
                    patched++;
                }
            }
            if (our_exit_off && ref_exit_hash &&
                our_exit_off + 4 <= mod_size) {
                uint32_t old;
                memcpy(&old, mod + our_exit_off, 4);
                if (old != ref_exit_hash) {
                    memcpy(mod + our_exit_off, &ref_exit_hash, 4);
                    fprintf(stderr, "kmod_loader: kCFI cleanup_module: "
                            "0x%08x -> 0x%08x (from %s)\n",
                            old, ref_exit_hash, de->d_name);
                    patched++;
                }
            }

            closedir(dp);
            return patched;
        }
        closedir(dp);
    }

    return 0;
}

static int patch_crcs(uint8_t *mod, const Ehdr *eh)
{
    Shdr *ver = elf_find_section(mod, eh, "__versions");
    if (!ver || ver->sh_size == 0) return 0;

    int patched = 0;
    int num_entries = ver->sh_size / 64;
    for (int i = 0; i < num_entries; i++) {
        uint8_t *ent = mod + ver->sh_offset + i * 64;
        const char *sym = (const char *)(ent + 8);
        uint32_t new_crc;

        if (resolve_crc(sym, &new_crc) == 0) {
            uint32_t old_crc;
            memcpy(&old_crc, ent, 4);
            if (old_crc != new_crc) {
                memcpy(ent, &new_crc, 4);
                fprintf(stderr, "kmod_loader: CRC %s: 0x%08x -> 0x%08x\n",
                        sym, old_crc, new_crc);
            }
            patched++;
        } else {
            fprintf(stderr, "kmod_loader: CRC %s: not found (keeping 0x%08x)\n",
                    sym, *(uint32_t *)ent);
        }
    }
    return patched;
}

/* ---- patch_crcs_via_resolver (Plan 2 M-C T13) ----
 *
 * Resolver-driven variant of patch_crcs(). Iterates __versions the same
 * way, but for each of the four known symbols (module_layout, _printk,
 * memcpy, memset) it routes the lookup through resolve(VAL_*_CRC) so the
 * CLI / probe_loaded_module / probe_ondisk_module / config strategies all
 * get a shot. For symbols outside that set it falls back to the legacy
 * crc_from_* helper chain (crc_from_override → crc_from_kallsyms →
 * crc_from_vendor_ko → crc_from_boot_image), which is the same chain the
 * old resolve_crc() used.
 *
 * Behavior is identical when __versions contains only the four known
 * symbols — which is the case for freestanding kh_test.ko — and a strict
 * superset otherwise (unknown syms still use the old chain). Defined in
 * this commit but not called yet; a later commit wires it into main().
 */
static int crc_fallback_chain(const char *sym, uint32_t *out)
{
    if (crc_from_override(sym, out) == 0) return 0;
    if (crc_from_kallsyms(sym, out) == 0) return 0;
    if (crc_from_vendor_ko(sym, out) == 0) return 0;
    if (crc_from_boot_image(sym, out) == 0) return 0;
    return -1;
}

static int sym_to_crc_value_id(const char *sym, value_id_t *out)
{
    if (strcmp(sym, "module_layout") == 0) { *out = VAL_MODULE_LAYOUT_CRC; return 0; }
    if (strcmp(sym, "_printk") == 0 || strcmp(sym, "printk") == 0) {
        *out = VAL_PRINTK_CRC; return 0;
    }
    if (strcmp(sym, "memcpy") == 0) { *out = VAL_MEMCPY_CRC; return 0; }
    if (strcmp(sym, "memset") == 0) { *out = VAL_MEMSET_CRC; return 0; }
    return -1;
}

static int patch_crcs_via_resolver(uint8_t *mod, const Ehdr *eh,
                                   resolve_ctx_t *ctx,
                                   trace_entry_t *trace, int *trace_count)
{
    Shdr *ver = elf_find_section(mod, eh, "__versions");
    if (!ver || ver->sh_size == 0) return 0;

    int patched = 0;
    int num_entries = ver->sh_size / 64;
    for (int i = 0; i < num_entries; i++) {
        uint8_t *ent = mod + ver->sh_offset + i * 64;
        const char *sym = (const char *)(ent + 8);
        uint32_t new_crc = 0;
        int ok = 0;
        const char *src = NULL;

        value_id_t vid;
        if (sym_to_crc_value_id(sym, &vid) == 0) {
            trace_entry_t t;
            resolved_t r = resolve(vid, ctx, &t);
            if (trace && trace_count && *trace_count < KH_TRACE_MAX)
                trace[(*trace_count)++] = t;
            if (r.available) {
                new_crc = (uint32_t)r.u64_val;
                src = r.source_label;
                ok = 1;
            }
        }
        if (!ok && crc_fallback_chain(sym, &new_crc) == 0) {
            src = "legacy_chain";
            ok = 1;
        }

        if (ok) {
            uint32_t old_crc;
            memcpy(&old_crc, ent, 4);
            if (old_crc != new_crc) {
                memcpy(ent, &new_crc, 4);
                fprintf(stderr, "kmod_loader: CRC %s: 0x%08x -> 0x%08x [%s]\n",
                        sym, old_crc, new_crc, src ? src : "?");
            }
            patched++;
        } else {
            fprintf(stderr, "kmod_loader: CRC %s: not found (keeping 0x%08x)\n",
                    sym, *(uint32_t *)ent);
        }
    }
    return patched;
}

/* ---- Patch vermagic in .modinfo ---- */

static void patch_vermagic(uint8_t *mod, const Ehdr *eh)
{
    Shdr *mi = elf_find_section(mod, eh, ".modinfo");
    if (!mi) return;

    const char *new_vm = get_vermagic();
    if (!new_vm) return;

    uint8_t *base = mod + mi->sh_offset;
    uint8_t *end = base + mi->sh_size;

    for (uint8_t *p = base; p < end; ) {
        if (strncmp((char *)p, "vermagic=", 9) == 0) {
            char *old_vm = (char *)p + 9;
            /* Calculate available space: scan past null padding to next
             * non-null modinfo entry or section end. This handles padded
             * vermagic strings (where padding is null bytes after the string). */
            size_t str_len = strlen(old_vm);
            char *slot_end = old_vm + str_len + 1; /* past first null */
            while (slot_end < (char *)end && *slot_end == '\0')
                slot_end++; /* skip padding nulls */
            size_t avail = (size_t)(slot_end - old_vm - 1); /* -1 for terminator */
            size_t new_len = strlen(new_vm);
            if (new_len <= avail) {
                memcpy(old_vm, new_vm, new_len);
                memset(old_vm + new_len, 0, avail - new_len + 1);
                fprintf(stderr, "kmod_loader: vermagic patched (avail=%zu)\n", avail);
            } else {
                fprintf(stderr, "kmod_loader: new vermagic too long (%zu > %zu)\n",
                        new_len, avail);
            }
            return;
        }
        p += strlen((char *)p) + 1;
    }
}

/* ---- patch_vermagic_via_resolver (Plan 2 M-C T13) ----
 *
 * Resolver-driven variant of patch_vermagic(). Calls resolve(VAL_VERMAGIC)
 * to obtain the target string, then applies the same .modinfo slot-rewrite
 * logic as patch_vermagic(). Behavior is identical on kernels where the
 * resolver's probe_procfs strategy returns the same string get_vermagic()
 * would return (which is the only strategy for VAL_VERMAGIC besides CLI and
 * device config, both of which are additive opt-ins).
 *
 * Defined in this commit but not yet called; a later commit wires it into
 * main(). Keeping the definition inert here keeps each commit trivially
 * reviewable.
 */
static void patch_vermagic_via_resolver(uint8_t *mod, const Ehdr *eh,
                                        resolve_ctx_t *ctx,
                                        trace_entry_t *trace, int *trace_count)
{
    Shdr *mi = elf_find_section(mod, eh, ".modinfo");
    if (!mi) return;

    trace_entry_t t;
    resolved_t r = resolve(VAL_VERMAGIC, ctx, &t);
    if (trace && trace_count) trace[(*trace_count)++] = t;
    if (!r.available || !r.str_val[0]) return;
    const char *new_vm = r.str_val;

    uint8_t *base = mod + mi->sh_offset;
    uint8_t *end = base + mi->sh_size;

    for (uint8_t *p = base; p < end; ) {
        if (strncmp((char *)p, "vermagic=", 9) == 0) {
            char *old_vm = (char *)p + 9;
            size_t str_len = strlen(old_vm);
            char *slot_end = old_vm + str_len + 1;
            while (slot_end < (char *)end && *slot_end == '\0')
                slot_end++;
            size_t avail = (size_t)(slot_end - old_vm - 1);
            size_t new_len = strlen(new_vm);
            if (new_len <= avail) {
                memcpy(old_vm, new_vm, new_len);
                memset(old_vm + new_len, 0, avail - new_len + 1);
                fprintf(stderr, "kmod_loader: vermagic patched via resolver "
                                "(avail=%zu, src=%s)\n",
                        avail, r.source_label);
            } else {
                fprintf(stderr, "kmod_loader: new vermagic too long (%zu > %zu)\n",
                        new_len, avail);
            }
            return;
        }
        p += strlen((char *)p) + 1;
    }
}

/* ---- Patch struct module layout ---- */

static int patch_module_layout(uint8_t *mod, size_t mod_size, const Ehdr *eh,
                               const struct kver_preset *preset)
{
    Shdr *this_mod = elf_find_section(mod, eh, ".gnu.linkonce.this_module");
    Shdr *rela = elf_find_section(mod, eh, ".rela.gnu.linkonce.this_module");

    if (!this_mod) {
        fprintf(stderr, "kmod_loader: .gnu.linkonce.this_module not found\n");
        return -1;
    }

    /* Zero out the entire section to ensure all unknown fields (num_ei_funcs,
     * ei_funcs, trace_events, etc.) are NULL/0, preventing kernel crashes in
     * module_notifier callbacks. Then restore the module name from .modinfo
     * (kernel expects it at offset 24 in struct module, max 56 bytes). */
    memset(mod + this_mod->sh_offset, 0, this_mod->sh_size);

    /* Restore module name at offset 24 (MODULE_NAME_LEN is 56 on all kernels) */
    {
        Shdr *mi = elf_find_section(mod, eh, ".modinfo");
        if (mi) {
            uint8_t *base = mod + mi->sh_offset;
            uint8_t *mend = base + mi->sh_size;
            for (uint8_t *p = base; p < mend; ) {
                if (strncmp((char *)p, "name=", 5) == 0) {
                    const char *name = (char *)p + 5;
                    size_t nlen = strlen(name);
                    if (nlen > 55) nlen = 55;
                    memcpy(mod + this_mod->sh_offset + 24, name, nlen);
                    break;
                }
                p += strlen((char *)p) + 1;
            }
        }
    }

    uint32_t old_size = (uint32_t)this_mod->sh_size;
    uint32_t new_size = preset->mod_size;

    if (old_size == new_size) {
        fprintf(stderr, "kmod_loader: struct module size already correct (0x%x)\n", new_size);
    } else {
        fprintf(stderr, "kmod_loader: struct module size 0x%x -> 0x%x\n", old_size, new_size);

        if (new_size > old_size) {
            /* Check there's room: both file size and no adjacent section overlap */
            if (this_mod->sh_offset + new_size > mod_size) {
                fprintf(stderr, "kmod_loader: cannot expand .this_module (file too small)\n");
                return -1;
            }
            /* Verify no section starts within the expansion range */
            uint64_t expand_end = this_mod->sh_offset + new_size;
            for (int i = 0; i < eh->e_shnum; i++) {
                Shdr *sh = (Shdr *)(mod + eh->e_shoff + i * eh->e_shentsize);
                if (sh == this_mod || sh->sh_size == 0) continue;
                if (sh->sh_offset > this_mod->sh_offset &&
                    sh->sh_offset < expand_end) {
                    fprintf(stderr, "kmod_loader: cannot expand .this_module "
                            "(overlaps section at 0x%llx)\n",
                            (unsigned long long)sh->sh_offset);
                    return -1;
                }
            }
            memset(mod + this_mod->sh_offset + old_size, 0, new_size - old_size);
        }
        /* If shrinking, just change the section header size. Data beyond is ignored. */
        this_mod->sh_size = new_size;
    }

    /* Patch relocation offsets for init/exit.
     * Only patch relocations whose symbol resolves to init_module or
     * cleanup_module. Other relocations (e.g., cfi_check) are left as-is. */
    if (rela && rela->sh_size >= 2 * sizeof(Rela)) {
        Rela *entries = (Rela *)(mod + rela->sh_offset);
        int num_rela = rela->sh_size / sizeof(Rela);

        /* Find init_module and cleanup_module symbol indices */
        Shdr *symtab_sh2 = NULL;
        for (int i = 0; i < eh->e_shnum; i++) {
            Shdr *sh = (Shdr *)(mod + eh->e_shoff + i * eh->e_shentsize);
            if (sh->sh_type == SHT_SYMTAB) { symtab_sh2 = sh; break; }
        }
        uint32_t init_sym_idx = 0, exit_sym_idx = 0;
        if (symtab_sh2 && symtab_sh2->sh_link < eh->e_shnum) {
            Shdr *str = (Shdr *)(mod + eh->e_shoff +
                                 symtab_sh2->sh_link * eh->e_shentsize);
            int ns = symtab_sh2->sh_size / symtab_sh2->sh_entsize;
            Elf64_Sym *sy = (Elf64_Sym *)(mod + symtab_sh2->sh_offset);
            const char *st = (const char *)(mod + str->sh_offset);
            for (int i = 0; i < ns; i++) {
                const char *n = st + sy[i].st_name;
                if (strcmp(n, "init_module") == 0) init_sym_idx = i;
                else if (strcmp(n, "cleanup_module") == 0) exit_sym_idx = i;
            }
        }

        for (int i = 0; i < num_rela; i++) {
            uint32_t sym_idx = (uint32_t)(entries[i].r_info >> 32);
            uint64_t old_off = entries[i].r_offset;

            if (sym_idx == init_sym_idx && init_sym_idx != 0) {
                if (old_off != preset->init_off) {
                    fprintf(stderr, "kmod_loader: init offset 0x%llx -> 0x%x\n",
                            (unsigned long long)old_off, preset->init_off);
                    entries[i].r_offset = preset->init_off;
                }
            } else if (sym_idx == exit_sym_idx && exit_sym_idx != 0) {
                if (old_off != preset->exit_off) {
                    fprintf(stderr, "kmod_loader: exit offset 0x%llx -> 0x%x\n",
                            (unsigned long long)old_off, preset->exit_off);
                    entries[i].r_offset = preset->exit_off;
                }
            }
            /* Other relocations (cfi_check, etc.) are left unchanged */
        }
    }

    return 0;
}

/* ---- Probe struct module size ---- */

static uint32_t probe_mod_size(uint8_t *mod, size_t mod_size, const Ehdr *eh,
                               const char *params, uint32_t hint)
{
    Shdr *this_mod = elf_find_section(mod, eh, ".gnu.linkonce.this_module");
    if (!this_mod) return hint;

    uint64_t orig_size = this_mod->sh_size;

    /* The kernel checks .gnu.linkonce.this_module size == sizeof(struct module)
     * BEFORE resolving symbols or checking CRCs. Wrong size → ENOEXEC.
     * Any other error (ENOENT, EINVAL) means size was accepted.
     *
     * Safety: zero out the init relocation offset so that even if the module
     * loads unexpectedly, the kernel won't call a random init function.
     * Also use finit_module (not init_module) to avoid executing code. */
    Shdr *rela = elf_find_section(mod, eh, ".rela.gnu.linkonce.this_module");
    uint64_t saved_rela[2] = {0, 0}; /* save original init/exit offsets */
    if (rela && rela->sh_size >= 2 * sizeof(Rela)) {
        Rela *entries = (Rela *)(mod + rela->sh_offset);
        saved_rela[0] = entries[0].r_offset;
        saved_rela[1] = entries[1].r_offset;
        /* Set init/exit to preset offsets for probing. If the module loads
         * with correct size, init will be called but fail quickly due to
         * empty params (kallsyms_addr=0 → ksyms_init fails → module unloads). */
        entries[0].r_offset = hint < saved_rela[0] ?
            (hint > 0x140 ? 0x140 : hint / 2) : saved_rela[0];
        entries[1].r_offset = hint < saved_rela[1] ?
            (hint > 0x280 ? 0x280 : hint - 8) : saved_rela[1];
    }

    /* Try sizes around the hint using init_module.
     * Wrong size → ENOEXEC. Other error → size is correct.
     * Safety: init/exit relocations are zeroed so even if the module
     * loads unexpectedly, no init function will be called. */
    static const int deltas[] = { 0, 0x40, -0x40, 0x80, -0x80, 0xC0, -0xC0 };
    uint32_t found = 0;

    for (int i = 0; i < (int)(sizeof(deltas)/sizeof(deltas[0])); i++) {
        uint32_t try_size = (uint32_t)((int)hint + deltas[i]);
        if (try_size < 0x200 || try_size > 0x800) continue;
        try_size = (try_size + 63) & ~63; /* 64-byte aligned */

        this_mod->sh_size = try_size;

        int ret = (int)syscall(__NR_init_module, mod, mod_size, "");
        int err = errno;

        if (ret == 0) {
            syscall(__NR_delete_module, "kh_test", 0);
            fprintf(stderr, "kmod_loader: probe 0x%x: loaded+unloaded\n", try_size);
            found = try_size;
            break;
        }

        if (err != ENOEXEC) {
            fprintf(stderr, "kmod_loader: probe 0x%x: errno=%d (%s) — size match\n",
                    try_size, err, strerror(err));
            found = try_size;
            break;
        }
        /* ENOEXEC = wrong size */
    }

probe_restore:

    /* Restore original section size and relocation offsets */
    this_mod->sh_size = orig_size;
    if (rela && rela->sh_size >= 2 * sizeof(Rela)) {
        Rela *entries = (Rela *)(mod + rela->sh_offset);
        entries[0].r_offset = saved_rela[0];
        entries[1].r_offset = saved_rela[1];
    }

    if (!found) {
        fprintf(stderr, "kmod_loader: probe failed, using hint 0x%x\n", hint);
        return hint;
    }
    return found;
}

/* ---- Patch printk symbol name ---- */

static void patch_printk_symbol(uint8_t *mod, const Ehdr *eh)
{
    /* Check if kernel exports _printk or printk */
    uint64_t addr_printk = ksym_addr("printk");
    uint64_t addr_uprintk = ksym_addr("_printk");

    /* Our module uses _printk by default (6.1+). If kernel has printk instead,
     * patch the symbol name in __versions and in the symbol table. */
    if (addr_uprintk) return; /* _printk exists, no patch needed */
    if (!addr_printk) return; /* neither exists?! */

    fprintf(stderr, "kmod_loader: kernel uses 'printk' instead of '_printk'\n");

    /* Patch __versions entry */
    Shdr *ver = elf_find_section(mod, eh, "__versions");
    if (ver) {
        int n = ver->sh_size / 64;
        for (int i = 0; i < n; i++) {
            char *sym = (char *)(mod + ver->sh_offset + i * 64 + 8);
            if (strcmp(sym, "_printk") == 0) {
                /* Shift name left by 1 to remove underscore */
                memmove(sym, sym + 1, strlen(sym)); /* "printk\0" */
                fprintf(stderr, "kmod_loader: __versions _printk -> printk\n");
            }
        }
    }

    /* Patch string table entry for the _printk symbol */
    Shdr *strtab = NULL;
    for (int i = 0; i < eh->e_shnum; i++) {
        Shdr *sh = (Shdr *)(mod + eh->e_shoff + i * eh->e_shentsize);
        if (sh->sh_type == SHT_STRTAB && i != eh->e_shstrndx) {
            strtab = sh;
            break;
        }
    }
    if (strtab) {
        char *base = (char *)(mod + strtab->sh_offset);
        char *end = base + strtab->sh_size;
        for (char *p = base; p < end; ) {
            if (strcmp(p, "_printk") == 0) {
                memmove(p, p + 1, strlen(p)); /* Remove leading underscore */
                fprintf(stderr, "kmod_loader: strtab _printk -> printk\n");
            }
            p += strlen(p) + 1;
        }
    }
}

/* ---- Probe stubs (Method A: disassembly, Method B: binary probe) ---- */

int probe_init_offset_disasm(uint32_t *out_init)
{
    uint64_t do_init = ksym_addr("do_init_module");
    if (!do_init) return -1;

    /* Read ~256 bytes of do_init_module from /proc/kcore */
    int fd = open("/proc/kcore", O_RDONLY);
    if (fd < 0) return -1;

    Elf64_Ehdr ehdr;
    if (read(fd, &ehdr, sizeof(ehdr)) != sizeof(ehdr)) { close(fd); return -1; }
    if (memcmp(ehdr.e_ident, ELFMAG, SELFMAG) != 0) { close(fd); return -1; }

    /* Scan PT_LOAD segments to find the one containing do_init_module */
    uint8_t code[256];
    int found = 0;
    for (int i = 0; i < ehdr.e_phnum; i++) {
        Elf64_Phdr phdr;
        if (pread(fd, &phdr, sizeof(phdr),
                  ehdr.e_phoff + (off_t)i * ehdr.e_phentsize) != sizeof(phdr))
            continue;
        if (phdr.p_type != PT_LOAD) continue;
        if (do_init >= phdr.p_vaddr &&
            do_init < phdr.p_vaddr + phdr.p_filesz) {
            off_t file_off = phdr.p_offset + (off_t)(do_init - phdr.p_vaddr);
            if (pread(fd, code, sizeof(code), file_off) == sizeof(code))
                found = 1;
            break;
        }
    }
    close(fd);
    if (!found) return -1;

    /* Scan for: LDR X0, [Xn, #imm] followed by CBZ X0, <target> */
    uint32_t *insns = (uint32_t *)code;
    int n = (sizeof(code) / 4) - 1;
    for (int i = 0; i < n; i++) {
        uint32_t ldr = insns[i];
        uint32_t cbz = insns[i + 1];
        /* LDR X0, [Xn, #imm] — 64-bit unsigned offset */
        if ((ldr & 0xFFC00000) != 0xF9400000) continue;
        if ((ldr & 0x1F) != 0) continue;  /* Rt must be X0 */
        /* CBZ X0, <target> — 64-bit */
        if ((cbz & 0xFF00001F) != 0xB4000000) continue;

        uint32_t imm12 = (ldr >> 10) & 0xFFF;
        uint32_t imm = imm12 * 8;
        if (imm < 0x100 || imm > 0x300) continue;

        *out_init = imm;
        fprintf(stderr, "kmod_loader: disasm do_init_module: init offset = 0x%x\n", imm);
        return 0;
    }
    return -1;
}

/* Method B: binary probe with embedded probe.ko.
 *
 * Iterates candidate init offsets 0x100..0x220 (step 8).
 * For each: patches probe .ko's init relocation, calls init_module.
 * EINVAL → init ran → found. 0 → init not called → skip. crash → recovered on next run.
 */
#define PROBE_CAND_BASE  0x100
#define PROBE_CAND_STEP  8
#define PROBE_CAND_COUNT 32  /* 0x100..0x200, step 8 */
_Static_assert(PROBE_CAND_COUNT <= 32, "probe bitmask overflow");

static uint32_t probe_cand_offset(int idx)
{
    return PROBE_CAND_BASE + idx * PROBE_CAND_STEP;
}

#ifdef EMBED_PROBE_KO
#include "probe_embed.h"
#endif

#ifndef __NR_delete_module
#define __NR_delete_module 106
#endif

int probe_init_offset_binary(const char *self_path, uint8_t *main_mod,
                                    size_t main_mod_size, const Ehdr *main_eh,
                                    const char *params, uint32_t *out_init)
{
#ifndef EMBED_PROBE_KO
    (void)self_path; (void)main_mod; (void)main_mod_size; (void)main_eh;
    (void)params; (void)out_init;
    fprintf(stderr, "kmod_loader: binary probe not available (no embedded probe.ko)\n");
    return -1;
#else
    struct utsname u;
    uname(&u);
    uint32_t vhash = hash_version(u.release);

    /* Crash recovery */
    if (g_probe.magic == PROBE_MAGIC && g_probe.version_hash == vhash &&
        g_probe.probing_idx != PROBE_IDLE) {
        int crashed = g_probe.probing_idx;
        fprintf(stderr, "kmod_loader: probe idx %d (0x%x) crashed, skipping\n",
                crashed, probe_cand_offset(crashed));
        g_probe.crash_mask |= (1u << crashed);
        g_probe.tried_mask |= (1u << crashed);
        g_probe.probing_idx = PROBE_IDLE;
        probe_persist(self_path);
    }

    /* Init probe state for this kernel */
    if (g_probe.magic != PROBE_MAGIC || g_probe.version_hash != vhash) {
        memset(&g_probe, 0, sizeof(g_probe));
        g_probe.magic = PROBE_MAGIC;
        g_probe.version_hash = vhash;
        g_probe.probing_idx = PROBE_IDLE;
    }

    size_t pko_alloc = probe_ko_size + 0x200;
    uint8_t *pko = calloc(1, pko_alloc);
    if (!pko) return -1;

    for (int idx = 0; idx < PROBE_CAND_COUNT; idx++) {
        if ((g_probe.tried_mask | g_probe.crash_mask) & (1u << idx)) continue;

        uint32_t cand = probe_cand_offset(idx);

        /* Fresh copy */
        memcpy(pko, probe_ko_data, probe_ko_size);
        Ehdr *peh = (Ehdr *)pko;

        /* Patch vermagic, printk rename, CRCs */
        patch_vermagic(pko, peh);
        patch_printk_symbol(pko, peh);
        patch_crcs(pko, peh);

        /* Patch init relocation offset to candidate */
        Shdr *rela = elf_find_section(pko, peh, ".rela.gnu.linkonce.this_module");
        if (!rela) { free(pko); return -1; }

        /* Find init_module symbol index */
        Shdr *symtab_sh = NULL;
        for (int i = 0; i < peh->e_shnum; i++) {
            Shdr *sh = (Shdr *)(pko + peh->e_shoff + i * peh->e_shentsize);
            if (sh->sh_type == SHT_SYMTAB) { symtab_sh = sh; break; }
        }
        if (!symtab_sh || symtab_sh->sh_link >= peh->e_shnum) { free(pko); return -1; }

        Shdr *pstrtab = (Shdr *)(pko + peh->e_shoff +
                                  symtab_sh->sh_link * peh->e_shentsize);
        Elf64_Sym *psyms = (Elf64_Sym *)(pko + symtab_sh->sh_offset);
        const char *pstrs = (const char *)(pko + pstrtab->sh_offset);
        int nsyms = symtab_sh->sh_size / symtab_sh->sh_entsize;

        int init_sym = -1;
        for (int s = 0; s < nsyms; s++) {
            if (strcmp(pstrs + psyms[s].st_name, "init_module") == 0) {
                init_sym = s; break;
            }
        }

        Rela *entries = (Rela *)(pko + rela->sh_offset);
        int nrela = rela->sh_size / sizeof(Rela);
        for (int r = 0; r < nrela; r++) {
            uint32_t sym = (uint32_t)(entries[r].r_info >> 32);
            if (init_sym >= 0 && sym == (uint32_t)init_sym) {
                entries[r].r_offset = cand;
                break;
            }
        }

        /* Zero and patch .gnu.linkonce.this_module */
        Shdr *this_mod = elf_find_section(pko, peh, ".gnu.linkonce.this_module");
        if (this_mod) {
            memset(pko + this_mod->sh_offset, 0, this_mod->sh_size);
            /* Unique name per probe to avoid EEXIST if rmmod fails */
            char pname[16];
            snprintf(pname, sizeof(pname), "kh_p%02d", idx);
            memcpy(pko + this_mod->sh_offset + 24, pname, strlen(pname) + 1);
            /* Also patch .modinfo name= entry */
            Shdr *pmi = elf_find_section(pko, peh, ".modinfo");
            if (pmi) {
                uint8_t *mb = pko + pmi->sh_offset;
                uint8_t *me = mb + pmi->sh_size;
                for (uint8_t *p = mb; p < me; ) {
                    if (strncmp((char *)p, "name=", 5) == 0) {
                        memcpy(p + 5, pname, strlen(pname) + 1);
                        break;
                    }
                    p += strlen((char *)p) + 1;
                }
            }
        }

        /* Persist probing_idx (crash marker) */
        g_probe.probing_idx = idx;
        probe_persist(self_path);

        fprintf(stderr, "kmod_loader: probe init=0x%x (idx=%d)... ", cand, idx);
        int ret = (int)syscall(__NR_init_module, pko,
                               (unsigned long)probe_ko_size, "");
        int err = errno;

        if (ret == 0) {
            fprintf(stderr, "loaded (init not called)\n");
            { char rmname[16]; snprintf(rmname, sizeof(rmname), "kh_p%02d", idx);
              syscall(__NR_delete_module, rmname, 0); }
            g_probe.tried_mask |= (1u << idx);
        } else if (err == EINVAL) {
            fprintf(stderr, "FOUND!\n");
            *out_init = cand;
            g_probe.probing_idx = PROBE_IDLE;
            free(pko);
            return 0;
        } else {
            fprintf(stderr, "errno=%d\n", err);
            g_probe.tried_mask |= (1u << idx);
        }

        g_probe.probing_idx = PROBE_IDLE;
        probe_persist(self_path);
    }

    free(pko);
    fprintf(stderr, "kmod_loader: binary probe exhausted all candidates\n");
    return -1;
#endif
}

/* ---- Vendor module introspection ----
 *
 * Read a loaded vendor .ko's ELF to extract the actual struct module size
 * and init/exit offsets from .rela.gnu.linkonce.this_module relocations.
 * This handles physical devices where GKI presets may not match. */

static int introspect_vendor_module(struct kver_preset *out)
{
    /* Search common vendor module directories */
    static const char *dirs[] = {
        "/vendor_dlkm/lib/modules",
        "/vendor/lib/modules",
        "/system/lib/modules",
        NULL
    };

    for (const char **dp = dirs; *dp; dp++) {
        DIR *d = opendir(*dp);
        if (!d) continue;
        struct dirent *ent;
        while ((ent = readdir(d)) != NULL) {
            size_t nlen = strlen(ent->d_name);
            if (nlen < 4 || strcmp(ent->d_name + nlen - 3, ".ko") != 0)
                continue;
            char path[512];
            snprintf(path, sizeof(path), "%s/%s", *dp, ent->d_name);

            int fd = open(path, O_RDONLY);
            if (fd < 0) continue;
            struct stat st;
            if (fstat(fd, &st) != 0 || st.st_size < (off_t)sizeof(Ehdr)) {
                close(fd); continue;
            }
            uint8_t *buf = malloc(st.st_size);
            if (!buf) { close(fd); continue; }
            if (read(fd, buf, st.st_size) != st.st_size) {
                free(buf); close(fd); continue;
            }
            close(fd);

            Ehdr *eh = (Ehdr *)buf;
            if (memcmp(eh->e_ident, ELFMAG, SELFMAG) != 0) {
                free(buf); continue;
            }

            /* Find .gnu.linkonce.this_module and its rela section */
            Shdr *this_mod = elf_find_section(buf, eh, ".gnu.linkonce.this_module");
            Shdr *rela = elf_find_section(buf, eh, ".rela.gnu.linkonce.this_module");
            if (!this_mod || !rela || rela->sh_entsize == 0) {
                free(buf); continue;
            }

            uint32_t mod_size = (uint32_t)this_mod->sh_size;
            uint32_t init_off = 0, exit_off = 0;
            size_t nrela = rela->sh_size / rela->sh_entsize;
            Shdr *strtab = NULL;
            Shdr *symtab = NULL;
            /* Find the symtab linked from rela */
            if (rela->sh_link < eh->e_shnum) {
                symtab = (Shdr *)(buf + eh->e_shoff + rela->sh_link * eh->e_shentsize);
                if (symtab->sh_link < eh->e_shnum)
                    strtab = (Shdr *)(buf + eh->e_shoff + symtab->sh_link * eh->e_shentsize);
            }

            for (size_t i = 0; i < nrela && symtab && strtab; i++) {
                Elf64_Rela *r = (Elf64_Rela *)(buf + rela->sh_offset + i * rela->sh_entsize);
                uint32_t sym_idx = ELF64_R_SYM(r->r_info);
                if (sym_idx == 0) continue;
                Elf64_Sym *sym = (Elf64_Sym *)(buf + symtab->sh_offset +
                                               sym_idx * symtab->sh_entsize);
                const char *name = (const char *)(buf + strtab->sh_offset + sym->st_name);
                if (strcmp(name, "init_module") == 0)
                    init_off = (uint32_t)r->r_offset;
                else if (strcmp(name, "cleanup_module") == 0)
                    exit_off = (uint32_t)r->r_offset;
            }

            free(buf);
            if (init_off && exit_off) {
                out->mod_size = mod_size;
                out->init_off = init_off;
                out->exit_off = exit_off;
                closedir(d);
                fprintf(stderr,
                    "kmod_loader: vendor introspect %s: size=0x%x init=0x%x exit=0x%x\n",
                    ent->d_name, mod_size, init_off, exit_off);
                return 0;
            }
        }
        closedir(d);
    }
    return -1;
}

/* ---- Resolve init/exit offsets (tiered: CLI → vendor → preset → cache → disasm → probe) ---- */

static struct kver_preset resolve_offsets(const char *self_path, int kmajor, int kminor,
                                          uint32_t cli_init, uint32_t cli_exit,
                                          int force_probe,
                                          uint8_t *mod, size_t mod_size,
                                          const Ehdr *eh, const char *params)
{
    struct utsname u;
    uname(&u);
    uint32_t vhash = hash_version(u.release);
    struct kver_preset result = {kmajor, kminor, 0, 0, 0};

    /* Tier 0: CLI override (still look up mod_size from preset/vendor) */
    if (cli_init && cli_exit) {
        result.init_off = cli_init;
        result.exit_off = cli_exit;
        /* Try to get mod_size from vendor introspection or preset */
        struct kver_preset vendor = {kmajor, kminor, 0, 0, 0};
        if (introspect_vendor_module(&vendor) == 0) {
            result.mod_size = vendor.mod_size;
        } else {
            const struct kver_preset *p = find_preset(kmajor, kminor);
            if (p) result.mod_size = p->mod_size;
        }
        fprintf(stderr, "kmod_loader: CLI offsets init=0x%x exit=0x%x\n",
                result.init_off, result.exit_off);
        return result;
    }

    /* Tier 1: Vendor module introspection (most accurate for physical devices).
     * Read a vendor .ko's ELF to determine the actual struct module layout.
     * This handles devices where GKI presets don't match (e.g. Pixel kernels). */
    {
        struct kver_preset vendor = {kmajor, kminor, 0, 0, 0};
        if (introspect_vendor_module(&vendor) == 0) {
            result = vendor;
            return result;
        }
    }

    /* Tier 2: Preset table (verified for GKI/AVD kernels) */
    const struct kver_preset *preset = find_preset(kmajor, kminor);
    if (preset && !force_probe) {
        result = *preset;
        fprintf(stderr, "kmod_loader: preset %d.%d: size=0x%x init=0x%x exit=0x%x\n",
                preset->major, preset->minor,
                preset->mod_size, preset->init_off, preset->exit_off);
        return result;
    }

    /* Tier 3: Persistent cache (for kernels without preset) */
    probe_load(self_path);
    if (!force_probe && g_probe.magic == PROBE_MAGIC &&
        g_probe.confirmed && g_probe.version_hash == vhash) {
        result.init_off = g_probe.found_init;
        result.exit_off = g_probe.found_exit;
        fprintf(stderr, "kmod_loader: cached offsets init=0x%x exit=0x%x\n",
                result.init_off, result.exit_off);
        return result;
    }

    /* (preset already checked in Tier 2) */

    /* Tier 4: Disassembly */
    uint32_t disasm_init = 0;
    if (probe_init_offset_disasm(&disasm_init) == 0 && disasm_init) {
        result.init_off = disasm_init;
        result.exit_off = cli_exit ? cli_exit : (find_nearest_preset(kmajor, kminor) ?
                              find_nearest_preset(kmajor, kminor)->exit_off : 0x3c8);
        g_probe.version_hash = vhash;
        g_probe.found_init = result.init_off;
        g_probe.found_exit = result.exit_off;
        g_probe.confirmed = 1;
        probe_persist(self_path);
        fprintf(stderr, "kmod_loader: disasm init=0x%x exit=0x%x\n",
                result.init_off, result.exit_off);
        return result;
    }

    /* Tier 5: Binary probe */
    if (force_probe) {
        /* --probe: reset persistent state to re-probe all candidates */
        memset(&g_probe, 0, sizeof(g_probe));
        g_probe.probing_idx = PROBE_IDLE;
    }
    uint32_t probe_init = 0;
    if (probe_init_offset_binary(self_path, mod, mod_size, eh, params,
                                 &probe_init) == 0 && probe_init) {
        result.init_off = probe_init;
        result.exit_off = cli_exit ? cli_exit : (find_nearest_preset(kmajor, kminor) ?
                              find_nearest_preset(kmajor, kminor)->exit_off : 0x3c8);
        g_probe.version_hash = vhash;
        g_probe.found_init = result.init_off;
        g_probe.found_exit = result.exit_off;
        g_probe.confirmed = 1;
        probe_persist(self_path);
        fprintf(stderr, "kmod_loader: probed init=0x%x exit=0x%x\n",
                result.init_off, result.exit_off);
        return result;
    }

    /* Fallback: use whatever we have */
    if (cli_init) result.init_off = cli_init;
    if (cli_exit) result.exit_off = cli_exit;
    if (!result.init_off)
        fprintf(stderr, "kmod_loader: WARNING: could not determine init offset. "
                "Use --init-off 0xHEX\n");
    return result;
}

/* ---- kallsyms auto-discovery ----
 *
 * Reads /proc/kallsyms and returns the address of `kallsyms_lookup_name`.
 * The loader must already be running as root (init_module / finit_module
 * requires CAP_SYS_MODULE), so /proc/kallsyms is readable with unmasked
 * addresses provided kptr_restrict <= 1. Returns 0 on failure; caller
 * can override with kallsyms_addr=0xHEX on the CLI.
 */
uint64_t auto_fetch_kallsyms_addr(void)
{
    FILE *fp = fopen("/proc/kallsyms", "r");
    if (!fp) {
        fprintf(stderr, "kmod_loader: cannot open /proc/kallsyms: %s\n",
                strerror(errno));
        return 0;
    }
    char line[512];
    uint64_t addr = 0;
    while (fgets(line, sizeof(line), fp)) {
        /* format: "ffffffc010123456 T kallsyms_lookup_name\n" */
        char type;
        uint64_t a;
        char name[256];
        if (sscanf(line, "%lx %c %255s", &a, &type, name) == 3 &&
            strcmp(name, "kallsyms_lookup_name") == 0) {
            addr = a;
            break;
        }
    }
    fclose(fp);
    if (addr) {
        fprintf(stderr, "kmod_loader: auto-fetched kallsyms_lookup_name=0x%lx\n",
                (unsigned long)addr);
    } else {
        fprintf(stderr, "kmod_loader: /proc/kallsyms exposes no unmasked "
                        "symbols (kptr_restrict?)\n");
    }
    return addr;
}

/* ---- Argv → resolve_ctx_t (Plan 2 M-C T13) ----
 *
 * Behavior-neutral helper: parses the same argv flags that main() has always
 * parsed and populates a resolve_ctx_t. Added as a standalone helper in this
 * commit so reviewers can diff it in isolation; it is wired into main() in a
 * later commit. No existing call site is touched.
 *
 * Returns 0 on success, non-zero on unrecoverable parse error. Fills:
 *   *out_ctx       — populated ctx (kmajor/kminor/uname_release, CLI flags)
 *   *out_mod_path  — argv[1]
 *   params[]       — concatenated module param string (kallsyms_addr= stripped)
 *   *out_have_k    — 1 if kallsyms_addr= was intercepted from argv
 *   *out_kaddr     — value for kallsyms_addr if intercepted
 *   *out_force_probe — 1 if --probe was passed
 *   *out_cli_mod_size — 0 or parsed --mod-size value
 */
static int build_ctx_from_argv(int argc, char *argv[],
                               resolve_ctx_t *out_ctx,
                               const char **out_mod_path,
                               char *params, size_t params_sz,
                               int *out_have_k, uint64_t *out_kaddr,
                               int *out_force_probe, uint32_t *out_cli_mod_size)
{
    memset(out_ctx, 0, sizeof(*out_ctx));
    params[0] = '\0';
    *out_have_k = 0;
    *out_kaddr = 0;
    *out_force_probe = 0;
    *out_cli_mod_size = 0;

    if (argc < 2) return -1;
    *out_mod_path = argv[1];

    /* Kernel identity */
    struct utsname u;
    if (uname(&u) == 0) {
        strncpy(out_ctx->uname_release, u.release, sizeof(out_ctx->uname_release) - 1);
        sscanf(u.release, "%d.%d", &out_ctx->kmajor, &out_ctx->kminor);
    }

    for (int i = 2; i < argc; i++) {
        if (strncmp(argv[i], "--init-off", 10) == 0) {
            const char *val = NULL;
            if (argv[i][10] == '=') val = &argv[i][11];
            else if (argv[i][10] == '\0' && i + 1 < argc) val = argv[++i];
            if (val) {
                uint32_t v = 0;
                sscanf(val, "0x%x", &v);
                if (v) {
                    out_ctx->have_module_init_offset = 1;
                    out_ctx->cli_module_init_offset = v;
                }
            }
            continue;
        }
        if (strncmp(argv[i], "--exit-off", 10) == 0) {
            const char *val = NULL;
            if (argv[i][10] == '=') val = &argv[i][11];
            else if (argv[i][10] == '\0' && i + 1 < argc) val = argv[++i];
            if (val) {
                uint32_t v = 0;
                sscanf(val, "0x%x", &v);
                if (v) {
                    out_ctx->have_module_exit_offset = 1;
                    out_ctx->cli_module_exit_offset = v;
                }
            }
            continue;
        }
        if (strcmp(argv[i], "--probe") == 0) {
            *out_force_probe = 1;
            continue;
        }
        if (strncmp(argv[i], "--mod-size", 10) == 0) {
            const char *val = NULL;
            if (argv[i][10] == '=') val = &argv[i][11];
            else if (argv[i][10] == '\0' && i + 1 < argc) val = argv[++i];
            if (val) {
                uint32_t v = 0;
                sscanf(val, "0x%x", &v);
                if (v) {
                    *out_cli_mod_size = v;
                    out_ctx->have_this_module_size = 1;
                    out_ctx->cli_this_module_size = v;
                }
            }
            continue;
        }
        if (strncmp(argv[i], "--device", 8) == 0) {
            const char *val = NULL;
            if (argv[i][8] == '=') val = &argv[i][9];
            else if (argv[i][8] == '\0' && i + 1 < argc) val = argv[++i];
            if (val) out_ctx->device_override = val;
            continue;
        }
        if (strcmp(argv[i], "--no-probe") == 0)    { out_ctx->no_probe = 1; continue; }
        if (strcmp(argv[i], "--no-config") == 0)   { out_ctx->no_config = 1; continue; }
        if (strcmp(argv[i], "--strict-config") == 0) { out_ctx->strict_config = 1; continue; }
        if (strcmp(argv[i], "--prefer-config") == 0) { out_ctx->prefer_config = 1; continue; }

        if (strncmp(argv[i], "--crc", 5) == 0) {
            const char *spec = NULL;
            if (argv[i][5] == '=') spec = &argv[i][6];
            else if (argv[i][5] == '\0' && i + 1 < argc) spec = argv[++i];
            if (spec) {
                /* Keep populating legacy crc_overrides[] so the existing
                 * crc_from_override() path still sees unknown-sym overrides. */
                if (num_crc_overrides < MAX_CRC_OVERRIDES) {
                    char name[56] = {0};
                    uint32_t crc = 0;
                    if (sscanf(spec, "%55[^=]=0x%x", name, &crc) == 2 ||
                        sscanf(spec, "%55[^=]=%u", name, &crc) == 2) {
                        strncpy(crc_overrides[num_crc_overrides].name, name, 55);
                        crc_overrides[num_crc_overrides].crc = crc;
                        num_crc_overrides++;

                        /* Mirror known CRCs into ctx so strategy_cli_override
                         * can return them via the resolver chain. */
                        if (strcmp(name, "module_layout") == 0) {
                            out_ctx->have_module_layout_crc = 1;
                            out_ctx->cli_module_layout_crc = crc;
                        } else if (strcmp(name, "_printk") == 0 ||
                                   strcmp(name, "printk") == 0) {
                            out_ctx->have_printk_crc = 1;
                            out_ctx->cli_printk_crc = crc;
                        } else if (strcmp(name, "memcpy") == 0) {
                            out_ctx->have_memcpy_crc = 1;
                            out_ctx->cli_memcpy_crc = crc;
                        } else if (strcmp(name, "memset") == 0) {
                            out_ctx->have_memset_crc = 1;
                            out_ctx->cli_memset_crc = crc;
                        }
                    }
                }
            }
            continue;
        }
        if (strncmp(argv[i], "kallsyms_addr=", 14) == 0) {
            uint64_t a = 0;
            sscanf(argv[i] + 14, "0x%lx", (unsigned long *)&a);
            if (!a) sscanf(argv[i] + 14, "%lu", (unsigned long *)&a);
            *out_kaddr = a;
            *out_have_k = 1;
            out_ctx->have_kallsyms_addr = 1;
            out_ctx->cli_kallsyms_addr = a;
            continue;
        }
        if (params[0]) strlcat(params, " ", params_sz);
        strlcat(params, argv[i], params_sz);
    }
    return 0;
}

/* ---- Main ---- */

int main(int argc, char *argv[])
{
    if (argc < 2) {
        fprintf(stderr,
            "Usage: %s <module.ko> [--init-off 0xHEX] [--exit-off 0xHEX]\n"
            "       [--probe] [--crc sym=0xHEX ...] [param=value ...]\n",
            argv[0]);
        return 1;
    }

    /* Parse --crc overrides and module parameters via the resolver ctx
     * helper (Plan 2 M-C T13). kallsyms_addr=0xHEX is intercepted and
     * patched directly into the ELF (avoids module_param callbacks that
     * trigger CFI on shadow-CFI kernels). */
    char params[4096] = "";
    uint64_t kallsyms_addr = 0;
    int have_kallsyms_addr = 0;
    uint32_t cli_mod_size = 0;
    int force_probe = 0;
    resolve_ctx_t ctx;
    const char *mod_path = NULL;
    if (build_ctx_from_argv(argc, argv, &ctx, &mod_path,
                            params, sizeof(params),
                            &have_kallsyms_addr, &kallsyms_addr,
                            &force_probe, &cli_mod_size) != 0) {
        fprintf(stderr, "kmod_loader: argv parse failed\n");
        return 1;
    }

    /* Trace buffer for resolver calls; dumped on verbose paths (future). */
    trace_entry_t trace[VAL__COUNT * 2];
    int trace_count = 0;
    (void)force_probe; /* force_probe currently re-entered via resolver probe chain */

    /* Read module binary */
    int fd = open(argv[1], O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        fprintf(stderr, "open(%s): %s\n", argv[1], strerror(errno));
        return 1;
    }

    struct stat st;
    if (fstat(fd, &st) < 0) {
        fprintf(stderr, "fstat: %s\n", strerror(errno));
        close(fd);
        return 1;
    }

    /* Allocate with extra room for section expansion */
    size_t alloc_size = st.st_size + 0x200;
    uint8_t *mod = calloc(1, alloc_size);
    if (!mod) {
        close(fd);
        return 1;
    }

    if (read(fd, mod, st.st_size) != st.st_size) {
        fprintf(stderr, "read: %s\n", strerror(errno));
        free(mod);
        close(fd);
        return 1;
    }
    close(fd);

    size_t mod_size = alloc_size;
    Ehdr *eh = (Ehdr *)mod;

    /* Validate ELF */
    if (memcmp(eh->e_ident, ELFMAG, SELFMAG) != 0 || eh->e_machine != EM_AARCH64) {
        fprintf(stderr, "Not an ARM64 ELF module\n");
        free(mod);
        return 1;
    }

    /* Disable kptr_restrict to read kallsyms */
    FILE *kptr = fopen("/proc/sys/kernel/kptr_restrict", "w");
    if (kptr) { fputs("0", kptr); fclose(kptr); }

    /* Determine kernel version */
    int kmajor = ctx.kmajor, kminor = ctx.kminor;
    if (!kmajor) parse_kver(&kmajor, &kminor);
    fprintf(stderr, "kmod_loader: kernel %d.%d\n", kmajor, kminor);

    /* Hand the loaded ELF to the resolver ctx so probe_binary_search and
     * strategies that inspect the module buffer can do their job. */
    ctx.mod_buf  = mod;
    ctx.mod_size = mod_size;
    ctx.mod_eh   = eh;

    /* Quick path: check if vermagic already matches. If so, skip all patching. */
    {
        Shdr *mi = elf_find_section(mod, eh, ".modinfo");
        const char *target_vm = get_vermagic();
        int vm_match = 0;
        if (mi && target_vm) {
            uint8_t *base = mod + mi->sh_offset;
            uint8_t *mend = base + mi->sh_size;
            for (uint8_t *p = base; p < mend; ) {
                if (strncmp((char *)p, "vermagic=", 9) == 0) {
                    if (strstr((char *)p + 9, target_vm) || strncmp((char *)p + 9, target_vm, strlen(target_vm)) == 0)
                        vm_match = 1;
                    break;
                }
                p += strlen((char *)p) + 1;
            }
        }
        if (vm_match) {
            fprintf(stderr, "kmod_loader: vermagic matches, loading directly\n");
            int ret = (int)syscall(__NR_init_module, mod, (unsigned long)st.st_size, params);
            if (ret == 0) {
                printf("Module %s loaded (init_module, no patching)\n", argv[1]);
                free(mod);
                return 0;
            }
            fprintf(stderr, "kmod_loader: direct load failed: %s (errno=%d), trying patches\n",
                    strerror(errno), errno);
        }
    }

    /* Step 1: Patch vermagic via resolver */
    patch_vermagic_via_resolver(mod, eh, &ctx, trace, &trace_count);

    /* Step 2: Patch printk symbol name (_printk vs printk) */
    patch_printk_symbol(mod, eh);

    /* Step 3: Resolve init/exit offsets + this_module size via resolver. */
    struct kver_preset resolved = { kmajor, kminor, 0, 0, 0 };
    {
        trace_entry_t t;
        resolved_t r;

        r = resolve(VAL_MODULE_INIT_OFFSET, &ctx, &t);
        if (trace_count < (int)(sizeof(trace)/sizeof(trace[0]))) trace[trace_count++] = t;
        if (r.available) resolved.init_off = (uint32_t)r.u64_val;

        r = resolve(VAL_MODULE_EXIT_OFFSET, &ctx, &t);
        if (trace_count < (int)(sizeof(trace)/sizeof(trace[0]))) trace[trace_count++] = t;
        if (r.available) resolved.exit_off = (uint32_t)r.u64_val;

        r = resolve(VAL_THIS_MODULE_SIZE, &ctx, &t);
        if (trace_count < (int)(sizeof(trace)/sizeof(trace[0]))) trace[trace_count++] = t;
        if (r.available) resolved.mod_size = (uint32_t)r.u64_val;
    }

    /* Patch struct module layout using resolved offsets */
    if (cli_mod_size) resolved.mod_size = cli_mod_size;
    if (resolved.init_off) {
        if (!resolved.mod_size) {
            Shdr *this_mod = elf_find_section(mod, eh, ".gnu.linkonce.this_module");
            resolved.mod_size = this_mod ? (uint32_t)this_mod->sh_size : 0;
        }
        patch_module_layout(mod, mod_size, eh, &resolved);
    }

    /* Step 3.5: Patch kallsyms_addr directly into ELF data section.
     * This bypasses module_param, avoiding CFI indirect-call checks
     * on shadow-CFI (5.10) kernels.
     *
     * If the user didn't pass kallsyms_addr= on the CLI, try to auto-fetch
     * kallsyms_lookup_name from /proc/kallsyms. This removes a manual step
     * for the common case. Failure is non-fatal — the loader still runs
     * and lets the in-kernel init report the missing symbol. */
    if (!have_kallsyms_addr) {
        trace_entry_t t;
        resolved_t r = resolve(VAL_KALLSYMS_LOOKUP_NAME_ADDR, &ctx, &t);
        if (trace_count < (int)(sizeof(trace)/sizeof(trace[0]))) trace[trace_count++] = t;
        if (r.available && r.u64_val) {
            kallsyms_addr = r.u64_val;
            have_kallsyms_addr = 1;
        } else {
            fprintf(stderr, "kmod_loader: WARNING: no kallsyms_addr= given and "
                            "auto-fetch failed; pass kallsyms_addr=0xHEX manually\n");
        }
    }
    if (have_kallsyms_addr && kallsyms_addr) {
        if (patch_elf_symbol(mod, alloc_size, eh, "kallsyms_addr", kallsyms_addr) == 0)
            fprintf(stderr, "kmod_loader: patched kallsyms_addr=0x%lx in ELF\n",
                    (unsigned long)kallsyms_addr);
        else
            fprintf(stderr, "kmod_loader: WARNING: could not patch kallsyms_addr\n");
    }

    /* Note: cfi_check is now handled at compile time via MODULE_CFI_CHECK_OFFSET
     * in shim.h — no runtime injection needed. */

    /* Step 4: Try to patch CRCs via the resolver framework. */
    patch_crcs_via_resolver(mod, eh, &ctx, trace, &trace_count);

    /* Step 4.5: Patch kCFI hashes from vendor .ko (for CONFIG_CFI_ICALL_NORMALIZE_INTEGERS).
     * Only applicable to 6.1+ kernels which use kCFI; pre-6.1 uses shadow CFI. */
    if (kmajor > 6 || (kmajor == 6 && kminor >= 1))
        patch_kcfi_hashes(mod, mod_size, eh);

    /* Step 5: Try finit_module with IGNORE flags (bypasses CRC/vermagic on supported kernels) */
    {
        char tmppath[] = "/data/local/tmp/.kmod_XXXXXX";
        int tmpfd = mkstemp(tmppath);
        if (tmpfd >= 0) {
            if (write(tmpfd, mod, st.st_size) == (ssize_t)st.st_size) {
                close(tmpfd);
                tmpfd = open(tmppath, O_RDONLY | O_CLOEXEC);
                if (tmpfd >= 0) {
                    int flags = MODULE_INIT_IGNORE_MODVERSIONS | MODULE_INIT_IGNORE_VERMAGIC;
                    int ret = (int)syscall(__NR_finit_module, tmpfd, params, flags);
                    int err = errno;
                    close(tmpfd);
                    unlink(tmppath);
                    if (ret == 0) {
                        printf("Module %s loaded (finit_module)\n", argv[1]);
                        free(mod);
                        return 0;
                    }
                    fprintf(stderr, "kmod_loader: finit_module: %s (errno=%d)\n",
                            strerror(err), err);
                } else {
                    close(tmpfd);
                }
            } else {
                close(tmpfd);
            }
            unlink(tmppath);
        }
    }

    /* Step 6: Fallback — init_module with patched binary */
    fprintf(stderr, "kmod_loader: trying init_module (size=%lu, alloc=%zu)\n",
            (unsigned long)st.st_size, mod_size);
    int ret = (int)syscall(__NR_init_module, mod, (unsigned long)st.st_size, params);
    int err = errno;
    free(mod);

    if (ret != 0) {
        fprintf(stderr, "kmod_loader: init_module: %s (errno=%d)\n", strerror(err), err);
        return 1;
    }

    printf("Module %s loaded (init_module, patched)\n", argv[1]);
    return 0;
}
