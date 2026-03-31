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

#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/utsname.h>
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

static const struct kver_preset presets[] = {
    { 5, 4,  0x340, 0x140, 0x2d8 },
    { 5, 10, 0x380, 0x158, 0x310 },
    { 5, 15, 0x3c0, 0x160, 0x358 },
    { 6, 1,  0x440, 0x170, 0x3d8 },
    { 6, 6,  0x460, 0x178, 0x3f0 },
    { 6, 12, 0x480, 0x180, 0x408 },
};
#define NUM_PRESETS (sizeof(presets) / sizeof(presets[0]))

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

static const char *get_vermagic(void)
{
    static char vm[256];
    struct utsname u;
    if (uname(&u) < 0) return NULL;

    /* Common GKI vermagic flags. TODO: detect from loaded modules. */
    snprintf(vm, sizeof(vm), "%s SMP preempt mod_unload modversions aarch64", u.release);
    return vm;
}

/* ---- Find best preset for kernel version ---- */

static const struct kver_preset *find_preset(int major, int minor)
{
    const struct kver_preset *best = NULL;
    for (int i = 0; i < (int)NUM_PRESETS; i++) {
        if (presets[i].major < major ||
            (presets[i].major == major && presets[i].minor <= minor)) {
            best = &presets[i];
        }
    }
    return best;
}

/* ---- CRC extraction from kernel Image ---- */

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

/* Read raw bytes from a block device or file at a given offset */
static ssize_t read_at(const char *path, void *buf, size_t len, off_t offset)
{
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    if (lseek(fd, offset, SEEK_SET) < 0) { close(fd); return -1; }
    ssize_t n = read(fd, buf, len);
    close(fd);
    return n;
}

/* Try to find and read the kernel Image from boot partition.
 * Returns malloc'd decompressed image, or NULL. */
static uint8_t *read_kernel_image(size_t *out_size)
{
    /* Common boot partition paths */
    static const char *boot_paths[] = {
        "/dev/block/by-name/boot",
        "/dev/block/bootdevice/by-name/boot",
        "/dev/block/platform/*/by-name/boot",
        NULL
    };

    /* Also check if kernel-ranchu is available (emulator) */
    const char *path = NULL;
    struct stat st;

    for (int i = 0; boot_paths[i]; i++) {
        if (stat(boot_paths[i], &st) == 0) {
            path = boot_paths[i];
            break;
        }
    }

    if (!path) {
        fprintf(stderr, "kmod_loader: no boot partition found for CRC extraction\n");
        return NULL;
    }

    /* Read boot image header to find kernel offset and size.
     * Android boot image v2/v3/v4 header: magic at offset 0 = "ANDROID!" */
    uint8_t hdr[4096];
    if (read_at(path, hdr, sizeof(hdr), 0) < (ssize_t)sizeof(hdr))
        return NULL;

    if (memcmp(hdr, "ANDROID!", 8) != 0) {
        fprintf(stderr, "kmod_loader: not an Android boot image\n");
        return NULL;
    }

    /* Boot image v0-v2: kernel_size at offset 8, kernel starts at page_size */
    uint32_t kernel_size = *(uint32_t *)(hdr + 8);
    uint32_t page_size = *(uint32_t *)(hdr + 36);
    if (!kernel_size || !page_size) return NULL;

    fprintf(stderr, "kmod_loader: boot image kernel_size=%u page_size=%u\n",
            kernel_size, page_size);

    uint8_t *kernel = malloc(kernel_size);
    if (!kernel) return NULL;

    if (read_at(path, kernel, kernel_size, page_size) != (ssize_t)kernel_size) {
        free(kernel);
        return NULL;
    }

    /* Check if it's a gzip-compressed Image */
    if (kernel[0] == 0x1f && kernel[1] == 0x8b) {
        /* TODO: decompress gzip. For now, skip. */
        fprintf(stderr, "kmod_loader: kernel is gzip-compressed (not yet supported)\n");
        free(kernel);
        return NULL;
    }

    /* Raw ARM64 Image: magic "ARM\x64" at offset 56 */
    if (kernel_size > 64 && memcmp(kernel + 56, "ARM\x64", 4) == 0) {
        *out_size = kernel_size;
        return kernel;
    }

    fprintf(stderr, "kmod_loader: unrecognized kernel format\n");
    free(kernel);
    return NULL;
}

/* Extract CRC for a symbol from ksymtab/kcrctab in the kernel Image */
static int extract_crc(const uint8_t *img, size_t img_size,
                       uint64_t text_va, uint64_t ksymtab_va, uint64_t kcrctab_va,
                       uint64_t ksymtab_end_va, const char *sym_name, uint32_t *out_crc)
{
    uint64_t ksymtab_off = ksymtab_va - text_va;
    uint64_t kcrctab_off = kcrctab_va - text_va;
    uint64_t ksymtab_end = ksymtab_end_va - text_va;
    int num_entries = (ksymtab_end - ksymtab_off) / 12;

    for (int i = 0; i < num_entries; i++) {
        uint64_t off = ksymtab_off + (uint64_t)i * 12;
        if (off + 12 > img_size) break;

        int32_t val_off, name_off;
        memcpy(&val_off, img + off, 4);
        memcpy(&name_off, img + off + 4, 4);

        uint64_t name_addr = off + 4 + (int64_t)name_off;
        if (name_addr >= img_size) continue;

        const char *name = (const char *)(img + name_addr);
        if (strcmp(name, sym_name) == 0) {
            uint64_t crc_off = kcrctab_off + (uint64_t)i * 4;
            if (crc_off + 4 > img_size) return -1;
            memcpy(out_crc, img + crc_off, 4);
            return 0;
        }
    }
    return -1;
}

/* Try to extract and patch CRC values in the module's __versions section */
static int patch_crcs(uint8_t *mod, const Ehdr *eh)
{
    Shdr *ver = elf_find_section(mod, eh, "__versions");
    if (!ver || ver->sh_size == 0) return 0; /* no __versions, skip */

    /* Get kernel symbol addresses */
    uint64_t text_va = ksym_addr("_text");
    uint64_t ksymtab_va = ksym_addr("__start___ksymtab");
    uint64_t ksymtab_end = ksym_addr("__stop___ksymtab");
    uint64_t kcrctab_va = ksym_addr("__start___kcrctab");

    if (!text_va || !ksymtab_va || !ksymtab_end || !kcrctab_va) {
        fprintf(stderr, "kmod_loader: cannot find ksymtab addresses in kallsyms\n");
        return -1;
    }

    /* Read kernel Image */
    size_t img_size = 0;
    uint8_t *img = read_kernel_image(&img_size);
    if (!img) {
        fprintf(stderr, "kmod_loader: cannot read kernel image for CRC extraction\n");
        return -1;
    }

    /* Also resolve GPL ksymtab/kcrctab (once, outside the loop) */
    uint64_t ksymtab_gpl = ksym_addr("__start___ksymtab_gpl");
    uint64_t ksymtab_gpl_end = ksym_addr("__stop___ksymtab_gpl");
    uint64_t kcrctab_gpl = ksym_addr("__start___kcrctab_gpl");

    /* Patch each __versions entry */
    int patched = 0;
    int num_entries = ver->sh_size / 64;
    for (int i = 0; i < num_entries; i++) {
        uint8_t *ent = mod + ver->sh_offset + i * 64;
        const char *sym = (const char *)(ent + 8);
        uint32_t new_crc;

        if (extract_crc(img, img_size, text_va, ksymtab_va, kcrctab_va,
                        ksymtab_end, sym, &new_crc) == 0 ||
            (ksymtab_gpl && extract_crc(img, img_size, text_va, ksymtab_gpl,
                                        kcrctab_gpl, ksymtab_gpl_end, sym, &new_crc) == 0)) {
            uint32_t old_crc;
            memcpy(&old_crc, ent, 4);
            memcpy(ent, &new_crc, 4);
            fprintf(stderr, "kmod_loader: CRC %s: 0x%08x -> 0x%08x\n", sym, old_crc, new_crc);
            patched++;
        } else {
            fprintf(stderr, "kmod_loader: CRC %s: not found in kernel\n", sym);
        }
    }

    free(img);
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

    /* Patch relocation offsets for init/exit */
    if (rela && rela->sh_size >= 2 * sizeof(Rela)) {
        Rela *entries = (Rela *)(mod + rela->sh_offset);
        int num_rela = rela->sh_size / sizeof(Rela);

        for (int i = 0; i < num_rela; i++) {
            uint64_t old_off = entries[i].r_offset;
            /* Heuristic: init is at lower offset, exit at higher */
            if (old_off < new_size / 2) {
                /* This is the init relocation */
                if (old_off != preset->init_off) {
                    fprintf(stderr, "kmod_loader: init offset 0x%llx -> 0x%x\n",
                            (unsigned long long)old_off, preset->init_off);
                    entries[i].r_offset = preset->init_off;
                }
            } else {
                /* This is the exit relocation */
                if (old_off != preset->exit_off) {
                    fprintf(stderr, "kmod_loader: exit offset 0x%llx -> 0x%x\n",
                            (unsigned long long)old_off, preset->exit_off);
                    entries[i].r_offset = preset->exit_off;
                }
            }
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
        if (try_size < 0x200 || try_size > 0x600) continue;
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

/* ---- Main ---- */

int main(int argc, char *argv[])
{
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <module.ko> [param=value ...]\n", argv[0]);
        return 1;
    }

    /* Concatenate remaining args as module parameters */
    char params[4096] = "";
    for (int i = 2; i < argc; i++) {
        if (i > 2) strlcat(params, " ", sizeof(params));
        strlcat(params, argv[i], sizeof(params));
    }

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
    int kmajor = 0, kminor = 0;
    parse_kver(&kmajor, &kminor);
    fprintf(stderr, "kmod_loader: kernel %d.%d\n", kmajor, kminor);

    /* Find preset */
    const struct kver_preset *preset = find_preset(kmajor, kminor);
    if (!preset) {
        fprintf(stderr, "kmod_loader: no preset for kernel %d.%d, using defaults\n",
                kmajor, kminor);
    } else {
        fprintf(stderr, "kmod_loader: preset %d.%d: size=0x%x init=0x%x exit=0x%x\n",
                preset->major, preset->minor,
                preset->mod_size, preset->init_off, preset->exit_off);
    }

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

    /* Step 1: Patch vermagic */
    patch_vermagic(mod, eh);

    /* Step 2: Patch printk symbol name (_printk vs printk) */
    patch_printk_symbol(mod, eh);

    /* Step 3: Patch struct module layout (only if size mismatch) */
    if (preset) {
        Shdr *this_mod = elf_find_section(mod, eh, ".gnu.linkonce.this_module");
        uint32_t cur_size = this_mod ? (uint32_t)this_mod->sh_size : 0;

        if (cur_size != preset->mod_size) {
            fprintf(stderr, "kmod_loader: module size 0x%x != preset 0x%x, patching...\n",
                    cur_size, preset->mod_size);
            /* Probe exact size */
            uint32_t exact = probe_mod_size(mod, mod_size, eh, params, preset->mod_size);
            struct kver_preset actual = *preset;
            actual.mod_size = exact;
            patch_module_layout(mod, mod_size, eh, &actual);
        } else {
            fprintf(stderr, "kmod_loader: struct module size matches (0x%x)\n", cur_size);
        }
    }

    /* Step 4: Try to patch CRCs from kernel Image (best-effort) */
    patch_crcs(mod, eh);

    /* Step 5: Try finit_module with IGNORE flags (bypasses CRC/vermagic on supported kernels) */
    {
        char tmppath[] = "/data/local/tmp/.kmod_XXXXXX";
        int tmpfd = mkstemp(tmppath);
        if (tmpfd >= 0) {
            if (write(tmpfd, mod, st.st_size) == st.st_size) {
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
