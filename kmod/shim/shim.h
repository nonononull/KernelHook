/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Minimal kernel shims for freestanding .ko build (Approach B).
 *
 * Replaces <linux/module.h>, <linux/kernel.h>, etc. for builds
 * that don't have access to the kernel source tree.
 *
 * The module loader only needs:
 *   - .modinfo section entries (license, description, etc.)
 *   - init_module / cleanup_module symbols
 *   - Proper ELF relocatable format (ET_REL)
 */

#ifndef _SHIM_H_
#define _SHIM_H_

#ifndef KMOD_FREESTANDING
#error "shim.h is freestanding-only; kbuild code must include <linux/*> directly"
#endif

#include <types.h>

/* ---- .modinfo section entries ---- */

#define __MODULE_INFO(tag, name, info)                                  \
    static const char __UNIQUE_ID(name)[]                               \
        __used __section(".modinfo") __aligned(1) = #tag "=" info

#define __UNIQUE_ID(prefix) __PASTE(__PASTE(__unique_, prefix), __COUNTER__)
#define __PASTE(a, b) __PASTE2(a, b)
#define __PASTE2(a, b) a##b

#define MODULE_LICENSE(x)       __MODULE_INFO(license, license, x)
#define MODULE_AUTHOR(x)        __MODULE_INFO(author, author, x)
#define MODULE_DESCRIPTION(x)   __MODULE_INFO(description, description, x)
#define MODULE_PARM_DESC(parm, desc) __MODULE_INFO(parm, parm, #parm ":" desc)

/* ---- Module init/exit via aliases ---- */

#define module_init(fn) \
    int init_module(void) __attribute__((alias(#fn)));
#define module_exit(fn) \
    void cleanup_module(void) __attribute__((alias(#fn)));

/* THIS_MODULE — pointer to this module's struct module instance.
 * In freestanding builds, __this_module is defined by MODULE_THIS_MODULE()
 * (called from the main translation unit). We expose it as extern here and
 * define THIS_MODULE as &__this_module, matching the real kernel macro from
 * include/linux/export.h. */
struct module;
extern struct module __this_module;
#ifndef THIS_MODULE
#define THIS_MODULE (&__this_module)
#endif

/* ---- Module parameter ----
 *
 * Freestanding module_param implementation. The kernel's parse_args()
 * iterates the __param section looking for matching kernel_param entries.
 * Each entry has a name, a set callback, and a pointer to the variable.
 *
 * We only support 'ulong' type (enough for kallsyms_addr). The set
 * callback must be resolved at runtime via ksyms because param_set_ulong
 * is not exported. Instead we provide a minimal inline parser.
 */

/* Minimal kernel_param struct (must match kernel's layout exactly).
 * See include/linux/moduleparam.h in kernel source. */
struct kernel_param;

/* param_set/get function pointer types */
typedef int (*param_set_fn)(const char *val, const struct kernel_param *kp);
typedef int (*param_get_fn)(char *buffer, const struct kernel_param *kp);

struct kernel_param_ops {
    unsigned int flags;
    param_set_fn set;
    param_get_fn get;
    void (*free)(void *arg);
};

struct kernel_param {
    const char *name;
    struct module *mod;            /* unused in freestanding */
    const struct kernel_param_ops *ops;
    uint16_t perm;
    int8_t level;                  /* -1 = early, 0+ = normal */
    uint8_t flags;
    union {
        void *arg;
        const void *str;           /* kparam_string */
    };
};

/* Simple ulong parser for module_param(x, ulong, ...) */
static int __kmod_param_set_ulong(const char *val, const struct kernel_param *kp)
{
    unsigned long result = 0;
    const char *p = val;

    /* Skip leading whitespace */
    while (*p == ' ' || *p == '\t') p++;

    /* Parse hex (0x prefix) or decimal */
    if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X')) {
        p += 2;
        while (*p) {
            unsigned int digit;
            if (*p >= '0' && *p <= '9') digit = *p - '0';
            else if (*p >= 'a' && *p <= 'f') digit = *p - 'a' + 10;
            else if (*p >= 'A' && *p <= 'F') digit = *p - 'A' + 10;
            else break;
            result = (result << 4) | digit;
            p++;
        }
    } else {
        while (*p >= '0' && *p <= '9') {
            result = result * 10 + (*p - '0');
            p++;
        }
    }

    *(unsigned long *)kp->arg = result;
    return 0;
}

static const struct kernel_param_ops __kmod_param_ops_ulong = {
    .flags = 0,
    .set = __kmod_param_set_ulong,
    .get = (param_get_fn)0,
    .free = (void (*)(void *))0,
};

/* Helper macro to avoid C preprocessor expanding `name` in `.name = ...` */
#define __KMOD_PARAM(var_name, str_name, perm_val)                      \
    static const struct kernel_param __param_##var_name                  \
        __used __aligned(sizeof(void *))                                \
        __section("__param") = {                                        \
            .name = str_name,                                           \
            .mod = (struct module *)0,                                  \
            .ops = &__kmod_param_ops_ulong,                             \
            .perm = (perm_val),                                         \
            .level = -1,                                                \
            .flags = 0,                                                 \
            .arg = &var_name,                                           \
        }

#define module_param(name, type, perm)                                  \
    __MODULE_INFO(parmtype, name##type, #name ":" #type);               \
    __KMOD_PARAM(name, #name, perm)

/* ---- Kernel PAGE_SIZE ---- */
#ifndef PAGE_SIZE
#define PAGE_SIZE 4096UL
#endif

/* ---- printk / pr_xxx ---- */
#include <linux/printk.h>

/* ---- Minimal bool ---- */
#ifndef true
#define true 1
#endif
#ifndef false
#define false 0
#endif

/* ---- Minimal errno ---- */
#ifndef EINVAL
#define EINVAL 22
#endif
#ifndef ENOENT
#define ENOENT 2
#endif
#ifndef ENOMEM
#define ENOMEM 12
#endif

/* ---- memset / memcpy (compiler may lower __builtin_* to calls) ---- */
extern void *memset(void *s, int c, unsigned long n);
extern void *memcpy(void *dst, const void *src, unsigned long n);
extern void *memmove(void *dst, const void *src, unsigned long n);

/* ---- __init / __exit section attributes ---- */
#define __init __section(".init.text")
#define __exit __section(".exit.text")

/* ---- __versions (modversion CRC table) ----
 *
 * When CONFIG_MODVERSIONS=y the kernel checks CRCs for every imported
 * symbol against entries in the module's __versions section.  Missing
 * entries cause try_to_force_load() → -ENOEXEC (unless FORCE_LOAD=y).
 *
 * We must provide CRCs for:
 *   module_layout  — checked by check_modstruct_version()
 *   _printk        — called by pr_info/pr_err macros
 *   memcpy/memset  — compiler-generated calls from __builtin_*
 *
 * Extract CRCs from a vendor module:
 *   objcopy --dump-section __versions=/tmp/v vendor.ko
 *   python3 -c "import struct; d=open('/tmp/v','rb').read(); \
 *     [print(hex(struct.unpack('<I',d[i:i+4])[0]),d[i+8:i+64].split(b'\0')[0]) \
 *      for i in range(0,len(d),64)]"
 *
 * Plan 2 (runtime resolver + device database) makes these values
 * runtime-resolved. The .ko is built with placeholder sentinel values
 * (0xDEADBE01..04) which kmod_loader's resolver chain overwrites before
 * calling init_module. See tools/kmod_loader/resolver.{h,c} and
 * kmod/devices/ *.conf for the resolution path.
 *
 * The sentinels exist only so a mis-patched module fails LOUDLY with a
 * "disagrees about version" error instead of silently accepting random
 * garbage. The kernel's modversion check will reject these values and
 * surface the bug instead of misloading.
 */

struct modversion_info {
    unsigned int crc;
    unsigned int pad;
    char name[56];
};

#define _MODVER_ENTRY(var, crc_val, sym_name)                           \
    static const struct modversion_info var                              \
        __used __section("__versions") __aligned(8) = {                 \
            .crc = (crc_val), .pad = 0, .name = (sym_name),            \
        }

#define MODULE_VERSIONS()                                                     \
    _MODVER_ENTRY(__modver_module_layout, 0xDEADBE01u, "module_layout");      \
    _MODVER_ENTRY(__modver_printk,        0xDEADBE02u, "_printk");            \
    _MODVER_ENTRY(__modver_memcpy,        0xDEADBE03u, "memcpy");             \
    _MODVER_ENTRY(__modver_memset,        0xDEADBE04u, "memset");             \
    _MODVER_ENTRY(__modver_strcmp,        0xDEADBE05u, "strcmp");             \
    _MODVER_ENTRY(__modver_strncmp,       0xDEADBE06u, "strncmp");            \
    _MODVER_ENTRY(__modver_strchr,        0xDEADBE07u, "strchr");             \
    _MODVER_ENTRY(__modver_strlcpy,       0xDEADBE08u, "strlcpy");           \
    _MODVER_ENTRY(__modver_kstrtol,       0xDEADBE09u, "kstrtol");           \
    _MODVER_ENTRY(__modver_add_taint,     0xDEADBE0Au, "add_taint");         \
    _MODVER_ENTRY(__modver_memcmp,                   0xDEADBE0Bu, "memcmp");               \
    _MODVER_ENTRY(__modver_debugfs_create_dir,       0xDEADBE0Cu, "debugfs_create_dir");   \
    _MODVER_ENTRY(__modver_debugfs_create_file,      0xDEADBE0Du, "debugfs_create_file");  \
    _MODVER_ENTRY(__modver_copy_from_user,           0xDEADBE0Eu, "copy_from_user");       \
    _MODVER_ENTRY(__modver_copy_to_user,             0xDEADBE0Fu, "copy_to_user");         \
    _MODVER_ENTRY(__modver_debugfs_remove_recursive, 0xDEADBE10u, "debugfs_remove_recursive"); \
    _MODVER_ENTRY(__modver_snprintf,                 0xDEADBE11u, "snprintf")

/* ---- vermagic ---- */
#ifndef VERMAGIC_STRING
#define VERMAGIC_STRING "unknown SMP preempt mod_unload aarch64"
#endif

/*
 * MODULE_VERMAGIC — emit exactly once in the main translation unit.
 * Call this macro from test_main.c (not from a header included by
 * multiple .c files) to avoid duplicate .modinfo entries.
 */
/* Module name — needed by the kernel to name kobject/sysfs entries */
#ifndef MODULE_NAME
#define MODULE_NAME "kh_test"
#endif

/* Pad vermagic with trailing spaces so kmod_loader can replace it at load
 * time with any kernel's vermagic string (which may be longer than the
 * compiled-in value). The kernel's check_modinfo() uses strcmp on vermagic,
 * so the trailing spaces are not tolerated at match time — kmod_loader MUST
 * rewrite the slot before calling init_module. */
#define _KH_VM_PAD \
    "                                                                "

#define MODULE_VERMAGIC()                                               \
    __MODULE_INFO(vermagic, vermagic, VERMAGIC_STRING _KH_VM_PAD);       \
    __MODULE_INFO(name, modulename, MODULE_NAME)

/* Shadow-CFI permissive stub (CONFIG_CFI_CLANG + CONFIG_CFI_CLANG_SHADOW).
 *
 * On 5.4/5.10/5.15 GKI kernels, shadow-based CFI uses mod->cfi_check to
 * validate indirect calls into modules. find_module_sections() sets it by
 * looking up the GLOBAL symbol "__cfi_check" in the module's symtab. Without
 * it, any indirect call (including do_one_initcall → mod->init) panics with
 * "CFI failure (target: init_module)" in __cfi_slowpath.
 *
 * On 6.1+ kCFI kernels, this symbol is found but the field is unused — kCFI
 * validates calls via inline type-hash checks, not the shadow + callback
 * mechanism. So this stub is harmless (and redundant) on kCFI.
 *
 * Must be non-weak GLOBAL: 5.4 GKI's find_module_sections() skips weak
 * symbols when setting mod->cfi_check. Emitted via MODULE_THIS_MODULE() to
 * guarantee exactly one definition per module. */
#define MODULE_CFI_CHECK()                                                    \
    void __attribute__((used, visibility("default"), section(".text")))        \
    __cfi_check(unsigned long id, void *ptr, void *diag) { (void)id; (void)ptr; (void)diag; } \
    void __attribute__((weak, used, visibility("default"), section(".text")))  \
    __cfi_check_fail(void *data, void *ptr) { (void)data; (void)ptr; }

/*
 * MODULE_THIS_MODULE — define the __this_module symbol with init/exit
 * function pointers so the kernel module loader can call them.
 *
 * The kernel reads mod->init and mod->exit from __this_module, NOT
 * from the ELF symbol table.  Kbuild's modpost generates
 * .rela.gnu.linkonce.this_module with R_AARCH64_ABS64 relocations
 * for init_module at offset MODULE_INIT_OFFSET and cleanup_module
 * at offset MODULE_EXIT_OFFSET.  We replicate this by placing
 * function pointers at the correct struct offsets.
 *
 * Call this macro exactly once from test_main.c.
 */
/*
 * Struct offsets for GKI 6.1 ARM64 (sizeof(struct module) = 0x440):
 *   name[56]          @ offset 24   (MODULE_NAME_OFFSET)
 *   int (*init)(void) @ offset 0x170 (MODULE_INIT_OFFSET)
 *   void (*exit)(void)@ offset 0x3d8 (MODULE_EXIT_OFFSET)
 *
 * Override at build time: -DTHIS_MODULE_SIZE=0x440 etc.
 */
#ifndef THIS_MODULE_SIZE
#define THIS_MODULE_SIZE 0x800
#endif

#ifndef MODULE_NAME_OFFSET
#define MODULE_NAME_OFFSET 24
#endif

#ifndef MODULE_INIT_OFFSET
#define MODULE_INIT_OFFSET 0x170
#endif

#ifndef MODULE_EXIT_OFFSET
#define MODULE_EXIT_OFFSET 0x3d8
#endif

#define MODULE_THIS_MODULE()                                            \
    extern int  init_module(void);                                      \
    extern void cleanup_module(void);                                   \
    struct module {                                                     \
        char __pre_name[MODULE_NAME_OFFSET];                            \
        char name[56];                                                  \
        char __pad1[MODULE_INIT_OFFSET - MODULE_NAME_OFFSET - 56];     \
        int (*init)(void);                                              \
        char __pad2[MODULE_EXIT_OFFSET - MODULE_INIT_OFFSET - 8];      \
        void (*exit)(void);                                             \
        char __pad3[THIS_MODULE_SIZE - MODULE_EXIT_OFFSET - 8];        \
    };                                                                  \
    /* Use .kh.this_module instead of .gnu.linkonce.this_module to avoid
     * lld discarding the section during -r linking (linkonce semantics).
     * The linker script renames it to .gnu.linkonce.this_module. */     \
    struct module __this_module                                         \
        __used __aligned(64) __section(".kh.this_module") = {           \
            .__pre_name = {0},                                          \
            .name = MODULE_NAME,                                        \
            .init = init_module,                                        \
            .exit = cleanup_module,                                     \
        };                                                              \
    MODULE_CFI_CHECK();                                                 \
    /* Force a 1-byte _error_injection_whitelist section.                \
     * CONFIG_FUNCTION_ERROR_INJECTION kernels call                      \
     * populate_error_injection_list() which does section_objs() /       \
     * sizeof(struct error_injection_entry). Missing section causes a    \
     * NULL deref on some builds; emitting exactly 1 byte makes          \
     * section_objs() return 0 entries (1/sizeof(entry) = 0). */         \
    __asm__(".pushsection _error_injection_whitelist, \"aw\"\n"         \
            ".byte 0\n"                                                 \
            ".popsection\n");                                           \
    /* Shadow-CFI jump table stubs for 5.4/5.10/5.15 GKI.               \
     * The kernel's module loader replaces init_module/cleanup_module    \
     * function pointers with their .cfi_jt jump table entries when      \
     * applying relocations to .gnu.linkonce.this_module. Without these  \
     * symbols, mod->init is set to NULL and do_init_module → 0 deref. */\
    __asm__(                                                            \
        ".pushsection .text, \"ax\"\n"                                  \
        ".global init_module.cfi_jt\n"                                  \
        ".type init_module.cfi_jt, %function\n"                         \
        "init_module.cfi_jt: b init_module\n"                           \
        ".size init_module.cfi_jt, . - init_module.cfi_jt\n"           \
        ".global cleanup_module.cfi_jt\n"                               \
        ".type cleanup_module.cfi_jt, %function\n"                      \
        "cleanup_module.cfi_jt: b cleanup_module\n"                     \
        ".size cleanup_module.cfi_jt, . - cleanup_module.cfi_jt\n"     \
        ".popsection\n"                                                 \
    )

#endif /* _SHIM_H_ */
