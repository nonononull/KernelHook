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

#ifndef _KMOD_SHIM_H_
#define _KMOD_SHIM_H_

#include <ktypes.h>

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

/* ---- pr_info / pr_err ---- */
/*
 * Kernel 6.1+ exports _printk; older kernels export printk.
 * We extern _printk and provide a printk alias so that both
 * our code and the log subsystem (which calls printk) resolve
 * to the same symbol the kernel actually exports.
 */
extern int _printk(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
#define printk _printk

#define KERN_INFO    "\001" "6"
#define KERN_ERR     "\001" "3"
#define KERN_WARNING "\001" "4"

#define pr_info(fmt, ...)  _printk(KERN_INFO fmt, ##__VA_ARGS__)
#define pr_err(fmt, ...)   _printk(KERN_ERR fmt, ##__VA_ARGS__)
#define pr_warn(fmt, ...)  _printk(KERN_WARNING fmt, ##__VA_ARGS__)

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
 * Override at build time: -DMODULE_LAYOUT_CRC=0x... etc.
 */
#ifndef MODULE_LAYOUT_CRC
#define MODULE_LAYOUT_CRC 0xea759d7f  /* GKI 6.1, Pixel 6 default */
#endif
#ifndef PRINTK_CRC
#define PRINTK_CRC 0x92997ed8         /* GKI 6.1, Pixel 6 default */
#endif
#ifndef MEMCPY_CRC
#define MEMCPY_CRC 0x4829a47e         /* GKI 6.1, Pixel 6 default */
#endif
#ifndef MEMSET_CRC
#define MEMSET_CRC 0xdcb764ad         /* GKI 6.1, Pixel 6 default */
#endif

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

#define MODULE_VERSIONS()                                               \
    _MODVER_ENTRY(__modver_module_layout, MODULE_LAYOUT_CRC, "module_layout"); \
    _MODVER_ENTRY(__modver_printk,        PRINTK_CRC,        "_printk");       \
    _MODVER_ENTRY(__modver_memcpy,        MEMCPY_CRC,        "memcpy");        \
    _MODVER_ENTRY(__modver_memset,        MEMSET_CRC,        "memset")

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

/* Pad vermagic to ~160 bytes with trailing spaces so the loader can replace
 * it with any kernel's vermagic (which may be longer than the compiled-in
 * string). The kernel's check_modinfo() uses strcmp on vermagic, so spaces
 * would cause mismatch — the loader must patch vermagic before loading. */
#define _KH_VM_PAD \
    "                                                                "
#define MODULE_VERMAGIC()                                               \
    __MODULE_INFO(vermagic, vermagic, VERMAGIC_STRING _KH_VM_PAD);      \
    __MODULE_INFO(name, modulename, MODULE_NAME)

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
#define THIS_MODULE_SIZE 0x440
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
        }

#endif /* _KMOD_SHIM_H_ */
