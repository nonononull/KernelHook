/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Linker script for freestanding .ko build (Approach B).
 *
 * A .ko is an ET_REL (relocatable) ELF. We use ld -r (partial link)
 * so this script only orders sections — all relocations are preserved.
 */

SECTIONS
{
    .text : {
        *(.text .text.*)
    }

    .plt : {
        *(.plt)
    }

    .init.plt : {
        *(.init.plt)
    }

    .init.text : {
        *(.init.text)
    }

    .exit.text : {
        *(.exit.text)
    }

    .transit.data : {
        *(.transit.data)
    }

    .rodata : {
        *(.rodata .rodata.*)
    }

    .modinfo : {
        *(.modinfo)
    }

    __versions : {
        *(__versions)
    }

    __param : {
        __start___param = .;
        *(__param)
        __stop___param = .;
    }

    /* Link-time strategy registry — iterated via __start___kh_strategies /
       __stop___kh_strategies at module init by src/kh_strategy.c. Mirrors
       the equivalent section in kmod/lds/kmod.lds used by kernelhook.ko. */
    .kh_strategies : ALIGN(8) {
        __start___kh_strategies = .;
        KEEP(*(.kh_strategies))
        __stop___kh_strategies = .;
    }

    .gnu.linkonce.this_module : {
        *(.kh.this_module)
    }

    .data : {
        *(.data .data.*)
    }

    .bss : {
        *(.bss .bss.*)
    }

    /* Exception table: registered automatically by the kernel module loader
     * at insmod time. Contains PC-relative entries for fault sites in
     * kh_inline_copy_to/from_user (ldtr/sttr paths). Needed for inline
     * uaccess to survive bad user addresses gracefully. */
    __ex_table : ALIGN(4) {
        *(__ex_table)
    }

    /* KernelHook exports (freestanding EXPORT_SYMBOL via kh_crc).
     * Populated by kmod/generated/kh_exports.o, emitted by tools/kh_crc
     * from kmod/exports.manifest. See spec §6.5.
     * SORT ensures deterministic ordering by symbol name. */
    __ksymtab : ALIGN(8) {
        *(SORT(___ksymtab+*))
        *(__ksymtab)
    }
    __ksymtab_strings : {
        *(__ksymtab_strings)
    }
    __kcrctab : ALIGN(4) {
        *(SORT(___kcrctab+*))
        *(__kcrctab)
    }

    /* Required by CONFIG_FUNCTION_ERROR_INJECTION (5.4 GKI).
     * The kernel's ei_module_callback dereferences this section;
     * missing → NULL pointer oops in populate_error_injection_list. */
    _error_injection_whitelist : {
        *(_error_injection_whitelist)
    }

    /DISCARD/ : {
        *(.comment)
        *(.note.*)
    }
}
