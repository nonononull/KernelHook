# SPDX-License-Identifier: GPL-2.0-or-later
# kmod.mk — includable build fragment for KernelHook freestanding .ko modules
#
# Usage (explicit):
#   MODULE_NAME   := my_hook
#   MODULE_SRCS   := my_hook.c
#   KERNELHOOK_DIR := /path/to/KernelHook/kmod
#   include $(KERNELHOOK_DIR)/mk/kmod.mk
#
# Usage (Kbuild-style shorthand):
#   obj-m := my_hook.o
#   KERNELHOOK := /path/to/KernelHook/kmod
#   include $(KERNELHOOK)/mk/kmod.mk

# ---------- Directory layout ----------

# KERNELHOOK_DIR: the kmod/ directory inside the KernelHook tree.
# Allow users to set KERNELHOOK as an alias.
KERNELHOOK_DIR ?= $(KERNELHOOK)
ifeq ($(KERNELHOOK_DIR),)
  # Derive from this file's location: kmod/mk/kmod.mk -> kmod/
  KERNELHOOK_DIR := $(patsubst %/mk/kmod.mk,%,$(lastword $(MAKEFILE_LIST)))
endif

# KH_ROOT: the KernelHook project root (parent of kmod/).
KH_ROOT := $(KERNELHOOK_DIR)/..

# ---------- kh_crc tool & generated files ----------

KH_CRC       := $(KH_ROOT)/tools/kh_crc/kh_crc
KH_MANIFEST  := $(KH_ROOT)/kmod/exports.manifest
KH_GEN_DIR   := $(KERNELHOOK_DIR)/generated
KH_EXPORTS_S := $(KH_GEN_DIR)/kh_exports.S
KH_SYMVERS_H := $(KERNELHOOK_DIR)/include/kernelhook/kh_symvers.h

$(KH_CRC):
	$(MAKE) -C $(KH_ROOT)/tools/kh_crc

$(KH_GEN_DIR):
	mkdir -p $@

# KH_KSYMTAB_LAYOUT selects the on-disk __ksymtab layout:
#   prel32 (default) — 12-byte struct with PREL32 relocs. Matches kernels
#                      built with CONFIG_HAVE_ARCH_PREL32_RELOCATIONS=y (GKI
#                      6.1+ on arm64, modern upstream).
#   abs64            — 24-byte struct with ABS64 pointers. Required for
#                      kernels where HAVE_ARCH_PREL32_RELOCATIONS is OFF
#                      (e.g. Android 11 GKI 5.4). Mismatched layout causes
#                      strcmp crashes in find_symbol at load time.
KH_KSYMTAB_LAYOUT ?= prel32
ifeq ($(KH_KSYMTAB_LAYOUT),abs64)
  KH_CRC_ASM_MODE := asm-abs64
else
  KH_CRC_ASM_MODE := asm
endif

$(KH_EXPORTS_S): $(KH_CRC) $(KH_MANIFEST) | $(KH_GEN_DIR)
	$(KH_CRC) --mode=$(KH_CRC_ASM_MODE) --manifest=$(KH_MANIFEST) --output=$@

$(KH_SYMVERS_H): $(KH_CRC) $(KH_MANIFEST)
	$(KH_CRC) --mode=header --manifest=$(KH_MANIFEST) --output=$@

# Always lint export.c <-> manifest consistency before linking.
.PHONY: _kh_lint
_kh_lint:
	@$(KH_ROOT)/scripts/lint_manifest.sh

# ---------- Module name / sources ----------

# Auto-detect MODULE_NAME from obj-m if not set
ifndef MODULE_NAME
  ifdef obj-m
    MODULE_NAME := $(basename $(firstword $(obj-m)))
  else
    $(error MODULE_NAME or obj-m must be defined before including kmod.mk)
  endif
endif

MODULE_SRCS ?=

# ---------- Cross-compiler ----------
# Resolved by shared detector. Sets KH_CC / KH_LD / KH_AR / KH_CROSS_COMPILE.
# See kmod/mk/detect_toolchain.mk for the decision tree.
include $(KERNELHOOK_DIR)/mk/detect_toolchain.mk

CC := $(KH_CC)
LD := $(KH_LD)
CROSS_COMPILE := $(KH_CROSS_COMPILE)

# ---------- Kernel release / vermagic ----------

KERNELRELEASE ?= unknown
VERMAGIC ?= $(KERNELRELEASE) SMP preempt mod_unload modversions aarch64

# ---------- Compile flags ----------
#
# Plan 2 (runtime resolver) made MODULE_LAYOUT_CRC / PRINTK_CRC /
# THIS_MODULE_SIZE / MODULE_INIT_OFFSET / MODULE_EXIT_OFFSET overrides
# obsolete — those values are resolved at load time by kmod_loader's
# strategy chain and patched directly into the .ko buffer before
# init_module. The .ko compiles with placeholder sentinels defined
# in kmod/shim/shim.h (MODULE_VERSIONS macro).
#
# If a consumer still passes any of those variables via `make VAR=val`,
# the build silently ignores them — harmless, but they no longer affect
# the produced .ko.

# KH_CFI_MODE selects the control-flow integrity build mode:
#   kcfi  (default) — clang -fsanitize=kcfi, matches GKI 6.1+ arm64 kernels
#                     built with CONFIG_CFI_CLANG=y + kCFI (new scheme)
#   none            — no CFI sanitizer. Needed for kernels built with
#                     the older shadow CFI (CONFIG_CFI_CLANG=y on GKI 5.4
#                     arm64); those reject kCFI-compiled modules with
#                     "CFI failure (target: init_module)" panic in
#                     __cfi_slowpath at do_one_initcall time.
KH_CFI_MODE ?= kcfi
ifeq ($(KH_CFI_MODE),none)
  KH_CFI_CFLAGS :=
else
  KH_CFI_CFLAGS := -fsanitize=kcfi
endif

# IMPORTANT: Do NOT add -fsanitize=shadow-call-stack to freestanding builds.
# The .ko must run on kernels with and without SCS. Our transit_body must
# not use x18 (SCS register), which may be uninitialized on non-SCS kernels.
# Target function SCS instructions are relocated verbatim and work correctly
# because x18 is managed by the target kernel's SCS infrastructure.
KH_CFLAGS := -DKMOD_FREESTANDING \
             -DVERMAGIC_STRING='"$(VERMAGIC)"' \
             -DMODULE_NAME='"$(MODULE_NAME)"' \
             -ffreestanding -fno-builtin -fno-stack-protector -fno-common \
             -fno-PIE -fno-pic \
             -fno-optimize-sibling-calls \
             -mbranch-protection=bti \
             -I$(KERNELHOOK_DIR)/shim/include \
             -I$(KH_ROOT)/include \
             -I$(KH_ROOT)/include/arch/arm64 \
             -I$(KERNELHOOK_DIR)/shim \
             -I$(KERNELHOOK_DIR)/include \
             -march=armv8.5-a -O2 -Wall -Wextra -Werror \
             -Wno-unused-parameter \
             -Wno-unused-function \
             -Wno-unknown-sanitizers \
             $(KH_CFI_CFLAGS)
# -fno-optimize-sibling-calls + -mbranch-protection=bti: Pixel production
# kernels mark both kernel .text and module vmalloc .text with PROT_BTI.
# That means:
#   (a) indirect calls from our module into kernel (ksyms-resolved fn
#       pointers) must be BLR — never tail-called via BR.
#       `-fno-optimize-sibling-calls` forbids clang to rewrite
#       `return fn(...)` as BR.
#   (b) the kernel's BLR into our init_module / cleanup_module / any
#       callback must land on a BTI_C (or BTI_JC) landing pad.
#       `-mbranch-protection=bti` makes clang prefix every function
#       entry with BTI_C. Without it, kernel-issued BLR into our
#       init_module lands on a plain `STP X29,X30,...` instruction
#       and raises a BTI exception — instant kernel panic on
#       CONFIG_CFI_PERMISSIVE=n kernels like stock Pixel 6.

# Allow user to append extra flags
KH_CFLAGS += $(EXTRA_CFLAGS)

# ---------- Linker script ----------

KH_LDS := $(KERNELHOOK_DIR)/lds/kmod.lds

# ---------- Source files ----------

# Core library sources from $(KH_ROOT)/src/
_KH_CORE_SRCS := $(KH_ROOT)/src/hook.c \
                 $(KH_ROOT)/src/memory.c \
                 $(KH_ROOT)/src/symbol.c \
                 $(KH_ROOT)/src/arch/arm64/inline.c \
                 $(KH_ROOT)/src/arch/arm64/transit.c \
                 $(KH_ROOT)/src/arch/arm64/insn.c \
                 $(KH_ROOT)/src/arch/arm64/pgtable.c \
                 $(KH_ROOT)/src/platform/syscall.c \
                 $(KH_ROOT)/src/uaccess.c \
                 $(KH_ROOT)/src/sync.c \
                 $(KH_ROOT)/src/kh_strategy.c \
                 $(KH_ROOT)/src/strategies/swapper_pg_dir.c \
                 $(KH_ROOT)/src/strategies/kimage_voffset.c

# kmod SDK sources from $(KERNELHOOK_DIR)/src/
_KH_KMOD_SRCS := $(KERNELHOOK_DIR)/src/mem_ops.c \
                 $(KERNELHOOK_DIR)/src/log.c \
                 $(KERNELHOOK_DIR)/src/transit_setup.c \
                 $(KERNELHOOK_DIR)/src/compat.c \
                 $(KERNELHOOK_DIR)/src/export.c \
                 $(KERNELHOOK_DIR)/src/kh_strategy_boot.c

# PLT stub
_KH_PLT_SRCS := $(KERNELHOOK_DIR)/plt/plt_stub.S

# kh_crc-generated exports (assembly)
_KH_GEN_SRCS := $(KH_EXPORTS_S)
_KH_GEN_OBJS := $(KH_GEN_DIR)/kh_exports.kmod.o

# ---------- Object files (use .kmod.o suffix, in subdirs) ----------

_KH_CORE_OBJS := $(patsubst $(KH_ROOT)/%.c,_kh_core/%.kmod.o,$(_KH_CORE_SRCS))
_KH_KMOD_OBJS := $(patsubst $(KERNELHOOK_DIR)/%.c,_kh_kmod/%.kmod.o,$(_KH_KMOD_SRCS))
_KH_PLT_OBJS  := $(patsubst $(KERNELHOOK_DIR)/%.S,_kh_kmod/%.kmod.o,$(_KH_PLT_SRCS))
_KH_MOD_OBJS  := $(patsubst %.c,%.kmod.o,$(MODULE_SRCS))

_KH_ALL_OBJS := $(_KH_MOD_OBJS) $(_KH_CORE_OBJS) $(_KH_KMOD_OBJS) $(_KH_PLT_OBJS) $(_KH_GEN_OBJS)

# ---------- Targets ----------

.PHONY: module loader clean

module: $(MODULE_NAME).ko
	@echo "Built $(MODULE_NAME).ko successfully"
	@file $(MODULE_NAME).ko

loader: $(KERNELHOOK_DIR)/loader/kmod_loader.c
	$(CC) -static -O2 -o kmod_loader $<

# Detect llvm-objcopy (from NDK or PATH)
_KH_OBJCOPY := $(shell which $(CROSS_COMPILE)objcopy 2>/dev/null || which llvm-objcopy 2>/dev/null)

$(MODULE_NAME).ko: _kh_lint $(KH_SYMVERS_H) $(_KH_ALL_OBJS)
	$(LD) -r -T $(KH_LDS) -o $@.tmp $(_KH_ALL_OBJS)
	@# lld renames .kh.this_module output section to .gnu.linkonce.this_module
	@# via linker script, but keeps .rela.kh.this_module as the relocation name.
	@# Kernel expects .rela.gnu.linkonce.this_module — fix with objcopy.
ifneq ($(_KH_OBJCOPY),)
	$(_KH_OBJCOPY) --rename-section .rela.kh.this_module=.rela.gnu.linkonce.this_module $@.tmp $@
	@rm -f $@.tmp
else
	@mv $@.tmp $@
	@echo "WARNING: llvm-objcopy not found, .rela.kh.this_module not renamed"
endif

# Module's own sources
%.kmod.o: %.c
	$(CC) $(KH_CFLAGS) -c $< -o $@

# Core library objects
_kh_core/%.kmod.o: $(KH_ROOT)/%.c
	@mkdir -p $(dir $@)
	$(CC) $(KH_CFLAGS) -c $< -o $@

# kmod SDK objects (C)
_kh_kmod/%.kmod.o: $(KERNELHOOK_DIR)/%.c
	@mkdir -p $(dir $@)
	$(CC) $(KH_CFLAGS) -c $< -o $@

# kmod SDK objects (assembly)
_kh_kmod/%.kmod.o: $(KERNELHOOK_DIR)/%.S
	@mkdir -p $(dir $@)
	$(CC) $(KH_CFLAGS) -c $< -o $@

# kh_crc-generated assembly (kh_exports.S -> kh_exports.kmod.o)
$(KH_GEN_DIR)/kh_exports.kmod.o: $(KH_EXPORTS_S) | $(KH_GEN_DIR)
	$(CC) $(KH_CFLAGS) -c $< -o $@

clean:
	rm -f $(MODULE_NAME).ko $(MODULE_NAME).ko.tmp $(_KH_MOD_OBJS)
	rm -rf _kh_core/ _kh_kmod/ $(KH_GEN_DIR)
	rm -f kmod_loader
