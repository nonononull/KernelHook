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

CROSS_COMPILE ?= aarch64-linux-gnu-

# Auto-detect: if the default gcc is missing, try Android NDK clang
_KH_HAVE_GCC := $(shell which $(CROSS_COMPILE)gcc 2>/dev/null)
ifeq ($(_KH_HAVE_GCC),)
  # Try to find Android NDK (filter .zip files that may appear in sdk/ndk/)
  _KH_NDK_CANDIDATES := $(wildcard $(HOME)/Library/Android/sdk/ndk/*) \
                         $(wildcard $(ANDROID_NDK_ROOT)) \
                         $(wildcard $(ANDROID_HOME)/ndk/*)
  _KH_NDK_BASE := $(lastword $(filter-out %.zip,$(_KH_NDK_CANDIDATES)))
  ifneq ($(_KH_NDK_BASE),)
    _KH_NDK_PREBUILT := $(firstword $(wildcard $(_KH_NDK_BASE)/toolchains/llvm/prebuilt/*/bin))
    ifneq ($(_KH_NDK_PREBUILT),)
      # Use NDK clang with Android target
      _KH_USE_NDK := 1
      CC  := $(_KH_NDK_PREBUILT)/clang --target=aarch64-linux-android30
      LD  := $(_KH_NDK_PREBUILT)/ld.lld
      CROSS_COMPILE := $(_KH_NDK_PREBUILT)/llvm-
    endif
  endif
endif

ifndef _KH_USE_NDK
  CC := $(CROSS_COMPILE)gcc
  LD := $(CROSS_COMPILE)ld
endif

# ---------- Kernel release / vermagic ----------

KERNELRELEASE ?= unknown
VERMAGIC ?= $(KERNELRELEASE) SMP preempt mod_unload modversions aarch64

# ---------- CRC overrides (for __versions section) ----------

MODULE_LAYOUT_CRC ?=
PRINTK_CRC ?=

# ---------- struct module offset overrides ----------

THIS_MODULE_SIZE   ?=
MODULE_INIT_OFFSET ?=
MODULE_EXIT_OFFSET ?=

# ---------- Compile flags ----------

KH_CFLAGS := -DKMOD_FREESTANDING \
             -DVERMAGIC_STRING='"$(VERMAGIC)"' \
             -DMODULE_NAME='"$(MODULE_NAME)"' \
             -ffreestanding -fno-builtin -fno-stack-protector -fno-common \
             -fno-PIE -fno-pic \
             -I$(KH_ROOT)/include \
             -I$(KH_ROOT)/include/arch/arm64 \
             -I$(KERNELHOOK_DIR)/shim \
             -I$(KERNELHOOK_DIR)/include \
             -march=armv8.5-a -O2 -Wall -Wextra -Werror \
             -Wno-unused-parameter \
             -Wno-unused-function \
             -Wno-unknown-sanitizers \
             -fsanitize=kcfi

# Append CRC defines if provided
ifneq ($(MODULE_LAYOUT_CRC),)
  KH_CFLAGS += -DMODULE_LAYOUT_CRC=$(MODULE_LAYOUT_CRC)
endif
ifneq ($(PRINTK_CRC),)
  KH_CFLAGS += -DPRINTK_CRC=$(PRINTK_CRC)
endif

# Append struct module offset defines if provided
ifneq ($(THIS_MODULE_SIZE),)
  KH_CFLAGS += -DTHIS_MODULE_SIZE=$(THIS_MODULE_SIZE)
endif
ifneq ($(MODULE_INIT_OFFSET),)
  KH_CFLAGS += -DMODULE_INIT_OFFSET=$(MODULE_INIT_OFFSET)
endif
ifneq ($(MODULE_EXIT_OFFSET),)
  KH_CFLAGS += -DMODULE_EXIT_OFFSET=$(MODULE_EXIT_OFFSET)
endif

# Allow user to append extra flags
KH_CFLAGS += $(EXTRA_CFLAGS)

# ---------- Linker script ----------

KH_LDS := $(KERNELHOOK_DIR)/lds/kmod.lds

# ---------- Source files ----------

# Core library sources from $(KH_ROOT)/src/
_KH_CORE_SRCS := $(KH_ROOT)/src/core_user.c \
                 $(KH_ROOT)/src/hmem.c \
                 $(KH_ROOT)/src/ksyms.c \
                 $(KH_ROOT)/src/arch/arm64/inline.c \
                 $(KH_ROOT)/src/arch/arm64/transit.c \
                 $(KH_ROOT)/src/arch/arm64/insn.c \
                 $(KH_ROOT)/src/arch/arm64/pgtable.c

# kmod SDK sources from $(KERNELHOOK_DIR)/src/
_KH_KMOD_SRCS := $(KERNELHOOK_DIR)/src/mem_ops.c \
                 $(KERNELHOOK_DIR)/src/log.c \
                 $(KERNELHOOK_DIR)/src/transit_setup.c \
                 $(KERNELHOOK_DIR)/src/compat.c \
                 $(KERNELHOOK_DIR)/src/export.c

# PLT stub
_KH_PLT_SRCS := $(KERNELHOOK_DIR)/plt/plt_stub.S

# ---------- Object files (use .kmod.o suffix, in subdirs) ----------

_KH_CORE_OBJS := $(patsubst $(KH_ROOT)/%.c,_kh_core/%.kmod.o,$(_KH_CORE_SRCS))
_KH_KMOD_OBJS := $(patsubst $(KERNELHOOK_DIR)/%.c,_kh_kmod/%.kmod.o,$(_KH_KMOD_SRCS))
_KH_PLT_OBJS  := $(patsubst $(KERNELHOOK_DIR)/%.S,_kh_kmod/%.kmod.o,$(_KH_PLT_SRCS))
_KH_MOD_OBJS  := $(patsubst %.c,%.kmod.o,$(MODULE_SRCS))

_KH_ALL_OBJS := $(_KH_MOD_OBJS) $(_KH_CORE_OBJS) $(_KH_KMOD_OBJS) $(_KH_PLT_OBJS)

# ---------- Targets ----------

.PHONY: module loader clean

module: $(MODULE_NAME).ko
	@echo "Built $(MODULE_NAME).ko successfully"
	@file $(MODULE_NAME).ko

loader: $(KERNELHOOK_DIR)/loader/kmod_loader.c
	$(CC) -static -O2 -o kmod_loader $<

# Detect llvm-objcopy (from NDK or PATH)
_KH_OBJCOPY := $(shell which $(CROSS_COMPILE)objcopy 2>/dev/null || which llvm-objcopy 2>/dev/null)

$(MODULE_NAME).ko: $(_KH_ALL_OBJS)
	$(LD) -r -T $(KH_LDS) -o $@.tmp $^
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

clean:
	rm -f $(MODULE_NAME).ko $(MODULE_NAME).ko.tmp $(_KH_MOD_OBJS)
	rm -rf _kh_core/ _kh_kmod/
	rm -f kmod_loader
