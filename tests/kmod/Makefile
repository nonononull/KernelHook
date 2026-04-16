# SPDX-License-Identifier: GPL-2.0-or-later
# Convenience Makefile for KernelHook kernel module test harness
#
# Targets:
#   make              — Approach A: build via Kbuild (requires kernel headers)
#   make KDIR=/path   — Approach A: build against a specific kernel source tree
#   make freestanding — Approach B: build with cross-compiler only (no kernel headers)
#   make clean        — remove build artifacts
#   make test         — run via scripts/run_android_tests.sh --kmod

KDIR ?= /lib/modules/$(shell uname -r)/build
PWD  := $(shell pwd)

# KernelHook project root
KH_ROOT := $(PWD)/../..

# Cross-compiler for freestanding build
CROSS_COMPILE ?= aarch64-linux-gnu-
CC := $(CROSS_COMPILE)gcc
LD := $(CROSS_COMPILE)ld

# Kernel release string (pass from device: KERNELRELEASE=$(uname -r))
KERNELRELEASE ?= unknown

# Construct vermagic: "<uname -r> SMP preempt mod_unload modversions aarch64"
VERMAGIC ?= $(KERNELRELEASE) SMP preempt mod_unload modversions aarch64

# Freestanding build flags
FS_CFLAGS := -DKMOD_FREESTANDING \
             -DVERMAGIC_STRING='"$(VERMAGIC)"' \
             -ffreestanding -fno-builtin -fno-stack-protector -fno-common \
             -fno-PIE -fno-pic \
             -fno-optimize-sibling-calls \
             -mbranch-protection=bti \
             -I$(KH_ROOT)/kmod/shim/include \
             -I$(KH_ROOT)/include -I$(KH_ROOT)/include/arch/arm64 \
             -I$(KH_ROOT)/kmod/shim \
             -I$(PWD) \
             -march=armv8.5-a -O2 -Wall -Wextra -Werror \
             -Wno-unused-parameter -Wno-unused-function
# -fno-optimize-sibling-calls + -mbranch-protection=bti: see kmod/mk/kmod.mk
# — Pixel BTI requires ksym-resolved indirect calls use BLR (not BR) and
# every function entry to carry BTI_C so kernel-issued BLR (e.g. into
# our init_module) lands on a legal target.

# kCFI: only for 6.1+ kernels (CONFIG_CFI_CLANG uses kCFI).
# 5.10/5.15 use shadow-based CFI — kCFI metadata causes panic.
KVER_MAJOR := $(word 1,$(subst ., ,$(KERNELRELEASE)))
KVER_MINOR := $(word 2,$(subst ., ,$(KERNELRELEASE)))
KCFI_OK := $(shell [ "$(KVER_MAJOR)" -gt 6 ] 2>/dev/null && echo y || \
             ([ "$(KVER_MAJOR)" -eq 6 ] && [ "$(KVER_MINOR)" -ge 1 ] 2>/dev/null && echo y || echo n))
ifeq ($(KCFI_OK),y)
FS_CFLAGS += -fsanitize=kcfi
endif

# Code model: 4.x kernels lack R_AARCH64_ADR_PREL_PG_HI21 (ADRP) relocation support
# in their module loader. Use -mcmodel=large to emit MOVZ/MOVK sequences instead.
LARGE_MODEL := $(shell [ "$(KVER_MAJOR)" -le 4 ] 2>/dev/null && echo y || echo n)
ifeq ($(LARGE_MODEL),y)
FS_CFLAGS += -mcmodel=large
endif

# struct module init/exit offsets differ by kernel version.
# THIS_MODULE_SIZE is padded to 0x800 so kmod_loader can always shrink to the
# actual device size (physical devices may differ from GKI AVD presets).
FS_CFLAGS += -DTHIS_MODULE_SIZE=0x800

# GKI preset offsets — kmod_loader overrides at load time if vendor .ko differs.
ifeq ($(KVER_MAJOR).$(KVER_MINOR),4.4)
FS_CFLAGS += -DMODULE_INIT_OFFSET=0x158 -DMODULE_EXIT_OFFSET=0x2d0
else ifeq ($(KVER_MAJOR).$(KVER_MINOR),4.9)
FS_CFLAGS += -DMODULE_INIT_OFFSET=0x150 -DMODULE_EXIT_OFFSET=0x2e8
else ifeq ($(KVER_MAJOR).$(KVER_MINOR),4.14)
FS_CFLAGS += -DMODULE_INIT_OFFSET=0x150 -DMODULE_EXIT_OFFSET=0x2f8
else ifeq ($(KVER_MAJOR).$(KVER_MINOR),4.19)
FS_CFLAGS += -DMODULE_INIT_OFFSET=0x168 -DMODULE_EXIT_OFFSET=0x318
else ifeq ($(KVER_MAJOR).$(KVER_MINOR),5.4)
FS_CFLAGS += -DMODULE_INIT_OFFSET=0x178 -DMODULE_EXIT_OFFSET=0x340
else ifeq ($(KVER_MAJOR).$(KVER_MINOR),5.10)
FS_CFLAGS += -DMODULE_INIT_OFFSET=0x190 -DMODULE_EXIT_OFFSET=0x3c8
else ifeq ($(KVER_MAJOR).$(KVER_MINOR),5.15)
FS_CFLAGS += -DMODULE_INIT_OFFSET=0x178 -DMODULE_EXIT_OFFSET=0x378
else ifeq ($(KVER_MAJOR).$(KVER_MINOR),6.1)
FS_CFLAGS += -DMODULE_INIT_OFFSET=0x140 -DMODULE_EXIT_OFFSET=0x3d8
else ifeq ($(KVER_MAJOR).$(KVER_MINOR),6.6)
FS_CFLAGS += -DMODULE_INIT_OFFSET=0x188 -DMODULE_EXIT_OFFSET=0x5b8
else ifeq ($(KVER_MAJOR).$(KVER_MINOR),6.12)
FS_CFLAGS += -DMODULE_INIT_OFFSET=0x188 -DMODULE_EXIT_OFFSET=0x5f8
endif

# Propagate CONFIG_KH_CHAIN_RCU to freestanding build (compiles RCU-backed chain_ops)
ifneq ($(CONFIG_KH_CHAIN_RCU),)
FS_CFLAGS += -DCONFIG_KH_CHAIN_RCU=1
endif

# Source files for freestanding build
FS_TEST_SRCS := test_main.c test_hook_kernel.c demo_kh_root.c \
                mem_ops.c log.c transit_setup.c \
                test_resolver_swapper_pg_dir.c \
                test_resolver_kimage_voffset.c \
                test_resolver_memstart_addr.c \
                test_resolver_cred.c \
                test_resolver_stack.c \
                test_resolver_copy_user.c \
                test_resolver_cross_cpu.c
FS_ASM_SRCS  := plt_stub.S
FS_CORE_SRCS := $(KH_ROOT)/src/hook.c \
                $(KH_ROOT)/src/memory.c \
                $(KH_ROOT)/src/symbol.c \
                $(KH_ROOT)/src/arch/arm64/inline.c \
                $(KH_ROOT)/src/arch/arm64/transit.c \
                $(KH_ROOT)/src/arch/arm64/insn.c \
                $(KH_ROOT)/src/arch/arm64/pgtable.c \
                $(KH_ROOT)/src/platform/syscall.c \
                $(KH_ROOT)/src/uaccess.c \
                $(KH_ROOT)/src/kh_strategy.c \
                $(KH_ROOT)/src/strategies/swapper_pg_dir.c \
                $(KH_ROOT)/src/strategies/kimage_voffset.c \
                $(KH_ROOT)/src/strategies/memstart_addr.c \
                $(KH_ROOT)/src/strategies/cred_task.c \
                $(KH_ROOT)/src/strategies/uaccess_copy.c \
                $(KH_ROOT)/src/strategies/cross_cpu.c \
                $(KH_ROOT)/kmod/shim/shim_libc.c \
                $(KH_ROOT)/kmod/shim/shim_ksyms.c

# Include RCU sync implementation when CONFIG_KH_CHAIN_RCU is requested
ifneq ($(CONFIG_KH_CHAIN_RCU),)
FS_CORE_SRCS += $(KH_ROOT)/src/sync.c
endif

FS_TEST_OBJS := $(FS_TEST_SRCS:.c=.fs.o)
FS_ASM_OBJS  := $(FS_ASM_SRCS:.S=.fs.o)
FS_CORE_OBJS := $(patsubst $(KH_ROOT)/%.c,%.fs.o,$(FS_CORE_SRCS))

.PHONY: all clean test freestanding

# ---- Approach A: Kbuild ----
all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

# ---- Approach B: Freestanding ----
freestanding: kh_test.ko
	@echo "Freestanding kh_test.ko built successfully"
	@file kh_test.ko
	@$(CROSS_COMPILE)objdump -s -j .modinfo $< 2>/dev/null | tail -5 || true

%.fs.o: %.c
	$(CC) $(FS_CFLAGS) -c $< -o $@

src/%.fs.o: $(KH_ROOT)/src/%.c
	@mkdir -p $(dir $@)
	$(CC) $(FS_CFLAGS) -c $< -o $@

# Shim sources (kmod/shim/shim_libc.c, kmod/shim/shim_ksyms.c) — compile
# into kmod/shim/*.fs.o mirroring their source path. Needed because the
# FS_CORE_SRCS list includes $(KH_ROOT)/kmod/shim/*.c but the local
# `src/%.fs.o` rule above only matches $(KH_ROOT)/src/%.c.
kmod/%.fs.o: $(KH_ROOT)/kmod/%.c
	@mkdir -p $(dir $@)
	$(CC) $(FS_CFLAGS) -c $< -o $@

%.fs.o: %.S
	$(CC) $(FS_CFLAGS) -c $< -o $@

kh_test.ko: $(FS_TEST_OBJS) $(FS_ASM_OBJS) $(FS_CORE_OBJS)
	$(LD) -r -T freestanding.lds -o $@ $^

# ---- Test (delegates to project-level Android test runner) ----
test:
	$(KH_ROOT)/scripts/run_android_tests.sh --kmod

# ---- Clean ----
clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean 2>/dev/null || true
	rm -f *.fs.o *.ko
	rm -rf src/
