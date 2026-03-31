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
             -I$(KH_ROOT)/include -I$(KH_ROOT)/include/arch/arm64 \
             -I$(PWD) \
             -march=armv8.5-a -O2 -Wall -Wextra -Werror \
             -Wno-unused-parameter -Wno-unused-function \
             -fsanitize=kcfi

# Source files for freestanding build
FS_TEST_SRCS := test_main.c test_hook_kernel.c kmod_mem_ops.c kmod_log.c kmod_transit_setup.c
FS_ASM_SRCS  := kmod_plt_stub.S
FS_CORE_SRCS := $(KH_ROOT)/src/core_user.c \
                $(KH_ROOT)/src/hmem.c \
                $(KH_ROOT)/src/ksyms.c \
                $(KH_ROOT)/src/arch/arm64/inline.c \
                $(KH_ROOT)/src/arch/arm64/transit.c \
                $(KH_ROOT)/src/arch/arm64/insn.c \
                $(KH_ROOT)/src/arch/arm64/pgtable.c

FS_TEST_OBJS := $(FS_TEST_SRCS:.c=.fs.o)
FS_ASM_OBJS  := $(FS_ASM_SRCS:.S=.fs.o)
FS_CORE_OBJS := $(patsubst $(KH_ROOT)/%.c,%.fs.o,$(FS_CORE_SRCS))

.PHONY: all clean test freestanding

# ---- Approach A: Kbuild ----
all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

# ---- Approach B: Freestanding ----
freestanding: kh_test.ko kmod_loader
	@echo "Freestanding kh_test.ko built successfully"
	@file kh_test.ko
	@$(CROSS_COMPILE)objdump -s -j .modinfo $< 2>/dev/null | tail -5 || true

# ---- kmod_loader: finit_module(2) wrapper for loading without modversions/vermagic ----
kmod_loader: kmod_loader.c
	$(CC) -static -O2 -o $@ $<

%.fs.o: %.c
	$(CC) $(FS_CFLAGS) -c $< -o $@

src/%.fs.o: $(KH_ROOT)/src/%.c
	@mkdir -p $(dir $@)
	$(CC) $(FS_CFLAGS) -c $< -o $@

%.fs.o: %.S
	$(CC) $(FS_CFLAGS) -c $< -o $@

kh_test.ko: $(FS_TEST_OBJS) $(FS_ASM_OBJS) $(FS_CORE_OBJS)
	$(LD) -r -T $(KH_ROOT)/kmod/lds/kmod.lds -o $@ $^

# ---- Test (delegates to project-level Android test runner) ----
test:
	$(KH_ROOT)/scripts/run_android_tests.sh --kmod

# ---- Clean ----
clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean 2>/dev/null || true
	rm -f *.fs.o *.ko kmod_loader
	rm -rf src/
