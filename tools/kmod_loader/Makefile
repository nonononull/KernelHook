# SPDX-License-Identifier: GPL-2.0-or-later
# Build kmod_loader — adaptive kernel module loader with embedded probe.
#
# Usage:
#   make                    — build kmod_loader (uses pre-committed probe_embed.h)
#   make regenerate         — regenerate probe_embed.h from source (needs cross-compiler)
#   make clean              — remove build artifacts

KH_ROOT := $(shell cd ../.. && pwd)

.DEFAULT_GOAL := all

# Cross-compiler (only needed for 'regenerate' target)
# Resolved by shared detector. See kmod/mk/detect_toolchain.mk.
include $(KH_ROOT)/kmod/mk/detect_toolchain.mk

CROSS_CC := $(KH_CC)
CROSS_LD := $(KH_LD)

# Host compiler for kmod_loader itself
HOSTCC ?= cc

# Device database codegen (Plan 2 Milestone A).
GEN_DEVICES := $(realpath ../gen_devices_table.py)
DEVICES_DIR := $(realpath ../../kmod/devices)
DEVICES_TABLE_C := devices_table.generated.c
DEVICES_TABLE_H := devices_table.h

.PHONY: devices_table
devices_table: $(DEVICES_TABLE_C)

$(DEVICES_TABLE_C): $(wildcard $(DEVICES_DIR)/*.conf) $(GEN_DEVICES)
	$(GEN_DEVICES) --devices-dir $(DEVICES_DIR) --output $@

FS_CFLAGS := -DKMOD_FREESTANDING \
             -ffreestanding -fno-builtin -fno-stack-protector -fno-common \
             -fno-PIE -fno-pic \
             -I$(KH_ROOT)/include -I$(KH_ROOT)/include/arch/arm64 \
             -march=armv8.5-a -O2 -Wall -Wextra -Werror \
             -Wno-unused-parameter -Wno-unused-function

.PHONY: all regenerate clean test

# Default: build kmod_loader using pre-committed probe_embed.h
all: kmod_loader
	@echo "Built kmod_loader successfully"

kmod_loader: kmod_loader.c probe_embed.h $(DEVICES_TABLE_C) $(DEVICES_TABLE_H)
	$(HOSTCC) -DEMBED_PROBE_KO -static -O2 -o $@ kmod_loader.c $(DEVICES_TABLE_C)

test: kmod_loader
	@./tests/test_config_parser.sh

# Regenerate probe_embed.h from source (requires cross-compiler)
regenerate: probe.ko
	@echo "// Auto-generated — do not edit" > probe_embed.h
	@echo "static const unsigned char probe_ko_data[] = {" >> probe_embed.h
	@xxd -i < probe.ko >> probe_embed.h
	@echo "};" >> probe_embed.h
	@echo "static const unsigned int probe_ko_size = sizeof(probe_ko_data);" >> probe_embed.h
	@echo "probe_embed.h regenerated — commit if changed"

probe.ko: probe.c
	$(CROSS_CC) $(FS_CFLAGS) -DMODULE_NAME='"kh_probe"' -c probe.c -o probe.fs.o
	$(CROSS_CC) $(FS_CFLAGS) -c $(KH_ROOT)/kmod/plt/plt_stub.S -o probe_plt.fs.o
	$(CROSS_LD) -r -T $(KH_ROOT)/kmod/lds/kmod.lds -o $@ probe.fs.o probe_plt.fs.o

clean:
	rm -f kmod_loader probe.ko probe.fs.o probe_plt.fs.o $(DEVICES_TABLE_C)
