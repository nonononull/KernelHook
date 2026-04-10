# SPDX-License-Identifier: GPL-2.0-or-later
# User-facing wrapper for kbuild_hello.ko (Mode C SDK consumer example).
#
# Prerequisites:
#   1. kernelhook.ko must have been built first to produce Module.symvers:
#        make -C $KERNEL_SRC M=$(KERNELHOOK)/kmod modules
#   2. KERNEL_SRC must point at a prepared Linux kernel source tree.
#
# Usage:
#   make                        # uses /lib/modules/$(uname -r)/build
#   make KERNEL_SRC=/path/to/kernel ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu-
#   make clean

KERNEL_SRC  ?= /lib/modules/$(shell uname -r)/build
KERNELHOOK  ?= $(CURDIR)/../..
PWD         := $(CURDIR)

.PHONY: all modules clean

all: modules

modules:
	$(MAKE) -C $(KERNEL_SRC) M=$(PWD) \
		KERNELHOOK=$(KERNELHOOK) \
		KBUILD_EXTRA_SYMBOLS=$(KERNELHOOK)/kmod/Module.symvers \
		modules

clean:
	$(MAKE) -C $(KERNEL_SRC) M=$(PWD) clean
