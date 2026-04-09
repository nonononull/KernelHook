# SPDX-License-Identifier: GPL-2.0-or-later
# Ring 2 test: build a minimal exporter (full kernelhook build) and a
# minimal importer (SDK build) as two independent freestanding .ko files.
#
# The exporter re-runs the full kmod.mk pipeline so its .ko ends up with the
# real __ksymtab/__kcrctab entries via kh_crc-generated kh_exports.S.
# The importer uses kmod_sdk.mk — core library is NOT linked, but its
# __versions section carries the frozen CRCs via KH_DECLARE_VERSIONS().

KH_ROOT        := $(CURDIR)/../../..
KERNELHOOK_DIR := $(KH_ROOT)/kmod

.PHONY: all clean
all: exporter.ko importer.ko

exporter.ko: exporter.c
	$(MAKE) -f $(KERNELHOOK_DIR)/mk/kmod.mk \
		MODULE_NAME=exporter \
		MODULE_SRCS=exporter.c \
		KERNELHOOK_DIR=$(KERNELHOOK_DIR) \
		module

importer.ko: importer.c
	$(MAKE) -f $(KERNELHOOK_DIR)/mk/kmod_sdk.mk \
		MODULE_NAME=importer \
		MODULE_SRCS=importer.c \
		KERNELHOOK_DIR=$(KERNELHOOK_DIR) \
		module

clean:
	rm -f exporter.ko exporter.ko.tmp importer.ko importer.ko.tmp \
	      exporter.kmod.o importer.kmod.o
	rm -rf _kh_core/ _kh_kmod/ $(KERNELHOOK_DIR)/generated
