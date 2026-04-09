# SPDX-License-Identifier: GPL-2.0-or-later
# kmod_sdk.mk — SDK mode build fragment for KernelHook kernel modules.
#
# Modules built with this fragment depend on kernelhook.ko being loaded.
# Core library and kmod support sources are NOT compiled into the module —
# they are provided by kernelhook.ko at runtime via freestanding
# __ksymtab/__kcrctab exports (see kmod/exports.manifest and tools/kh_crc).
#
# Usage:
#   MODULE_NAME   := my_hook
#   MODULE_SRCS   := my_hook.c
#   KERNELHOOK_DIR := /path/to/KernelHook/kmod
#   include $(KERNELHOOK_DIR)/mk/kmod_sdk.mk

# Include the base build fragment (sets up toolchain, flags, targets)
include $(dir $(lastword $(MAKEFILE_LIST)))/kmod.mk

# Override: remove core library and kmod support sources
_KH_CORE_SRCS :=
_KH_KMOD_SRCS :=
_KH_CORE_OBJS :=
_KH_KMOD_OBJS :=

# Recompute all objects (module sources + PLT stub only)
_KH_ALL_OBJS := $(_KH_MOD_OBJS) $(_KH_PLT_OBJS)

# Add SDK mode compile flag
KH_CFLAGS += -DKH_SDK_MODE
