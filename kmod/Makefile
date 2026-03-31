# SPDX-License-Identifier: GPL-2.0-or-later
# Build kernelhook.ko — the prebuilt KernelHook kernel module.
#
# Usage:
#   make module        — build kernelhook.ko (freestanding, no kernel headers)
#   make loader        — build kmod_loader helper
#   make clean         — remove build artifacts

MODULE_NAME  := kernelhook
MODULE_SRCS  := src/main.c
KERNELHOOK_DIR := $(shell pwd)

include mk/kmod.mk
