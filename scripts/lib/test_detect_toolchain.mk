# Test harness for kmod/mk/detect_toolchain.mk.
# Usage: make -f scripts/lib/test_detect_toolchain.mk CASE=<case_name> [vars]
# Each target prints KH_* values, the caller (shell driver) asserts.

HERE := $(dir $(lastword $(MAKEFILE_LIST)))
DETECTOR := $(HERE)../../kmod/mk/detect_toolchain.mk

include $(DETECTOR)

.PHONY: dump
dump:
	@printf 'KH_TOOLCHAIN_KIND=%s\n' '$(KH_TOOLCHAIN_KIND)'
	@printf 'KH_CC=%s\n' '$(KH_CC)'
	@printf 'KH_LD=%s\n' '$(KH_LD)'
	@printf 'KH_AR=%s\n' '$(KH_AR)'
	@printf 'KH_CROSS_COMPILE=%s\n' '$(KH_CROSS_COMPILE)'
	@printf 'KH_ANDROID_SDK=%s\n' '$(KH_ANDROID_SDK)'
	@printf 'KH_NDK=%s\n' '$(KH_NDK)'
	@printf 'KH_NDK_HOST_TAG=%s\n' '$(KH_NDK_HOST_TAG)'
	@printf 'KH_ANDROID_API_LEVEL=%s\n' '$(KH_ANDROID_API_LEVEL)'
