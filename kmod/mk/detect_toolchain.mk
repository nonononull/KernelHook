# SPDX-License-Identifier: GPL-2.0-or-later
# detect_toolchain.mk — include this to resolve a cross-compiler.
# KEEP IN SYNC WITH scripts/lib/detect_toolchain.sh
#
# Decision tree (first match wins):
#   1. User override: $(origin CC/LD/CROSS_COMPILE) is command line or environment
#   2. Android NDK auto-detected from env or default paths
#   3. System aarch64-linux-gnu-gcc / clang + ld.lld
#   4. $(error ...)
#
# Sets (using := so each include re-evaluates):
#   KH_CC KH_LD KH_AR KH_CROSS_COMPILE
#   KH_ANDROID_SDK KH_NDK KH_NDK_BIN KH_NDK_HOST_TAG
#   KH_ANDROID_API_LEVEL KH_TOOLCHAIN_KIND KH_TOOLCHAIN_DESC

# Idempotency: clear prior outputs.
KH_CC :=
KH_LD :=
KH_AR :=
KH_CROSS_COMPILE :=
KH_ANDROID_SDK :=
KH_NDK :=
KH_NDK_BIN :=
KH_NDK_HOST_TAG :=
KH_ANDROID_API_LEVEL :=
KH_TOOLCHAIN_KIND :=
KH_TOOLCHAIN_DESC :=

# Helper: is a variable user-provided (command line or environment)?
_kh_is_user = $(filter command line environment,$(origin $(1)))

# ---- Step 1: user override ----
ifneq ($(call _kh_is_user,CC),)
  KH_CC := $(CC)
  ifneq ($(call _kh_is_user,LD),)
    KH_LD := $(LD)
  else ifneq ($(findstring clang,$(CC)),)
    KH_LD := ld.lld
  else
    KH_LD := $(if $(call _kh_is_user,CROSS_COMPILE),$(CROSS_COMPILE)ld,ld)
  endif
  KH_AR := $(if $(call _kh_is_user,CROSS_COMPILE),$(CROSS_COMPILE)ar,ar)
  KH_CROSS_COMPILE := $(if $(call _kh_is_user,CROSS_COMPILE),$(CROSS_COMPILE),)
  KH_TOOLCHAIN_KIND := user
  KH_TOOLCHAIN_DESC := user CC=$(CC) LD=$(KH_LD)
  $(info [toolchain] using user: CC=$(KH_CC) LD=$(KH_LD) (from environment))
else ifneq ($(call _kh_is_user,CROSS_COMPILE),)
  KH_CROSS_COMPILE := $(CROSS_COMPILE)
  KH_CC := $(CROSS_COMPILE)gcc
  KH_LD := $(CROSS_COMPILE)ld
  KH_AR := $(CROSS_COMPILE)ar
  KH_TOOLCHAIN_KIND := user
  KH_TOOLCHAIN_DESC := user CROSS_COMPILE=$(CROSS_COMPILE)
  $(info [toolchain] using user: CROSS_COMPILE=$(CROSS_COMPILE) (from environment))
else
  # ---- Step 2: Android NDK ----
  # Resolve SDK root
  _kh_uname_s := $(shell uname -s)
  ifneq ($(ANDROID_SDK_ROOT),)
    KH_ANDROID_SDK := $(ANDROID_SDK_ROOT)
  else ifneq ($(ANDROID_HOME),)
    KH_ANDROID_SDK := $(ANDROID_HOME)
  else ifeq ($(_kh_uname_s),Darwin)
    ifneq ($(wildcard $(HOME)/Library/Android/sdk),)
      KH_ANDROID_SDK := $(HOME)/Library/Android/sdk
    endif
  endif
  ifeq ($(KH_ANDROID_SDK),)
    ifneq ($(wildcard $(HOME)/Android/Sdk),)
      KH_ANDROID_SDK := $(HOME)/Android/Sdk
    endif
  endif

  # Resolve NDK root. Warn if user set ANDROID_NDK_{ROOT,HOME} but the
  # path does not exist — silent fall-through would produce a surprising
  # sys-gcc result and wrong-ABI binaries.
  _kh_ndk :=
  ifneq ($(ANDROID_NDK_ROOT),)
    ifneq ($(wildcard $(ANDROID_NDK_ROOT)),)
      _kh_ndk := $(ANDROID_NDK_ROOT)
    else
      $(warning [toolchain] ANDROID_NDK_ROOT=$(ANDROID_NDK_ROOT) does not exist, ignoring)
    endif
  endif
  ifeq ($(_kh_ndk),)
  ifneq ($(ANDROID_NDK_HOME),)
    ifneq ($(wildcard $(ANDROID_NDK_HOME)),)
      _kh_ndk := $(ANDROID_NDK_HOME)
    else
      $(warning [toolchain] ANDROID_NDK_HOME=$(ANDROID_NDK_HOME) does not exist, ignoring)
    endif
  endif
  endif
  ifeq ($(_kh_ndk),)
  ifneq ($(KH_ANDROID_SDK),)
    # Pick highest-version non-zip entry under $(KH_ANDROID_SDK)/ndk. Use
    # shell sort -V instead of Make's $(sort) (lex-only) so "25.2.9xxxxx"
    # ranks below "25.2.11xxxxx".
    _kh_ndk := $(shell ls -1 $(KH_ANDROID_SDK)/ndk 2>/dev/null | grep -v '\.zip$$' | sort -V | tail -1)
    ifneq ($(_kh_ndk),)
      _kh_ndk := $(KH_ANDROID_SDK)/ndk/$(_kh_ndk)
    endif
  endif
  endif

  ifneq ($(_kh_ndk),)
    ifneq ($(wildcard $(_kh_ndk)/toolchains/llvm/prebuilt),)
      # Host tag — prefer $(uname-s)-$(uname-m), else first entry
      _kh_want := $(shell echo $(_kh_uname_s) | tr A-Z a-z)-$(shell uname -m)
      _kh_tag :=
      ifneq ($(wildcard $(_kh_ndk)/toolchains/llvm/prebuilt/$(_kh_want)),)
        _kh_tag := $(_kh_want)
      else
        _kh_tag := $(notdir $(firstword $(wildcard $(_kh_ndk)/toolchains/llvm/prebuilt/*)))
      endif
      ifneq ($(_kh_tag),)
        KH_NDK := $(_kh_ndk)
        KH_NDK_HOST_TAG := $(_kh_tag)
        KH_NDK_BIN := $(_kh_ndk)/toolchains/llvm/prebuilt/$(_kh_tag)/bin
        # API level
        ifneq ($(ANDROID_API_LEVEL),)
          KH_ANDROID_API_LEVEL := $(ANDROID_API_LEVEL)
        else
          _kh_sysdir := $(_kh_ndk)/toolchains/llvm/prebuilt/$(_kh_tag)/sysroot/usr/lib/aarch64-linux-android
          KH_ANDROID_API_LEVEL := $(shell ls -1 $(_kh_sysdir) 2>/dev/null | grep -E '^[0-9]+$$' | sort -n | tail -1)
          ifeq ($(KH_ANDROID_API_LEVEL),)
            KH_ANDROID_API_LEVEL := 30
          endif
        endif
        KH_CC := $(KH_NDK_BIN)/clang --target=aarch64-linux-android$(KH_ANDROID_API_LEVEL)
        KH_LD := $(KH_NDK_BIN)/ld.lld
        KH_AR := $(KH_NDK_BIN)/llvm-ar
        KH_CROSS_COMPILE := $(KH_NDK_BIN)/llvm-
        KH_TOOLCHAIN_KIND := ndk
        KH_TOOLCHAIN_DESC := ndk $(KH_NDK) ($(KH_NDK_HOST_TAG), api=$(KH_ANDROID_API_LEVEL))
        $(info [toolchain] using ndk: $(KH_NDK_BIN)/clang --target=aarch64-linux-android$(KH_ANDROID_API_LEVEL) (host=$(KH_NDK_HOST_TAG), api=$(KH_ANDROID_API_LEVEL)))
      endif
    endif
  endif

  # ---- Step 3: system cross-compiler ----
  ifeq ($(KH_TOOLCHAIN_KIND),)
    $(warning [toolchain] NDK not found; falling back)
    _kh_sysgcc := $(shell command -v aarch64-linux-gnu-gcc 2>/dev/null)
    ifneq ($(_kh_sysgcc),)
      KH_CC := $(_kh_sysgcc)
      KH_LD := $(shell command -v aarch64-linux-gnu-ld 2>/dev/null)
      KH_AR := $(shell command -v aarch64-linux-gnu-ar 2>/dev/null)
      KH_CROSS_COMPILE := aarch64-linux-gnu-
      KH_TOOLCHAIN_KIND := sys-gcc
      KH_TOOLCHAIN_DESC := sys-gcc $(KH_CC)
      $(info [toolchain] using sys-gcc: $(KH_CC) (NDK not found))
    else
      _kh_clang := $(shell command -v clang 2>/dev/null)
      _kh_lldld := $(shell command -v ld.lld 2>/dev/null)
      ifneq ($(_kh_clang),)
        ifneq ($(_kh_lldld),)
          KH_CC := $(_kh_clang) --target=aarch64-linux-gnu
          KH_LD := $(_kh_lldld)
          KH_AR := $(shell command -v llvm-ar 2>/dev/null || command -v ar 2>/dev/null)
          KH_TOOLCHAIN_KIND := sys-clang
          KH_TOOLCHAIN_DESC := sys-clang $(KH_CC)
          $(info [toolchain] using sys-clang: $(KH_CC) (NDK not found))
        endif
      endif
    endif
  endif
endif

# ---- Step 4: failure ----
ifeq ($(KH_TOOLCHAIN_KIND),)
  $(error [toolchain] no usable toolchain found. Checked: CC/CROSS_COMPILE (unset), ANDROID_NDK_ROOT=$(ANDROID_NDK_ROOT), ANDROID_SDK_ROOT=$(ANDROID_SDK_ROOT), aarch64-linux-gnu-gcc, clang+ld.lld. Set one of: ANDROID_NDK_ROOT, ANDROID_SDK_ROOT, CROSS_COMPILE, or CC+LD)
endif
