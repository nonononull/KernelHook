# shellcheck shell=bash
# SPDX-License-Identifier: GPL-2.0-or-later
# detect_toolchain.sh — source this to resolve a cross-compiler.
# KEEP IN SYNC WITH kmod/mk/detect_toolchain.mk
#
# Decision tree (first match wins):
#   1. User override: $CC (+ $LD), or $CROSS_COMPILE
#   2. Android NDK auto-detected from env or default paths
#   3. System aarch64-linux-gnu-gcc / clang + ld.lld
#   4. Error
#
# Exports on success: KH_CC KH_LD KH_AR KH_CROSS_COMPILE
#                     KH_ANDROID_SDK KH_NDK KH_NDK_BIN KH_NDK_HOST_TAG
#                     KH_ANDROID_API_LEVEL KH_TOOLCHAIN_KIND KH_TOOLCHAIN_DESC
# On failure: returns nonzero if sourced (safe for interactive shells) or
# exits nonzero if executed directly. Callers should `. detect_toolchain.sh`
# and check $? (or use `|| exit 1`, since `set -e` does not catch a sourced
# script's `return` in all bash versions).

# Idempotency: always clear our own outputs first.
unset KH_CC KH_LD KH_AR KH_CROSS_COMPILE KH_ANDROID_SDK \
      KH_NDK KH_NDK_BIN KH_NDK_HOST_TAG KH_ANDROID_API_LEVEL \
      KH_TOOLCHAIN_KIND KH_TOOLCHAIN_DESC

_kh_log() { printf '[toolchain] %s\n' "$*" >&2; }

# ---- Step 1: user override ----
if [ "${CC+set}" = set ] && [ -n "${CC:-}" ]; then
    KH_CC="$CC"
    if [ "${LD+set}" = set ] && [ -n "${LD:-}" ]; then
        KH_LD="$LD"
    else
        # Derive LD from CC
        _cc_dir=$(dirname "${CC%% *}")
        if printf '%s' "$CC" | grep -q clang; then
            if [ -x "$_cc_dir/ld.lld" ]; then KH_LD="$_cc_dir/ld.lld"
            elif command -v ld.lld >/dev/null 2>&1; then KH_LD=ld.lld
            else KH_LD=ld
            fi
        else
            KH_LD="${CROSS_COMPILE:-}ld"
        fi
    fi
    KH_AR="${AR:-${CROSS_COMPILE:-}ar}"
    KH_CROSS_COMPILE="${CROSS_COMPILE:-}"
    KH_TOOLCHAIN_KIND=user
    KH_TOOLCHAIN_DESC="user CC=$CC LD=$KH_LD"
    _kh_log "using user: CC=$KH_CC LD=$KH_LD (from environment)"
elif [ "${CROSS_COMPILE+set}" = set ] && [ -n "${CROSS_COMPILE:-}" ]; then
    KH_CROSS_COMPILE="$CROSS_COMPILE"
    KH_CC="${CROSS_COMPILE}gcc"
    KH_LD="${CROSS_COMPILE}ld"
    KH_AR="${CROSS_COMPILE}ar"
    KH_TOOLCHAIN_KIND=user
    KH_TOOLCHAIN_DESC="user CROSS_COMPILE=$CROSS_COMPILE"
    _kh_log "using user: CROSS_COMPILE=$CROSS_COMPILE (from environment)"
else
    # ---- Step 2: Android NDK ----
    # Resolve SDK root
    if [ -n "${ANDROID_SDK_ROOT:-}" ]; then KH_ANDROID_SDK="$ANDROID_SDK_ROOT"
    elif [ -n "${ANDROID_HOME:-}" ]; then KH_ANDROID_SDK="$ANDROID_HOME"
    elif [ "$(uname -s)" = Darwin ] && [ -d "$HOME/Library/Android/sdk" ]; then
        KH_ANDROID_SDK="$HOME/Library/Android/sdk"
    elif [ -d "$HOME/Android/Sdk" ]; then
        KH_ANDROID_SDK="$HOME/Android/Sdk"
    else
        KH_ANDROID_SDK=""
    fi

    # Resolve NDK root. Warn if user set ANDROID_NDK_{ROOT,HOME} but the
    # path does not exist — silent fall-through would produce a surprising
    # sys-gcc result and wrong-ABI binaries.
    _ndk=""
    if [ -n "${ANDROID_NDK_ROOT:-}" ]; then
        if [ -d "$ANDROID_NDK_ROOT" ]; then
            _ndk="$ANDROID_NDK_ROOT"
        else
            _kh_log "ANDROID_NDK_ROOT=$ANDROID_NDK_ROOT does not exist, ignoring"
        fi
    fi
    if [ -z "$_ndk" ] && [ -n "${ANDROID_NDK_HOME:-}" ]; then
        if [ -d "$ANDROID_NDK_HOME" ]; then
            _ndk="$ANDROID_NDK_HOME"
        else
            _kh_log "ANDROID_NDK_HOME=$ANDROID_NDK_HOME does not exist, ignoring"
        fi
    fi
    if [ -z "$_ndk" ] && [ -n "$KH_ANDROID_SDK" ] && [ -d "$KH_ANDROID_SDK/ndk" ]; then
        # Pick the highest-version non-zip entry (version sort, not lex).
        _ndk=$(ls -1 "$KH_ANDROID_SDK/ndk" 2>/dev/null | grep -v '\.zip$' | sort -V | tail -1)
        [ -n "$_ndk" ] && _ndk="$KH_ANDROID_SDK/ndk/$_ndk"
    fi

    if [ -n "$_ndk" ] && [ -d "$_ndk/toolchains/llvm/prebuilt" ]; then
        # Resolve host tag
        _want="$(uname -s | tr '[:upper:]' '[:lower:]')-$(uname -m)"
        _tag=""
        if [ -d "$_ndk/toolchains/llvm/prebuilt/$_want" ]; then
            _tag="$_want"
        else
            _tag=$(ls -1 "$_ndk/toolchains/llvm/prebuilt" 2>/dev/null | head -1)
        fi
        if [ -n "$_tag" ] && [ -d "$_ndk/toolchains/llvm/prebuilt/$_tag/bin" ]; then
            KH_NDK="$_ndk"
            KH_NDK_HOST_TAG="$_tag"
            KH_NDK_BIN="$_ndk/toolchains/llvm/prebuilt/$_tag/bin"
            # API level
            if [ -n "${ANDROID_API_LEVEL:-}" ]; then
                KH_ANDROID_API_LEVEL="$ANDROID_API_LEVEL"
            else
                _sysdir="$_ndk/toolchains/llvm/prebuilt/$_tag/sysroot/usr/lib/aarch64-linux-android"
                KH_ANDROID_API_LEVEL=$(ls -1 "$_sysdir" 2>/dev/null | grep -E '^[0-9]+$' | sort -n | tail -1)
                : "${KH_ANDROID_API_LEVEL:=30}"
            fi
            KH_CC="$KH_NDK_BIN/clang --target=aarch64-linux-android$KH_ANDROID_API_LEVEL"
            KH_LD="$KH_NDK_BIN/ld.lld"
            KH_AR="$KH_NDK_BIN/llvm-ar"
            KH_CROSS_COMPILE="$KH_NDK_BIN/llvm-"
            KH_TOOLCHAIN_KIND=ndk
            KH_TOOLCHAIN_DESC="ndk $KH_NDK ($KH_NDK_HOST_TAG, api=$KH_ANDROID_API_LEVEL)"
            _kh_log "using ndk: $KH_NDK_BIN/clang --target=aarch64-linux-android$KH_ANDROID_API_LEVEL (host=$KH_NDK_HOST_TAG, api=$KH_ANDROID_API_LEVEL)"
        fi
    fi

    # ---- Step 3: system cross-compiler ----
    if [ -z "${KH_TOOLCHAIN_KIND:-}" ]; then
        _sdk_msg="${KH_ANDROID_SDK:+$KH_ANDROID_SDK/ndk}"; _sdk_msg="${_sdk_msg:-<no SDK found>}"
        _kh_log "NDK not found (checked: ANDROID_NDK_ROOT=${ANDROID_NDK_ROOT:-<unset>}, ANDROID_NDK_HOME=${ANDROID_NDK_HOME:-<unset>}, $_sdk_msg); falling back"
        if command -v aarch64-linux-gnu-gcc >/dev/null 2>&1; then
            KH_CC=$(command -v aarch64-linux-gnu-gcc)
            KH_LD=$(command -v aarch64-linux-gnu-ld 2>/dev/null || echo aarch64-linux-gnu-ld)
            KH_AR=$(command -v aarch64-linux-gnu-ar 2>/dev/null || echo aarch64-linux-gnu-ar)
            KH_CROSS_COMPILE="aarch64-linux-gnu-"
            KH_TOOLCHAIN_KIND=sys-gcc
            KH_TOOLCHAIN_DESC="sys-gcc $KH_CC"
            _kh_log "using sys-gcc: $KH_CC (NDK not found)"
        elif command -v clang >/dev/null 2>&1 && command -v ld.lld >/dev/null 2>&1; then
            KH_CC="$(command -v clang) --target=aarch64-linux-gnu"
            KH_LD=$(command -v ld.lld)
            KH_AR=$(command -v llvm-ar 2>/dev/null || command -v ar)
            KH_CROSS_COMPILE=""
            KH_TOOLCHAIN_KIND=sys-clang
            KH_TOOLCHAIN_DESC="sys-clang $KH_CC"
            _kh_log "using sys-clang: $KH_CC (NDK not found)"
        fi
    fi
fi

# ---- Step 4: failure ----
if [ -z "${KH_TOOLCHAIN_KIND:-}" ]; then
    _kh_log "ERROR: no usable toolchain found"
    _kh_log "  checked user overrides: CC=<unset> CROSS_COMPILE=<unset>"
    _kh_log "  checked NDK: ANDROID_NDK_ROOT=${ANDROID_NDK_ROOT:-<unset>}, ANDROID_NDK_HOME=${ANDROID_NDK_HOME:-<unset>}, ANDROID_SDK_ROOT=${ANDROID_SDK_ROOT:-<unset>}"
    _kh_log "  checked system: aarch64-linux-gnu-gcc, clang+ld.lld"
    _kh_log "  set one of: ANDROID_NDK_ROOT, ANDROID_SDK_ROOT, CROSS_COMPILE, or CC+LD"
    # `return` if sourced (preserves caller shell); `exit` if executed directly.
    return 1 2>/dev/null || exit 1
fi

export KH_CC KH_LD KH_AR KH_CROSS_COMPILE KH_ANDROID_SDK \
       KH_NDK KH_NDK_BIN KH_NDK_HOST_TAG KH_ANDROID_API_LEVEL \
       KH_TOOLCHAIN_KIND KH_TOOLCHAIN_DESC
