#!/usr/bin/env bash
# Creates fake NDK layouts used by detect_toolchain tests.
# Idempotent: safe to re-run.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"

make_ndk() {
    local name=$1 host_tag=$2
    shift 2
    local bin="$HERE/$name/toolchains/llvm/prebuilt/$host_tag/bin"
    local sys="$HERE/$name/toolchains/llvm/prebuilt/$host_tag/sysroot/usr/lib/aarch64-linux-android"
    mkdir -p "$bin" "$sys"
    for tool in clang ld.lld llvm-ar llvm-strip llvm-objcopy; do
        printf '#!/bin/sh\nexit 0\n' > "$bin/$tool"
        chmod +x "$bin/$tool"
    done
    for api in "$@"; do
        mkdir -p "$sys/$api"
        touch "$sys/$api/.keep"
    done
}

make_ndk ndk_linux  linux-x86_64  28 30 35
make_ndk ndk_darwin darwin-x86_64 30
echo "fixtures ready in $HERE"
