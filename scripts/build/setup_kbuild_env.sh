#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-or-later
# Set up a kbuild environment for building out-of-tree GKI modules.
#
# Installs host toolchain (if apt available), clones kernel source (if
# KERNEL_DIR is empty), runs defconfig + modules_prepare + vmlinux.
#
# Required env:
#   BRANCH       — GKI branch (e.g., android14-6.1)
#   KERNEL_DIR   — where to clone/find kernel source
#   KERNEL_OUT   — kernel output directory (O=)
#
# Optional env:
#   SKIP_APT=1   — skip apt install (for local use on non-Debian hosts)

set -euo pipefail

: "${BRANCH:?BRANCH is required (e.g., android14-6.1)}"
: "${KERNEL_DIR:?KERNEL_DIR is required}"
: "${KERNEL_OUT:?KERNEL_OUT is required}"

# ---------- Host toolchain ----------

if [ "${SKIP_APT:-0}" != "1" ] && command -v apt-get >/dev/null 2>&1; then
    echo "==> Installing host toolchain"
    sudo apt-get update
    sudo apt-get install -y --no-install-recommends \
        bc bison flex libssl-dev libelf-dev cpio kmod python3 ccache \
        clang lld llvm llvm-dev \
        gcc-aarch64-linux-gnu binutils-aarch64-linux-gnu \
        rsync zstd xz-utils \
        dwarves
    clang --version
    ld.lld --version
fi

# ---------- Kernel source ----------

if [ ! -d "$KERNEL_DIR/.git" ]; then
    echo "==> Cloning kernel/common branch $BRANCH"
    git clone --depth=1 --single-branch \
        --branch "$BRANCH" \
        https://android.googlesource.com/kernel/common "$KERNEL_DIR"
else
    echo "==> Kernel source already present at $KERNEL_DIR"
fi

# ---------- Configure ----------

if [ -f "$KERNEL_DIR/arch/arm64/configs/gki_defconfig" ]; then
    CFG=gki_defconfig
else
    CFG=defconfig
fi
echo "==> Configuring with $CFG"
make -C "$KERNEL_DIR" O="$KERNEL_OUT" ARCH=arm64 LLVM=1 "$CFG"

# ---------- modules_prepare ----------

echo "==> modules_prepare"
make -C "$KERNEL_DIR" O="$KERNEL_OUT" ARCH=arm64 LLVM=1 \
     modules_prepare -j"$(nproc)"

# ---------- vmlinux (for Module.symvers) ----------

echo "==> Building vmlinux (for Module.symvers)"
make -C "$KERNEL_DIR" O="$KERNEL_OUT" ARCH=arm64 LLVM=1 \
     vmlinux -j"$(nproc)" || \
make -C "$KERNEL_DIR" O="$KERNEL_OUT" ARCH=arm64 LLVM=1 \
     Image -j"$(nproc)"

echo "==> Kbuild environment ready"
