#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-or-later
# Build and verify all out-of-tree GKI modules for one kernel branch.
#
# Usage:
#   KERNEL_OUT=/path/to/out bash scripts/build/ci_kbuild.sh android14-6.1
#
# This is the single entry point called by CI after setup_kbuild_env.sh
# has prepared the kernel tree.  Contributors can also run it locally
# after setting up their own KERNEL_OUT.
#
# Required env:
#   KERNEL_OUT   — kernel output directory (from setup_kbuild_env.sh)
#
# Required arg:
#   $1           — GKI branch name (e.g., android14-6.1)

set -euo pipefail

BRANCH="${1:?usage: ci_kbuild.sh <branch>}"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"

: "${KERNEL_OUT:?KERNEL_OUT is required}"

# Extract kernel minor version from branch name (e.g., "android14-6.1" → "6.1")
KVER="${BRANCH##*-}"

# ---------- Build kh_test.ko ----------

echo "==> Building kh_test.ko (M=tests/kmod)"
make -C "$KERNEL_OUT" \
     M="$ROOT/tests/kmod" \
     ARCH=arm64 LLVM=1 \
     modules -j"$(nproc)"

echo "==> Verifying kh_test.ko"
bash "$ROOT/scripts/ci/verify_kmod.sh" \
     "$ROOT/tests/kmod/kh_test.ko" \
     "$KVER"

# ---------- Mode C: kernelhook.ko + kbuild_hello.ko (6.1 only) ----------

if [ "$KVER" = "6.1" ]; then
    echo "==> Building kernelhook.ko (Mode C)"
    make -C "$KERNEL_OUT" \
         M="$ROOT/kmod" \
         ARCH=arm64 LLVM=1 \
         modules -j"$(nproc)"

    echo "==> Asserting Module.symvers contains all manifest exports"
    MISS=0
    while read -r sym; do
        [ -z "$sym" ] && continue
        if ! grep -q "[[:space:]]${sym}[[:space:]]" "$ROOT/kmod/Module.symvers"; then
            echo "ERROR: missing export in Module.symvers: $sym" >&2
            MISS=$((MISS + 1))
        fi
    done < <(awk '!/^#/ && NF {print $1}' "$ROOT/kmod/exports.manifest")
    echo "--- Module.symvers head ---"
    head -20 "$ROOT/kmod/Module.symvers" || true
    [ "$MISS" -eq 0 ] || { echo "FAIL: $MISS missing exports" >&2; exit 1; }

    echo "==> Building kbuild_hello.ko (SDK consumer)"
    make -C "$KERNEL_OUT" \
         M="$ROOT/examples/kbuild_hello" \
         KBUILD_EXTRA_SYMBOLS="$ROOT/kmod/Module.symvers" \
         KERNELHOOK="$ROOT" \
         ARCH=arm64 LLVM=1 \
         modules -j"$(nproc)"

    echo "==> Asserting kbuild_hello.ko depends on kernelhook"
    modinfo "$ROOT/examples/kbuild_hello/kbuild_hello.ko"
    modinfo "$ROOT/examples/kbuild_hello/kbuild_hello.ko" | \
        grep -qE "^depends:.*\bkernelhook\b" \
        || { echo "FAIL: kbuild_hello.ko does not declare depends: kernelhook" >&2; exit 1; }
fi

echo "==> All builds and assertions passed for $BRANCH"
