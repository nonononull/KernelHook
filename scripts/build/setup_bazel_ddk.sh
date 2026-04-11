#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-or-later
# Set up the Bazel DDK build environment inside a DDK container.
#
# Must be run INSIDE the DDK container (or after finding a kernel build dir).
# After this script, `bazel build //kmod:kernelhook` etc. will work.
#
# What this script does:
#   1. Installs Bazelisk as `bazel` if not already present.
#   2. Accepts $KDIR (kernel build directory with Module.symvers).
#   3. Creates bazel/kernel_build/files/ symlink -> $KDIR.
#   4. Writes bazel/kernel_build/BUILD.bazel with kernel_filegroup().
#
# Usage:
#   bash scripts/build/setup_bazel_ddk.sh /path/to/kernel_build_dir
#
# After setup:
#   bazel build //kmod:kernelhook
#   bazel build //tests/kmod:kh_test
#   bazel build //examples/kbuild_hello:kbuild_hello

set -euo pipefail

KDIR="${1:?usage: setup_bazel_ddk.sh <kernel-build-dir>}"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"

RED='\033[31m'; GREEN='\033[32m'; BOLD='\033[1m'; RESET='\033[0m'
ok()   { printf "${GREEN}ok${RESET}   %s\n" "$*"; }
bold() { printf "${BOLD}==> %s${RESET}\n" "$*"; }
fail() { printf "${RED}FAIL${RESET} %s\n" "$*" >&2; exit 1; }

# ---------- Validate kernel dir ----------

[[ -f "$KDIR/Module.symvers" ]] || \
    fail "No Module.symvers in $KDIR — is this a kernel build directory?"
ok "Kernel build dir: $KDIR"

# Read kernel version string from the build dir
KVER=""
if [[ -f "$KDIR/include/generated/utsrelease.h" ]]; then
    KVER=$(grep UTS_RELEASE "$KDIR/include/generated/utsrelease.h" \
           | awk '{print $3}' | tr -d '"')
elif [[ -f "$KDIR/.config" ]]; then
    KVER=$(grep '^CONFIG_LOCALVERSION=' "$KDIR/.config" | cut -d= -f2 | tr -d '"')
fi
KVER="${KVER:-unknown}"
ok "Kernel version: $KVER"

# ---------- Install Bazelisk ----------

if ! command -v bazel >/dev/null 2>&1; then
    bold "Installing Bazelisk"
    BAZELISK_URL="https://github.com/bazelbuild/bazelisk/releases/download/v1.20.0/bazelisk-linux-amd64"
    if command -v curl >/dev/null 2>&1; then
        curl -sSL "$BAZELISK_URL" -o /usr/local/bin/bazel
    elif command -v wget >/dev/null 2>&1; then
        wget -q "$BAZELISK_URL" -O /usr/local/bin/bazel
    else
        fail "Neither curl nor wget found — cannot install Bazelisk"
    fi
    chmod +x /usr/local/bin/bazel
    ok "Bazelisk installed: $(bazel version 2>&1 | head -1)"
else
    ok "bazel already installed: $(bazel version 2>&1 | head -1)"
fi

# ---------- Set up kernel_build repository ----------

KBUILD_DIR="${ROOT}/bazel/kernel_build"
mkdir -p "$KBUILD_DIR"

bold "Setting up kernel_build repository at $KBUILD_DIR"

# Write kdir.txt — the single source of truth for KDIR used by ddk_module().
printf '%s\n' "$KDIR" > "${KBUILD_DIR}/kdir.txt"
ok "Wrote ${KBUILD_DIR}/kdir.txt (KDIR=$KDIR)"

# ---- Capture DDK clang directory from current shell PATH ----
#
# When Bazel genrules run with --genrule_strategy=local, they use a
# sanitized environment and do NOT inherit the container shell's PATH.
# The DDK container's clang (required for LLVM=1 in kbuild and for
# llvm-nm in check-local-export) ends up missing.
#
# Fix: capture the first non-system clang from the current shell PATH
# HERE (where PATH is correct) and write it to clangdir.txt.
# The genrule then prepends that directory to the sanitized Bazel PATH.
#
# We use "the container's first non-system clang" because each DDK
# container ships the correct clang for out-of-tree module builds for
# that KMI — NOT the kernel build clang (which may be a different,
# older version stored in /opt/ddk/clang/<rev>/bin).

DDK_CLANG_DIR=""

# Walk the shell's PATH to find the first non-system clang.
# The container shell has PATH set up with the correct module-build clang;
# we capture that here (where PATH is correct) for use in Bazel genrules
# (where PATH is sanitized and lacks the container's toolchain).
IFS=: read -ra PATH_DIRS <<< "$PATH"
for pdir in "${PATH_DIRS[@]:-}"; do
    [ -z "$pdir" ] && continue
    clang_bin="$pdir/clang"
    [ -x "$clang_bin" ] || continue
    # Skip system clang locations
    case "$pdir" in
        /bin|/usr/bin|/usr/local/bin|/sbin|/usr/sbin)
            continue ;;
    esac
    DDK_CLANG_DIR="$pdir"
    break
done

# Fallback: check common DDK locations if PATH walk didn't find anything
if [ -z "$DDK_CLANG_DIR" ]; then
    for candidate_dir in \
        /opt/ddk/clang/*/bin \
        /opt/ddk/toolchain/*/bin \
        /opt/android-kernel/*/bin \
        /usr/local/clang/bin \
        "$(dirname "$(command -v clang 2>/dev/null || true)")" ; do
        if [ -n "$candidate_dir" ] && [ -x "$candidate_dir/clang" ]; then
            case "$candidate_dir" in
                /bin|/usr/bin|/usr/local/bin) continue ;;
            esac
            DDK_CLANG_DIR="$candidate_dir"
            break
        fi
    done
fi

if [ -n "$DDK_CLANG_DIR" ]; then
    printf '%s\n' "$DDK_CLANG_DIR" > "${KBUILD_DIR}/clangdir.txt"
    CLANG_VER=$("${DDK_CLANG_DIR}/clang" --version 2>&1 | head -1 || true)
    ok "Wrote ${KBUILD_DIR}/clangdir.txt (DDK clang: $DDK_CLANG_DIR — $CLANG_VER)"
else
    # No non-system clang found.  Write empty file.
    # This means Bazel genrule will use system clang (may cause issues).
    printf '' > "${KBUILD_DIR}/clangdir.txt"
    printf "${RED}warn${RESET} no non-system clang found in PATH; shell PATH was:\n%s\n" "$PATH"
fi

# Write BUILD.bazel for the kernel local repository
cat > "${KBUILD_DIR}/BUILD.bazel" << 'BUILDEOF'
# Generated by scripts/build/setup_bazel_ddk.sh — do not edit.
# Exposes KDIR and DDK clang directory to ddk_module() genrules.

exports_files(
    ["kdir.txt", "clangdir.txt"],
    visibility = ["//visibility:public"],
)

# kdir_file: absolute path to the kernel build directory (Module.symvers parent).
filegroup(
    name = "kdir_file",
    srcs = ["kdir.txt"],
    visibility = ["//visibility:public"],
)

# clangdir_file: DDK clang bin directory; prepended to PATH in ddk_module()
# genrules so that check-local-export uses the correct llvm-nm version.
filegroup(
    name = "clangdir_file",
    srcs = ["clangdir.txt"],
    visibility = ["//visibility:public"],
)
BUILDEOF

ok "Wrote ${KBUILD_DIR}/BUILD.bazel"

# Ensure WORKSPACE exists (marks the local_repository boundary)
cat > "${KBUILD_DIR}/WORKSPACE" << 'WSEOF'
# Generated by scripts/build/setup_bazel_ddk.sh — do not edit.
workspace(name = "gki_kernel")
WSEOF

ok "Wrote ${KBUILD_DIR}/WORKSPACE"

# ---------- Warm Bazel cache ----------

bold "Warming Bazel repository cache"
cd "$ROOT"
# Fetch the local gki_kernel repository (kdir.txt).
# This is fast (local) and validates that Bazel can read the workspace.
bazel fetch //bazel/kernel_build:kdir_file 2>&1 | tail -5 || \
    printf "${RED}warn${RESET} bazel fetch failed — bazel build will retry\n"

bold "DDK Bazel setup complete"
echo ""
echo "Run:"
echo "  bazel build //kmod:kernelhook"
echo "  bazel build //tests/kmod:kh_test"
echo "  bazel build //examples/kbuild_hello:kbuild_hello"
