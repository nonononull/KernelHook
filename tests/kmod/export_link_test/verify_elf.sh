#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-or-later
# Ring 2 ELF-level assertions for the exporter + importer pair.
# Runs entirely on the host — no device, no AVD.

set -euo pipefail

cd "$(dirname "$0")"
ROOT="$(cd ../../.. && pwd)"

# shellcheck source=../../../scripts/lib/detect_toolchain.sh
. "$ROOT/scripts/lib/detect_toolchain.sh"

# Probe readelf / objdump: prefer ${KH_CROSS_COMPILE}readelf, fall back to
# $KH_NDK_BIN/llvm-readelf for NDK installs (macOS NDK ships llvm-readelf).
pick_tool() {
    local base="$1"
    if [ -n "${KH_CROSS_COMPILE:-}" ] && command -v "${KH_CROSS_COMPILE}${base}" >/dev/null 2>&1; then
        echo "${KH_CROSS_COMPILE}${base}"
        return
    fi
    if [ -n "${KH_NDK_BIN:-}" ] && [ -x "$KH_NDK_BIN/llvm-${base}" ]; then
        echo "$KH_NDK_BIN/llvm-${base}"
        return
    fi
    if command -v "llvm-${base}" >/dev/null 2>&1; then
        echo "llvm-${base}"
        return
    fi
    if command -v "${base}" >/dev/null 2>&1; then
        echo "${base}"
        return
    fi
    echo "ERROR: cannot locate ${base}" >&2
    exit 2
}

READELF="$(pick_tool readelf)"
OBJDUMP="$(pick_tool objdump)"

fail=0
pass=0

assert_section() {
    local ko="$1" name="$2"
    if "$READELF" -S "$ko" | awk '{for(i=1;i<=NF;i++) print $i}' | grep -qx "${name}"; then
        echo "PASS $ko has section $name"
        pass=$((pass+1))
    else
        echo "FAIL $ko missing section $name"
        fail=$((fail+1))
    fi
}

assert_symbol() {
    local ko="$1" name="$2"
    if "$READELF" -s "$ko" | awk '{print $NF}' | grep -qx "${name}"; then
        echo "PASS $ko has symbol $name"
        pass=$((pass+1))
    else
        echo "FAIL $ko missing symbol $name"
        fail=$((fail+1))
    fi
}

# Exporter assertions
assert_section exporter.ko __ksymtab
assert_section exporter.ko __ksymtab_strings
assert_section exporter.ko __kcrctab
assert_symbol  exporter.ko __ksymtab_hook_wrap
assert_symbol  exporter.ko __crc_hook_wrap
assert_symbol  exporter.ko hook_wrap

# Importer assertions
assert_section importer.ko __versions
assert_symbol  importer.ko ksyms_lookup
assert_symbol  importer.ko hook_wrap

# Importer __versions must reference hook_wrap.
# Extract raw bytes of the __versions section and grep for the symbol name.
if "$OBJDUMP" -s -j __versions importer.ko 2>/dev/null \
        | awk '/Contents of section __versions/ {in_sec=1; next}
               in_sec && /^ [0-9a-f]/ {for(i=2;i<=5;i++) printf "%s", $i; print ""}' \
        | xxd -r -p 2>/dev/null | LC_ALL=C tr -c '[:print:]' '\n' \
        | grep -q "^hook_wrap$"; then
    echo "PASS importer.ko __versions references hook_wrap"
    pass=$((pass+1))
else
    echo "FAIL importer.ko __versions does not reference hook_wrap"
    fail=$((fail+1))
fi

echo ""
echo "Ring 2 ELF verify: $pass passed, $fail failed"
[ $fail -eq 0 ]
