#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-or-later
# Ring 3 test: push exporter.ko + importer.ko to a running AVD, load both
# via kmod_loader, and assert dmesg has the expected success markers with
# no "disagrees" / "Unknown symbol" errors.
#
# Usage:
#   KADDR=0x<kallsyms_lookup_name> CRC_ARGS="--crc module_layout=0x..." \
#       ./test_on_avd.sh <adb-serial>
#
# If KADDR is omitted we try to read /proc/kallsyms on the device.
# Requires: an AVD already booted + rooted + reachable via adb.

set -uo pipefail

cd "$(dirname "$0")"
ROOT="$(cd ../../.. && pwd)"

SERIAL="${1:-emulator-5554}"
ADB="adb -s $SERIAL"
KADDR="${KADDR:-}"
CRC_ARGS="${CRC_ARGS:-}"

if [ ! -f exporter.ko ] || [ ! -f importer.ko ]; then
    echo "ERROR: exporter.ko / importer.ko not built — run 'make' first" >&2
    exit 2
fi

LOADER="$ROOT/tools/kmod_loader/kmod_loader"
if [ ! -f "$LOADER" ]; then
    echo "ERROR: kmod_loader not built at $LOADER" >&2
    exit 2
fi

# Resolve kallsyms_lookup_name if caller didn't supply it.
if [ -z "$KADDR" ]; then
    KADDR=$($ADB shell "cat /proc/kallsyms" 2>/dev/null \
        | grep -E ' [Tt] kallsyms_lookup_name$' | awk '{print $1}' | head -1)
    KADDR="${KADDR:-0}"
    KADDR="0x${KADDR}"
fi

echo "[ring3] serial=$SERIAL kaddr=$KADDR"
[ -n "$CRC_ARGS" ] && echo "[ring3] crc_args=$CRC_ARGS"

$ADB push exporter.ko /data/local/tmp/exporter.ko >/dev/null
$ADB push importer.ko /data/local/tmp/importer.ko >/dev/null
$ADB push "$LOADER"   /data/local/tmp/kmod_loader >/dev/null
$ADB shell "chmod +x /data/local/tmp/kmod_loader" >/dev/null

# Reset device state and clear dmesg ring.
$ADB shell "rmmod importer 2>/dev/null; rmmod exporter 2>/dev/null; dmesg -c >/dev/null 2>&1; true"

# Load exporter first — provides __ksymtab/__kcrctab entries.
load_out=$($ADB shell "/data/local/tmp/kmod_loader /data/local/tmp/exporter.ko kallsyms_addr=${KADDR} ${CRC_ARGS}" 2>&1)
if ! echo "$load_out" | grep -qi "loaded"; then
    echo "FAIL: exporter.ko load failed" >&2
    echo "$load_out" | sed 's/^/  /'
    $ADB shell "dmesg | tail -30" | sed 's/^/  dmesg: /'
    exit 1
fi

# Load importer — references the exporter's symbols.
load_out=$($ADB shell "/data/local/tmp/kmod_loader /data/local/tmp/importer.ko kallsyms_addr=${KADDR} ${CRC_ARGS}" 2>&1)
if ! echo "$load_out" | grep -qi "loaded"; then
    echo "FAIL: importer.ko load failed" >&2
    echo "$load_out" | sed 's/^/  /'
    $ADB shell "dmesg | tail -30" | sed 's/^/  dmesg: /'
    $ADB shell "rmmod exporter" >/dev/null 2>&1 || true
    exit 1
fi

sleep 1
dmesg_output=$($ADB shell "dmesg" 2>/dev/null)

pass=0
fail=0
check_contains() {
    if echo "$dmesg_output" | grep -q "$1"; then
        echo "PASS dmesg contains: $1"; pass=$((pass+1))
    else
        echo "FAIL dmesg missing: $1"; fail=$((fail+1))
    fi
}
check_not_contains() {
    if echo "$dmesg_output" | grep -q "$1"; then
        echo "FAIL dmesg contains forbidden: $1"; fail=$((fail+1))
    else
        echo "PASS dmesg lacks: $1"; pass=$((pass+1))
    fi
}

check_contains "export_link_test exporter: loaded"
check_contains "export_link_test importer: do_sys_openat2"
check_not_contains "disagrees about version of symbol"
check_not_contains "Unknown symbol"

# Clean up in reverse order.
$ADB shell "rmmod importer" >/dev/null 2>&1 || true
$ADB shell "rmmod exporter" >/dev/null 2>&1 || true

echo ""
echo "Ring 3 AVD test: $pass passed, $fail failed"
if [ $fail -ne 0 ]; then
    echo "---- last 60 lines of dmesg ----"
    echo "$dmesg_output" | tail -60
    exit 1
fi
echo "Ring 3 AVD test: PASS"
