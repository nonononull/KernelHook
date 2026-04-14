#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-or-later
# Automated kmod test runner for a physical (USB) Android device.
#
# Mirrors scripts/test_avd_kmod.sh but skips emulator boot and routes
# every privileged command through `su -c` (Magisk-rooted userdebug or
# production builds with su binaries installed). `adb root` is not
# required — production builds reject it.
#
# Usage:
#   ./scripts/test_device_kmod.sh                  # first connected non-emulator
#   ./scripts/test_device_kmod.sh <adb-serial>     # target a specific device
#
# Prereqs on the device:
#   - Connected via USB, `adb devices` shows it as "device"
#   - `su -c id` returns uid=0 (Magisk works)
#   - SELinux Permissive (Enforcing will block some module_load paths)
#   - CONFIG_MODULES=y  /proc/sys/kernel/modules_disabled=0

set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"

# shellcheck source=lib/detect_toolchain.sh
. "$ROOT/scripts/lib/detect_toolchain.sh" || {
    echo "ERROR: toolchain detection failed" >&2
    exit 1
}

case "${KH_TOOLCHAIN_KIND:-}" in
    sys-gcc|sys-clang)
        echo "ERROR: test_device_kmod.sh requires a real NDK (bionic ABI for kmod_loader)." >&2
        echo "       Set \$ANDROID_NDK_ROOT or install the NDK." >&2
        exit 2
        ;;
esac

RED='\033[31m'; GREEN='\033[32m'; YELLOW='\033[33m'; BOLD='\033[1m'; RESET='\033[0m'

# Pick device serial: explicit arg > first non-emulator `adb devices`.
SERIAL="${1:-}"
if [ -z "$SERIAL" ]; then
    SERIAL=$(adb devices 2>/dev/null \
        | awk 'NR>1 && $2=="device" && $1 !~ /^emulator-/ {print $1; exit}')
    if [ -z "$SERIAL" ]; then
        echo "ERROR: no non-emulator adb device found. Run 'adb devices' and pass serial explicitly." >&2
        exit 2
    fi
fi
ADB="adb -s $SERIAL"
printf "${BOLD}KernelHook kmod Device Test${RESET}\n"
printf "Device serial: %s\n" "$SERIAL"
printf "Toolchain: %s\n\n" "$KH_TOOLCHAIN_DESC"

# Helper: run a shell command as root on the device. Echoes combined stdout+stderr.
# All privileged ops go through this so the script stays flat.
dsu() {
    # Escape outer double quotes in the caller's command by wrapping with single-quote-outer
    # via printf. Using 'sh -c' for predictable quoting.
    $ADB shell "su -c 'sh -c \"$*\"'"
}

# Preflight: root + SELinux + module_disabled
if ! ROOT_ID=$($ADB shell 'su -c id' 2>&1) || ! echo "$ROOT_ID" | grep -q 'uid=0'; then
    echo "ERROR: 'su -c id' did not return uid=0. Is Magisk root granted for adb shell?" >&2
    echo "  got: $ROOT_ID" >&2
    exit 2
fi
SELINUX=$(dsu "getenforce" 2>&1 | tr -d '[:space:]')
MD=$(dsu "cat /proc/sys/kernel/modules_disabled" 2>&1 | tr -d '[:space:]')
printf "  SELinux: %s   modules_disabled: %s\n" "$SELINUX" "$MD"
if [ "$MD" != "0" ]; then
    echo "ERROR: kernel has modules_disabled=1 — module loading is permanently blocked." >&2
    exit 2
fi
if [ "$SELINUX" = "Enforcing" ]; then
    printf "  ${YELLOW}WARN${RESET} SELinux is Enforcing — attempting setenforce 0 to avoid avc denials.\n"
    dsu "setenforce 0 2>&1 || true" >/dev/null || true
fi

# Production Pixel / Samsung GKI kernels ship with
# CONFIG_MODULE_SIG_PROTECT=y — a vendor-specific extension that blocks
# init_module for unsigned modules even when CONFIG_MODULE_SIG_FORCE is
# unset. Magisk root cannot bypass this (the check lives inside the
# kernel's module loader, not userspace), and attempting to insmod
# triggers a silent init skip or — worse — a kernel panic that reboots
# the device. Detect the config up front and refuse rather than brick
# the phone's uptime.
SIG_PROTECT=$(dsu "zcat /proc/config.gz 2>/dev/null | grep -E '^CONFIG_MODULE_SIG_PROTECT='" 2>&1 | tr -d '[:space:]')
if [ "$SIG_PROTECT" = "CONFIG_MODULE_SIG_PROTECT=y" ]; then
    printf "  ${RED}REFUSE${RESET} kernel has CONFIG_MODULE_SIG_PROTECT=y.\n"
    printf "         Vendor signature enforcement blocks unsigned module init;\n"
    printf "         insmod typically reboots the device. Run this suite on a\n"
    printf "         userdebug/eng kernel or an AVD instead (scripts/test_avd_kmod.sh).\n"
    exit 3
fi

# Build kmod_loader if missing.
LOADER="$ROOT/tools/kmod_loader/kmod_loader"
if [ ! -f "$LOADER" ]; then
    printf "${BOLD}Building kmod_loader...${RESET}\n"
    make -C "$ROOT/tools/kmod_loader" kmod_loader HOSTCC="$KH_CC" >/dev/null
fi

# Read live kernel version and API level. These must come from the
# device — a host-side guess would pick the wrong vermagic.
UNAME=$($ADB shell 'uname -r' 2>/dev/null | tr -d '[:space:]')
SDK=$($ADB shell 'getprop ro.build.version.sdk' 2>/dev/null | tr -d '[:space:]')
printf "  API: %s   Kernel: %s\n" "$SDK" "$UNAME"

# Kernel 3.18 ARM64 module loader can't handle our large freestanding
# .ko (too many MOVW relocations). Same gate as AVD script.
KMAJOR=$(echo "$UNAME" | cut -d. -f1)
KMINOR=$(echo "$UNAME" | cut -d. -f2)
if [ "$KMAJOR" -lt 4 ] || { [ "$KMAJOR" -eq 4 ] && [ "$KMINOR" -lt 4 ]; }; then
    echo "ERROR: kernel $UNAME is pre-4.4 — unsupported by this module loader."
    exit 2
fi

# Build kh_test.ko for this exact kernel version.
printf "  Building kh_test.ko for %s...\n" "$UNAME"
cd "$ROOT/tests/kmod"
make clean >/dev/null 2>&1 || true
if ! make freestanding \
    KERNELRELEASE="$UNAME" \
    CC="$KH_CC" \
    LD="$KH_LD" \
    CROSS_COMPILE="$KH_CROSS_COMPILE" \
    >/tmp/kh_test_build.log 2>&1; then
    printf "  ${RED}FAIL${RESET} build failed — see /tmp/kh_test_build.log\n"
    tail -30 /tmp/kh_test_build.log | sed 's/^/       /'
    exit 1
fi

# Bypass kptr_restrict so we can read kallsyms_lookup_name from /proc/kallsyms.
dsu "echo 0 > /proc/sys/kernel/kptr_restrict" >/dev/null 2>&1 || true
KADDR=$(dsu "cat /proc/kallsyms" 2>/dev/null \
    | grep -E ' [Tt] kallsyms_lookup_name$' | awk '{print $1}' | head -1)
if [ -z "$KADDR" ] || [ "$KADDR" = "0000000000000000" ]; then
    KADDR="0"
fi
printf "  kallsyms_lookup_name: 0x%s\n" "$KADDR"

# CRC auto-resolve via on-device vendor modules (same fallback path
# kmod_loader uses); only pass host-extracted CRCs when we have them.
CRC_ARGS=""
CRC_OUT=$(python3 "$ROOT/scripts/extract_avd_crcs.py" -s "$SERIAL" \
    module_layout _printk printk memcpy memset 2>/dev/null || echo "")
if [ -n "$CRC_OUT" ]; then
    CRC_ARGS=$(echo "$CRC_OUT" | grep '^--crc' | tr '\n' ' ' || true)
fi
if [ -n "$CRC_ARGS" ]; then
    printf "  CRCs: %s\n" "$CRC_ARGS"
else
    printf "  CRCs: (auto-resolve via kmod_loader)\n"
fi

# Push files. /data/local/tmp is world-writable; chmod happens there.
$ADB push "$ROOT/tests/kmod/kh_test.ko" /data/local/tmp/kh_test.ko >/dev/null
$ADB push "$LOADER" /data/local/tmp/kmod_loader >/dev/null
$ADB shell 'chmod +x /data/local/tmp/kmod_loader' >/dev/null

# Unload any stale kh_test from a previous run (ignore failure).
dsu "rmmod kh_test 2>/dev/null; true" >/dev/null || true
dsu "dmesg -c" >/dev/null 2>&1 || true

# Live kmsg capture for post-mortem if module init crashes the kernel.
LIVE_KMSG="/tmp/kh_dmesg_${SERIAL}.log"
rm -f "$LIVE_KMSG"
$ADB shell "su -c 'cat /dev/kmsg'" > "$LIVE_KMSG" 2>&1 &
KMSG_PID=$!
sleep 1

# Load. Host-side 60s timeout handles old BusyBox lacking `timeout`.
LOAD_OUTPUT=$(perl -e 'alarm 60; exec @ARGV' \
    $ADB shell "su -c '/data/local/tmp/kmod_loader /data/local/tmp/kh_test.ko kallsyms_addr=0x${KADDR} ${CRC_ARGS}'" 2>&1) || true

sleep 1
kill "$KMSG_PID" 2>/dev/null || true
wait "$KMSG_PID" 2>/dev/null || true

if [ -s "$LIVE_KMSG" ] && grep -qE "BUG:|Unable to handle|Oops|Kernel panic|Call trace:" "$LIVE_KMSG"; then
    printf "  ${YELLOW}Kernel panic captured in live kmsg:${RESET}\n"
    awk '/BUG:|Unable to handle|Oops|Kernel panic|Call trace:/{p=1} p{print; if(++n>80) exit}' "$LIVE_KMSG" \
        | sed 's/^/       /'
fi

if ! echo "$LOAD_OUTPUT" | grep -qi "loaded"; then
    printf "  ${RED}FAIL${RESET} module load failed\n"
    echo "$LOAD_OUTPUT" | sed 's/^/       /'
    exit 1
fi

sleep 3
DMESG=$(dsu "dmesg" 2>/dev/null | grep "kh_test:")
dsu "rmmod kh_test 2>/dev/null; true" >/dev/null || true

SUMMARY=$(echo "$DMESG" | grep "Results:")
PASSED=$(echo "$SUMMARY" | grep -oE '[0-9]+ passed' | grep -oE '[0-9]+')
FAILED=$(echo "$SUMMARY" | grep -oE '[0-9]+ failed' | grep -oE '[0-9]+')
PASSED="${PASSED:-0}"
FAILED="${FAILED:-0}"

if echo "$DMESG" | grep -q "ALL TESTS PASSED"; then
    printf "  ${GREEN}PASS${RESET} %s passed, %s failed (API %s, kernel %s)\n" \
        "$PASSED" "$FAILED" "$SDK" "$UNAME"
else
    printf "  ${RED}FAIL${RESET} %s passed, %s failed\n" "$PASSED" "$FAILED"
    echo "$DMESG" | grep -i "FAIL" | sed 's/^/       /'
    exit 1
fi

# ---- Ring 3: export_link_test ----
printf "  Running export_link_test (Ring 3)...\n"
# Layout probe: PREL32 vs ABS64 __ksymtab struct — same logic as AVD.
KH_LAYOUT="prel32"
if dsu "zcat /proc/config.gz 2>/dev/null | grep -q CONFIG_HAVE_ARCH_PREL32_RELOCATIONS=y"; then
    KH_LAYOUT="prel32"
else
    KH_LAYOUT="abs64"
fi
printf "  Ring 3 __ksymtab layout: %s\n" "$KH_LAYOUT"

(
    cd "$ROOT/tests/kmod/export_link_test" && \
    rm -rf _kh_kmod _kh_core exporter.ko importer.ko \
           exporter.kmod.o importer.kmod.o \
           "$ROOT/kmod/generated/kh_exports.S" 2>/dev/null; \
    KERNELRELEASE="$UNAME" \
    CC="$KH_CC" \
    LD="$KH_LD" \
    CROSS_COMPILE="$KH_CROSS_COMPILE" \
    KH_KSYMTAB_LAYOUT="$KH_LAYOUT" \
    make >/tmp/kh_ring3_build.log 2>&1
)
if [ ! -f "$ROOT/tests/kmod/export_link_test/exporter.ko" ] \
   || [ ! -f "$ROOT/tests/kmod/export_link_test/importer.ko" ]; then
    printf "  ${RED}FAIL${RESET} Ring 3 build failed — see /tmp/kh_ring3_build.log\n"
    exit 1
fi

# Re-use the existing Ring 3 driver, but it does `$ADB shell "cmd"` directly
# (shell user) instead of su. Inline a device-native version here.
EXPORTER="$ROOT/tests/kmod/export_link_test/exporter.ko"
IMPORTER="$ROOT/tests/kmod/export_link_test/importer.ko"

$ADB push "$EXPORTER" /data/local/tmp/exporter.ko >/dev/null
$ADB push "$IMPORTER" /data/local/tmp/importer.ko >/dev/null

dsu "rmmod importer 2>/dev/null; rmmod exporter 2>/dev/null; dmesg -c 2>/dev/null; true" >/dev/null || true

EXP_OUT=$(dsu "/data/local/tmp/kmod_loader /data/local/tmp/exporter.ko kallsyms_addr=0x${KADDR} ${CRC_ARGS}" 2>&1)
if ! echo "$EXP_OUT" | grep -qi "loaded"; then
    printf "  ${RED}FAIL${RESET} Ring 3: exporter.ko load failed\n"
    echo "$EXP_OUT" | sed 's/^/       /'
    exit 1
fi
IMP_OUT=$(dsu "/data/local/tmp/kmod_loader /data/local/tmp/importer.ko kallsyms_addr=0x${KADDR} ${CRC_ARGS}" 2>&1)
if ! echo "$IMP_OUT" | grep -qi "loaded"; then
    printf "  ${RED}FAIL${RESET} Ring 3: importer.ko load failed\n"
    echo "$IMP_OUT" | sed 's/^/       /'
    dsu "dmesg | tail -30" | sed 's/^/       dmesg: /'
    dsu "rmmod exporter 2>/dev/null; true" >/dev/null || true
    exit 1
fi

sleep 1
R3_DMESG=$(dsu "dmesg" 2>/dev/null)

R3_PASS=0; R3_FAIL=0
if echo "$R3_DMESG" | grep -q "export_link_test exporter: loaded"; then
    R3_PASS=$((R3_PASS+1))
else
    printf "  ${RED}FAIL${RESET} Ring 3: exporter load-marker missing\n"; R3_FAIL=$((R3_FAIL+1))
fi
if echo "$R3_DMESG" | grep -q "export_link_test importer: vfs_open"; then
    R3_PASS=$((R3_PASS+1))
else
    printf "  ${RED}FAIL${RESET} Ring 3: importer vfs_open-marker missing\n"; R3_FAIL=$((R3_FAIL+1))
fi
if echo "$R3_DMESG" | grep -q "Unknown symbol"; then
    printf "  ${RED}FAIL${RESET} Ring 3: Unknown symbol errors in dmesg\n"
    echo "$R3_DMESG" | grep "Unknown symbol" | sed 's/^/       /'
    R3_FAIL=$((R3_FAIL+1))
else
    R3_PASS=$((R3_PASS+1))
fi

dsu "rmmod importer 2>/dev/null; rmmod exporter 2>/dev/null; true" >/dev/null || true

if [ "$R3_FAIL" -ne 0 ]; then
    printf "  ${RED}FAIL${RESET} Ring 3: %d passed, %d failed\n" "$R3_PASS" "$R3_FAIL"
    exit 1
fi
printf "  ${GREEN}PASS${RESET} Ring 3: %d/%d\n" "$R3_PASS" "$R3_PASS"

printf "\n${GREEN}All device tests passed.${RESET}\n"
exit 0
