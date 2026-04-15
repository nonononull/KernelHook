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
#   ./scripts/test_device_kmod.sh                               # sdk mode, first connected non-emulator
#   ./scripts/test_device_kmod.sh <adb-serial>                  # sdk mode, explicit device
#   ./scripts/test_device_kmod.sh --mode=freestanding           # legacy kh_test.ko kh_root demo + Ring 3 sweep
#   ./scripts/test_device_kmod.sh --mode=sdk <adb-serial>       # explicit sdk mode + explicit device
#
# Modes:
#   sdk (default): build kernelhook.ko + examples/hello_hook/hello_hook.ko,
#                  two-step kmod_loader insmod, verify hello_hook dmesg marker,
#                  reverse-order rmmod.
#   freestanding:  build tests/kmod/kh_test.ko, single-load, run the kh_root demo
#                  kh_root elevation test and the Ring 3 export_link_test sweep.
#
# Prereqs on the device:
#   - Connected via USB, `adb devices` shows it as "device"
#   - `su -c id` returns uid=0 (Magisk works)
#   - SELinux Permissive (Enforcing will block some module_load paths)
#   - CONFIG_MODULES=y  /proc/sys/kernel/modules_disabled=0

set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"

# Flag parser: --mode={sdk,freestanding} (default sdk). Bare arg is the adb serial.
# Default (sdk) builds + loads kernelhook.ko AND examples/hello_hook/hello_hook.ko
# (the SDK consumer reference under Phase B / 方案 C). Freestanding mode falls back
# to the legacy single-kh_test.ko path, which also runs the kh_root demo + Ring 3 sweep.
KH_MODE="sdk"
KH_SERIAL=""
while [ "$#" -gt 0 ]; do
    case "$1" in
        --mode=*) KH_MODE="${1#--mode=}"; shift ;;
        --) shift; break ;;
        -*) echo "unknown flag $1" >&2; exit 2 ;;
        *)  KH_SERIAL="$1"; shift ;;
    esac
done
case "$KH_MODE" in
    sdk|freestanding) ;;
    *) echo "invalid --mode=$KH_MODE (expected sdk|freestanding)" >&2; exit 2 ;;
esac

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
SERIAL="${KH_SERIAL:-}"
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
printf "Mode: %s\n" "$KH_MODE"
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

# Build the target kernel module(s) for this exact kernel version.
# SDK mode: kmod/kernelhook.ko + examples/hello_hook/hello_hook.ko (两步加载).
# Freestanding mode: tests/kmod/kh_test.ko (legacy single .ko, kh_root demo + Ring 3).
: > /tmp/kh_test_build.log
if [ "$KH_MODE" = "sdk" ]; then
    printf "  Building kernelhook.ko + hello_hook.ko (SDK mode) for %s...\n" "$UNAME"
    if ! ( cd "$ROOT/kmod" && \
           { make clean >/dev/null 2>&1 || true; } && \
           make module \
               KERNELRELEASE="$UNAME" \
               CC="$KH_CC" \
               LD="$KH_LD" \
               CROSS_COMPILE="$KH_CROSS_COMPILE" \
               >>/tmp/kh_test_build.log 2>&1 ); then
        printf "  ${RED}FAIL${RESET} kernelhook.ko build failed — see /tmp/kh_test_build.log\n"
        tail -30 /tmp/kh_test_build.log | sed 's/^/       /'
        exit 1
    fi
    if ! ( cd "$ROOT/examples/hello_hook" && \
           { make clean >/dev/null 2>&1 || true; } && \
           KERNELRELEASE="$UNAME" \
           CC="$KH_CC" \
           LD="$KH_LD" \
           CROSS_COMPILE="$KH_CROSS_COMPILE" \
           make module \
               >>/tmp/kh_test_build.log 2>&1 ); then
        printf "  ${RED}FAIL${RESET} hello_hook.ko (SDK) build failed — see /tmp/kh_test_build.log\n"
        tail -30 /tmp/kh_test_build.log | sed 's/^/       /'
        exit 1
    fi
else
    printf "  Building kh_test.ko (freestanding) for %s...\n" "$UNAME"
    cd "$ROOT/tests/kmod"
    make clean >/dev/null 2>&1 || true
    if ! make freestanding \
        KERNELRELEASE="$UNAME" \
        CC="$KH_CC" \
        LD="$KH_LD" \
        CROSS_COMPILE="$KH_CROSS_COMPILE" \
        CONFIG_KH_CHAIN_RCU=1 \
        >/tmp/kh_test_build.log 2>&1; then
        printf "  ${RED}FAIL${RESET} build failed — see /tmp/kh_test_build.log\n"
        tail -30 /tmp/kh_test_build.log | sed 's/^/       /'
        exit 1
    fi
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
if [ "$KH_MODE" = "sdk" ]; then
    $ADB push "$ROOT/kmod/kernelhook.ko"                /data/local/tmp/kernelhook.ko >/dev/null
    $ADB push "$ROOT/examples/hello_hook/hello_hook.ko" /data/local/tmp/hello_hook.ko >/dev/null
else
    $ADB push "$ROOT/tests/kmod/kh_test.ko"             /data/local/tmp/kh_test.ko    >/dev/null
fi
$ADB push "$LOADER" /data/local/tmp/kmod_loader >/dev/null
$ADB shell 'chmod +x /data/local/tmp/kmod_loader' >/dev/null

# Unload any stale modules from a previous run (ignore failure). In SDK mode
# the consumer (hello_hook) must come off first because it holds a refcount on
# kernelhook via the ksymtab imports.
if [ "$KH_MODE" = "sdk" ]; then
    dsu "rmmod hello_hook 2>/dev/null; rmmod kernelhook 2>/dev/null; true" >/dev/null || true
else
    dsu "rmmod kh_test 2>/dev/null; true" >/dev/null || true
fi
dsu "dmesg -c" >/dev/null 2>&1 || true

# Live kmsg capture for post-mortem if module init crashes the kernel.
LIVE_KMSG="/tmp/kh_dmesg_${SERIAL}.log"
rm -f "$LIVE_KMSG"
$ADB shell "su -c 'cat /dev/kmsg'" > "$LIVE_KMSG" 2>&1 &
KMSG_PID=$!
sleep 1

# Load. Host-side 60s timeout handles old BusyBox lacking `timeout`.
# SDK mode does a two-step load (kernelhook.ko first, then hello_hook.ko);
# freestanding mode loads the single kh_test.ko as before.
if [ "$KH_MODE" = "sdk" ]; then
    LOAD_OUTPUT=$(perl -e 'alarm 60; exec @ARGV' \
        $ADB shell "su -c '/data/local/tmp/kmod_loader /data/local/tmp/kernelhook.ko kallsyms_addr=0x${KADDR} ${CRC_ARGS}'" 2>&1) || true
    if ! echo "$LOAD_OUTPUT" | grep -qi "loaded"; then
        sleep 1
        kill "$KMSG_PID" 2>/dev/null || true
        wait "$KMSG_PID" 2>/dev/null || true
        printf "  ${RED}FAIL${RESET} kernelhook.ko load failed\n"
        echo "$LOAD_OUTPUT" | sed 's/^/       /'
        exit 1
    fi
    LOAD_OUTPUT=$(perl -e 'alarm 60; exec @ARGV' \
        $ADB shell "su -c '/data/local/tmp/kmod_loader /data/local/tmp/hello_hook.ko kallsyms_addr=0x${KADDR} ${CRC_ARGS}'" 2>&1) || true
    if ! echo "$LOAD_OUTPUT" | grep -qi "loaded"; then
        sleep 1
        kill "$KMSG_PID" 2>/dev/null || true
        wait "$KMSG_PID" 2>/dev/null || true
        printf "  ${RED}FAIL${RESET} hello_hook.ko load failed\n"
        echo "$LOAD_OUTPUT" | sed 's/^/       /'
        # Best-effort cleanup: peel kernelhook back off so we don't leave it loaded.
        dsu "rmmod kernelhook 2>/dev/null; true" >/dev/null || true
        exit 1
    fi
else
    LOAD_OUTPUT=$(perl -e 'alarm 60; exec @ARGV' \
        $ADB shell "su -c '/data/local/tmp/kmod_loader /data/local/tmp/kh_test.ko kallsyms_addr=0x${KADDR} ${CRC_ARGS}'" 2>&1) || true
fi

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

# ---- SDK mode: runtime-verify the hello_hook consumer, unload in reverse order, done.
# kh_root demo + Ring 3 are freestanding-mode concerns (kh_test.ko not loaded here).
#
# Two-step verification:
#   (1) Setup marker: 'hello_hook: hooked do_sys_open*' must appear in dmesg
#       after load — proves hook_wrap4() registered the trampoline.
#   (2) Fire marker: trigger a few open syscalls on-device, then verify that
#       'hello_hook: open called' appears >=1 time — proves the before-callback
#       was actually invoked by the kernel (not just installed).
# Both must succeed for the test to PASS. A hook that installs but never fires
# is a silent failure we need to catch.
if [ "$KH_MODE" = "sdk" ]; then
    sleep 2
    SDK_DMESG_SETUP=$(dsu "dmesg" 2>/dev/null)
    if ! echo "$SDK_DMESG_SETUP" | grep -q "hello_hook: hooked do_sys_open"; then
        printf "  ${RED}FAIL${RESET} hello_hook setup marker not found in dmesg\n"
        echo "$SDK_DMESG_SETUP" | grep -E "hello_hook:|kernelhook:" | tail -20 | sed 's/^/       /'
        dsu "rmmod hello_hook 2>/dev/null; rmmod kernelhook 2>/dev/null; true" >/dev/null || true
        exit 1
    fi
    SETUP_LINE=$(echo "$SDK_DMESG_SETUP" | grep "hello_hook: hooked do_sys_open" | tail -1)
    printf "  ${GREEN}PASS${RESET} setup: %s\n" "$SETUP_LINE"

    # Trigger a handful of open syscalls; every cat/ls forces do_sys_openat2
    # through the hooked path, so the before-callback should fire at least once.
    dsu "cat /system/build.prop >/dev/null 2>&1; \
         cat /proc/version    >/dev/null 2>&1; \
         ls   /data/local/tmp  >/dev/null 2>&1; true" >/dev/null 2>&1 || true
    sleep 1

    SDK_DMESG_FIRE=$(dsu "dmesg" 2>/dev/null)
    FIRE_COUNT=$(echo "$SDK_DMESG_FIRE" | grep -c "hello_hook: open called" || true)
    if [ "${FIRE_COUNT:-0}" -lt 1 ]; then
        printf "  ${RED}FAIL${RESET} hook installed but before-callback never fired (open_before not invoked)\n"
        echo "$SDK_DMESG_FIRE" | grep "hello_hook:" | tail -10 | sed 's/^/       /'
        dsu "rmmod hello_hook 2>/dev/null; rmmod kernelhook 2>/dev/null; true" >/dev/null || true
        exit 1
    fi
    printf "  ${GREEN}PASS${RESET} fire: before-callback invoked %d time(s) on triggered opens\n" "$FIRE_COUNT"

    # SDK unload: reverse order — consumer first (refcount holder),
    # then the SDK base module.
    dsu "rmmod hello_hook 2>/dev/null; true" >/dev/null || true
    dsu "rmmod kernelhook 2>/dev/null; true" >/dev/null || true

    printf "\n${GREEN}All device tests passed.${RESET}\n"
    printf "=== Summary: %d PASS, %d FAIL ===\n" 2 0
    exit 0
fi

sleep 3
DMESG=$(dsu "dmesg" 2>/dev/null | grep "kh_test:")

# Capture kh_root demo result while module is still loaded (hooks active).
uid_before=$(adb -s "$SERIAL" shell 'id -u' | tr -d '\r\n')
uid_kh_root=$(adb -s "$SERIAL" shell '/system/bin/kh_root -c "id -u"' 2>&1 | tr -d '\r\n')

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

# ---- kh_root demo verification: elevates uid=0 ----
# uid_before / uid_kh_root were captured above while the module was loaded.
printf "\nVerifying kh_root demo...\n"
printf "  baseline shell uid = %s\n" "$uid_before"
printf "  kh_root -c id -u   = %s\n" "$uid_kh_root"
if [ "$uid_kh_root" != "0" ]; then
    printf "  ${RED}FAIL${RESET} kh_root demo: kh_root did not elevate to uid=0 (got '%s')\n" "$uid_kh_root"
    exit 1
fi
printf "  ${GREEN}PASS${RESET} kh_root demo: kh_root elevated %s → 0\n" "$uid_before"

printf "\n${GREEN}All device tests passed.${RESET}\n"

# Final safety net: if any kh_test FAIL lines leaked through above guards, exit non-zero.
# $FAILED is populated from the kh_test Results: dmesg line (lines 183-185 above).
# R3_FAIL covers Ring 3; both are already checked, but make the exit explicit.
TOTAL_FAIL=$(( FAILED + R3_FAIL ))
TOTAL_PASS=$(( PASSED + R3_PASS ))
printf "=== Summary: %d PASS, %d FAIL ===\n" "$TOTAL_PASS" "$TOTAL_FAIL"
if [ "$TOTAL_FAIL" -gt 0 ]; then
    exit 1
fi
exit 0
