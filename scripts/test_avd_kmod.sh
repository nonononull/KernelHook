#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-or-later
# Automated kmod test runner for all AVD emulators.
#
# Usage:
#   ./scripts/test_avd_kmod.sh                  # test all AVDs
#   ./scripts/test_avd_kmod.sh Pixel_31 Pixel_37 # test specific AVDs

set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"

# Resolve SDK + toolchain via shared detector.
# Exports KH_ANDROID_SDK, KH_CC, KH_LD, KH_NDK_BIN, KH_ANDROID_API_LEVEL, ...
# shellcheck source=lib/detect_toolchain.sh
. "$ROOT/scripts/lib/detect_toolchain.sh" || {
    echo "ERROR: toolchain detection failed" >&2
    exit 1
}

if [ -z "${KH_ANDROID_SDK:-}" ]; then
    echo "ERROR: Android SDK root not found. Set ANDROID_SDK_ROOT or ANDROID_HOME." >&2
    exit 1
fi
EMULATOR="$KH_ANDROID_SDK/emulator/emulator"

RED='\033[31m'; GREEN='\033[32m'; YELLOW='\033[33m'; BOLD='\033[1m'; RESET='\033[0m'

case "${KH_TOOLCHAIN_KIND:-}" in
    sys-gcc|sys-clang)
        echo "ERROR: test_avd_kmod.sh requires a real NDK (bionic ABI for kmod_loader)." >&2
        echo "       Set \$ANDROID_NDK_ROOT or install the NDK." >&2
        exit 2
        ;;
esac

# Build kmod_loader if missing
LOADER="$ROOT/tools/kmod_loader/kmod_loader"
if [ ! -f "$LOADER" ]; then
    printf "${BOLD}Building kmod_loader...${RESET}\n"
    cd "$ROOT/tools/kmod_loader"
    $KH_CC -DEMBED_PROBE_KO -static -O2 -o kmod_loader kmod_loader.c
fi

# Determine AVD list
if [ $# -gt 0 ]; then
    AVDS=("$@")
else
    AVDS=($(ls ~/.android/avd/*.ini 2>/dev/null | sed 's|.*/||;s|\.ini$||' | grep -v Small | sort))
fi

RESULTS=()
PASS_COUNT=0
FAIL_COUNT=0
SKIP_COUNT=0

kill_emulator() {
    # Kill all emulators on all ports
    for serial in $(adb devices 2>/dev/null | grep 'emulator-' | awk '{print $1}'); do
        adb -s "$serial" emu kill >/dev/null 2>&1 || true
    done
    sleep 3
    # Force-kill any remaining QEMU processes
    pkill -9 -f 'qemu-system' 2>/dev/null || true
    sleep 2
    # Wait until no emulators in adb
    for i in $(seq 1 10); do
        if ! adb devices 2>/dev/null | grep -q "emulator-"; then break; fi
        sleep 2
    done
}

test_avd() {
    local avd="$1"
    printf "\n${BOLD}======== Testing $avd ========${RESET}\n"

    # Kill any running emulator
    kill_emulator

    # Start emulator
    "$EMULATOR" -avd "$avd" -no-window -no-audio -no-boot-anim -no-snapshot-load -gpu swiftshader_indirect >/dev/null 2>&1 &
    local emu_pid=$!

    # Wait for boot (max 120s)
    local booted=0
    for i in $(seq 1 24); do
        sleep 5
        local boot=$(adb -s emulator-5554 shell "getprop sys.boot_completed" 2>/dev/null | tr -d '[:space:]')
        if [ "$boot" = "1" ]; then booted=1; break; fi
    done

    if [ "$booted" -ne 1 ]; then
        printf "  ${RED}SKIP${RESET} $avd: boot timeout\n"
        RESULTS+=("SKIP|$avd|boot_timeout||")
        SKIP_COUNT=$((SKIP_COUNT + 1))
        kill_emulator
        return
    fi

    # Get root — must happen before any privileged operations.
    # adb root restarts adbd, so we re-establish the connection.
    adb -s emulator-5554 root >/dev/null 2>&1
    sleep 3
    adb -s emulator-5554 wait-for-device >/dev/null 2>&1

    local uname=$(adb -s emulator-5554 shell "uname -r" 2>/dev/null | tr -d '[:space:]')
    local sdk=$(adb -s emulator-5554 shell "getprop ro.build.version.sdk" 2>/dev/null | tr -d '[:space:]')
    printf "  API: %s  Kernel: %s\n" "$sdk" "$uname"

    # Skip kernels before 4.4 — 3.18's ARM64 module loader hangs on large
    # freestanding modules (too many MOVW relocations). Minimum supported: 4.4.
    local kmajor=$(echo "$uname" | cut -d. -f1)
    local kminor=$(echo "$uname" | cut -d. -f2)
    if [ "$kmajor" -lt 4 ] || ([ "$kmajor" -eq 4 ] && [ "$kminor" -lt 4 ]); then
        printf "  ${YELLOW}SKIP${RESET} $avd: kernel %s (3.18 module loader incompatible)\n" "$uname"
        RESULTS+=("SKIP|$avd|kernel_3.18|$sdk|$uname")
        SKIP_COUNT=$((SKIP_COUNT + 1))
        kill_emulator
        return
    fi

    # Check if modules are supported
    local mod_support=$(adb -s emulator-5554 shell "zcat /proc/config.gz 2>/dev/null | grep '^CONFIG_MODULES=y'" 2>/dev/null | tr -d '[:space:]')
    if [ "$mod_support" != "CONFIG_MODULES=y" ]; then
        printf "  ${YELLOW}SKIP${RESET} $avd: CONFIG_MODULES not enabled\n"
        RESULTS+=("SKIP|$avd|no_modules|$sdk|$uname")
        SKIP_COUNT=$((SKIP_COUNT + 1))
        kill_emulator
        return
    fi

    # Build kh_test.ko for this kernel
    printf "  Building kh_test.ko...\n"
    cd "$ROOT/tests/kmod"
    make clean >/dev/null 2>&1 || true
    if ! make freestanding \
        KERNELRELEASE="$uname" \
        CC="$KH_CC" \
        LD="$KH_LD" \
        CROSS_COMPILE="$KH_CROSS_COMPILE" \
        >/dev/null 2>&1; then
        printf "  ${RED}FAIL${RESET} $avd: build failed\n"
        RESULTS+=("FAIL|$avd|build_failed|$sdk|$uname")
        FAIL_COUNT=$((FAIL_COUNT + 1))
        kill_emulator
        return
    fi

    # Setup device — run all privileged ops in a single shell to avoid root loss
    adb -s emulator-5554 shell "setenforce 0; echo 0 > /proc/sys/kernel/kptr_restrict; echo 0 > /proc/sys/kernel/panic_on_oops" >/dev/null 2>&1 || true

    # Get kallsyms_lookup_name address
    local kaddr=$(adb -s emulator-5554 shell "cat /proc/kallsyms" 2>/dev/null | grep -E ' [Tt] kallsyms_lookup_name$' | awk '{print $1}' | head -1)
    if [ -z "$kaddr" ] || [ "$kaddr" = "0000000000000000" ]; then
        kaddr="0"
    fi
    printf "  kallsyms_lookup_name: 0x%s\n" "$kaddr"

    # Extract CRCs from host-side kernel image (fallback for AVDs without vendor .ko).
    # kmod_loader can auto-resolve CRCs from vendor modules on device, but older AVDs
    # (API <31) may lack vendor .ko files.
    local crc_args=""
    local crc_output=$(python3 "$ROOT/scripts/extract_avd_crcs.py" -s emulator-5554 module_layout _printk printk memcpy memset 2>/dev/null || echo "")
    if [ -n "$crc_output" ]; then
        crc_args=$(echo "$crc_output" | grep '^--crc' | tr '\n' ' ' || true)
    fi
    if [ -n "$crc_args" ]; then
        printf "  CRCs: %s\n" "$crc_args"
    else
        printf "  CRCs: (auto-resolve via kmod_loader)\n"
    fi

    # Push files
    adb -s emulator-5554 push "$ROOT/tests/kmod/kh_test.ko" /data/local/tmp/kh_test.ko >/dev/null 2>&1 || true
    adb -s emulator-5554 push "$LOADER" /data/local/tmp/kmod_loader >/dev/null 2>&1 || true
    adb -s emulator-5554 shell "chmod +x /data/local/tmp/kmod_loader" >/dev/null 2>&1 || true

    # Load and test — run in single shell session to stay root
    adb -s emulator-5554 shell "rmmod kh_test" >/dev/null 2>&1 || true
    adb -s emulator-5554 shell "dmesg -c" >/dev/null 2>&1 || true
    local load_output=""
    local load_rc=1
    # Use host-side timeout (60s) since Android 'timeout' may not exist on old AVDs
    load_output=$(perl -e 'alarm 60; exec @ARGV' adb -s emulator-5554 shell "/data/local/tmp/kmod_loader /data/local/tmp/kh_test.ko kallsyms_addr=0x${kaddr} ${crc_args}" 2>&1) || true
    load_rc=$?

    if ! echo "$load_output" | grep -qi "loaded"; then
        printf "  ${RED}FAIL${RESET} $avd: module load failed\n"
        echo "$load_output" | sed 's/^/       /'
        RESULTS+=("FAIL|$avd|load_failed|$sdk|$uname")
        FAIL_COUNT=$((FAIL_COUNT + 1))
        kill_emulator
        return
    fi

    # Wait for tests and capture results
    sleep 3
    local dmesg=$(adb -s emulator-5554 shell "dmesg" 2>/dev/null | grep "kh_test:")
    adb -s emulator-5554 shell "rmmod kh_test" >/dev/null 2>&1

    # Parse results
    local summary=$(echo "$dmesg" | grep "Results:")
    local passed=$(echo "$summary" | grep -oE '[0-9]+ passed' | grep -oE '[0-9]+')
    local failed=$(echo "$summary" | grep -oE '[0-9]+ failed' | grep -oE '[0-9]+')
    passed="${passed:-0}"
    failed="${failed:-0}"

    if echo "$dmesg" | grep -q "ALL TESTS PASSED"; then
        printf "  ${GREEN}PASS${RESET} $avd: %s passed, %s failed (API %s, kernel %s)\n" "$passed" "$failed" "$sdk" "$uname"
        RESULTS+=("PASS|$avd|${passed}/${passed}|$sdk|$uname")
        PASS_COUNT=$((PASS_COUNT + 1))

        # ---- Ring 3: export_link_test (exporter + importer) ----
        printf "  Running export_link_test (Ring 3)...\n"
        (
            cd "$ROOT/tests/kmod/export_link_test" && \
            make clean >/dev/null 2>&1; \
            KERNELRELEASE="$uname" \
            CC="$KH_CC" \
            LD="$KH_LD" \
            CROSS_COMPILE="$KH_CROSS_COMPILE" \
            make >/dev/null 2>&1
        )
        if [ ! -f "$ROOT/tests/kmod/export_link_test/exporter.ko" ] || \
           [ ! -f "$ROOT/tests/kmod/export_link_test/importer.ko" ]; then
            printf "  ${RED}FAIL${RESET} $avd: export_link_test build failed\n"
            RESULTS+=("FAIL|$avd|export_link_build|$sdk|$uname")
            FAIL_COUNT=$((FAIL_COUNT + 1))
        else
            if KADDR="0x${kaddr}" CRC_ARGS="${crc_args}" \
               "$ROOT/tests/kmod/export_link_test/test_on_avd.sh" emulator-5554; then
                printf "  ${GREEN}PASS${RESET} $avd: export_link_test (Ring 3)\n"
                RESULTS+=("PASS|$avd|export_link_test|$sdk|$uname")
            else
                printf "  ${RED}FAIL${RESET} $avd: export_link_test (Ring 3)\n"
                RESULTS+=("FAIL|$avd|export_link_test|$sdk|$uname")
                FAIL_COUNT=$((FAIL_COUNT + 1))
            fi
        fi
    elif [ "$passed" -gt 0 ] || [ "$failed" -gt 0 ]; then
        printf "  ${RED}FAIL${RESET} $avd: %s passed, %s failed\n" "$passed" "$failed"
        echo "$dmesg" | grep -i "FAIL" | sed 's/^/       /'
        RESULTS+=("FAIL|$avd|${passed}/$((passed+failed))|$sdk|$uname")
        FAIL_COUNT=$((FAIL_COUNT + 1))
    else
        printf "  ${YELLOW}WARN${RESET} $avd: no test output (init may not have run)\n"
        echo "$dmesg" | head -5 | sed 's/^/       /'
        RESULTS+=("FAIL|$avd|no_output|$sdk|$uname")
        FAIL_COUNT=$((FAIL_COUNT + 1))
    fi

    kill_emulator
}

printf "${BOLD}KernelHook kmod AVD Test Suite${RESET}\n"
printf "AVDs to test: %s\n" "${AVDS[*]}"
printf "Toolchain: %s\n\n" "$KH_TOOLCHAIN_DESC"

for avd in "${AVDS[@]}"; do
    test_avd "$avd"
done

# Summary
printf "\n${BOLD}================ Summary ================${RESET}\n"
printf "%-14s %-6s %-10s %-35s %s\n" "AVD" "API" "Result" "Kernel" "Detail"
printf "%-14s %-6s %-10s %-35s %s\n" "---" "---" "------" "------" "------"
for r in "${RESULTS[@]}"; do
    IFS='|' read -r status avd detail api kernel <<< "$r"
    case "$status" in
        PASS)  color="$GREEN" ;;
        FAIL)  color="$RED" ;;
        SKIP)  color="$YELLOW" ;;
        *)     color="$RESET" ;;
    esac
    printf "%-14s %-6s ${color}%-10s${RESET} %-35s %s\n" "$avd" "$api" "$status" "$kernel" "$detail"
done
printf "\n${GREEN}Passed: %d${RESET}  ${RED}Failed: %d${RESET}  ${YELLOW}Skipped: %d${RESET}  Total: %d\n" \
    "$PASS_COUNT" "$FAIL_COUNT" "$SKIP_COUNT" "$((PASS_COUNT + FAIL_COUNT + SKIP_COUNT))"

exit $((FAIL_COUNT > 0 ? 1 : 0))
