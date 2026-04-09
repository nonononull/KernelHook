#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-or-later
# Run KernelHook tests on an Android device or emulator via ADB.
#
# Usage:
#   ./scripts/run_android_tests.sh                    # auto-detect device/emulator
#   ./scripts/run_android_tests.sh --serial ABCD1234  # target specific device
#   ./scripts/run_android_tests.sh --device-only      # USB devices only
#   ./scripts/run_android_tests.sh --emulator-only    # emulators only
#   ./scripts/run_android_tests.sh --build-dir DIR    # custom build dir
#   ./scripts/run_android_tests.sh --kmod             # kernel module (stub)

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

# Resolve toolchain via shared detector. Exports KH_* including
# KH_TOOLCHAIN_KIND used below for bionic ABI enforcement.
# shellcheck source=lib/detect_toolchain.sh
. "$ROOT/scripts/lib/detect_toolchain.sh" || {
    echo "ERROR: toolchain detection failed" >&2
    exit 1
}

# Colors
RED='\033[31m'
GREEN='\033[32m'
YELLOW='\033[33m'
BOLD='\033[1m'
RESET='\033[0m'

# Defaults
BUILD_DIR="build_android"
SERIAL=""
FILTER=""  # "" = any, "device" = USB only, "emulator" = emulator only
KMOD=0

# Parse arguments
while [ $# -gt 0 ]; do
    case "$1" in
        --serial)      SERIAL="$2"; shift 2 ;;
        --device-only) FILTER="device"; shift ;;
        --emulator-only) FILTER="emulator"; shift ;;
        --build-dir)   BUILD_DIR="$2"; shift 2 ;;
        --kmod)        KMOD=1; shift ;;
        -h|--help)
            echo "Usage: $0 [--serial SN] [--device-only] [--emulator-only] [--build-dir DIR] [--kmod]"
            exit 0 ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

# ---- Verify ADB ----

if ! command -v adb &>/dev/null; then
    printf "${RED}Error: adb not found in PATH${RESET}\n"
    printf "Install Android SDK Platform Tools or set PATH.\n"
    exit 1
fi

# ---- Device detection ----

detect_device() {
    local devices
    devices=$(adb devices 2>/dev/null | tail -n +2 | grep -v "^$" | awk '{print $1}')

    if [ -z "$devices" ]; then
        printf "${RED}Error: No Android devices/emulators found.${RESET}\n"
        printf "Connect a USB device or start an emulator, then retry.\n"
        exit 1
    fi

    if [ -n "$SERIAL" ]; then
        if echo "$devices" | grep -qx "$SERIAL"; then
            echo "$SERIAL"
            return
        fi
        printf "${RED}Error: Device %s not found.${RESET}\n" "$SERIAL"
        printf "Available devices:\n"
        echo "$devices" | sed 's/^/  /'
        exit 1
    fi

    # Filter by type
    local selected=""
    for dev in $devices; do
        if [ "$FILTER" = "device" ] && echo "$dev" | grep -q "^emulator-"; then
            continue
        fi
        if [ "$FILTER" = "emulator" ] && ! echo "$dev" | grep -q "^emulator-"; then
            continue
        fi
        selected="$dev"
        break
    done

    if [ -z "$selected" ]; then
        printf "${RED}Error: No matching device found (filter: %s).${RESET}\n" "${FILTER:-any}"
        printf "Available devices:\n"
        echo "$devices" | sed 's/^/  /'
        exit 1
    fi

    echo "$selected"
}

DEVICE=$(detect_device)
ADB="adb -s $DEVICE"

# Classify device type
if echo "$DEVICE" | grep -q "^emulator-"; then
    DEV_TYPE="emulator"
else
    DEV_TYPE="USB device"
fi

printf "${BOLD}KernelHook Android Test Runner${RESET}\n"
printf "  Target: %s (%s)\n" "$DEVICE" "$DEV_TYPE"

# ---- Check / acquire root ----
#
# Three paths to root:
#   1. magisk `su` (USB devices) — non-interactive `su -c id`
#   2. adb root (userdebug emulators / -userdebug devices) — restarts adbd
#   3. nothing — tests requiring mprotect RW→RX will SEGV; warn loudly
#
# On emulators we always try `adb root` first since `su` is not present.

HAS_ROOT=0

try_su_root() {
    $ADB shell "su -c id" 2>/dev/null | grep -q "uid=0"
}

try_adb_root() {
    # adb root succeeds silently on userdebug builds and prints
    # "adbd cannot run as root in production builds" otherwise.
    local out
    out=$($ADB root 2>&1)
    case "$out" in
        *"already running as root"*|*"restarting adbd as root"*) ;;
        *"production builds"*|*"cannot run as root"*) return 1 ;;
    esac
    # adbd restarts; wait for it to come back.
    $ADB wait-for-device >/dev/null 2>&1
    $ADB shell id 2>/dev/null | grep -q "uid=0"
}

if try_su_root; then
    HAS_ROOT=1
    ROOT_METHOD="su"
elif [ "$DEV_TYPE" = "emulator" ] && try_adb_root; then
    HAS_ROOT=1
    ROOT_METHOD="adb-root"
fi

if [ "$HAS_ROOT" -eq 1 ]; then
    printf "  Root: ${GREEN}available${RESET} (%s)\n" "$ROOT_METHOD"
    # Magisk path: targeted execmod policy
    if $ADB shell "which magiskpolicy" >/dev/null 2>&1; then
        $ADB shell "su -c 'magiskpolicy --live \"allow shell shell_data_file file execmod\"'" >/dev/null 2>&1
        printf "  SELinux: ${GREEN}execmod policy added${RESET}\n"
    elif [ "$ROOT_METHOD" = "adb-root" ]; then
        # adb-root path (emulators): drop SELinux to permissive so platform_write_code
        # can mprotect RW→RX. This is the same effect run_tests.sh used to require
        # users to do manually.
        $ADB shell "setenforce 0" 2>/dev/null
        mode=$($ADB shell "getenforce" 2>/dev/null | tr -d '[:space:]')
        if [ "$mode" = "Permissive" ]; then
            printf "  SELinux: ${GREEN}permissive${RESET}\n"
        else
            printf "  SELinux: ${YELLOW}%s (could not set permissive)${RESET}\n" "$mode"
        fi
    fi
else
    printf "  Root: ${YELLOW}not available${RESET}\n"
    if [ "$DEV_TYPE" = "emulator" ]; then
        printf "         Tried 'adb root' but adbd refused — is this a -user build?\n"
    fi
    printf "         Tests requiring mprotect RW→RX will crash (SIGSEGV).\n"
fi

# ---- Build if needed ----

case "${KH_TOOLCHAIN_KIND:-}" in
    sys-gcc|sys-clang)
        echo "ERROR: Android userspace tests require a real NDK (bionic ABI)." >&2
        echo "       System cross-compiler cannot produce Android-compatible binaries." >&2
        echo "       Set \$ANDROID_NDK_ROOT or \$ANDROID_SDK_ROOT (with NDK installed)," >&2
        echo "       or install the NDK, then re-run." >&2
        echo "       (Kbuild / freestanding steps already ran successfully.)" >&2
        exit 2
        ;;
esac

if [ ! -d "$BUILD_DIR" ]; then
    printf "\n${BOLD}Building for Android...${RESET}\n"
    cmake -B "$BUILD_DIR" \
          -DCMAKE_TOOLCHAIN_FILE=cmake/android-arm64.cmake \
          -DCMAKE_BUILD_TYPE=Debug \
          2>&1 | tail -3
    cmake --build "$BUILD_DIR" -j"$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)" \
          2>&1 | tail -3
fi

# ---- Discover test binaries ----

TEST_DIR="$BUILD_DIR/tests/userspace"
if [ ! -d "$TEST_DIR" ]; then
    # Fallback: tests may be directly under tests/
    TEST_DIR="$BUILD_DIR/tests"
fi
if [ ! -d "$TEST_DIR" ]; then
    printf "${RED}Error: Test directory %s not found.${RESET}\n" "$TEST_DIR"
    exit 1
fi

TESTS=()
for bin in "$TEST_DIR"/test_*; do
    [ -f "$bin" ] && [ -x "$bin" ] && TESTS+=("$(basename "$bin")")
done

if [ ${#TESTS[@]} -eq 0 ]; then
    printf "${RED}Error: No test binaries found in %s${RESET}\n" "$TEST_DIR"
    exit 1
fi

printf "  Tests found: %d\n\n" "${#TESTS[@]}"

# ---- Push binaries ----

REMOTE_DIR="/data/local/tmp/kh_tests"
$ADB shell "rm -rf $REMOTE_DIR && mkdir -p $REMOTE_DIR" 2>/dev/null

printf "${BOLD}Pushing test binaries...${RESET}\n"
for t in "${TESTS[@]}"; do
    $ADB push "$TEST_DIR/$t" "$REMOTE_DIR/$t" >/dev/null 2>&1
    $ADB shell "chmod +x $REMOTE_DIR/$t" 2>/dev/null
done

# ---- Run tests ----

PASSED=0
FAILED=0
SKIPPED=0
FAILURES=""

# Helper: extract a leading integer before a keyword (portable, no -P required)
_parse_count() {
    # Usage: _parse_count "3 passed" "passed"  → prints "3"
    echo "$1" | grep -oE "[0-9]+ $2" | grep -oE "^[0-9]+" | head -1
}

run_test() {
    local name="$1"
    local cmd="$REMOTE_DIR/$name"

    # adb-root devices already run adbd as uid 0 — no `su` needed
    # (and emulators don't ship a `su` binary anyway).
    if [ "$HAS_ROOT" -eq 1 ] && [ "$ROOT_METHOD" = "su" ]; then
        cmd="su -c $cmd"
    fi

    local output
    local rc=0
    output=$($ADB shell "$cmd" 2>&1) || rc=$?

    # Parse output for pass/fail/skip counts (grep -oE is portable; avoids -P)
    local t_passed t_failed t_skipped
    t_passed=$(_parse_count "$output" "passed")
    t_failed=$(_parse_count "$output" "failed")
    t_skipped=$(_parse_count "$output" "skipped")

    # Fallback: if parsing yields nothing, use exit code
    if [ -z "$t_passed" ] && [ -z "$t_failed" ]; then
        if [ "$rc" -eq 0 ]; then
            t_passed=1; t_failed=0
        else
            t_passed=0; t_failed=1
        fi
    fi

    t_passed="${t_passed:-0}"
    t_failed="${t_failed:-0}"
    t_skipped="${t_skipped:-0}"

    PASSED=$((PASSED + t_passed))
    FAILED=$((FAILED + t_failed))
    SKIPPED=$((SKIPPED + t_skipped))

    if [ "${t_failed}" -gt 0 ] || [ "$rc" -ne 0 ]; then
        printf "  ${RED}FAIL${RESET} %s (%s passed, %s failed, %s skipped)\n" \
               "$name" "$t_passed" "$t_failed" "$t_skipped"
        FAILURES="${FAILURES}\n  ${RED}FAIL${RESET} ${name}"
        echo "$output" | sed 's/^/       /'
    else
        printf "  ${GREEN}PASS${RESET} %s (%s passed, %s skipped)\n" \
               "$name" "$t_passed" "$t_skipped"
    fi
}

printf "${BOLD}Running tests on %s...${RESET}\n" "$DEVICE"
for t in "${TESTS[@]}"; do
    run_test "$t"
done

# ---- Kernel module tests ----

if [ "$KMOD" -eq 1 ]; then
    printf "\n${BOLD}Running kernel module tests...${RESET}\n"

    # Require root for kmod operations
    if [ "$HAS_ROOT" -ne 1 ]; then
        printf "  ${YELLOW}SKIP${RESET} kmod tests (no root access)\n"
        SKIPPED=$((SKIPPED + 1))
    elif [ "$ROOT_METHOD" = "adb-root" ]; then
        printf "  ${YELLOW}SKIP${RESET} kmod tests (adb-root path uses 'su -c' helpers; use scripts/test_avd_kmod.sh for emulator kmod regression)\n"
        SKIPPED=$((SKIPPED + 1))
    else
        KMOD_KO="$ROOT/tests/kmod/kh_test.ko"
        KMOD_LOADER="$ROOT/tools/kmod_loader/kmod_loader"

        # Query device kernel version for vermagic
        DEV_UNAME=$($ADB shell "uname -r" 2>/dev/null | tr -d '[:space:]')
        printf "  Device kernel: %s\n" "$DEV_UNAME"

        # Pin API level to this specific device and re-run detector so
        # KH_CC's --target matches the connected device's API.
        DEV_SDK=$($ADB shell "getprop ro.build.version.sdk" 2>/dev/null | tr -d '[:space:]')
        if [ -n "$DEV_SDK" ]; then
            export ANDROID_API_LEVEL="$DEV_SDK"
            . "$ROOT/scripts/lib/detect_toolchain.sh" || true
            printf "  Toolchain re-pinned to API %s\n" "$DEV_SDK"
        fi

        # Build freestanding .ko (always rebuild to pick up correct vermagic).
        # Use an array so $KH_CC (which contains "clang --target=...") stays
        # as a single assignment and is not broken up by shell word-splitting.
        printf "  Building freestanding kh_test.ko...\n"
        MAKE_ARGS=(freestanding "KERNELRELEASE=$DEV_UNAME"
                   "CC=$KH_CC" "LD=$KH_LD" "CROSS_COMPILE=$KH_CROSS_COMPILE")
        if ! (cd "$ROOT/tests/kmod" && make clean >/dev/null 2>&1; make "${MAKE_ARGS[@]}" 2>&1 | tail -5); then
            printf "  ${RED}FAIL${RESET} kmod build failed\n"
            FAILED=$((FAILED + 1))
            FAILURES="${FAILURES}\n  ${RED}FAIL${RESET} kmod_build"
            KMOD_KO=""
        fi

        if [ -n "$KMOD_KO" ] && [ -f "$KMOD_KO" ]; then
            REMOTE_KO="/data/local/tmp/kh_test.ko"
            REMOTE_LOADER="/data/local/tmp/kmod_loader"
            KMOD_OK=1

            # Push .ko and loader to device
            printf "  Pushing kh_test.ko to device...\n"
            if ! $ADB push "$KMOD_KO" "$REMOTE_KO" >/dev/null 2>&1; then
                printf "  ${RED}FAIL${RESET} adb push failed for kh_test.ko\n"
                FAILED=$((FAILED + 1))
                FAILURES="${FAILURES}\n  ${RED}FAIL${RESET} kmod_push"
                KMOD_OK=0
            fi

            HAS_LOADER=0
            if [ -f "$KMOD_LOADER" ]; then
                if $ADB push "$KMOD_LOADER" "$REMOTE_LOADER" >/dev/null 2>&1; then
                    $ADB shell "chmod +x $REMOTE_LOADER" 2>/dev/null
                    HAS_LOADER=1
                fi
            fi

            if [ "$KMOD_OK" -eq 1 ]; then
                # Resolve kallsyms_lookup_name from /proc/kallsyms
                KALLSYMS_ADDR=""
                KALLSYMS_RAW=$($ADB shell "su -c 'cat /proc/kallsyms'" 2>/dev/null | grep -E ' [Tt] kallsyms_lookup_name$' | awk '{print $1}' | head -1)

                if [ -z "$KALLSYMS_RAW" ] || [ "$KALLSYMS_RAW" = "0000000000000000" ]; then
                    # Try reading kptr_restrict
                    KPTR=$($ADB shell "su -c 'cat /proc/sys/kernel/kptr_restrict'" 2>/dev/null | tr -d '[:space:]')
                    printf "  ${YELLOW}WARN${RESET} kallsyms_lookup_name not readable"
                    if [ "$KPTR" != "0" ]; then
                        printf " (kptr_restrict=%s)\n" "$KPTR"
                        printf "       Fix: adb shell su -c 'echo 0 > /proc/sys/kernel/kptr_restrict'\n"
                        # Attempt to lower kptr_restrict and retry
                        $ADB shell "su -c 'echo 0 > /proc/sys/kernel/kptr_restrict'" 2>/dev/null || true
                        KALLSYMS_RAW=$($ADB shell "su -c 'cat /proc/kallsyms'" 2>/dev/null | grep -E ' [Tt] kallsyms_lookup_name$' | awk '{print $1}' | head -1)
                    else
                        printf "\n"
                    fi
                fi

                if [ -n "$KALLSYMS_RAW" ] && [ "$KALLSYMS_RAW" != "0000000000000000" ]; then
                    KALLSYMS_ADDR="0x${KALLSYMS_RAW}"
                    printf "  kallsyms_lookup_name: %s\n" "$KALLSYMS_ADDR"
                else
                    printf "  ${YELLOW}WARN${RESET} Proceeding without kallsyms_lookup_name address (addr=0)\n"
                    KALLSYMS_ADDR="0x0"
                fi

                # Unload module if already loaded
                if $ADB shell "su -c 'lsmod'" 2>/dev/null | grep -q "^kh_test"; then
                    printf "  Unloading existing kh_test module...\n"
                    $ADB shell "su -c 'rmmod kh_test'" 2>/dev/null || true
                    sleep 1
                fi

                # Clear dmesg
                $ADB shell "su -c 'dmesg -c'" >/dev/null 2>&1 || true

                # Load module with kallsyms_addr parameter
                # Try kmod_loader first (bypasses vermagic/modversions checks),
                # fall back to insmod
                printf "  Loading kh_test.ko (kallsyms_addr=%s)...\n" "$KALLSYMS_ADDR"
                INSMOD_OUT=""
                INSMOD_RC=1

                if [ "$HAS_LOADER" -eq 1 ]; then
                    printf "  Trying kmod_loader (finit_module with relaxed checks)...\n"
                    INSMOD_OUT=$($ADB shell "su -c 'timeout 30 $REMOTE_LOADER $REMOTE_KO kallsyms_addr=$KALLSYMS_ADDR'" 2>&1)
                    INSMOD_RC=$?
                    if [ "$INSMOD_RC" -ne 0 ]; then
                        printf "  ${YELLOW}WARN${RESET} kmod_loader failed: %s\n" "$INSMOD_OUT"
                        printf "  Falling back to insmod...\n"
                    fi
                fi

                if [ "$INSMOD_RC" -ne 0 ]; then
                    INSMOD_OUT=$($ADB shell "su -c 'insmod $REMOTE_KO kallsyms_addr=$KALLSYMS_ADDR'" 2>&1)
                    INSMOD_RC=$?
                fi

                if [ "$INSMOD_RC" -ne 0 ]; then
                    printf "  ${RED}FAIL${RESET} module load failed: %s\n" "$INSMOD_OUT"
                    # Check for SELinux denial
                    if echo "$INSMOD_OUT" | grep -qi "permission denied\|selinux\|avc:"; then
                        printf "       SELinux may be blocking module load.\n"
                        printf "       Fix: adb shell su -c 'setenforce 0'\n"
                    fi
                    # Check for signature enforcement
                    if echo "$INSMOD_OUT" | grep -qi "required key\|signature\|MODULE_SIG"; then
                        printf "       Kernel requires signed modules.\n"
                        printf "       Fix: boot with module signature enforcement disabled.\n"
                    fi
                    FAILED=$((FAILED + 1))
                    FAILURES="${FAILURES}\n  ${RED}FAIL${RESET} kmod_load"
                    KMOD_OK=0
                fi

                if [ "$KMOD_OK" -eq 1 ]; then
                    # Wait for module to run its tests
                    sleep 2

                    # Capture dmesg filtered by kh_test
                    KMOD_DMESG=$($ADB shell "su -c 'dmesg'" 2>/dev/null | grep "kh_test:" || true)

                    # Unload module
                    $ADB shell "su -c 'rmmod kh_test'" 2>/dev/null || true

                    # Parse PASS/FAIL/SKIP counts from dmesg
                    KM_PASSED=0
                    KM_FAILED=0
                    KM_SKIPPED=0

                    while IFS= read -r line; do
                        if echo "$line" | grep -qi "\bPASS\b"; then
                            KM_PASSED=$((KM_PASSED + 1))
                        elif echo "$line" | grep -qi "\bFAIL\b"; then
                            KM_FAILED=$((KM_FAILED + 1))
                        elif echo "$line" | grep -qi "\bSKIP\b"; then
                            KM_SKIPPED=$((KM_SKIPPED + 1))
                        fi
                    done <<EOF
$KMOD_DMESG
EOF

                    # Try summary-line parse as well (override individual counts if summary present)
                    SUMMARY_LINE=$(echo "$KMOD_DMESG" | grep -E "[0-9]+ passed" | tail -1)
                    if [ -n "$SUMMARY_LINE" ]; then
                        _sp=$(_parse_count "$SUMMARY_LINE" "passed")
                        _sf=$(_parse_count "$SUMMARY_LINE" "failed")
                        _ss=$(_parse_count "$SUMMARY_LINE" "skipped")
                        [ -n "$_sp" ] && KM_PASSED=$_sp
                        [ -n "$_sf" ] && KM_FAILED=$_sf
                        [ -n "$_ss" ] && KM_SKIPPED=$_ss
                    fi

                    # Add to global counters
                    PASSED=$((PASSED + KM_PASSED))
                    FAILED=$((FAILED + KM_FAILED))
                    SKIPPED=$((SKIPPED + KM_SKIPPED))

                    # Report result
                    if [ "$KM_FAILED" -gt 0 ]; then
                        printf "  ${RED}FAIL${RESET} kh_test.ko (%d passed, %d failed, %d skipped)\n" \
                               "$KM_PASSED" "$KM_FAILED" "$KM_SKIPPED"
                        FAILURES="${FAILURES}\n  ${RED}FAIL${RESET} kh_test.ko"
                        printf "%s\n" "$KMOD_DMESG" | sed 's/^/       /'
                    elif [ "$KM_PASSED" -eq 0 ] && [ "$KM_SKIPPED" -eq 0 ]; then
                        printf "  ${YELLOW}WARN${RESET} kh_test.ko produced no results (check dmesg)\n"
                        printf "%s\n" "$KMOD_DMESG" | sed 's/^/       /'
                    else
                        printf "  ${GREEN}PASS${RESET} kh_test.ko (%d passed, %d skipped)\n" \
                               "$KM_PASSED" "$KM_SKIPPED"
                    fi
                fi

                # Cleanup pushed files from device
                $ADB shell "rm -f $REMOTE_KO $REMOTE_LOADER" 2>/dev/null || true
            fi
        fi
    fi
fi

# ---- Cleanup ----

$ADB shell "rm -rf $REMOTE_DIR" 2>/dev/null

# ---- Summary ----

printf "\n${BOLD}========== Summary ==========${RESET}\n"
TOTAL=$((PASSED + FAILED + SKIPPED))
printf "  Total: %d  |  ${GREEN}Passed: %d${RESET}  |  ${RED}Failed: %d${RESET}  |  ${YELLOW}Skipped: %d${RESET}\n" \
    "$TOTAL" "$PASSED" "$FAILED" "$SKIPPED"

if [ -n "$FAILURES" ]; then
    printf "\nFailures:${FAILURES}\n"
fi

exit $((FAILED > 0 ? 1 : 0))
