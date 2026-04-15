#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-or-later
# KernelHook unified test dispatcher.
# See `scripts/test.sh --help` for usage.

set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
. "$ROOT/scripts/lib/test_common.sh"

# ---- Subcommand registry ---------------------------------------------------
# Each entry: "name|short description"
KH_SUBCOMMANDS=(
    "host|Host userspace ctest (Debug)"
    "host-all|Host userspace, Debug + Release"
    "android|Userspace tests on Android device/emulator"
    "avd|kmod tests on AVD emulator(s)"
    "device|kmod tests on physical USB device"
    "sdk-consumer|SDK ABI link verification"
    "kbuild-verify|Static .ko validation"
    "all|Every subcommand whose env is available"
)

usage() {
    cat <<'EOF'
Usage:
  scripts/test.sh <subcommand> [options]

Subcommands:
  host                     Host userspace ctest (Debug build)
  host-all                 Host userspace, Debug + Release
  android [--serial S]     Userspace tests pushed to Android via adb
  avd [name...]            kmod tests on AVD emulator(s) (default: all AVDs)
  device [serial]          kmod tests on physical USB device (with kh_root demo)
  sdk-consumer             SDK ABI link verification (Ring 3 + hello_hook.ko consumer)
  kbuild-verify <ko> <kv>  Static .ko validation
  all                      Every subcommand whose environment is available

Global options:
  --mode={sdk,freestanding} kmod build mode (avd/device only). Default: sdk.
  --no-build               Skip rebuild; assume artifacts exist
  --verbose                Pass -v / --verbose down to worker scripts
  --list                   Enumerate subcommands and exit
  --help, -h               Show this help and exit
EOF
}

list_subcommands() {
    printf "%-16s %s\n" "SUBCOMMAND" "DESCRIPTION"
    printf "%-16s %s\n" "----------" "-----------"
    for entry in "${KH_SUBCOMMANDS[@]}"; do
        local name="${entry%%|*}"
        local desc="${entry#*|}"
        printf "%-16s %s\n" "$name" "$desc"
    done
}

# ---- Global option parsing -------------------------------------------------
KH_MODE="sdk"
KH_NO_BUILD=0
KH_VERBOSE=0

# First pass: extract global options. Subcommand args are stuffed into
# KH_SUBCMD_ARGS (preserving order).
KH_SUBCMD=""
KH_SUBCMD_ARGS=()

while [ "$#" -gt 0 ]; do
    case "$1" in
        --help|-h) usage; exit 0 ;;
        --list)    list_subcommands; exit 0 ;;
        --mode=*)  KH_MODE="${1#--mode=}"; shift ;;
        --no-build) KH_NO_BUILD=1; shift ;;
        --verbose) KH_VERBOSE=1; shift ;;
        --)        shift; while [ "$#" -gt 0 ]; do KH_SUBCMD_ARGS+=("$1"); shift; done ;;
        -*)
            # Once a subcommand is set, dashed args belong to it (forward them).
            # Pre-subcommand, dashed args that didn't match any global option
            # above are typos / unknown — reject loudly.
            if [ -n "$KH_SUBCMD" ]; then
                KH_SUBCMD_ARGS+=("$1"); shift
            else
                printf "unknown global option: %s\n" "$1" >&2; usage >&2; exit 2
            fi
            ;;
        *)
            if [ -z "$KH_SUBCMD" ]; then
                KH_SUBCMD="$1"
            else
                KH_SUBCMD_ARGS+=("$1")
            fi
            shift
            ;;
    esac
done

if [ -z "$KH_SUBCMD" ]; then
    usage >&2
    exit 2
fi

case "$KH_MODE" in
    sdk|freestanding) ;;
    *) printf "invalid --mode=%s (want sdk|freestanding)\n" "$KH_MODE" >&2; exit 2 ;;
esac

# ---- Subcommand dispatch ---------------------------------------------------
# Wired progressively across Tasks 3..6 and Tasks 12..15. For now everything
# routes to a stub that explains "not yet implemented". Subsequent tasks
# replace each stub with the real wiring.

cmd_stub() {
    printf "%sNOT IMPLEMENTED%s subcommand '%s' is wired in a later P1 task.\n" \
        "$KH_YELLOW" "$KH_RESET" "$KH_SUBCMD" >&2
    return 64
}

case "$KH_SUBCMD" in
    host)
        kh_section_start "host: ctest (Debug)"
        BUILD_DIR="$ROOT/build_debug"
        if [ "$KH_NO_BUILD" -ne 1 ] || [ ! -d "$BUILD_DIR" ]; then
            cmake -S "$ROOT" -B "$BUILD_DIR" -DCMAKE_BUILD_TYPE=Debug >/dev/null
            cmake --build "$BUILD_DIR" >/dev/null
        fi
        if (cd "$BUILD_DIR" && ctest --output-on-failure); then
            kh_section_end "host" PASS
            kh_summary_line 1 0
            exit 0
        else
            kh_section_end "host" FAIL
            kh_summary_line 0 1
            exit 1
        fi
        ;;
    host-all)
        kh_section_start "host-all: Debug + Release"
        if "$ROOT/tests/userspace/run_tests.sh"; then
            kh_section_end "host-all" PASS
            kh_summary_line 1 0
            exit 0
        else
            kh_section_end "host-all" FAIL
            kh_summary_line 0 1
            exit 1
        fi
        ;;
    android)
        kh_section_start "android: userspace tests via adb"
        # Pass through subcommand args (e.g. --serial S, --emulator-only).
        if "$ROOT/scripts/run_android_tests.sh" "${KH_SUBCMD_ARGS[@]+"${KH_SUBCMD_ARGS[@]}"}"; then
            kh_section_end "android" PASS
            kh_summary_line 1 0
            exit 0
        else
            rc=$?
            kh_section_end "android" FAIL
            kh_summary_line 0 1
            exit "$rc"
        fi
        ;;
    avd)
        kh_section_start "avd: kmod tests on AVD(s) (--mode=$KH_MODE)"
        if "$ROOT/scripts/test_avd_kmod.sh" --mode="$KH_MODE" "${KH_SUBCMD_ARGS[@]+"${KH_SUBCMD_ARGS[@]}"}"; then
            kh_section_end "avd" PASS
            kh_summary_line 1 0
            exit 0
        else
            rc=$?
            kh_section_end "avd" FAIL
            kh_summary_line 0 1
            exit "$rc"
        fi
        ;;
    device)
        kh_section_start "device: kmod tests on physical device (--mode=$KH_MODE)"
        if "$ROOT/scripts/test_device_kmod.sh" --mode="$KH_MODE" "${KH_SUBCMD_ARGS[@]+"${KH_SUBCMD_ARGS[@]}"}"; then
            kh_section_end "device" PASS
            kh_summary_line 1 0
            exit 0
        else
            rc=$?
            kh_section_end "device" FAIL
            kh_summary_line 0 1
            exit "$rc"
        fi
        ;;
    sdk-consumer)
        kh_section_start "sdk-consumer: SDK ABI link verification"

        # Pick first AVD or first non-emulator device (for Ring 3 step).
        SERIAL="${KH_SUBCMD_ARGS[0]:-}"
        if [ -z "$SERIAL" ]; then
            SERIAL=$(adb devices 2>/dev/null \
                | awk 'NR>1 && $2=="device" {print $1; exit}')
        fi

        pass=0; fail=0; skip=0

        # Step 1: Ring 3 — minimal exporter + importer (needs adb).
        if [ -z "$SERIAL" ]; then
            printf "  ${KH_YELLOW}SKIP${KH_RESET} ring3 exporter+importer (no adb device)\n"
            skip=$((skip+1))
        elif (cd "$ROOT/tests/kmod/export_link_test" && make >/tmp/ring3_build.log 2>&1) \
             && "$ROOT/tests/kmod/export_link_test/test_on_avd.sh" "$SERIAL"; then
            pass=$((pass+1))
            printf "  ${KH_GREEN}PASS${KH_RESET} ring3 exporter+importer\n"
        else
            fail=$((fail+1))
            printf "  ${KH_RED}FAIL${KH_RESET} ring3 exporter+importer (see /tmp/ring3_build.log)\n"
        fi

        # Step 2: hello_hook.ko SDK link check (hermetic — no device required).
        # (方案 C: kh_test.ko is freestanding-only; hello_hook.ko is the SDK
        # consumer reference. We verify the SDK build produces a .ko whose
        # undefined-symbol set is fully satisfied by kmod/exports.manifest.)
        . "$ROOT/scripts/lib/detect_toolchain.sh"
        NM="${KH_CROSS_COMPILE}nm"
        [ -x "$NM" ] || NM="${KH_NDK_BIN}/llvm-nm"
        if (cd "$ROOT/kmod" && make module >/tmp/sdkc_core.log 2>&1) \
           && (cd "$ROOT/examples/hello_hook" && make -f Makefile.sdk module >/tmp/sdkc_hello.log 2>&1) \
           && "$NM" -u "$ROOT/examples/hello_hook/hello_hook.ko" 2>/dev/null \
                | awk '{print $NF}' | sort -u > /tmp/sdkc_undef.txt \
           && awk '/^[a-zA-Z_]/ {print $1}' "$ROOT/kmod/exports.manifest" | sort -u > /tmp/sdkc_man.txt \
           && [ -z "$(comm -23 /tmp/sdkc_undef.txt /tmp/sdkc_man.txt \
                       | grep -E '^(hook|fp_hook|hook_chain|hook_mem|platform_|sync_|hmem_|kh_)')" ]; then
            pass=$((pass+1))
            printf "  ${KH_GREEN}PASS${KH_RESET} hello_hook.ko SDK consumer link\n"
        else
            fail=$((fail+1))
            printf "  ${KH_RED}FAIL${KH_RESET} hello_hook.ko SDK consumer link\n"
            printf "      see /tmp/sdkc_core.log /tmp/sdkc_hello.log\n"
            printf "      missing: $(comm -23 /tmp/sdkc_undef.txt /tmp/sdkc_man.txt \
                       | grep -E '^(hook|fp_hook|hook_chain|hook_mem|platform_|sync_|hmem_|kh_)' \
                       | tr '\n' ' ')\n"
        fi

        if [ "$fail" -eq 0 ]; then
            kh_section_end "sdk-consumer" PASS
        else
            kh_section_end "sdk-consumer" FAIL
        fi
        kh_summary_line "$pass" "$fail" "$skip"
        [ "$fail" -eq 0 ]
        ;;
    kbuild-verify)
        if [ "${#KH_SUBCMD_ARGS[@]}" -lt 2 ]; then
            printf "usage: scripts/test.sh kbuild-verify <ko-path> <expected-kver>\n" >&2
            exit 2
        fi
        kh_section_start "kbuild-verify: ${KH_SUBCMD_ARGS[0]}"
        if "$ROOT/scripts/ci/verify_kmod.sh" "${KH_SUBCMD_ARGS[0]}" "${KH_SUBCMD_ARGS[1]}"; then
            kh_section_end "kbuild-verify" PASS
            kh_summary_line 1 0
            exit 0
        else
            kh_section_end "kbuild-verify" FAIL
            kh_summary_line 0 1
            exit 1
        fi
        ;;
    all)
        kh_banner "test.sh all — every available subcommand"
        total_pass=0; total_fail=0

        # host: always available
        if "$0" host; then total_pass=$((total_pass+1)); else total_fail=$((total_fail+1)); fi

        # android: only if a device or emulator is attached
        if adb devices 2>/dev/null | awk 'NR>1 && $2=="device"' | grep -q .; then
            if "$0" android; then total_pass=$((total_pass+1)); else total_fail=$((total_fail+1)); fi
        else
            kh_section_end "android" SKIP
        fi

        # avd: only if AVDs exist
        if ls ~/.android/avd/*.ini >/dev/null 2>&1; then
            if "$0" --mode="$KH_MODE" avd; then total_pass=$((total_pass+1)); else total_fail=$((total_fail+1)); fi
        else
            kh_section_end "avd" SKIP
        fi

        # device: only if a non-emulator device is attached
        if adb devices 2>/dev/null | awk 'NR>1 && $2=="device" && $1 !~ /^emulator-/' | grep -q .; then
            if "$0" --mode="$KH_MODE" device; then total_pass=$((total_pass+1)); else total_fail=$((total_fail+1)); fi
        else
            kh_section_end "device" SKIP
        fi

        # sdk-consumer: Step 2 (hello_hook.ko SDK link check) is hermetic and
        # always runs; Step 1 (Ring 3) self-SKIPs internally when no adb device
        # is present. Running unconditionally ensures 'all' covers the hermetic
        # link check even on device-less CI hosts.
        if "$0" sdk-consumer; then total_pass=$((total_pass+1)); else total_fail=$((total_fail+1)); fi

        kh_banner "==== Aggregate ===="
        kh_summary_line "$total_pass" "$total_fail"
        [ "$total_fail" -eq 0 ]
        ;;
    *)
        printf "unknown subcommand: %s\n" "$KH_SUBCMD" >&2
        usage >&2
        exit 2
        ;;
esac
