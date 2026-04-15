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
  sdk-consumer             SDK ABI link verification (Ring 3 + kh_test.ko consumer)
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
        -*)        printf "unknown global option: %s\n" "$1" >&2; usage >&2; exit 2 ;;
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
    host)          cmd_stub ;;
    host-all)      cmd_stub ;;
    android)       cmd_stub ;;
    avd)           cmd_stub ;;
    device)        cmd_stub ;;
    sdk-consumer)  cmd_stub ;;
    kbuild-verify) cmd_stub ;;
    all)           cmd_stub ;;
    *)
        printf "unknown subcommand: %s\n" "$KH_SUBCMD" >&2
        usage >&2
        exit 2
        ;;
esac
