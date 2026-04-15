#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-or-later
# Shared shell helpers for KernelHook test harness.
# Source from scripts/test.sh and worker scripts.
#
# Exposed:
#   KH_RED, KH_GREEN, KH_YELLOW, KH_BOLD, KH_RESET — ANSI color codes
#   kh_banner <text>          — print a bold banner line
#   kh_section_start <name>   — print "==> <name>"
#   kh_section_end <name> <result>  — print "<-- <name>: <result>"
#   kh_summary_line <pass> <fail>   — print "=== Summary: N PASS, M FAIL ==="
#
# The SDK-mode 2-ko load order (kernelhook.ko first, kh_test.ko second;
# rmmod in reverse) is open-coded inside the worker scripts — they need
# perl-alarm wrapping + on-device kmsg capture state that doesn't fit a
# generic helper. See scripts/test_device_kmod.sh under --mode=sdk.
#
# Idempotent — safe to source multiple times.

if [ -n "${_KH_TEST_COMMON_LOADED:-}" ]; then return 0; fi
_KH_TEST_COMMON_LOADED=1

KH_RED=$'\033[31m'
KH_GREEN=$'\033[32m'
KH_YELLOW=$'\033[33m'
KH_BOLD=$'\033[1m'
KH_RESET=$'\033[0m'

kh_banner() {
    printf "%s%s%s\n" "$KH_BOLD" "$*" "$KH_RESET"
}

kh_section_start() {
    printf "%s==>%s %s\n" "$KH_BOLD" "$KH_RESET" "$*"
}

kh_section_end() {
    local name="$1" result="$2"
    case "$result" in
        PASS) printf "%s<--%s %s: %sPASS%s\n" "$KH_BOLD" "$KH_RESET" "$name" "$KH_GREEN" "$KH_RESET" ;;
        FAIL) printf "%s<--%s %s: %sFAIL%s\n" "$KH_BOLD" "$KH_RESET" "$name" "$KH_RED"   "$KH_RESET" ;;
        SKIP) printf "%s<--%s %s: %sSKIP%s\n" "$KH_BOLD" "$KH_RESET" "$name" "$KH_YELLOW" "$KH_RESET" ;;
        *)    printf "%s<--%s %s: %s\n"        "$KH_BOLD" "$KH_RESET" "$name" "$result" ;;
    esac
}

kh_summary_line() {
    local pass="$1" fail="$2"
    printf "=== Summary: %d PASS, %d FAIL ===\n" "$pass" "$fail"
}
