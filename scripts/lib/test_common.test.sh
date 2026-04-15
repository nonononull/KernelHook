#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-or-later
# Smoke test for scripts/lib/test_common.sh — verifies sourcing works
# and helper functions emit the expected substrings.

set -uo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
. "$ROOT/scripts/lib/test_common.sh"

fail=0
check() {
    local label="$1" expected="$2" actual="$3"
    if echo "$actual" | grep -qF "$expected"; then
        echo "  ok   $label"
    else
        echo "  FAIL $label: expected '$expected' in '$actual'" >&2
        fail=$((fail+1))
    fi
}

check "banner contains text"       "hello"               "$(kh_banner hello)"
check "section_start uses '==>'"   "==>"                 "$(kh_section_start foo)"
check "section_end PASS prints"    "PASS"                "$(kh_section_end foo PASS)"
check "section_end FAIL prints"    "FAIL"                "$(kh_section_end foo FAIL)"
check "summary_line format"        "=== Summary: 3 PASS" "$(kh_summary_line 3 1)"
check "double-source is idempotent" "1"                  "$_KH_TEST_COMMON_LOADED"
. "$ROOT/scripts/lib/test_common.sh"   # source again — must not error

if [ "$fail" -ne 0 ]; then
    echo "$fail check(s) failed" >&2
    exit 1
fi
echo "test_common.sh smoke passed"
