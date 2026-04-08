#!/usr/bin/env bash
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
FIX="$HERE/fixtures"
MK="$HERE/test_detect_toolchain.mk"

PASS=0; FAIL=0; FAILURES=()

run_mk() {
    # Runs make -f test harness in a clean env.
    # Extra args are VAR=VAL assignments passed to make as environment.
    env -i PATH="$PATH" HOME="$HOME" "$@" make --no-print-directory -f "$MK" dump 2>&1
}

get() { echo "$1" | awk -F= -v k="$2" '$1==k{sub(/^[^=]*=/,""); print}'; }
assert_eq() {
    local name=$1 want=$2 got=$3
    if [ "$want" = "$got" ]; then PASS=$((PASS+1));
    else FAIL=$((FAIL+1)); FAILURES+=("  $name: want='$want' got='$got'"); fi
}

# Case 1: NDK via ANDROID_NDK_ROOT, auto API
out=$(run_mk ANDROID_NDK_ROOT="$FIX/ndk_linux")
assert_eq "mk.ndk.kind" "ndk" "$(get "$out" KH_TOOLCHAIN_KIND)"
assert_eq "mk.ndk.api"  "35"  "$(get "$out" KH_ANDROID_API_LEVEL)"

# Case 2: user CROSS_COMPILE (command-line origin)
out=$(env -i PATH="$PATH" HOME="$HOME" make --no-print-directory -f "$MK" CROSS_COMPILE=my- dump 2>&1)
assert_eq "mk.user.kind" "user" "$(get "$out" KH_TOOLCHAIN_KIND)"
assert_eq "mk.user.cc"   "my-gcc" "$(get "$out" KH_CC)"

# Case 3: API override
out=$(run_mk ANDROID_NDK_ROOT="$FIX/ndk_linux" ANDROID_API_LEVEL=28)
assert_eq "mk.api_override" "28" "$(get "$out" KH_ANDROID_API_LEVEL)"

# Case 4: failure — unreachable toolchain
out=$(env -i PATH=/nonexistent HOME="$HOME" make --no-print-directory -f "$MK" dump 2>&1 || true)
echo "$out" | grep -q 'no usable toolchain' && PASS=$((PASS+1)) || { FAIL=$((FAIL+1)); FAILURES+=("  mk.fail: expected error message"); }

echo "---"
echo "PASS: $PASS  FAIL: $FAIL"
[ $FAIL -eq 0 ] || { printf '%s\n' "${FAILURES[@]}"; exit 1; }
