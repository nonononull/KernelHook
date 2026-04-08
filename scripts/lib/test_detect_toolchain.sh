#!/usr/bin/env bash
# Test harness for scripts/lib/detect_toolchain.sh.
# Mocks env + PATH, sources the detector, asserts on exported KH_* vars.
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
DETECTOR="$HERE/detect_toolchain.sh"
FIX="$HERE/fixtures"

PASS=0
FAIL=0
FAILURES=()

assert_eq() {
    local name=$1 want=$2 got=$3
    if [ "$want" = "$got" ]; then
        PASS=$((PASS+1))
    else
        FAIL=$((FAIL+1))
        FAILURES+=("  $name: want='$want' got='$got'")
    fi
}

run_case() {
    local name=$1; shift
    (
        # Clean slate for every case
        unset KH_CC KH_LD KH_AR KH_CROSS_COMPILE KH_ANDROID_SDK \
              KH_NDK KH_NDK_BIN KH_NDK_HOST_TAG KH_ANDROID_API_LEVEL \
              KH_TOOLCHAIN_KIND KH_TOOLCHAIN_DESC
        unset CC LD CROSS_COMPILE ANDROID_NDK_ROOT ANDROID_NDK_HOME \
              ANDROID_SDK_ROOT ANDROID_HOME ANDROID_API_LEVEL
        # Per-case setup runs as the rest of the arguments
        eval "$@"
        # shellcheck disable=SC1090
        . "$DETECTOR" 2>/dev/null || true
        printf "%s|%s|%s|%s|%s\n" \
            "${KH_TOOLCHAIN_KIND:-}" "${KH_CC:-}" "${KH_LD:-}" \
            "${KH_ANDROID_API_LEVEL:-}" "${KH_ANDROID_SDK:-}"
    )
}

# --- Case 1: user override via CC+LD ---
out=$(run_case user_cc_ld 'CC=/tmp/fake-cc; LD=/tmp/fake-ld; export CC LD')
kind=$(echo "$out" | cut -d'|' -f1)
cc=$(echo "$out" | cut -d'|' -f2)
assert_eq "user_cc_ld.kind" "user" "$kind"
assert_eq "user_cc_ld.cc"   "/tmp/fake-cc" "$cc"

# --- Case 2: user override via CROSS_COMPILE ---
out=$(run_case user_cross 'CROSS_COMPILE=aarch64-linux-gnu-; export CROSS_COMPILE')
kind=$(echo "$out" | cut -d'|' -f1)
cc=$(echo "$out" | cut -d'|' -f2)
assert_eq "user_cross.kind" "user" "$kind"
assert_eq "user_cross.cc"   "aarch64-linux-gnu-gcc" "$cc"

# --- Case 3: NDK linux via ANDROID_NDK_ROOT, API auto-max ---
out=$(run_case ndk_linux_max "ANDROID_NDK_ROOT='$FIX/ndk_linux'; export ANDROID_NDK_ROOT")
kind=$(echo "$out" | cut -d'|' -f1)
cc=$(echo "$out" | cut -d'|' -f2)
api=$(echo "$out" | cut -d'|' -f4)
assert_eq "ndk_linux_max.kind" "ndk" "$kind"
assert_eq "ndk_linux_max.api"  "35"  "$api"
case "$cc" in
    *linux-x86_64/bin/clang*aarch64-linux-android35*) PASS=$((PASS+1)) ;;
    *) FAIL=$((FAIL+1)); FAILURES+=("  ndk_linux_max.cc: got '$cc'") ;;
esac

# --- Case 4: NDK with ANDROID_API_LEVEL override ---
out=$(run_case ndk_api_override \
    "ANDROID_NDK_ROOT='$FIX/ndk_linux'; ANDROID_API_LEVEL=28; export ANDROID_NDK_ROOT ANDROID_API_LEVEL")
api=$(echo "$out" | cut -d'|' -f4)
assert_eq "ndk_api_override.api" "28" "$api"

# --- Case 5: sys-gcc fallback (PATH-controlled) ---
SYSBIN=$(mktemp -d)
cat >"$SYSBIN/aarch64-linux-gnu-gcc" <<'EOF'
#!/bin/sh
exit 0
EOF
cat >"$SYSBIN/aarch64-linux-gnu-ld" <<'EOF'
#!/bin/sh
exit 0
EOF
cat >"$SYSBIN/aarch64-linux-gnu-ar" <<'EOF'
#!/bin/sh
exit 0
EOF
chmod +x "$SYSBIN"/*
out=$(run_case sys_gcc "PATH='$SYSBIN'; export PATH")
kind=$(echo "$out" | cut -d'|' -f1)
assert_eq "sys_gcc.kind" "sys-gcc" "$kind"
rm -rf "$SYSBIN"

# --- Case 6: total failure (no NDK, no cross, empty PATH) ---
set +e
out=$(run_case no_tools "PATH=/nonexistent; export PATH" 2>&1)
rc=$?
set -e
if [ $rc -eq 0 ]; then
    FAIL=$((FAIL+1)); FAILURES+=("  no_tools: expected nonzero exit")
else
    PASS=$((PASS+1))
fi

# --- Case 7: idempotency — second source recomputes ---
out1=$(run_case idem1 "ANDROID_NDK_ROOT='$FIX/ndk_linux'; ANDROID_API_LEVEL=30; export ANDROID_NDK_ROOT ANDROID_API_LEVEL")
out2=$(run_case idem2 "ANDROID_NDK_ROOT='$FIX/ndk_linux'; ANDROID_API_LEVEL=35; export ANDROID_NDK_ROOT ANDROID_API_LEVEL")
api1=$(echo "$out1" | cut -d'|' -f4)
api2=$(echo "$out2" | cut -d'|' -f4)
assert_eq "idem.api_30" "30" "$api1"
assert_eq "idem.api_35" "35" "$api2"

echo "---"
echo "PASS: $PASS  FAIL: $FAIL"
if [ $FAIL -gt 0 ]; then
    printf '%s\n' "${FAILURES[@]}"
    exit 1
fi
