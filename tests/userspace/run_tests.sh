#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-or-later
# Run all KernelHook tests in Debug and Release modes.
# Usage: tests/userspace/run_tests.sh [--release-only | --debug-only]

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

# Colors
RED='\033[31m'
GREEN='\033[32m'
YELLOW='\033[33m'
BOLD='\033[1m'
RESET='\033[0m'

TESTS=(
    test_smoke
    test_hmem
    test_reloc
    test_chain
    test_hook_basic
    test_hook_chain
    test_stress
)

PASSED=0
FAILED=0
SKIPPED=0
FAILURES=""

run_suite() {
    local mode="$1"           # Debug or Release
    local build_dir="build_$(echo "$mode" | tr '[:upper:]' '[:lower:]')"

    printf "\n${BOLD}========== Building %s ==========${RESET}\n" "$mode"
    cmake -B "$build_dir" -DCMAKE_BUILD_TYPE="$mode" -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
        > /dev/null 2>&1
    if ! cmake --build "$build_dir" -j"$(nproc 2>/dev/null || sysctl -n hw.ncpu)" 2>&1 \
        | tail -1; then
        printf "${RED}Build failed for %s${RESET}\n" "$mode"
        for t in "${TESTS[@]}"; do
            FAILED=$((FAILED + 1))
            FAILURES="${FAILURES}\n  ${RED}FAIL${RESET} [${mode}] ${t} (build error)"
        done
        return
    fi

    printf "${BOLD}---------- %s tests ----------${RESET}\n" "$mode"
    for t in "${TESTS[@]}"; do
        local bin="${build_dir}/tests/${t}"
        if [ ! -x "$bin" ]; then
            printf "  ${YELLOW}SKIP${RESET} [%s] %s (binary not found)\n" "$mode" "$t"
            SKIPPED=$((SKIPPED + 1))
            continue
        fi

        if output=$("$bin" 2>&1); then
            printf "  ${GREEN}PASS${RESET} [%s] %s\n" "$mode" "$t"
            PASSED=$((PASSED + 1))
        else
            printf "  ${RED}FAIL${RESET} [%s] %s\n" "$mode" "$t"
            FAILED=$((FAILED + 1))
            FAILURES="${FAILURES}\n  ${RED}FAIL${RESET} [${mode}] ${t}"
            # Show output for failed tests
            echo "$output" | sed 's/^/       /'
        fi
    done
}

# Parse arguments
RUN_DEBUG=1
RUN_RELEASE=1
for arg in "$@"; do
    case "$arg" in
        --release-only) RUN_DEBUG=0 ;;
        --debug-only)   RUN_RELEASE=0 ;;
        -h|--help)
            echo "Usage: $0 [--release-only | --debug-only]"
            exit 0
            ;;
        *)
            echo "Unknown option: $arg"
            exit 1
            ;;
    esac
done

printf "${BOLD}KernelHook Test Suite${RESET}\n"

[ "$RUN_DEBUG"   -eq 1 ] && run_suite Debug
[ "$RUN_RELEASE" -eq 1 ] && run_suite Release

# Summary
printf "\n${BOLD}========== Summary ==========${RESET}\n"
TOTAL=$((PASSED + FAILED + SKIPPED))
printf "  Total: %d  |  ${GREEN}Passed: %d${RESET}  |  ${RED}Failed: %d${RESET}  |  ${YELLOW}Skipped: %d${RESET}\n" \
    "$TOTAL" "$PASSED" "$FAILED" "$SKIPPED"

if [ -n "$FAILURES" ]; then
    printf "\nFailures:${FAILURES}\n"
fi

exit "$FAILED"
