#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-or-later
# Automated kmod test runner for all AVD emulators.
#
# Usage:
#   ./scripts/test_avd_kmod.sh                                  # sdk mode, all AVDs
#   ./scripts/test_avd_kmod.sh Pixel_31 Pixel_37                # sdk mode, specific AVDs
#   ./scripts/test_avd_kmod.sh --mode=freestanding              # legacy kh_test.ko kh_root demo + Ring 3 sweep
#   ./scripts/test_avd_kmod.sh --mode=sdk Pixel_35              # explicit sdk mode + specific AVD
#
# Modes:
#   sdk (default): build kernelhook.ko + examples/hello_hook/hello_hook.ko once,
#                  two-step kmod_loader insmod per AVD, verify hello_hook dmesg marker,
#                  reverse-order rmmod.
#   freestanding:  per-AVD rebuild of tests/kmod/kh_test.ko against the AVD's
#                  kernel release, single-load, run the kh_root demo + Ring 3 sweep.

set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"

# Flag parser: --mode={sdk,freestanding} (default sdk). Remaining positional
# arguments are AVD names. Bash-3.2 / macOS-safe: the `"${NEW_ARGS[@]+...}"`
# form avoids the "unbound variable" error that `set -u` would raise on an
# empty array re-expansion.
KH_MODE="sdk"
NEW_ARGS=()
while [ "$#" -gt 0 ]; do
    case "$1" in
        --mode=*) KH_MODE="${1#--mode=}"; shift ;;
        --)       shift; while [ "$#" -gt 0 ]; do NEW_ARGS+=("$1"); shift; done ;;
        -*)       echo "unknown flag $1" >&2; exit 2 ;;
        *)        NEW_ARGS+=("$1"); shift ;;
    esac
done
set -- "${NEW_ARGS[@]+"${NEW_ARGS[@]}"}"
case "$KH_MODE" in
    sdk|freestanding) ;;
    *) echo "invalid --mode=$KH_MODE (expected sdk|freestanding)" >&2; exit 2 ;;
esac

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

# Shared color + summary helpers (KH_RED/GREEN/YELLOW/BOLD/RESET, kh_summary_line).
# shellcheck source=lib/test_common.sh
. "$ROOT/scripts/lib/test_common.sh"

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
    printf "${KH_BOLD}Building kmod_loader...${KH_RESET}\n"
    make -C "$ROOT/tools/kmod_loader" kmod_loader HOSTCC="$KH_CC"
fi

# SDK-mode build is common across AVDs: build kernelhook.ko + hello_hook.ko
# ONCE here, push to each AVD in the loop. Common-kernel vermagic assumption
# is reasonable for the Pixel_30..37 matrix (all are android GKI). If an AVD
# has a divergent KERNELRELEASE, the per-AVD load step will surface the
# vermagic mismatch as a load failure, which is the correct classification.
if [ "$KH_MODE" = "sdk" ]; then
    printf "${KH_BOLD}Building SDK artifacts (kernelhook.ko + hello_hook.ko)...${KH_RESET}\n"
    : > /tmp/kh_avd_sdk_build.log
    if ! ( cd "$ROOT/kmod" && \
           { make clean >/dev/null 2>&1 || true; } && \
           make module \
               CC="$KH_CC" \
               LD="$KH_LD" \
               CROSS_COMPILE="$KH_CROSS_COMPILE" \
               >>/tmp/kh_avd_sdk_build.log 2>&1 ); then
        printf "${KH_RED}FAIL${KH_RESET} kernelhook.ko build failed — see /tmp/kh_avd_sdk_build.log\n"
        tail -30 /tmp/kh_avd_sdk_build.log | sed 's/^/       /'
        exit 1
    fi
    if ! ( cd "$ROOT/examples/hello_hook" && \
           { make clean >/dev/null 2>&1 || true; } && \
           CC="$KH_CC" \
           LD="$KH_LD" \
           CROSS_COMPILE="$KH_CROSS_COMPILE" \
           make module \
               >>/tmp/kh_avd_sdk_build.log 2>&1 ); then
        printf "${KH_RED}FAIL${KH_RESET} hello_hook.ko (SDK) build failed — see /tmp/kh_avd_sdk_build.log\n"
        tail -30 /tmp/kh_avd_sdk_build.log | sed 's/^/       /'
        exit 1
    fi
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
    printf "\n${KH_BOLD}======== Testing $avd ========${KH_RESET}\n"

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
        printf "  ${KH_RED}SKIP${KH_RESET} $avd: boot timeout\n"
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
        printf "  ${KH_YELLOW}SKIP${KH_RESET} $avd: kernel %s (3.18 module loader incompatible)\n" "$uname"
        RESULTS+=("SKIP|$avd|kernel_3.18|$sdk|$uname")
        SKIP_COUNT=$((SKIP_COUNT + 1))
        kill_emulator
        return
    fi

    # Check if modules are supported
    local mod_support=$(adb -s emulator-5554 shell "zcat /proc/config.gz 2>/dev/null | grep '^CONFIG_MODULES=y'" 2>/dev/null | tr -d '[:space:]')
    if [ "$mod_support" != "CONFIG_MODULES=y" ]; then
        printf "  ${KH_YELLOW}SKIP${KH_RESET} $avd: CONFIG_MODULES not enabled\n"
        RESULTS+=("SKIP|$avd|no_modules|$sdk|$uname")
        SKIP_COUNT=$((SKIP_COUNT + 1))
        kill_emulator
        return
    fi

    # SDK mode: artifacts were built once before the loop; freestanding mode
    # rebuilds kh_test.ko per-AVD because it's ifdef'd against kernel internals.
    if [ "$KH_MODE" = "freestanding" ]; then
        printf "  Building kh_test.ko...\n"
        cd "$ROOT/tests/kmod"
        make clean >/dev/null 2>&1 || true
        if ! make freestanding \
            KERNELRELEASE="$uname" \
            CC="$KH_CC" \
            LD="$KH_LD" \
            CROSS_COMPILE="$KH_CROSS_COMPILE" \
            >/dev/null 2>&1; then
            printf "  ${KH_RED}FAIL${KH_RESET} $avd: build failed\n"
            RESULTS+=("FAIL|$avd|build_failed|$sdk|$uname")
            FAIL_COUNT=$((FAIL_COUNT + 1))
            kill_emulator
            return
        fi
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
    if [ "$KH_MODE" = "sdk" ]; then
        adb -s emulator-5554 push "$ROOT/kmod/kernelhook.ko"                /data/local/tmp/kernelhook.ko >/dev/null 2>&1 || true
        adb -s emulator-5554 push "$ROOT/examples/hello_hook/hello_hook.ko" /data/local/tmp/hello_hook.ko >/dev/null 2>&1 || true
    else
        adb -s emulator-5554 push "$ROOT/tests/kmod/kh_test.ko"             /data/local/tmp/kh_test.ko    >/dev/null 2>&1 || true
    fi
    adb -s emulator-5554 push "$LOADER" /data/local/tmp/kmod_loader >/dev/null 2>&1 || true
    adb -s emulator-5554 shell "chmod +x /data/local/tmp/kmod_loader" >/dev/null 2>&1 || true

    # Unload any stale modules from a previous run. In SDK mode the consumer
    # (hello_hook) must come off first because it holds a refcount on
    # kernelhook via the ksymtab imports.
    if [ "$KH_MODE" = "sdk" ]; then
        adb -s emulator-5554 shell "rmmod hello_hook 2>/dev/null; rmmod kernelhook 2>/dev/null; true" >/dev/null 2>&1 || true
    else
        adb -s emulator-5554 shell "rmmod kh_test" >/dev/null 2>&1 || true
    fi
    adb -s emulator-5554 shell "dmesg -c" >/dev/null 2>&1 || true

    # Live kernel-log capture: survives emulator death so kernel panic
    # (BUG:/Oops/Call trace) is retrievable even when init_module aborts
    # the VM. /dev/kmsg is unbuffered and strictly ordered, unlike
    # `dmesg -w` which pipes through userspace buffering.
    local live_dmesg="/tmp/kh_dmesg_${avd}.log"
    rm -f "$live_dmesg"
    adb -s emulator-5554 shell "cat /dev/kmsg" > "$live_dmesg" 2>&1 &
    local dmesg_pid=$!
    sleep 1

    local load_output=""
    local load_rc=1
    if [ "$KH_MODE" = "sdk" ]; then
        # Step 1: insmod kernelhook.ko (the SDK base). Host-side 60s timeout
        # since Android 'timeout' may not exist on old AVDs.
        load_output=$(perl -e 'alarm 60; exec @ARGV' adb -s emulator-5554 shell "/data/local/tmp/kmod_loader /data/local/tmp/kernelhook.ko kallsyms_addr=0x${kaddr} ${crc_args}" 2>&1) || true
        load_rc=$?
        if ! echo "$load_output" | grep -qi "loaded"; then
            sleep 1
            kill "$dmesg_pid" 2>/dev/null || true
            wait "$dmesg_pid" 2>/dev/null || true
            printf "  ${KH_RED}FAIL${KH_RESET} $avd: kernelhook.ko load failed\n"
            echo "$load_output" | sed 's/^/       /'
            RESULTS+=("FAIL|$avd|sdk_base_load|$sdk|$uname")
            FAIL_COUNT=$((FAIL_COUNT + 1))
            kill_emulator
            return
        fi
        # Step 2: insmod hello_hook.ko (the SDK consumer).
        load_output=$(perl -e 'alarm 60; exec @ARGV' adb -s emulator-5554 shell "/data/local/tmp/kmod_loader /data/local/tmp/hello_hook.ko kallsyms_addr=0x${kaddr} ${crc_args}" 2>&1) || true
        load_rc=$?
    else
        load_output=$(perl -e 'alarm 60; exec @ARGV' adb -s emulator-5554 shell "/data/local/tmp/kmod_loader /data/local/tmp/kh_test.ko kallsyms_addr=0x${kaddr} ${crc_args}" 2>&1) || true
        load_rc=$?
    fi

    # Let adb drain any in-flight kernel-log lines before closing the pipe.
    sleep 1
    kill "$dmesg_pid" 2>/dev/null || true
    wait "$dmesg_pid" 2>/dev/null || true
    if [ -s "$live_dmesg" ] && grep -qE "BUG:|Unable to handle|Oops|Kernel panic|Call trace:" "$live_dmesg"; then
        printf "  ${KH_YELLOW}Kernel panic captured in live kmsg:${KH_RESET}\n"
        awk '/BUG:|Unable to handle|Oops|Kernel panic|Call trace:/{p=1} p{print; if(++n>80) exit}' "$live_dmesg" | sed 's/^/       /'
    fi

    if ! echo "$load_output" | grep -qi "loaded"; then
        printf "  ${KH_RED}FAIL${KH_RESET} $avd: module load failed\n"
        echo "$load_output" | sed 's/^/       /'
        RESULTS+=("FAIL|$avd|load_failed|$sdk|$uname")
        FAIL_COUNT=$((FAIL_COUNT + 1))
        # SDK mode: best-effort peel kernelhook back off so it's not left loaded.
        if [ "$KH_MODE" = "sdk" ]; then
            adb -s emulator-5554 shell "rmmod kernelhook 2>/dev/null; true" >/dev/null 2>&1 || true
        fi
        kill_emulator
        return
    fi

    # ---- SDK mode: runtime-verify the hello_hook consumer marker, unload reverse.
    if [ "$KH_MODE" = "sdk" ]; then
        sleep 2
        # Marker is emitted at hello_hook_init() time — i.e. during the insmod
        # call above. The live /dev/kmsg capture ($live_dmesg) caught it at
        # emit time; a fresh `adb shell dmesg` poll here can miss it because
        # the callback-spam (one pr_info per open(2)) can evict the setup
        # line from the kernel ring buffer before we poll. Prefer the live
        # capture; fall back to fresh dmesg only if the capture missed it.
        local hook_line=""
        if [ -s "$live_dmesg" ]; then
            hook_line=$(grep "hello_hook: hooked do_sys_open" "$live_dmesg" | tail -1)
        fi
        if [ -z "$hook_line" ]; then
            local sdk_dmesg=$(adb -s emulator-5554 shell "dmesg" 2>/dev/null)
            hook_line=$(echo "$sdk_dmesg" | grep "hello_hook: hooked do_sys_open" | tail -1)
        fi
        if [ -n "$hook_line" ]; then
            printf "  ${KH_GREEN}PASS${KH_RESET} $avd: hello_hook active (API %s, kernel %s)\n" "$sdk" "$uname"
            printf "       %s\n" "$hook_line"
            RESULTS+=("PASS|$avd|hello_hook|$sdk|$uname")
            PASS_COUNT=$((PASS_COUNT + 1))
        else
            printf "  ${KH_RED}FAIL${KH_RESET} $avd: hello_hook marker not found in live kmsg or dmesg\n"
            if [ -s "$live_dmesg" ]; then
                grep -E "hello_hook:|kernelhook:" "$live_dmesg" | tail -10 | sed 's/^/       live: /'
            fi
            adb -s emulator-5554 shell "dmesg" 2>/dev/null | grep -E "hello_hook:|kernelhook:" | tail -10 | sed 's/^/       poll: /'
            RESULTS+=("FAIL|$avd|hello_hook_marker|$sdk|$uname")
            FAIL_COUNT=$((FAIL_COUNT + 1))
        fi
        # Reverse-order rmmod: consumer first (refcount holder), then SDK base.
        adb -s emulator-5554 shell "rmmod hello_hook 2>/dev/null; rmmod kernelhook 2>/dev/null; true" >/dev/null 2>&1 || true
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
        printf "  ${KH_GREEN}PASS${KH_RESET} $avd: %s passed, %s failed (API %s, kernel %s)\n" "$passed" "$failed" "$sdk" "$uname"
        RESULTS+=("PASS|$avd|${passed}/${passed}|$sdk|$uname")
        PASS_COUNT=$((PASS_COUNT + 1))

        # ---- Ring 3: export_link_test (exporter + importer) ----
        printf "  Running export_link_test (Ring 3)...\n"
        # Select __ksymtab layout based on the LIVE kernel config rather
        # than a version heuristic. `struct kernel_symbol` is a 12-byte
        # PREL32 struct when CONFIG_HAVE_ARCH_PREL32_RELOCATIONS=y and a
        # 24-byte absolute-pointer struct otherwise. A mismatch causes a
        # strcmp crash inside find_symbol → bsearch at load time (verified
        # on Pixel_30 GKI 5.4 android11 where PREL32 is OFF). AVDs in the
        # wild can go either way — 5.4 android11 = abs64, 5.15 android13
        # = prel32, 6.1+ = prel32 — so probe at test time.
        local kh_layout="prel32"
        if adb -s emulator-5554 shell 'su 0 sh -c "zcat /proc/config.gz 2>/dev/null | grep -q CONFIG_HAVE_ARCH_PREL32_RELOCATIONS=y"' 2>/dev/null; then
            kh_layout="prel32"
        else
            kh_layout="abs64"
        fi
        printf "  Ring 3 __ksymtab layout: %s\n" "$kh_layout"
        (
            cd "$ROOT/tests/kmod/export_link_test" && \
            rm -rf _kh_kmod _kh_core exporter.ko importer.ko \
                   exporter.kmod.o importer.kmod.o \
                   "$ROOT/kmod/generated/kh_exports.S" 2>/dev/null; \
            KERNELRELEASE="$uname" \
            CC="$KH_CC" \
            LD="$KH_LD" \
            CROSS_COMPILE="$KH_CROSS_COMPILE" \
            KH_KSYMTAB_LAYOUT="$kh_layout" \
            make >/dev/null 2>&1
        )
        if [ ! -f "$ROOT/tests/kmod/export_link_test/exporter.ko" ] || \
           [ ! -f "$ROOT/tests/kmod/export_link_test/importer.ko" ]; then
            printf "  ${KH_RED}FAIL${KH_RESET} $avd: export_link_test build failed\n"
            RESULTS+=("FAIL|$avd|export_link_build|$sdk|$uname")
            FAIL_COUNT=$((FAIL_COUNT + 1))
        else
            if KADDR="0x${kaddr}" CRC_ARGS="${crc_args}" \
               "$ROOT/tests/kmod/export_link_test/test_on_avd.sh" emulator-5554; then
                printf "  ${KH_GREEN}PASS${KH_RESET} $avd: export_link_test (Ring 3)\n"
                RESULTS+=("PASS|$avd|export_link_test|$sdk|$uname")
            else
                printf "  ${KH_RED}FAIL${KH_RESET} $avd: export_link_test (Ring 3)\n"
                RESULTS+=("FAIL|$avd|export_link_test|$sdk|$uname")
                FAIL_COUNT=$((FAIL_COUNT + 1))
            fi
        fi
    elif [ "$passed" -gt 0 ] || [ "$failed" -gt 0 ]; then
        printf "  ${KH_RED}FAIL${KH_RESET} $avd: %s passed, %s failed\n" "$passed" "$failed"
        echo "$dmesg" | grep -i "FAIL" | sed 's/^/       /'
        RESULTS+=("FAIL|$avd|${passed}/$((passed+failed))|$sdk|$uname")
        FAIL_COUNT=$((FAIL_COUNT + 1))
    else
        printf "  ${KH_YELLOW}WARN${KH_RESET} $avd: no test output (init may not have run)\n"
        echo "$dmesg" | head -5 | sed 's/^/       /'
        RESULTS+=("FAIL|$avd|no_output|$sdk|$uname")
        FAIL_COUNT=$((FAIL_COUNT + 1))
    fi

    kill_emulator
}

printf "${KH_BOLD}KernelHook kmod AVD Test Suite${KH_RESET}\n"
printf "Mode: %s\n" "$KH_MODE"
printf "AVDs to test: %s\n" "${AVDS[*]}"
printf "Toolchain: %s\n\n" "$KH_TOOLCHAIN_DESC"

for avd in "${AVDS[@]}"; do
    test_avd "$avd"
done

# Summary
printf "\n${KH_BOLD}================ Summary ================${KH_RESET}\n"
printf "%-14s %-6s %-10s %-35s %s\n" "AVD" "API" "Result" "Kernel" "Detail"
printf "%-14s %-6s %-10s %-35s %s\n" "---" "---" "------" "------" "------"
for r in "${RESULTS[@]}"; do
    IFS='|' read -r status avd detail api kernel <<< "$r"
    case "$status" in
        PASS)  color="$KH_GREEN" ;;
        FAIL)  color="$KH_RED" ;;
        SKIP)  color="$KH_YELLOW" ;;
        *)     color="$KH_RESET" ;;
    esac
    printf "%-14s %-6s ${color}%-10s${KH_RESET} %-35s %s\n" "$avd" "$api" "$status" "$kernel" "$detail"
done
printf "\n${KH_GREEN}Passed: %d${KH_RESET}  ${KH_RED}Failed: %d${KH_RESET}  ${KH_YELLOW}Skipped: %d${KH_RESET}  Total: %d\n" \
    "$PASS_COUNT" "$FAIL_COUNT" "$SKIP_COUNT" "$((PASS_COUNT + FAIL_COUNT + SKIP_COUNT))"

# Shared skip-aware summary line (kh_summary_line from scripts/lib/test_common.sh).
kh_summary_line "$PASS_COUNT" "$FAIL_COUNT" "$SKIP_COUNT"

exit $((FAIL_COUNT > 0 ? 1 : 0))
