#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-or-later
# kh_crc host test driver. Run via `make test` in tools/kh_crc/.

set -uo pipefail

cd "$(dirname "$0")/.."
TOOL=./kh_crc
MANIFEST=../../kmod/exports.manifest
GOLDEN=tests/golden.expected

if [ ! -x "$TOOL" ]; then
    echo "ERROR: $TOOL not built. Run 'make' first." >&2
    exit 2
fi

fail=0
pass=0

# ---- Test 1: self-test (CRC32, canonicalize, parser) ----
if "$TOOL" --mode=self-test > /tmp/kh_crc_selftest.log 2>&1; then
    echo "PASS self-test"
    pass=$((pass+1))
else
    echo "FAIL self-test"
    cat /tmp/kh_crc_selftest.log
    fail=$((fail+1))
fi

# ---- Test 2: golden regression ----
# Re-run the tool against the real manifest, compare against frozen values.
# Method: for each line in golden.expected, assert kh_crc's CRC matches.
# Uses --mode=symvers which emits one line per symbol.
"$TOOL" --mode=symvers --manifest="$MANIFEST" > /tmp/kh_crc_symvers.txt 2>&1 || {
    echo "FAIL golden: --mode=symvers errored"
    cat /tmp/kh_crc_symvers.txt
    fail=$((fail+1))
}

# Parse both golden and actual into "name -> crc" pairs and diff.
# Golden format: <canonical>\t0x<crc>
# symvers format (Linux standard): 0x<crc>\t<name>\tvmlinux\tEXPORT_SYMBOL
awk 'NR==FNR{
        if ($0 ~ /^#/ || NF < 2) next
        # canonical string is before tab, crc after
        sub(/\(.*/, "", $1)  # strip "(args)->ret" to get just the name
        golden[$1] = $2
        next
    }
    {
        if ($0 ~ /^#/ || NF < 2) next
        actual[$2] = $1
    }
    END {
        for (k in golden) {
            if (!(k in actual)) {
                printf "FAIL golden: symbol %s missing from actual output\n", k
                exit 1
            }
            if (golden[k] != actual[k]) {
                printf "FAIL golden: %s got %s expected %s\n", k, actual[k], golden[k]
                exit 1
            }
        }
        for (k in actual) {
            if (!(k in golden)) {
                printf "FAIL golden: symbol %s in actual but not golden (add it!)\n", k
                exit 1
            }
        }
    }
' "$GOLDEN" /tmp/kh_crc_symvers.txt

if [ $? -eq 0 ]; then
    echo "PASS golden regression"
    pass=$((pass+1))
else
    fail=$((fail+1))
fi

# ---- Test 3: Contract 1 independence ----
# Adding a new line to the manifest must not change any existing CRC.
# Both kh_crc invocations must succeed — otherwise empty outputs could
# vacuously satisfy the diff check and silently pass.
if ! "$TOOL" --mode=symvers --manifest="$MANIFEST" > /tmp/kh_crc_orig.txt 2>/tmp/kh_crc_orig.err; then
    echo "FAIL independence: --mode=symvers on MANIFEST failed"
    cat /tmp/kh_crc_orig.err
    fail=$((fail+1))
elif ! "$TOOL" --mode=symvers --manifest=tests/dummy_extra.txt > /tmp/kh_crc_plus.txt 2>/tmp/kh_crc_plus.err; then
    echo "FAIL independence: --mode=symvers on dummy_extra.txt failed"
    cat /tmp/kh_crc_plus.err
    fail=$((fail+1))
elif [ ! -s /tmp/kh_crc_orig.txt ] || [ ! -s /tmp/kh_crc_plus.txt ]; then
    echo "FAIL independence: kh_crc produced empty output"
    fail=$((fail+1))
else
    # Strip the dummy line from the "plus" output, compare to original.
    grep -v '^0x[0-9a-f]*[[:space:]]*dummy_never_exported' /tmp/kh_crc_plus.txt > /tmp/kh_crc_plus_stripped.txt
    if diff -q /tmp/kh_crc_orig.txt /tmp/kh_crc_plus_stripped.txt > /dev/null; then
        echo "PASS independence (Contract 1)"
        pass=$((pass+1))
    else
        echo "FAIL independence: adding a line changed existing CRCs"
        diff /tmp/kh_crc_orig.txt /tmp/kh_crc_plus_stripped.txt
        fail=$((fail+1))
    fi
fi

# ---- Report ----
echo ""
echo "tests: $pass passed, $fail failed"
[ $fail -eq 0 ]
