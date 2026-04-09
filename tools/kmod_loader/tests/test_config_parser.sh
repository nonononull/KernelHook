#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-or-later
# Host unit tests for tools/gen_devices_table.py.
# Run via `make test` in tools/kmod_loader/.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
GEN="$ROOT/tools/gen_devices_table.py"

fail=0

mkdir -p /tmp/khtst
cleanup() { rm -rf /tmp/khtst; }
trap cleanup EXIT

# Test 1: valid minimal .conf → one entry
cat > /tmp/khtst/a.conf <<'EOF'
[identity]
name = a_valid
arch = aarch64
[match]
kernelrelease = 0.0.
[modversions]
module_layout = 0x1
_printk = 0x2
memcpy = 0x3
memset = 0x4
[struct_module]
this_module_size = 0x100
module_init_offset = 0x20
module_exit_offset = 0x30
[vermagic]
string = "vm"
EOF
mkdir -p /tmp/khtst/d1
cp /tmp/khtst/a.conf /tmp/khtst/d1/
"$GEN" --devices-dir /tmp/khtst/d1 --output /tmp/khtst/d1.c >/dev/null 2>&1
if grep -q '"a_valid"' /tmp/khtst/d1.c; then
    echo "PASS parse valid .conf"
else
    echo "FAIL parse valid .conf"; fail=$((fail+1))
fi

# Test 2: missing section → error
cat > /tmp/khtst/bad.conf <<'EOF'
[identity]
name = bad
arch = aarch64
EOF
mkdir -p /tmp/khtst/d2
cp /tmp/khtst/bad.conf /tmp/khtst/d2/
if ! "$GEN" --devices-dir /tmp/khtst/d2 --output /tmp/khtst/d2.c 2>/dev/null; then
    echo "PASS reject missing section"
else
    echo "FAIL should have rejected missing section"; fail=$((fail+1))
fi

# Test 3: duplicate names → error
cat > /tmp/khtst/b.conf <<'EOF'
[identity]
name = a_valid
arch = aarch64
[match]
kernelrelease = 1.0.
[modversions]
module_layout = 0x10
_printk = 0x20
memcpy = 0x30
memset = 0x40
[struct_module]
this_module_size = 0x100
module_init_offset = 0x20
module_exit_offset = 0x30
[vermagic]
string = "vm2"
EOF
mkdir -p /tmp/khtst/d3
cp /tmp/khtst/a.conf /tmp/khtst/d3/
cp /tmp/khtst/b.conf /tmp/khtst/d3/
if ! "$GEN" --devices-dir /tmp/khtst/d3 --output /tmp/khtst/d3.c 2>/dev/null; then
    echo "PASS reject duplicate names"
else
    echo "FAIL should have rejected duplicate names"; fail=$((fail+1))
fi

# Test 4: bad hex → error
cat > /tmp/khtst/c.conf <<'EOF'
[identity]
name = bad_hex
arch = aarch64
[match]
kernelrelease = 1.0.
[modversions]
module_layout = not_hex
_printk = 0x1
memcpy = 0x2
memset = 0x3
[struct_module]
this_module_size = 0x100
module_init_offset = 0x20
module_exit_offset = 0x30
[vermagic]
string = "vm"
EOF
mkdir -p /tmp/khtst/d4
cp /tmp/khtst/c.conf /tmp/khtst/d4/
if ! "$GEN" --devices-dir /tmp/khtst/d4 --output /tmp/khtst/d4.c 2>/dev/null; then
    echo "PASS reject bad hex"
else
    echo "FAIL should have rejected bad hex"; fail=$((fail+1))
fi

[ $fail -eq 0 ]
