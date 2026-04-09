#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Investigation 2026-04-09: GKI 6.6/6.12 kh_test.ko load failure
#
# Hex-edits the .gnu.linkonce.this_module section size (sh_size) in a
# freestanding-built kh_test.ko. Used to validate the root-cause hypothesis
# that Android 15 GKI 6.6+ downstream kernels enforce an exact sh_size ==
# sizeof(struct module) check at module load time.
#
# This is NOT a production fix. The production fix belongs in
# tools/kmod_loader/kmod_loader.c:patch_module_layout() (see the accompanying
# investigation report for direction).
#
# Assumes section index 11 is .gnu.linkonce.this_module (verified via
# `llvm-readelf -S kh_test.ko` on artifacts built by tests/kmod/Makefile).
#
# Usage:
#   python3 shrink_this_module.py <kh_test.ko> <new_size_hex>
# Examples:
#   python3 shrink_this_module.py kh_test.ko 0x600    # for GKI 6.6
#   python3 shrink_this_module.py kh_test.ko 0x640    # for GKI 6.12
import struct
import sys

if len(sys.argv) != 3:
    print("usage: shrink_this_module.py <kh_test.ko> <new_sh_size_hex>",
          file=sys.stderr)
    sys.exit(2)

path, new_size = sys.argv[1], int(sys.argv[2], 0)
with open(path, "rb") as f:
    b = bytearray(f.read())

e_shoff = struct.unpack_from("<Q", b, 0x28)[0]
e_shentsize = struct.unpack_from("<H", b, 0x3a)[0]
sh = e_shoff + 11 * e_shentsize  # section 11 = .gnu.linkonce.this_module

old = struct.unpack_from("<Q", b, sh + 0x20)[0]
print(f"old sh_size=0x{old:x}  new sh_size=0x{new_size:x}")
struct.pack_into("<Q", b, sh + 0x20, new_size)

with open(path, "wb") as f:
    f.write(b)
