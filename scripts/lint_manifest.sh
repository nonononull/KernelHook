#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-or-later
# lint_manifest.sh — assert kmod/exports.manifest and kmod/src/export.c
# list the same set of symbol names, and that each side is duplicate-free.
#
# Called by kmod/mk/kmod.mk as a build-time check.
#
# The export.c parser is NOT a raw grep — it uses Python to strip C comments
# (both /* */ and //), #if 0 / #endif disabled blocks, and #define lines
# before searching for KH_EXPORT(name) call sites. A commented-out or
# preprocessor-disabled call must NOT be counted, because the compiler will
# not see it and the resulting symbol would be absent from kernelhook.ko
# while the lint silently considered it present.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
MANIFEST="$ROOT/kmod/exports.manifest"
EXPORT_C="$ROOT/kmod/src/export.c"

if [ ! -f "$MANIFEST" ]; then
    echo "lint_exports: $MANIFEST not found" >&2
    exit 2
fi
if [ ! -f "$EXPORT_C" ]; then
    echo "lint_exports: $EXPORT_C not found" >&2
    exit 2
fi

# Extract symbol names from manifest (skip blank/comment lines, first
# colon-separated field). Sort WITHOUT -u so duplicates remain visible
# for the uniq -d check below.
manifest_syms=$(awk -F: '!/^[[:space:]]*#/ && NF >= 2 { gsub(/[[:space:]]/, "", $1); if ($1 != "") print $1 }' "$MANIFEST" | sort)

# Extract KH_EXPORT(<name>) from export.c using a minimal Python parser
# that strips comments, #if 0 blocks, and #define lines first.
export_c_syms=$(python3 - "$EXPORT_C" <<'PY'
import re, sys
with open(sys.argv[1]) as f:
    src = f.read()
# Strip /* ... */ comments (multi-line).
src = re.sub(r'/\*.*?\*/', '', src, flags=re.DOTALL)
# Strip // ... line comments.
src = re.sub(r'//[^\n]*', '', src)
# Strip #if 0 ... #endif blocks (flat only; no nested #if support — this
# is sufficient for export.c's discipline of at most one #if 0 depth).
src = re.sub(r'(?ms)^\s*#\s*if\s+0\b.*?^\s*#\s*endif\b[^\n]*', '', src)
# Drop #define lines so the macro definition (e.g. "#define KH_EXPORT(sym)")
# does not contribute its formal parameter as a bogus symbol name.
src = '\n'.join(l for l in src.split('\n') if not re.match(r'\s*#\s*define\b', l))
# Find KH_EXPORT(name) call sites.
for m in re.finditer(r'\bKH_EXPORT\(\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*\)', src):
    print(m.group(1))
PY
)
export_c_syms=$(printf '%s\n' "$export_c_syms" | sort)

# Duplicate detection on each side (manifest and export.c independently).
manifest_dupes=$(printf '%s\n' "$manifest_syms" | uniq -d || true)
if [ -n "$manifest_dupes" ]; then
    echo "lint_exports: duplicate symbol(s) in $MANIFEST:" >&2
    printf '  %s\n' $manifest_dupes >&2
    exit 1
fi
export_c_dupes=$(printf '%s\n' "$export_c_syms" | uniq -d || true)
if [ -n "$export_c_dupes" ]; then
    echo "lint_exports: duplicate KH_EXPORT call(s) in $EXPORT_C:" >&2
    printf '  %s\n' $export_c_dupes >&2
    exit 1
fi

# Cross-check: same set on both sides (order-independent).
manifest_uniq=$(printf '%s\n' "$manifest_syms" | uniq)
export_c_uniq=$(printf '%s\n' "$export_c_syms" | uniq)
set_diff=$(diff <(echo "$manifest_uniq") <(echo "$export_c_uniq") || true)
if [ -n "$set_diff" ]; then
    echo "lint_exports: manifest and export.c disagree" >&2
    echo "  (< = in manifest only, > = in export.c only)" >&2
    echo "$set_diff" >&2
    exit 1
fi

count=$(echo "$manifest_uniq" | wc -l | tr -d ' ')
echo "lint_exports: OK ($count symbols)"
