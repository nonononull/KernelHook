#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-or-later
# lint_exports.sh — assert kmod/exports.manifest and kmod/src/export.c
# list the same set of symbol names.
#
# Called by kmod/mk/kmod.mk as a build-time check.

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

# Extract symbol names from manifest (skip blank/comment lines, first colon-separated field).
manifest_syms=$(awk -F: '!/^[[:space:]]*#/ && NF >= 2 { gsub(/[[:space:]]/, "", $1); if ($1 != "") print $1 }' "$MANIFEST" | sort -u)

# Extract KH_EXPORT(<name>) from export.c.
export_c_syms=$(grep -oE 'KH_EXPORT\([a-zA-Z_][a-zA-Z0-9_]*\)' "$EXPORT_C" | sed -E 's/KH_EXPORT\(([^)]+)\)/\1/' | sort -u)

diff=$(diff <(echo "$manifest_syms") <(echo "$export_c_syms") || true)
if [ -n "$diff" ]; then
    echo "lint_exports: manifest and export.c disagree" >&2
    echo "  (< = in manifest only, > = in export.c only)" >&2
    echo "$diff" >&2
    exit 1
fi

count=$(echo "$manifest_syms" | wc -l | tr -d ' ')
echo "lint_exports: OK ($count symbols)"
