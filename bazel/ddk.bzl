# SPDX-License-Identifier: GPL-2.0-or-later
# bazel/ddk.bzl — KernelHook DDK build rules.
#
# Provides ddk_module() and ddk_headers() with the same call-site interface
# as AOSP's kleaf rules.  Implementation uses genrule() + make, delegating
# to the kernel build system in the DDK container.  No AOSP workspace needed.
#
# Migration path to upstream kleaf: when moving to a full AOSP kleaf setup,
# replace each BUILD.bazel's load() from
#   load("//bazel:ddk.bzl", "ddk_module", "ddk_headers")
# to
#   load("@kleaf//build/kernel/kleaf:kernel.bzl", "ddk_module", "ddk_headers")
# No other changes to BUILD.bazel files are required.

def ddk_headers(
        name,
        hdrs = [],
        includes = [],
        linux_includes = [],
        visibility = None,
        **kwargs):
    """Export a set of kernel headers for downstream ddk_module() targets.

    API-compatible with AOSP's ddk_headers().

    Args:
        name:           Target name.
        hdrs:           Header files to export.
        includes:       Include dirs (API compat; compilation flags in Kbuild).
        linux_includes: Extra linux/ paths (API compat, not used here).
        visibility:     Bazel visibility.
    """
    native.filegroup(
        name = name,
        srcs = hdrs,
        visibility = visibility or ["//visibility:public"],
    )

def ddk_module(
        name,
        srcs = [],
        hdrs = [],
        out = None,
        kernel_build = None,
        deps = [],
        includes = [],
        copts = [],
        visibility = None,
        **kwargs):
    """Build an out-of-tree GKI kernel module.

    API-compatible with AOSP's ddk_module().  Invokes:
      make -C $KDIR M=<workspace>/<package> ARCH=arm64 LLVM=1 modules

    KDIR is read from bazel/kernel_build/kdir.txt (written by
    scripts/build/setup_bazel_ddk.sh).  The package source directory
    is discovered from native.package_name() and the workspace root is
    found by walking up from $(RULEDIR) until WORKSPACE.bazel is seen.

    Args:
        name:         Target name, also the module name.
        srcs:         Source files (used only as Bazel inputs; actual
                      source list comes from the package Kbuild file).
        hdrs:         Exported header targets (API compat).
        out:          Output .ko name (defaults to <name>.ko).
        kernel_build: Kernel build label (API compat with kleaf).
        deps:         Upstream ddk_module/ddk_headers targets.
        includes:     Include directories (API compat; set via Kbuild).
        copts:        Extra compiler flags (API compat; set via Kbuild).
        visibility:   Bazel visibility.
    """
    ko_name = out or (name + ".ko")
    pkg_path = native.package_name()  # e.g. "tests/kmod" or "kmod"

    # Collect genrule inputs: kdir_file + clangdir_file + upstream deps.
    genrule_srcs = [
        "//bazel/kernel_build:kdir_file",
        "//bazel/kernel_build:clangdir_file",
    ]
    for d in deps:
        genrule_srcs.append(d)

    # Build the shell command.  Uses RULEDIR (bazel-bin/<pkg>) to find
    # the workspace root by walking up until WORKSPACE.bazel is found.
    # This is robust across all bazel-out/<config>/bin/ path variations.
    cmd = (
        "set -euo pipefail\n" +
        # ---- Locate KDIR ----
        "KDIR=$$(cat $(location //bazel/kernel_build:kdir_file))\n" +
        "[ -f \"$$KDIR/Module.symvers\" ] || " +
        "{ echo 'ERROR: no Module.symvers in '\"$$KDIR\"; exit 1; }\n" +
        # ---- Use PATH from DDK container ----
        # The DDK container sets up PATH with the correct clang version for
        # both compilation (LLVM=1 → PATH clang) and llvm-nm (check-local-export).
        # We trust the container's PATH by prepending the detected DDK clang dir,
        # but fall back to unmodified PATH if no custom clang dir was detected.
        # Always use LLVM=1 (not LLVM=<dir>/) to let kbuild use PATH clang, which
        # the DDK container configures correctly for each KMI.
        "DDK_CLANG=$$(cat $(location //bazel/kernel_build:clangdir_file) 2>/dev/null | head -1 || true)\n" +
        "if [ -n \"$$DDK_CLANG\" ] && [ -d \"$$DDK_CLANG\" ]; then\n" +
        "    export PATH=\"$$DDK_CLANG:$$PATH\"\n" +
        "    echo \"ddk_module: prepended $$DDK_CLANG to PATH\"\n" +
        "fi\n" +
        "LLVM_ARG=\"LLVM=1\"\n" +
        # ---- Locate the real workspace root ----
        # With --genrule_strategy=local, $(RULEDIR) is inside Bazel's execroot
        # (e.g. /home/.cache/bazel/.../execroot/_main/bazel-out/.../bin/<pkg>).
        # The execroot has WORKSPACE.bazel as a SYMLINK to the real workspace.
        # Using realpath on that symlink gives the actual workspace root, so
        # make -C KDIR M=<real-pkg> works with real Kbuild files (not execroot copies).
        "EXECROOT_WS=$$(realpath \"$(RULEDIR)\" 2>/dev/null || " +
        "(cd \"$(RULEDIR)\" && pwd))\n" +
        "while [ ! -f \"$$EXECROOT_WS/WORKSPACE.bazel\" ] && " +
        "[ \"$$EXECROOT_WS\" != \"/\" ]; do\n" +
        "    EXECROOT_WS=$$(dirname \"$$EXECROOT_WS\")\n" +
        "done\n" +
        "[ -f \"$$EXECROOT_WS/WORKSPACE.bazel\" ] || " +
        "{ echo 'ERROR: could not find WORKSPACE.bazel'; exit 1; }\n" +
        # Resolve the WORKSPACE.bazel symlink to get the REAL workspace root
        "REAL_WS=$$(dirname $$(realpath \"$$EXECROOT_WS/WORKSPACE.bazel\"))\n" +
        "echo \"ddk_module: execroot=$$EXECROOT_WS real_ws=$$REAL_WS\"\n" +
        # ---- Package source directory (real path, not execroot) ----
        "PKG_DIR=\"$$REAL_WS/" + pkg_path + "\"\n" +
        "echo \"ddk_module: PKG_DIR=$$PKG_DIR\"\n" +
        # ---- Clean first (avoid stale .o from previous make invocations) ----
        "make -C \"$$KDIR\" M=\"$$PKG_DIR\" ARCH=arm64 LLVM=1 clean " +
        "2>/dev/null || true\n" +
        # ---- Build via make (same flags as Path A) ----
        "echo \"ddk_module: PATH=$$(echo $$PATH | tr : \\n | head -3 | tr \\n :)\"\n" +
        "echo \"ddk_module: clang=$$(which clang 2>/dev/null || echo not-found)\"\n" +
        "make -C \"$$KDIR\" M=\"$$PKG_DIR\" ARCH=arm64 LLVM=1 " +
        "KBUILD_MODPOST_WARN=1 modules -j$$(nproc)\n" +
        # ---- Copy output .ko ----
        "KO=\"$$PKG_DIR/" + ko_name + "\"\n" +
        "[ -f \"$$KO\" ] || " +
        "{ echo 'ERROR: " + ko_name + " not produced in '\"$$PKG_DIR\"; exit 1; }\n" +
        "cp \"$$KO\" \"$@\"\n" +
        "echo '==> Bazel ddk_module: " + ko_name + " done'\n"
    )

    native.genrule(
        name = name,
        srcs = genrule_srcs,
        outs = [ko_name],
        message = "DDK ddk_module: " + ko_name,
        cmd = cmd,
        visibility = visibility or ["//visibility:public"],
    )
