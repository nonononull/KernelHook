# scripts/build — KernelHook kbuild scripts

Scripts for building out-of-tree GKI kernel modules, either locally or in CI.

## Overview

KernelHook supports two build paths:

| Path | When to use | Host requirement |
|------|-------------|-----------------|
| **Freestanding** (Mode A/B) | AVD testing, cross-kernel deployment | NDK only, any OS |
| **Kbuild** (Mode C) | Standard kernel module build | Docker (local), or CI |

The scripts in this directory cover the kbuild path.

## Local builds with Docker

`build_with_docker.sh` runs the same DDK containers used by CI, so local and
CI builds are byte-for-byte identical.

**Prerequisites:** Docker (or Podman) installed and in `PATH`.

```bash
# Build kh_test.ko against Android 14 / GKI 6.1
bash scripts/build/build_with_docker.sh android14-6.1

# Build for multiple branches
for branch in android13-5.15 android14-6.1 android15-6.6; do
    bash scripts/build/build_with_docker.sh $branch
done

# Build kernelhook.ko + its SDK consumer on GKI 6.1
bash scripts/build/build_with_docker.sh android14-6.1 kernelhook kbuild_hello

# Custom container registry (e.g., your own mirror)
DDK_IMAGE_BASE=myregistry.example.com/ddk-min \
    bash scripts/build/build_with_docker.sh android14-6.1
```

Output goes to `build/output/<branch>/`. The first run downloads the DDK image
(~500 MB per branch); subsequent runs use the cached image.

### Supported branches

| Branch | Kernel |
|--------|--------|
| `android12-5.10` | GKI 5.10 |
| `android13-5.15` | GKI 5.15 |
| `android14-6.1`  | GKI 6.1  |
| `android15-6.6`  | GKI 6.6  |
| `android16-6.12` | GKI 6.12 |

### Supported module targets

| Target | Path | Output |
|--------|------|--------|
| `kh_test` (default) | `tests/kmod/` | `kh_test.ko` |
| `kernelhook` | `kmod/` | `kernelhook.ko` + `Module.symvers` |
| `kbuild_hello` | `examples/kbuild_hello/` | `kbuild_hello.ko` |

`kbuild_hello` requires `kernelhook` to be built first (needs `kmod/Module.symvers`).

## CI entry point

`ci_kbuild.sh` is called by `.github/workflows/kbuild.yml` after the container
starts. It receives the branch name and an already-populated `KERNEL_OUT`
(the DDK container's pre-built kernel directory), then builds all modules and
runs `scripts/ci/verify_kmod.sh`.

Contributors who want to reproduce a CI failure locally should use
`build_with_docker.sh` instead — it sets up the same environment automatically.

## Linux host without Docker

`setup_kbuild_env.sh` sets up a full kernel source tree for contributors on
Linux who want to build without Docker (e.g., in a bare-metal CI environment
or an existing kernel development VM). It clones `android.googlesource.com/kernel/common`,
runs `gki_defconfig`, and builds `vmlinux` to produce `Module.symvers`.

After setup:

```bash
KERNEL_DIR=/tmp/linux KERNEL_OUT=/tmp/linux-out BRANCH=android14-6.1 \
    bash scripts/build/setup_kbuild_env.sh

KERNEL_OUT=/tmp/linux-out \
    bash scripts/build/ci_kbuild.sh android14-6.1
```

This path requires ~10 GB disk (kernel clone + build) and 30–60 min on first
run. The Docker path is recommended for most contributors.

## Bazel DDK build (ddk_module — Phase 3)

In addition to the Docker-based `make` path, KernelHook supports building
via AOSP's `ddk_module()` Bazel rule (kleaf). This gives native Bazel
dependency tracking, incremental builds, and a `bazel build //kmod:kernelhook`
interface.

**Prerequisites:** Docker + a running DDK container, or direct access to a
kernel build directory (Linux only).

```bash
# Inside the DDK container, after finding KDIR:
bash scripts/build/setup_bazel_ddk.sh "$KDIR"

# Then build any module:
bazel build //kmod:kernelhook
bazel build //tests/kmod:kh_test
bazel build //examples/kbuild_hello:kbuild_hello
```

`setup_bazel_ddk.sh` installs Bazelisk (if absent), creates the
`bazel/kernel_build/files` symlink pointing to KDIR, generates the
`BUILD.bazel` for the `@gki_kernel//:kernel_build` target, and warms
the kleaf download cache.

The Bazel build is **experimental** (Phase 3). The `make` path remains
the authoritative CI gate. Bazel steps run with `continue-on-error: true`
until the integration is fully validated across all five GKI branches.

## Troubleshooting

**Docker pull fails:** Check your network connection and the image name. The
registry is `ghcr.io/ylarod/ddk-min`. If your corporate firewall blocks ghcr,
mirror the image to your own registry and set `DDK_IMAGE_BASE`.

**`Module.symvers` not found inside container:** The DDK container layout is
discovered dynamically via a `find /` scan. Open an issue if a new container
version moves the file to a new location.

**kbuild_hello fails with "missing Module.symvers":** Build `kernelhook` first:
`bash scripts/build/build_with_docker.sh android14-6.1 kernelhook`
