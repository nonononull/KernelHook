# bazel/kernel_build — GKI kernel Bazel repository

This directory is generated at build time by `scripts/build/setup_bazel_ddk.sh`.
Do not edit manually; changes here will be overwritten by the setup script.

## Contents (after setup)

```
bazel/kernel_build/
├── BUILD.bazel          # kernel_filegroup() target — generated
├── WORKSPACE            # empty, marks local_repository boundary
└── files -> /path/to/KDIR   # symlink to the kernel build dir in DDK container
```

## How to regenerate

Inside a DDK container with a valid `$KDIR`:

```bash
bash scripts/build/setup_bazel_ddk.sh "$KDIR"
```

The script writes `BUILD.bazel`, creates the `files/` symlink, and writes an
empty `WORKSPACE` so Bazel treats this as a local repository root.
