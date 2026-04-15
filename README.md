# KernelHook

> **WARNING / 警告**
>
> This project is under active exploration and development. APIs are unstable
> and may change without notice. **Do not use in production.**
>
> 本项目正处于探索开发阶段，接口不稳定，随时可能变更。**请勿用于生产环境。**

ARM64 function hooking framework for Linux kernels.

## Features

- **Inline kh_hook** -- replace any kernel function, call original via backup pointer
- **Hook chain** -- multiple before/after callbacks on one function, priority-ordered
- **Function pointer kh_hook** -- kh_hook ops table callbacks with chain support
- **Syscall-level kh_hook** -- `kh_hook_syscalln(nr, ...)` over `__arm64_sys_<name>`, handles pt_regs wrapper ABI; [user-pointer helpers](docs/en/api-reference.md#user-pointer-helpers) (`kh_strncpy_from_user`, `kh_copy_to_user_stack`) for rewriting syscall arguments
- **Alias-page write path** -- primary text-patch mechanism via vmalloc alias + `aarch64_insn_patch_text_nosync` (KernelPatch-style), bypasses `__ro_after_init` + kCFI; PTE-direct fallback
- **RCU-safe dispatch** -- transit_body snapshots chain state onto stack before origin call; validated under 27.8M syscalls × 67K add/remove races in 3s
- **Symbol resolution** -- `ksyms_lookup` for runtime symbol lookup
- **Three build modes** -- SDK (default, shared `kernelhook.ko`), Freestanding (no kernel headers, fallback), Kbuild (demo only)
- **Adaptive loader** -- `kmod_loader` patches .ko binaries for cross-kernel loading
- **Featured demo** -- [`kh_root`](docs/en/kh-root-demo.md): full privilege-escalation via 3 syscall hooks (~350 LOC)

### Quick Start (SDK mode)

```sh
# Build the SDK module
make -C kmod module

# Build an example consumer
make -C examples/hello_hook module

# Push + load on an Android device with Magisk root
adb push kmod/kernelhook.ko             /data/local/tmp/
adb push examples/hello_hook/hello_hook.ko /data/local/tmp/
adb push tools/kmod_loader/kmod_loader  /data/local/tmp/
adb shell su -c '/data/local/tmp/kmod_loader /data/local/tmp/kernelhook.ko'
adb shell su -c '/data/local/tmp/kmod_loader /data/local/tmp/hello_hook.ko'
adb shell su -c 'dmesg | tail -20'
```

> Need a self-contained .ko (no `kernelhook.ko` on target)? Use the
> freestanding fallback: `make -f Makefile.freestanding module` in any
> example directory.

## Architecture

| Component | Description |
|-----------|-------------|
| `src/arch/arm64/inline.c` | Instruction relocation + alias-page & PTE-direct write paths |
| `src/arch/arm64/transit.c` | Transit stub + RCU-snapshot callback dispatch |
| `src/arch/arm64/pgtable.c` | Page table walking + TLB flush (vaale1is) |
| `src/platform/syscall.c` | Syscall-level kh_hook infrastructure (`kh_hook_syscalln`, `kh_raw_syscallN`) |
| `src/uaccess.c` | User pointer helpers (strncpy_from_user / copy_to_user / stack) |
| `src/kh_hook.c` | Hook chain API (kh_hook/kh_unhook/kh_hook_wrap/kh_fp_hook_wrap) |
| `src/memory.c` | Bitmap allocator for ROX/RW memory pools |
| `kmod/` | SDK, linker scripts, shim headers |
| `tools/kmod_loader/` | Adaptive module loader |
| `examples/` | hello_hook, fp_hook, hook_chain, hook_wrap_args, ksyms_lookup |
| `tests/kmod/test_phase6_kh_root.c` | Featured kh_root demo (see [docs](docs/en/kh-root-demo.md)) |

## Kernel Compatibility

Verified on Android AVD emulators and USB devices (ARM64):

| Kernel | Android | API | Status | Notes |
|--------|---------|-----|--------|-------|
| 4.4    | 9       | 28  | Verified | `-mcmodel=large` for MOVZ/MOVK relocations |
| 4.14   | 10      | 29  | Verified | CRC fallback via `__ksymtab_` lookup |
| 5.4    | 11      | 30  | Verified | shadow-CFI + `_error_injection_whitelist` fix |
| 5.10   | 12/12L  | 31-32 | Verified | shadow-CFI + KABI_RESERVE |
| 5.15   | 13      | 33  | Verified | shadow-CFI, no KABI |
| 6.1    | 14      | 34  | Verified | kCFI replaces shadow CFI; Pixel USB device verified |
| 6.6    | 15/16   | 35-36 | Verified | |
| 6.12   | 16      | 36.1-37 | Verified | 16K page support |

Physical devices may have different `struct module` layouts than GKI AVDs.
The `kmod_loader` auto-detects the correct layout by introspecting vendor `.ko` files on the device.

## Documentation

- [Getting Started](docs/en/getting-started.md)
- [Build Modes](docs/en/build-modes.md)
- [API Reference](docs/en/api-reference.md) — includes syscall hooks + user-pointer helpers
- [kh_root Demo](docs/en/kh-root-demo.md) — featured privilege-escalation demo
- [kmod_loader](docs/en/kmod-loader.md)
- [AVD Testing](docs/en/avd-testing.md)
- [Examples](docs/en/examples.md)

[中文文档](README_zh.md)

## Build & Test

### Userspace Tests (macOS / Android)

```bash
# macOS (Apple Silicon)
cmake -B build_debug -DCMAKE_BUILD_TYPE=Debug
cmake --build build_debug
cd build_debug && ctest

# Android (cross-compile) — runs on any connected device or emulator.
# On userdebug emulators the runner auto-issues `adb root` + `setenforce 0`
# so tests can mprotect RW→RX. On USB devices it uses magisk `su -c`.
cmake -B build_android -DCMAKE_TOOLCHAIN_FILE=cmake/android-arm64.cmake -DCMAKE_BUILD_TYPE=Debug
cmake --build build_android
./scripts/run_android_tests.sh              # auto-detect; or --serial emulator-5554
```

### Kernel Module Tests

```bash
# Run kmod tests on all available AVD emulators
./scripts/test_avd_kmod.sh

# Test specific AVDs
./scripts/test_avd_kmod.sh Pixel_31 Pixel_37

# Manual single-device kmod test (USB / magisk only — emulators should
# use test_avd_kmod.sh, which handles adb-root pathways correctly)
./scripts/run_android_tests.sh --kmod
```

### Build Modes

| Mode          | Default? | Notes                                              |
|---------------|----------|----------------------------------------------------|
| SDK           | **yes**  | Recommended path for all consumers                 |
| Freestanding  | no       | Use when target has no `kernelhook.ko`             |
| Kbuild        | no       | Demo-only (`examples/kbuild_hello/`)               |

```bash
# SDK (default) — depends on kernelhook.ko loaded on target
cd examples/hello_hook && make module

# Freestanding — self-contained .ko (no kernelhook.ko required)
cd examples/hello_hook && make -f Makefile.freestanding module

# Kbuild — standard out-of-tree build (requires kernel source)
cd examples/hello_hook && make -C /path/to/kernel M=$(pwd)
```

## Contributing

Source-file header conventions (role comment, build modes, depends-on,
notes) are documented in [`docs/style/file-header.md`](docs/style/file-header.md).
Public API namespace (`kh_` prefix for every exported symbol + type) is
enforced by `scripts/lint_exports.sh` — wired into `scripts/test.sh sdk-consumer`.

## License

GPL-2.0-or-later
