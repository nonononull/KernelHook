# KernelHook

> **WARNING / 警告**
>
> This project is under active exploration and development. APIs are unstable
> and may change without notice. **Do not use in production.**
>
> 本项目正处于探索开发阶段，接口不稳定，随时可能变更。**请勿用于生产环境。**

ARM64 function hooking framework for Linux kernels.

## Features

- **Inline hook** -- replace any kernel function, call original via backup pointer
- **Hook chain** -- multiple before/after callbacks on one function, priority-ordered
- **Function pointer hook** -- hook ops table callbacks with chain support
- **Symbol resolution** -- `ksyms_lookup` for runtime symbol lookup
- **Three build modes** -- Freestanding (no kernel headers), SDK (shared kernelhook.ko), Kbuild (standard)
- **Adaptive loader** -- `kmod_loader` patches .ko binaries for cross-kernel loading

## Quick Start

```bash
# Build the hello_hook example (Mode A, freestanding)
cd examples/hello_hook
make module

# Build the adaptive loader
cd ../../tools/kmod_loader
make

# Push to device
adb push kmod_loader hello_hook.ko /data/local/tmp/

# Load (loader auto-fetches kallsyms_lookup_name from /proc/kallsyms;
# pass kallsyms_addr=0xHEX to override)
adb shell "su -c '/data/local/tmp/kmod_loader /data/local/tmp/hello_hook.ko'"

# Verify
adb shell dmesg | grep hello_hook
```

## Architecture

| Component | Description |
|-----------|-------------|
| `src/arch/arm64/inline.c` | Instruction relocation engine + code patching |
| `src/arch/arm64/transit.c` | Transit stub + callback dispatch |
| `src/arch/arm64/pgtable.c` | Page table walking + PTE modification |
| `src/hook.c` | Hook chain API (hook/unhook/hook_wrap) |
| `src/memory.c` | Bitmap allocator for ROX/RW memory pools |
| `kmod/` | SDK, linker scripts, shim headers |
| `tools/kmod_loader/` | Adaptive module loader |
| `examples/` | hello_hook, fp_hook, hook_chain, hook_wrap_args, ksyms_lookup |

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
- [API Reference](docs/en/api-reference.md)
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

```bash
# Mode A (freestanding, no kernel headers)
cd examples/hello_hook && make module

# Mode B (SDK, depends on kernelhook.ko)
cd examples/hello_hook && make -f Makefile.sdk module

# Mode C (Kbuild, requires kernel source)
cd examples/hello_hook && make -C /path/to/kernel M=$(pwd) modules
```

## License

GPL-2.0-or-later
