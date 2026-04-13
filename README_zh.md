# KernelHook

面向 Linux 内核的 ARM64 函数 hook 框架。

## 功能特性

- **内联 hook** -- 替换任意内核函数，通过备份指针调用原函数
- **Hook 链** -- 同一函数上注册多个 before/after 回调，按优先级排序执行
- **函数指针 hook** -- hook ops 表中的回调函数，支持链式调用
- **符号解析** -- `ksyms_lookup` 运行时查找内核符号
- **三种构建模式** -- Freestanding（无需内核头文件）、SDK（共享 kernelhook.ko）、Kbuild（标准方式）
- **自适应加载器** -- `kmod_loader` 修补 .ko 二进制文件，实现跨内核版本加载

## 快速开始

```bash
# 构建 hello_hook 示例（模式 A，freestanding）
cd examples/hello_hook
make module

# 构建自适应加载器
cd ../../tools/kmod_loader
make

# 推送到设备
adb push kmod_loader hello_hook.ko /data/local/tmp/

# 加载（loader 会自动从 /proc/kallsyms 读取 kallsyms_lookup_name；
# 如需手动指定可追加 kallsyms_addr=0xHEX）
adb shell "su -c '/data/local/tmp/kmod_loader /data/local/tmp/hello_hook.ko'"

# 验证
adb shell dmesg | grep hello_hook
```

## 架构

| 组件 | 说明 |
|------|------|
| `src/arch/arm64/inline.c` | 指令重定位引擎 + 代码修补 |
| `src/arch/arm64/transit.c` | 中转桩 + 回调分发 |
| `src/arch/arm64/pgtable.c` | 页表遍历 + PTE 修改 |
| `src/hook.c` | Hook 链 API（hook/unhook/hook_wrap） |
| `src/memory.c` | ROX/RW 内存池的位图分配器 |
| `kmod/` | SDK、链接脚本、shim 头文件 |
| `tools/kmod_loader/` | 自适应模块加载器 |
| `examples/` | hello_hook、fp_hook、hook_chain、hook_wrap_args、ksyms_lookup |

## 内核兼容性

已在 Android AVD 模拟器和 USB 物理设备 (ARM64) 上验证：

| 内核版本 | Android | API | 状态 | 备注 |
|---------|---------|-----|------|------|
| 4.4     | 9       | 28  | 已验证 | `-mcmodel=large` 生成 MOVZ/MOVK 重定位 |
| 4.14    | 10      | 29  | 已验证 | CRC 通过 `__ksymtab_` 回退提取 |
| 5.4     | 11      | 30  | 已验证 | shadow-CFI + `_error_injection_whitelist` 修复 |
| 5.10    | 12/12L  | 31-32 | 已验证 | shadow-CFI + KABI_RESERVE |
| 5.15    | 13      | 33  | 已验证 | shadow-CFI，无 KABI |
| 6.1     | 14      | 34  | 已验证 | kCFI 取代 shadow CFI；Pixel USB 设备已验证 |
| 6.6     | 15/16   | 35-36 | 已验证 | |
| 6.12    | 16      | 36.1-37 | 已验证 | 16K 页面支持 |

物理设备的 `struct module` 布局可能与 GKI AVD 不同。
`kmod_loader` 通过解析设备上的 vendor `.ko` 文件自动检测正确的布局。

## 文档

- [快速上手](docs/zh/getting-started.md)
- [构建模式](docs/zh/build-modes.md)
- [API 参考](docs/zh/api-reference.md)
- [kmod_loader](docs/zh/kmod-loader.md)
- [AVD 测试](docs/zh/avd-testing.md)
- [示例](docs/zh/examples.md)

[English](README.md)

## 构建与测试

### 用户态测试（macOS / Android）

```bash
# macOS（Apple Silicon）
cmake -B build_debug -DCMAKE_BUILD_TYPE=Debug
cmake --build build_debug
cd build_debug && ctest

# Android（交叉编译）— 自动适配真机或模拟器。
# 在 userdebug 模拟器上 runner 会自动 `adb root` + `setenforce 0`，
# 让测试能 mprotect RW→RX；在 USB 真机上则使用 magisk `su -c`。
cmake -B build_android -DCMAKE_TOOLCHAIN_FILE=cmake/android-arm64.cmake -DCMAKE_BUILD_TYPE=Debug
cmake --build build_android
./scripts/run_android_tests.sh              # 自动探测；或加 --serial emulator-5554
```

### 内核模块测试

```bash
# 在所有可用的 AVD 模拟器上运行 kmod 测试
./scripts/test_avd_kmod.sh

# 测试指定 AVD
./scripts/test_avd_kmod.sh Pixel_31 Pixel_37

# 手动单设备 kmod 测试（仅 USB / magisk 设备 — 模拟器请用
# test_avd_kmod.sh，它正确处理 adb-root 路径）
./scripts/run_android_tests.sh --kmod
```

### 构建模式

```bash
# 模式 A（freestanding，无需内核头文件）
cd examples/hello_hook && make module

# 模式 B（SDK，依赖 kernelhook.ko）
cd examples/hello_hook && make -f Makefile.sdk module

# 模式 C（Kbuild，需要内核源码）
cd examples/hello_hook && make -C /path/to/kernel M=$(pwd) modules
```

## 许可证

GPL-2.0-or-later
