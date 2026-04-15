# KernelHook

面向 Linux 内核的 ARM64 函数 kh_hook 框架。

## 功能特性

- **内联 kh_hook** -- 替换任意内核函数，通过备份指针调用原函数
- **Hook 链** -- 同一函数上注册多个 before/after 回调，按优先级排序执行
- **函数指针 kh_hook** -- kh_hook ops 表中的回调函数，支持链式调用
- **系统调用级 kh_hook** -- `kh_hook_syscalln(nr, ...)` 通过 `__arm64_sys_<name>` 操作，处理 pt_regs 包装器 ABI；[用户指针辅助](docs/zh/api-reference.md#用户指针辅助)（`kh_strncpy_from_user`、`kh_copy_to_user_stack`）支持改写系统调用参数
- **Alias-page 写入通道** -- 主力 text-patch 机制（KernelPatch 风格）：vmalloc alias page + `aarch64_insn_patch_text_nosync`，绕过 `__ro_after_init` + kCFI；PTE 直改作为 fallback
- **RCU 安全调度** -- transit_body 在进入原函数前把链状态 snapshot 到栈；3 秒内 2780 万次 syscall × 67000 次 add/remove 并发压测零 Oops
- **符号解析** -- `ksyms_lookup` 运行时查找内核符号
- **三种构建模式** -- SDK（默认，共享 `kernelhook.ko`）、Freestanding（无需内核头文件，回退方案）、Kbuild（仅演示）
- **自适应加载器** -- `kmod_loader` 修补 .ko 二进制文件，实现跨内核版本加载
- **主打 demo** -- [`kh_root`](docs/zh/kh-root-demo.md)：通过 3 个 syscall kh_hook 实现完整提权（~350 LOC）

### 快速开始（SDK 模式）

```sh
# 构建 SDK 模块
make -C kmod module

# 构建示例消费者
make -C examples/hello_hook module

# 推送到 Magisk root 的 Android 设备并加载
adb push kmod/kernelhook.ko             /data/local/tmp/
adb push examples/hello_hook/hello_hook.ko /data/local/tmp/
adb push tools/kmod_loader/kmod_loader  /data/local/tmp/
adb shell su -c '/data/local/tmp/kmod_loader /data/local/tmp/kernelhook.ko'
adb shell su -c '/data/local/tmp/kmod_loader /data/local/tmp/hello_hook.ko'
adb shell su -c 'dmesg | tail -20'
```

> 需要自包含的 .ko（目标机器没有 `kernelhook.ko`）？使用 freestanding
> 回退方案：在任意示例目录中执行 `make -f Makefile.freestanding module`。

## 架构

| 组件 | 说明 |
|------|------|
| `src/arch/arm64/inline.c` | 指令重定位 + alias-page 和 PTE 直改两条写入路径 |
| `src/arch/arm64/transit.c` | 中转桩 + RCU-snapshot 回调分发 |
| `src/arch/arm64/pgtable.c` | 页表遍历 + TLB 刷新（vaale1is） |
| `src/platform/syscall.c` | 系统调用级 kh_hook 基础设施（`kh_hook_syscalln`、`kh_raw_syscallN`） |
| `src/uaccess.c` | 用户指针辅助（strncpy_from_user / copy_to_user / stack） |
| `src/kh_hook.c` | Hook 链 API（kh_hook/kh_unhook/kh_hook_wrap/kh_fp_hook_wrap） |
| `src/memory.c` | ROX/RW 内存池的位图分配器 |
| `kmod/` | SDK、链接脚本、shim 头文件 |
| `tools/kmod_loader/` | 自适应模块加载器 |
| `examples/` | hello_hook、fp_hook、hook_chain、hook_wrap_args、ksyms_lookup |
| `tests/kmod/test_phase6_kh_root.c` | 主打 kh_root demo（见[文档](docs/zh/kh-root-demo.md)） |

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
- [API 参考](docs/zh/api-reference.md) —— 包含系统调用 kh_hook + 用户指针辅助
- [kh_root Demo](docs/zh/kh-root-demo.md) —— 主打提权 demo
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

| 模式          | 默认？   | 说明                                               |
|---------------|----------|----------------------------------------------------|
| SDK           | **是**   | 所有消费者的推荐方式                               |
| Freestanding  | 否       | 目标机器没有 `kernelhook.ko` 时使用                |
| Kbuild        | 否       | 仅用于演示（`examples/kbuild_hello/`）             |

```bash
# SDK（默认）—— 依赖目标机器上已加载的 kernelhook.ko
cd examples/hello_hook && make module

# Freestanding —— 自包含 .ko（无需 kernelhook.ko）
cd examples/hello_hook && make -f Makefile.freestanding module

# Kbuild —— 标准 out-of-tree 构建（需要内核源码）
cd examples/hello_hook && make -C /path/to/kernel M=$(pwd)
```

## 贡献指南

源文件头约定（role 注释、build modes、depends on、notes 字段）见
[`docs/style/file-header.md`](docs/style/file-header.md)。公共 API
命名空间（所有导出符号/类型以 `kh_` 前缀）由 `scripts/lint_exports.sh`
把守——已接入 `scripts/test.sh sdk-consumer`。

## 许可证

GPL-2.0-or-later
