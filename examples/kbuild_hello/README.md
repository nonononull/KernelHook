# kbuild_hello — Mode C SDK consumer example

[中文](#中文) | [English](#english)

---

## English

A minimal KernelHook consumer `.ko` that imports the 17 SDK symbols from an
externally built `kernelhook.ko` via `KBUILD_EXTRA_SYMBOLS`. It hooks
`vfs_open` and logs every file open.

This is the authoritative working reference for **Mode C SDK** (see
[`docs/en/build-modes.md`](../../docs/en/build-modes.md)). Unlike
[`examples/hello_hook/`](../hello_hook/) which statically links the core
library into its own `.ko`, `kbuild_hello` only links against the exported
SDK symbols — `kernelhook.ko` must be loaded first at runtime.

### Prerequisites

- A Linux kernel source tree with `modules_prepare` run.
- `CONFIG_KPROBES=y` in the running kernel if you load `kernelhook.ko`
  without passing `kallsyms_addr=` (the compat init uses a kprobes
  fallback to resolve `kallsyms_lookup_name`).
- For cross-compiling to arm64: `aarch64-linux-gnu-` (or NDK) toolchain.

### Build

Step 1 — build `kernelhook.ko` first (produces `kmod/Module.symvers`):

```sh
cd $KERNELHOOK_REPO
make -C $KERNEL_SRC ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- \
     M=$(pwd)/kmod modules
```

Step 2 — build this consumer against those exports:

```sh
make -C $KERNEL_SRC ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- \
     M=$(pwd)/examples/kbuild_hello \
     KBUILD_EXTRA_SYMBOLS=$(pwd)/kmod/Module.symvers modules
```

Or use the wrapper Makefile:

```sh
cd examples/kbuild_hello
make KERNEL_SRC=/path/to/kernel ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu-
```

### Load

```sh
insmod kernelhook.ko                 # or: insmod kernelhook.ko kallsyms_addr=0x<addr>
insmod kbuild_hello.ko
dmesg | tail                         # -> "kbuild_hello: hooked vfs_open ..."
```

### Verify the dependency

```sh
modinfo kbuild_hello.ko | grep depends   # -> depends: kernelhook
```

---

## 中文

最小的 KernelHook 消费者 `.ko` 示例，通过 `KBUILD_EXTRA_SYMBOLS` 从外部构建
的 `kernelhook.ko` 导入 17 个 SDK 符号。Hook `vfs_open`，每次打开文件都
记录一条日志。

这是 **Mode C SDK** 的权威可运行参考（见
[`docs/zh/build-modes.md`](../../docs/zh/build-modes.md)）。与
[`examples/hello_hook/`](../hello_hook/) 把 core library 静态链进自身 `.ko`
不同，`kbuild_hello` 只链接导出的 SDK 符号——运行时必须先加载
`kernelhook.ko`。

### 前置条件

- 已执行过 `modules_prepare` 的 Linux kernel 源码树。
- 如果加载 `kernelhook.ko` 时不带 `kallsyms_addr=` 参数，运行的 kernel 必须
  开启 `CONFIG_KPROBES=y`（compat init 会走 kprobes fallback 来解析
  `kallsyms_lookup_name`）。
- arm64 交叉编译：`aarch64-linux-gnu-`（或 NDK）工具链。

### 构建

第 1 步——先构建 `kernelhook.ko`（生成 `kmod/Module.symvers`）：

```sh
cd $KERNELHOOK_REPO
make -C $KERNEL_SRC ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- \
     M=$(pwd)/kmod modules
```

第 2 步——基于这些导出符号构建消费者：

```sh
make -C $KERNEL_SRC ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- \
     M=$(pwd)/examples/kbuild_hello \
     KBUILD_EXTRA_SYMBOLS=$(pwd)/kmod/Module.symvers modules
```

或使用 wrapper Makefile：

```sh
cd examples/kbuild_hello
make KERNEL_SRC=/path/to/kernel ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu-
```

### 加载

```sh
insmod kernelhook.ko
insmod kbuild_hello.ko
dmesg | tail
```

### 验证依赖关系

```sh
modinfo kbuild_hello.ko | grep depends   # -> depends: kernelhook
```
