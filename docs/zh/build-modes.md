# 构建模式

KernelHook 为内核模块提供三种构建模式，根据实际需求选择。

## 对比

| | 模式 A（Freestanding） | 模式 B（SDK） | 模式 C（Kbuild） |
|---|---|---|---|
| 内核头文件 | 不需要 | 不需要 | 需要 |
| kernelhook.ko | 不需要 | 必须先加载 | 可选 |
| 核心库编入 .ko | 是 | 否（运行时链接） | 可选 |
| 加载方式 | insmod / kmod_loader | insmod / kmod_loader | insmod |
| .ko 体积 | 较大（~200KB） | 较小（~10KB） | 取决于配置 |
| 适用场景 | 单模块部署 | 多模块部署 | 标准内核开发 |

## 模式 A -- Freestanding

无需内核头文件。使用 `shim.h` 作为最小化的内核头文件替代。核心 hook 库直接编译进你的 `.ko` 中。

### 构建

```bash
cd examples/hello_hook
make module
```

Makefile 中 include 了 `kmod/mk/kmod.mk`，自动处理交叉编译、链接脚本和 shim 层。

### Makefile 模板

```makefile
MODULE_NAME  := my_hook
MODULE_SRCS  := my_hook.c
KERNELHOOK_DIR := /path/to/KernelHook/kmod
include $(KERNELHOOK_DIR)/mk/kmod.mk
```

### 源码 include

```c
#include "../../kmod/shim/shim.h"
#include <ktypes.h>
#include <hook.h>
#include <ksyms.h>
#include <log.h>
#include <hmem.h>
#include <arch/arm64/pgtable.h>
#include "../../kmod/src/compat.h"
#include "../../kmod/src/mem_ops.h"
```

### 初始化流程

模式 A 的模块需要手动初始化各子系统：

```c
static int __init my_hook_init(void)
{
    int rc;

    rc = kmod_compat_init(kallsyms_addr);    /* 符号解析 */
    if (rc) return rc;

    rc = kmod_hook_mem_init();               /* 内存池 */
    if (rc) return rc;

    rc = pgtable_init();                     /* 页表操作 */
    if (rc) { kmod_hook_mem_cleanup(); return rc; }

    extern void kh_write_insts_init(void);
    kh_write_insts_init();                   /* 代码修补 */

    /* ... 安装 hook ... */
    return 0;
}
```

### 加载

CRC/vermagic 匹配时用 `insmod`，不匹配时用 `kmod_loader` 实现跨内核加载：

```bash
kmod_loader my_hook.ko    # 自动从 /proc/kallsyms 获取 kallsyms_addr
```

## 模式 B -- SDK

依赖预先加载的 `kernelhook.ko`。你的模块在运行时链接导出符号，生成的 `.ko` 体积小很多。

### 构建

```bash
cd examples/hello_hook
make -f Makefile.sdk module
```

使用 `kmod/mk/kmod_sdk.mk`，自动定义 `-DKH_SDK_MODE`。

### Makefile 模板

```makefile
MODULE_NAME  := my_hook
MODULE_SRCS  := my_hook.c
KERNELHOOK_DIR := /path/to/KernelHook/kmod
include $(KERNELHOOK_DIR)/mk/kmod_sdk.mk
```

### 源码 include

```c
#include <kernelhook/hook.h>
#include <kernelhook/types.h>
#include <kernelhook/kh_symvers.h>   /* 自动生成，提供 KH_DECLARE_VERSIONS() */
```

### 模块元数据

消费者 `.ko` 的主翻译单元（与 `module_init` 同一个 `.c` 文件）需要同时
声明内核符号和 KernelHook 符号的版本信息：

```c
MODULE_VERSIONS();       /* 内核符号 (module_layout / _printk / memcpy / memset) */
KH_DECLARE_VERSIONS();   /* KernelHook 导出符号 (hook_wrap / ksyms_lookup / ...) */
MODULE_VERMAGIC();
MODULE_THIS_MODULE();
```

`KH_DECLARE_VERSIONS()` 来自自动生成的 `<kernelhook/kh_symvers.h>`，由
`tools/kh_crc` 从 `kmod/exports.manifest` 生成。所有 KernelHook 符号的
CRC 按契约 4（Contract 4）冻结，`kernelhook.ko` 升级不会破坏已编译的
消费者 `.ko`——只要某个符号的 manifest 条目不变，它的 CRC 就永远不变。

### 初始化流程

无需初始化子系统，`kernelhook.ko` 已经处理好了：

```c
static int __init my_hook_init(void)
{
    void *target = (void *)ksyms_lookup("do_sys_openat2");
    hook_err_t err = hook_wrap4(target, my_before, my_after, NULL);
    /* ... */
    return 0;
}
```

### 加载

先加载 `kernelhook.ko`，再加载你的模块：

```bash
insmod kernelhook.ko kallsyms_addr=0x...
insmod my_hook.ko
```

## 模式 C -- Kbuild

基于真实 Linux 内核源码树的标准 out-of-tree 模块构建方式。与模式 A 不同的
是：每个 `.ko` 都绑定到一个确切的内核版本（CRC + vermagic 必须匹配），作为
代价换来"零运行时补丁"的干净方案。

权威可运行参考（`.github/workflows/kbuild.yml` 在 GKI 6.1 上 CI 验证）：

- [`kmod/Kbuild`](../../kmod/Kbuild) — 构建 `kernelhook.ko` + `Module.symvers`
- [`examples/kbuild_hello/`](../../examples/kbuild_hello/) — 通过
  `KBUILD_EXTRA_SYMBOLS` 链接上述导出的 SDK 消费者示例
- [`examples/hello_hook/Kbuild`](../../examples/hello_hook/Kbuild) —
  对照：把 core library 静态链进消费者自身 `.ko` 的另一种风格

### 前置条件

- 执行过 `modules_prepare` 的 Linux kernel 源码树。
- 若加载 `kernelhook.ko` 时不传 `kallsyms_addr=` 参数，目标 kernel 必须
  开启 `CONFIG_KPROBES=y` — `kmod_compat_init()` 会在加载时用 kprobes
  fallback 解析 `kallsyms_lookup_name`。

### 构建 `kernelhook.ko`

```bash
make -C /path/to/kernel ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- \
     M=$(pwd)/kmod modules
```

产出：

- `kmod/kernelhook.ko`
- `kmod/Module.symvers` — 通过真实 `EXPORT_SYMBOL()` 承载
  `kmod/exports.manifest` 里的 17 个 SDK 导出（由 `kmod/src/export.c` 的
  `KH_EXPORT` 宏分派）。

### 通过 `KBUILD_EXTRA_SYMBOLS` 构建消费者模块

完整示例见 [`examples/kbuild_hello/`](../../examples/kbuild_hello/)。
Kbuild 关键接线：

```makefile
obj-m := my_hook.o
my_hook-y := my_hook_main.o

ccflags-y := \
    -I$(KERNELHOOK)/include \
    -I$(KERNELHOOK)/include/arch/arm64 \
    -I$(KERNELHOOK)/kmod/include

KBUILD_EXTRA_SYMBOLS := $(KERNELHOOK)/kmod/Module.symvers
```

在 `kernelhook.ko` 产出之后构建：

```bash
make -C /path/to/kernel ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- \
     M=$(pwd)/examples/kbuild_hello \
     KBUILD_EXTRA_SYMBOLS=$(pwd)/kmod/Module.symvers modules
```

验证依赖关系生效：

```bash
modinfo examples/kbuild_hello/kbuild_hello.ko | grep depends
# -> depends: kernelhook
```

### 加载

```bash
insmod kernelhook.ko                 # 或 kallsyms_addr=0x...（无 kprobes 场景）
insmod kbuild_hello.ko
```

### 重要兼容性说明

Mode C 的 `kernelhook.ko` 使用的是真实 kernel 生成的 CRC，**不能**与
Mode A（freestanding）消费者 `.ko` 互相混用，反之亦然 — 两套 CRC 空间
相互独立。每次部署只选一种模式。

## 主机平台支持

KernelHook 支持在 macOS 和 Linux 主机上构建。构建系统按以下决策顺序自动检测交叉编译器（第一个匹配项优先）：

1. **用户覆盖** — 若设置了 `CC`+`LD` 或 `CROSS_COMPILE`，直接使用，无需修改任何文件即可接入自定义工具链。
2. **Android NDK** — 依次在以下位置查找：`$ANDROID_NDK_ROOT`、`$ANDROID_NDK_HOME`、`$ANDROID_SDK_ROOT/ndk/<ver>`，以及平台默认路径（macOS 为 `~/Library/Android/sdk/ndk/<ver>`，Linux 为 `~/Android/Sdk/ndk/<ver>`）。选取已安装的最高版本 NDK。API level 自动从 NDK sysroot 中检测最大支持值；如需指定，可通过 `$ANDROID_API_LEVEL` 覆盖。
3. **系统交叉编译器** — `aarch64-linux-gnu-gcc`，或带 `ld.lld` 的 `clang --target=aarch64-linux-gnu`。此回退方式只能生成 glibc-ABI 二进制，对于 freestanding `.ko` 模块和 probe.ko **是安全的**，但**不适用**于 Android 用户空间二进制（如 `tests/userspace/test_android.c` 等），后者需要 bionic ABI。
4. **报错** — 以上均不满足时，构建中止，并列出可设置的环境变量供参考。

每次构建都会向 stderr 打印一行 `[toolchain] using <kind>: ...`，说明实际使用的编译器。回退原因也会一并记录。

### 环境变量

| 变量 | 用途 |
|---|---|
| `CC`, `LD` | 显式指定编译器/链接器路径（最高优先级） |
| `CROSS_COMPILE` | 工具链前缀，例如 `aarch64-linux-gnu-` |
| `ANDROID_NDK_ROOT` | NDK 的直接路径 |
| `ANDROID_NDK_HOME` | `ANDROID_NDK_ROOT` 的旧版别名 |
| `ANDROID_SDK_ROOT` | SDK 根目录；NDK 通过 `$SDK/ndk/<ver>` 解析 |
| `ANDROID_HOME` | `ANDROID_SDK_ROOT` 的旧版别名 |
| `ANDROID_API_LEVEL` | 覆盖自动检测的 API level |

### Linux 主机示例

在 `~/Android/Sdk/ndk/<ver>`（Android Studio 默认路径）下安装 NDK 后，无需其他配置：

```bash
./scripts/run_android_tests.sh   # 自动检测 NDK
```

或者，在没有 NDK 的情况下使用系统交叉编译器进行 freestanding 构建：

```bash
sudo apt install gcc-aarch64-linux-gnu
make -C examples/hello_hook KDIR=/path/to/linux-headers-arm64
```

Android 用户空间测试仍然需要 NDK——若只有系统 cross-gcc，会立即报错并给出明确提示。
