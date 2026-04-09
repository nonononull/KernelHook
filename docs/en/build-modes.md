# Build Modes

KernelHook supports three build modes for kernel modules. Choose based on your constraints.

## Comparison

| | Mode A (Freestanding) | Mode B (SDK) | Mode C (Kbuild) |
|---|---|---|---|
| Kernel headers | Not needed | Not needed | Required |
| kernelhook.ko | Not needed | Must load first | Optional |
| Core lib in .ko | Yes (compiled in) | No (linked at runtime) | Optional |
| Load method | insmod / kmod_loader | insmod / kmod_loader | insmod |
| .ko size | Large (~200KB) | Small (~10KB) | Depends |
| Best for | Single-module deployment | Multi-module deployment | Standard kernel dev |

## Mode A -- Freestanding

No kernel headers required. Uses `shim.h` as a minimal kernel header replacement. The core hooking library is compiled directly into your `.ko`.

### Build

```bash
cd examples/hello_hook
make module
```

The Makefile includes `kmod/mk/kmod.mk`, which handles cross-compilation, linker scripts, and the shim layer automatically.

### Makefile Template

```makefile
MODULE_NAME  := my_hook
MODULE_SRCS  := my_hook.c
KERNELHOOK_DIR := /path/to/KernelHook/kmod
include $(KERNELHOOK_DIR)/mk/kmod.mk
```

### Source Includes

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

### Init Sequence

Mode A modules must initialize the subsystems manually:

```c
static int __init my_hook_init(void)
{
    int rc;

    rc = kmod_compat_init(kallsyms_addr);    /* symbol resolution */
    if (rc) return rc;

    rc = kmod_hook_mem_init();               /* memory pools */
    if (rc) return rc;

    rc = pgtable_init();                     /* page table ops */
    if (rc) { kmod_hook_mem_cleanup(); return rc; }

    extern void kh_write_insts_init(void);
    kh_write_insts_init();                   /* code patching */

    /* ... install hooks ... */
    return 0;
}
```

### Loading

Use `insmod` if CRC/vermagic matches, or `kmod_loader` for cross-kernel compatibility:

```bash
kmod_loader my_hook.ko    # auto-fetches kallsyms_addr from /proc/kallsyms
```

## Mode B -- SDK

Depends on `kernelhook.ko` being loaded first. Your module links against the exported symbols at runtime, resulting in a much smaller `.ko`.

### Build

```bash
cd examples/hello_hook
make -f Makefile.sdk module
```

Uses `kmod/mk/kmod_sdk.mk`. Defines `-DKH_SDK_MODE` automatically.

### Makefile Template

```makefile
MODULE_NAME  := my_hook
MODULE_SRCS  := my_hook.c
KERNELHOOK_DIR := /path/to/KernelHook/kmod
include $(KERNELHOOK_DIR)/mk/kmod_sdk.mk
```

### Source Includes

```c
#include <kernelhook/hook.h>
#include <kernelhook/types.h>
#include <kernelhook/kh_symvers.h>   /* auto-generated, provides KH_DECLARE_VERSIONS() */
```

### Module Metadata

The consumer `.ko`'s main translation unit (the same `.c` file that carries
`module_init`) must declare version info for both kernel and KernelHook
symbols:

```c
MODULE_VERSIONS();       /* kernel symbols (module_layout / _printk / memcpy / memset) */
KH_DECLARE_VERSIONS();   /* KernelHook exports (hook_wrap / ksyms_lookup / ...) */
MODULE_VERMAGIC();
MODULE_THIS_MODULE();
```

`KH_DECLARE_VERSIONS()` comes from the auto-generated
`<kernelhook/kh_symvers.h>`, produced by `tools/kh_crc` out of
`kmod/exports.manifest`. Every KernelHook symbol's CRC is frozen under
Contract 4: upgrading `kernelhook.ko` will never break an already-built
consumer `.ko`, as long as the symbol's manifest entry stays unchanged the
CRC stays unchanged.

### Init Sequence

No subsystem init needed -- `kernelhook.ko` handles it:

```c
static int __init my_hook_init(void)
{
    void *target = (void *)ksyms_lookup("do_sys_openat2");
    hook_err_t err = hook_wrap4(target, my_before, my_after, NULL);
    /* ... */
    return 0;
}
```

### Loading

Load `kernelhook.ko` first, then your module:

```bash
insmod kernelhook.ko kallsyms_addr=0x...
insmod my_hook.ko
```

## Mode C -- Kbuild

Standard Linux kernel module build. Requires kernel source tree or pre-built headers.

### Build

```bash
make -C /path/to/kernel M=$(pwd) modules
```

### Kbuild Template

```makefile
# Kbuild
KH_ROOT := /path/to/KernelHook

obj-m := my_hook.o
my_hook-y := my_hook_main.o \
    $(KH_ROOT)/src/hook.o \
    $(KH_ROOT)/src/hmem.o \
    $(KH_ROOT)/src/ksyms.o \
    $(KH_ROOT)/src/arch/arm64/inline.o \
    $(KH_ROOT)/src/arch/arm64/transit.o \
    $(KH_ROOT)/src/arch/arm64/insn.o \
    $(KH_ROOT)/src/arch/arm64/pgtable.o

ccflags-y := -I$(KH_ROOT)/include -I$(KH_ROOT)/include/arch/arm64
```

### Loading

Standard `insmod` -- the module is built against the exact kernel, so CRC/vermagic matches:

```bash
insmod my_hook.ko kallsyms_addr=0x...
```

## Host platform support

KernelHook builds on macOS and Linux hosts. The build system auto-detects a
cross-compiler using this decision order (first match wins):

1. **User override** — if you set `CC`+`LD`, or `CROSS_COMPILE`, they are
   used as-is. This lets you plug in any toolchain without editing files.
2. **Android NDK** — searched in: `$ANDROID_NDK_ROOT`, `$ANDROID_NDK_HOME`,
   `$ANDROID_SDK_ROOT/ndk/<ver>`, and the platform default
   (`~/Library/Android/sdk/ndk/<ver>` on macOS, `~/Android/Sdk/ndk/<ver>`
   on Linux). The highest installed NDK version wins. API level is
   auto-detected as the maximum supported by the NDK sysroot; override with
   `$ANDROID_API_LEVEL` if you need a specific level.
3. **System cross-compiler** — `aarch64-linux-gnu-gcc`, or
   `clang --target=aarch64-linux-gnu` with `ld.lld`. This fallback only
   produces glibc-ABI binaries, which are **safe for freestanding `.ko`
   modules and probe.ko** but **not** for Android userspace binaries
   (`tests/userspace/test_android.c` et al.), which require bionic ABI.
4. **Error** — if none of the above, the build aborts with the list of
   environment variables you can set to unblock it.

Every invocation prints one `[toolchain] using <kind>: ...` line to stderr
naming the compiler actually selected. Fallback reasons are also logged.

### Environment variables

| Variable | Purpose |
|---|---|
| `CC`, `LD` | Explicit compiler/linker paths (highest priority) |
| `CROSS_COMPILE` | Toolchain prefix, e.g. `aarch64-linux-gnu-` |
| `ANDROID_NDK_ROOT` | Direct path to an NDK |
| `ANDROID_NDK_HOME` | Legacy alias for `ANDROID_NDK_ROOT` |
| `ANDROID_SDK_ROOT` | SDK root; NDK resolved via `$SDK/ndk/<ver>` |
| `ANDROID_HOME` | Legacy alias for `ANDROID_SDK_ROOT` |
| `ANDROID_API_LEVEL` | Override auto-detected API level |

### Linux host examples

Install the NDK under `~/Android/Sdk/ndk/<ver>` (Android Studio default) and
nothing else is needed:

```bash
./scripts/run_android_tests.sh   # auto-detects NDK
```

Or use a system cross-compiler for freestanding builds without an NDK:

```bash
sudo apt install gcc-aarch64-linux-gnu
make -C examples/hello_hook KDIR=/path/to/linux-headers-arm64
```

Android userspace tests still require an NDK — they will fail fast with a
clear error if only system cross-gcc is available.
