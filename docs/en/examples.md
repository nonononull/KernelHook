# Examples

## Overview

| Example | Description | Key API |
|---------|-------------|---------|
| [hello_hook](../../examples/hello_hook/) | Hook `do_sys_openat2`, log filename | `hook_wrap4`, `hook_unwrap` |
| [fp_hook](../../examples/fp_hook/) | Hook function pointer in struct | `fp_hook`, `fp_unhook` |
| [hook_chain](../../examples/hook_chain/) | Multiple callbacks with priority | `hook_wrap` with priority |
| [hook_wrap_args](../../examples/hook_wrap_args/) | Inspect args, override return value | `hook_wrap4`, `fargs->ret` |
| [ksyms_lookup](../../examples/ksyms_lookup/) | Runtime kernel symbol resolution | `ksyms_lookup` |

## hello_hook

Hooks `do_sys_openat2` (or `do_sys_open` on older kernels) and logs the filename pointer for every `open()` syscall.

```c
static void open_before(hook_fargs4_t *fargs, void *udata)
{
    const char *filename = (const char *)fargs->arg1;
    pr_info("hello_hook: open called, filename ptr=%llx",
          (unsigned long long)(uintptr_t)filename);
}

/* In init: */
hook_err_t err = hook_wrap4(target, open_before, NULL, NULL);

/* In exit: */
hook_unwrap(hooked_func, open_before, NULL);
```

**Expected dmesg:**
```
hello_hook: hooked do_sys_open* at ffffffc0xxxxxxxx
hello_hook: open called, filename ptr=7fxxxxxxxx
```

## fp_hook

Hooks a function pointer in a struct. Demonstrates `fp_hook` / `fp_unhook` with a backup pointer for calling the original.

```c
struct demo_ops { int (*callback)(int x, int y); };

fp_hook((uintptr_t)&ops.callback, replacement_callback, &backup_func);
/* Now ops.callback(3, 4) calls replacement_callback */

fp_unhook((uintptr_t)&ops.callback, backup_func);
/* ops.callback is restored to original_callback */
```

**Expected dmesg:**
```
fp_hook: before hook: ops.callback(3,4) = 7
fp_hook: replacement called with x=3 y=4
fp_hook: original returned 7, we return 12
fp_hook: after hook: ops.callback(3,4) = 12
```

## hook_chain

Registers three before-callbacks on the same function with different priorities (0, 50, 100). Demonstrates that priority controls execution order, not registration order.

```c
hook_wrap(target, 4, (void *)before_medium, NULL, NULL, 50);
hook_wrap(target, 4, (void *)before_low,    (void *)after_cb, NULL, 100);
hook_wrap(target, 4, (void *)before_high,   NULL, NULL, 0);
/* Execution order: high(0) -> medium(50) -> low(100) -> original -> after */
```

**Expected dmesg:**
```
hook_chain: [priority 0] HIGH priority before callback
hook_chain: [priority 50] MEDIUM priority before callback
hook_chain: [priority 100] LOW priority before callback
hook_chain: after callback, ret=...
```

## hook_wrap_args

Hooks `do_sys_openat2` with both before and after callbacks. The before callback inspects all arguments; the after callback reads and overrides the return value.

```c
static void openat2_before(hook_fargs4_t *fargs, void *udata)
{
    pr_info("BEFORE arg0(dfd)=%lld arg1(filename)=%llx",
          (long long)fargs->arg0, (unsigned long long)fargs->arg1);
}

static void openat2_after(hook_fargs4_t *fargs, void *udata)
{
    pr_info("AFTER original ret=%lld, overriding with 0", (long long)fargs->ret);
    fargs->ret = 0;
}
```

**Expected dmesg:**
```
hook_wrap_args: BEFORE arg0(dfd)=... arg1(filename)=... arg2(how)=...
hook_wrap_args: AFTER original ret=..., overriding with 0
```

## ksyms_lookup

Demonstrates `ksyms_lookup()` for runtime kernel symbol resolution. Does not require `hook_mem_init` or `pgtable_init`.

```c
uint64_t addr = ksyms_lookup("vfs_read");
/* addr = kernel address of vfs_read */

addr = ksyms_lookup("nonexistent_symbol");
/* addr = 0 */
```

**Expected dmesg:**
```
ksyms_lookup: vfs_read = ffffffc0xxxxxxxx
ksyms_lookup: vfs_write = ffffffc0xxxxxxxx
ksyms_lookup: do_sys_openat2 = ffffffc0xxxxxxxx
ksyms_lookup: vfs_read (cached, 1st) = ffffffc0xxxxxxxx
ksyms_lookup: vfs_read (cached, 2nd) = ffffffc0xxxxxxxx
ksyms_lookup: nonexistent symbol = 0 (expected 0)
```

## Building Examples

All examples support three build modes:

```bash
# Mode A (Freestanding)
cd examples/<name>
make module

# Mode B (SDK)
cd examples/<name>
make -f Makefile.sdk module

# Mode C (Kbuild)
cd examples/<name>
make -C /path/to/kernel M=$(pwd) modules
```
