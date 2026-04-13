# 示例

## 概览

| 示例 | 说明 | 核心 API |
|------|------|----------|
| [hello_hook](../../examples/hello_hook/) | Hook `do_sys_openat2`，记录文件名 | `hook_wrap4`、`hook_unwrap` |
| [fp_hook](../../examples/fp_hook/) | Hook 结构体中的函数指针 | `fp_hook`、`fp_unhook` |
| [hook_chain](../../examples/hook_chain/) | 多回调按优先级排序 | 带优先级的 `hook_wrap` |
| [hook_wrap_args](../../examples/hook_wrap_args/) | 查看参数、覆盖返回值 | `hook_wrap4`、`fargs->ret` |
| [ksyms_lookup](../../examples/ksyms_lookup/) | 运行时内核符号解析 | `ksyms_lookup` |

## hello_hook

Hook `do_sys_openat2`（旧内核上为 `do_sys_open`），记录每次 `open()` 系统调用的文件名指针。

```c
static void open_before(hook_fargs4_t *fargs, void *udata)
{
    const char *filename = (const char *)fargs->arg1;
    pr_info("hello_hook: open called, filename ptr=%llx",
          (unsigned long long)(uintptr_t)filename);
}

/* 初始化时: */
hook_err_t err = hook_wrap4(target, open_before, NULL, NULL);

/* 退出时: */
hook_unwrap(hooked_func, open_before, NULL);
```

**预期 dmesg 输出：**
```
hello_hook: hooked do_sys_open* at ffffffc0xxxxxxxx
hello_hook: open called, filename ptr=7fxxxxxxxx
```

## fp_hook

Hook 结构体中的函数指针。演示 `fp_hook` / `fp_unhook` 的用法，以及通过备份指针调用原始函数。

```c
struct demo_ops { int (*callback)(int x, int y); };

fp_hook((uintptr_t)&ops.callback, replacement_callback, &backup_func);
/* 此时 ops.callback(3, 4) 会调用 replacement_callback */

fp_unhook((uintptr_t)&ops.callback, backup_func);
/* ops.callback 恢复为 original_callback */
```

**预期 dmesg 输出：**
```
fp_hook: before hook: ops.callback(3,4) = 7
fp_hook: replacement called with x=3 y=4
fp_hook: original returned 7, we return 12
fp_hook: after hook: ops.callback(3,4) = 12
```

## hook_chain

在同一函数上注册三个不同优先级（0、50、100）的 before 回调。展示优先级决定执行顺序，而非注册顺序。

```c
hook_wrap(target, 4, (void *)before_medium, NULL, NULL, 50);
hook_wrap(target, 4, (void *)before_low,    (void *)after_cb, NULL, 100);
hook_wrap(target, 4, (void *)before_high,   NULL, NULL, 0);
/* 执行顺序: high(0) -> medium(50) -> low(100) -> 原函数 -> after */
```

**预期 dmesg 输出：**
```
hook_chain: [priority 0] HIGH priority before callback
hook_chain: [priority 50] MEDIUM priority before callback
hook_chain: [priority 100] LOW priority before callback
hook_chain: after callback, ret=...
```

## hook_wrap_args

用 before 和 after 两个回调 hook `do_sys_openat2`。before 回调检查所有参数，after 回调读取并覆盖返回值。

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

**预期 dmesg 输出：**
```
hook_wrap_args: BEFORE arg0(dfd)=... arg1(filename)=... arg2(how)=...
hook_wrap_args: AFTER original ret=..., overriding with 0
```

## ksyms_lookup

演示 `ksyms_lookup()` 的运行时内核符号解析功能。无需 `hook_mem_init` 或 `pgtable_init`。

```c
uint64_t addr = ksyms_lookup("vfs_read");
/* addr = vfs_read 的内核地址 */

addr = ksyms_lookup("nonexistent_symbol");
/* addr = 0 */
```

**预期 dmesg 输出：**
```
ksyms_lookup: vfs_read = ffffffc0xxxxxxxx
ksyms_lookup: vfs_write = ffffffc0xxxxxxxx
ksyms_lookup: do_sys_openat2 = ffffffc0xxxxxxxx
ksyms_lookup: vfs_read (cached, 1st) = ffffffc0xxxxxxxx
ksyms_lookup: vfs_read (cached, 2nd) = ffffffc0xxxxxxxx
ksyms_lookup: nonexistent symbol = 0 (expected 0)
```

## 构建示例

所有示例都支持三种构建模式：

```bash
# 模式 A（Freestanding）
cd examples/<name>
make module

# 模式 B（SDK）
cd examples/<name>
make -f Makefile.sdk module

# 模式 C（Kbuild）
cd examples/<name>
make -C /path/to/kernel M=$(pwd) modules
```
