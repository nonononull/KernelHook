# API 参考

头文件：`<hook.h>`、`<symbol.h>`

## 内联 Hook

### `hook`

```c
hook_err_t hook(void *func, void *replace, void **backup);
```

将 `func` 替换为 `replace`。原始入口点（重定位后的指令）保存在 `*backup` 中，可用于调用原函数。

- `func` -- 目标内核函数地址
- `replace` -- 替换函数（签名必须与原函数一致）
- `backup` -- 接收指向重定位后原始代码的指针

成功返回 `HOOK_NO_ERR`。

### `unhook`

```c
void unhook(void *func);
```

移除由 `hook()` 安装的内联 hook，恢复 `func` 处的原始指令。

## Hook 链（Wrap API）

Wrap API 支持在同一函数上注册多个 before/after 回调，按优先级排序执行。优先级数值越小，优先级越高，越先执行。

### `hook_wrap`

```c
hook_err_t hook_wrap(void *func, int32_t argno, void *before, void *after,
                     void *udata, int32_t priority);
```

在 `func` 上注册一对 before/after 回调。

- `func` -- 目标函数地址
- `argno` -- 需要捕获的参数个数（0-12）
- `before` -- 原函数执行前调用（可为 NULL）
- `after` -- 原函数执行后调用（可为 NULL）
- `udata` -- 传递给回调的用户数据
- `priority` -- 执行顺序（越小越优先，0 = 最高优先级）

对同一 `func` 多次调用 `hook_wrap` 会向链中添加回调（上限 `HOOK_CHAIN_NUM` = 8）。

### `hook_wrap0` ... `hook_wrap12`

```c
static inline hook_err_t hook_wrap4(void *func,
    hook_chain4_callback before,
    hook_chain4_callback after,
    void *udata);
```

类型安全的便捷封装，优先级默认为 0。后缀数字决定回调中使用的 `hook_fargsN_t` 类型。

### `hook_unwrap`

```c
void hook_unwrap(void *func, void *before, void *after);
```

从链中移除指定的 before/after 回调对。若链变空，hook 会被完全移除。

### `wrap_get_origin_func`

```c
void *wrap_get_origin_func(void *hook_args);
```

在回调中获取重定位后的原函数指针。将 `fargs` 参数强制转换传入即可。

## 函数指针 Hook

Hook 存储在内存地址处的函数指针（例如 `struct` ops 表中的回调）。

### `fp_hook`

```c
void fp_hook(uintptr_t fp_addr, void *replace, void **backup);
```

将 `fp_addr` 处的函数指针替换为 `replace`，原始指针保存到 `*backup`。

### `fp_unhook`

```c
void fp_unhook(uintptr_t fp_addr, void *backup);
```

恢复 `fp_addr` 处的原始函数指针。

### `fp_hook_wrap`

```c
hook_err_t fp_hook_wrap(uintptr_t fp_addr, int32_t argno,
                        void *before, void *after,
                        void *udata, int32_t priority);
```

类似 `hook_wrap`，但作用于函数指针。最多支持 `FP_HOOK_CHAIN_NUM` = 16 个回调。

### `fp_hook_unwrap`

```c
void fp_hook_unwrap(uintptr_t fp_addr, void *before, void *after);
```

从函数指针 hook 链中移除回调对。

### `fp_get_origin_func`

```c
void *fp_get_origin_func(void *hook_args);
```

在函数指针 hook 回调中获取原始函数指针。

### `fp_hook_wrap0` ... `fp_hook_wrap12`

类型安全的便捷封装，与 `hook_wrapN` 用法类似。

## 符号解析

头文件：`<symbol.h>`

### `ksyms_init`

```c
int ksyms_init(uint64_t kallsyms_lookup_name_addr);
```

用内核 `kallsyms_lookup_name` 的运行时地址初始化符号解析器。必须在调用
`ksyms_lookup` 之前调用。成功返回 0，失败返回非零。

### `ksyms_lookup`

```c
uint64_t ksyms_lookup(const char *name);
```

按名称查找内核符号，返回地址。未找到时返回 0。必须先调用 `ksyms_init()`。

## 类型

### `hook_fargsN_t`

回调参数结构体，公共字段：

| 字段 | 类型 | 说明 |
|------|------|------|
| `chain` | `void *` | 内部使用——指向链状态 |
| `skip_origin` | `int` | 在 `before` 中置 1 可跳过原函数 |
| `local` | `hook_local_t *` | 每回调本地存储（4 x uint64_t） |
| `ret` | `uint64_t` | 返回值（`after` 中读取，写入可覆盖） |
| `arg0`...`argN` | `uint64_t` | 函数参数（可读写） |

变体：`hook_fargs0_t`（无参数）到 `hook_fargs12_t`（12 个参数）。

- `hook_fargs1_t` 到 `hook_fargs3_t` 是 `hook_fargs4_t` 的别名
- `hook_fargs5_t` 到 `hook_fargs7_t` 是 `hook_fargs8_t` 的别名
- `hook_fargs9_t` 到 `hook_fargs11_t` 是 `hook_fargs12_t` 的别名

### `hook_local_t`

每回调本地存储，通过 `fargs->local->data0` 到 `data3`（或 `data[0..3]`）访问。链中每个回调拥有独立的 `hook_local_t`。

### `hook_err_t`

| 值 | 名称 | 说明 |
|----|------|------|
| 0 | `HOOK_NO_ERR` | 成功 |
| 4095 | `HOOK_BAD_ADDRESS` | 函数地址无效 |
| 4094 | `HOOK_DUPLICATED` | 该地址已存在 hook |
| 4093 | `HOOK_NO_MEM` | 内存分配失败 |
| 4092 | `HOOK_BAD_RELO` | 指令重定位失败 |
| 4091 | `HOOK_TRANSIT_NO_MEM` | 中转桩分配失败 |
| 4090 | `HOOK_CHAIN_FULL` | 链已满（内联最多 8 / 函数指针最多 16） |

## 回调签名

```c
typedef void (*hook_chainN_callback)(hook_fargsN_t *fargs, void *udata);
```

N 为 0-12。以 4 参数函数为例：

```c
void my_before(hook_fargs4_t *fargs, void *udata)
{
    uint64_t arg0 = fargs->arg0;       /* 读取参数 */
    fargs->arg1 = 0;                   /* 修改参数 */
    fargs->skip_origin = 1;            /* 跳过原函数 */
    fargs->ret = -EPERM;               /* 设置返回值 */
    fargs->local->data0 = arg0;        /* 保存到本地存储 */
}

void my_after(hook_fargs4_t *fargs, void *udata)
{
    uint64_t saved = fargs->local->data0;  /* 读取本地存储 */
    fargs->ret = 0;                        /* 覆盖返回值 */
}
```
