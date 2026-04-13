# API Reference

Header: `<hook.h>`, `<symbol.h>`

## Inline Hook

### `hook`

```c
hook_err_t hook(void *func, void *replace, void **backup);
```

Replace `func` with `replace`. The original entry point (relocated instructions) is stored in `*backup` for calling the original function.

- `func` -- target kernel function address
- `replace` -- replacement function (must match original signature)
- `backup` -- receives pointer to relocated original code

Returns `HOOK_NO_ERR` on success.

### `unhook`

```c
void unhook(void *func);
```

Remove a raw inline hook installed by `hook()`. Restores the original instructions at `func`.

## Hook Chain (Wrap API)

The wrap API supports multiple before/after callbacks on the same function, ordered by priority. Lower priority number = higher priority = runs first.

### `hook_wrap`

```c
hook_err_t hook_wrap(void *func, int32_t argno, void *before, void *after,
                     void *udata, int32_t priority);
```

Register a before/after callback pair on `func`.

- `func` -- target function address
- `argno` -- number of arguments to capture (0-12)
- `before` -- called before the original (may be NULL)
- `after` -- called after the original (may be NULL)
- `udata` -- user data passed to callbacks
- `priority` -- execution order (lower = first, 0 = highest)

Multiple calls to `hook_wrap` on the same `func` add callbacks to the chain (up to `HOOK_CHAIN_NUM` = 8).

### `hook_wrap0` ... `hook_wrap12`

```c
static inline hook_err_t hook_wrap4(void *func,
    hook_chain4_callback before,
    hook_chain4_callback after,
    void *udata);
```

Type-safe convenience wrappers. Priority defaults to 0. The number suffix determines the `hook_fargsN_t` type used in callbacks.

### `hook_unwrap`

```c
void hook_unwrap(void *func, void *before, void *after);
```

Remove a specific before/after callback pair from the chain. If the chain becomes empty, the hook is fully removed.

### `wrap_get_origin_func`

```c
void *wrap_get_origin_func(void *hook_args);
```

Get the relocated original function pointer from within a callback. Cast `hook_args` from the `fargs` parameter.

## Function Pointer Hook

Hook a function pointer stored at a memory address (e.g., in a `struct` ops table).

### `fp_hook`

```c
void fp_hook(uintptr_t fp_addr, void *replace, void **backup);
```

Replace the function pointer at `fp_addr` with `replace`. Original pointer saved to `*backup`.

### `fp_unhook`

```c
void fp_unhook(uintptr_t fp_addr, void *backup);
```

Restore the original function pointer at `fp_addr`.

### `fp_hook_wrap`

```c
hook_err_t fp_hook_wrap(uintptr_t fp_addr, int32_t argno,
                        void *before, void *after,
                        void *udata, int32_t priority);
```

Like `hook_wrap` but for function pointers. Supports up to `FP_HOOK_CHAIN_NUM` = 16 callbacks.

### `fp_hook_unwrap`

```c
void fp_hook_unwrap(uintptr_t fp_addr, void *before, void *after);
```

Remove a callback pair from a function pointer hook chain.

### `fp_get_origin_func`

```c
void *fp_get_origin_func(void *hook_args);
```

Get the original function pointer from within an FP hook callback.

### `fp_hook_wrap0` ... `fp_hook_wrap12`

Type-safe convenience wrappers, analogous to `hook_wrapN`.

## Symbol Resolution

Header: `<symbol.h>`

### `ksyms_init`

```c
int ksyms_init(uint64_t kallsyms_lookup_name_addr);
```

Initialize the symbol resolver with the runtime address of the kernel's
`kallsyms_lookup_name`. Must be called before `ksyms_lookup`. Returns 0 on success, non-zero on error.

### `ksyms_lookup`

```c
uint64_t ksyms_lookup(const char *name);
```

Look up a kernel symbol by name. Returns the address, or 0 if not found.
Requires prior `ksyms_init()`.

## Types

### `hook_fargsN_t`

Callback argument structs. Common fields:

| Field | Type | Description |
|-------|------|-------------|
| `chain` | `void *` | Internal -- pointer to chain state |
| `skip_origin` | `int` | Set to 1 in `before` to skip original function |
| `local` | `hook_local_t *` | Per-item local storage (4 x uint64_t) |
| `ret` | `uint64_t` | Return value (read in `after`, write to override) |
| `arg0`...`argN` | `uint64_t` | Function arguments (read/write) |

Variants: `hook_fargs0_t` (no args) through `hook_fargs12_t` (12 args).

- `hook_fargs1_t` through `hook_fargs3_t` are aliases for `hook_fargs4_t`
- `hook_fargs5_t` through `hook_fargs7_t` are aliases for `hook_fargs8_t`
- `hook_fargs9_t` through `hook_fargs11_t` are aliases for `hook_fargs12_t`

### `hook_local_t`

Per-callback local storage, accessible as `fargs->local->data0` through `data3` (or `data[0..3]`). Each callback in the chain gets its own independent `hook_local_t`.

### `hook_err_t`

| Value | Name | Description |
|-------|------|-------------|
| 0 | `HOOK_NO_ERR` | Success |
| 4095 | `HOOK_BAD_ADDRESS` | Invalid function address |
| 4094 | `HOOK_DUPLICATED` | Hook already exists at this address |
| 4093 | `HOOK_NO_MEM` | Memory allocation failed |
| 4092 | `HOOK_BAD_RELO` | Instruction relocation failed |
| 4091 | `HOOK_TRANSIT_NO_MEM` | Transit stub allocation failed |
| 4090 | `HOOK_CHAIN_FULL` | Chain is full (max 8 inline / 16 FP) |

## Callback Signature

```c
typedef void (*hook_chainN_callback)(hook_fargsN_t *fargs, void *udata);
```

Where N is 0-12. Example for 4-argument function:

```c
void my_before(hook_fargs4_t *fargs, void *udata)
{
    uint64_t arg0 = fargs->arg0;       /* read argument */
    fargs->arg1 = 0;                   /* modify argument */
    fargs->skip_origin = 1;            /* skip original function */
    fargs->ret = -EPERM;               /* set return value */
    fargs->local->data0 = arg0;        /* save to local storage */
}

void my_after(hook_fargs4_t *fargs, void *udata)
{
    uint64_t saved = fargs->local->data0;  /* read from local storage */
    fargs->ret = 0;                        /* override return value */
}
```
