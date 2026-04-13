# ksyms_lookup

Runtime kernel symbol resolution. Look up multiple symbols and handle nonexistent symbols.

运行时内核符号解析。查找多个符号、处理不存在的符号。

## API

- `ksyms_lookup` -- look up kernel symbol by name, returns address (0 if not found)

## Build / 构建

```bash
# Mode A (Freestanding)
make module

# Mode B (SDK — requires kernelhook.ko loaded first)
make -f Makefile.sdk module

# Mode C (Kbuild — requires kernel source)
make -C /path/to/kernel M=$(pwd) modules
```

## Load / 加载

```bash
kmod_loader ksyms_lookup.ko kallsyms_addr=0x...
```

## Expected dmesg / 预期输出

```
ksyms_lookup: vfs_read = ffffffc0xxxxxxxx
ksyms_lookup: vfs_write = ffffffc0xxxxxxxx
ksyms_lookup: do_sys_openat2 = ffffffc0xxxxxxxx
ksyms_lookup: vfs_read = ffffffc0xxxxxxxx
ksyms_lookup: nonexistent symbol = 0 (expected 0)
ksyms_lookup: all lookups complete
```

## Notes / 备注

This example only needs `kmod_compat_init` -- no `hook_mem_init` or `pgtable_init` required since it does not install any hooks.

本示例只需要 `kmod_compat_init`，不安装任何 hook，因此无需 `hook_mem_init` 或 `pgtable_init`。
