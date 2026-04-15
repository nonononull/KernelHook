# kh_root —— 提权 Demo

集成在主测试套件里的端到端 demo（`tests/kmod/test_phase6_kh_root.c`）。用 ~350 行 C 代码在 KernelHook 的 syscall hook API 之上实现一个可用的 `su` 式 root shell，不含 kstorage、不动 SELinux scontext、无 32 位 compat。

> ⚠️ **Demo only。** `kh_root` 会让**任何调用者**调用 `/system/bin/kh_root` 就提权到 uid=0 —— 没有白名单。仅在你拥有并控制的设备上使用。

## 作用

装载 `kh_test.ko` 期间，执行 `/system/bin/kh_root`（这个二进制**不需要**真的存在）时内核会：

1. 在路径解析前拦截 `execve` 系统调用
2. 对 `current` 调 `commit_creds(prepare_kernel_cred(NULL))` → 当前 task cred 变为 uid=0、完整 capability 掩码、所有 group 清零
3. 改写 syscall 的 filename 参数为 `/system/bin/sh`
4. 放行让内核继续 —— 调用方得到一个 root `sh` shell

此外还 hook 了 `faccessat` 和 `fstatat`，将对 `/system/bin/kh_root` 的路径查询重定向到 `/system/bin/sh`，这样 `test -x /system/bin/kh_root` 即使文件不存在也返回 true。

## 用法

构建并加载 `kh_test.ko` 之后：

```bash
# 基线 —— userdebug 设备上 adb shell 以 uid=shell (2000) 运行
adb shell id -u                                    # → 2000

# 调用 kh_root —— 该路径上的二进制并不存在
adb shell /system/bin/kh_root -c 'id'              # → uid=0(root) gid=0(root) ...
adb shell /system/bin/kh_root -c 'whoami'          # → root
adb shell /system/bin/kh_root -c 'cat /data/misc/adb/adb_keys'   # 仅 root 可读

# 交互式 root shell（不加 -c，直接进入 sh 作为 root）
adb shell /system/bin/kh_root
# （输入命令；exit 退回 shell 用户）

# 验证二进制根本不存在
adb shell 'ls -la /system/bin/kh_root'             # → no such file
# 但 access/stat 对其操作被重定向到 sh 报告成功：
adb shell 'test -e /system/bin/kh_root && echo yes'  # → yes
```

## 加载模块（freestanding 模式）

kh_root demo 位于 `kh_test.ko` 的 Phase 6 测试套件内，这是一个自包含的
freestanding 内核模块（不消费 SDK）。直接加载即可：

```sh
make -C tests/kmod freestanding        # 也可通过 scripts/test_device_kmod.sh --mode=freestanding
adb push tests/kmod/kh_test.ko          /data/local/tmp/
adb push tools/kmod_loader/kmod_loader  /data/local/tmp/
adb shell 'chmod +x /data/local/tmp/kmod_loader'

# 获取 kallsyms_lookup_name 地址
KADDR=$(adb shell "su -c 'cat /proc/kallsyms | awk \"/ T kallsyms_lookup_name$/{print \\\$1; exit}\"'")
KADDR="0x$KADDR"

# 加载（单个自包含 .ko —— freestanding）
adb shell "su -c '/data/local/tmp/kmod_loader /data/local/tmp/kh_test.ko kallsyms_addr=$KADDR'"

# 验证
adb shell 'lsmod | grep kh_test'
```

收工：

```sh
adb shell "su -c 'rmmod kh_test'"
```

> **为什么用 freestanding？** `kh_test.ko` 测试的是 KernelHook 的内部
> 底层 API（syscall 级 hook、transit 缓冲区初始化、原始内存后端）。
> SDK 消费者只使用高层公共 API（见 `examples/hello_hook/`）。
> 将 `kh_test.ko` 保持 freestanding 可维护封装边界 —— 内部 API
> 保持内部可见。
>
> 如需查看 SDK 消费者示例，请参考 `examples/hello_hook/` 或 `examples/`
> 下的其他示例；它们采用两步加载方式（先 `kernelhook.ko`，再消费者 `.ko`），
> 可通过 `scripts/test.sh device`（默认 `--mode=sdk`）运行。

## 原理（代码走读）

### 安装 (`kh_root_install`)

```c
kh_prepare_kernel_cred = ksyms_lookup("prepare_kernel_cred");
kh_commit_creds        = ksyms_lookup("commit_creds");

kh_hook_syscalln(__NR_execve,       3, kh_before_execve,     NULL, NULL);
kh_hook_syscalln(__NR_faccessat,    3, kh_before_path_arg1,  NULL, NULL);
kh_hook_syscalln(__NR3264_fstatat,  4, kh_before_path_arg1,  NULL, NULL);
```

### execve 提权 (`kh_before_execve`)

```c
void **u_filename_p = (void **)kh_syscall_argn_p(args, 0);
char buf[64];
kh_strncpy_from_user(buf, *u_filename_p, sizeof(buf));

if (strcmp(buf, "/system/bin/kh_root") != 0) return;   /* 快速拒绝 */

struct cred *new = kh_prepare_kernel_cred(NULL);
if (!new) return;
kh_commit_creds(new);                                  /* → uid=0 */

void *uptr = kh_copy_to_user_stack("/system/bin/sh", 15);
if ((long)uptr > 0) *u_filename_p = uptr;              /* 重定向 */
```

`before_execve` 返回后，内核以改写后的 filename 继续 —— 执行 `/system/bin/sh` 而非缺失的 `kh_root` 二进制。由于我们已调 `commit_creds`，得到的 `sh` 进程以 root 身份运行。

### 卸载

`kh_root_uninstall()` 在 `kh_test_exit()` 中调用 —— **必须**，因为我们用的是 inline hook。不卸的话 `rmmod` 会留下指向已释放模块 text 的跳板，系统上任何进程下次 execve 都会 panic 内核。

## 实现 ~350 LOC

对比 KernelPatch 的 `kernel/patch/common/sucompat.c`（去掉 compat/kstorage/scontext 后约 400 LOC）—— 架构相同，范围更窄。

明确排除的非目标：
- SELinux scontext 切换（结果仍为 `u:r:shell:s0` 即使 uid=0 —— 有些 root-only 服务可能拒绝）
- 32 位 compat ABI
- 按 uid 的白名单 / kstorage
- argv/envp 改写（只改 filename）
- 跨重启持久化

架构设计详情见 [design spec](../../docs/plans/2026-04-15-syscall-hook-and-kh-root.md)。

## 安全模型

这是证明 syscall-hook 基础设施可用的 **demo**，不要和完备的 root 管理器混为一谈：

- 任何能 `execve("/system/bin/kh_root", ...)` 的进程都能拿 root。Android 常规沙箱不阻止 —— 任意 app 都能 spawn 进程。
- hook 无审计日志、无限流、无冷却。
- 加载 `kh_test.ko` 本身就需要 root（经 Magisk su），所以实际场景里攻击者在此之前已经有特权。

若要在 KernelHook API 之上做生产级 root 管理器，需加：uid 白名单（kstorage）、按 app 的 SELinux 上下文、supercall 风格的控制面、二进制校验。那是一个 ~1500 LOC 的项目（参考 KernelPatch `kernel/patch/common/*`）—— 明确不在本 demo 范围。
