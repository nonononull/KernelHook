# kh_root — Privilege Escalation Demo

Featured end-to-end demo integrated into the main test suite (`tests/kmod/test_phase6_kh_root.c`). Demonstrates that a fully functional `su`-style root shell can be built on top of KernelHook's syscall hook API with ~350 lines of C, no kstorage, no SELinux scontext manipulation, no 32-bit compat.

> ⚠️ **Demo only.** `kh_root` elevates **any caller** that invokes `/system/bin/kh_root` to uid=0 — there is no allowlist. Install only on a device you own and control.

## What it does

While `kh_test.ko` is loaded, executing `/system/bin/kh_root` (which does **not** need to exist as a real binary) causes the kernel to:

1. Intercept the `execve` syscall before path resolution
2. Call `commit_creds(prepare_kernel_cred(NULL))` on `current` → task cred becomes uid=0, full capability mask, all groups zeroed
3. Rewrite the syscall's filename argument to `/system/bin/sh`
4. Let the kernel continue — the caller gets a root `sh` shell

Additionally, `faccessat` and `fstatat` are hooked to redirect path queries for `/system/bin/kh_root` to `/system/bin/sh`, so `test -x /system/bin/kh_root` returns true even though the file doesn't exist.

## Usage

After building and loading `kh_test.ko`:

```bash
# Baseline — adb shell runs as uid=shell (2000) on userdebug devices
adb shell id -u                                    # → 2000

# Invoke kh_root — the binary does NOT exist at that path
adb shell /system/bin/kh_root -c 'id'              # → uid=0(root) gid=0(root) ...
adb shell /system/bin/kh_root -c 'whoami'          # → root
adb shell /system/bin/kh_root -c 'cat /data/misc/adb/adb_keys'   # root-only file

# Interactive root shell (no -c; drops into sh as root)
adb shell /system/bin/kh_root
# (type commands; exit returns to shell user)

# Verify binary truly doesn't exist
adb shell 'ls -la /system/bin/kh_root'             # → no such file
# But access/stat on it is redirected to sh and reports success:
adb shell 'test -e /system/bin/kh_root && echo yes'  # → yes
```

## Loading the module (freestanding mode)

The kh_root demo lives inside `kh_test.ko`'s Phase 6 test harness, which
is a self-contained freestanding kernel module (it does not consume the
SDK). Load it directly:

```sh
make -C tests/kmod freestanding        # or via scripts/test_device_kmod.sh --mode=freestanding
adb push tests/kmod/kh_test.ko          /data/local/tmp/
adb push tools/kmod_loader/kmod_loader  /data/local/tmp/
adb shell 'chmod +x /data/local/tmp/kmod_loader'

# Resolve kallsyms_lookup_name once
KADDR=$(adb shell "su -c 'cat /proc/kallsyms | awk \"/ T kallsyms_lookup_name$/{print \\\$1; exit}\"'")
KADDR="0x$KADDR"

# Load (single self-contained .ko — freestanding)
adb shell "su -c '/data/local/tmp/kmod_loader /data/local/tmp/kh_test.ko kallsyms_addr=$KADDR'"

# Verify
adb shell 'lsmod | grep kh_test'
```

When you're done:

```sh
adb shell "su -c 'rmmod kh_test'"
```

> **Why freestanding?** `kh_test.ko` exercises KernelHook's internal
> low-level APIs (syscall-level hooks, transit-buffer setup, raw
> memory backends). SDK consumers use the high-level public API
> only (see `examples/hello_hook/`). Keeping `kh_test.ko`
> freestanding preserves encapsulation — internal APIs stay internal.
>
> For SDK consumer demonstrations, see `examples/hello_hook/` or any
> sibling under `examples/`; those load the 2-step way
> (`kernelhook.ko` first, consumer `.ko` second) via
> `scripts/test.sh device` (default `--mode=sdk`).

## How it works (code walkthrough)

### Install (`kh_root_install`)

```c
kh_prepare_kernel_cred = ksyms_lookup("prepare_kernel_cred");
kh_commit_creds        = ksyms_lookup("commit_creds");

kh_hook_syscalln(__NR_execve,       3, kh_before_execve,     NULL, NULL);
kh_hook_syscalln(__NR_faccessat,    3, kh_before_path_arg1,  NULL, NULL);
kh_hook_syscalln(__NR3264_fstatat,  4, kh_before_path_arg1,  NULL, NULL);
```

### execve elevation (`kh_before_execve`)

```c
void **u_filename_p = (void **)kh_syscall_argn_p(args, 0);
char buf[64];
kh_strncpy_from_user(buf, *u_filename_p, sizeof(buf));

if (strcmp(buf, "/system/bin/kh_root") != 0) return;   /* fast reject */

struct cred *new = kh_prepare_kernel_cred(NULL);
if (!new) return;
kh_commit_creds(new);                                  /* → uid=0 */

void *uptr = kh_copy_to_user_stack("/system/bin/sh", 15);
if ((long)uptr > 0) *u_filename_p = uptr;              /* redirect */
```

When `before_execve` returns, the kernel continues with the rewritten filename — it exec's `/system/bin/sh` instead of the missing `kh_root` binary. Because we already called `commit_creds`, the resulting `sh` process runs as root.

### Teardown

`kh_root_uninstall()` is called from `kh_test_exit()` — **mandatory** because we use inline hooks. Without it, `rmmod` leaves trampolines pointing into freed module text, and the next execve from any process on the system panics the kernel.

## Implementation ~350 LOC

Compare with KernelPatch's `kernel/patch/common/sucompat.c` (~400 LOC trimmed of compat/kstorage/scontext) — same architecture, narrower scope.

Non-goals intentionally excluded:
- SELinux scontext override (result stays `u:r:shell:s0` even though uid=0 — some root-only services may reject)
- 32-bit compat ABI
- Per-uid allowlist / kstorage
- argv/envp rewriting (just filename redirect)
- Persistence across reboot

See [design spec](../../docs/plans/2026-04-15-syscall-hook-and-kh-root.md) for the full architecture rationale.

## Security model

This is a **demo** to prove the syscall-hook infrastructure works. Do not confuse it with a secure root manager:

- Any process that can `execve("/system/bin/kh_root", ...)` gets root. Normal Android sandbox doesn't prevent that — any app can spawn processes.
- The hook has no audit log, no rate limiting, no cooldown.
- Loading `kh_test.ko` itself already requires root (via Magisk su), so in practice the attacker already has privilege before this is useful.

For a production-grade root manager on top of KernelHook APIs, you'd add: uid allowlist (kstorage), per-app SELinux contexts, supercall-style control plane, binary verification. That's a ~1500 LOC project (see KernelPatch `kernel/patch/common/*` for reference) — deliberately out of scope for this demo.
