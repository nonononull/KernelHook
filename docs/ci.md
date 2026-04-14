# CI / Continuous Integration (CI / 持续集成)

## Workflows

### `kbuild.yml` (GKI build matrix)

Builds `kh_test.ko` and `kernelhook.ko` against five GKI KMIs
(`android12-5.10` through `android16-6.12`) using pre-built DDK containers.
Runs both `make` (authoritative, gates merge) and `bazel ddk_module()`
(validated, all five KMIs green) paths in parallel.

针对五个 GKI KMI（`android12-5.10` 到 `android16-6.12`），使用预编译 DDK 容器
构建 `kh_test.ko` 和 `kernelhook.ko`。`make`（权威路径，控制合并）和
`bazel ddk_module()`（已验证，五个 KMI 全绿）并行运行。

### `real-device-smoke.yml` (Pixel 6 hardware)

Runs the full freestanding test suite (kh_test + Ring 3 export_link_test)
on a physical Pixel 6 userdebug device connected via USB to a self-hosted
runner. Gated on `vars.HAS_REAL_DEVICE == 'true'`; forks without the
variable skip the job cleanly.

在通过 USB 连接到 self-hosted runner 的物理 Pixel 6 userdebug 设备上运行完整
freestanding 测试套件（kh_test + Ring 3 export_link_test）。由仓库变量
`vars.HAS_REAL_DEVICE == 'true'` 开关控制，没有配置该变量的 fork 会跳过此 job。

---

## Self-Hosted Runner Setup (Pixel 6) / 自建 Runner 配置

### Hardware (硬件)

- Pixel 6 running a `userdebug` build (GKI 6.1 or 6.6)
- Magisk rooted (`su -c id` returns `uid=0`)
- `adb authorized` (device authorized to accept ADB from the runner host)
- `modules_disabled=0` (verify: `adb shell cat /proc/sys/kernel/modules_disabled`)
- USB cable attached to the runner host machine

### Runner labels (Runner 标签)

Configure the GitHub Actions self-hosted runner with **all three** of these labels:

```
self-hosted
pixel6
adb
```

All three labels must be present for the job to dispatch; partial matches will not work.

三个标签必须全部存在，job 才会被调度；缺少任意一个将不匹配。

### Repository variable (仓库变量)

Navigate to: **Repo Settings → Secrets and variables → Actions → Variables**

| Variable name    | Value  |
|-----------------|--------|
| `HAS_REAL_DEVICE` | `true` |

The job is gated on this variable. Set to anything other than `true`
(or leave it unset) to disable the real-device job without modifying workflow
files.

该变量控制 job 是否运行。将其设为 `true` 以外的值（或不设置）即可禁用真机 job，
无需修改 workflow 文件。

### Environment (环境变量)

The workflow uses `DEVICE_SERIAL: "1B101FDF6003PM"`. If you use a different
device, edit the `env:` block in
`.github/workflows/real-device-smoke.yml` accordingly.

工作流中 `DEVICE_SERIAL` 默认为 `1B101FDF6003PM`。如使用其他设备，请修改
`.github/workflows/real-device-smoke.yml` 中的 `env:` 块。

---

## Exit Code Contract (退出码约定)

`scripts/test_device_kmod.sh` follows a strict exit-code contract:

| Exit code | Meaning |
|-----------|---------|
| `0` | All tests passed (kh_test + Ring 3) |
| `1` | Build failure, module load failure, or ≥ 1 test FAIL |
| `2` | Preflight failure (no device, no root, modules_disabled=1) |

The CI job fails if and only if the script exits non-zero, so a passing
run on the runner implies a 99/99 kh_test PASS + Ring 3 3/3 PASS.

`scripts/test_device_kmod.sh` 遵循严格的退出码约定：

| 退出码 | 含义 |
|--------|------|
| `0` | 所有测试通过（kh_test + Ring 3） |
| `1` | 构建失败、模块加载失败或 ≥ 1 个测试 FAIL |
| `2` | 前置检查失败（无设备/无 root/modules_disabled=1） |

---

## Artifacts (产物)

The real-device job uploads `/tmp/*.log` and `/tmp/crash*.log` on every run
(success or failure), retained for **14 days**. Logs include:

- `/tmp/kh_dmesg_<serial>.log` — live `/dev/kmsg` capture during module load
- `/tmp/kh_test_build.log` — kh_test.ko freestanding build output
- `/tmp/kh_ring3_build.log` — Ring 3 export_link_test build output

真机 job 无论成败均上传 `/tmp/*.log` 和 `/tmp/crash*.log`，保留 **14 天**。
