# File-header template (authoritative)

Every `.c` / `.h` file under `src/`, `include/`, and `tests/kmod/` starts
with this exact header block:

```c
/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2026 bmax121.
 *
 * <One-line role: what this file does in the system>
 *
 * Build modes: <userspace | kernel | shared>
 * Depends on: <key headers / runtime symbols>
 * Notes: <only if non-obvious>
 */
```

## Fields

- **One-line role** — a single English sentence describing what the file
  owns. Be specific. Bad: "core library". Good: "ARM64 inline hook
  instruction relocation engine: patches origin prologue + emits
  relocated instructions into the transit buffer".
- **Build modes** — one of:
  - `userspace` — host tests (`tests/userspace/`, some scaffolding).
  - `kernel` — kmod-only code (freestanding + kbuild).
  - `shared` — compiles in both modes (most of `src/`).
- **Depends on** — pointer to the key external headers or runtime
  symbols this file relies on. Examples:
  - `<linux/uaccess.h>`, `<asm/ptrace.h>` (kbuild-mode kernel headers)
  - `ksyms_lookup("init_cred")`, `ksyms_lookup("prepare_kernel_cred")`
    (freestanding runtime-resolved symbols)
  - `kh_alias_init()`, `kh_platform_alloc_rox()` (intra-project API)
- **Notes** — omit unless a reader needs it. Include when:
  - "Ported from KernelPatch kernel/base/hotpatch.c — see
    docs/audits/kp-port-audit-2026-04-15.md for deviations."
  - "RCU snapshot window covers before-origin-after; do NOT reintroduce
    a second sync_read_lock (see CLAUDE.md rationale)."
  - "TLBI sequence must stay `dsb ishst → tlbi vaale1is → dsb ish → isb`
    (CLAUDE.md TLBI correctness)."

## Lighter-touch variant

`tests/userspace/*.c` and `examples/**/*.c` carry only the SPDX line and
a single-line role comment:

```c
/* SPDX-License-Identifier: GPL-2.0-or-later */
/* <One-line role>. */
```

## Enforcement

Review-time only. No lint automation (yet). `scripts/lint_exports.sh`
covers symbol-namespace enforcement; header conformance is a code-review
responsibility.

---

## 中文概要

所有 `src/`、`include/`、`tests/kmod/` 下的 `.c`/`.h` 必须以上方的
C 注释模板开头。字段含义：

- **One-line role** — 用一句英文说清楚该文件在系统中负责什么；要具体，
  不写 "core library"。
- **Build modes** — `userspace` / `kernel` / `shared` 三选一。
- **Depends on** — 关键外部头文件或运行时符号（含项目内 API）。
- **Notes** — 仅在非显而易见时填写；常见例子：KP 移植来源、RCU 快照
  窗口设计理由、TLBI 顺序锁死。

`tests/userspace/*.c` 和 `examples/**/*.c` 用精简形式：SPDX + 一行 role
注释即可，不需要完整模板。

强制性：代码评审阶段人工检查；暂无 lint 自动化。`scripts/lint_exports.sh`
只负责符号命名空间的回归门。
