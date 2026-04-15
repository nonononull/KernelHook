# KernelPatch Port Audit — 2026-04-15

> Produced under plan [`docs/superpowers/plans/2026-04-15-p2-kp-port-audit-plan.md`](../superpowers/plans/2026-04-15-p2-kp-port-audit-plan.md).
> Upstream reference: `ref/KernelPatch/` (gitignored; see plan header for
> exact counterpart paths).

## 0. Scope

Every `src/` / `tests/kmod/` site derived from KernelPatch. Each finding is
classified:

| Class         | Meaning                                                                    |
| ------------- | -------------------------------------------------------------------------- |
| **must-fix**  | Correctness bug or missing safety invariant. Blocker for P2 exit.          |
| **optimization** | Working correctly, but improvable (comment, structure, dead branch). |
| **no-action** | Investigated, deliberate deviation or matches KP — justification recorded. |

Each must-fix / optimization row gets a resolving commit SHA once landed.

## 1. Grep sweep

Commands run and results captured at plan T2:

(filled in T2)

## 2. Per-file findings

### 2.1 `src/uaccess.c` ↔ `ref/KernelPatch/kernel/patch/common/utils.c`
(filled in T3)

### 2.2 `src/platform/syscall.c` ↔ `ref/KernelPatch/kernel/patch/common/syscall.c`
(filled in T4)

### 2.3 `src/arch/arm64/transit.c` ↔ `ref/KernelPatch/kernel/base/hook.c`
(filled in T5)

### 2.4 `src/arch/arm64/inline.c::write_insts_via_alias` ↔ `ref/KernelPatch/kernel/base/hotpatch.c`
(filled in T6)

### 2.5 `src/arch/arm64/pgtable.c` + `include/arch/arm64/pgtable.h` ↔ `ref/KernelPatch/kernel/include/pgtable.h`
(filled in T7)

### 2.6 `tests/kmod/test_phase6_kh_root.c` ↔ `ref/KernelPatch/kernel/patch/common/sucompat.c`
(filled in T8)

## 3. Resolution tracker

| ID | File | Class | Summary | Commit |
| -- | ---- | ----- | ------- | ------ |
| -  | -    | -     | -       | -      |

(rows appended as audit tasks fill the sections above)

## 4. Device verification

`scripts/test.sh device` run log excerpt (filled in T final task).
