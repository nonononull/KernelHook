# Architecture

This document describes the internal architecture of KernelHook, with a focus on the
Strategy Registry subsystem introduced in SP-7. For the public API surface, see
[`docs/en/api-reference.md`](api-reference.md). For build modes, see
[`docs/en/build-modes.md`](build-modes.md).

The SP-7 detailed design lives in
[`docs/superpowers/specs/2026-04-16-single-ko-unified-version-compat-design.md`](../superpowers/specs/2026-04-16-single-ko-unified-version-compat-design.md)
§5; this chapter is the publicly readable summary mandated by §5.9 criterion (6).

---

## Overview

KernelHook targets Android GKI kernels from 4.4 through 6.12 on arm64. Across that
range, kernel internals shift in ways that break any single resolution path:

- Symbols are renamed (`_copy_to_user` vs `copy_to_user` vs `__arch_copy_to_user`).
- Symbols disappear entirely on some builds (e.g. `swapper_pg_dir` is not exported on
  all GKI variants).
- Struct layouts change (`struct pt_regs`, `struct module`, `thread_size`).
- Compile-time constants that were stable across older kernels diverge at 5.10 and 6.1.

A single hard-coded resolution strategy fails silently on some kernel generation and
causes subtle bugs that are difficult to reproduce. The Strategy Registry is the
framework-level answer: every capability has multiple independent resolution strategies,
tried in priority order, with the result cached after the first success.

---

## Strategy Registry

### Why It Exists

The core problem is **kernel symbol drift across GKI 4.4 through 6.12**. Any single
resolution path — a direct `ksyms_lookup`, a compile-time extern, or a hard-coded
offset — breaks on at least one kernel generation. Examples:

- `swapper_pg_dir` is exported on 5.15 GKI but absent from some 6.1 configurations.
- `kimage_voffset` exists on all known builds but reading it requires the symbol to
  be present and the VA-PA offset to be sane — neither is guaranteed after live patching.
- `pt_regs_size = 0x150` was correct for all tested GKI 5.x/6.x builds at time of
  writing, but is not contractually stable and has already differed on 4.4 kernels.

The defense is **multiple fallback strategies per capability + a consistency-check mode**:

1. Each capability registers N ordered strategies at link time.
2. `kh_strategy_resolve` walks them by priority, caches the first success.
3. Failures are logged explicitly; silent wrong guesses are rejected.
4. `kh_consistency_check=1` runs every strategy and taints on mismatch — catching
   strategy drift before it causes a production panic.

### ELF-section Registration

Each strategy is a `struct kh_strategy` placed into the `.kh_strategies` ELF section
at link time using `KH_STRATEGY_DECLARE`:

```c
/* include/kh_strategy.h */

typedef int (*kh_strategy_fn_t)(void *out, size_t out_size);

struct kh_strategy {
    const char         *capability;  /* e.g. "swapper_pg_dir"   */
    const char         *name;        /* e.g. "kallsyms"         */
    int                 priority;    /* 0 = highest             */
    bool                enabled;     /* mutable at runtime      */
    kh_strategy_fn_t    resolve;
    size_t              out_size;
};

#define KH_STRATEGY_DECLARE(cap, nm, prio, fn, sz)                      \
    static struct kh_strategy __kh_strat_##cap##_##nm                   \
    __attribute__((used, section(".kh_strategies"))) = {                \
        .capability = #cap, .name = #nm, .priority = prio,             \
        .enabled = true, .resolve = fn, .out_size = (sz),              \
    }
```

The linker script exposes `__start___kh_strategies` and `__stop___kh_strategies`.
`kh_strategy_init()`, called from module init, iterates the section and builds a
per-capability priority-sorted linked list.

**Example — registering the `kallsyms` strategy for `swapper_pg_dir`:**

```c
/* src/strategies/swapper_pg_dir.c */

static int strat_swapper_kallsyms(void *out, size_t sz)
{
    void *addr = ksyms_lookup("swapper_pg_dir");
    if (!addr)
        return -ENOENT;
    *(void **)out = addr;
    return 0;
}

KH_STRATEGY_DECLARE(swapper_pg_dir, kallsyms, 0, strat_swapper_kallsyms, sizeof(void *));
```

### Resolution Algorithm

`kh_strategy_resolve(cap, &out, sizeof(out))` implements the following logic:

```
kh_strategy_resolve(cap, out, out_size):
    if cached[cap] is valid:
        *out = cached[cap]; return 0
    if in_flight[cap]:
        return -EDEADLK          /* recursive cycle detected */
    in_flight[cap] = true
    if kh_force_map[cap] is set:
        r = strategies[cap][kh_force_map[cap]].resolve(out, out_size)
        goto done
    for each strategy in strategies[cap] sorted by priority:
        if !strategy.enabled: continue
        if kh_inject_fail_map[cap][strategy.name] > 0:
            kh_inject_fail_map[cap][strategy.name]--
            continue             /* inject artificial failure */
        r = strategy.resolve(out, out_size)
        if r == 0:
            cached[cap] = *out
            break
    r = (r == 0) ? 0 : -ENODATA
done:
    in_flight[cap] = false
    return r
```

**Recursive dependencies** are handled correctly. Some strategies depend on another
capability being resolved first (e.g. `swapper_pg_dir:ttbr1_walk` needs `memstart_addr`;
`kimage_voffset:text_va_minus_pa` needs `swapper_pg_dir`). Such strategies call
`kh_strategy_resolve(dep_cap, ...)` internally. The `in_flight` set detects cycles and
returns `-EDEADLK`, causing the calling strategy to be skipped. Results are cached after
first success, so each capability is resolved at most once.

### Runtime Controls

Four mechanisms allow per-strategy control without recompilation. All accept CSV
`capability:strategy_name` pairs.

**Module parameters** (passed at `insmod`):

| Parameter | Effect |
|---|---|
| `kh_disable="cap:name,..."` | Disable named strategies at load time |
| `kh_enable="cap:name,..."` | Re-enable strategies previously disabled |
| `kh_force="cap:name,..."` | Bypass priority ordering, pin a specific strategy |
| `kh_inject_fail="cap:name:count,..."` | Force the strategy to fail the next `count` calls |
| `kh_consistency_check=1` | Run all enabled strategies and compare results at init |

**debugfs** (under `/sys/kernel/debug/kernelhook/`):

| File | Operation | Semantics |
|---|---|---|
| `strategies` | read | Tabular listing: (cap, name, prio, enabled, last-winner, last-value) |
| `disable` | write | `"cap:name"` — disable a strategy at runtime |
| `enable` | write | `"cap:name"` — re-enable |
| `force` | write | `"cap:name"` to pin; `"cap:"` to clear |
| `consistency_last` | read | JSON-like result of the most recent consistency run |

debugfs entries are compiled in only when `CONFIG_DEBUG_FS=y` (or
`KMOD_FREESTANDING`). They are observability and test interfaces only; they are not
on the capability resolution critical path.

### Consistency-Check Mode

When `kh_consistency_check=1` is passed at load time:

1. Module init runs **every enabled strategy** for each capability, not just the
   highest-priority one.
2. All successful results are compared against each other.
3. Any mismatch triggers `WARN` + `add_taint(TAINT_CRAP)`.
4. The full result table is written to debugfs `consistency_last` for automated
   assertion by the test harness.

Overhead is bounded: roughly N `ksyms_lookup` calls per capability (N = 2–4), estimated
at under 50 ms total for all 12 capabilities. Consistency check runs in CI by default
(`scripts/test_avd_kmod.sh` and `scripts/test_device_kmod.sh` both pass
`kh_consistency_check=1` to insmod).

### Error Semantics

When all strategies for a capability fail, the behavior depends on criticality tier:

- **Tier 1 (fatal)**: module init returns `-ENOENT` and prints a full attempt table:
  ```
  [kh] FATAL: cannot resolve 'swapper_pg_dir'
  [kh]   strategy kallsyms       : -ENOENT (symbol not in /proc/kallsyms)
  [kh]   strategy init_mm_pgd    : -EINVAL (init_mm.pgd offset probe failed)
  [kh]   strategy ttbr1_walk     : -ENOTSUPP (memstart_addr unresolved)
  [kh]   strategy pg_end_anchor  : -ENOENT (swapper_pg_end not in kallsyms)
  ```
- **Tier 2 (non-fatal)**: a kernel warning is printed, the result is recorded in sysfs,
  and the module continues to load with degraded functionality.

Silent wrong guesses are never accepted — the framework logs every attempt and its
specific failure reason.

---

## Capability Table

The following 12 capabilities are registered in SP-7. Each has its own source file
under `src/strategies/`.

| Capability | Strategies (priority order) | Purpose |
|---|---|---|
| `swapper_pg_dir` | kallsyms, init_mm_pgd, ttbr1_walk, pg_end_anchor | Kernel PGD for page-table walks |
| `kimage_voffset` | kallsyms, text_va_minus_pa, loader_inject | Kernel VA-PA delta |
| `memstart_addr` | kallsyms, dtb_parse, dma_phys_limit | DRAM base physical address |
| `init_cred` | kallsyms_init_cred, current_task_walk, init_task_walk | Kernel init credential pointer |
| `init_thread_union` | kallsyms_init_thread_union, kallsyms_init_stack, current_task_stack | Init-task stack base VA |
| `thread_size` | const_default (16384), probe_from_current_task | Kernel stack size (const_default prio 0: probe over-detects 32K on 32K-aligned stacks) |
| `pt_regs_size` | probe_from_current_task, const_default (0x150) | `struct pt_regs` size |
| `copy_to_user` | _copy_to_user, copy_to_user, \_\_arch_copy_to_user, inline_ldtr_sttr | User-dest copy function pointer |
| `copy_from_user` | _copy_from_user, copy_from_user, \_\_arch_copy_from_user, inline_ldtr | User-src copy function pointer |
| `stop_machine` | kallsyms_stop_machine, smp_call_function_many | Quiesce-all-CPUs function pointer |
| `aarch64_insn_patch_text_nosync` | kallsyms, inline_alias_patch | Kernel text patcher |
| `register_ex_table` | probe_extable, give_up | Fault-fixup registration gate for inline uaccess |

For the inline uaccess strategies (`copy_to_user:inline_ldtr_sttr` and
`copy_from_user:inline_ldtr`), the `register_ex_table` capability is a hard prerequisite:
the inline implementation installs a module-level exception table entry to catch page
faults, and `register_ex_table` must succeed before the inline strategy is considered
viable.

---

## Testing Layers

The strategy subsystem has three test layers, all driven through `scripts/test.sh`.

### L1 — Userspace Unit Tests

Location: `tests/userspace/test_strategy_*.c`

These tests run on the development host (macOS or Linux) via ctest. They mock the
strategy registry, task-struct layout, `__ksymtab` boundaries, and DTB packets to
verify pure logic: registration semantics, priority ordering, disable/force/inject,
cycle detection, and the consistency-check comparison algorithm.

```bash
cmake -B build_debug -DCMAKE_BUILD_TYPE=Debug
cmake --build build_debug
(cd build_debug && ctest -R test_strategy)
```

### L2 — In-Kernel Single-Strategy Coverage

Location: `tests/kmod/test_resolver_<cap>.c`

Each file tests one capability inside a single `insmod` cycle on a real or emulated
kernel:

1. Record the "natural" result (highest-priority strategy winner) as the group golden.
2. `kh_strategy_force(cap, name)` over each enabled strategy, assert result matches golden.
3. `kh_strategy_inject_fail(cap, name, 1)` for each strategy, verify the next strategy
   takes over.
4. Negative assertion: `kh_strategy_force(cap, "not_exist")` must return `-ENODATA`.
5. All assertions pass → dmesg prints `[test_resolver_X] PASS`.

L2 runs as part of `scripts/test.sh avd` and `scripts/test.sh device`.

### L3 — Golden Matrix (Strategy Survival + Value Reconciliation)

Location: `tests/golden/strategy_matrix/`

`scripts/test.sh strategy-matrix` loads `kernelhook.ko` with `kh_consistency_check=1`
on each available AVD and real device, reads
`/sys/kernel/debug/kernelhook/strategies` and `consistency_last`, and compares the
output against checked-in golden files:

| Artifact | Path | Contents |
|---|---|---|
| Per-device values | `values/<avd-id>.yaml` | Per-strategy resolved value + ok/errno |
| Survival matrix | `survival.tsv` | Y/N for every (device, capability, strategy) triple |
| Consistency log | `consistency_runs.log` | Append-only log; one line per CI run |
| Expectations | `expectations.yaml` | Declared expectation type per capability |
| Workflow guide | `README.md` | How to update goldens when adding AVDs or strategies |

Three reconciliation levels run in order:

1. **Consistency pass** — no `TAINT_CRAP` in dmesg for any capability.
2. **Golden diff** — `values/<avd>.yaml` matches checked-in golden byte-for-byte
   (modulo `run_metadata`).
3. **Expectations validation** — every capability satisfies its declared expectation
   type (`scalar_all_strategies_equal`, `function_pointer_any_valid`, etc.).

Return codes: `0` = PASS; `1` = DRIFT (golden mismatch, human review needed);
`2` = FAIL (expectations rule violated).

To update goldens after a new strategy is added or an AVD is changed:

```bash
scripts/test.sh strategy-matrix --accept <avd-id>   # update one device's golden
scripts/test.sh strategy-matrix --dump <avd-id>     # print fresh yaml without writing
scripts/test.sh strategy-matrix                     # check all without update
```

### Known failing L2 tests (SP-7 follow-ups)

Two L2 resolver tests currently FAIL on the Pixel_35 AVD baseline and are tracked
as follow-up work rather than release blockers:

- `test_resolver_swapper_pg_dir` — the `init_mm_pgd` walker heuristic
  (first-match 8-byte-aligned scan of `init_mm`) is too loose on GKI 6.6 and
  returns a value that disagrees with the kallsyms natural winner. `kallsyms`
  prio 0 still resolves correctly; only the inter-strategy consistency check
  fails. See SP-7 open_questions task-9.
- `test_resolver_cred` — `walk_task_for_cred`'s (usage, uid) heuristic finds
  a false-positive inside `init_task` on GKI 6.6 task_struct layout. Same
  containment: kallsyms prio 0 works; consistency check flags the disagreement.
  See SP-7 open_questions task-12.

Neither bug affects production use (the working kallsyms prio 0 always wins).
Both must be resolved before §5.9 exit criterion (1) can be fully closed.

---

## Adding a New Capability

Follow these steps to extend the registry with a new capability.

### 1. Implement the strategy functions

Create `src/strategies/<name>.c`. Each strategy function must match
`kh_strategy_fn_t` and use `KH_STRATEGY_DECLARE` to register itself:

```c
/* src/strategies/my_cap.c */
#include <kh_strategy.h>

static int strat_my_cap_kallsyms(void *out, size_t sz)
{
    void *addr = ksyms_lookup("my_kernel_symbol");
    if (!addr)
        return -ENOENT;
    *(void **)out = addr;
    return 0;
}

/* Priority 0 = tried first */
KH_STRATEGY_DECLARE(my_cap, kallsyms, 0, strat_my_cap_kallsyms, sizeof(void *));

static int strat_my_cap_fallback(void *out, size_t sz)
{
    /* alternative resolution logic */
    return -ENOENT;
}

KH_STRATEGY_DECLARE(my_cap, fallback, 1, strat_my_cap_fallback, sizeof(void *));
```

Provide at least two strategies. The primary strategy should be the most reliable
(usually `ksyms_lookup`); the fallback should be fully independent of the primary.

### 2. Add the expectation declaration

Add an entry to `tests/golden/strategy_matrix/expectations.yaml`:

```yaml
my_cap:   { type: scalar_all_strategies_equal }
# or:     { type: function_pointer_any_valid }
# or:     { type: probed_may_vary, allowed: [4096, 8192, 16384] }
```

Choose the expectation type that matches the capability's semantics (see the
expectation type table in the SP-7 design spec §5.10.2).

### 3. Write an L2 in-kernel test

Create `tests/kmod/test_resolver_<name>.c` following the pattern in
`tests/kmod/test_resolver_swapper_pg_dir.c`. The test should exercise
force/inject/negative cases for each registered strategy.

### 4. Wire into the build system

Four locations need updating:

- `CMakeLists.txt` — add `src/strategies/<name>.c` to the userspace test build (for
  mock-based L1 tests).
- `kmod/mk/kmod.mk` — add `src/strategies/<name>.c` to the freestanding and SDK
  kernel-module builds.
- `tests/kmod/Kbuild` and `tests/kmod/Makefile` — include the new L2 test source.
- `tests/kmod/test_main.c` — register the new L2 test section.

### 5. Regenerate goldens

Run the new strategy against a connected device or AVD and accept the results:

```bash
scripts/test.sh strategy-matrix --accept <device-serial>
```

Commit the updated `values/<device>.yaml`, `survival.tsv`, and
`consistency_runs.log`.

---

## Source Layout Reference

| Path | Contents |
|---|---|
| `include/kh_strategy.h` | Registry API: `kh_strategy_resolve`, `KH_STRATEGY_DECLARE`, control functions |
| `src/kh_strategy.c` | Registry implementation, module parameters, debugfs entries |
| `src/strategies/swapper_pg_dir.c` | Four strategies for `swapper_pg_dir` |
| `src/strategies/kimage_voffset.c` | Three strategies for `kimage_voffset` |
| `src/strategies/memstart_addr.c` | Three strategies for `memstart_addr` |
| `src/strategies/cred_task.c` | Strategies for `init_cred`, `init_thread_union`, `thread_size` |
| `src/strategies/uaccess_copy.c` | Strategies for `copy_to_user`, `copy_from_user`, `register_ex_table` |
| `src/strategies/cross_cpu.c` | Strategies for `stop_machine`, `aarch64_insn_patch_text_nosync` |
| `src/strategies/runtime_sizes.c` | Strategies for `pt_regs_size` |
| `tests/userspace/test_strategy_*.c` | L1 mock-based unit tests |
| `tests/kmod/test_resolver_*.c` | L2 in-kernel per-capability tests |
| `tests/golden/strategy_matrix/` | L3 golden artifacts and expectation declarations |
| `scripts/lib/strategy_matrix.sh` | dump / check / accept helpers |
