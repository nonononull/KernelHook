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

### 1.1 Explicit attribution (`grep "KernelPatch|ported from|mirrors|KP\\b"`)

````
src/platform/syscall.c:5: * Syscall-level hook infrastructure — port of KernelPatch
src/platform/syscall.c:74:/* ---- Name table (ported verbatim from KP sysname.c, 64-bit only) ---- */
src/arch/arm64/pgtable.c:231: * Mirrors KernelPatch kernel/base/start.c:176-202. Handles mid-level
src/arch/arm64/inline.c:373: * Mirrors KernelPatch kernel/base/hotpatch.c. vmalloc'd at init;
src/arch/arm64/inline.c:586:     * This is the KernelPatch approach — works on all kernels
src/arch/arm64/inline.c:611:    /* Primary: alias-page + aarch64_insn_patch_text_nosync (KP path).
src/uaccess.c:5: * User-pointer helpers. Trimmed port of KernelPatch
src/uaccess.c:100:         * is already the NUL. Adjust to include NUL to match KP. */
tests/kmod/test_phase6_kh_root.c:6: * Mirrors ref/KernelPatch/kernel/patch/common/sucompat.c, simplified:
tests/kmod/test_phase6_kh_root.c:22: *   3. KernelPatch's sucompat.c uses inline hooks on __arm64_sys_<name>
include/syscall_names.h:6: * ref/KernelPatch/kernel/patch/common/sysname.c:syscall_name_table,
include/syscall_names.h:21:/* Table capacity — matches KernelPatch (covers __NR_cachestat = 451). */
include/uaccess.h:5: * KernelHook user-pointer helpers — trimmed port of KernelPatch
include/uaccess.h:30: * bytes copied INCLUDING the NUL terminator on success (KP semantics),
include/arch/arm64/pgtable.h:116:/* Flush TLB for a single kernel VA. Matches KernelPatch
include/syscall.h:6: * ref/KernelPatch/kernel/patch/common/syscall.c, 64-bit only
kmod/shim/include/asm/set_memory.h:4: * Forwards to linux/set_memory.h (mirrors kernel's pre-5.8 layout).
````

### 1.2 KP-API footprints

````
src/platform/syscall.c:438:            addr = (uintptr_t)ksyms_lookup(buf);
src/platform/syscall.c:629:        (uintptr_t *)(uintptr_t)ksyms_lookup("sys_call_table");
src/platform/syscall.c:631:        ksyms_lookup("__arm64_sys_openat") ? 1 : 0;
src/sync.c:61:    _rcu_read_lock = (void (*)(void))ksyms_lookup("rcu_read_lock");
src/sync.c:63:        _rcu_read_lock = (void (*)(void))ksyms_lookup("__rcu_read_lock");
src/sync.c:69:    _rcu_read_unlock = (void (*)(void))ksyms_lookup("rcu_read_unlock");
src/sync.c:71:        _rcu_read_unlock = (void (*)(void))ksyms_lookup("__rcu_read_unlock");
src/sync.c:77:    _synchronize_rcu = (void (*)(void))ksyms_lookup("synchronize_rcu");
src/sync.c:83:    _raw_spin_lock_fn = (void (*)(void *))ksyms_lookup("_raw_spin_lock");
src/sync.c:89:    _raw_spin_unlock_fn = (void (*)(void *))ksyms_lookup("_raw_spin_unlock");
src/arch/arm64/pgtable.c:69:    flush_tlb_kernel_page = (flush_tlb_kernel_page_func_t)(uintptr_t)ksyms_lookup("flush_tlb_kernel_page");
src/arch/arm64/pgtable.c:70:    flush_tlb_kernel_range = (flush_tlb_kernel_range_func_t)(uintptr_t)ksyms_lookup("flush_tlb_kernel_range");
src/arch/arm64/pgtable.c:71:    flush_icache_all = (flush_icache_all_func_t)(uintptr_t)ksyms_lookup("flush_icache_all");
src/arch/arm64/pgtable.c:72:    flush_icache_range = (flush_icache_range_func_t)(uintptr_t)ksyms_lookup("flush_icache_range");
src/arch/arm64/pgtable.c:73:    __flush_dcache_area = (flush_dcache_area_func_t)(uintptr_t)ksyms_lookup("__flush_dcache_area");
src/arch/arm64/pgtable.c:76:        __flush_dcache_area = (flush_dcache_area_func_t)(uintptr_t)ksyms_lookup("dcache_clean_inval_poc");
src/arch/arm64/pgtable.c:90:    uint64_t *voffset_ptr = (uint64_t *)(uintptr_t)ksyms_lookup("kimage_voffset");
src/arch/arm64/pgtable.c:107:    uint64_t *memstart_ptr = (uint64_t *)(uintptr_t)ksyms_lookup("memstart_addr");
src/arch/arm64/pgtable.c:118:    kernel_pgd = ksyms_lookup("swapper_pg_dir");
src/arch/arm64/inline.c:375: * text's physical page, we call aarch64_insn_patch_text_nosync
src/arch/arm64/inline.c:388: * aarch64_insn_patch_text_nosync to write to the wrong target. */
src/arch/arm64/inline.c:430:extern int aarch64_insn_patch_text_nosync(void *addr, u32 insn);
src/arch/arm64/inline.c:437:    kh_vmalloc = (vmalloc_fn_t)(uintptr_t)ksyms_lookup("vmalloc");
src/arch/arm64/inline.c:438:    kh_vfree = (vfree_fn_t)(uintptr_t)ksyms_lookup("vfree");
src/arch/arm64/inline.c:440:        ksyms_lookup("aarch64_insn_patch_text_nosync");
src/arch/arm64/inline.c:445:        aarch64_insn_patch_text_nosync;
src/arch/arm64/inline.c:527:    kh_set_memory_rw = (set_memory_fn_t)(uintptr_t)ksyms_lookup("set_memory_rw");
src/arch/arm64/inline.c:528:    kh_set_memory_ro = (set_memory_fn_t)(uintptr_t)ksyms_lookup("set_memory_ro");
src/arch/arm64/inline.c:529:    kh_set_memory_x  = (set_memory_fn_t)(uintptr_t)ksyms_lookup("set_memory_x");
src/arch/arm64/inline.c:531:        kh_set_memory_x = (set_memory_fn_t)(uintptr_t)ksyms_lookup("set_memory_exec");
src/arch/arm64/inline.c:611:    /* Primary: alias-page + aarch64_insn_patch_text_nosync (KP path).
src/arch/arm64/inline.c:612:     * aarch64_insn_patch_text_nosync handles icache internally. */
src/symbol.c:23:uint64_t ksyms_lookup(const char *name)
src/uaccess.c:94:        /* kernel's strncpy_from_user() never returns > count, but
src/uaccess.c:178:    uintptr_t init_task_addr = (uintptr_t)ksyms_lookup("init_task");
src/uaccess.c:185:    uintptr_t init_cred_addr = (uintptr_t)ksyms_lookup("init_cred");
src/uaccess.c:201:    uintptr_t init_stack_addr = (uintptr_t)ksyms_lookup("init_thread_union");
src/uaccess.c:203:        init_stack_addr = (uintptr_t)ksyms_lookup("init_stack");
src/uaccess.c:229:        ksyms_lookup("strncpy_from_user");
src/uaccess.c:238:        ksyms_lookup("_copy_to_user");
src/uaccess.c:241:            ksyms_lookup("copy_to_user");
src/uaccess.c:244:            ksyms_lookup("__arch_copy_to_user");
src/uaccess.c:246:    /* In kbuild, strncpy_from_user / copy_to_user may be macros that
src/uaccess.c:250:    kh_strncpy_from_user_fn = (kh_strncpy_from_user_fn_t)&strncpy_from_user;
src/uaccess.c:254:    pr_info("uaccess: strncpy_from_user=%llx copy_to_user=%llx\n",
tests/kmod/test_phase6_kh_root.c:58:/* Kernel 6.1 signature: struct cred *prepare_kernel_cred(struct task_struct *).
tests/kmod/test_phase6_kh_root.c:139:        ksyms_lookup("prepare_kernel_cred");
tests/kmod/test_phase6_kh_root.c:141:        ksyms_lookup("commit_creds");
tests/kmod/test_phase6_kh_root.c:143:        pr_warn("kh_root: prepare_kernel_cred=%llx commit_creds=%llx -- "
tests/kmod/log.c:61:    kh_vprintk_func = (vprintk_func_t)(uintptr_t)ksyms_lookup("vprintk");
tests/kmod/export_link_test/importer.c:6: * references hook_wrap + ksyms_lookup as undefined symbols that the running
tests/kmod/export_link_test/importer.c:21:extern uint64_t ksyms_lookup(const char *name);
tests/kmod/export_link_test/importer.c:30:    uint64_t addr = ksyms_lookup("vfs_open");
tests/kmod/export_link_test/exporter.c:8: * (hook_wrap, ksyms_lookup, ...) that Ring 2's verify_elf.sh checks.
tests/kmod/export_link_test/exporter.c:11: * importer.ko later calls ksyms_lookup("do_sys_openat2") it resolves to a
tests/kmod/export_link_test/verify_elf.sh:76:assert_symbol  importer.ko ksyms_lookup
tests/kmod/test_phase6_kh_root.h:7: * required symbols (prepare_kernel_cred, commit_creds) unresolvable. */
tests/kmod/test_main.c:294:    /* 7. uaccess helpers — resolve strncpy_from_user/copy_to_user +
tests/kmod/test_main.c:435:     * These tests resolve real kernel functions via ksyms_lookup() and
tests/kmod/mem_ops.c:14: *   KMOD_FREESTANDING:    resolves all symbols via ksyms_lookup() at runtime
tests/kmod/mem_ops.c:52:    uint64_t addr = ksyms_lookup(fb->primary);
tests/kmod/mem_ops.c:54:        addr = ksyms_lookup(fb->fallback);
tests/kmod/test_hook_kernel.c:70: * ksyms_lookup so that Phase 5d concurrency tests can run without
tests/kmod/test_hook_kernel.c:81: * resolve them via ksyms_lookup and call through function pointers instead. */
tests/kmod/test_hook_kernel.c:107:        ksyms_lookup("kthread_create_on_node");
tests/kmod/test_hook_kernel.c:109:        ksyms_lookup("wake_up_process");
tests/kmod/test_hook_kernel.c:111:        ksyms_lookup("kthread_stop");
tests/kmod/test_hook_kernel.c:112:    _msleep = (msleep_fn_t)(uintptr_t)ksyms_lookup("msleep");
tests/kmod/test_hook_kernel.c:114:        ksyms_lookup("synchronize_rcu");
tests/kmod/test_hook_kernel.c:115:    _schedule = (schedule_fn_t)(uintptr_t)ksyms_lookup("schedule");
tests/kmod/test_hook_kernel.c:117:        ksyms_lookup("kthread_should_stop");
tests/kmod/test_hook_kernel.c:543:    func_addr = ksyms_lookup("do_faccessat");
tests/kmod/test_hook_kernel.c:602:    func_addr = ksyms_lookup("do_faccessat");
tests/kmod/test_hook_kernel.c:691: * Each test resolves a real kernel function via ksyms_lookup(),
tests/kmod/test_hook_kernel.c:751:    uint64_t func_addr = ksyms_lookup("__arm64_sys_getpid");
tests/kmod/test_hook_kernel.c:823:    uint64_t func_addr = ksyms_lookup("do_faccessat");
tests/kmod/test_hook_kernel.c:925:    uint64_t func_addr = ksyms_lookup("do_filp_open");
tests/kmod/test_hook_kernel.c:981:    uint64_t vfs_read_addr  = ksyms_lookup("vfs_read");
tests/kmod/test_hook_kernel.c:982:    uint64_t vfs_write_addr = ksyms_lookup("vfs_write");
tests/kmod/test_hook_kernel.c:1078:    uint64_t func_addr = ksyms_lookup("do_faccessat");
tests/kmod/test_hook_kernel.c:1202:    func_addr = ksyms_lookup("do_faccessat");
tests/kmod/test_hook_kernel.c:1301:    func_addr = ksyms_lookup("do_faccessat");
tests/kmod/test_hook_kernel.c:1348: * headers; in freestanding mode they are resolved via ksyms_lookup
tests/kmod/test_hook_kernel.c:1472:    uint64_t func_addr = ksyms_lookup("__arm64_sys_getpid");
````

### 1.3 Files in scope

Spec §4 enumerates six files. Sweep result:

| File | In spec | Present in sweep |
|------|---------|------------------|
| src/uaccess.c | ✅ | ✅ |
| src/platform/syscall.c | ✅ | ✅ |
| src/arch/arm64/transit.c | ✅ | ❌ |
| src/arch/arm64/inline.c | ✅ | ✅ |
| src/arch/arm64/pgtable.c | ✅ | ✅ |
| tests/kmod/test_phase6_kh_root.c | ✅ | ✅ |

Note on `src/arch/arm64/transit.c` (❌ in sweep): the file carries no KP attribution
comment and none of the KP-API footprint identifiers appear in its body. It was derived
from KP `kernel/base/hook.c` (the RCU-snapshot transit dispatch pattern) but that
provenance is implicit. It is correctly in scope for the audit at T5 despite the sweep
miss — the sweep is not exhaustive; T5 covers it by direct code comparison.

Extra sites discovered by sweep:

| File | Reason appeared | Classification |
|------|----------------|----------------|
| `include/arch/arm64/pgtable.h` | KP attribution comment (TLB flush sequence) | noise — header companion to `src/arch/arm64/pgtable.c`; covered under §2.5 |
| `include/syscall.h` | KP attribution comment (syscall infra header) | noise — header companion to `src/platform/syscall.c`; covered under §2.2 |
| `include/syscall_names.h` | KP attribution comment (sysname.c table) | noise — header companion to `src/platform/syscall.c`; covered under §2.2 |
| `include/uaccess.h` | KP attribution comment (uaccess port header) | noise — header companion to `src/uaccess.c`; covered under §2.1 |
| `kmod/shim/include/asm/set_memory.h` | "mirrors" keyword in comment describing kernel pre-5.8 header layout | noise — not KP-derived; comment describes kernel layout, not a KP port |
| `src/symbol.c` | Defines `ksyms_lookup()` itself | noise — this is the KH symbol-lookup implementation, not a KP-derived file |
| `src/sync.c` | Uses `ksyms_lookup()` to resolve RCU/spinlock symbols | noise — uses the KH API; not KP-derived code; no audit task needed |
| `tests/kmod/export_link_test/exporter.c` | "ksyms_lookup" in comment describing SDK ABI | noise — test fixture documenting the exported API; not KP-derived |
| `tests/kmod/export_link_test/importer.c` | Calls `ksyms_lookup("vfs_open")` to exercise SDK export | noise — test fixture; not KP-derived |
| `tests/kmod/export_link_test/verify_elf.sh` | Asserts `ksyms_lookup` symbol present in importer.ko | noise — test script; not KP-derived |
| `tests/kmod/log.c` | Calls `ksyms_lookup("vprintk")` | noise — logging helper; not KP-derived |
| `tests/kmod/mem_ops.c` | Calls `ksyms_lookup()` for memory-op symbol resolution | noise — generic helper; not KP-derived |
| `tests/kmod/test_hook_kernel.c` | Heavy use of `ksyms_lookup()` throughout test suite | noise — test code using the KH API; not KP-derived |
| `tests/kmod/test_main.c` | "strncpy_from_user" and "ksyms_lookup" in comments | noise — test orchestrator referencing API names; not KP-derived |
| `tests/kmod/test_phase6_kh_root.h` | `prepare_kernel_cred` / `commit_creds` in guard comment | noise — companion header for `test_phase6_kh_root.c`; covered under §2.6 |

Summary: 0 extra sites need a new audit task. All 15 extra hits are noise (header companions,
the `ksyms_lookup` implementation itself, or test code that calls the KH API without
containing KP-ported logic).

## 2. Per-file findings

### 2.1 `src/uaccess.c` ↔ `ref/KernelPatch/kernel/patch/common/utils.c`

Diff reviewed: `src/uaccess.c` is a deliberately trimmed port. KP `utils.c` covers a much
broader surface (trace_seq / seq_buf copy helpers, random, `_task_pt_reg` with pre-5.10
`pt_regs` size variants). Our port retains only what Phase 5b / Phase 6 callers need.

| # | Site | Delta | Class | Rationale |
|---|------|-------|-------|-----------|
| 3.1 | `kh_cred_uid_offset = 4` (hardcoded) | KP resolves via `cred_offset.uid_offset` at runtime (set by pre-data layer); we hardcode. | **no-action** | Empirically confirmed on Pixel 6 GKI 6.1: `init_cred=%llx cred_uid@+4 = 0` — offset 4 is correct. `struct cred` starts with `atomic_t usage` (4 bytes on all LP64 targets from 4.4 to 6.12), so uid sits at offset 4. No GKI kernel has upgraded `usage` to `atomic_long_t`. Hardcoding eliminates an unnecessary runtime scan over `init_cred`. |
| 3.2 | `rc++` in `kh_strncpy_from_user` | Identical to KP `compat_strncpy_from_user` lines 110–117. | **no-action** | Behavior is intentional: return length INCLUDING the NUL terminator to match KP semantics (documented in `include/uaccess.h`). The `rc >= count` guard is defensive — kernel guarantees `rc <= count` but the guard is cheap and mirrors KP exactly. |
| 3.3 | `probe_pointer_offset(base, target, 0x1000)` walk range | KP uses a predata struct (compile-time layout resolver), not runtime probing. Our port probes at init. | **no-action** | Empirically confirmed on Pixel 6 GKI 6.1: `task_struct.cred offset = 0x830` and `task_struct.stack offset = 0x38` — both well within the 0x1000 upper bound. Even on CONFIG_NUMA_BALANCING=y or DEBUG_PREEMPT kernels that extend task_struct, the cred pointer is within the first 0x1000 bytes (Linux `task_struct` layout has always placed `cred` in early fields). |
| 3.4 | `kh_copy_to_user` 3-way fallback chain (`_copy_to_user` → `copy_to_user` → `__arch_copy_to_user`) vs KP's 4-way (`xt_data_to_user` → `seq_buf_to_user` → `bits_to_user` → `trace_seq_to_user`) | Different fallback axis. | **no-action** | KP's chain works around the lack of a direct `copy_to_user` export on older/patched kernels by exploiting auxiliary functions with compatible copy semantics. GKI 5.10+ exports `_copy_to_user` or `__arch_copy_to_user` directly. Our 3-way chain hits on the first symbol present; GKI 6.1 resolves `_copy_to_user` on the first try. No correctness gap for our callers. |

**Device empirical data (Pixel 6, GKI 6.1.99-android14, freestanding mode):**
- `uaccess-audit: init_cred=ffffffe68a1e12a8 cred_uid@+4 = 0 (expect 0)`
- `uaccess: task_struct.cred offset = 0x830`
- `uaccess: task_struct.stack offset = 0x38 (probed)`

### 2.2 `src/platform/syscall.c` ↔ `ref/KernelPatch/kernel/patch/common/syscall.c`

Diff reviewed: our port strips compat/AArch32 branches, kstorage, `KP_EXPORT_SYMBOL`,
`link2runtime` name-table fixups, `fp_wrap_syscalln` / `hook_syscalln` (fp path),
`get_user_arg_ptr` / `set_user_arg_ptr`. Core logic retained: name-table caching,
wrapper detection, `kh_raw_syscallN` invocation path.

| # | Site | Delta | Class | Rationale |
|---|------|-------|-------|-----------|
| 4.1 | `regs.syscallno` not set in `kh_raw_syscallN` | KP sets both `regs.syscallno = nr` AND `regs.regs[8] = nr`; our port only sets `regs.regs[8]` via `KH_SYS_NR_FIELD`. Active callers exist in `tests/kmod/test_hook_kernel.c` (kh_raw_syscall0/1/3/4 used in Phase 5c/5d/kh_root tests). | **must-fix** | `syscallno` is the field the kernel syscall entry path reads for audit/tracing and ptrace interception. Missing it means any handler that inspects `regs->syscallno` instead of `regs->regs[8]` sees 0. Callers confirmed active (grep hit 8 call sites). Fixed: `regs.syscallno = (int32_t)nr;` added after `KH_SYS_NR_FIELD` in all 7 wrappers. Both fields present in `struct kh_pt_regs_shim` (line 55: `int32_t syscallno`) and kernel `struct pt_regs`. |
| 4.2 | No compat/AArch32 table or `compat_sys_call_table` | KP has full compat support (`compat_syscall_name_table`, `has_config_compat`, `compat_sys_call_table`). | **no-action** | Documented in file header: "64-bit only (no compat branches, no AArch32 table, no kstorage)." GKI Android targets are LP64-only in practice; AArch32 compat is not required for the current feature set. Deliberate deviation. |
| 4.3 | `kh_zero_regs` pre-zeros the `KH_PT_REGS` frame before field assignment | KP does NOT zero the struct — it assigns only `syscallno`, `regs[8]`, and argument registers, leaving all other fields uninitialised. | **no-action** | Our approach is strictly safer: no risk of stale stack values leaking into kernel entry path. Cost is negligible (one loop over ~200 bytes at inline-hook invocation frequency). Deliberate improvement over KP. |
| 4.4 | Name-table caching stores resolved address back into `kh_syscall_name_table[nr].addr` (monotonic; never invalidated) | Identical to KP `syscalln_name_addr` caching pattern. | **no-action** | Matches KP exactly. Safe because symbol addresses are stable for the kernel lifetime; modules that export `__arm64_sys_*` are built-in. No issue. |
| 4.5 | `kh_sys_call_table` resolved but never written through; `kh_hook_syscalln` uses inline hook exclusively | KP's `hook_syscalln` prefers `fp_wrap_syscalln` when `sys_call_table` is present. | **no-action** | Documented in CLAUDE.md "Syscall hooks" section and in the file header: `sys_call_table` is `__ro_after_init` on GKI ≥ 5.10 and kCFI in `invoke_syscall+0x50` rejects the fp-hook trampoline. `kh_sys_call_table` exported for diagnostic/discovery use only. Deliberate deviation from KP, justified by GKI constraints. |

### 2.3 `src/arch/arm64/transit.c` ↔ `ref/KernelPatch/kernel/base/hook.c`

Diff reviewed: KP upstream (`hook.c` lines 346–506 for inline transit, `fphook.c` lines
16–176 for fp transit) uses **no locking at all** — each transit function accesses
`hook_chain->states[i]`, `hook_chain->befores[i]`, `hook_chain->afters[i]`, and
`hook_chain->hook.relo_addr` directly across the full before+origin+after sequence, with no
critical section. KP's `fp_hook_unwrap` marks items as `CHAIN_ITEM_STATE_BUSY` then
`CHAIN_ITEM_STATE_EMPTY` but does not wait for in-flight transit calls, leaving a
window where `hook_mem_free` runs while a transit body is still executing.

Our port replaces all four transit functions (transit0/4/8/12 + fp_transit0/4/8/12) with a
single unified `transit_body` + `fp_transit_body`, using a single `sync_read_lock()` window
to snapshot `sorted_count`, `items[idx].{before,after,udata}`, and `rox->hook.relo_addr`
onto the stack, then releases the lock before calling origin. After-callbacks iterate the
stack snapshot — no second RCU window between origin and after-callbacks.

| # | Site | Delta | Class | Rationale |
|---|------|-------|-------|-----------|
| 5.1 | RCU-snapshot design in `transit_body` / `fp_transit_body` | KP has no RCU locking at all across the entire before+origin+after sequence; our port takes a single `sync_read_lock()` window, snapshots dispatch state to stack, then drops the lock before calling origin. No second lock window between origin and after-callbacks. | **no-action** | Fixes UAF: concurrent `hook_unwrap_remove` + `synchronize_rcu` + `hook_mem_free_rw/rox` races against in-flight transit in KP upstream. Our deviation is stress-validated at 27.8M calls × 67K add/remove in 3 seconds, zero Oops. Reintroducing a second `sync_read_lock` window between origin and after-callbacks would recreate the original bug (pre-commit e41e543). See CLAUDE.md "RCU snapshot in transit_body". |
| 5.2 | FPAC safety comment coverage | `transit_body` has a detailed FPAC-safety invariant comment block (lines 53–73) covering why the BLR to `relo_addr` is safe and what the SP stability requirement is. `fp_transit_body` has a shorter disclaimer at the `if (!fargs.skip_origin)` branch (lines 317–320) noting it is exempt from the inline-transit FPAC invariant because `origin_fp` enters at its natural entry point. Both comments are accurate and not contradictory. | **no-action** | `transit_body` calls relocated code that may begin with PACIASP (from the original function prologue) — SP stability is a real requirement and the comment explains why the compiler upholds it. `fp_transit_body` calls `origin_fp` at its natural entry point with its own PAC context; relocated-code PACIASP does not apply. Both coverage points are verified correct. |
| 5.3 | Stack budget per invocation | `transit_body`: snap[8]×24 = 192 B + snap_local[8]×32 = 256 B + hook_fargs12_t = 128 B + scalars ≈ 32 B = **608 bytes**. `fp_transit_body`: snap[16]×24 = 384 B + snap_local[16]×32 = 512 B + hook_fargs12_t = 128 B + scalars ≈ 16 B = **1040 bytes**. | **no-action** | Both well under the 4 KiB threshold; ARM64 kernel stack is 16 KiB. fp_transit_body uses FP_HOOK_CHAIN_NUM = 16 vs HOOK_CHAIN_NUM = 8 for inline transit, doubling the snapshot arrays, but the total remains well within budget. |

### 2.4 `src/arch/arm64/inline.c::write_insts_via_alias` ↔ `ref/KernelPatch/kernel/base/hotpatch.c`

Diff reviewed: KP's `hotpatch_nosync` is a single-instruction primitive. KP's `hotpatch()`
(lines 106–122) wraps a whole-trampoline multi-instruction write in `stop_machine(cpu_online_mask)`
via `hotpatch_cb` — the master CPU iterates `hotpatch_nosync` calls while all other CPUs yield
inside the stop_machine barrier. Our port originally omitted the stop_machine wrapper and
patched one instruction at a time via the alias page, each call guarded only by an internal
per-instruction lock (DAIF-disable spin in freestanding, `spin_lock_irqsave` in kbuild).

The key architectural question is whether ARMv8's 4-byte-aligned instruction-fetch atomicity
(ARM ARM B2.2.1 "Concurrent modification and execution of instructions") is sufficient on its
own. For a **single** 4-byte patch the answer is yes — another CPU observes either the old or
new word, never a torn value, and the kernel's own `aarch64_insn_hotpatch_safe()` allowlist
(B/BL/NOP/BKPT/SVC/HVC/SMC per arch/arm64 `patching.c:162`) confirms the single-instruction
safe set. For a **multi-instruction trampoline**, however, intermediate states during the
write sequence can fault.

Our non-BTI/PAC trampoline (`branch_absolute`, `src/arch/arm64/insn.c:26–33`) is 4 words:

```
tramp[0] = LDR X17, #8         ; load from tramp[2..3]
tramp[1] = BR  X17
tramp[2] = replace_addr_lo     ; data, interpreted as instruction if
tramp[3] = replace_addr_hi     ;       executed before BR X17 commits
```

`write_insts_via_alias` patches tramp[0]..tramp[3] sequentially through the alias page. Between
iterations, other CPUs see hybrid states:

- After write[0]: `LDR X17, #8 | orig[1] | orig[2] | orig[3]` — CPU loads X17 from orig[2]/orig[3]
  (random values) then falls through to orig[1], which then executes with a clobbered X17. If
  orig[1] references X17 (rare for a prologue, but legal), it uses garbage.
- After write[1]: `LDR X17, #8 | BR X17 | orig[2] | orig[3]` — CPU branches to orig[2]:orig[3]
  interpreted as a 64-bit address. This is almost always an invalid/non-executable address →
  synchronous abort.
- After write[2]: `LDR X17, #8 | BR X17 | replace_lo | orig[3]` — high half of the branch
  target still corrupt.

Arm's stock `aarch64_insn_patch_text()` (arch/arm64/kernel/patching.c:224–244) has the same
rule: when `cnt > 1`, it falls through to `aarch64_insn_patch_text_sync()` which uses
`stop_machine`. The comment on that path explicitly reads *"Unsafe to patch multiple
instructions without synchronization."* KP follows the same pattern; we did not.

**Resolution:** Added `stop_machine(write_insts_via_alias_sm_cb, &arg, cpu_online_mask)` inside
`#ifndef KMOD_FREESTANDING` only (the kbuild build path), matching KP `hotpatch()`. The inner
`write_insts_via_alias_impl` retains the per-instruction alias lock so freestanding semantics
are preserved unchanged — freestanding cannot reach `linux/stop_machine.h` and keeps relying on
(a) single-writer serialisation via `kh_alias_lock`, (b) icache flush inside
`aarch64_insn_patch_text_nosync` after each write, and (c) the empirical observation that the
27.8M-call × 67K add/remove stress sweep did not land in the vulnerable intermediate window.
The residual theoretical race in freestanding mode is documented in the `write_insts_via_alias_impl`
comment block and acknowledged here.

| # | Site | Delta | Class | Rationale |
|---|------|-------|-------|-----------|
| 6.1 | No `stop_machine` around alias patch | KP wraps `hotpatch_nosync` in `stop_machine(cpu_online_mask)`; we didn't. | **must-fix** | ARMv8 B2.2.1 atomicity covers only a single 4-byte write. Our trampoline is 4 (or 5 with BTI/PAC) words; intermediate states between the per-instruction alias writes produce a corrupted branch sequence (`LDR X17, #8; BR X17; <data>; <data>`) that would crash any CPU executing the target during the patch window. Arm's own `aarch64_insn_patch_text()` comments this explicitly: *"Unsafe to patch multiple instructions without synchronization."* Empirical stress (27.8M calls × 67K add/remove in 3 seconds, zero Oops, freestanding mode) suggests the window is narrow — but empirical luck ≠ theoretical safety. **Fixed in kbuild mode** by wrapping the whole alias-patch loop in `stop_machine()` matching KP `hotpatch()` (lines 106–122). Freestanding remains on the empirical path because `linux/stop_machine.h` is unreachable there; residual risk documented in `write_insts_via_alias_impl` header comment. The same intermediate-state hazard exists in the `set_memory` fallback path (reachable when alias init fails: vmalloc OOM or PTE_CONT); this path also performs a per-word for-loop write. **Extended fix**: `stop_machine` now wraps BOTH the alias path (`write_insts_via_alias_sm_cb`) and the `set_memory` fallback path (`write_insts_via_setmem_sm_cb`) in kbuild mode, giving symmetric protection across the full fallback chain. The PTE-direct fallback (`write_insts_via_pte`) is freestanding-only (kh_write_mode == 0 is unreachable in kbuild per `kh_write_insts_init`), so no additional stop_machine wrapping is needed there. |
| 6.2 | DAIF-disable spinlock (freestanding) vs `spin_lock_irqsave` (KP) | Different type, same semantics. | no-action | Freestanding cannot pull `struct spinlock` from kernel headers. Uses `__atomic_exchange_n(..., __ATOMIC_ACQUIRE)` + `msr daifset, #0xf` (mask DAIF) to serialize the alias PTE rewrite + patch + restore sequence (see `kh_alias_lock_acquire` at `src/arch/arm64/inline.c:394–405`). Semantically equivalent to `spin_lock_irqsave`: mutual exclusion + IRQ-safe. Kbuild path uses real `DEFINE_SPINLOCK` (line 414). Both paths stress-validated. |
| 6.3 | PTE_CONT guard in `kh_alias_init` | KP lacks this guard; `modify_entry_kernel` rewrites the whole CONT group instead. | no-action | Defensive: refuses the alias path rather than silently corrupting the 16-entry contiguous PTE group. Guard is at `src/arch/arm64/inline.c:479–483` — `else if (pte & PTE_CONT) { pr_warn(...); } else { kh_alias_pte = pte; }`. When PTE_CONT is detected we leave `kh_alias_pte = 0`, which short-circuits `write_insts_via_alias_impl` (line 511) and forces fallback to `set_memory` or `write_insts_via_pte`. Verified `grep -c 'PTE_CONT' src/arch/arm64/inline.c` = 2 (comment + condition). |
| 6.4 | `_relo_cfi_hash` via `is_bad_address(origin_addr-4)` | KP has no kCFI path so no equivalent. | no-action | kCFI-kernel-specific. kCFI checks `*(target - 4)` before every BLR, so placing the hash at `_relo_cfi_hash` (immediately before `relo_insts[0]`) allows the backup pointer returned by `hook()` to pass CFI validation. On non-kCFI kernels this is harmless — 4 bytes of data that never execute. Cited in `src/arch/arm64/inline.c:328–337`. Only copy when the address is readable; otherwise leave the field zero (no CFI impact on non-kCFI builds, and kCFI builds always have readable kernel text at `origin_addr - 4`). |
| 6.5 | TLBI sequence inside `write_insts_via_alias_impl` (pre + post) | Matches KP exactly. | no-action | Verified: `src/arch/arm64/inline.c:522–525` and 531–533 — `*alias_entry = new_pte → dsb ish → kh_flush_tlb_kernel_page` before, and `*alias_entry = kh_alias_pte → dsb ish → kh_flush_tlb_kernel_page` after. `kh_flush_tlb_kernel_page` (`include/arch/arm64/pgtable.h:122–129`) emits `dsb ishst → tlbi vaale1is → dsb ish → isb`, mirroring KP `flush_tlb_kernel_page` and the kernel's own `__tlbi(vaale1is, ...)` macro. The additional `dsb ish` before the TLBI-page call is redundant with the TLBI primitive's own pre-barrier but harmless; matches KP line 53/57. |

### 2.5 `src/arch/arm64/pgtable.c` + `include/arch/arm64/pgtable.h` ↔ `ref/KernelPatch/kernel/include/pgtable.h`

| # | Site | Delta | Class | Rationale |
|---|------|-------|-------|-----------|
| 7.1 | `kh_flush_tlb_kernel_page` TLBI sequence (`include/arch/arm64/pgtable.h:122-129`) | IDENTICAL: both use `dsb ishst` → `tlbi vaale1is, addr` → `dsb ish` → `isb`. KP uses the `tlbi_1(vaale1is, addr)` macro (ref `pgtable.h:162`); ours uses direct inline asm — same four instructions, same order. | **no-action** | CLAUDE.md documents the rationale (`vaale1is` = VA, All ASIDs, EL1, IS; pre-TLBI `dsb(ishst)` orders the preceding PTE store; post-TLBI `dsb(ish)+isb` completes maintenance). No drift detected. |
| 7.2 | `kernel_pgd = swapper_pg_dir` only; no `init_mm.pgd` fallback (`pgtable.c:118-124`) | KP (`start.c:459-464`) reads `TTBR1_EL1` hardware register directly to obtain `pgd_pa`, then derives `pgd_va = phys_to_virt(pgd_pa)`. KP does not use `swapper_pg_dir` or `init_mm.pgd`. Our path (ksyms-resolve `swapper_pg_dir`) is a different approach; both arrive at the same physical pgd. No `init_mm` fallback in KP either. | **no-action** | GKI exports `swapper_pg_dir` unconditionally. `init_mm.pgd` is unsafe because `struct mm_struct` layout varies across kernel versions and reading at offset 0 of `init_mm` is not `pgd`. Comment in `pgtable.c:117` already states this. Keep single `swapper_pg_dir` path. |
| 7.3 | `kva_min = page_offset ? page_offset : 0xffffff8000000000ULL` guard in `pgtable_entry` and `pgtable_phys_kernel` (`pgtable.c:180, 242`) | KP `pgtable_entry` (`start.c:127-173`) has no kva_min sanity check at all. Our guard is a defensive addition absent in KP. The fallback constant `0xffffff8000000000ULL` is the correct lower bound for 39-bit VA kernels (T1SZ=25). For all wider VA configs the runtime-computed `page_offset` is used. | **no-action** | Strictly stricter than KP. Prevents a nonsensical walk if `pgtable_init` was skipped or if a caller passes a userspace VA. The fallback constant is architecturally correct for the minimum GKI VA width (39-bit). |
| 7.4 | VA-bits detection via `TCR_EL1.T1SZ` (`pgtable.c:141-154`) | IDENTICAL algorithm: both read `tcr_el1` via `mrs`, extract T1SZ from bits `[21:16]`, compute `va_bits = 64 - t1sz`. KP (`start.c:444-446`): `t1sz = bits(tcr_el1, 21, 16); va_bits = 64 - t1sz`. Our code: `t1sz = (tcr >> 16) & 0x3f; va_bits = 64 - t1sz`. Same for page-size detection via TG1 bits `[31:30]`. | **no-action** | Algorithm matches KP exactly. `page_level` formula differs slightly (`(va_bits - 4) / (page_shift - 3)` in KP vs ceiling formula in ours) but produces the same integer result for all valid GKI VA/page-size combinations. |

### 2.6 `tests/kmod/test_phase6_kh_root.c` ↔ `ref/KernelPatch/kernel/patch/common/sucompat.c`

Diff reviewed: KP `sucompat.c` is a full production su-compat layer: kstorage allowlist
(`su_kstorage_gid` + `is_su_allow_uid`), per-entry `su_profile` structs with `to_uid` and
`scontext`, runtime-configurable su path (`current_su_path`), AArch32 compat hooks
(`hook_compat_syscalln(11/327/334, ...)`), `apd_path` delegation, `set_user_arg_ptr`
for argv rewriting, and SELinux scontext commit via `commit_su(to_uid, sctx)`. It uses
`hook_syscalln()` which in KP can fall back to the `fp_wrap_syscalln` path.

Our port retains only the minimum needed for the kh_root demo: execve redirection to sh,
and faccessat/fstatat path faking so `test -x /system/bin/kh_root` succeeds. All
production-grade features (kstorage, allowlist, SELinux, AArch32, apd) are deliberately
absent. The file's header comment (lines 1–28) accurately lists each simplification.

**Step 1 — `kh_root_uninstall` wired to `module_exit` (critical check):**

```
tests/kmod/test_main.c:502:  static void __exit kh_test_exit(void)
tests/kmod/test_main.c:510:      extern void kh_root_uninstall(void);
tests/kmod/test_main.c:511:      kh_root_uninstall();     /* FIRST call in exit body */
tests/kmod/test_main.c:514:      kh_subsystem_cleanup();  /* teardown AFTER hooks removed */
tests/kmod/test_main.c:520:  module_exit(kh_test_exit);
```

`kh_root_uninstall()` is the FIRST action in `kh_test_exit()`, before `kh_subsystem_cleanup()`.
The ordering is commented at lines 504–508 ("Phase 6: uninstall syscall hooks BEFORE freeing
module memory"). Requirement fully satisfied — **no-action**.

| # | Site | Delta | Class | Rationale |
|---|------|-------|-------|-----------|
| 8.1 | `kh_root_uninstall` wired to `module_exit` | Must exist per CLAUDE.md ("rmmod without uninstall → next execve/faccessat/fstatat panic") | **no-action** | Confirmed wired: `test_main.c:511` calls `kh_root_uninstall()` as the first statement in `kh_test_exit()` (line 502), which is registered via `module_exit(kh_test_exit)` at line 520. Ordering contract also satisfied: uninstall precedes `kh_subsystem_cleanup()` at line 514. |
| 8.2 | Hardcoded `__NR_execve=221` / `__NR_faccessat=48` / `__NR3264_fstatat=79` | KP resolves via `<uapi/scdefs.h>` constants from the kernel build environment | **no-action** | ARM64 ABI syscall numbers have been stable since kernel 3.7 (defined in `arch/arm64/include/asm/unistd.h`). CLAUDE.md "Common pitfalls" explicitly documents these three values. Guards `#ifndef __NR_*` at lines 45–53 allow kernel-header-supplied values to override the hardcoded fallbacks in kbuild mode. |
| 8.3 | Inline `hook_wrap` on `__arm64_sys_<name>` (not `hook_syscalln` / sys_call_table fp-hook) | KP uses `hook_syscalln()` which can attempt `fp_wrap_syscalln` | **no-action** | GKI ≥ 5.10 marks `sys_call_table` as `__ro_after_init`; writing through it requires clearing PTE_RDONLY. Even if cleared, kCFI in `invoke_syscall+0x50` rejects the fp-hook trampoline (type hash mismatch). File header lines 13–27 document both constraints with the exact CFI failure message. CLAUDE.md "Syscall hooks" section confirms this is the required approach on GKI kCFI kernels. KP uses `hook_syscalln()` which hits the same inline path when `sys_call_table` is unwriteable; our port is simply unconditional on the safe path. |
| 8.4 | `match_user_path` 64-byte buffer | KP uses `SU_PATH_MAX_LEN` (128 bytes in `sucompat.h`) | **no-action** | Target path `/system/bin/kh_root` is 20 bytes including NUL. A 64-byte buffer provides 3× margin. Comment at line 84 documents the reasoning. kh_strncpy_from_user truncates at `sizeof(buf)` regardless, so no overflow is possible. |
| 8.5 | No SELinux / allowlist / kstorage / AArch32 compat | KP has all of: `su_kstorage_gid` allowlist, per-uid `su_profile` with `scontext`, `commit_su(to_uid, sctx)` SELinux patch, AArch32 compat hooks (syscalls 11/327/334), `apd_path` delegation, `set_user_arg_ptr` argv rewriting, runtime-configurable su path | **no-action** | Demo scope. File header lines 6–10 explicitly lists all omissions: "No kstorage / allowlist: any caller → uid=0", "No scontext change (SELinux label stays shell)", "Single hardcoded magic path", "64-bit only, no compat". These are deliberate simplifications for the kh_root demo, not a production su tool. P4 will preserve these header comments in the rename. |

## 3. Resolution tracker

| ID | File | Class | Summary | Commit |
| -- | ---- | ----- | ------- | ------ |
| 3.1 | `src/uaccess.c` | **no-action** | `kh_cred_uid_offset = 4` hardcoded — confirmed correct on GKI 6.1 (init_cred uid@+4 = 0) | 68e39fd |
| 3.2 | `src/uaccess.c` | **no-action** | `rc++` NUL-inclusive return — matches KP `compat_strncpy_from_user` lines 110–117 exactly | 68e39fd |
| 3.3 | `src/uaccess.c` | **no-action** | `probe_pointer_offset` 0x1000 walk range — confirmed sufficient: cred@0x830, stack@0x38 on GKI 6.1 | 68e39fd |
| 3.4 | `src/uaccess.c` | **no-action** | 3-way `copy_to_user` fallback vs KP 4-way — different fallback axis; GKI resolves `_copy_to_user` directly | 68e39fd |
| 4.1 | `src/platform/syscall.c` | **must-fix** | `regs.syscallno` not set in `kh_raw_syscallN` — active callers in test suite; fixed: added `regs.syscallno = (int32_t)nr;` in all 7 wrappers | 178a698 |
| 4.2 | `src/platform/syscall.c` | **no-action** | 64-bit only, no compat/AArch32 — deliberate deviation documented in file header; GKI targets are LP64-only | 178a698 |
| 4.3 | `src/platform/syscall.c` | **no-action** | `kh_zero_regs` pre-zeros frame — strictly safer than KP; cost negligible | 178a698 |
| 4.4 | `src/platform/syscall.c` | **no-action** | Name-table caching monotonic — matches KP exactly; stable kernel-lifetime symbol addresses | 178a698 |
| 4.5 | `src/platform/syscall.c` | **no-action** | `kh_sys_call_table` diagnostic-only; inline hook path only — GKI kCFI + `__ro_after_init` make fp-hook path broken; documented in CLAUDE.md | 178a698 |
| 5.1 | `src/arch/arm64/transit.c` | **no-action** | RCU-snapshot design — deliberate deviation from KP upstream (which has no locking); fixes UAF in concurrent unwrap path; stress-validated 27.8M calls × 67K add/remove, zero Oops; see CLAUDE.md "RCU snapshot in transit_body" | 3291b7a |
| 5.2 | `src/arch/arm64/transit.c` | **no-action** | FPAC safety comment coverage — both `transit_body` (function header, lines 53–73) and `fp_transit_body` (body, lines 317–320) have accurate, non-contradictory FPAC disclaimers; verified correct | 3291b7a |
| 5.3 | `src/arch/arm64/transit.c` | **no-action** | Stack budget — transit_body ≈ 608 bytes, fp_transit_body ≈ 1040 bytes per invocation; both well under 4 KiB of the 16 KiB ARM64 kernel stack | 3291b7a |
| 6.1 | `src/arch/arm64/inline.c` | **must-fix** | No `stop_machine` around the alias-page multi-instruction patch loop — intermediate states of the 4/5-word trampoline crash other CPUs entering the target during the patch window. Fixed in kbuild mode by wrapping the loop in `stop_machine(cpu_online_mask)`, matching KP `hotpatch()`. Freestanding retains the empirical path (no kernel header access); residual risk documented. Extended: `stop_machine` now also wraps the `set_memory` fallback path (same hazard; reachable when alias init fails). | 431ad03, c273598 |
| 6.2 | `src/arch/arm64/inline.c` | **no-action** | DAIF-disable spinlock (freestanding) vs `spin_lock_irqsave` (KP / kbuild) — different type, same semantics; freestanding cannot pull `struct spinlock` from headers | 431ad03 |
| 6.3 | `src/arch/arm64/inline.c` | **no-action** | PTE_CONT guard in `kh_alias_init` — defensive vs KP; refuses the alias path rather than corrupt a contiguous PTE group | 431ad03 |
| 6.4 | `src/arch/arm64/inline.c` | **no-action** | `_relo_cfi_hash` via `is_bad_address(origin_addr-4)` — kCFI-specific; KP has no equivalent because it predates kCFI | 431ad03 |
| 6.5 | `src/arch/arm64/inline.c` | **no-action** | TLBI sequence inside alias patch (pre + post) — matches KP `hotpatch_nosync` lines 53/57 and the KP `flush_tlb_kernel_page` pattern | 431ad03 |
| 7.1 | `include/arch/arm64/pgtable.h` | **no-action** | `kh_flush_tlb_kernel_page` TLBI sequence — IDENTICAL to KP `flush_tlb_kernel_page` (ref `pgtable.h:158-165`): `dsb ishst → tlbi vaale1is → dsb ish → isb` | 2424040 |
| 7.2 | `src/arch/arm64/pgtable.c` | **no-action** | `kernel_pgd` resolved via `swapper_pg_dir` only — KP uses `TTBR1_EL1` hardware register; no `init_mm.pgd` fallback in either. GKI exports `swapper_pg_dir`; `init_mm.pgd` unsafe due to struct layout variance | 2424040 |
| 7.3 | `src/arch/arm64/pgtable.c` | **no-action** | `kva_min` guard with `0xffffff8000000000ULL` fallback — defensive addition absent in KP; fallback is correct 39-bit VA lower bound | 2424040 |
| 7.4 | `src/arch/arm64/pgtable.c` | **no-action** | VA-bits detection via `TCR_EL1.T1SZ` — identical algorithm to KP `start.c:444-446`; `page_level` formula difference produces same integer result for all GKI configs | 2424040 |
| 8.1 | `tests/kmod/test_main.c` | **no-action** | `kh_root_uninstall` wired as first call in `kh_test_exit()` (line 511) before `kh_subsystem_cleanup()`; `module_exit(kh_test_exit)` at line 520 — ordering contract satisfied | aa19c3f |
| 8.2 | `tests/kmod/test_phase6_kh_root.c` | **no-action** | Hardcoded `__NR_execve=221`, `__NR_faccessat=48`, `__NR3264_fstatat=79` — stable ARM64 ABI since kernel 3.7; `#ifndef` guards allow kernel-supplied override in kbuild | aa19c3f |
| 8.3 | `tests/kmod/test_phase6_kh_root.c` | **no-action** | Inline `hook_wrap` on `__arm64_sys_<name>` — GKI kCFI + `__ro_after_init` make sys_call_table fp-hook path broken; documented in file header and CLAUDE.md | aa19c3f |
| 8.4 | `tests/kmod/test_phase6_kh_root.c` | **no-action** | `match_user_path` 64-byte buffer vs 128-byte KP `SU_PATH_MAX_LEN` — target path is 20 bytes; 3× margin; overflow impossible (kh_strncpy_from_user truncates) | aa19c3f |
| 8.5 | `tests/kmod/test_phase6_kh_root.c` | **no-action** | No SELinux / allowlist / kstorage / AArch32 compat — demo scope; all omissions listed in file header lines 6–10; deliberate simplifications vs production KP sucompat | aa19c3f |

(rows appended as audit tasks fill the sections above)

## 4. Device verification

Device: Pixel 6 (1B101FDF6003PM), GKI 6.1.99-android14, SDK mode.

```
==> device: kmod tests on physical device (--mode=sdk)
[toolchain] using ndk: .../ndk/29.0.13599879/.../clang --target=aarch64-linux-android35
KernelHook kmod Device Test
Mode: sdk
Device serial: 1B101FDF6003PM
Toolchain: ndk /Users/bmax/Library/Android/sdk/ndk/29.0.13599879 (darwin-x86_64, api=35)

  SELinux: Permissive   modules_disabled: 0
  API: 35   Kernel: 6.1.99-android14-11-gd7dac4b14270-ab12946699
  Building kernelhook.ko + hello_hook.ko (SDK mode) for 6.1.99-android14-11-gd7dac4b14270-ab12946699...
  kallsyms_lookup_name: 0xffffffe6883a752c
  CRCs: (auto-resolve via kmod_loader)
  [pushed] kernelhook.ko, hello_hook.ko, kmod_loader
  PASS setup: [29281.990014] [KH/I] hello_hook: hooked do_sys_open* at ffffffe688593768
  PASS fire: before-callback invoked 2961 time(s) on triggered opens

All device tests passed.
=== Summary: 2 PASS, 0 FAIL ===
<-- device: PASS
=== Summary: 1 PASS, 0 FAIL ===
```

Note on pre-existing gap: `export_link_test/` Ring 3 exporter+importer on-device FAIL
(known since P1) did not surface in this SDK-mode run. The SDK path exercises
`kernelhook.ko` + `hello_hook.ko` only; `kh_test.ko` (which carries the Ring 3
export_link_test) is not loaded in `--mode=sdk`. The gap is pre-existing from P1 —
not P2-introduced; forwarded to a separate follow-up. Does not block P2 exit.
