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
| 3.1 | `src/uaccess.c` | **no-action** | `kh_cred_uid_offset = 4` hardcoded — confirmed correct on GKI 6.1 (init_cred uid@+4 = 0) | (filled in T3 commit) |
| 3.2 | `src/uaccess.c` | **no-action** | `rc++` NUL-inclusive return — matches KP `compat_strncpy_from_user` lines 110–117 exactly | (filled in T3 commit) |
| 3.3 | `src/uaccess.c` | **no-action** | `probe_pointer_offset` 0x1000 walk range — confirmed sufficient: cred@0x830, stack@0x38 on GKI 6.1 | (filled in T3 commit) |
| 3.4 | `src/uaccess.c` | **no-action** | 3-way `copy_to_user` fallback vs KP 4-way — different fallback axis; GKI resolves `_copy_to_user` directly | (filled in T3 commit) |

(rows appended as audit tasks fill the sections above)

## 4. Device verification

`scripts/test.sh device` run log excerpt (filled in T final task).
