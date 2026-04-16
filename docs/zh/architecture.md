# 架构说明

本文档描述 KernelHook 的内部架构，重点介绍 SP-7 引入的策略注册表子系统。公共 API
接口详见 [`docs/zh/api-reference.md`](api-reference.md)，构建模式详见
[`docs/zh/build-modes.md`](build-modes.md)。

SP-7 完整设计规范位于
[`docs/superpowers/specs/2026-04-16-single-ko-unified-version-compat-design.md`](../superpowers/specs/2026-04-16-single-ko-unified-version-compat-design.md)
§5；本章是 §5.9 退出准则第 6 条所要求的对外可读摘要。

---

## 概览

KernelHook 面向 arm64 平台的 Android GKI 内核，覆盖 4.4 至 6.12。跨越这个范围，
内核内部实现会以各种方式发生偏移，导致任何单一解析路径失效：

- 符号被重命名（`_copy_to_user` → `copy_to_user` → `__arch_copy_to_user`）。
- 符号在某些构建配置下完全消失（`swapper_pg_dir` 并非所有 GKI 变体都导出）。
- 结构体布局变化（`struct pt_regs`、`struct module`、`thread_size`）。
- 曾经稳定的编译期常量在 5.10 和 6.1 之后出现分叉。

单一硬编码解析策略会在某些内核代际上静默失败，产生难以复现的隐患。
**策略注册表**是框架层面的应对方案：每个"能力"配备多条独立解析策略，按优先级依次
尝试，首次成功后缓存结果。

---

## 策略注册表

### 存在意义

根本问题是 **GKI 4.4→6.12 跨版本的内核符号漂移**。任何单一解析路径——无论是直接
`ksyms_lookup`、编译期 extern，还是硬编码偏移——都会在至少一个内核代际上失败。具体例子：

- `swapper_pg_dir` 在 5.15 GKI 上有导出，但在某些 6.1 配置下不存在。
- `kimage_voffset` 在所有已知构建上均存在，但读取它依赖符号可寻址且 VA-PA 偏移正确，
  这两点在 live patch 后均无法保证。
- `pt_regs_size = 0x150` 在撰写时对所有测试过的 GKI 5.x/6.x 构建均成立，但并非
  合同保证，在 4.4 内核上已有差异记录。

防御手段是**每个能力配备多条 fallback 策略 + 一致性检查模式**：

1. 每个能力在链接期注册 N 条有序策略。
2. `kh_strategy_resolve` 按优先级遍历，缓存首次成功结果。
3. 失败情况明确记录；静默错误猜测被拒绝。
4. `kh_consistency_check=1` 运行所有策略并在结果不一致时标记内核污染（taint），
   在生产环境 panic 发生前捕捉策略漂移。

### ELF section 注册机制

每条策略是一个 `struct kh_strategy`，在链接期通过 `KH_STRATEGY_DECLARE` 宏放入
`.kh_strategies` ELF section：

```c
/* include/kh_strategy.h */

typedef int (*kh_strategy_fn_t)(void *out, size_t out_size);

struct kh_strategy {
    const char         *capability;  /* 例如 "swapper_pg_dir"   */
    const char         *name;        /* 例如 "kallsyms"         */
    int                 priority;    /* 0 = 最高优先级          */
    bool                enabled;     /* 运行时可修改            */
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

链接脚本暴露 `__start___kh_strategies` 和 `__stop___kh_strategies`。模块 init 调用
`kh_strategy_init()`，遍历该 section，按能力建立各自的优先级有序链表。

**示例 — 为 `swapper_pg_dir` 注册 `kallsyms` 策略：**

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

### 解析算法

`kh_strategy_resolve(cap, &out, sizeof(out))` 的逻辑如下：

```
kh_strategy_resolve(cap, out, out_size):
    if cached[cap] 有效:
        *out = cached[cap]; return 0
    if in_flight[cap]:
        return -EDEADLK          /* 检测到递归环 */
    in_flight[cap] = true
    if kh_force_map[cap] 已设置:
        r = strategies[cap][kh_force_map[cap]].resolve(out, out_size)
        goto done
    for 每条按优先级排序的策略:
        if !strategy.enabled: continue
        if kh_inject_fail_map[cap][strategy.name] > 0:
            kh_inject_fail_map[cap][strategy.name]--
            continue             /* 注入人工失败 */
        r = strategy.resolve(out, out_size)
        if r == 0:
            cached[cap] = *out
            break
    r = (r == 0) ? 0 : -ENODATA
done:
    in_flight[cap] = false
    return r
```

**递归依赖**的处理。某些策略依赖其他能力先解析完成，例如
`swapper_pg_dir:ttbr1_walk` 依赖 `memstart_addr`，
`kimage_voffset:text_va_minus_pa` 依赖 `swapper_pg_dir`。
这类策略内部直接再调 `kh_strategy_resolve(dep_cap, ...)`。
`in_flight` 集合负责环检测——若检测到同一能力在自身调用栈中重入，返回 `-EDEADLK`，
当前策略跳过。解析结果缓存后每个能力至多只成功解析一次。

### 运行时控制接口

四种机制允许无需重新编译即可按策略粒度控制行为。所有接口均接受
`capability:strategy_name` 格式的 CSV 字符串。

**模块参数**（`insmod` 时传入）：

| 参数 | 语义 |
|---|---|
| `kh_disable="cap:name,..."` | 加载时禁用指定策略 |
| `kh_enable="cap:name,..."` | 重新启用之前禁用的策略 |
| `kh_force="cap:name,..."` | 绕过优先级排序，强制指定某条策略 |
| `kh_inject_fail="cap:name:count,..."` | 令该策略在接下来的 `count` 次调用中强制失败 |
| `kh_consistency_check=1` | 初始化时运行所有启用策略并比对结果 |

**debugfs**（`/sys/kernel/debug/kernelhook/` 下）：

| 文件 | 操作 | 语义 |
|---|---|---|
| `strategies` | 读 | 表格形式列出全部条目：(能力, 策略名, 优先级, 是否启用, 上次命中者, 上次结果) |
| `disable` | 写 | `"cap:name"` — 运行时禁用某条策略 |
| `enable` | 写 | `"cap:name"` — 重新启用 |
| `force` | 写 | `"cap:name"` 固定策略；`"cap:"` 清除强制 |
| `consistency_last` | 读 | 最近一次一致性检查结果（类 JSON 格式） |

debugfs 条目仅在 `CONFIG_DEBUG_FS=y`（或 `KMOD_FREESTANDING`）时编入。
它们是纯观测与测试接口，不在能力解析关键路径上。

### 一致性检查模式

加载时传入 `kh_consistency_check=1` 后：

1. 模块 init 对每个能力运行**所有 `enabled=true` 的策略**，而非只取优先级最高者。
2. 将所有成功策略的返回值互相比对。
3. 任何不一致触发 `WARN` + `add_taint(TAINT_CRAP)`。
4. 完整结果表写入 debugfs `consistency_last`，供测试框架自动断言。

开销可接受：每个能力约 N 次 `ksyms_lookup`（N = 2–4），12 个能力合计估算
不超过 50 ms。CI 默认开启一致性检查（`scripts/test_avd_kmod.sh` 和
`scripts/test_device_kmod.sh` 均向 insmod 传入 `kh_consistency_check=1`）。

### 错误语义

当某能力所有策略全部失败时，行为取决于其关键性档位：

- **档 1（致命）**：模块 init 返回 `-ENOENT`，dmesg 打印完整尝试表：
  ```
  [kh] FATAL: cannot resolve 'swapper_pg_dir'
  [kh]   strategy kallsyms       : -ENOENT (symbol not in /proc/kallsyms)
  [kh]   strategy init_mm_pgd    : -EINVAL (init_mm.pgd offset probe failed)
  [kh]   strategy ttbr1_walk     : -ENOTSUPP (memstart_addr unresolved)
  [kh]   strategy pg_end_anchor  : -ENOENT (swapper_pg_end not in kallsyms)
  ```
- **档 2（非致命）**：打印内核警告，结果记录到 sysfs，模块以降级状态继续运行。

系统永远不接受静默错误猜测——框架记录每次尝试及其具体失败原因。

---

## 能力表

SP-7 注册了以下 12 个能力，每个能力都有对应的源文件位于 `src/strategies/` 下。

| 能力 | 策略（按优先级） | 用途 |
|---|---|---|
| `swapper_pg_dir` | kallsyms, init_mm_pgd, ttbr1_walk, pg_end_anchor | 页表遍历所需的内核 PGD |
| `kimage_voffset` | kallsyms, text_va_minus_pa, loader_inject | 内核 VA-PA 偏移量 |
| `memstart_addr` | kallsyms, dtb_parse, dma_phys_limit | DRAM 基地址（物理地址） |
| `init_cred` | kallsyms_init_cred, current_task_walk, init_task_walk | 内核 init 进程的 cred 指针 |
| `init_thread_union` | kallsyms_init_thread_union, kallsyms_init_stack, current_task_stack | init task 栈的起始 VA |
| `thread_size` | const_default (16384), probe_from_current_task | 内核栈大小（const_default 为 prio 0：probe 在 32K 对齐的栈上会误报 32K） |
| `pt_regs_size` | probe_from_current_task, const_default (0x150) | `struct pt_regs` 大小 |
| `copy_to_user` | _copy_to_user, copy_to_user, \_\_arch_copy_to_user, inline_ldtr_sttr | 向用户空间拷贝的函数指针 |
| `copy_from_user` | _copy_from_user, copy_from_user, \_\_arch_copy_from_user, inline_ldtr | 从用户空间拷贝的函数指针 |
| `stop_machine` | kallsyms_stop_machine, smp_call_function_many | 全 CPU 暂停的函数指针 |
| `aarch64_insn_patch_text_nosync` | kallsyms, inline_alias_patch | 内核文本段修改器 |
| `register_ex_table` | probe_extable, give_up | 内联 uaccess 的 fault fixup 注册入口 |

内联 uaccess 策略（`copy_to_user:inline_ldtr_sttr` 和 `copy_from_user:inline_ldtr`）
以 `register_ex_table` 能力为前置条件：内联实现需要在模块级异常表中登记 page fault
处理条目，`register_ex_table` 必须先成功，内联策略才能被视为可用。

---

## 测试分层

策略子系统有三个测试层，均通过 `scripts/test.sh` 统一入口驱动。

### L1 — 用户态单元测试

位置：`tests/userspace/test_strategy_*.c`

这些测试在开发机（macOS 或 Linux）上通过 ctest 运行。使用 mock 替换策略注册表、
task_struct 布局、`__ksymtab` 边界和 DTB 报文，验证纯逻辑：注册语义、优先级排序、
禁用/强制/注入、递归环检测、一致性比对算法。

```bash
cmake -B build_debug -DCMAKE_BUILD_TYPE=Debug
cmake --build build_debug
(cd build_debug && ctest -R test_strategy)
```

### L2 — 在核单策略覆盖

位置：`tests/kmod/test_resolver_<cap>.c`

每个文件在单次 `insmod` 周期内测试一个能力：

1. 记录"自然"结果（默认优先级首个成功策略的值），作为组内 golden。
2. 对每条启用策略执行 `kh_strategy_force(cap, name)`，断言结果与组内 golden 一致。
3. 对每条策略执行 `kh_strategy_inject_fail(cap, name, 1)`，验证下一条策略接管。
4. 负向断言：`kh_strategy_force(cap, "not_exist")` 必须返回 `-ENODATA`。
5. 所有断言通过 → dmesg 打印 `[test_resolver_X] PASS`，测试脚本解析该行判定结果。

L2 测试通过 `scripts/test.sh avd` 和 `scripts/test.sh device` 运行。

### L3 — Golden 矩阵（策略存活 + 值对账）

位置：`tests/golden/strategy_matrix/`

`scripts/test.sh strategy-matrix` 对每个可用 AVD 和真机加载
`kh_consistency_check=1` 的 `kernelhook.ko`，读取
`/sys/kernel/debug/kernelhook/strategies` 和 `consistency_last`，
与 git 中存储的 golden 文件比对：

| 产物 | 路径 | 内容 |
|---|---|---|
| 每设备值文件 | `values/<avd-id>.yaml` | 每条策略的实际返回值与 ok/errno |
| 存活矩阵 | `survival.tsv` | (设备, 能力, 策略) 三元组的 Y/N 布尔表 |
| 一致性日志 | `consistency_runs.log` | 追加式日志，每次 CI run 一行 |
| 期望声明 | `expectations.yaml` | 每个能力的期望类型声明 |
| 流程说明 | `README.md` | 新增 AVD 或策略时更新 golden 的操作指南 |

对账分三层依次执行：

1. **一致性通过** — dmesg 中不含任何能力的 `TAINT_CRAP`。
2. **Golden diff** — `values/<avd>.yaml` 与 git 中文件逐字节一致（`run_metadata` 除外）。
3. **期望校验** — 每个能力满足其声明的期望类型
   （`scalar_all_strategies_equal`、`function_pointer_any_valid` 等）。

返回码：`0` = PASS；`1` = DRIFT（golden 不匹配，需人工审核后执行 `--accept`）；
`2` = FAIL（违反 expectations 规则）。

新增策略或变更 AVD 后更新 golden 的操作：

```bash
scripts/test.sh strategy-matrix --accept <avd-id>   # 更新指定设备的 golden
scripts/test.sh strategy-matrix --dump <avd-id>     # 打印最新 yaml，不写入
scripts/test.sh strategy-matrix                     # 仅检查，不更新
```

### 已知失败的 L2 测试（SP-7 后续事项）

Pixel_35 AVD 基线上有两个 L2 resolver 测试当前失败，已记录为后续工作而非发布阻塞：

- `test_resolver_swapper_pg_dir` — `init_mm_pgd` walker 启发式（在 `init_mm`
  里按 8 字节对齐首次匹配扫描）在 GKI 6.6 上过于宽松，返回的值与 kallsyms
  自然优胜者不一致。prio 0 的 `kallsyms` 仍能正常解析；只是策略间 consistency
  检查失败。见 SP-7 open_questions task-9。
- `test_resolver_cred` — `walk_task_for_cred` 的 (usage, uid) 启发式在 GKI 6.6
  的 task_struct 布局下会在 `init_task` 内误命中。同样被 kallsyms prio 0 兜底；
  只是 consistency 检查标记分歧。见 SP-7 open_questions task-12。

两个 bug 都不影响生产使用（kallsyms prio 0 总能胜出），但在 §5.9 exit criterion (1)
被完全满足之前必须解决。

---

## 新增能力指南

按以下步骤向注册表扩展新能力。

### 1. 实现策略函数

新建 `src/strategies/<name>.c`。每个策略函数必须符合 `kh_strategy_fn_t` 签名，
并用 `KH_STRATEGY_DECLARE` 完成注册：

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

/* priority 0 = 最先尝试 */
KH_STRATEGY_DECLARE(my_cap, kallsyms, 0, strat_my_cap_kallsyms, sizeof(void *));

static int strat_my_cap_fallback(void *out, size_t sz)
{
    /* 独立于主策略的替代解析逻辑 */
    return -ENOENT;
}

KH_STRATEGY_DECLARE(my_cap, fallback, 1, strat_my_cap_fallback, sizeof(void *));
```

至少提供两条策略。主策略应尽量可靠（通常是 `ksyms_lookup`）；
fallback 策略必须与主策略完全独立，不能依赖同一前提条件。

### 2. 添加期望声明

在 `tests/golden/strategy_matrix/expectations.yaml` 中添加一条：

```yaml
my_cap:   { type: scalar_all_strategies_equal }
# 或：    { type: function_pointer_any_valid }
# 或：    { type: probed_may_vary, allowed: [4096, 8192, 16384] }
```

根据能力的语义选择对应期望类型（期望类型定义见 SP-7 设计规范 §5.10.2）。

### 3. 编写 L2 在核测试

新建 `tests/kmod/test_resolver_<name>.c`，参照
`tests/kmod/test_resolver_swapper_pg_dir.c` 的模式，覆盖每条策略的
force/inject/负向测试场景。

### 4. 接入构建系统

需要更新四处：

- `CMakeLists.txt` — 将 `src/strategies/<name>.c` 加入用户态测试构建（供 mock 化的 L1 测试使用）。
- `kmod/mk/kmod.mk` — 将 `src/strategies/<name>.c` 加入 freestanding 和 SDK 内核模块构建。
- `tests/kmod/Kbuild` 和 `tests/kmod/Makefile` — 包含新的 L2 测试源文件。
- `tests/kmod/test_main.c` — 注册新的 L2 测试 section。

### 5. 重新生成 golden

在连接的设备或 AVD 上运行新策略并接受结果：

```bash
scripts/test.sh strategy-matrix --accept <device-serial>
```

将更新后的 `values/<device>.yaml`、`survival.tsv` 和 `consistency_runs.log` 一同提交。

---

## 源码路径速查

| 路径 | 内容 |
|---|---|
| `include/kh_strategy.h` | 注册表 API：`kh_strategy_resolve`、`KH_STRATEGY_DECLARE`、控制函数 |
| `src/kh_strategy.c` | 注册表实现、模块参数处理、debugfs 条目 |
| `src/strategies/swapper_pg_dir.c` | `swapper_pg_dir` 的四条策略 |
| `src/strategies/kimage_voffset.c` | `kimage_voffset` 的三条策略 |
| `src/strategies/memstart_addr.c` | `memstart_addr` 的三条策略 |
| `src/strategies/cred_task.c` | `init_cred`、`init_thread_union`、`thread_size` 的策略 |
| `src/strategies/uaccess_copy.c` | `copy_to_user`、`copy_from_user`、`register_ex_table` 的策略 |
| `src/strategies/cross_cpu.c` | `stop_machine`、`aarch64_insn_patch_text_nosync` 的策略 |
| `src/strategies/runtime_sizes.c` | `pt_regs_size` 的策略 |
| `tests/userspace/test_strategy_*.c` | L1 mock 化单元测试 |
| `tests/kmod/test_resolver_*.c` | L2 在核按能力测试 |
| `tests/golden/strategy_matrix/` | L3 golden 产物与期望声明 |
| `scripts/lib/strategy_matrix.sh` | dump / check / accept 辅助脚本 |
