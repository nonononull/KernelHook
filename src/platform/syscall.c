/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2026 bmax121.
 *
 * Syscall-level hook infrastructure — port of KernelPatch
 * kernel/patch/common/syscall.c, 64-bit only (no compat branches,
 * no AArch32 table, no kstorage).
 *
 * Responsibilities:
 *   - Resolve `sys_call_table` via kallsyms (kh_sys_call_table).
 *   - Detect pt_regs wrapper ABI by presence of `__arm64_sys_openat`
 *     (kh_has_syscall_wrapper).
 *   - Per-syscall entry resolution via a name table + ksyms probe
 *     (kh_syscalln_name_addr / kh_syscalln_addr).
 *   - `kh_hook_syscalln` / `kh_unhook_syscalln`: prefer fp-hook on the
 *     sys_call_table slot, fall back to inline hook on the entry.
 *   - `kh_raw_syscallN`: in-kernel syscall invocation (wrapper-aware).
 */

#include <types.h>
#include <kh_log.h>
#include <hook.h>
#include <symbol.h>
#include <syscall.h>
#include <syscall_names.h>

/*
 * struct pt_regs access.
 *
 * Layout assumption (stable on ARM64 since the kernel exists):
 *   struct pt_regs { unsigned long regs[31]; unsigned long sp; ... };
 *
 * In kbuild mode we include the real <asm/ptrace.h>. In freestanding
 * we define a locally-named minimal struct with the same layout — the
 * embedded raw-syscall invocation only writes regs[0..6] and regs[8]
 * (x8 = syscall number on arm64), all reachable at offset 8*N.
 */
#ifdef KMOD_FREESTANDING
/* Minimal freestanding pt_regs. Field layout must match the kernel's
 * `unsigned long regs[31]` prefix. Any tail fields the kernel entry
 * path touches (sp, pc, pstate, syscallno, etc.) are left zero — the
 * syscall entry only consults regs[0..7] + regs[8]. */
struct kh_pt_regs_shim {
    uint64_t regs[31];
    uint64_t sp;
    uint64_t pc;
    uint64_t pstate;
    uint64_t orig_x0;
    int32_t  syscallno;
    uint32_t _pad;
    uint64_t sdei_ttbr1;
    uint64_t pmr_save;
    uint64_t stackframe[2];
    uint64_t lockdep_hardirqs;
    uint64_t exit_rcu;
};
#define KH_PT_REGS struct kh_pt_regs_shim
#else
#include <asm/ptrace.h>
#define KH_PT_REGS struct pt_regs
#endif

/* ---- Globals ---- */

uintptr_t *kh_sys_call_table = NULL;
int        kh_has_syscall_wrapper = 0;

/* ---- Name table (ported verbatim from KP sysname.c, 64-bit only) ---- */

struct kh_syscall_name_entry
    kh_syscall_name_table[KH_SYSCALL_NAME_TABLE_SIZE] = {
    [0]   = { "sys_io_setup", 0 },
    [1]   = { "sys_io_destroy", 0 },
    [2]   = { "sys_io_submit", 0 },
    [3]   = { "sys_io_cancel", 0 },
    [4]   = { "sys_io_getevents", 0 },
    [5]   = { "sys_setxattr", 0 },
    [6]   = { "sys_lsetxattr", 0 },
    [7]   = { "sys_fsetxattr", 0 },
    [8]   = { "sys_getxattr", 0 },
    [9]   = { "sys_lgetxattr", 0 },
    [10]  = { "sys_fgetxattr", 0 },
    [11]  = { "sys_listxattr", 0 },
    [12]  = { "sys_llistxattr", 0 },
    [13]  = { "sys_flistxattr", 0 },
    [14]  = { "sys_removexattr", 0 },
    [15]  = { "sys_lremovexattr", 0 },
    [16]  = { "sys_fremovexattr", 0 },
    [17]  = { "sys_getcwd", 0 },
    [19]  = { "sys_eventfd2", 0 },
    [20]  = { "sys_epoll_create1", 0 },
    [21]  = { "sys_epoll_ctl", 0 },
    [22]  = { "sys_epoll_pwait", 0 },
    [23]  = { "sys_dup", 0 },
    [24]  = { "sys_dup3", 0 },
    [25]  = { "sys_fcntl", 0 },
    [26]  = { "sys_inotify_init1", 0 },
    [27]  = { "sys_inotify_add_watch", 0 },
    [28]  = { "sys_inotify_rm_watch", 0 },
    [29]  = { "sys_ioctl", 0 },
    [30]  = { "sys_ioprio_set", 0 },
    [31]  = { "sys_ioprio_get", 0 },
    [32]  = { "sys_flock", 0 },
    [33]  = { "sys_mknodat", 0 },
    [34]  = { "sys_mkdirat", 0 },
    [35]  = { "sys_unlinkat", 0 },
    [36]  = { "sys_symlinkat", 0 },
    [37]  = { "sys_linkat", 0 },
    [38]  = { "sys_renameat", 0 },
    [39]  = { "sys_umount", 0 },
    [40]  = { "sys_mount", 0 },
    [41]  = { "sys_pivot_root", 0 },
    [43]  = { "sys_statfs", 0 },
    [44]  = { "sys_fstatfs", 0 },
    [45]  = { "sys_truncate", 0 },
    [46]  = { "sys_ftruncate", 0 },
    [47]  = { "sys_fallocate", 0 },
    [48]  = { "sys_faccessat", 0 },
    [49]  = { "sys_chdir", 0 },
    [50]  = { "sys_fchdir", 0 },
    [51]  = { "sys_chroot", 0 },
    [52]  = { "sys_fchmod", 0 },
    [53]  = { "sys_fchmodat", 0 },
    [54]  = { "sys_fchownat", 0 },
    [55]  = { "sys_fchown", 0 },
    [56]  = { "sys_openat", 0 },
    [57]  = { "sys_close", 0 },
    [58]  = { "sys_vhangup", 0 },
    [59]  = { "sys_pipe2", 0 },
    [60]  = { "sys_quotactl", 0 },
    [61]  = { "sys_getdents64", 0 },
    [62]  = { "sys_lseek", 0 },
    [63]  = { "sys_read", 0 },
    [64]  = { "sys_write", 0 },
    [65]  = { "sys_readv", 0 },
    [66]  = { "sys_writev", 0 },
    [67]  = { "sys_pread64", 0 },
    [68]  = { "sys_pwrite64", 0 },
    [69]  = { "sys_preadv", 0 },
    [70]  = { "sys_pwritev", 0 },
    [71]  = { "sys_sendfile64", 0 },
    [72]  = { "sys_pselect6", 0 },
    [73]  = { "sys_ppoll", 0 },
    [74]  = { "sys_signalfd4", 0 },
    [75]  = { "sys_vmsplice", 0 },
    [76]  = { "sys_splice", 0 },
    [77]  = { "sys_tee", 0 },
    [78]  = { "sys_readlinkat", 0 },
    [79]  = { "sys_newfstatat", 0 },
    [80]  = { "sys_newfstat", 0 },
    [81]  = { "sys_sync", 0 },
    [82]  = { "sys_fsync", 0 },
    [83]  = { "sys_fdatasync", 0 },
    [84]  = { "sys_sync_file_range", 0 },
    [85]  = { "sys_timerfd_create", 0 },
    [86]  = { "sys_timerfd_settime", 0 },
    [87]  = { "sys_timerfd_gettime", 0 },
    [88]  = { "sys_utimensat", 0 },
    [89]  = { "sys_acct", 0 },
    [90]  = { "sys_capget", 0 },
    [91]  = { "sys_capset", 0 },
    [92]  = { "sys_arm64_personality", 0 },
    [93]  = { "sys_exit", 0 },
    [94]  = { "sys_exit_group", 0 },
    [95]  = { "sys_waitid", 0 },
    [96]  = { "sys_set_tid_address", 0 },
    [97]  = { "sys_unshare", 0 },
    [98]  = { "sys_futex", 0 },
    [99]  = { "sys_set_robust_list", 0 },
    [100] = { "sys_get_robust_list", 0 },
    [101] = { "sys_nanosleep", 0 },
    [102] = { "sys_getitimer", 0 },
    [103] = { "sys_setitimer", 0 },
    [104] = { "sys_kexec_load", 0 },
    [105] = { "sys_init_module", 0 },
    [106] = { "sys_delete_module", 0 },
    [107] = { "sys_timer_create", 0 },
    [108] = { "sys_timer_gettime", 0 },
    [109] = { "sys_timer_getoverrun", 0 },
    [110] = { "sys_timer_settime", 0 },
    [111] = { "sys_timer_delete", 0 },
    [112] = { "sys_clock_settime", 0 },
    [113] = { "sys_clock_gettime", 0 },
    [114] = { "sys_clock_getres", 0 },
    [115] = { "sys_clock_nanosleep", 0 },
    [116] = { "sys_syslog", 0 },
    [117] = { "sys_ptrace", 0 },
    [118] = { "sys_sched_setparam", 0 },
    [119] = { "sys_sched_setscheduler", 0 },
    [120] = { "sys_sched_getscheduler", 0 },
    [121] = { "sys_sched_getparam", 0 },
    [122] = { "sys_sched_setaffinity", 0 },
    [123] = { "sys_sched_getaffinity", 0 },
    [124] = { "sys_sched_yield", 0 },
    [125] = { "sys_sched_get_priority_max", 0 },
    [126] = { "sys_sched_get_priority_min", 0 },
    [127] = { "sys_sched_rr_get_interval", 0 },
    [128] = { "sys_restart_syscall", 0 },
    [129] = { "sys_kill", 0 },
    [130] = { "sys_tkill", 0 },
    [131] = { "sys_tgkill", 0 },
    [132] = { "sys_sigaltstack", 0 },
    [133] = { "sys_rt_sigsuspend", 0 },
    [134] = { "sys_rt_sigaction", 0 },
    [135] = { "sys_rt_sigprocmask", 0 },
    [136] = { "sys_rt_sigpending", 0 },
    [137] = { "sys_rt_sigtimedwait", 0 },
    [138] = { "sys_rt_sigqueueinfo", 0 },
    [139] = { "sys_rt_sigreturn", 0 },
    [140] = { "sys_setpriority", 0 },
    [141] = { "sys_getpriority", 0 },
    [142] = { "sys_reboot", 0 },
    [143] = { "sys_setregid", 0 },
    [144] = { "sys_setgid", 0 },
    [145] = { "sys_setreuid", 0 },
    [146] = { "sys_setuid", 0 },
    [147] = { "sys_setresuid", 0 },
    [148] = { "sys_getresuid", 0 },
    [149] = { "sys_setresgid", 0 },
    [150] = { "sys_getresgid", 0 },
    [151] = { "sys_setfsuid", 0 },
    [152] = { "sys_setfsgid", 0 },
    [153] = { "sys_times", 0 },
    [154] = { "sys_setpgid", 0 },
    [155] = { "sys_getpgid", 0 },
    [156] = { "sys_getsid", 0 },
    [157] = { "sys_setsid", 0 },
    [158] = { "sys_getgroups", 0 },
    [159] = { "sys_setgroups", 0 },
    [160] = { "sys_newuname", 0 },
    [161] = { "sys_sethostname", 0 },
    [162] = { "sys_setdomainname", 0 },
    [163] = { "sys_getrlimit", 0 },
    [164] = { "sys_setrlimit", 0 },
    [165] = { "sys_getrusage", 0 },
    [166] = { "sys_umask", 0 },
    [167] = { "sys_prctl", 0 },
    [168] = { "sys_getcpu", 0 },
    [169] = { "sys_gettimeofday", 0 },
    [170] = { "sys_settimeofday", 0 },
    [171] = { "sys_adjtimex", 0 },
    [172] = { "sys_getpid", 0 },
    [173] = { "sys_getppid", 0 },
    [174] = { "sys_getuid", 0 },
    [175] = { "sys_geteuid", 0 },
    [176] = { "sys_getgid", 0 },
    [177] = { "sys_getegid", 0 },
    [178] = { "sys_gettid", 0 },
    [179] = { "sys_sysinfo", 0 },
    [180] = { "sys_mq_open", 0 },
    [181] = { "sys_mq_unlink", 0 },
    [182] = { "sys_mq_timedsend", 0 },
    [183] = { "sys_mq_timedreceive", 0 },
    [184] = { "sys_mq_notify", 0 },
    [185] = { "sys_mq_getsetattr", 0 },
    [186] = { "sys_msgget", 0 },
    [187] = { "sys_msgctl", 0 },
    [188] = { "sys_msgrcv", 0 },
    [189] = { "sys_msgsnd", 0 },
    [190] = { "sys_semget", 0 },
    [191] = { "sys_semctl", 0 },
    [192] = { "sys_semtimedop", 0 },
    [193] = { "sys_semop", 0 },
    [194] = { "sys_shmget", 0 },
    [195] = { "sys_shmctl", 0 },
    [196] = { "sys_shmat", 0 },
    [197] = { "sys_shmdt", 0 },
    [198] = { "sys_socket", 0 },
    [199] = { "sys_socketpair", 0 },
    [200] = { "sys_bind", 0 },
    [201] = { "sys_listen", 0 },
    [202] = { "sys_accept", 0 },
    [203] = { "sys_connect", 0 },
    [204] = { "sys_getsockname", 0 },
    [205] = { "sys_getpeername", 0 },
    [206] = { "sys_sendto", 0 },
    [207] = { "sys_recvfrom", 0 },
    [208] = { "sys_setsockopt", 0 },
    [209] = { "sys_getsockopt", 0 },
    [210] = { "sys_shutdown", 0 },
    [211] = { "sys_sendmsg", 0 },
    [212] = { "sys_recvmsg", 0 },
    [213] = { "sys_readahead", 0 },
    [214] = { "sys_brk", 0 },
    [215] = { "sys_munmap", 0 },
    [216] = { "sys_mremap", 0 },
    [217] = { "sys_add_key", 0 },
    [218] = { "sys_request_key", 0 },
    [219] = { "sys_keyctl", 0 },
    [220] = { "sys_clone", 0 },
    [221] = { "sys_execve", 0 },
    [222] = { "sys_mmap", 0 },
    [223] = { "sys_fadvise64_64", 0 },
    [224] = { "sys_swapon", 0 },
    [225] = { "sys_swapoff", 0 },
    [226] = { "sys_mprotect", 0 },
    [227] = { "sys_msync", 0 },
    [228] = { "sys_mlock", 0 },
    [229] = { "sys_munlock", 0 },
    [230] = { "sys_mlockall", 0 },
    [231] = { "sys_munlockall", 0 },
    [232] = { "sys_mincore", 0 },
    [233] = { "sys_madvise", 0 },
    [234] = { "sys_remap_file_pages", 0 },
    [235] = { "sys_mbind", 0 },
    [236] = { "sys_get_mempolicy", 0 },
    [237] = { "sys_set_mempolicy", 0 },
    [238] = { "sys_migrate_pages", 0 },
    [239] = { "sys_move_pages", 0 },
    [240] = { "sys_rt_tgsigqueueinfo", 0 },
    [241] = { "sys_perf_event_open", 0 },
    [242] = { "sys_accept4", 0 },
    [243] = { "sys_recvmmsg", 0 },
    [260] = { "sys_wait4", 0 },
    [261] = { "sys_prlimit64", 0 },
    [262] = { "sys_fanotify_init", 0 },
    [263] = { "sys_fanotify_mark", 0 },
    [264] = { "sys_name_to_handle_at", 0 },
    [265] = { "sys_open_by_handle_at", 0 },
    [266] = { "sys_clock_adjtime", 0 },
    [267] = { "sys_syncfs", 0 },
    [268] = { "sys_setns", 0 },
    [269] = { "sys_sendmmsg", 0 },
    [270] = { "sys_process_vm_readv", 0 },
    [271] = { "sys_process_vm_writev", 0 },
    [272] = { "sys_kcmp", 0 },
    [273] = { "sys_finit_module", 0 },
    [274] = { "sys_sched_setattr", 0 },
    [275] = { "sys_sched_getattr", 0 },
    [276] = { "sys_renameat2", 0 },
    [277] = { "sys_seccomp", 0 },
    [278] = { "sys_getrandom", 0 },
    [279] = { "sys_memfd_create", 0 },
    [280] = { "sys_bpf", 0 },
    [281] = { "sys_execveat", 0 },
    [282] = { "sys_userfaultfd", 0 },
    [283] = { "sys_membarrier", 0 },
    [284] = { "sys_mlock2", 0 },
    [285] = { "sys_copy_file_range", 0 },
    [286] = { "sys_preadv2", 0 },
    [287] = { "sys_pwritev2", 0 },
    [288] = { "sys_pkey_mprotect", 0 },
    [289] = { "sys_pkey_alloc", 0 },
    [290] = { "sys_pkey_free", 0 },
    [291] = { "sys_statx", 0 },
    [292] = { "sys_io_pgetevents", 0 },
    [293] = { "sys_rseq", 0 },
    [294] = { "sys_kexec_file_load", 0 },
    [424] = { "sys_pidfd_send_signal", 0 },
    [425] = { "sys_io_uring_setup", 0 },
    [426] = { "sys_io_uring_enter", 0 },
    [427] = { "sys_io_uring_register", 0 },
    [428] = { "sys_open_tree", 0 },
    [429] = { "sys_move_mount", 0 },
    [430] = { "sys_fsopen", 0 },
    [431] = { "sys_fsconfig", 0 },
    [432] = { "sys_fsmount", 0 },
    [433] = { "sys_fspick", 0 },
    [434] = { "sys_pidfd_open", 0 },
    [435] = { "sys_clone3", 0 },
    [436] = { "sys_close_range", 0 },
    [437] = { "sys_openat2", 0 },
    [438] = { "sys_pidfd_getfd", 0 },
    [439] = { "sys_faccessat2", 0 },
    [440] = { "sys_process_madvise", 0 },
    [441] = { "sys_epoll_pwait2", 0 },
    [442] = { "sys_mount_setattr", 0 },
    [443] = { "sys_quotactl_fd", 0 },
    [444] = { "sys_landlock_create_ruleset", 0 },
    [445] = { "sys_landlock_add_rule", 0 },
    [446] = { "sys_landlock_restrict_self", 0 },
    [447] = { "sys_memfd_secret", 0 },
    [448] = { "sys_process_mrelease", 0 },
    [449] = { "sys_futex_waitv", 0 },
    [450] = { "sys_set_mempolicy_home_node", 0 },
    [451] = { "sys_cachestat", 0 },
};

/* ---- Tiny string helpers (freestanding-safe) ---- */

static int kh_strlen(const char *s)
{
    int n = 0;
    while (s[n]) n++;
    return n;
}

static void kh_strcpy_at(char *dst, int *pos, int cap, const char *src)
{
    while (*src && *pos < cap - 1) {
        dst[(*pos)++] = *src++;
    }
    dst[*pos] = '\0';
}

/* ---- Per-syscall entry resolution ---- */

__attribute__((no_sanitize("kcfi")))
uintptr_t kh_syscalln_name_addr(int nr)
{
    if (nr < 0 || nr >= KH_SYSCALL_NAME_TABLE_SIZE)
        return 0;
    if (kh_syscall_name_table[nr].addr)
        return kh_syscall_name_table[nr].addr;

    const char *name = kh_syscall_name_table[nr].name;
    if (!name)
        return 0;

    /* Try each (prefix, suffix) combination. __arm64_ prefix matches
     * the pt_regs wrapper stub on modern ARM64 kernels; empty prefix
     * matches older kernels or direct sys_xxx symbols. .cfi_jt /
     * .cfi suffixes cover CFI-jump-table-built kernels like Pixel
     * GKI 6.1. */
    static const char *const prefixes[2] = { "__arm64_", "" };
    static const char *const suffixes[3] = { ".cfi_jt", ".cfi", "" };

    char buf[128];
    uintptr_t addr = 0;

    for (int i = 0; i < 2 && !addr; i++) {
        for (int j = 0; j < 3 && !addr; j++) {
            int pos = 0;
            int plen = kh_strlen(prefixes[i]);
            int nlen = kh_strlen(name);
            int slen = kh_strlen(suffixes[j]);
            if (plen + nlen + slen + 1 > (int)sizeof(buf))
                continue;
            kh_strcpy_at(buf, &pos, sizeof(buf), prefixes[i]);
            kh_strcpy_at(buf, &pos, sizeof(buf), name);
            kh_strcpy_at(buf, &pos, sizeof(buf), suffixes[j]);
            addr = (uintptr_t)ksyms_lookup(buf);
        }
    }

    kh_syscall_name_table[nr].addr = addr;
    return addr;
}

__attribute__((no_sanitize("kcfi")))
uintptr_t kh_syscalln_addr(int nr)
{
    if (kh_sys_call_table) {
        if (nr < 0 || nr >= KH_SYSCALL_NAME_TABLE_SIZE)
            return 0;
        return kh_sys_call_table[nr];
    }
    return kh_syscalln_name_addr(nr);
}

/* ---- Raw syscall invocation ---- */

typedef long (*kh_wrap_raw_t)(const KH_PT_REGS *regs);
typedef long (*kh_raw0_t)(void);
typedef long (*kh_raw1_t)(long);
typedef long (*kh_raw2_t)(long, long);
typedef long (*kh_raw3_t)(long, long, long);
typedef long (*kh_raw4_t)(long, long, long, long);
typedef long (*kh_raw5_t)(long, long, long, long, long);
typedef long (*kh_raw6_t)(long, long, long, long, long, long);

/* Zero-init a pt_regs frame without relying on memset. */
static inline void kh_zero_regs(KH_PT_REGS *r)
{
    uint8_t *p = (uint8_t *)r;
    for (unsigned i = 0; i < sizeof(*r); i++) p[i] = 0;
}

#define KH_SYS_NR_FIELD(regs, nr)                                             \
    do {                                                                       \
        (regs).regs[8] = (uint64_t)(nr);                                       \
    } while (0)

__attribute__((no_sanitize("kcfi")))
long kh_raw_syscall0(long nr)
{
    uintptr_t addr = kh_syscalln_addr((int)nr);
    if (!addr) return -38; /* -ENOSYS */
    if (kh_has_syscall_wrapper) {
        KH_PT_REGS regs;
        kh_zero_regs(&regs);
        KH_SYS_NR_FIELD(regs, nr);
        return ((kh_wrap_raw_t)addr)(&regs);
    }
    return ((kh_raw0_t)addr)();
}

__attribute__((no_sanitize("kcfi")))
long kh_raw_syscall1(long nr, long a0)
{
    uintptr_t addr = kh_syscalln_addr((int)nr);
    if (!addr) return -38;
    if (kh_has_syscall_wrapper) {
        KH_PT_REGS regs;
        kh_zero_regs(&regs);
        KH_SYS_NR_FIELD(regs, nr);
        regs.regs[0] = a0;
        return ((kh_wrap_raw_t)addr)(&regs);
    }
    return ((kh_raw1_t)addr)(a0);
}

__attribute__((no_sanitize("kcfi")))
long kh_raw_syscall2(long nr, long a0, long a1)
{
    uintptr_t addr = kh_syscalln_addr((int)nr);
    if (!addr) return -38;
    if (kh_has_syscall_wrapper) {
        KH_PT_REGS regs;
        kh_zero_regs(&regs);
        KH_SYS_NR_FIELD(regs, nr);
        regs.regs[0] = a0;
        regs.regs[1] = a1;
        return ((kh_wrap_raw_t)addr)(&regs);
    }
    return ((kh_raw2_t)addr)(a0, a1);
}

__attribute__((no_sanitize("kcfi")))
long kh_raw_syscall3(long nr, long a0, long a1, long a2)
{
    uintptr_t addr = kh_syscalln_addr((int)nr);
    if (!addr) return -38;
    if (kh_has_syscall_wrapper) {
        KH_PT_REGS regs;
        kh_zero_regs(&regs);
        KH_SYS_NR_FIELD(regs, nr);
        regs.regs[0] = a0;
        regs.regs[1] = a1;
        regs.regs[2] = a2;
        return ((kh_wrap_raw_t)addr)(&regs);
    }
    return ((kh_raw3_t)addr)(a0, a1, a2);
}

__attribute__((no_sanitize("kcfi")))
long kh_raw_syscall4(long nr, long a0, long a1, long a2, long a3)
{
    uintptr_t addr = kh_syscalln_addr((int)nr);
    if (!addr) return -38;
    if (kh_has_syscall_wrapper) {
        KH_PT_REGS regs;
        kh_zero_regs(&regs);
        KH_SYS_NR_FIELD(regs, nr);
        regs.regs[0] = a0;
        regs.regs[1] = a1;
        regs.regs[2] = a2;
        regs.regs[3] = a3;
        return ((kh_wrap_raw_t)addr)(&regs);
    }
    return ((kh_raw4_t)addr)(a0, a1, a2, a3);
}

__attribute__((no_sanitize("kcfi")))
long kh_raw_syscall5(long nr, long a0, long a1, long a2, long a3, long a4)
{
    uintptr_t addr = kh_syscalln_addr((int)nr);
    if (!addr) return -38;
    if (kh_has_syscall_wrapper) {
        KH_PT_REGS regs;
        kh_zero_regs(&regs);
        KH_SYS_NR_FIELD(regs, nr);
        regs.regs[0] = a0;
        regs.regs[1] = a1;
        regs.regs[2] = a2;
        regs.regs[3] = a3;
        regs.regs[4] = a4;
        return ((kh_wrap_raw_t)addr)(&regs);
    }
    return ((kh_raw5_t)addr)(a0, a1, a2, a3, a4);
}

__attribute__((no_sanitize("kcfi")))
long kh_raw_syscall6(long nr, long a0, long a1, long a2, long a3,
                     long a4, long a5)
{
    uintptr_t addr = kh_syscalln_addr((int)nr);
    if (!addr) return -38;
    if (kh_has_syscall_wrapper) {
        KH_PT_REGS regs;
        kh_zero_regs(&regs);
        KH_SYS_NR_FIELD(regs, nr);
        regs.regs[0] = a0;
        regs.regs[1] = a1;
        regs.regs[2] = a2;
        regs.regs[3] = a3;
        regs.regs[4] = a4;
        regs.regs[5] = a5;
        return ((kh_wrap_raw_t)addr)(&regs);
    }
    return ((kh_raw6_t)addr)(a0, a1, a2, a3, a4, a5);
}

/* ---- Hook install / remove ---- */

__attribute__((no_sanitize("kcfi")))
hook_err_t kh_hook_syscalln(int nr, int narg, void *before, void *after,
                            void *udata)
{
    int phys_narg = kh_has_syscall_wrapper ? 1 : narg;

    if (kh_sys_call_table) {
        if (nr < 0 || nr >= KH_SYSCALL_NAME_TABLE_SIZE)
            return HOOK_BAD_ADDRESS;
        uintptr_t fp_addr = (uintptr_t)(kh_sys_call_table + nr);
        return fp_hook_wrap(fp_addr, phys_narg, before, after, udata, 0);
    }

    uintptr_t addr = kh_syscalln_name_addr(nr);
    if (!addr)
        return HOOK_BAD_ADDRESS;
    return hook_wrap((void *)addr, phys_narg, before, after, udata, 0);
}

__attribute__((no_sanitize("kcfi")))
void kh_unhook_syscalln(int nr, void *before, void *after)
{
    if (kh_sys_call_table) {
        if (nr < 0 || nr >= KH_SYSCALL_NAME_TABLE_SIZE)
            return;
        uintptr_t fp_addr = (uintptr_t)(kh_sys_call_table + nr);
        fp_hook_unwrap(fp_addr, before, after);
        return;
    }

    uintptr_t addr = kh_syscalln_name_addr(nr);
    if (addr)
        hook_unwrap((void *)addr, before, after);
}

/* ---- Init ---- */

__attribute__((no_sanitize("kcfi")))
int kh_syscall_init(void)
{
    kh_sys_call_table =
        (uintptr_t *)(uintptr_t)ksyms_lookup("sys_call_table");
    kh_has_syscall_wrapper =
        ksyms_lookup("__arm64_sys_openat") ? 1 : 0;

    pr_info("syscall_init: table=%llx wrapper=%d",
            (unsigned long long)(uintptr_t)kh_sys_call_table,
            kh_has_syscall_wrapper);

    if (!kh_sys_call_table) {
        pr_warn("syscall_init: sys_call_table not resolved — "
                "kh_hook_syscalln will fall back to inline hooks");
    }
    return 0;
}
