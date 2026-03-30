/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Integration tests for remote process hooking API.
 * Linux ARM64 only — skips gracefully on macOS and when ptrace is restricted.
 */

#include "test_framework.h"

#include <remote_hook.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <sys/wait.h>

#if !defined(__linux__) || defined(__ANDROID__)

TEST(remote_attach_detach)
{
    SKIP_TEST("remote hooking requires Linux (non-Android)");
}

TEST(remote_alloc_in_child)
{
    SKIP_TEST("remote hooking requires Linux (non-Android)");
}

TEST(remote_install_hook_in_child)
{
    SKIP_TEST("remote hooking requires Linux (non-Android)");
}

TEST(remote_hook_unhook_lifecycle)
{
    SKIP_TEST("remote hooking requires Linux (non-Android)");
}

#else /* __linux__ && !__ANDROID__ */

#include <stdio.h>
#include <fcntl.h>
#include <sys/mman.h>

/*
 * Check if ptrace is allowed on this system.
 * /proc/sys/kernel/yama/ptrace_scope:
 *   0 = classic ptrace (any process can attach)
 *   1 = restricted (only parent can attach — our fork tests work)
 *   2 = admin-only (CAP_SYS_PTRACE required)
 *   3 = no ptrace at all
 */
static int ptrace_allowed(void)
{
    FILE *f = fopen("/proc/sys/kernel/yama/ptrace_scope", "r");
    if (!f)
        return 1; /* No YAMA — ptrace allowed */
    int scope = 0;
    if (fscanf(f, "%d", &scope) != 1)
        scope = 0;
    fclose(f);
    /* scope 0 and 1 work for parent-attaches-to-child */
    return scope <= 1;
}

/*
 * Helper: fork a child that loops sleeping and optionally runs a function
 * before each sleep. The child writes its PID to the pipe for synchronization.
 * Returns child PID, or -1 on error.
 */
static pid_t fork_looping_child(int pipe_fd[2])
{
    if (pipe(pipe_fd) < 0)
        return -1;

    pid_t child = fork();
    if (child < 0) {
        close(pipe_fd[0]);
        close(pipe_fd[1]);
        return -1;
    }

    if (child == 0) {
        /* Child process */
        close(pipe_fd[0]); /* Close read end */

        /* Signal parent that we're ready */
        char ready = 'R';
        (void)write(pipe_fd[1], &ready, 1);

        /* Loop sleeping — parent will attach/detach/kill us */
        for (int i = 0; i < 300; i++) {
            usleep(10000); /* 10ms */
        }

        close(pipe_fd[1]);
        _exit(0);
    }

    /* Parent: close write end, wait for child to be ready */
    close(pipe_fd[1]);
    char buf;
    (void)read(pipe_fd[0], &buf, 1);

    return child;
}

/* Helper: kill child and wait for it to exit */
static void kill_child(pid_t pid)
{
    kill(pid, SIGKILL);
    int status;
    waitpid(pid, &status, 0);
}

/*
 * Test 1: Fork a child, attach via remote_hook_attach, detach —
 * child continues running normally.
 */
TEST(remote_attach_detach)
{
    if (!ptrace_allowed())
        SKIP_TEST("ptrace restricted (yama ptrace_scope > 1)");

    int pipe_fd[2];
    pid_t child = fork_looping_child(pipe_fd);
    ASSERT_NE(child, -1);

    /* Attach to child */
    remote_hook_handle_t h = remote_hook_attach(child);
    ASSERT_NOT_NULL(h);

    /* Detach */
    int ret = remote_hook_detach(h);
    ASSERT_EQ(ret, 0);

    /* Give child a moment to continue */
    usleep(50000);

    /* Verify child is still alive */
    int alive = (kill(child, 0) == 0);
    ASSERT_TRUE(alive);

    close(pipe_fd[0]);
    kill_child(child);
}

/*
 * Test 2: Fork a child, attach, allocate memory in child's address space,
 * detach — child continues normally.
 */
TEST(remote_alloc_in_child)
{
    if (!ptrace_allowed())
        SKIP_TEST("ptrace restricted (yama ptrace_scope > 1)");

    int pipe_fd[2];
    pid_t child = fork_looping_child(pipe_fd);
    ASSERT_NE(child, -1);

    remote_hook_handle_t h = remote_hook_attach(child);
    ASSERT_NOT_NULL(h);

    /* Allocate RW memory in child */
    uint64_t remote_addr = remote_hook_alloc(h, 4096, PROT_READ | PROT_WRITE);
    ASSERT_NE(remote_addr, (uint64_t)0);

    /* Allocate RX memory in child */
    uint64_t remote_rx = remote_hook_alloc(h, 4096, PROT_READ | PROT_EXEC);
    ASSERT_NE(remote_rx, (uint64_t)0);

    /* Two allocations should be at different addresses */
    ASSERT_NE(remote_addr, remote_rx);

    int ret = remote_hook_detach(h);
    ASSERT_EQ(ret, 0);

    /* Child should still be alive */
    usleep(50000);
    int alive = (kill(child, 0) == 0);
    ASSERT_TRUE(alive);

    close(pipe_fd[0]);
    kill_child(child);
}

/*
 * Test 3: Fork a child, remotely install a simple hook (write known bytes
 * to a code page), verify the write took effect by reading back via
 * /proc/pid/mem.
 */
TEST(remote_install_hook_in_child)
{
    if (!ptrace_allowed())
        SKIP_TEST("ptrace restricted (yama ptrace_scope > 1)");

    int pipe_fd[2];
    pid_t child = fork_looping_child(pipe_fd);
    ASSERT_NE(child, -1);

    remote_hook_handle_t h = remote_hook_attach(child);
    ASSERT_NOT_NULL(h);

    /* Allocate an RX page in the child to act as a "function" we hook */
    uint64_t target_page = remote_hook_alloc(h, 4096, PROT_READ | PROT_EXEC);
    ASSERT_NE(target_page, (uint64_t)0);

    /*
     * Create a small "transit" code payload: just a few NOP instructions
     * followed by a RET. This simulates writing hook trampoline code.
     * ARM64: NOP = 0xD503201F, RET = 0xD65F03C0
     */
    uint32_t transit_code[] = {
        0xD503201F, /* NOP */
        0xD503201F, /* NOP */
        0xD503201F, /* NOP */
        0xD65F03C0, /* RET */
    };
    uint64_t transit_size = sizeof(transit_code);

    int ret = remote_hook_install(h, target_page, transit_code, transit_size);
    ASSERT_EQ(ret, 0);

    /*
     * Verify the write by reading back from /proc/<pid>/mem.
     * The page should now contain our transit code.
     */
    char proc_mem_path[64];
    snprintf(proc_mem_path, sizeof(proc_mem_path), "/proc/%d/mem", child);
    int mem_fd = open(proc_mem_path, O_RDONLY);
    ASSERT_NE(mem_fd, -1);

    uint32_t readback[4] = {0};
    ssize_t n = pread(mem_fd, readback, sizeof(readback), (off_t)target_page);
    close(mem_fd);

    ASSERT_EQ(n, (ssize_t)sizeof(readback));
    ASSERT_EQ(readback[0], transit_code[0]);
    ASSERT_EQ(readback[1], transit_code[1]);
    ASSERT_EQ(readback[2], transit_code[2]);
    ASSERT_EQ(readback[3], transit_code[3]);

    ret = remote_hook_detach(h);
    ASSERT_EQ(ret, 0);

    close(pipe_fd[0]);
    kill_child(child);
}

/*
 * Test 4: Full remote hook + unhook lifecycle.
 * Attach → alloc → install → detach → child continues.
 * Then re-attach → overwrite with original code (unhook) → detach → child ok.
 */
TEST(remote_hook_unhook_lifecycle)
{
    if (!ptrace_allowed())
        SKIP_TEST("ptrace restricted (yama ptrace_scope > 1)");

    int pipe_fd[2];
    pid_t child = fork_looping_child(pipe_fd);
    ASSERT_NE(child, -1);

    /* Phase 1: Attach, alloc, install hook */
    remote_hook_handle_t h = remote_hook_attach(child);
    ASSERT_NOT_NULL(h);

    uint64_t target_page = remote_hook_alloc(h, 4096, PROT_READ | PROT_EXEC);
    ASSERT_NE(target_page, (uint64_t)0);

    /* Hook: write NOP sled */
    uint32_t hook_code[] = {
        0xD503201F, /* NOP */
        0xD503201F, /* NOP */
        0xD65F03C0, /* RET */
        0xD503201F, /* NOP */
    };
    int ret = remote_hook_install(h, target_page, hook_code, sizeof(hook_code));
    ASSERT_EQ(ret, 0);

    ret = remote_hook_detach(h);
    ASSERT_EQ(ret, 0);

    /* Child should still be alive after first detach */
    usleep(50000);
    ASSERT_TRUE(kill(child, 0) == 0);

    /* Phase 2: Re-attach, overwrite with "original" code (unhook) */
    h = remote_hook_attach(child);
    ASSERT_NOT_NULL(h);

    /* Unhook: overwrite with RET instructions */
    uint32_t orig_code[] = {
        0xD65F03C0, /* RET */
        0xD65F03C0, /* RET */
        0xD65F03C0, /* RET */
        0xD65F03C0, /* RET */
    };
    ret = remote_hook_install(h, target_page, orig_code, sizeof(orig_code));
    ASSERT_EQ(ret, 0);

    /* Verify the unhook by reading back */
    char proc_mem_path[64];
    snprintf(proc_mem_path, sizeof(proc_mem_path), "/proc/%d/mem", child);
    int mem_fd = open(proc_mem_path, O_RDONLY);
    ASSERT_NE(mem_fd, -1);

    uint32_t readback[4] = {0};
    ssize_t n = pread(mem_fd, readback, sizeof(readback), (off_t)target_page);
    close(mem_fd);

    ASSERT_EQ(n, (ssize_t)sizeof(readback));
    ASSERT_EQ(readback[0], orig_code[0]);
    ASSERT_EQ(readback[1], orig_code[1]);

    ret = remote_hook_detach(h);
    ASSERT_EQ(ret, 0);

    /* Child should survive the full lifecycle */
    usleep(50000);
    ASSERT_TRUE(kill(child, 0) == 0);

    close(pipe_fd[0]);
    kill_child(child);
}

#endif /* __linux__ */

int main(void)
{
    return RUN_ALL_TESTS();
}
