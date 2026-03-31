// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Minimal kernel module loader using init_module(2) / finit_module(2).
 *
 * Tries finit_module first (with IGNORE_MODVERSIONS|IGNORE_VERMAGIC),
 * then falls back to init_module (reads file into memory — bypasses
 * path-based signature checks on GKI kernels with MODULE_SIG_PROTECT).
 *
 * Usage: kmod_loader <module.ko> [param=value ...]
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef __NR_finit_module
#define __NR_finit_module 273  /* ARM64 syscall number */
#endif

#ifndef __NR_init_module
#define __NR_init_module 105  /* ARM64 syscall number */
#endif

#define MODULE_INIT_IGNORE_MODVERSIONS 1
#define MODULE_INIT_IGNORE_VERMAGIC    2

int main(int argc, char *argv[])
{
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <module.ko> [param=value ...]\n", argv[0]);
        return 1;
    }

    /* Concatenate remaining args as module parameters */
    char params[4096] = "";
    size_t off = 0;
    for (int i = 2; i < argc; i++) {
        int n = snprintf(params + off, sizeof(params) - off, "%s%s",
                         (i > 2 ? " " : ""), argv[i]);
        if (n > 0) off += (size_t)n;
    }

    int fd = open(argv[1], O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        fprintf(stderr, "open(%s): %s\n", argv[1], strerror(errno));
        return 1;
    }

    /* Try finit_module first */
    int flags = MODULE_INIT_IGNORE_MODVERSIONS | MODULE_INIT_IGNORE_VERMAGIC;
    int ret = (int)syscall(__NR_finit_module, fd, params, flags);
    int err = errno;

    if (ret == 0) {
        close(fd);
        printf("Module %s loaded (finit_module)\n", argv[1]);
        return 0;
    }

    fprintf(stderr, "finit_module: %s (errno=%d), trying init_module...\n",
            strerror(err), err);

    /* Fallback: init_module — read file into memory.
     * This bypasses path-based checks (GKI MODULE_SIG_PROTECT). */
    struct stat st;
    if (fstat(fd, &st) < 0) {
        fprintf(stderr, "fstat(%s): %s\n", argv[1], strerror(errno));
        close(fd);
        return 1;
    }

    void *buf = malloc(st.st_size);
    if (!buf) {
        fprintf(stderr, "malloc(%ld): out of memory\n", (long)st.st_size);
        close(fd);
        return 1;
    }

    if (lseek(fd, 0, SEEK_SET) < 0 ||
        read(fd, buf, st.st_size) != st.st_size) {
        fprintf(stderr, "read(%s): %s\n", argv[1], strerror(errno));
        free(buf);
        close(fd);
        return 1;
    }
    close(fd);

    ret = (int)syscall(__NR_init_module, buf, st.st_size, params);
    err = errno;
    free(buf);

    if (ret != 0) {
        fprintf(stderr, "init_module(%s): %s (errno=%d)\n",
                argv[1], strerror(err), err);
        return 1;
    }

    printf("Module %s loaded (init_module)\n", argv[1]);
    return 0;
}
