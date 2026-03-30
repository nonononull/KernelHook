/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2026 bmax121.
 *
 * Remote process hooking stub — returns -ENOTSUP on unsupported platforms.
 */

#ifdef __USERSPACE__
#if !defined(__linux__) || defined(__ANDROID__)

#include <remote_hook.h>
#include <errno.h>

remote_hook_handle_t remote_hook_attach(int pid)
{
    (void)pid;
    return NULL;
}

int remote_hook_detach(remote_hook_handle_t handle)
{
    (void)handle;
    return -ENOTSUP;
}

uint64_t remote_hook_alloc(remote_hook_handle_t handle, uint64_t size, int prot)
{
    (void)handle;
    (void)size;
    (void)prot;
    return 0;
}

int remote_hook_install(remote_hook_handle_t handle, uint64_t func_addr,
                        const void *transit_code, uint64_t transit_size)
{
    (void)handle;
    (void)func_addr;
    (void)transit_code;
    (void)transit_size;
    return -ENOTSUP;
}

#endif /* !__linux__ || __ANDROID__ */
#endif /* __USERSPACE__ */
