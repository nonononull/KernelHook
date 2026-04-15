/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef _KH_TEST_PHASE6_KH_ROOT_H_
#define _KH_TEST_PHASE6_KH_ROOT_H_

/* Install execve/faccessat/fstatat hooks that elevate current to uid=0
 * on execve("/system/bin/kh_root", ...). Returns 0 on success, <0 if
 * required symbols (prepare_kernel_cred, commit_creds) unresolvable. */
int kh_root_install(void);

/* Uninstall all 3 hooks. */
void kh_root_uninstall(void);

#endif
