/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Fake <linux/debugfs.h> for freestanding .ko builds.
 *
 * ABI-safe layout: struct file_operations declares ONLY the 4 fields whose
 * offsets are frozen ABI in every LP64 ARM64 Linux kernel since file_operations
 * was introduced (owner@0, llseek@8, read@16, write@24). All later fields
 * (open/release/iopoll/splice_eof/uring_cmd/etc.) shift between kernel versions
 * and we MUST NOT use them.
 *
 * The trailing _padding[] array ensures sizeof(struct file_operations) is at
 * least as large as any GKI 4.4..6.12 kernel's actual struct (~280 bytes for
 * 6.12).  Padding bytes are zero-initialized in our static-const fops, so
 * even if a kernel codepath reads beyond offset 32, it sees NULL function
 * pointers and skips the callback.  This pad is defensive-only; the kernel's
 * normal access pattern is single-field deref (e.g. `fops->write(...)`).
 *
 * Project consumers MUST set only .owner, .llseek, .read, .write in any
 * file_operations instance.  Setting any other field is a layout violation.
 */

#ifndef _FAKE_LINUX_DEBUGFS_H
#define _FAKE_LINUX_DEBUGFS_H

#include <linux/types.h>
#include <linux/uaccess.h>   /* loff_t, ssize_t, __user, copy_to_user */

/* Forward declarations — only used as pointers in our APIs. */
struct dentry;
struct file;
struct module;
struct inode;

struct file_operations {
	struct module *owner;
	loff_t  (*llseek)(struct file *, loff_t, int);
	ssize_t (*read)(struct file *, char __user *, size_t, loff_t *);
	ssize_t (*write)(struct file *, const char __user *, size_t, loff_t *);
	/* Defensive padding — see header comment for rationale.
	 * 480 bytes covers GKI 6.12's ~280-byte struct with headroom. */
	char _padding[480];
};

extern struct dentry *debugfs_create_dir(const char *name,
					 struct dentry *parent);
extern struct dentry *debugfs_create_file(const char *name,
					  unsigned short mode,
					  struct dentry *parent, void *data,
					  const struct file_operations *fops);
extern void debugfs_remove_recursive(struct dentry *dentry);

/* IS_ERR_OR_NULL — true if ptr is NULL or an ERR_PTR (value in [-4095, -1]).
 * Matches kernel include/linux/err.h definition. */
#ifndef IS_ERR_OR_NULL
static inline int IS_ERR_OR_NULL(const void *ptr)
{
	return !ptr || ((unsigned long)ptr >= (unsigned long)-4095UL);
}
#endif

/* errno values used in the debugfs write handlers.
 * Match kernel <uapi/asm-generic/errno-base.h>. */
#ifndef EINVAL
#define EINVAL 22
#endif
#ifndef EFAULT
#define EFAULT 14
#endif

#endif /* _FAKE_LINUX_DEBUGFS_H */
