/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef _SYNC_H
#define _SYNC_H

#ifdef CONFIG_KH_CHAIN_RCU

int  sync_init(void);
void sync_cleanup(void);
void sync_read_lock(void);
void sync_read_unlock(void);
void sync_write_lock(void);
void sync_write_unlock(void);

#else

static inline int  sync_init(void) { return 0; }
static inline void sync_cleanup(void) {}
static inline void sync_read_lock(void) {}
static inline void sync_read_unlock(void) {}
static inline void sync_write_lock(void) {}
static inline void sync_write_unlock(void) {}

#endif /* CONFIG_KH_CHAIN_RCU */

#endif /* _SYNC_H */
