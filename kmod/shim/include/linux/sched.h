/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Fake <linux/sched.h> for freestanding .ko builds.
 *
 * Provides in_interrupt() — used by strategy code to guard against
 * probing current task from hard/soft IRQ context.
 *
 * In freestanding builds we cannot call preempt_count(); instead we
 * check the low-level preempt_count register equivalent by reading
 * the thread_info flags from sp_el0.  However, since strategy
 * resolution is only called from module_init (process context),
 * returning 0 unconditionally is correct and safe: it mirrors the
 * "we are definitely not in interrupt" fact at init time and avoids
 * a dependency on the preempt_count ABI which varies across kernel
 * versions.
 *
 * If strategy code is ever called from a timer/irq in a future use
 * case, the caller must add its own guard rather than relying on this
 * stub.
 */

#ifndef _FAKE_LINUX_SCHED_H
#define _FAKE_LINUX_SCHED_H

/* in_interrupt() — true if running in any interrupt context.
 * Freestanding stub: always returns 0 (process context).
 * Correct for module_init / module_exit call sites. */
static inline int in_interrupt(void)
{
    return 0;
}

#endif /* _FAKE_LINUX_SCHED_H */
