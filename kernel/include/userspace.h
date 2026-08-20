/* SPDX-License-Identifier: GPL-2.0-only */
/*
 *  Copyright (C) 2025-2026  Joel Bueno
 *  Copyright (C) 2025-2026  Carlos López
 */

#ifndef PCIEM_USERSPACE_H
#define PCIEM_USERSPACE_H

#include "pciem_api.h"
#include "trace/smptrace.h"

#include <linux/atomic.h>
#include <linux/spinlock.h>
#include <linux/types.h>
#include <linux/wait.h>
#include <linux/workqueue.h>
#include <linux/poll.h>
#include <linux/pci_regs.h>

int pciem_userspace_init(void);
void pciem_userspace_cleanup(void);
struct pciem_userspace_state *pciem_userspace_create(void);

extern const struct file_operations pciem_device_fops;

/*
 * Handler-routed notification callbacks, normally reached only via
 * smptrace's kprobe #PF trap (through a tracer's smptrace_ctx.notif.*).
 * Non-static so framework/mmap_trap.c's fault handler can call them
 * directly for a trapped mmap access, given
 * &us->tracers[func][bar_index].ctx.
 */
void pciem_notif_write(struct smptrace_ctx *ctx, struct smptrace_io *io);
int pciem_notif_read_sync(struct smptrace_ctx *ctx, struct smptrace_io *io);

/*
 * `struct pciem_userspace_state` is fully defined only in userspace.c;
 * everywhere else it's opaque. Given the `us` reached via
 * pciem_root_complex->owner_us, this gets back the smptrace_ctx to pass
 * into the two functions above. Returns NULL for an out-of-range
 * func/bar_index rather than asserting — callers may be handed these
 * from guest-controlled mmap offsets.
 */
struct smptrace_ctx *pciem_get_tracer_ctx(struct pciem_userspace_state *us,
                                         u8 func, u32 bar_index);

#endif
