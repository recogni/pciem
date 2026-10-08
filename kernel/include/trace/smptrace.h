/* SPDX-License-Identifier: GPL-2.0 */
/*
 *  Copyright (C) 2026  Carlos López <carlos.lopezr4096@gmail.com>
 *  Copyright (C) 2026  Joel Bueno <buenocalvachejoel@gmail.com>
 */
#ifndef _PCIEM_SMPTRACE_H
#define _PCIEM_SMPTRACE_H
#include <asm/pgtable.h>
#include <linux/kprobes.h>
#include <linux/compiler.h>
#include <linux/rcupdate.h>
#include <linux/llist.h>
#include <linux/workqueue.h>

union smptrace_data {
	u8 raw[8];
	u8 byte;
	u16 word;
	u32 dword;
	u64 qword;
};

struct smptrace_io {
	u64 offset;
	union smptrace_data data;
	u32 size;
	/* The caller may sleep until a read is answered (a user-mode fault) */
	bool may_sleep;
};

struct smptrace_ctx;

/* A traced part of a tracer's range, [start, end), as offsets into it */
struct smptrace_range {
	u64 start;
	u64 end;
};

typedef void (*smptrace_handler_t)(struct smptrace_ctx *ctx, struct smptrace_io *);

/* User defined hooks */
struct smptrace_notifier {
	smptrace_handler_t read;
	smptrace_handler_t write;
	/*
	 * Synchronous read hook. Called BEFORE the shadow read with
	 * io->offset / io->size filled in. Returns 0 with io->data set to
	 * the value the faulting instruction must observe; nonzero falls
	 * back to the shadow read. Runs in the #PF emulation path
	 * (atomic context) — implementations must not sleep.
	 */
	int (*read_sync)(struct smptrace_ctx *ctx, struct smptrace_io *io);
};

/* A poisoned page table entry and the value it had. @va is the start of the
 * @size bytes the entry maps. */
struct smptrace_pte {
	struct list_head list;
	unsigned long va;
	unsigned long size;
#ifndef CONFIG_RISCV
	pteval_t pte;
#else
    u64 pte;
#endif
	unsigned int level;
};

/* An active traced ioremap region */
struct smptrace_map {
	struct list_head list;
	unsigned long va;
	unsigned long len;
	resource_size_t pa;
	/* Un-poisoned PTEs */
	struct list_head ptes;
	/* Huge leaves split to poison part of them, for the log */
	unsigned int nr_split;
	struct rcu_head rcu;
	/* On ctx->rejected when poisoning failed */
	struct llist_node reject;
};

struct smptrace_ctx {
	/* User hooks */
	struct smptrace_notifier notif;
	/* User-defined data for this tracer */
	uint64_t opaque;
	/* PA to be tracked */
	resource_size_t pa;
	/* Size of PA to be tracked */
	unsigned long len;
	/* Whether to emulate writes into the BAR */
	bool stop_writes;
	/*
	 * The parts of [pa, pa + len) that are traced: sorted, disjoint, not
	 * adjacent, page aligned. NULL traces all of it. Accesses elsewhere go
	 * to the backing memory as if nothing traced it. Set with
	 * smptrace_set_ranges() before smptrace_init(), and fixed until
	 * smptrace_destroy(), which frees it.
	 */
	struct smptrace_range *ranges;
	unsigned int nr_ranges;

	/*** Do not touch below here ***/

	/* Protects structural modifications to the lists */
	spinlock_t lock;
	/*
	 * Held while a map's saved entries are written back, by the iounmap()
	 * probe (riscv: its continuation) and by deactivation, so that only one
	 * of them restores a map and iounmap() goes on to free the mapping only
	 * after that. Taken outside lock. On riscv the restore sends IPIs
	 * while holding it, so there it is only taken with interrupts enabled
	 * (the continuation and deactivation); on x86 and arm64 the restore
	 * sends none, and the probe may take it with interrupts masked.
	 */
	spinlock_t restore_lock;

	/* Active mapped VA regions */
	struct list_head maps;

	/* Tracing hooks */
	struct kretprobe ioremap_krp;
	struct kprobe iounmap_kp;
	struct kprobe badarea_kp;

	/* Address of the shadow memory we maintain. Size is ctx->len */
	void __iomem *shadow_va;

	/* iounmap() continuations that were handed this ctx and have not yet
	 * finished with it (riscv) */
	atomic_t unmaps_pending;

	/* On the list smptrace_find_ctx() searches, while active */
	struct list_head active_node;

	/* Mappings that could not be poisoned. The ioremap() return handler
	 * cannot sleep, so reject_work iounmap()s them */
	struct llist_head rejected;
	struct work_struct reject_work;

	/* Whether this CPU is handling #PF or not */
	bool __percpu *in_pf;
};


int smptrace_set_ranges(struct smptrace_ctx *ctx, const struct smptrace_range *ranges,
                        unsigned int nr);
void smptrace_free_ranges(struct smptrace_ctx *ctx);
bool smptrace_traced(const struct smptrace_ctx *ctx, u64 off, u64 len);
int smptrace_init(struct smptrace_ctx *ctx);
/* Route userspace vfio-pci accesses (mmap, read, write) of traced BARs */
void smptrace_vfio_init(void);
void smptrace_vfio_exit(void);

void smptrace_destroy(struct smptrace_ctx *ctx);

#endif
