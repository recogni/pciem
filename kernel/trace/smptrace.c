// SPDX-License-Identifier: GPL-2.0
/*
 *  Copyright (C) 2026  Carlos López <carlos.lopezr4096@gmail.com>
 *  Copyright (C) 2026  Joel Bueno <buenocalvachejoel@gmail.com>
 *
 * smptrace: SMP MMIO read/write tracing
 *
 * This module implements something similar to mmiotrace in the Linux kernel,
 * (see Documentation/trace/mmiotrace.rst), with some differences. The main
 * change is that smptrace works with multiple CPUs concurrently, and has first
 * class software APIs for other in-kernel users (instead of just exposing a
 * debugfs interface).
 *
 * The reason why this implementation works in SMP configurations is that
 * single-stepping is not used, avoiding the potential races with that approach.
 * Instead, we hook #PF to emulate faulting MMIO instructions, allowing a
 * strictly per-CPU approach, with little inter-CPU synchronization.
 *
 * mmiotrace also has first-class support in the kernel, while smptrace uses
 * kprobes to hook the relevant pieces. While this works, it may be more
 * brittle to future changes in the  kernel. Do not use this in a production
 * system.
 *
 * smptrace uses as little kernel APIs as possible, since it is built out of
 * tree. This also implies vendoring some kernel code, namely the x86
 * isntruction decoder, which is not exported to kernel modules.
 */
#define pr_fmt(fmt) KBUILD_MODNAME ": trace: " fmt

#include <linux/srcu.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/kprobes.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/smp.h>
#include <linux/mm.h>
#include <linux/notifier.h>
#include <linux/kallsyms.h>
#include <linux/sched.h>
#include <linux/ptrace.h>
#include <linux/version.h>
#include <linux/rculist.h>
#include <linux/wait_bit.h>
#include <linux/sort.h>
#include <asm/io.h>
#include <asm/tlbflush.h>
#include "trace/smptrace.h"
#include "trace/smptrace_internal.h"

static bool __fill_io_notif(struct smptrace_io *io, const u8 *data, u32 size,
                            u64 off)
{
	io->offset = off;
	io->size = size;
	switch (size) {
	case 1:
		io->data.byte = *(u8 *)data;
		break;
	case 2:
		io->data.word = *(u16 *)data;
		break;
	case 4:
		io->data.dword = *(u32 *)data;
		break;
	case 8:
		io->data.qword = *(u64 *)data;
		break;
	default:
		pr_warn_once("unsupported access size %u, dropping notification\n",
		             size);
		return false;
	}
	return true;
}

static int smptrace_range_cmp(const void *a, const void *b)
{
	const struct smptrace_range *x = a, *y = b;

	return x->start < y->start ? -1 : x->start > y->start;
}

/*
 * Traces only the given parts of the tracer's range, as offsets into it. Each
 * must be page aligned (its end may instead be the end of the range) and none
 * may overlap; adjacent ones are merged. Called before smptrace_init(). With
 * nr == 0 the whole range is traced, as when this is never called.
 */
int smptrace_set_ranges(struct smptrace_ctx *ctx, const struct smptrace_range *ranges,
                        unsigned int nr)
{
	struct smptrace_range *r;
	unsigned int i, n = 0;

	if (!nr)
		return 0;

	r = kmemdup(ranges, array_size(nr, sizeof(*r)), GFP_KERNEL);
	if (!r)
		return -ENOMEM;
	sort(r, nr, sizeof(*r), smptrace_range_cmp, NULL);

	for (i = 0; i < nr; i++) {
		if (r[i].start >= r[i].end || r[i].end > ctx->len ||
		    !PAGE_ALIGNED(r[i].start) ||
		    (!PAGE_ALIGNED(r[i].end) && r[i].end != ctx->len) ||
		    (n && r[i].start < r[n - 1].end)) {
			kfree(r);
			return -EINVAL;
		}
		if (n && r[i].start == r[n - 1].end)
			r[n - 1].end = r[i].end;
		else
			r[n++] = r[i];
	}

	ctx->ranges = r;
	ctx->nr_ranges = n;
	return 0;
}

/* Undoes smptrace_set_ranges() before smptrace_init(); later, destroy does it */
void smptrace_free_ranges(struct smptrace_ctx *ctx)
{
	kfree(ctx->ranges);
	ctx->ranges = NULL;
	ctx->nr_ranges = 0;
}

/*
 * Whether any byte of [off, off + len), offsets into the tracer's range, is
 * traced. A binary search of an array that is fixed while the tracer is
 * active, so it takes no lock: the caller only needs ctx to stay alive.
 */
bool smptrace_traced(const struct smptrace_ctx *ctx, u64 off, u64 len)
{
	unsigned int lo = 0, hi = ctx->nr_ranges;

	if (!ctx->ranges)
		return off < ctx->len;

	/* The first range that ends after off */
	while (lo < hi) {
		unsigned int mid = lo + (hi - lo) / 2;

		if (ctx->ranges[mid].end <= off)
			lo = mid + 1;
		else
			hi = mid;
	}
	return lo < ctx->nr_ranges && ctx->ranges[lo].start < off + len;
}

void smptrace_emulate_read(struct smptrace_ctx *ctx, struct smptrace_map *map,
                         u64 addr, u32 size, u8 *dst)
{
	smptrace_emulate_read_may_sleep(ctx, map, addr, size, dst, false);
}

void smptrace_emulate_read_may_sleep(struct smptrace_ctx *ctx, struct smptrace_map *map,
                                     u64 addr, u32 size, u8 *dst, bool may_sleep)
{
	u64 off;
	struct smptrace_io io = { .may_sleep = may_sleep };

	off = (map->pa - ctx->pa) + (addr - map->va);
	if (off >= ctx->len || off + size > ctx->len) {
		pr_warn_once("read off 0x%llx size %u outside region len 0x%llx\n",
		             off, size, (u64)ctx->len);
		memset(dst, 0, size);
		return;
	}

	/* Outside every traced range: the backing memory, unseen. Reached
	 * through a huge page that a traced range shares, or by a vfio-pci
	 * read() or write() that crosses a range's edge. */
	if (!smptrace_traced(ctx, off, size)) {
		memcpy_fromio(dst, ctx->shadow_va + off, size);
		return;
	}

	/* Handler-routed read: the device model produces the value. */
	if (ctx->notif.read_sync) {
		io.offset = off;
		io.size = size;
		if (!ctx->notif.read_sync(ctx, &io)) {
			/* Union members alias the low bytes; LE layout. */
			memcpy(dst, &io.data, size);
			return;
		}
		/* Daemon never answered, the ring was full, or a reset failed it */
		memset(dst, 0xff, size);
		return;
	}

	memcpy_fromio(dst, ctx->shadow_va + off, size);

	if (ctx->notif.read && __fill_io_notif(&io, dst, size, off))
		ctx->notif.read(ctx, &io);
}

void smptrace_emulate_write(struct smptrace_ctx *ctx, struct smptrace_map *map,
                          u64 addr, u32 size, const u8 *src)
{
	smptrace_emulate_write_may_sleep(ctx, map, addr, size, src, false);
}

/*
 * A write the caller may sleep in: when the device model has fallen behind, the
 * write waits for room to report it rather than being lost, as a PCIe posted
 * write waits for flow-control credit.
 */
void smptrace_emulate_write_may_sleep(struct smptrace_ctx *ctx, struct smptrace_map *map,
                                      u64 addr, u32 size, const u8 *src, bool may_sleep)
{
	u64 off;
	struct smptrace_io io = { .may_sleep = may_sleep };

	off = (map->pa - ctx->pa) + (addr - map->va);
	if (off >= ctx->len || off + size > ctx->len) {
		pr_warn_once("write off 0x%llx size %u outside region len 0x%llx\n",
		             off, size, (u64)ctx->len);
		return;
	}

	if (!smptrace_traced(ctx, off, size)) {
		memcpy_toio(ctx->shadow_va + off, src, size);
		return;
	}

	if (!ctx->stop_writes)
		memcpy_toio(ctx->shadow_va + off, src, size);

	pr_debug("Write @ 0x%llx:%x", off, size);

	if (ctx->notif.write && __fill_io_notif(&io, src, size, off))
		ctx->notif.write(ctx, &io);
}

int smptrace_enter_ioremap(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct ioremap_args *args = (struct ioremap_args *)ri->data;

	args->pa  = regs_get_kernel_argument(regs, 0);
	args->len = regs_get_kernel_argument(regs, 1);
	return 0;
}

/*
 * Poisons the pages of map that a traced range covers, one call to the arch
 * per range. Returns how many ranges map reaches, or a negative errno.
 */
static int smptrace_poison_map(struct smptrace_ctx *ctx, struct smptrace_map *map)
{
	const struct smptrace_range whole = { 0, PAGE_ALIGN(ctx->len) };
	const struct smptrace_range *r = ctx->ranges ?: &whole;
	unsigned int i, nr = ctx->ranges ? ctx->nr_ranges : 1;
	/* The pages of map, as offsets into the tracer's range */
	u64 first = ALIGN_DOWN(map->pa, PAGE_SIZE) - ctx->pa;
	u64 last = min_t(u64, PAGE_ALIGN(map->pa + map->len) - ctx->pa, PAGE_ALIGN(ctx->len));
	unsigned long va = ALIGN_DOWN(map->va, PAGE_SIZE);
	int ret, reached = 0;

	for (i = 0; i < nr; i++) {
		u64 start = max(r[i].start, first);
		u64 end = min(PAGE_ALIGN(r[i].end), last);

		if (start >= end)
			continue;
		ret = smptrace_arch_poison_pte(map, va + (start - first), end - start);
		if (ret)
			return ret;
		reached++;
	}
	return reached;
}

int smptrace_exit_ioremap(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct kretprobe *rp = get_kretprobe(ri);
	struct smptrace_ctx *ctx = container_of(rp, struct smptrace_ctx,
	                                        ioremap_krp);
	struct ioremap_args *args = (struct ioremap_args *)ri->data;
	unsigned long va = regs_return_value(regs);
	struct smptrace_map *map;
	unsigned long flags;
	int ret;

	if (!va || args->pa < ctx->pa || args->pa >= ctx->pa + ctx->len)
		return 0;

	map = kzalloc(sizeof(*map), GFP_ATOMIC);
	if (!map)
		return 0;

	map->va  = va;
	map->len = args->len;
	map->pa  = args->pa;
	INIT_LIST_HEAD(&map->ptes);

	ret = smptrace_poison_map(ctx, map);
	if (!ret) {
		/* No traced range in it: an ordinary mapping */
		kfree(map);
	} else if (ret < 0) {
		pr_warn("failed to poison VA=0x%lx:%lx (PA=0x%llx:%lx)",
		        va, args->len, args->pa, args->len);

		/* The caller sees ioremap() fail. This handler runs with
		 * preemption disabled and iounmap() may sleep, so the mapping
		 * is released from process context */
		regs_set_return_value(regs, 0);
		llist_add(&map->reject, &ctx->rejected);
		schedule_work(&ctx->reject_work);
	} else {
		/* One line per map; the per-entry ones are pr_debug() */
		pr_info("poisoned VA=0x%lx:%lx (PA=0x%llx:%lx) in %d traced range(s): %zu entries, %u huge PMD(s) split",
		        va, args->len, (unsigned long long)args->pa, args->len, ret,
		        list_count_nodes(&map->ptes), map->nr_split);
		spin_lock_irqsave(&ctx->lock, flags);
		list_add_tail_rcu(&map->list, &ctx->maps);
		spin_unlock_irqrestore(&ctx->lock, flags);
	}

	return 0;
}

static void smptrace_unmap_rejected(struct work_struct *work)
{
	struct smptrace_ctx *ctx = container_of(work, struct smptrace_ctx,
	                                        reject_work);
	struct smptrace_map *map, *tmp;

	llist_for_each_entry_safe(map, tmp, llist_del_all(&ctx->rejected),
	                          reject) {
		iounmap((void __iomem *)map->va);
		kfree(map);
	}
}

/*
 * Writes map's saved entries back, unless that was done already: the arch
 * restore empties map->ptes. The iounmap() probe and smptrace_deactivate() can
 * both come for the same map, and each calls this under ctx->restore_lock, so
 * the second one to get there finds nothing to do.
 */
static void smptrace_restore_map(struct smptrace_ctx *ctx, struct smptrace_map *map)
{
	lockdep_assert_held(&ctx->restore_lock);

	if (list_empty(&map->ptes))
		return;
	pr_info("restoring VA=0x%lx (PA=0x%llx): %zu entries", map->va,
	        (unsigned long long)map->pa, list_count_nodes(&map->ptes));
	smptrace_arch_restore_pte(map);
}

/*
 * Stops tracing the map at va, which is about to be iounmap()ed: restores its
 * entries while the mapping still exists. Returns once they are back, so the
 * caller's vunmap() only ever clears live entries.
 */
void smptrace_untrace_map(struct smptrace_ctx *ctx, unsigned long va)
{
	struct smptrace_map *map, *found = NULL;
	unsigned long flags;

	spin_lock(&ctx->restore_lock);
	spin_lock_irqsave(&ctx->lock, flags);
	list_for_each_entry(map, &ctx->maps, list) {
		if (map->va == va) {
			found = map;
			list_del_rcu(&map->list);
			break;
		}
	}
	spin_unlock_irqrestore(&ctx->lock, flags);

	/* Deactivation may have restored it already, and waits for this */
	if (found)
		smptrace_restore_map(ctx, found);
	spin_unlock(&ctx->restore_lock);

	if (found)
		kfree_rcu(found, rcu);
}

int smptrace_enter_iounmap(struct kprobe *kp, struct pt_regs *regs)
{
	struct smptrace_ctx *ctx = container_of(kp, struct smptrace_ctx,
	                                        iounmap_kp);

	smptrace_untrace_map(ctx, regs_get_kernel_argument(regs, 0));
	return 0;
}

int smptrace_register_probes(struct smptrace_ctx *ctx)
{
	int ret;

	ret = register_kprobe(&ctx->badarea_kp);
	if (ret) {
		pr_err("Failed to register fault kprobe (%s): %d\n",
		       ctx->badarea_kp.symbol_name, ret);
		goto fail_badarea;
	}

	ret = register_kprobe(&ctx->iounmap_kp);
	if (ret) {
		pr_err("Failed to register iounmap kprobe: %d\n", ret);
		goto fail_iounmap;
	}

	ret = register_kretprobe(&ctx->ioremap_krp);
	if (ret) {
		pr_err("Failed to register ioremap kretprobe (%s): %d\n",
		       ctx->ioremap_krp.kp.symbol_name, ret);
		goto fail_ioremap;
	}

	return 0;

fail_ioremap:
	unregister_kprobe(&ctx->iounmap_kp);
fail_iounmap:
	unregister_kprobe(&ctx->badarea_kp);
fail_badarea:
	iounmap(ctx->shadow_va);
	ctx->shadow_va = NULL;
	ctx->pa = 0;
	return ret;
}

/* Active tracers, searchable by physical address from contexts that are not
 * one of a tracer's own probes (user mappings of a traced BAR). SRCU, because
 * a user-mapping fault sleeps while its read is answered. */
static LIST_HEAD(smptrace_active);
static DEFINE_SPINLOCK(smptrace_active_lock);
DEFINE_SRCU(smptrace_active_srcu);

/*
 * Returns the active tracer whose range contains [pa, pa + len), or NULL.
 * Caller holds smptrace_active_srcu; the tracer stays valid until it drops it.
 */
struct smptrace_ctx *smptrace_find_ctx(phys_addr_t pa, size_t len)
{
	struct smptrace_ctx *ctx;

	list_for_each_entry_srcu(ctx, &smptrace_active, active_node,
	                         srcu_read_lock_held(&smptrace_active_srcu)) {
		if (pa >= ctx->pa && pa + len <= ctx->pa + ctx->len)
			return ctx;
	}
	return NULL;
}

/*
 * Whether [pa, pa + len) is inside an active tracer's range and any byte of it
 * is traced. Caller holds smptrace_active_srcu.
 */
bool smptrace_pa_traced(phys_addr_t pa, size_t len)
{
	struct smptrace_ctx *ctx = smptrace_find_ctx(pa, len);

	return ctx && smptrace_traced(ctx, pa - ctx->pa, len);
}

/* Starts tracing. On failure the ranges smptrace_set_ranges() set are freed. */
int smptrace_init(struct smptrace_ctx *ctx)
{
	int ret;

	INIT_LIST_HEAD(&ctx->maps);
	spin_lock_init(&ctx->lock);
	spin_lock_init(&ctx->restore_lock);
	atomic_set(&ctx->unmaps_pending, 0);
	init_llist_head(&ctx->rejected);
	INIT_WORK(&ctx->reject_work, smptrace_unmap_rejected);

	ctx->in_pf = alloc_percpu_gfp(bool, GFP_KERNEL_ACCOUNT);
	if (!ctx->in_pf) {
		ret = -ENOMEM;
		goto fail;
	}

	ret = smptrace_arch_activate(ctx);
	if (ret) {
		free_percpu(ctx->in_pf);
		goto fail;
	}

	spin_lock(&smptrace_active_lock);
	list_add_rcu(&ctx->active_node, &smptrace_active);
	spin_unlock(&smptrace_active_lock);

	return 0;

fail:
	smptrace_free_ranges(ctx);
	return ret;
}

static void smptrace_deactivate(struct smptrace_ctx *ctx)
{
	struct smptrace_map *map, *tmp;
	unsigned long flags;

	/* Unpublish first: a user-mapping fault that already found this
	 * tracer holds smptrace_active_srcu until it has finished with it. The
	 * owner must first fail any read such a fault is sleeping on. */
	spin_lock(&smptrace_active_lock);
	list_del_rcu(&ctx->active_node);
	spin_unlock(&smptrace_active_lock);
	synchronize_srcu(&smptrace_active_srcu);

	/* Then stop the ioremap() hook, so that no map is added */
	unregister_kretprobe(&ctx->ioremap_krp);
	/* unregister_kretprobe() waited for running return handlers, so
	 * nothing queues reject_work after this */
	flush_work(&ctx->reject_work);

	/*
	 * Now unpoison PTEs so that we stop hitting #PF, while the iounmap()
	 * hook is still registered: a map that its owner iounmap()s at the
	 * same time is restored by whichever of the two gets restore_lock
	 * first, and iounmap() waits for it. Were the hook gone, that
	 * iounmap() would free the mapping first and the entries would be
	 * written back into a range that is no longer mapped, where the next
	 * vmap() of it finds them. Only the hook removes maps, under
	 * restore_lock, so holding it keeps the list still. Restoring a PTE
	 * may flush the TLB with IPIs (riscv), so interrupts stay enabled.
	 */
	spin_lock(&ctx->restore_lock);
	list_for_each_entry(map, &ctx->maps, list)
		smptrace_restore_map(ctx, map);
	spin_unlock(&ctx->restore_lock);

	/*
	 * Every map is restored, so the iounmap() hook has nothing left to do
	 * but unlist. After it is gone (unregister_kprobe() waits for running
	 * handlers) and riscv's continuations are done with ctx, nothing else
	 * removes maps.
	 */
	unregister_kprobe(&ctx->iounmap_kp);
	wait_var_event(&ctx->unmaps_pending,
	               !atomic_read(&ctx->unmaps_pending));

	/*
	 * Only then forget the maps. A fault already taken on a poisoned PTE
	 * runs with interrupts disabled until the kprobe has looked its map
	 * up, so after a grace period none is left that could miss it and go
	 * unclaimed.
	 */
	synchronize_rcu();

	spin_lock_irqsave(&ctx->lock, flags);
	list_for_each_entry_safe(map, tmp, &ctx->maps, list) {
		list_del_rcu(&map->list);
		kfree_rcu(map, rcu);
	}
	spin_unlock_irqrestore(&ctx->lock, flags);

	/* Stop #PF hook now that we shouldn't be hitting #PF */
	unregister_kprobe(&ctx->badarea_kp);

	if (ctx->shadow_va) {
		iounmap(ctx->shadow_va);
		ctx->shadow_va = NULL;
	}
}

void smptrace_destroy(struct smptrace_ctx *ctx)
{
	smptrace_deactivate(ctx);
	free_percpu(ctx->in_pf);
	/* Nothing can look at the ranges after deactivation: every probe is
	 * unregistered and no SRCU reader can still find ctx */
	smptrace_free_ranges(ctx);
}
