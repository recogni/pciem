/* SPDX-License-Identifier: GPL-2.0 */
/*
 *  Copyright (C) 2026  Carlos López <carlos.lopezr4096@gmail.com>
 *  Copyright (C) 2026  Joel Bueno <buenocalvachejoel@gmail.com>
 */
#ifndef _PCIEM_SMPTRACE_INTERNAL
#define _PCIEM_SMPTRACE_INTERNAL
#include <linux/srcu.h>
#include "trace/smptrace.h"

struct ioremap_args {
	resource_size_t pa;
	unsigned long len;
};

static void __used smptrace_ret_gadget(void) {}

/* The end of the leaf the last entry poisoned in map covers, or 0 */
static inline unsigned long smptrace_poisoned_end(struct smptrace_map *map)
{
	struct smptrace_pte *last;

	if (list_empty(&map->ptes))
		return 0;
	last = list_last_entry(&map->ptes, struct smptrace_pte, list);
	return last->va + last->size;
}

static inline bool smptrace_find_map_rcu(struct smptrace_ctx *ctx,
					  unsigned long va, struct smptrace_map *dst)
{
	struct smptrace_map *tmp_map;

	guard(rcu)();

	list_for_each_entry_rcu(tmp_map, &ctx->maps, list) {
		if (va >= tmp_map->va && va < tmp_map->va + tmp_map->len) {
			*dst = *tmp_map;
			return true;
		}
	}

	return false;
}


int smptrace_register_probes(struct smptrace_ctx *ctx);
extern struct srcu_struct smptrace_active_srcu;
/*
 * Every reader of smptrace_active_srcu uses the NMI-safe flavour, since SRCU
 * wants one flavour per srcu_struct: some read from a kprobe pre-handler, which
 * riscv runs from its breakpoint trap under irqentry_nmi_enter(), and the plain
 * srcu_read_lock() there trips "NMI-unsafe use in NMI" in
 * __srcu_check_read_flavor().
 */
DEFINE_LOCK_GUARD_1(smptrace_active, struct srcu_struct,
		    _T->idx = srcu_read_lock_nmisafe(_T->lock),
		    srcu_read_unlock_nmisafe(_T->lock, _T->idx),
		    int idx)
struct smptrace_ctx *smptrace_find_ctx(phys_addr_t pa, size_t len);
bool smptrace_pa_traced(phys_addr_t pa, size_t len);
int smptrace_enter_ioremap(struct kretprobe_instance *ri, struct pt_regs *regs);
int smptrace_exit_ioremap(struct kretprobe_instance *ri, struct pt_regs *regs);
void smptrace_untrace_map(struct smptrace_ctx *ctx, unsigned long va);
int smptrace_enter_iounmap(struct kprobe *rp, struct pt_regs *regs);
void smptrace_emulate_write(struct smptrace_ctx *ctx, struct smptrace_map *map,
                            u64 addr, u32 size, const u8 *src);
void smptrace_emulate_write_may_sleep(struct smptrace_ctx *ctx, struct smptrace_map *map,
                                      u64 addr, u32 size, const u8 *src, bool may_sleep);
void smptrace_emulate_read(struct smptrace_ctx *ctx, struct smptrace_map *map,
                           u64 addr, u32 size, u8 *dst);
void smptrace_emulate_read_may_sleep(struct smptrace_ctx *ctx, struct smptrace_map *map,
                                     u64 addr, u32 size, u8 *dst, bool may_sleep);

/* Arch-specific functionality. Architectures must implement these in order
 * to be supported by smptrace */

int smptrace_arch_activate(struct smptrace_ctx *ctx);
/*
 * Poisons the kernel page table entries that map [va, va + len), a page-aligned
 * part of map, and saves each entry on map->ptes. The parts of one map are
 * poisoned in ascending order; an entry the previous part already poisoned (a
 * huge leaf both parts share) is skipped. On failure frees every saved entry
 * of map, without restoring them.
 */
int smptrace_arch_poison_pte(struct smptrace_map *map, unsigned long va, unsigned long len);
void smptrace_arch_restore_pte(struct smptrace_map *map);

/*
 * Emulates the user-mode instruction at regs' instruction pointer, which
 * faulted at fault_va inside a user mapping of [start, end) that maps physical
 * address pa at start. Returns 0 once emulated and stepped past, -EAGAIN when
 * the instruction could not be fetched and should be re-executed, -ENOENT
 * when the access is not to a traced range, or another negative errno when
 * the instruction cannot be emulated.
 */
#ifdef CONFIG_X86
int smptrace_arch_user_fault(struct pt_regs *regs, unsigned long fault_va,
                             unsigned long start, unsigned long end, phys_addr_t pa);
#else
static inline int smptrace_arch_user_fault(struct pt_regs *regs, unsigned long fault_va,
                                           unsigned long start, unsigned long end,
                                           phys_addr_t pa)
{
	return -EOPNOTSUPP;
}
#endif

#endif
