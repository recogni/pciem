/* SPDX-License-Identifier: GPL-2.0 */
/*
 *  Copyright (C) 2026  Carlos López <carlos.lopezr4096@gmail.com>
 *  Copyright (C) 2026  Joel Bueno <buenocalvachejoel@gmail.com>
 */

#include <asm/debugreg.h>
#include <asm/traps.h>
#include <asm/pgtable.h>
#include <asm/tlbflush.h>
#include <linux/mm.h>
#include <linux/version.h>
#include "insn.h"
#include "insn-eval.h"
#include "trace/smptrace_internal.h"

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 12, 0)
static inline pud_t pud_mkinvalid(pud_t pud)
{
	return pfn_pud(pud_pfn(pud),
	               __pgprot(pud_flags(pud) & ~(_PAGE_PRESENT | _PAGE_PROTNONE)));
}
#endif

static void smptrace_flush_tlb_ipi(void *unused)
{
	__flush_tlb_all();
}

/*
 * Flushes every CPU's TLB, global entries included, as flush_tlb_all() does
 * (neither it nor flush_tlb_kernel_range() is exported; __flush_tlb_all() is).
 * A whole flush per CPU rather than one INVLPG per page: a traced BAR can be
 * 65536 pages, and this runs once per poisoned range, not per access.
 *
 * on_each_cpu() waits for the other CPUs, which needs interrupts enabled. The
 * callers run in the ioremap() caller's context, which may sleep, so they are;
 * should one not be, only this CPU is flushed. Called with preemption disabled.
 */
static void smptrace_flush_tlb_all(void)
{
	if (!irqs_disabled()) {
		on_each_cpu(smptrace_flush_tlb_ipi, NULL, 1);
		return;
	}
	pr_warn_once("interrupts disabled: flushing only this CPU's TLB, other CPUs may bypass tracing\n");
	__flush_tlb_all();
}

static u64 level2size(unsigned int level)
{
	switch (level) {
	case PG_LEVEL_4K: return PAGE_SIZE;
	case PG_LEVEL_2M: return PMD_SIZE;
	case PG_LEVEL_1G: return PUD_SIZE;
	default: BUG();
	}
}

/*
 * Replaces the 2 MiB leaf at pmdp with a table of 4 KiB entries that map the
 * same memory with the same attributes, so that only part of it need be
 * poisoned. Called from the ioremap() return handler, before the caller has the
 * mapping, so nothing else is using it; preemption is disabled, so the table is
 * allocated atomically, as the kernel's own kernel PTE tables are constructed.
 *
 * The table stays after the PTEs are restored. From then on it is an ordinary
 * kernel PTE table: vunmap() clears its entries, and a later huge mapping of the
 * range frees it through pmd_free_pte_page(), which flushes first.
 */
static int smptrace_split_pmd(pmd_t *pmdp, unsigned long va)
{
	pmd_t pmd = pmdp_get(pmdp);
	unsigned long pfn = pmd_pfn(pmd);
	/* The PAT bit of a 4 KiB entry is where a 2 MiB one keeps PSE */
	pgprot_t prot = pgprot_large_2_4k(pmd_pgprot(pmd));
	pte_t *table;
	int i;

	/* A Xen PV guest must be told of a new page table, through
	 * paravirt_alloc_pte(), which takes init_mm: not exported. */
	if (cpu_feature_enabled(X86_FEATURE_XENPV))
		return -EOPNOTSUPP;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 15, 0)
	/* Since 6.15 kernel PTE tables are constructed, and pte_free_kernel()
	 * destructs them. pagetable_pte_ctor() for init_mm, which is only
	 * __pagetable_ctor(), since init_mm is not exported. */
	struct ptdesc *ptdesc = pagetable_alloc(GFP_ATOMIC | __GFP_ZERO, 0);

	if (!ptdesc)
		return -ENOMEM;
	__pagetable_ctor(ptdesc);
	table = ptdesc_address(ptdesc);
#else
	table = (pte_t *)__get_free_page(GFP_ATOMIC | __GFP_ZERO);
	if (!table)
		return -ENOMEM;
#endif
	for (i = 0; i < PTRS_PER_PTE; i++)
		set_pte(&table[i], pfn_pte(pfn + i, prot));

	/* pmd_populate_kernel(&init_mm, ...) without the paravirt hook */
	set_pmd(pmdp, __pmd(__pa(table) | _PAGE_TABLE));

	/* Another CPU may hold the 2 MiB translation speculatively; a TLB must
	 * not keep it next to 4 KiB ones that are about to differ from it, as
	 * the kernel's own __split_large_page() flushes before changing any. */
	smptrace_flush_tlb_all();
	pr_debug("split huge PMD for VA=%lx", va & PMD_MASK);
	return 0;
}

int smptrace_arch_poison_pte(struct smptrace_map *map, unsigned long start,
                             unsigned long len)
{
	unsigned long va = max(start, smptrace_poisoned_end(map));
	unsigned long end = start + len;
	unsigned int level;
	struct smptrace_pte *orig, *tmp;
	int ret;

	while (va < end) {
		pte_t *ptep = lookup_address(va, &level);

		if (!ptep) {
			ret = -ENOENT;
			goto fail;
		}

		/* Nothing to poison, and saving it would make the restore
		 * write back a poisoned entry */
		if (!(pte_flags(*ptep) & _PAGE_PRESENT)) {
			va = ALIGN_DOWN(va, level2size(level)) + level2size(level);
			continue;
		}

		/* A 2 MiB leaf the range covers only partly is split, so the
		 * rest of it stays mapped. If that fails the whole leaf is
		 * poisoned, and faults outside the range are served from the
		 * backing memory. */
		if (level == PG_LEVEL_2M &&
		    ((va & PMD_MASK) < start || (va & PMD_MASK) + PMD_SIZE > end)) {
			if (!smptrace_split_pmd((pmd_t *)ptep, va)) {
				map->nr_split++;
				continue;
			}
			pr_warn_once("cannot split huge PMD for VA=%lx, poisoning all of it", va);
		}

		orig = kzalloc(sizeof(*orig), GFP_ATOMIC);
		if (!orig) {
			ret = -ENOMEM;
			goto fail;
		}

		INIT_LIST_HEAD(&orig->list);
		orig->level = level;

		/* Swap out PTE */
		switch (level) {
		case PG_LEVEL_4K: {
			pte_t pte = native_local_ptep_get_and_clear(ptep);
			orig->pte = pte_val(pte);
			break;
		}
		case PG_LEVEL_2M: {
			pmd_t *pmdp = (pmd_t *)ptep;
			pmd_t  pmd  = pmdp_get(pmdp);
			orig->pte = pmd_val(pmd);
			set_pmd(pmdp, pmd_mkinvalid(pmd));
			break;
		}
		case PG_LEVEL_1G: {
			pud_t *pudp = (pud_t *)ptep;
			pud_t  pud  = pudp_get(pudp);
			orig->pte = pud_val(pud);
			set_pud(pudp, pud_mkinvalid(pud));
			break;
		}
		default:
			pr_err("unexpected page level 0x%x for VA 0x%llx\n",
			       level, (u64)va);
			kfree(orig);
			ret = -EINVAL;
			goto fail;
		}

		orig->size = level2size(level);
		orig->va   = va & ~(orig->size - 1);
		pr_debug("poisoned PTE for VA=%lx (level=%u)", orig->va, level);

		va = orig->va + orig->size;
		list_add_tail(&orig->list, &map->ptes);
	}

	/*
	 * The entries were present from ioremap_page_range() until now, and
	 * installing them flushed nothing, so any CPU may have cached them
	 * (speculatively: the caller has not had the mapping yet). A CPU that
	 * kept one would reach the BAR untraced until its entry was evicted,
	 * and this handler may run on a different CPU from the one that made
	 * the mapping, or from the one the caller then uses it on.
	 */
	smptrace_flush_tlb_all();
	return 0;

fail:
	/* Free items, but do not bother to unpoison the PTEs. Let our
	 * caller detect the error, and simply return NULL to the caller
	 * of ioremap() */
	list_for_each_entry_safe(orig, tmp, &map->ptes, list) {
		list_del(&orig->list);
		kfree(orig);
	}
	smptrace_flush_tlb_all();
	return ret;
}

/* Puts back every entry smptrace_arch_poison_pte() saved, at the level it
 * saved it. Entries that were never poisoned are not touched. */
void smptrace_arch_restore_pte(struct smptrace_map *map)
{
	struct smptrace_pte *orig, *tmp;

	list_for_each_entry_safe(orig, tmp, &map->ptes, list) {
		unsigned int level;
		pte_t *ptep = lookup_address(orig->va, &level);

		list_del(&orig->list);

		if (!ptep || level != orig->level) {
			pr_err("cannot restore PTE for va=0x%lx (saved level=%u, walk %s level=%u)",
			       orig->va, orig->level, ptep ? "found" : "failed", level);
			kfree(orig);
			continue;
		}

		switch (level) {
		case PG_LEVEL_4K:
			set_pte_atomic(ptep, __pte(orig->pte));
			break;
		case PG_LEVEL_2M:
			set_pmd((pmd_t *)ptep, __pmd(orig->pte));
			break;
		case PG_LEVEL_1G:
			set_pud((pud_t *)ptep, __pud(orig->pte));
			break;
		}

		pr_debug("restored PTE for VA=%lx (level=%u)", orig->va, level);
		kfree(orig);
	}

	/*
	 * Only this CPU. Every entry written here goes from not present to
	 * present, and x86 caches no translation through a not-present entry
	 * (in the TLB or the paging-structure caches), so no CPU can hold a
	 * stale poisoned one: its next access walks the tables and finds the
	 * restored entry, as after ioremap_page_range(), which flushes nothing
	 * either. Present translations of the restored entries that a CPU
	 * caches from now on are removed with the mapping: iounmap()'s
	 * vunmap_range_noflush() leaves the range lazily freed, and
	 * __purge_vmap_area_lazy() flushes every CPU before it is reused.
	 * The caller holds restore_lock, which the x86 iounmap() probe takes
	 * with interrupts disabled when it is an int3 probe, so this must not
	 * wait on other CPUs.
	 */
	guard(preempt)();
	__flush_tlb_all();
}

static int decode_pf_instr(struct pt_regs *regs, struct insn *insn)
{
	u8 buf[MAX_INSN_SIZE];

	if (copy_from_kernel_nofault(buf, (void *)regs->ip, MAX_INSN_SIZE))
		return -EINVAL;

	return insn_decode_kernel(insn, buf);
}

/* A decoded trapped instruction: what to access, how wide, and where the
 * register operand lives in the faulting context's pt_regs. */
struct smptrace_x86_op {
	struct insn insn;
	enum insn_mmio_type mmio;
	unsigned int len;
	long *data;
	u64 addr;
	/* A user-mode fault, which may sleep while a read is answered */
	bool may_sleep;
};

/*
 * Decodes the instruction at regs->ip without performing it. Called twice per
 * fault, from the kprobe to decide whether to claim it and again from the
 * continuation to perform it; decoding reads only kernel text and pt_regs, so
 * both calls agree.
 */
static int classify_pf_instruction(struct pt_regs *regs, struct smptrace_x86_op *op);

static int plan_pf_instruction(struct pt_regs *regs, struct smptrace_x86_op *op)
{
	int ret;

	if (user_mode(regs))
		return -EACCES;

	ret = decode_pf_instr(regs, &op->insn);
	if (ret) {
		pr_warn("failed to decode #PF instr ip=0x%lx", regs->ip);
		return ret;
	}

	return classify_pf_instruction(regs, op);
}

/* Everything after decoding: the access kind, width, register and address. */
static int classify_pf_instruction(struct pt_regs *regs, struct smptrace_x86_op *op)
{
	op->mmio = insn_decode_mmio(&op->insn, &op->len);
	switch (op->mmio) {
	case INSN_MMIO_WRITE:
	case INSN_MMIO_WRITE_IMM:
	case INSN_MMIO_READ:
	case INSN_MMIO_READ_ZERO_EXTEND:
	case INSN_MMIO_READ_SIGN_EXTEND:
		break;
	case INSN_MMIO_DECODE_FAILED:
		pr_warn_ratelimited("failed to decode MMIO instr ip=0x%lx", regs->ip);
		return -EINVAL;
	case INSN_MMIO_MOVS:
		pr_warn_ratelimited("unhandled MOVS instruction ip=0x%lx", regs->ip);
		return -ENOTSUPP;
	default:
		pr_warn_ratelimited("unhandled MMIO instruction ip=0x%lx (%d)",
		                    regs->ip, op->mmio);
		return -ENOTSUPP;
	}

	op->data = NULL;
	if (op->mmio != INSN_MMIO_WRITE_IMM) {
		op->data = insn_get_modrm_reg_ptr(&op->insn, regs);
		if (!op->data) {
			pr_warn_ratelimited("failed to get modrm reg ptr");
			return -EINVAL;
		}
	}

	/* Without a REX prefix, byte registers 4-7 are AH, CH, DH and BH, not the
	 * SPL..DIL insn_get_modrm_reg_ptr() resolves them to. */
	if (op->len == 1 && (op->mmio == INSN_MMIO_READ || op->mmio == INSN_MMIO_WRITE) &&
	    !op->insn.rex_prefix.nbytes) {
		static const unsigned short high_byte[] = {
			offsetof(struct pt_regs, ax), offsetof(struct pt_regs, cx),
			offsetof(struct pt_regs, dx), offsetof(struct pt_regs, bx),
		};
		int reg = X86_MODRM_REG(op->insn.modrm.value);

		if (reg >= 4)
			op->data = (long *)((u8 *)regs + high_byte[reg - 4] + 1);
	}

	op->addr = (u64)insn_get_addr_ref(&op->insn, regs);
	op->may_sleep = false;
	return 0;
}

static bool op_is_read(const struct smptrace_x86_op *op)
{
	return op->mmio == INSN_MMIO_READ ||
	       op->mmio == INSN_MMIO_READ_ZERO_EXTEND ||
	       op->mmio == INSN_MMIO_READ_SIGN_EXTEND;
}

/* Performs a planned access and steps the faulting context past it. */
static void execute_pf_instruction(struct smptrace_ctx *ctx,
                                   struct smptrace_map *map,
                                   struct pt_regs *regs,
                                   struct smptrace_x86_op *op)
{
	switch (op->mmio) {
	case INSN_MMIO_WRITE:
		smptrace_emulate_write_may_sleep(ctx, map, op->addr, op->len, (u8 *)op->data,
		                                 op->may_sleep);
		break;
	case INSN_MMIO_WRITE_IMM: {
		/* The immediate is at most 32 bits; a 64-bit store sign-extends it. */
		u64 imm = (s64)op->insn.immediate1.value;

		smptrace_emulate_write_may_sleep(ctx, map, op->addr, op->len, (u8 *)&imm,
		                                 op->may_sleep);
		break;
	}
	case INSN_MMIO_READ:
		if (op->len == 4)
			*op->data = 0;
		smptrace_emulate_read_may_sleep(ctx, map, op->addr, op->len, (u8 *)op->data,
		                                op->may_sleep);
		break;
	case INSN_MMIO_READ_ZERO_EXTEND:
		/* A 32-bit destination zeroes bits 63:32 too, as on hardware. */
		memset(op->data, 0, op->insn.opnd_bytes == 2 ? 2 : sizeof(*op->data));
		smptrace_emulate_read_may_sleep(ctx, map, op->addr, op->len, (u8 *)op->data,
		                                op->may_sleep);
		break;
	case INSN_MMIO_READ_SIGN_EXTEND: {
		u16 val = 0;
		long ext;

		smptrace_emulate_read_may_sleep(ctx, map, op->addr, op->len, (u8 *)&val,
		                                op->may_sleep);
		ext = op->len == 1 ? (s8)val : (s16)val;
		if (op->insn.opnd_bytes == 2)
			*(u16 *)op->data = ext;
		else if (op->insn.opnd_bytes == 4)
			/* A 32-bit destination zeroes bits 63:32, as on hardware. */
			*op->data = (u32)ext;
		else
			*op->data = ext;
		break;
	}
	default:
		/* plan_pf_instruction() admits nothing else */
		break;
	}

	regs->ip += op->insn.length;
}

int smptrace_arch_user_fault(struct pt_regs *regs, unsigned long fault_va,
                             unsigned long start, unsigned long end, phys_addr_t pa)
{
	unsigned char buf[MAX_INSN_SIZE];
	struct smptrace_map map = {0};
	struct smptrace_x86_op op;
	struct smptrace_ctx *ctx;
	int n, ret, idx;

	if (!user_mode(regs))
		return -EACCES;

	/* The caller holds mmap_lock, which a fault on the text page would
	 * take again, so the fetch must not fault. A short fetch that leaves
	 * the instruction undecodable is retried: re-executing it faults the
	 * text page in through the normal path. */
	pagefault_disable();
	n = insn_fetch_from_user_inatomic(regs, buf);
	pagefault_enable();
	if (n <= 0 || !insn_decode_from_regs(&op.insn, regs, buf, n)) {
		if (n >= 0 && n < MAX_INSN_SIZE)
			return -EAGAIN;
		pr_warn_ratelimited("failed to decode user instr ip=0x%lx", regs->ip);
		return -EINVAL;
	}
	ret = classify_pf_instruction(regs, &op);
	if (ret)
		return ret;

	/* The decoded access must be the one that faulted, inside this mapping. */
	if (op.addr < start || op.addr + op.len > end ||
	    fault_va < op.addr || fault_va >= op.addr + op.len) {
		pr_warn_ratelimited("user instr ip=0x%lx accesses 0x%llx, fault at 0x%lx",
		                    regs->ip, op.addr, fault_va);
		return -EFAULT;
	}

	map.va = start;
	map.pa = pa;
	op.may_sleep = true;

	idx = srcu_read_lock_nmisafe(&smptrace_active_srcu);
	ctx = smptrace_find_ctx(pa + (op.addr - start), op.len);
	if (ctx)
		execute_pf_instruction(ctx, &map, regs, &op);
	srcu_read_unlock_nmisafe(&smptrace_active_srcu, idx);

	return ctx ? 0 : -ENOENT;
}

/* The tracer whose kprobe claimed this CPU's current fault, handed from the
 * kprobe to the continuation. Nothing runs on this CPU in between: the kprobe
 * returns straight into the continuation with interrupts still disabled. */
static DEFINE_PER_CPU(struct smptrace_ctx *, smptrace_cont_ctx);

/*
 * Runs in place of bad_area_nosemaphore() for a fault the kprobe claimed, with
 * the same arguments, and returns to its caller. Unlike the kprobe handler it
 * may run with interrupts enabled, so a read that waits on userspace restores
 * the faulting context's interrupt state for the wait: a CPU that spins with
 * interrupts off cannot acknowledge TLB-flush IPIs, and every CPU waiting on
 * that acknowledgement is one the device model cannot run on.
 *
 * Returning without advancing pf_regs->ip retries the access, which faults
 * again and is re-judged by the kprobe.
 */
static void smptrace_badarea_cont(struct pt_regs *pf_regs, unsigned long error_code,
                                  unsigned long address)
{
	struct smptrace_ctx *ctx = this_cpu_read(smptrace_cont_ctx);
	struct smptrace_map map = {0};
	struct smptrace_x86_op op;
	bool irqs_on;

	this_cpu_write(smptrace_cont_ctx, NULL);
	if (WARN_ON_ONCE(!ctx))
		return;

	/* smptrace_deactivate() unregisters the kprobe, which waits for an RCU
	 * grace period, before it frees what this reads. */
	guard(rcu)();

	if (!smptrace_find_map_rcu(ctx, address, &map))
		return;
	if (WARN_ON_ONCE(plan_pf_instruction(pf_regs, &op)))
		return;

	irqs_on = op_is_read(&op) && (pf_regs->flags & X86_EFLAGS_IF);

	/* ctx->in_pf and the eventual return stay on this CPU. */
	preempt_disable();
	if (irqs_on) {
		/* An interrupt taken here may fault on a traced BAR itself; that
		 * fault is claimed afresh, so in_pf is left clear. */
		local_irq_enable();
		execute_pf_instruction(ctx, &map, pf_regs, &op);
		local_irq_disable();
	} else {
		this_cpu_write(*ctx->in_pf, true);
		execute_pf_instruction(ctx, &map, pf_regs, &op);
		this_cpu_write(*ctx->in_pf, false);
	}
	preempt_enable();

	pr_debug("badarea: emulated %s at %pS with interrupts %s",
	         op_is_read(&op) ? "read" : "write", (void *)pf_regs->ip,
	         irqs_on ? "enabled" : "disabled");
}
NOKPROBE_SYMBOL(smptrace_badarea_cont);

static int __enter_badarea(struct kprobe *kp, struct pt_regs *regs)
{
	struct smptrace_ctx *ctx = container_of(kp, struct smptrace_ctx, badarea_kp);
	struct pt_regs *pf_regs  = (struct pt_regs *)regs_get_kernel_argument(regs, 0);
	unsigned long pf_va      = regs_get_kernel_argument(regs, 2);
	unsigned long pf_err     = regs_get_kernel_argument(regs, 1);
	struct smptrace_map map = {0};
	struct smptrace_x86_op op;

	pr_debug("badarea: kprobe fired pf_va=0x%lx err=0x%lx pf_ip=0x%lx pf_user=%d ctx.pa=0x%llx ctx.len=0x%lx",
	        pf_va, pf_err, pf_regs->ip, user_mode(pf_regs),
	        (unsigned long long)ctx->pa, ctx->len);

	if (!smptrace_find_map_rcu(ctx, pf_va, &map))
		return 0;

	if (this_cpu_read(*ctx->in_pf)) {
		pr_warn("reentrant #PF on 0x%lx, ignoring", pf_va);
		return 0;
	}

	if (plan_pf_instruction(pf_regs, &op)) {
		pr_debug("badarea: NOT claimed pf_va=0x%lx -> default kernel handler will oops",
		         pf_va);
		return 0;
	}

	/* Emulate in the continuation, outside kprobe context, where the wait
	 * for a read's answer may run with interrupts enabled. */
	this_cpu_write(smptrace_cont_ctx, ctx);
	instruction_pointer_set(regs, (unsigned long)smptrace_badarea_cont);
	return 1;
}

/*
 * Deliberately empty. An optimized kprobe (a jump in place of the int3) ignores its
 * pre_handler's return value and the instruction pointer it sets, so the
 * pre_handler's redirect would be dropped and the fault would oops.
 * Kprobes does not optimize a probe that has a post_handler. Probes placed
 * through ftrace (KPROBES_ON_FTRACE) are never optimized, which is why kernels
 * with a function tracer did not need this.
 */
static void smptrace_badarea_no_optimize(struct kprobe *kp, struct pt_regs *regs,
                                         unsigned long flags)
{
}

int smptrace_arch_activate(struct smptrace_ctx *ctx)
{
	ctx->shadow_va = ioremap(ctx->pa, ctx->len);
	if (!ctx->shadow_va) {
		pr_err("Failed to map shadow VA\n");
		return -ENOMEM;
	}
	/* Force the kernel to set the page as present to avoid a #PF */
	readl(ctx->shadow_va);

	ctx->badarea_kp = (struct kprobe){
		.pre_handler  = __enter_badarea,
		.post_handler = smptrace_badarea_no_optimize,
		.symbol_name  = "bad_area_nosemaphore",
	};
	ctx->iounmap_kp = (struct kprobe){
		.pre_handler = smptrace_enter_iounmap,
		.symbol_name = "iounmap",
	};
	ctx->ioremap_krp = (struct kretprobe){
		.entry_handler  = smptrace_enter_ioremap,
		.handler        = smptrace_exit_ioremap,
		.maxactive      = 32,
		.data_size      = sizeof(struct ioremap_args),
		.kp.symbol_name = "ioremap",
	};

	return smptrace_register_probes(ctx);
}
