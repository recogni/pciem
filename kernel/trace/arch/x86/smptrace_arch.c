/* SPDX-License-Identifier: GPL-2.0 */
/*
 *  Copyright (C) 2026  Carlos López <carlos.lopezr4096@gmail.com>
 *  Copyright (C) 2026  Joel Bueno <buenocalvachejoel@gmail.com>
 */

#include <asm/debugreg.h>
#include <asm/traps.h>
#include <asm/pgtable.h>
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

static void ____write_cr4(unsigned long val)
{
	asm volatile("mov %0,%%cr4" : "+r"(val) :: "memory");
}

static void __flush_tlb(void)
{
	unsigned long cr4 = __read_cr4();
	____write_cr4(cr4 ^ X86_CR4_PGE);
	____write_cr4(cr4);
}

static u64 level2size(unsigned int level)
{
	switch (level) {
	case PG_LEVEL_4K: return PAGE_SIZE;
	case PG_LEVEL_2M: return HPAGE_PMD_SIZE;
	case PG_LEVEL_1G: return HPAGE_PUD_SIZE;
	default: BUG();
	}
}

int smptrace_arch_poison_pte(struct smptrace_map *map)
{
	int64_t remain = map->len;
	unsigned long va = map->va;
	unsigned int level;
	struct smptrace_pte *orig, *tmp;
	int ret;

	while (remain > 0) {
		pte_t *ptep = lookup_address(va, &level);

		if (!ptep) {
			ret = -ENOENT;
			goto fail;
		}

		orig = kzalloc(sizeof(*orig), GFP_ATOMIC);
		if (!orig) {
			ret = -ENOMEM;
			goto fail;
		}

		INIT_LIST_HEAD(&orig->list);
		orig->va    = va;
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

		pr_info("poisoned PTE for VA=%lx (level=%u)", va, level);

		remain -= level2size(level);
		va     += level2size(level);
		list_add_tail(&orig->list, &map->ptes);
	}

	__flush_tlb();
	return 0;

fail:
	/* Free items, but do not bother to unpoison the PTEs. Let our
	 * caller detect the error, and simply return NULL to the caller
	 * of ioremap() */
	list_for_each_entry_safe(orig, tmp, &map->ptes, list) {
		list_del(&orig->list);
		kfree(orig);
	}
	__flush_tlb();
	return ret;
}

void smptrace_arch_restore_pte(struct smptrace_map *map)
{
	unsigned long va = map->va;
	int64_t remain = map->len;

	while (remain > 0) {
		unsigned int level;
		pte_t *ptep = lookup_address(va, &level);
		struct smptrace_pte *orig;

		if (!ptep) {
			remain -= PAGE_SIZE;
			va     += PAGE_SIZE;
			continue;
		}

		orig = smptrace_find_pte(map, va);
		if (!orig) {
			pr_err("could not find saved PTE for va=0x%lx\n", va);
			remain -= level2size(level);
			va     += level2size(level);
			continue;
		}

		list_del(&orig->list);

		if (orig->level != level)
			pr_warn("PTE level mismatch for va=0x%lx (saved=%u walk=%u)",
			        va, orig->level, level);

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
		default:
			pr_err("unexpected page level %u for VA 0x%lx\n", level, va);
			kfree(orig);
			return;
		}

		pr_info("restored PTE for VA=%lx (level=%u)", va, level);

		remain -= level2size(orig->level);
		va     += level2size(orig->level);
		kfree(orig);
	}

	__flush_tlb();
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
};

/*
 * Decodes the instruction at regs->ip without performing it. Called twice per
 * fault, from the kprobe to decide whether to claim it and again from the
 * continuation to perform it; decoding reads only kernel text and pt_regs, so
 * both calls agree.
 */
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

	op->mmio = insn_decode_mmio(&op->insn, &op->len);
	switch (op->mmio) {
	case INSN_MMIO_WRITE:
	case INSN_MMIO_WRITE_IMM:
	case INSN_MMIO_READ:
	case INSN_MMIO_READ_ZERO_EXTEND:
	case INSN_MMIO_READ_SIGN_EXTEND:
		break;
	case INSN_MMIO_DECODE_FAILED:
		pr_warn("failed to decode MMIO instr ip=0x%lx", regs->ip);
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
			pr_warn("failed to get modrm reg ptr");
			return -EINVAL;
		}
	}

	op->addr = (u64)insn_get_addr_ref(&op->insn, regs);
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
	u8 sign_byte;

	switch (op->mmio) {
	case INSN_MMIO_WRITE:
		smptrace_emulate_write(ctx, map, op->addr, op->len, (u8 *)op->data);
		break;
	case INSN_MMIO_WRITE_IMM: {
		/* The immediate is at most 32 bits; a 64-bit store sign-extends it. */
		u64 imm = (s64)op->insn.immediate1.value;

		smptrace_emulate_write(ctx, map, op->addr, op->len, (u8 *)&imm);
		break;
	}
	case INSN_MMIO_READ:
		if (op->len == 4)
			*op->data = 0;
		smptrace_emulate_read(ctx, map, op->addr, op->len, (u8 *)op->data);
		break;
	case INSN_MMIO_READ_ZERO_EXTEND:
		memset(op->data, 0, op->insn.opnd_bytes);
		smptrace_emulate_read(ctx, map, op->addr, op->len, (u8 *)op->data);
		break;
	case INSN_MMIO_READ_SIGN_EXTEND:
		/* Sign extend based on operand size */
		if (op->len == 1) {
			u8 val;
			smptrace_emulate_read(ctx, map, op->addr, op->len, &val);
			sign_byte = (val & 0x80) ? 0xff : 0x00;
		} else {
			u16 val;
			smptrace_emulate_read(ctx, map, op->addr, op->len, (u8 *)&val);
			sign_byte = (val & 0x8000) ? 0xff : 0x00;
		}
		memset(op->data, sign_byte, op->insn.opnd_bytes);
		smptrace_emulate_read(ctx, map, op->addr, op->len, (u8 *)op->data);
		break;
	default:
		/* plan_pf_instruction() admits nothing else */
		break;
	}

	regs->ip += op->insn.length;
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
