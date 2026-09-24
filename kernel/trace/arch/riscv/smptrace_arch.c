/* SPDX-License-Identifier: GPL-2.0 */
/*
 *  Copyright (C) 2026  Carlos López <carlos.lopezr4096@gmail.com>
 *  Copyright (C) 2026  Joel Bueno <buenocalvachejoel@gmail.com>
 */
#include <asm/csr.h>
#include "trace/smptrace_internal.h"

#define SMPTRACE_RISCV_LEVEL_PTE  0
#define SMPTRACE_RISCV_LEVEL_PMD  1
#define SMPTRACE_RISCV_LEVEL_PUD  2

// Would love not to re-invent the wheel
#define RISCV_PTE_V          BIT_ULL(0)
#define RISCV_PTE_R          BIT_ULL(1)
#define RISCV_PTE_X          BIT_ULL(3)
#define RISCV_PTE_LEAF       (RISCV_PTE_R | RISCV_PTE_X)
#define RISCV_PTE_PPN_MASK   GENMASK_ULL(53, 10)
#define RISCV_PTE_PPN_SHIFT  10
#define RISCV_SATP_PPN_MASK  GENMASK_ULL(43, 0)
#define RISCV_SATP_MODE_SHIFT 60
#define RISCV_SATP_MODE_SV48  9UL
#define RISCV_SATP_MODE_SV57  10UL

static inline phys_addr_t riscv_pte_pa(u64 pte)
{
	return (phys_addr_t)((pte & RISCV_PTE_PPN_MASK) >> RISCV_PTE_PPN_SHIFT)
	       << PAGE_SHIFT;
}

static inline void riscv_smptrace_sfence(void *unused)
{
	asm volatile("sfence.vma" ::: "memory");
}

// Both 3-level and 4-level page walking
static pte_t *riscv_walk_pte(unsigned long va, unsigned int *level_out,
                              unsigned long kernel_satp)
{
	unsigned long mode = kernel_satp >> RISCV_SATP_MODE_SHIFT;
	u64 *table = (u64 *)phys_to_virt(
		(phys_addr_t)(kernel_satp & RISCV_SATP_PPN_MASK) << PAGE_SHIFT);
	unsigned long idx;
	u64 pte;

	if (mode >= RISCV_SATP_MODE_SV57) {
		idx = (va >> 48) & 0x1FF;
		pte = READ_ONCE(table[idx]);
		if (!(pte & RISCV_PTE_V))
			return NULL;
		if (pte & RISCV_PTE_LEAF) {
			*level_out = SMPTRACE_RISCV_LEVEL_PUD;
			return (pte_t *)&table[idx];
		}
		table = (u64 *)phys_to_virt(riscv_pte_pa(pte));
	}

	if (mode >= RISCV_SATP_MODE_SV48) {
		idx = (va >> 39) & 0x1FF;
		pte = READ_ONCE(table[idx]);
		if (!(pte & RISCV_PTE_V))
			return NULL;
		if (pte & RISCV_PTE_LEAF) {
			*level_out = SMPTRACE_RISCV_LEVEL_PUD;
			return (pte_t *)&table[idx];
		}
		table = (u64 *)phys_to_virt(riscv_pte_pa(pte));
	}

	idx = (va >> 30) & 0x1FF;
	pte = READ_ONCE(table[idx]);
	if (!(pte & RISCV_PTE_V))
		return NULL;
	if (pte & RISCV_PTE_LEAF) {
		*level_out = SMPTRACE_RISCV_LEVEL_PUD;
		return (pte_t *)&table[idx];
	}
	table = (u64 *)phys_to_virt(riscv_pte_pa(pte));

	idx = (va >> 21) & 0x1FF;
	pte = READ_ONCE(table[idx]);
	if (!(pte & RISCV_PTE_V))
		return NULL;
	if (pte & RISCV_PTE_LEAF) {
		*level_out = SMPTRACE_RISCV_LEVEL_PMD;
		return (pte_t *)&table[idx];
	}
	table = (u64 *)phys_to_virt(riscv_pte_pa(pte));

	idx = (va >> PAGE_SHIFT) & 0x1FF;
	*level_out = SMPTRACE_RISCV_LEVEL_PTE;
	return (pte_t *)&table[idx];
}

static unsigned long riscv_level2size(unsigned int level)
{
	switch (level) {
	case SMPTRACE_RISCV_LEVEL_PTE: return PAGE_SIZE;
	case SMPTRACE_RISCV_LEVEL_PMD: return PMD_SIZE;
	case SMPTRACE_RISCV_LEVEL_PUD: return PUD_SIZE;
	default: BUG();
	}
}

int smptrace_arch_poison_pte(struct smptrace_map *map)
{
	unsigned long satp = csr_read(CSR_SATP);
	unsigned long va = map->va;
	int64_t remain = map->len;
	struct smptrace_pte *orig, *tmp;
	int ret;

	while (remain > 0) {
		unsigned int level;
		pte_t *ptep = riscv_walk_pte(va, &level, satp);

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

		switch (level) {
		case SMPTRACE_RISCV_LEVEL_PTE:
			orig->pte = pte_val(READ_ONCE(*ptep));
			WRITE_ONCE(*ptep, __pte(0));
			break;
		case SMPTRACE_RISCV_LEVEL_PMD:
			orig->pte = pmd_val(READ_ONCE(*(pmd_t *)ptep));
			WRITE_ONCE(*(pmd_t *)ptep, __pmd(0));
			break;
		case SMPTRACE_RISCV_LEVEL_PUD:
			orig->pte = pud_val(READ_ONCE(*(pud_t *)ptep));
			WRITE_ONCE(*(pud_t *)ptep, __pud(0));
			break;
		}

		pr_info("poisoned PTE for VA=%lx (level=%u)", va, level);

		remain -= riscv_level2size(level);
		va     += riscv_level2size(level);
		list_add_tail(&orig->list, &map->ptes);
	}

	on_each_cpu(riscv_smptrace_sfence, NULL, 1);
	return 0;

fail:
	list_for_each_entry_safe(orig, tmp, &map->ptes, list) {
		list_del(&orig->list);
		kfree(orig);
	}
	on_each_cpu(riscv_smptrace_sfence, NULL, 1);
	return ret;
}

void smptrace_arch_restore_pte(struct smptrace_map *map)
{
	unsigned long satp = csr_read(CSR_SATP);
	unsigned long va = map->va;
	int64_t remain = map->len;

	while (remain > 0) {
		unsigned int level;
		pte_t *ptep = riscv_walk_pte(va, &level, satp);
		struct smptrace_pte *orig;
		unsigned long step;

		if (!ptep) {
			remain -= PAGE_SIZE;
			va     += PAGE_SIZE;
			continue;
		}

		step = riscv_level2size(level);

		orig = smptrace_find_pte(map, va);
		if (!orig) {
			pr_err("could not find saved PTE for va=0x%lx\n", va);
			remain -= step;
			va     += step;
			continue;
		}

		list_del(&orig->list);

		if (orig->level != level)
			pr_warn("PTE level mismatch for va=0x%lx (saved=%u walk=%u)",
			        va, orig->level, level);

		switch (level) {
		case SMPTRACE_RISCV_LEVEL_PTE:
			WRITE_ONCE(*ptep, __pte(orig->pte));
			break;
		case SMPTRACE_RISCV_LEVEL_PMD:
			WRITE_ONCE(*(pmd_t *)ptep, __pmd(orig->pte));
			break;
		case SMPTRACE_RISCV_LEVEL_PUD:
			WRITE_ONCE(*(pud_t *)ptep, __pud(orig->pte));
			break;
		}

		pr_info("restored PTE for VA=%lx (level=%u)", va, level);

		remain -= step;
		va     += step;
		kfree(orig);
	}

	// No need to fully flush the TLB since the restored mapping should be valid
	if (irqs_disabled())
		asm volatile("sfence.vma" ::: "memory");
	else
		on_each_cpu(riscv_smptrace_sfence, NULL, 1);
}

struct riscv_ls_insn {
	u32  rd;
	u32  rs2;
	u32  size;
	bool is_store;
	bool sign_extend;
};

static const unsigned short riscv_gpr_offsets[32] = {
	[0]  = 0, // Could do w/o this probably
	[1]  = offsetof(struct pt_regs, ra),
	[2]  = offsetof(struct pt_regs, sp),
	[3]  = offsetof(struct pt_regs, gp),
	[4]  = offsetof(struct pt_regs, tp),
	[5]  = offsetof(struct pt_regs, t0),
	[6]  = offsetof(struct pt_regs, t1),
	[7]  = offsetof(struct pt_regs, t2),
	[8]  = offsetof(struct pt_regs, s0),
	[9]  = offsetof(struct pt_regs, s1),
	[10] = offsetof(struct pt_regs, a0),
	[11] = offsetof(struct pt_regs, a1),
	[12] = offsetof(struct pt_regs, a2),
	[13] = offsetof(struct pt_regs, a3),
	[14] = offsetof(struct pt_regs, a4),
	[15] = offsetof(struct pt_regs, a5),
	[16] = offsetof(struct pt_regs, a6),
	[17] = offsetof(struct pt_regs, a7),
	[18] = offsetof(struct pt_regs, s2),
	[19] = offsetof(struct pt_regs, s3),
	[20] = offsetof(struct pt_regs, s4),
	[21] = offsetof(struct pt_regs, s5),
	[22] = offsetof(struct pt_regs, s6),
	[23] = offsetof(struct pt_regs, s7),
	[24] = offsetof(struct pt_regs, s8),
	[25] = offsetof(struct pt_regs, s9),
	[26] = offsetof(struct pt_regs, s10),
	[27] = offsetof(struct pt_regs, s11),
	[28] = offsetof(struct pt_regs, t3),
	[29] = offsetof(struct pt_regs, t4),
	[30] = offsetof(struct pt_regs, t5),
	[31] = offsetof(struct pt_regs, t6),
};

static unsigned long riscv_get_reg(struct pt_regs *regs, u32 regno)
{
	if (regno == 0)
		return 0;
	return *(unsigned long *)((u8 *)regs + riscv_gpr_offsets[regno]);
}

static void riscv_set_reg(struct pt_regs *regs, u32 regno, unsigned long val)
{
	if (regno == 0)
		return;
	*(unsigned long *)((u8 *)regs + riscv_gpr_offsets[regno]) = val;
}

static int riscv_decode_rvc_ls_insn(u16 insn16, struct riscv_ls_insn *out)
{
	u32 op     = insn16 & 0x3;
	u32 funct3 = (insn16 >> 13) & 0x7;

	out->sign_extend = false;

	// Compressed load/store(s)
	if (op == 0x0) {
		u32 rp = (insn16 >> 2) & 0x7;

		switch (funct3) {
		// C.LW, which sign-extends like LW
		case 0x2:
			out->rd = 8 + rp; out->rs2 = 0;
			out->size = 4;    out->is_store = false;
			out->sign_extend = true; break;
		// C.LD
		case 0x3:
			out->rd = 8 + rp; out->rs2 = 0;
			out->size = 8;    out->is_store = false; break;
		// C.SW
		case 0x6:
			out->rs2 = 8 + rp; out->rd = 0;
			out->size = 4;     out->is_store = true;  break;
		// C.SD
		case 0x7:
			out->rs2 = 8 + rp; out->rd = 0;
			out->size = 8;     out->is_store = true;  break;
		default:
			return -EINVAL;
		}

	} else if (op == 0x2) {
		switch (funct3) {
		// C.LWSP, which sign-extends like LW
		case 0x2:
			out->rd = (insn16 >> 7) & 0x1F; out->rs2 = 0;
			out->size = 4;                   out->is_store = false;
			out->sign_extend = true;         break;
		// C.LDSP
		case 0x3:
			out->rd = (insn16 >> 7) & 0x1F; out->rs2 = 0;
			out->size = 8;                   out->is_store = false; break;
		// C.SWSP
		case 0x6:
			out->rs2 = (insn16 >> 2) & 0x1F; out->rd = 0;
			out->size = 4;                    out->is_store = true;  break;
		// C.SDSP
		case 0x7:
			out->rs2 = (insn16 >> 2) & 0x1F; out->rd = 0;
			out->size = 8;                    out->is_store = true;  break;
		default:
			return -EINVAL;
		}

	} else {
		return -EINVAL;
	}

	return 0;
}

static int riscv_decode_ls_insn(u32 insn, struct riscv_ls_insn *out)
{
	u32 opcode = insn & 0x7F;
	u32 funct3 = (insn >> 12) & 0x7;

	// Immediate group
	if (opcode == 0x03) {
		out->rd       = (insn >> 7)  & 0x1F;
		out->rs2      = 0;
		out->is_store = false;

		switch (funct3) {
		// LB
		case 0x0: out->size = 1; out->sign_extend = true;  break;
		// LH
		case 0x1: out->size = 2; out->sign_extend = true;  break;
		// LW
		case 0x2: out->size = 4; out->sign_extend = true;  break;
		// LD
		case 0x3: out->size = 8; out->sign_extend = false; break;
		// LBU
		case 0x4: out->size = 1; out->sign_extend = false; break;
		// LHU
		case 0x5: out->size = 2; out->sign_extend = false; break;
		// LWU
		case 0x6: out->size = 4; out->sign_extend = false; break;
		default:  return -EINVAL;
		}

	} else if (opcode == 0x23) {
		out->rs2         = (insn >> 20) & 0x1F;
		out->rd          = 0;
		out->is_store    = true;
		out->sign_extend = false;

		switch (funct3) {
		// SB
		case 0x0: out->size = 1; break;
		// SH
		case 0x1: out->size = 2; break;
		// SW
		case 0x2: out->size = 4; break;
		// SD
		case 0x3: out->size = 8; break;
		default:  return -EINVAL;
		}

	} else {
		return -EINVAL;
	}

	return 0;
}

/* A decoded trapped load or store, and how long its encoding is. */
struct smptrace_riscv_op {
	struct riscv_ls_insn ls;
	bool is_rvc;
};

/*
 * Decodes the instruction at regs->epc without performing it. Called twice per
 * fault, from the kprobe to decide whether to claim it and again from the
 * continuation to perform it; decoding reads only kernel text and pt_regs, so
 * both calls agree.
 */
static int plan_riscv_fault(struct pt_regs *regs, struct smptrace_riscv_op *op)
{
	u32 insn;

	if (user_mode(regs))
		return -EACCES;

	if (copy_from_kernel_nofault(&insn, (void *)regs->epc, sizeof(insn))) {
		pr_warn_ratelimited("failed to read insn at epc=0x%lx", regs->epc);
		return -EFAULT;
	}

	op->is_rvc = (insn & 0x3) != 0x3;
	if (op->is_rvc) {
		if (riscv_decode_rvc_ls_insn((u16)insn, &op->ls)) {
			pr_warn_ratelimited(
				"unhandled RVC instruction at epc=0x%lx (insn=0x%04x)",
				regs->epc, insn & 0xFFFF);
			return -EINVAL;
		}
	} else {
		if (riscv_decode_ls_insn(insn, &op->ls)) {
			pr_warn_ratelimited(
				"unrecognised load/store at epc=0x%lx insn=0x%08x",
				regs->epc, insn);
			return -EINVAL;
		}
	}

	return 0;
}

/* Performs a planned access and steps the faulting context past it. */
static void execute_riscv_fault(struct smptrace_ctx *ctx,
                                struct smptrace_map *map,
                                unsigned long fault_va,
                                struct pt_regs *regs,
                                const struct smptrace_riscv_op *op)
{
	const struct riscv_ls_insn *ls = &op->ls;
	u64 val;

	if (ls->is_store) {
		unsigned long src = riscv_get_reg(regs, ls->rs2);
		smptrace_emulate_write(ctx, map, fault_va, ls->size, (u8 *)&src);
	} else {
		val = 0;
		smptrace_emulate_read(ctx, map, fault_va, ls->size, (u8 *)&val);

		if (ls->rd != 0) {
			if (ls->sign_extend) {
				unsigned int sbits = ls->size * 8;
				s64 sval = (s64)(val << (64 - sbits)) >> (64 - sbits);
				riscv_set_reg(regs, ls->rd, (unsigned long)sval);
			} else {
				riscv_set_reg(regs, ls->rd, (unsigned long)val);
			}
		}
	}

	// Compressed opcodes are 2 bytes, let's take that into account or fun stuff awaits us
	regs->epc += op->is_rvc ? 2 : 4;
}

/* The tracer whose kprobe claimed this CPU's current fault, handed from the
 * kprobe to the continuation. Nothing runs on this CPU in between: the kprobe
 * returns straight into the continuation with interrupts still disabled. */
static DEFINE_PER_CPU(struct smptrace_ctx *, smptrace_cont_ctx);

/*
 * Runs in place of handle_page_fault() for a fault the kprobe claimed, with the
 * same argument, and returns to its caller. Unlike the kprobe handler it may run
 * with interrupts enabled, so a load that waits on userspace restores the
 * faulting context's interrupt state (SR_PIE) for the wait, as
 * handle_page_fault() itself does: a hart that spins with interrupts off cannot
 * take the IPIs that remote TLB flushes and other cross-CPU calls wait on, and
 * every hart waiting on it is one the device model cannot run on.
 *
 * Returning without advancing regs->epc retries the access, which faults again
 * and is re-judged by the kprobe.
 */
static void smptrace_page_fault_cont(struct pt_regs *regs)
{
	struct smptrace_ctx *ctx = this_cpu_read(smptrace_cont_ctx);
	unsigned long fault_va = regs->badaddr;
	struct smptrace_map map = {0};
	struct smptrace_riscv_op op;
	bool irqs_on;

	this_cpu_write(smptrace_cont_ctx, NULL);
	if (WARN_ON_ONCE(!ctx))
		return;

	/* smptrace_deactivate() unregisters the kprobe, which waits for an RCU
	 * grace period, before it frees what this reads. */
	guard(rcu)();

	if (!smptrace_find_map_rcu(ctx, fault_va, &map))
		return;
	if (WARN_ON_ONCE(plan_riscv_fault(regs, &op)))
		return;

	irqs_on = !op.ls.is_store && !regs_irqs_disabled(regs);

	/* ctx->in_pf and the eventual return stay on this hart. */
	preempt_disable();
	if (irqs_on) {
		/* An interrupt taken here may fault on a traced BAR itself; that
		 * fault is claimed afresh, so in_pf is left clear. */
		local_irq_enable();
		execute_riscv_fault(ctx, &map, fault_va, regs, &op);
		local_irq_disable();
	} else {
		this_cpu_write(*ctx->in_pf, true);
		execute_riscv_fault(ctx, &map, fault_va, regs, &op);
		this_cpu_write(*ctx->in_pf, false);
	}
	preempt_enable();

	pr_debug("page fault: emulated %s at %pS with interrupts %s",
	         op.ls.is_store ? "store" : "load", (void *)regs->epc,
	         irqs_on ? "enabled" : "disabled");
}
NOKPROBE_SYMBOL(smptrace_page_fault_cont);

// do_trap_load_page_fault and do_trap_store_page are NOKPROBE, let's do handle_page_fault
static int __enter_riscv_handle_page_fault(struct kprobe *kp,
                                           struct pt_regs *regs)
{
	struct smptrace_ctx *ctx = container_of(kp, struct smptrace_ctx, badarea_kp);
	struct pt_regs *fault_regs =
		(struct pt_regs *)regs_get_kernel_argument(regs, 0);
	unsigned long fault_va = fault_regs->badaddr;
	unsigned long cause    = fault_regs->cause;
	struct smptrace_map map = {0};
	struct smptrace_riscv_op op;

	if (cause != EXC_LOAD_PAGE_FAULT && cause != EXC_STORE_PAGE_FAULT)
		return 0;

	if (user_mode(fault_regs))
		return 0;

	if (!smptrace_find_map_rcu(ctx, fault_va, &map))
		return 0;

	if (this_cpu_read(*ctx->in_pf)) {
		pr_warn("reentrant fault on 0x%lx, ignoring", fault_va);
		return 0;
	}

	if (plan_riscv_fault(fault_regs, &op))
		return 0;

	/* Emulate in the continuation, outside kprobe context, where the wait
	 * for a load's answer may run with interrupts enabled. */
	this_cpu_write(smptrace_cont_ctx, ctx);
	instruction_pointer_set(regs, (unsigned long)smptrace_page_fault_cont);
	return 1;
}

int smptrace_arch_activate(struct smptrace_ctx *ctx)
{
	unsigned long satp;
	
	// Maybe we could do w/o SATP but it should point to kernel page tables on this context
	satp = csr_read(CSR_SATP);
	if (!satp) {
		pr_err("SATP is zero — MMU not enabled?\n");
		return -EINVAL;
	}

	ctx->shadow_va = ioremap(ctx->pa, ctx->len);
	if (!ctx->shadow_va) {
		pr_err("Failed to map shadow VA\n");
		return -ENOMEM;
	}
	readl(ctx->shadow_va);

	ctx->badarea_kp = (struct kprobe){
		.pre_handler = __enter_riscv_handle_page_fault,
		.symbol_name = "handle_page_fault",
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
		.kp.symbol_name = "ioremap_prot",
	};

	return smptrace_register_probes(ctx);
}
