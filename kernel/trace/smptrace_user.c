/* SPDX-License-Identifier: GPL-2.0 */
/*
 * The fault handler core for userspace mappings of a traced BAR, shared by
 * every way a process can map one (vfio-pci, and sysfs or procfs resource
 * files).
 *
 * Such a mapping never holds a PTE for a traced page: each access to one
 * faults, and the handler emulates the one instruction against the tracer and
 * steps past it, in the accessing process's context, so a read may sleep while
 * the device model answers it. Pages no traced range covers are mapped, and
 * then accessed directly. Everything the handler needs is derived from the
 * vma and the physical address its start maps, so it keeps no state.
 */
#define pr_fmt(fmt) KBUILD_MODNAME ": user: " fmt

#include <linux/mm.h>
#include <linux/sched/task_stack.h>
#include "trace/smptrace_internal.h"

/*
 * Maps order pages at pfn, as vfio_pci_mmap_huge_fault() does, or asks for a
 * smaller order.
 */
static vm_fault_t smptrace_user_insert(struct vm_fault *vmf, unsigned long pfn,
                                       unsigned int order)
{
	switch (order) {
	case 0:
		return vmf_insert_pfn(vmf->vma, vmf->address, pfn);
#ifdef SMPTRACE_USER_HUGE_FAULT
#ifdef CONFIG_ARCH_SUPPORTS_PMD_PFNMAP
	case PMD_ORDER:
		return vmf_insert_pfn_pmd(vmf, pfn, false);
#endif
#ifdef CONFIG_ARCH_SUPPORTS_PUD_PFNMAP
	case PUD_ORDER:
		return vmf_insert_pfn_pud(vmf, pfn, false);
#endif
#endif
	default:
		return VM_FAULT_FALLBACK;
	}
}

static struct page *smptrace_scratch;

int smptrace_scratch_alloc(void)
{
	struct page *page;

	if (smptrace_scratch)
		return 0;
	page = alloc_page(GFP_KERNEL);
	if (!page)
		return -ENOMEM;
	memset(page_address(page), 0xff, PAGE_SIZE);
	smptrace_scratch = page;
	return 0;
}

void smptrace_scratch_free(void)
{
	if (smptrace_scratch)
		__free_page(smptrace_scratch);
	smptrace_scratch = NULL;
}

void smptrace_scratch_fill(void)
{
	struct page *page = READ_ONCE(smptrace_scratch);

	if (page)
		memset(page_address(page), 0xff, PAGE_SIZE);
}

/*
 * Serves a fault in a user mapping of a BAR whose start maps physical address pa.
 * A traced page is emulated; an untraced one maps the BAR, or ones while gated.
 */
vm_fault_t smptrace_user_huge_fault(struct vm_fault *vmf, unsigned int order, phys_addr_t pa)
{
	struct vm_area_struct *vma = vmf->vma;
	unsigned long addr = vmf->address & ~((PAGE_SIZE << order) - 1);
	unsigned long pfn = PHYS_PFN(pa) + ((addr - vma->vm_start) >> PAGE_SHIFT);
	struct page *scratch = READ_ONCE(smptrace_scratch);
	bool traced, gated;
	int err;

	if (order && (addr < vma->vm_start || addr + (PAGE_SIZE << order) > vma->vm_end ||
	              pfn & ((1UL << order) - 1)))
		return VM_FAULT_FALLBACK;

	scoped_guard(smptrace_active, &smptrace_active_srcu) {
		traced = smptrace_pa_traced(PFN_PHYS(pfn), PAGE_SIZE << order);
		gated = smptrace_pa_gated(PFN_PHYS(pfn), PAGE_SIZE << order);
	}
	/* A huge page with a traced part, or a gated one, is faulted page by page */
	if ((traced || gated) && order)
		return VM_FAULT_FALLBACK;
	if (gated && !traced && !scratch)
		traced = true;

	/* Only a user-mode load or store has an instruction to emulate. A
	 * kernel access (uaccess) gets -EFAULT, an instruction fetch SIGBUS. */
	if (traced && (!(vmf->flags & FAULT_FLAG_USER) || (vmf->flags & FAULT_FLAG_INSTRUCTION)))
		return VM_FAULT_SIGBUS;

	err = traced ? smptrace_arch_user_fault(task_pt_regs(current), vmf->real_address,
	                                        vma->vm_start, vma->vm_end, pa) : -ENOENT;
	if (!err || err == -EAGAIN)
		return VM_FAULT_NOPAGE;
	if (err == -ENOENT) {
		/* Not traced, or no longer (the device model is gone) */
		bool use_scratch = gated && scratch;
		vm_fault_t ret = smptrace_user_insert(vmf, use_scratch ? page_to_pfn(scratch) : pfn, order);

		smp_mb();
		scoped_guard(smptrace_active, &smptrace_active_srcu)
			gated = smptrace_pa_gated(PFN_PHYS(pfn), PAGE_SIZE << order);
		if (gated == use_scratch)
			return ret;
		zap_vma_ptes(vma, addr, PAGE_SIZE << order);
		return VM_FAULT_NOPAGE;
	}
	return VM_FAULT_SIGBUS;
}
