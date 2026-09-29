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

/*
 * Serves a fault of the given order in a user mapping of a BAR whose start,
 * vma->vm_start, maps physical address pa. Pages no traced range covers are
 * mapped at the orders asked for, when the huge page is wholly inside the vma
 * and aligned. An access to a traced page is emulated and never maps it. The
 * ranges are fixed while a tracer lives, so what is traced can only change to
 * nothing, when the tracer goes away, and a page mapped stays correctly
 * mapped. The caller applies its own rules for whether the device's memory
 * may be touched at all.
 */
vm_fault_t smptrace_user_huge_fault(struct vm_fault *vmf, unsigned int order, phys_addr_t pa)
{
	struct vm_area_struct *vma = vmf->vma;
	unsigned long addr = vmf->address & ~((PAGE_SIZE << order) - 1);
	unsigned long pfn = PHYS_PFN(pa) + ((addr - vma->vm_start) >> PAGE_SHIFT);
	bool traced;
	int err;

	if (order && (addr < vma->vm_start || addr + (PAGE_SIZE << order) > vma->vm_end ||
	              pfn & ((1UL << order) - 1)))
		return VM_FAULT_FALLBACK;

	scoped_guard(smptrace_active, &smptrace_active_srcu)
		traced = smptrace_pa_traced(PFN_PHYS(pfn), PAGE_SIZE << order);
	/* A huge page with a traced part is faulted page by page */
	if (traced && order)
		return VM_FAULT_FALLBACK;

	/* Only a user-mode load or store has an instruction to emulate. A
	 * kernel access (uaccess) gets -EFAULT, an instruction fetch SIGBUS. */
	if (traced && (!(vmf->flags & FAULT_FLAG_USER) || (vmf->flags & FAULT_FLAG_INSTRUCTION)))
		return VM_FAULT_SIGBUS;

	err = traced ? smptrace_arch_user_fault(task_pt_regs(current), vmf->real_address,
	                                        vma->vm_start, vma->vm_end, pa) : -ENOENT;
	if (!err || err == -EAGAIN)
		return VM_FAULT_NOPAGE;
	if (err == -ENOENT)
		/* Not traced, or no longer (the device model is gone) */
		return smptrace_user_insert(vmf, pfn, order);
	return VM_FAULT_SIGBUS;
}
