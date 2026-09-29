/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Routes userspace accesses through an mmap() of a traced BAR's sysfs
 * resource files (/sys/bus/pci/devices/<bdf>/resourceN and resourceN_wc) or
 * its procfs file (/proc/bus/pci/<bus>/<devfn>) to the device model, as the
 * vfio-pci mmap() trap does, for a process that has no vfio device fd.
 *
 * Both files map a BAR through pci_mmap_resource_range(), which sets the vma
 * up and maps every page of it at once with io_remap_pfn_range(). Its vm_ops
 * have no fault handler, and the process then reads and writes the BAR's
 * backing memory directly, unseen by the device model.
 *
 * A kprobe on pci_mmap_resource_range() redirects the call, for a mapping
 * that reaches a traced range, to a replacement that sets the vma up the same
 * way (vm_page_prot, vm_pgoff as a physical page number, the flags
 * remap_pfn_range() sets) but maps nothing, and installs vm_ops whose fault
 * handler is smptrace_user_huge_fault(): an access to a traced page is
 * emulated against the tracer and never maps it, other pages are mapped when
 * first touched. No PTE for a traced page exists while its tracer does.
 * Redirecting, rather than letting the original run and zapping the traced
 * PTEs from a return handler, keeps traced pages from ever being mapped, and
 * a return handler cannot sleep, which zapping does.
 *
 * kernfs wraps a sysfs file's vm_ops in its own, which forward only open,
 * fault, page_mkwrite and access, and it refuses vm_ops with a close. A vma
 * needs a close to hold a module reference, and huge faults would be lost. So
 * for a sysfs file the replacement installs vm_ops with no close, which kernfs
 * accepts and records, and a kretprobe on kernfs_fop_mmap() puts the full
 * vm_ops back once kernfs has wrapped them. Its entry handler marks the vma
 * (vm_private_data, which nothing on this path uses) so that the redirect
 * knows the return handler will run; a sysfs mapping without the mark (the
 * kretprobe had no instance free) keeps the original path. The module
 * reference the redirect takes goes to the vma once the mmap() succeeds, and
 * is dropped if kernfs then fails it. The procfs file has no wrapper.
 *
 * Nothing here needs the pci_dev after mmap(): the handler finds the tracer
 * by physical address, so the mapping is stateless like the vfio-pci one.
 * Once the tracer is gone every page is mapped on first touch and the mapping
 * keeps working against the backing memory.
 *
 * Memory decoding is not modelled on this path: an access reaches the tracer,
 * or the backing memory, whatever the device's PCI_COMMAND says. On hardware
 * a sysfs mapping keeps its PTEs when decoding is turned off and the bus
 * answers reads with all-ones; pciem has no bus, pages already mapped would
 * reach the backing memory anyway, and nothing (vfio-pci zaps only its own
 * mappings) revokes a sysfs mapping when the bit changes, so a check at fault
 * time could only be partial. pciem's trap of kernel mappings does not model
 * it either.
 *
 * A mapping made before its BAR was traced has all its PTEs already and is
 * not affected by the tracing: as for a vfio-pci mapping made then, its
 * accesses reach the backing memory unseen.
 *
 * x86 only, like the vfio-pci mmap() trap: only x86 has a user-mode emulator.
 */
#define pr_fmt(fmt) KBUILD_MODNAME ": sysfs: " fmt

#include <linux/fs.h>
#include <linux/kprobes.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <uapi/linux/magic.h>
#include "trace/smptrace_internal.h"

/* vm_private_data of a vma in a kernfs mmap() whose return will be seen */
static char smptrace_sysfs_armed;
/* ... and once the replacement has set it up, holding a module reference */
static char smptrace_sysfs_owned;

static bool smptrace_sysfs_file(struct file *file)
{
	return file && file_inode(file)->i_sb->s_magic == SYSFS_MAGIC;
}

/* A sysfs file whose mapping is the iomem one (pci_create_attr() gives every
 * resource file iomem_get_mapping()), as opposed to other mmap()able sysfs
 * files, whose vm_private_data must not be touched. */
static bool smptrace_sysfs_resource_file(struct file *file)
{
	return smptrace_sysfs_file(file) && file->f_mapping &&
	       file->f_mapping != file_inode(file)->i_mapping && file->f_mapping->host &&
	       file->f_mapping->host->i_sb->s_magic == DEVMEM_MAGIC;
}

static void smptrace_sysfs_vma_open(struct vm_area_struct *vma)
{
	__module_get(THIS_MODULE);
}

static void smptrace_sysfs_vma_close(struct vm_area_struct *vma)
{
	module_put(THIS_MODULE);
}

/* vm_pgoff is the physical page number vma->vm_start maps */
static vm_fault_t smptrace_sysfs_huge_fault(struct vm_fault *vmf, unsigned int order)
{
	return smptrace_user_huge_fault(vmf, order, PFN_PHYS(vmf->vma->vm_pgoff));
}

static vm_fault_t smptrace_sysfs_fault(struct vm_fault *vmf)
{
	return smptrace_sysfs_huge_fault(vmf, 0);
}

static const struct vm_operations_struct smptrace_sysfs_vm_ops = {
	.open  = smptrace_sysfs_vma_open,
	.close = smptrace_sysfs_vma_close,
	.fault = smptrace_sysfs_fault,
#ifdef SMPTRACE_USER_HUGE_FAULT
	.huge_fault = smptrace_sysfs_huge_fault,
#endif
#ifdef CONFIG_HAVE_IOREMAP_PROT
	/* As pci_phys_vm_ops. It needs a PTE, so a traced page is refused. */
	.access = generic_access_phys,
#endif
};

/*
 * What kernfs records for a sysfs mapping and wraps: no close, which kernfs
 * refuses. The kernfs_fop_mmap() return handler replaces it on the vma with
 * smptrace_sysfs_vm_ops before the vma can be used, so only kernfs's check
 * that later mmap()s of the same open file use the same vm_ops sees it.
 */
static const struct vm_operations_struct smptrace_sysfs_kernfs_vm_ops = {
	.fault = smptrace_sysfs_fault,
#ifdef CONFIG_HAVE_IOREMAP_PROT
	.access = generic_access_phys,
#endif
};

/*
 * Runs in place of pci_mmap_resource_range() for a memory BAR mapping that
 * reaches a traced range, with its arguments, and returns to its caller. It
 * does what the original does, except that it maps nothing and installs
 * vm_ops with a fault handler. The kprobe took a module reference, which the
 * vma keeps.
 */
static int smptrace_sysfs_mmap_range(struct pci_dev *pdev, int bar, struct vm_area_struct *vma,
                                     enum pci_mmap_state mmap_state, int write_combine)
{
	bool kernfs = vma->vm_private_data == &smptrace_sysfs_armed;

	/* A private writable mapping copies a page on write, which
	 * vmf_insert_pfn() does not support in a PFN map (it BUG()s): refuse
	 * it, as vfio-pci refuses every private mapping. */
	if (is_cow_mapping(vma->vm_flags)) {
		module_put(THIS_MODULE);
		return -EINVAL;
	}

	if (write_combine)
		vma->vm_page_prot = pgprot_writecombine(vma->vm_page_prot);
	else
		vma->vm_page_prot = pgprot_device(vma->vm_page_prot);
	/* What io_remap_pfn_range() maps with; vmf_insert_pfn() uses
	 * vm_page_prot as it is. The cache mode of each page inserted is the
	 * memory type reserved for it (on x86 the tracer's own ioremap(),
	 * UC-), as remap_pfn_range() would settle on while a tracer lives. */
	vma->vm_page_prot = pgprot_decrypted(vma->vm_page_prot);
	vma->vm_pgoff += pci_resource_start(pdev, bar) >> PAGE_SHIFT;
	/* What remap_pfn_range() sets */
	vm_flags_set(vma, VM_IO | VM_PFNMAP | VM_DONTEXPAND | VM_DONTDUMP);

	if (kernfs) {
		/* The kernfs_fop_mmap() return handler finishes this */
		vma->vm_private_data = &smptrace_sysfs_owned;
		vma->vm_ops = &smptrace_sysfs_kernfs_vm_ops;
	} else {
		vma->vm_ops = &smptrace_sysfs_vm_ops;
	}
	return 0;
}
NOKPROBE_SYMBOL(smptrace_sysfs_mmap_range);

static int smptrace_sysfs_enter_mmap_range(struct kprobe *kp, struct pt_regs *regs)
{
	/* pci_mmap_resource_range(pdev, bar, vma, mmap_state, write_combine) */
	struct pci_dev *pdev = (void *)regs_get_kernel_argument(regs, 0);
	int bar = regs_get_kernel_argument(regs, 1);
	struct vm_area_struct *vma = (void *)regs_get_kernel_argument(regs, 2);
	enum pci_mmap_state state = regs_get_kernel_argument(regs, 3);
	resource_size_t len;
	phys_addr_t pa;
	bool traced;

	if (state != pci_mmap_mem || bar < 0 || bar >= PCI_STD_NUM_BARS ||
	    !(pci_resource_flags(pdev, bar) & IORESOURCE_MEM))
		return 0;
	len = pci_resource_len(pdev, bar);
	/* The original refuses a mapping that runs past the BAR */
	if (!len || vma->vm_pgoff + vma_pages(vma) > ((len - 1) >> PAGE_SHIFT) + 1)
		return 0;

	pa = PFN_PHYS((pci_resource_start(pdev, bar) >> PAGE_SHIFT) + vma->vm_pgoff);
	scoped_guard(smptrace_active, &smptrace_active_srcu)
		traced = smptrace_pa_traced(pa, vma->vm_end - vma->vm_start);
	if (!traced)
		return 0;

	/* kernfs would keep its wrapper, around vm_ops without a close */
	if (vma->vm_private_data != &smptrace_sysfs_armed && smptrace_sysfs_file(vma->vm_file)) {
		pr_warn_ratelimited("%s BAR%d: cannot trap this sysfs mmap(), the device model will not see its accesses\n",
		                    pci_name(pdev), bar);
		return 0;
	}
	if (!try_module_get(THIS_MODULE))
		return 0;

	instruction_pointer_set(regs, (unsigned long)smptrace_sysfs_mmap_range);
	return 1;
}

/* Deliberately empty: a kprobe with a post_handler is never optimized, and an
 * optimized one would drop the redirect (see smptrace_badarea_no_optimize()). */
static void smptrace_sysfs_mmap_range_no_optimize(struct kprobe *kp, struct pt_regs *regs,
                                                  unsigned long flags)
{
}

struct smptrace_sysfs_kernfs_args {
	struct vm_area_struct *vma;
};

static int smptrace_sysfs_enter_kernfs_mmap(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct smptrace_sysfs_kernfs_args *args = (void *)ri->data;
	/* kernfs_fop_mmap(struct file *, struct vm_area_struct *) */
	struct file *file = (struct file *)regs_get_kernel_argument(regs, 0);
	struct vm_area_struct *vma = (struct vm_area_struct *)regs_get_kernel_argument(regs, 1);

	/* Nonzero: no return handler for this call */
	if (vma->vm_private_data || !smptrace_sysfs_resource_file(file))
		return 1;
	vma->vm_private_data = &smptrace_sysfs_armed;
	args->vma = vma;
	return 0;
}

static int smptrace_sysfs_exit_kernfs_mmap(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct smptrace_sysfs_kernfs_args *args = (void *)ri->data;
	struct vm_area_struct *vma = args->vma;
	void *mark = vma->vm_private_data;

	/* The vma is not yet visible to other threads: mmap() inserts it
	 * only after the file's ->mmap returns, or frees it if that failed. */
	if (mark != &smptrace_sysfs_armed && mark != &smptrace_sysfs_owned)
		return 0;
	vma->vm_private_data = NULL;
	if (mark == &smptrace_sysfs_armed)
		/* Not redirected: the original mapped it */
		return 0;

	if (regs_return_value(regs))
		module_put(THIS_MODULE);
	else
		/* In place of kernfs's wrapper around smptrace_sysfs_kernfs_vm_ops */
		vma->vm_ops = &smptrace_sysfs_vm_ops;
	return 0;
}

static struct kprobe smptrace_sysfs_kp;
static struct kretprobe smptrace_sysfs_krp;
static bool smptrace_sysfs_kp_registered, smptrace_sysfs_krp_registered;

int smptrace_sysfs_init(void)
{
	/* Only architectures with a user-mode emulator trap user mappings. */
	if (!IS_ENABLED(CONFIG_X86))
		return 0;

	/* First, so that no sysfs mapping is redirected without it */
	smptrace_sysfs_krp = (struct kretprobe){
		.kp.symbol_name = "kernfs_fop_mmap",
		.entry_handler  = smptrace_sysfs_enter_kernfs_mmap,
		.handler        = smptrace_sysfs_exit_kernfs_mmap,
		.data_size      = sizeof(struct smptrace_sysfs_kernfs_args),
		.maxactive      = 32,
	};
	if (!register_kretprobe(&smptrace_sysfs_krp))
		smptrace_sysfs_krp_registered = true;
	else
		pr_warn("cannot probe kernfs_fop_mmap(): sysfs mmap()s of traced BARs are not trapped\n");

	smptrace_sysfs_kp = (struct kprobe){
		.symbol_name  = "pci_mmap_resource_range",
		.pre_handler  = smptrace_sysfs_enter_mmap_range,
		.post_handler = smptrace_sysfs_mmap_range_no_optimize,
	};
	if (!register_kprobe(&smptrace_sysfs_kp)) {
		smptrace_sysfs_kp_registered = true;
		pr_info("trapping sysfs/procfs mmap()s of traced BARs\n");
	}
	return 0;
}

void smptrace_sysfs_exit(void)
{
	/* Every redirected mapping holds a module reference, so none is
	 * between the two probes now. */
	if (smptrace_sysfs_kp_registered) {
		unregister_kprobe(&smptrace_sysfs_kp);
		smptrace_sysfs_kp_registered = false;
	}
	if (smptrace_sysfs_krp_registered) {
		unregister_kretprobe(&smptrace_sysfs_krp);
		smptrace_sysfs_krp_registered = false;
	}
}
