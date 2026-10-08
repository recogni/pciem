/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Routes userspace accesses to a traced BAR through vfio-pci, by mmap() or by
 * read()/write() on the device fd, to the device model, in the accessing
 * process's context so a read may sleep while the device model answers it.
 *
 * smptrace traps kernel mappings of a BAR by poisoning the PTEs ioremap()
 * creates. A process that mmap()s the BAR through its vfio device fd gets its
 * own page tables pointing at the BAR, which nothing poisons, so its loads and
 * stores would never reach the device model.
 *
 * vfio-pci maps BAR pages lazily, from its fault handler. A kretprobe on
 * vfio_pci_core_mmap() replaces that handler, for mappings that reach a traced
 * range, with one that never maps a traced page: each access to one faults,
 * and the handler emulates the one instruction against the tracer and steps
 * past it. No access can bypass the device model, from any thread, because no
 * PTE for a traced page ever exists. Untraced pages are mapped as vfio-pci
 * maps them.
 *
 * vfio-pci's vm_ops only has fault handlers, and everything this handler
 * needs is derived from the vma, so the replacement is stateless and splits,
 * mremap() and fork() need nothing beyond a module reference per vma.
 *
 * read() and write() reach a BAR through vfio_pci_bar_rw(), which accesses
 * vfio-pci's own kernel mapping of it. smptrace would trap those accesses as
 * kernel faults, and a kernel fault cannot tell whether it may sleep, so it
 * spins. A kprobe on vfio_pci_bar_rw() instead redirects the call, for traced
 * BARs, to a replacement that hands each access to the tracer directly.
 */
#define pr_fmt(fmt) KBUILD_MODNAME ": vfio: " fmt

#include <linux/kprobes.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/pci.h>
#include <linux/rwsem.h>
#include <linux/sched/task_stack.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <linux/vfio_pci_core.h>
#include "trace/smptrace_internal.h"

static unsigned int vma_bar(struct vm_area_struct *vma)
{
	return vma->vm_pgoff >> (VFIO_PCI_OFFSET_SHIFT - PAGE_SHIFT);
}

/* Physical address vma->vm_start maps, following vfio's vm_pgoff encoding. */
static phys_addr_t vma_phys(struct vm_area_struct *vma)
{
	struct vfio_pci_core_device *vdev = vma->vm_private_data;
	u64 pgoff = vma->vm_pgoff & ((1UL << (VFIO_PCI_OFFSET_SHIFT - PAGE_SHIFT)) - 1);

	return pci_resource_start(vdev->pdev, vma_bar(vma)) + (pgoff << PAGE_SHIFT);
}

/*
 * vfio-pci's rule for touching device memory (__vfio_pci_memory_enabled(),
 * which is not exported, and its fault handler's runtime-PM check): memory
 * decoding as the user set it in vfio-pci's virtual command register, and the
 * device not in D3 or runtime suspended. Caller holds memory_lock.
 */
static bool smptrace_vfio_mem_usable(struct vfio_pci_core_device *vdev)
{
	struct pci_dev *pdev = vdev->pdev;
	u16 cmd = le16_to_cpu(*(__le16 *)&vdev->vconfig[PCI_COMMAND]);

	return !vdev->pm_runtime_engaged && pdev->current_state < PCI_D3hot &&
	       (pdev->no_command_memory || (cmd & PCI_COMMAND_MEMORY));
}

static void smptrace_vfio_vma_open(struct vm_area_struct *vma)
{
	__module_get(THIS_MODULE);
}

static void smptrace_vfio_vma_close(struct vm_area_struct *vma)
{
	module_put(THIS_MODULE);
}

#if defined(CONFIG_ARCH_SUPPORTS_HUGE_PFNMAP) && LINUX_VERSION_CODE >= KERNEL_VERSION(6, 17, 0)
#define SMPTRACE_VFIO_HUGE_FAULT
#endif

/*
 * vfio_pci_mmap_huge_fault() for untraced memory: maps order pages at pfn, or
 * asks for a smaller order. Caller holds memory_lock and has checked that
 * memory is usable.
 */
static vm_fault_t smptrace_vfio_insert(struct vm_fault *vmf, unsigned long pfn,
                                       unsigned int order)
{
	switch (order) {
	case 0:
		return vmf_insert_pfn(vmf->vma, vmf->address, pfn);
#ifdef SMPTRACE_VFIO_HUGE_FAULT
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
 * Pages no traced range covers are mapped as vfio-pci maps them, at the orders
 * it would, so that part of the BAR behaves like an ordinary vfio-pci mmap().
 * An access to a traced page is emulated and never maps it. The ranges are
 * fixed while a tracer lives, so what is traced can only change to nothing,
 * when the tracer goes away, and a page mapped stays correctly mapped.
 */
static vm_fault_t smptrace_vfio_huge_fault(struct vm_fault *vmf, unsigned int order)
{
	struct vm_area_struct *vma = vmf->vma;
	struct vfio_pci_core_device *vdev = vma->vm_private_data;
	phys_addr_t pa = vma_phys(vma);
	unsigned long addr = vmf->address & ~((PAGE_SIZE << order) - 1);
	unsigned long pfn = PHYS_PFN(pa) + ((addr - vma->vm_start) >> PAGE_SHIFT);
	vm_fault_t ret = VM_FAULT_SIGBUS;
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

	/* The rules of vfio-pci's own fault handler: no access while device
	 * memory is disabled or the device is runtime-suspended, and none
	 * concurrent with a reset, which holds memory_lock for write. */
	down_read(&vdev->memory_lock);
	if (!smptrace_vfio_mem_usable(vdev))
		goto out;

	err = traced ? smptrace_arch_user_fault(task_pt_regs(current), vmf->real_address,
	                                        vma->vm_start, vma->vm_end, pa) : -ENOENT;
	if (!err || err == -EAGAIN)
		ret = VM_FAULT_NOPAGE;
	else if (err == -ENOENT)
		/* Not traced, or no longer (the device model is gone) */
		ret = smptrace_vfio_insert(vmf, pfn, order);
out:
	up_read(&vdev->memory_lock);
	return ret;
}

static vm_fault_t smptrace_vfio_fault(struct vm_fault *vmf)
{
	return smptrace_vfio_huge_fault(vmf, 0);
}

static const struct vm_operations_struct smptrace_vfio_vm_ops = {
	.open  = smptrace_vfio_vma_open,
	.close = smptrace_vfio_vma_close,
	.fault = smptrace_vfio_fault,
#ifdef SMPTRACE_VFIO_HUGE_FAULT
	.huge_fault = smptrace_vfio_huge_fault,
#endif
};

/* One access of a read() or write(), under vfio-pci's rules. With no tracer
 * left (the device model is gone) it behaves as a device that has gone:
 * reads return all-ones and writes are dropped. */
static int smptrace_vfio_access(struct vfio_pci_core_device *vdev, struct smptrace_ctx *ctx,
                                struct smptrace_map *map, u64 pos, u32 size, u8 *val,
                                bool iswrite)
{
	guard(rwsem_read)(&vdev->memory_lock);
	if (!smptrace_vfio_mem_usable(vdev))
		return -EIO;
	if (!ctx) {
		if (!iswrite)
			memset(val, 0xff, size);
	} else if (iswrite) {
		smptrace_emulate_write_may_sleep(ctx, map, pos, size, val, true);
	} else {
		smptrace_emulate_read_may_sleep(ctx, map, pos, size, val, true);
	}
	return 0;
}

/*
 * Runs in place of vfio_pci_bar_rw() for a transfer that reaches a traced
 * range, with its arguments, and returns to its caller. Splits the transfer
 * into naturally aligned accesses of up to 8 bytes and skips the MSI-X table
 * (reads of it return all-ones), as vfio_pci_core_do_io_rw() does. Accesses
 * outside every traced range go to the backing memory, unseen by the tracer.
 * The kprobe took a module reference for it.
 */
static ssize_t smptrace_vfio_bar_rw(struct vfio_pci_core_device *vdev, char __user *buf,
                                    size_t count, loff_t *ppos, bool iswrite)
{
	unsigned int bar = VFIO_PCI_OFFSET_TO_INDEX(*ppos);
	struct smptrace_map map = { .pa = pci_resource_start(vdev->pdev, bar) };
	u64 end = pci_resource_len(vdev->pdev, bar);
	u64 pos = *ppos & VFIO_PCI_OFFSET_MASK;
	u64 x_start = 0, x_end = 0;
	struct smptrace_ctx *ctx;
	ssize_t done = 0;
	int idx, ret = 0;

	if (pos >= end) {
		ret = -EINVAL;
		goto out_put;
	}
	count = min_t(u64, count, end - pos);
	if (bar == vdev->msix_bar) {
		x_start = vdev->msix_offset;
		x_end = vdev->msix_offset + vdev->msix_size;
	}

	idx = srcu_read_lock_nmisafe(&smptrace_active_srcu);
	ctx = smptrace_find_ctx(map.pa, end);
	while (count) {
		u64 fillable = pos < x_start ? min_t(u64, count, x_start - pos) :
		               pos >= x_end ? count : 0;
		u64 val = 0;
		u32 size;

		if (!fillable) {
			u8 ff = 0xff;

			size = min_t(u64, count, x_end - pos);
			for (u32 i = 0; !iswrite && i < size; i++) {
				if (copy_to_user(buf + i, &ff, 1)) {
					ret = -EFAULT;
					break;
				}
			}
		} else {
			size = fillable >= 8 && !(pos % 8) ? 8 :
			       fillable >= 4 && !(pos % 4) ? 4 :
			       fillable >= 2 && !(pos % 2) ? 2 : 1;
			if (iswrite && copy_from_user(&val, buf, size))
				ret = -EFAULT;
			else
				ret = smptrace_vfio_access(vdev, ctx, &map, pos, size, (u8 *)&val,
				                           iswrite);
			if (!ret && !iswrite && copy_to_user(buf, &val, size))
				ret = -EFAULT;
		}
		if (ret)
			break;

		count -= size;
		done += size;
		pos += size;
		buf += size;
	}
	srcu_read_unlock_nmisafe(&smptrace_active_srcu, idx);

	if (!ret)
		*ppos += done;
out_put:
	module_put(THIS_MODULE);
	return ret ? ret : done;
}
NOKPROBE_SYMBOL(smptrace_vfio_bar_rw);

static int smptrace_vfio_enter_bar_rw(struct kprobe *kp, struct pt_regs *regs)
{
	/* vfio_pci_bar_rw(vdev, buf, count, ppos, iswrite) */
	struct vfio_pci_core_device *vdev = (void *)regs_get_kernel_argument(regs, 0);
	size_t count = regs_get_kernel_argument(regs, 2);
	loff_t *ppos = (loff_t *)regs_get_kernel_argument(regs, 3);
	unsigned int bar = VFIO_PCI_OFFSET_TO_INDEX(*ppos);
	u64 pos = *ppos & VFIO_PCI_OFFSET_MASK;
	phys_addr_t start;
	u64 len;
	bool traced;

	if (bar >= PCI_STD_NUM_BARS || !pci_resource_start(vdev->pdev, bar))
		return 0;
	start = pci_resource_start(vdev->pdev, bar);
	len = pci_resource_len(vdev->pdev, bar);
	/* vfio-pci rejects a transfer that starts past the end */
	if (pos >= len || !count)
		return 0;

	/* Only a transfer that reaches a traced range goes to the tracer. One
	 * that misses them all takes vfio-pci's path, whose mapping of the BAR
	 * is not poisoned outside them. */
	scoped_guard(smptrace_active, &smptrace_active_srcu)
		traced = smptrace_pa_traced(start + pos, min_t(u64, count, len - pos));
	if (!traced || !try_module_get(THIS_MODULE))
		return 0;

	instruction_pointer_set(regs, (unsigned long)smptrace_vfio_bar_rw);
	return 1;
}

/* Deliberately empty: a kprobe with a post_handler is never optimized, and an
 * optimized one would drop the redirect (see smptrace_badarea_no_optimize()). */
static void smptrace_vfio_bar_rw_no_optimize(struct kprobe *kp, struct pt_regs *regs,
                                             unsigned long flags)
{
}

struct smptrace_vfio_mmap_args {
	struct vm_area_struct *vma;
};

static int smptrace_vfio_enter_mmap(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct smptrace_vfio_mmap_args *args = (void *)ri->data;

	/* vfio_pci_core_mmap(struct vfio_device *, struct vm_area_struct *) */
	args->vma = (struct vm_area_struct *)regs_get_kernel_argument(regs, 1);
	return 0;
}

static int smptrace_vfio_exit_mmap(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct smptrace_vfio_mmap_args *args = (void *)ri->data;
	struct vm_area_struct *vma = args->vma;
	bool traced;

	if (regs_return_value(regs) || vma_bar(vma) >= PCI_STD_NUM_BARS)
		return 0;

	/* The vma is not yet visible to other threads: mmap() inserts it only
	 * after the file's ->mmap returns. One that no traced range reaches
	 * keeps vfio-pci's own handler. */
	scoped_guard(smptrace_active, &smptrace_active_srcu)
		traced = smptrace_pa_traced(vma_phys(vma), vma->vm_end - vma->vm_start);
	if (!traced || !try_module_get(THIS_MODULE))
		return 0;

	vma->vm_ops = &smptrace_vfio_vm_ops;
	return 0;
}

static struct kretprobe smptrace_vfio_krp;
static struct kprobe smptrace_vfio_rw_kp;
static bool smptrace_vfio_mmap_registered, smptrace_vfio_rw_registered;
static DEFINE_MUTEX(smptrace_vfio_lock);

/* Caller holds smptrace_vfio_lock. Probing a symbol that is not loaded fails
 * with -ENOENT, which is expected until vfio-pci-core loads, so it is reported
 * only once @loaded says vfio-pci-core is in; the module notifier retries when
 * it loads. A probe that fails lets vfio-pci accesses to traced BARs bypass the
 * device model, so every other failure is reported. */
static void smptrace_vfio_register(bool loaded)
{
	int ret;

	/* Only architectures with a user-mode emulator trap user mappings. */
	if (IS_ENABLED(CONFIG_X86) && !smptrace_vfio_mmap_registered) {
		smptrace_vfio_krp = (struct kretprobe){
			.kp.symbol_name = "vfio_pci_core_mmap",
			.entry_handler  = smptrace_vfio_enter_mmap,
			.handler        = smptrace_vfio_exit_mmap,
			.data_size      = sizeof(struct smptrace_vfio_mmap_args),
			.maxactive      = 32,
		};
		ret = register_kretprobe(&smptrace_vfio_krp);
		if (!ret) {
			smptrace_vfio_mmap_registered = true;
			pr_info("trapping vfio-pci mmap()s of traced BARs\n");
		} else if (loaded || ret != -ENOENT) {
			pr_warn("cannot probe vfio_pci_core_mmap(): %d; vfio-pci mmap()s of traced BARs will bypass the device model\n",
			        ret);
		}
	}
	if (!smptrace_vfio_rw_registered) {
		smptrace_vfio_rw_kp = (struct kprobe){
			.symbol_name  = "vfio_pci_bar_rw",
			.pre_handler  = smptrace_vfio_enter_bar_rw,
			.post_handler = smptrace_vfio_bar_rw_no_optimize,
		};
		ret = register_kprobe(&smptrace_vfio_rw_kp);
		if (!ret) {
			smptrace_vfio_rw_registered = true;
			pr_info("routing vfio-pci read()/write() of traced BARs\n");
		} else if (loaded || ret != -ENOENT) {
			pr_warn("cannot probe vfio_pci_bar_rw(): %d; vfio-pci read()/write() of traced BARs will spin in the fault handler\n",
			        ret);
		}
	}
}

static void smptrace_vfio_unregister(void)
{
	if (smptrace_vfio_mmap_registered) {
		unregister_kretprobe(&smptrace_vfio_krp);
		smptrace_vfio_mmap_registered = false;
	}
	if (smptrace_vfio_rw_registered) {
		unregister_kprobe(&smptrace_vfio_rw_kp);
		smptrace_vfio_rw_registered = false;
	}
}

static int smptrace_vfio_module_notify(struct notifier_block *nb, unsigned long action,
                                       void *data)
{
	struct module *mod = data;

	if (strcmp(mod->name, "vfio_pci_core"))
		return NOTIFY_DONE;

	guard(mutex)(&smptrace_vfio_lock);
	if (action == MODULE_STATE_LIVE)
		smptrace_vfio_register(true);
	else if (action == MODULE_STATE_GOING)
		smptrace_vfio_unregister();
	return NOTIFY_OK;
}

static struct notifier_block smptrace_vfio_module_nb = {
	.notifier_call = smptrace_vfio_module_notify,
};

void smptrace_vfio_init(void)
{
	if (!IS_ENABLED(CONFIG_VFIO_PCI_CORE))
		return;

	register_module_notifier(&smptrace_vfio_module_nb);
	guard(mutex)(&smptrace_vfio_lock);
	smptrace_vfio_register(IS_BUILTIN(CONFIG_VFIO_PCI_CORE));
}

void smptrace_vfio_exit(void)
{
	if (!IS_ENABLED(CONFIG_VFIO_PCI_CORE))
		return;

	unregister_module_notifier(&smptrace_vfio_module_nb);
	guard(mutex)(&smptrace_vfio_lock);
	smptrace_vfio_unregister();
}
