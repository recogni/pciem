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
 * vfio_pci_core_mmap() replaces that handler, for traced BARs, with one that
 * never maps the page: each access faults, and the handler emulates the one
 * instruction against the tracer and steps past it. No access can bypass the
 * device model, from any thread, because no PTE ever exists.
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

/* vfio-pci's rule for touching device memory. Caller holds memory_lock. */
static bool smptrace_vfio_mem_usable(struct vfio_pci_core_device *vdev)
{
	u16 cmd;

	return !vdev->pm_runtime_engaged &&
	       !pci_read_config_word(vdev->pdev, PCI_COMMAND, &cmd) &&
	       (cmd & PCI_COMMAND_MEMORY);
}

static void smptrace_vfio_vma_open(struct vm_area_struct *vma)
{
	__module_get(THIS_MODULE);
}

static void smptrace_vfio_vma_close(struct vm_area_struct *vma)
{
	module_put(THIS_MODULE);
}

static vm_fault_t smptrace_vfio_fault(struct vm_fault *vmf)
{
	struct vm_area_struct *vma = vmf->vma;
	struct vfio_pci_core_device *vdev = vma->vm_private_data;
	phys_addr_t pa = vma_phys(vma);
	vm_fault_t ret = VM_FAULT_SIGBUS;
	int err;

	/* Only a user-mode load or store has an instruction to emulate. A
	 * kernel access (uaccess) gets -EFAULT, an instruction fetch SIGBUS. */
	if (!(vmf->flags & FAULT_FLAG_USER) || (vmf->flags & FAULT_FLAG_INSTRUCTION))
		return VM_FAULT_SIGBUS;

	/* The rules of vfio-pci's own fault handler: no access while device
	 * memory is disabled or the device is runtime-suspended, and none
	 * concurrent with a reset, which holds memory_lock for write. */
	down_read(&vdev->memory_lock);
	if (!smptrace_vfio_mem_usable(vdev))
		goto out;

	err = smptrace_arch_user_fault(task_pt_regs(current), vmf->real_address,
	                               vma->vm_start, vma->vm_end, pa);
	if (!err || err == -EAGAIN)
		ret = VM_FAULT_NOPAGE;
	else if (err == -ENOENT)
		/* No longer traced (the device model is gone): behave as
		 * vfio-pci would and map the page. */
		ret = vmf_insert_pfn(vma, vmf->address,
		                     PHYS_PFN(pa) + ((vmf->address - vma->vm_start) >> PAGE_SHIFT));
out:
	up_read(&vdev->memory_lock);
	return ret;
}

static const struct vm_operations_struct smptrace_vfio_vm_ops = {
	.open  = smptrace_vfio_vma_open,
	.close = smptrace_vfio_vma_close,
	.fault = smptrace_vfio_fault,
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
 * Runs in place of vfio_pci_bar_rw() for a traced BAR, with its arguments, and
 * returns to its caller. Splits the transfer into naturally aligned accesses
 * of up to 8 bytes and skips the MSI-X table (reads of it return all-ones), as
 * vfio_pci_core_do_io_rw() does. The kprobe took a module reference for it.
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

	idx = srcu_read_lock(&smptrace_active_srcu);
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
	srcu_read_unlock(&smptrace_active_srcu, idx);

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
	loff_t *ppos = (loff_t *)regs_get_kernel_argument(regs, 3);
	unsigned int bar = VFIO_PCI_OFFSET_TO_INDEX(*ppos);
	bool traced;

	if (bar >= PCI_STD_NUM_BARS || !pci_resource_start(vdev->pdev, bar))
		return 0;
	scoped_guard(srcu, &smptrace_active_srcu)
		traced = smptrace_find_ctx(pci_resource_start(vdev->pdev, bar),
		                           pci_resource_len(vdev->pdev, bar));
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
	 * after the file's ->mmap returns. */
	scoped_guard(srcu, &smptrace_active_srcu)
		traced = smptrace_find_ctx(vma_phys(vma), vma->vm_end - vma->vm_start);
	if (!traced || !try_module_get(THIS_MODULE))
		return 0;

	vma->vm_ops = &smptrace_vfio_vm_ops;
	return 0;
}

static struct kretprobe smptrace_vfio_krp;
static struct kprobe smptrace_vfio_rw_kp;
static bool smptrace_vfio_mmap_registered, smptrace_vfio_rw_registered;
static DEFINE_MUTEX(smptrace_vfio_lock);

/* Caller holds smptrace_vfio_lock. Fails quietly while vfio-pci-core is not
 * loaded; the module notifier retries when it is. */
static void smptrace_vfio_register(void)
{
	/* Only architectures with a user-mode emulator trap user mappings. */
	if (IS_ENABLED(CONFIG_X86) && !smptrace_vfio_mmap_registered) {
		smptrace_vfio_krp = (struct kretprobe){
			.kp.symbol_name = "vfio_pci_core_mmap",
			.entry_handler  = smptrace_vfio_enter_mmap,
			.handler        = smptrace_vfio_exit_mmap,
			.data_size      = sizeof(struct smptrace_vfio_mmap_args),
			.maxactive      = 32,
		};
		if (!register_kretprobe(&smptrace_vfio_krp)) {
			smptrace_vfio_mmap_registered = true;
			pr_info("trapping vfio-pci mmap()s of traced BARs\n");
		}
	}
	if (!smptrace_vfio_rw_registered) {
		smptrace_vfio_rw_kp = (struct kprobe){
			.symbol_name  = "vfio_pci_bar_rw",
			.pre_handler  = smptrace_vfio_enter_bar_rw,
			.post_handler = smptrace_vfio_bar_rw_no_optimize,
		};
		if (!register_kprobe(&smptrace_vfio_rw_kp)) {
			smptrace_vfio_rw_registered = true;
			pr_info("routing vfio-pci read()/write() of traced BARs\n");
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
		smptrace_vfio_register();
	else if (action == MODULE_STATE_GOING)
		smptrace_vfio_unregister();
	return NOTIFY_OK;
}

static struct notifier_block smptrace_vfio_module_nb = {
	.notifier_call = smptrace_vfio_module_notify,
};

int smptrace_vfio_init(void)
{
	if (!IS_ENABLED(CONFIG_VFIO_PCI_CORE))
		return 0;

	register_module_notifier(&smptrace_vfio_module_nb);
	guard(mutex)(&smptrace_vfio_lock);
	smptrace_vfio_register();
	return 0;
}

void smptrace_vfio_exit(void)
{
	if (!IS_ENABLED(CONFIG_VFIO_PCI_CORE))
		return;

	unregister_module_notifier(&smptrace_vfio_module_nb);
	guard(mutex)(&smptrace_vfio_lock);
	smptrace_vfio_unregister();
}
