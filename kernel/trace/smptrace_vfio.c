/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Traps userspace accesses through a vfio-pci mmap() of a traced BAR.
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
 */
#define pr_fmt(fmt) KBUILD_MODNAME ": vfio: " fmt

#include <linux/kprobes.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/pci.h>
#include <linux/sched/task_stack.h>
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
	u16 cmd;
	int err;

	/* Only a user-mode load or store has an instruction to emulate. A
	 * kernel access (uaccess) gets -EFAULT, an instruction fetch SIGBUS. */
	if (!(vmf->flags & FAULT_FLAG_USER) || (vmf->flags & FAULT_FLAG_INSTRUCTION))
		return VM_FAULT_SIGBUS;

	/* The rules of vfio-pci's own fault handler: no access while device
	 * memory is disabled or the device is runtime-suspended, and none
	 * concurrent with a reset, which holds memory_lock for write. */
	down_read(&vdev->memory_lock);
	if (vdev->pm_runtime_engaged)
		goto out;
	if (pci_read_config_word(vdev->pdev, PCI_COMMAND, &cmd) ||
	    !(cmd & PCI_COMMAND_MEMORY))
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
static bool smptrace_vfio_registered;
static DEFINE_MUTEX(smptrace_vfio_lock);

/* Caller holds smptrace_vfio_lock. Fails quietly while vfio-pci-core is not
 * loaded; the module notifier retries when it is. */
static void smptrace_vfio_register(void)
{
	if (smptrace_vfio_registered)
		return;

	smptrace_vfio_krp = (struct kretprobe){
		.kp.symbol_name = "vfio_pci_core_mmap",
		.entry_handler  = smptrace_vfio_enter_mmap,
		.handler        = smptrace_vfio_exit_mmap,
		.data_size      = sizeof(struct smptrace_vfio_mmap_args),
		.maxactive      = 32,
	};
	if (!register_kretprobe(&smptrace_vfio_krp)) {
		smptrace_vfio_registered = true;
		pr_info("trapping vfio-pci mmap()s of traced BARs\n");
	}
}

static void smptrace_vfio_unregister(void)
{
	if (!smptrace_vfio_registered)
		return;
	unregister_kretprobe(&smptrace_vfio_krp);
	smptrace_vfio_registered = false;
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
	/* Only architectures with a user-mode emulator trap user mappings. */
	if (!IS_ENABLED(CONFIG_X86) || !IS_ENABLED(CONFIG_VFIO_PCI_CORE))
		return 0;

	register_module_notifier(&smptrace_vfio_module_nb);
	guard(mutex)(&smptrace_vfio_lock);
	smptrace_vfio_register();
	return 0;
}

void smptrace_vfio_exit(void)
{
	if (!IS_ENABLED(CONFIG_X86) || !IS_ENABLED(CONFIG_VFIO_PCI_CORE))
		return;

	unregister_module_notifier(&smptrace_vfio_module_nb);
	guard(mutex)(&smptrace_vfio_lock);
	smptrace_vfio_unregister();
}
