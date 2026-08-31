// SPDX-License-Identifier: GPL-2.0-only
/*
 * pciem mmap trap — traps a guest's mmap() of a pyxis-class synthetic
 * BAR so every access round-trips through the daemon
 *
 * This file hooks in via a kretprobe on the exported vfio_pci_core_mmap() 
 * which sets vma->vm_private_data and vma->vm_ops right before it returns success.
 * Since mmap() never faults a page in, the return-handler below can safely swap 
 * vm_ops for a pciem-owned BAR with registered trap ranges before the guest
 * ever touches the mapping.
 *
 * Swapping vm_ops on a vma this code doesn't own isn't an official
 * API, and depends on vfio_pci_core_mmap() continuing to set both
 * fields before returning; it never touches any device pciem doesn't
 * own, since pciem_lookup_root_complex() gates it below.
 */

#include "pciem.h"
#include "userspace.h"

#include <linux/io.h>
#include <linux/kdebug.h>
#include <linux/kprobes.h>
#include <linux/list.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/notifier.h>
#include <linux/pci.h>
#include <linux/pgtable.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/vfio_pci_core.h>
#include <asm/debugreg.h>
#include <asm/processor-flags.h>
#include <asm/tlbflush.h>
#include <asm/ptrace.h>

/*
 * Clear the PTE for one page in a user vma so the next access
 * re-faults through vma->vm_ops->fault. Called synchronously from the
 * #DB notifier below — atomic context, must not sleep.
 *
 * v1 gaps: no mmap_lock held, and the flush is local-CPU only — a
 * second vCPU could still observe a stale entry.
 */
static void pciem_vma_revoke_page(struct vm_area_struct *vma, unsigned long addr)
{
    struct mm_struct *mm = vma->vm_mm;
    pmd_t *pmd;
    pte_t *ptep;

    addr &= PAGE_MASK;

    pmd = pmd_off(mm, addr);
    if (!pmd || pmd_none(*pmd) || pmd_bad(*pmd))
        return;

    ptep = pte_offset_kernel(pmd, addr);
    if (pte_present(*ptep)) {
        pte_clear(mm, addr, ptep);
        __flush_tlb_all();
    }
}

/*
 * #DB (single-step) hook — the trap's other half. 
 * Only one single-step is ever pending per task, so entries are
 * matched by `current` alone.
 */
struct pciem_pending_singlestep {
    struct list_head list;
    struct task_struct *task;
    struct vm_area_struct *vma;
    unsigned long addr;
    bool is_write;
    struct smptrace_ctx *ctx;
    void __iomem *kva;
    u64 bar_offset;
    u32 size;
};

static LIST_HEAD(pciem_pending_singlesteps);
static DEFINE_SPINLOCK(pciem_pending_singlestep_lock);

/*
 * Arm the follow-up trap: called right before setting TF, so the one
 * retired instruction produces exactly one more #DB, consumed below to
 * revoke the mapping (and, for a write, notify the daemon).
 */
static void pciem_arm_singlestep(struct vm_area_struct *vma, unsigned long addr,
                                 bool is_write, struct smptrace_ctx *ctx,
                                 void __iomem *kva, u64 bar_offset, u32 size)
{
    struct pciem_pending_singlestep *entry;
    unsigned long flags;

    entry = kzalloc(sizeof(*entry), GFP_ATOMIC);
    if (!entry) {
        pr_warn_ratelimited("pciem: OOM arming single-step at 0x%lx, will not re-trap\n",
                            addr);
        return;
    }

    entry->task       = current;
    entry->vma        = vma;
    entry->addr       = addr;
    entry->is_write   = is_write;
    entry->ctx        = ctx;
    entry->kva        = kva;
    entry->bar_offset = bar_offset;
    entry->size       = size;

    spin_lock_irqsave(&pciem_pending_singlestep_lock, flags);
    list_add(&entry->list, &pciem_pending_singlesteps);
    spin_unlock_irqrestore(&pciem_pending_singlestep_lock, flags);
}

static int pciem_mmap_trap_debug_notify(struct notifier_block *nb, unsigned long val, void *data)
{
    struct die_args *args = data;
    struct pciem_pending_singlestep *entry, *found = NULL;
    unsigned long *dr6_p;
    unsigned long flags;

    if (val != DIE_DEBUG)
        return NOTIFY_DONE;

    if (!user_mode(args->regs))
        return NOTIFY_DONE;

    dr6_p = (unsigned long *)args->err;
    if (!(*dr6_p & DR_STEP))
        return NOTIFY_DONE;

    spin_lock_irqsave(&pciem_pending_singlestep_lock, flags);
    list_for_each_entry(entry, &pciem_pending_singlesteps, list) {
        if (entry->task == current) {
            found = entry;
            list_del(&entry->list);
            break;
        }
    }
    spin_unlock_irqrestore(&pciem_pending_singlestep_lock, flags);

    if (!found)
        return NOTIFY_DONE;

    /* Remove single-step trap */
    *dr6_p &= ~DR_STEP;
    args->regs->flags &= ~X86_EFLAGS_TF;

    if (found->is_write && found->ctx) {
        struct smptrace_io io = {0};

        io.offset = found->bar_offset;
        io.size   = found->size;
        switch (found->size) {
        case 1: io.data.byte  = ioread8(found->kva);  break;
        case 2: io.data.word  = ioread16(found->kva); break;
        case 4: io.data.dword = ioread32(found->kva); break;
        case 8:
            io.data.qword = (u64)ioread32(found->kva) |
                            ((u64)ioread32(found->kva + 4) << 32);
            break;
        default:
            pr_warn_ratelimited("pciem: bad trapped write size %u at off 0x%llx\n",
                                found->size, (unsigned long long)found->bar_offset);
            goto done;
        }
        pciem_notif_write(found->ctx, &io);
    }

done:
    /* Synchronous: pciem_vma_revoke_page() only uses non-sleeping
     * primitives, so it's safe to call inline here */
    pciem_vma_revoke_page(found->vma, found->addr);
    kfree(found);
    return NOTIFY_STOP;
}

static struct notifier_block pciem_mmap_trap_debug_nb = {
    .notifier_call = pciem_mmap_trap_debug_notify,
};

/*
 * Installed by the kretprobe below in place of vfio-pci's own vm_ops, 
 * for BARs with registered trap ranges. For untrapped offsets, 
 * pciem_mmap_trap_fault() reimplements vfio_pci_mmap_huge_fault()'s 
 * order-0 mapping inline.
 */
static vm_fault_t pciem_mmap_trap_huge_fault(struct vm_fault *vmf, unsigned int order)
{
    /* Trap ranges are sub-page; always fall back to order-0. */
    return VM_FAULT_FALLBACK;
}

static vm_fault_t pciem_mmap_trap_fault(struct vm_fault *vmf)
{
    struct vm_area_struct *vma = vmf->vma;
    struct vfio_pci_core_device *vdev = vma->vm_private_data;
    struct pciem_root_complex *v = NULL;
    struct pciem_bar_info *bar = NULL;
    struct smptrace_ctx *ctx = NULL;
    bool is_write = (vmf->flags & FAULT_FLAG_WRITE) != 0;
    unsigned int bar_index, func, i;
    u64 bar_offset = 0;
    u32 range_len = 0;
    bool trapped = false;
    unsigned long pgoff, pfn;
    void __iomem *kva = NULL;

    bar_index = vma->vm_pgoff >> (VFIO_PCI_OFFSET_SHIFT - PAGE_SHIFT);
    pgoff = (vmf->address - vma->vm_start) >> PAGE_SHIFT;

    if (bar_index < PCI_STD_NUM_BARS) {
        /* use real_address for the exact byte offset when checking trap ranges */
        bar_offset = ((u64)vma->vm_pgoff << PAGE_SHIFT) +
                    (vmf->real_address - vma->vm_start);
        bar_offset &= (1ULL << VFIO_PCI_OFFSET_SHIFT) - 1;

        v = pciem_lookup_root_complex(vdev->pdev);
        if (v) {
            read_lock(&v->bars_lock);
            bar = &v->bars[bar_index];
            for (i = 0; i < bar->num_mmap_trap_ranges; i++) {
                u64 start = bar->mmap_trap_ranges[i].offset;
                u64 len   = bar->mmap_trap_ranges[i].len;

                if (bar_offset >= start && bar_offset < start + len) {
                    trapped = true;
                    /* width, not len: len is the whole range's span,
                     * which can cover many registers — width is the
                     * declared per-access size to actually use. */
                    range_len = (u32)bar->mmap_trap_ranges[i].width;
                    break;
                }
            }
            read_unlock(&v->bars_lock);
        }

        if (trapped) {
            func = PCI_FUNC(vdev->pdev->devfn);
            ctx = pciem_get_tracer_ctx(v->owner_us, func, bar_index);

            if (!ctx || !ctx->shadow_va) {
                /* Trap range registered but tracing never enabled on
                 * this BAR */
                return VM_FAULT_SIGBUS;
            }

            /* Reuse the BAR's existing ioremap() as the backing
             * kernel VA */
            kva = ctx->shadow_va + bar_offset;

            if (is_write) {
                /* Value arrives via the real store; the daemon is
                 * notified from the #DB handler once we know what was
                 * actually written. */
            } else {
                struct smptrace_io io = {0};

                io.offset = bar_offset;
                io.size   = range_len;
                if (pciem_notif_read_sync(ctx, &io)) {
                    /* Daemon didn't answer — fault */
                    return VM_FAULT_SIGBUS;
                }
                switch (io.size) {
                case 1: iowrite8(io.data.byte, kva);   break;
                case 2: iowrite16(io.data.word, kva);  break;
                case 4: iowrite32(io.data.dword, kva); break;
                case 8:
                    iowrite32((u32)io.data.qword, kva);
                    iowrite32((u32)(io.data.qword >> 32), kva + 4);
                    break;
                default: return VM_FAULT_SIGBUS;
                }
            }
        }
    } else {
        trapped = false;
    }

    pfn = (pci_resource_start(vdev->pdev, bar_index) >> PAGE_SHIFT) + pgoff;

    {
        vm_fault_t ret = vmf_insert_pfn(vma, vmf->address, pfn);

        if (ret != VM_FAULT_NOPAGE)
            return ret;
    }

    /*
     * Always re-arm, even when this byte isn't in any registered trap
     * range: this vm_ops is only installed on a BAR that has at least
     * one trapped range. 
     */
    {
        struct pt_regs *regs = task_pt_regs(current);

        pciem_arm_singlestep(vma, vmf->address, is_write, ctx, kva,
                             bar_offset, range_len);
        regs->flags |= X86_EFLAGS_TF;
    }

    return VM_FAULT_NOPAGE;
}

static const struct vm_operations_struct pciem_mmap_trap_vm_ops = {
    .fault      = pciem_mmap_trap_fault,
    .huge_fault = pciem_mmap_trap_huge_fault,
};

/*
 * kretprobe on vfio_pci_core_mmap(): the trigger for the vm_ops swap
 * above. The entry handler stashes the vma argument for the return handler, 
 * which only proceeds if the real call succeeded, then applies the same ownership
 * + trap-range check as the fault handler before swapping vm_ops.
 */
struct pciem_mmap_probe_data {
    struct vm_area_struct *vma;
};

static int pciem_mmap_probe_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct pciem_mmap_probe_data *data = (struct pciem_mmap_probe_data *)ri->data;

    /* vfio_pci_core_mmap(core_vdev, vma) — arg2 is in rsi. */
    data->vma = (struct vm_area_struct *)regs->si;
    return 0;
}

static int pciem_mmap_probe_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct pciem_mmap_probe_data *data = (struct pciem_mmap_probe_data *)ri->data;
    struct vm_area_struct *vma = data->vma;
    struct vfio_pci_core_device *vdev;
    struct pciem_root_complex *v;
    unsigned int bar_index;
    bool has_traps;

    if (regs_return_value(regs) != 0)
        return 0; /* vfio_pci_core_mmap() itself failed — nothing to do */

    bar_index = vma->vm_pgoff >> (VFIO_PCI_OFFSET_SHIFT - PAGE_SHIFT);
    if (bar_index >= PCI_STD_NUM_BARS)
        return 0; /* ROM/region mmap — never trap-eligible */

    vdev = vma->vm_private_data;
    v = pciem_lookup_root_complex(vdev->pdev);
    if (!v)
        return 0; /* not a pciem-owned device — leave it alone */

    read_lock(&v->bars_lock);
    has_traps = v->bars[bar_index].num_mmap_trap_ranges > 0;
    read_unlock(&v->bars_lock);

    if (has_traps)
        vma->vm_ops = &pciem_mmap_trap_vm_ops;

    return 0;
}

static struct kretprobe pciem_mmap_kretprobe = {
    .kp.symbol_name = "vfio_pci_core_mmap",
    .entry_handler  = pciem_mmap_probe_entry,
    .handler        = pciem_mmap_probe_ret,
    .data_size      = sizeof(struct pciem_mmap_probe_data),
};

int pciem_mmap_trap_init(void)
{
    int ret;

    register_die_notifier(&pciem_mmap_trap_debug_nb);

    ret = register_kretprobe(&pciem_mmap_kretprobe);
    if (ret) {
        unregister_die_notifier(&pciem_mmap_trap_debug_nb);
        return ret;
    }

    return 0;
}

void pciem_mmap_trap_cleanup(void)
{
    unregister_kretprobe(&pciem_mmap_kretprobe);
    unregister_die_notifier(&pciem_mmap_trap_debug_nb);
}
