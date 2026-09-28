// SPDX-License-Identifier: GPL-2.0-only
/*
 * MSI parent irq domain for virtual-root devices.
 *
 * A synthetic device never writes an MSI message: pciem raises its
 * interrupts itself, by vector, from pciem_trigger_msi(). So the domain only
 * has to hand out Linux irqs for the PCI core's per-device MSI and MSI-X
 * domains and remember which irq backs which vector. It is the root of that
 * hierarchy, with no parent, so it does not depend on what the platform
 * provides: with no interrupt remapping the x86 vector domain allows one MSI
 * vector, and it only accepts interrupts in hard interrupt context.
 *
 * Masking stays the PCI core's: the per-device domains write the MSI mask
 * bits and the MSI-X vector control words, which the device model sees, and
 * the irq core holds an interrupt raised while its vector is masked or
 * disabled and replays it when the vector is unmasked.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": msi: " fmt

#include "pciem.h"
#include "msi_domain.h"

#include <linux/interrupt.h>
#include <linux/irq.h>
#include <linux/irqdomain.h>
#include <linux/msi.h>
#include <linux/xarray.h>

/*
 * The message pciem composes for each vector. Nothing is ever written to
 * this address; the data is the Linux irq number, so a device model that
 * reads its MSI-X table can tell the vectors apart.
 */
#define PCIEM_MSI_ADDRESS 0xfeed0000u

static struct irq_domain *pciem_msi_parent;

struct irq_domain *pciem_msi_domain(void)
{
    return pciem_msi_parent;
}

static void pciem_msi_noop(struct irq_data *d) {}

static void pciem_msi_compose_msg(struct irq_data *d, struct msi_msg *msg)
{
    msg->address_hi = 0;
    msg->address_lo = PCIEM_MSI_ADDRESS;
    msg->data = d->hwirq;
}

/* pciem delivers on whichever CPU raises the interrupt; there is nothing to steer. */
static int pciem_msi_set_affinity(struct irq_data *d, const struct cpumask *mask, bool force)
{
    irq_data_update_effective_affinity(d, mask);
    return IRQ_SET_MASK_OK_DONE;
}

static struct irq_chip pciem_msi_parent_chip = {
    .name                = "pciem-MSI",
    .irq_ack             = pciem_msi_noop,
    .irq_mask            = pciem_msi_noop,
    .irq_unmask          = pciem_msi_noop,
    .irq_compose_msi_msg = pciem_msi_compose_msg,
    .irq_set_affinity    = pciem_msi_set_affinity,
};

static int pciem_msi_domain_alloc(struct irq_domain *d, unsigned int virq,
                                  unsigned int nr_irqs, void *arg)
{
    msi_alloc_info_t *info = arg;
    struct pciem_root_complex *v;
    unsigned int i;
    int ret;

    if (!info->desc || !dev_is_pci(info->desc->dev))
        return -EINVAL;

    v = pciem_rc_from_pdev(to_pci_dev(info->desc->dev));
    if (!v)
        return -ENODEV;

    /*
     * The per-device domain passes the vector (MSI-X entry, or the first
     * MSI vector of a multi-vector block) as the hwirq. The parent's hwirq
     * only has to be unique within it, so it is the Linux irq number.
     */
    guard(mutex)(&v->msi_lock);
    for (i = 0; i < nr_irqs; i++) {
        ret = xa_err(xa_store(&v->msi_virqs, info->hwirq + i,
                              xa_mk_value(virq + i), GFP_KERNEL));
        if (ret) {
            while (i--) {
                xa_erase(&v->msi_virqs, info->hwirq + i);
                irq_domain_reset_irq_data(irq_domain_get_irq_data(d, virq + i));
            }
            return ret;
        }
        irq_domain_set_hwirq_and_chip(d, virq + i, virq + i, &pciem_msi_parent_chip, v);
    }

    return 0;
}

static void pciem_msi_domain_free(struct irq_domain *d, unsigned int virq,
                                  unsigned int nr_irqs)
{
    unsigned int i;

    for (i = 0; i < nr_irqs; i++) {
        struct irq_data *data = irq_domain_get_irq_data(d, virq + i);
        struct pciem_root_complex *v = data ? irq_data_get_irq_chip_data(data) : NULL;

        if (v) {
            unsigned long vector;
            void *entry;

            guard(mutex)(&v->msi_lock);
            xa_for_each(&v->msi_virqs, vector, entry) {
                if (xa_to_value(entry) == virq + i) {
                    xa_erase(&v->msi_virqs, vector);
                    break;
                }
            }
        }
        if (data)
            irq_domain_reset_irq_data(data);
    }
}

static const struct irq_domain_ops pciem_msi_domain_ops = {
    .alloc = pciem_msi_domain_alloc,
    .free  = pciem_msi_domain_free,
};

#define PCIEM_MSI_FLAGS_SUPPORTED (MSI_GENERIC_FLAGS_MASK | MSI_FLAG_MULTI_PCI_MSI | \
                                   MSI_FLAG_PCI_MSIX | MSI_FLAG_PCI_MSIX_ALLOC_DYN)

static bool pciem_msi_init_dev_msi_info(struct device *dev, struct irq_domain *domain,
                                        struct irq_domain *real_parent,
                                        struct msi_domain_info *info)
{
    if (WARN_ON_ONCE(domain != real_parent))
        return false;

    switch (info->bus_token) {
    case DOMAIN_BUS_PCI_DEVICE_MSI:
    case DOMAIN_BUS_PCI_DEVICE_MSIX:
        break;
    default:
        WARN_ON_ONCE(1);
        return false;
    }

    info->flags &= PCIEM_MSI_FLAGS_SUPPORTED;
    /* The per-device templates rely on the core's default domain and chip ops. */
    info->flags |= MSI_FLAG_USE_DEF_DOM_OPS | MSI_FLAG_USE_DEF_CHIP_OPS;

    /* handle_edge_irq() acks every interrupt; the parent's ack does nothing. */
    info->chip->irq_ack = irq_chip_ack_parent;
    info->chip->irq_set_affinity = irq_chip_set_affinity_parent;
    info->chip->flags |= IRQCHIP_SKIP_SET_WAKE;
    info->handler = handle_edge_irq;
    info->handler_name = "edge";

    return true;
}

static const struct msi_parent_ops pciem_msi_parent_ops = {
    .supported_flags   = PCIEM_MSI_FLAGS_SUPPORTED,
    .prefix            = "pciem-",
    .init_dev_msi_info = pciem_msi_init_dev_msi_info,
};

int pciem_msi_domain_init(void)
{
    struct fwnode_handle *fwnode;
    struct irq_domain *d;

    fwnode = irq_domain_alloc_named_fwnode("pciem-MSI");
    if (!fwnode)
        return -ENOMEM;

    /*
     * A tree domain: its hwirqs are Linux irq numbers.
     *
     * Isolated: a device can only raise the vectors allocated to it, since
     * pciem raises them by vector for the device and nothing turns a DMA
     * write into an interrupt (PCIEM_IOCTL_DMA is a CPU copy through the
     * stub IOMMU's mappings). vfio type1 then needs no
     * allow_unsafe_interrupts for these devices.
     */
    d = irq_domain_create_hierarchy(NULL, IRQ_DOMAIN_FLAG_MSI_PARENT | IRQ_DOMAIN_FLAG_ISOLATED_MSI,
                                    0, fwnode, &pciem_msi_domain_ops, NULL);
    if (!d) {
        irq_domain_free_fwnode(fwnode);
        return -ENOMEM;
    }
    irq_domain_update_bus_token(d, DOMAIN_BUS_NEXUS);
    d->msi_parent_ops = &pciem_msi_parent_ops;
    pciem_msi_parent = d;

    return 0;
}

void pciem_msi_domain_exit(void)
{
    struct fwnode_handle *fwnode;

    if (!pciem_msi_parent)
        return;

    fwnode = pciem_msi_parent->fwnode;
    irq_domain_remove(pciem_msi_parent);
    irq_domain_free_fwnode(fwnode);
    pciem_msi_parent = NULL;
}

void pciem_msi_rc_init(struct pciem_root_complex *v)
{
    mutex_init(&v->msi_lock);
    xa_init(&v->msi_virqs);
}

void pciem_msi_rc_destroy(struct pciem_root_complex *v)
{
    WARN_ON(!xa_empty(&v->msi_virqs));
    xa_destroy(&v->msi_virqs);
}

/*
 * Raises MSI or MSI-X vector @vector of @v's device, falling back to vector 0
 * for a vector that has no irq, and returns -ENOENT if the device has no
 * vectors in this domain (MSI and MSI-X disabled, or not a virtual-root
 * device). Process context.
 *
 * The handler runs here, with interrupts disabled, rather than from an
 * irq_work: one irq_work per device can hold only one pending vector, so
 * vectors raised together from several CPUs overwrote each other. msi_lock
 * keeps the vector's irq from being freed, and its number reused, before the
 * handler has run.
 */
int pciem_msi_deliver(struct pciem_root_complex *v, int vector)
{
    void *entry = NULL;

    might_sleep();

    guard(mutex)(&v->msi_lock);

    if (xa_empty(&v->msi_virqs))
        return -ENOENT;

    if (vector >= 0)
        entry = xa_load(&v->msi_virqs, vector);
    if (!entry) {
        pr_warn_ratelimited("%s: vector %d has no interrupt, raising vector 0\n",
                            v->pciem_pdev ? pci_name(v->pciem_pdev) : "?", vector);
        entry = xa_load(&v->msi_virqs, 0);
        if (!entry)
            return -EINVAL;
    }

    return generic_handle_irq_safe(xa_to_value(entry));
}
