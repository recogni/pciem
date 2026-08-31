// SPDX-License-Identifier: GPL-2.0-only
/*
 * pciem stub IOMMU — register a placeholder IOMMU instance so that
 * synthetic PCIe devices created on a pciem virtual-root bus can be
 * bound to vfio-pci through the standard iommu/iommu_group machinery
 * without resorting to vfio.enable_unsafe_noiommu_mode (which taints
 * the kernel and is gated as "unsafe").
 *
 * The stub honours the iommu_ops contract just enough for the kernel's
 * iommu core to:
 *   1. Allocate a per-device iommu_group (via ->device_group)
 *   2. Build a default paging domain for the group
 *   3. Let vfio_register_iommu_group claim DMA ownership cleanly
 *
 * ->iova_to_phys performs a real lookup against a per-page {iova -> paddr}
 * table filled in by ->map_pages / erased by ->unmap_pages. Tracked per-page 
 * rather than per-call because the iommu core is free to split one logical 
 * map/unmap into several calls.
 *
 * Hookup model — the upstream-clean way:
 *
 * The iommu core registers a notifier on pci_bus_type at subsys_initcall
 * with default priority (0); on BUS_NOTIFY_ADD_DEVICE it calls
 * iommu_probe_device(dev), which walks dev->iommu->fwspec to find the
 * matching iommu controller. For pciem virtual-root devices we have no
 * firmware-described fwnode chain (no DMAR, no IORT, no OF), so this
 * default path can't reach our stub.
 *
 * Rather than calling iommu_probe_device() ourselves after the device
 * is added (which requires EXPORT_SYMBOL_GPL on a non-exported symbol),
 * we register our own pci_bus_type notifier with priority = 1 — higher
 * than the iommu core's. The notifier chain is sorted by priority
 * descending (kernel/notifier.c::notifier_chain_register), so for any
 * device added on a pciem-owned bus our notifier runs first and installs
 * iommu_fwspec; the iommu core's notifier then runs immediately after
 * on the same BUS_NOTIFY_ADD_DEVICE event, sees the fwspec, and probes
 * us through the standard path. No EXPORT_SYMBOL changes required, no
 * manual reprobe, no kernel patches.
 *
 * Identifying "a pciem-owned bus": pci_bus->bridge is the &dev of the
 * pci_host_bridge. pciem registers each bridge it allocates here at
 * pci_alloc_host_bridge() time, before pci_scan_root_bus_bridge runs
 * the scan that fires BUS_NOTIFY_ADD_DEVICE on each new pci_dev. The
 * notifier walks pdev->bus->bridge and looks it up in this list. We do
 * NOT use container_of(bus->sysdata, ...) because that's only safe on
 * pciem's own buses and would crash on real PCI buses that get the same
 * notification. Real PCI devices on real buses pass the lookup, find no
 * match, and we return NOTIFY_DONE — leaving them entirely to the
 * platform IOMMU.
 */

#include <linux/iommu.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/notifier.h>
#include <linux/pci.h>
#include <linux/printk.h>
#include <linux/property.h>
#include <linux/sizes.h>
#include <linux/slab.h>
#include <linux/xarray.h>
#include <linux/module.h>

#include "iommu_stub.h"

static struct iommu_device pciem_stub_iommu;

#define PCIEM_STUB_PAGE_SIZE   SZ_4K

struct pciem_stub_domain {
    struct iommu_domain domain;
    struct xarray        pfns;   /* index = iova / PCIEM_STUB_PAGE_SIZE, value = paddr / PCIEM_STUB_PAGE_SIZE */
};

static struct pciem_stub_domain *to_stub_domain(struct iommu_domain *domain)
{
    return container_of(domain, struct pciem_stub_domain, domain);
}

/* Synthetic fwnode used as the "iommu controller" identity. The real
 * PCIe devices in the system never reference this fwnode, so there's
 * no collision with intel-iommu / amd-iommu / smmu / etc.            */
static const struct software_node pciem_stub_iommu_swnode = {
    .name = "pciem-iommu-stub",
};

/* ---------------------------------------------------------------- */
/* domain ops — real iova->phys bookkeeping                         */
/* ---------------------------------------------------------------- */

static int pciem_stub_attach_dev(struct iommu_domain *domain, struct device *dev)
{
    return 0;
}

static int pciem_stub_map_pages(struct iommu_domain *domain, unsigned long iova,
                                phys_addr_t paddr, size_t pgsize, size_t pgcount,
                                int prot, gfp_t gfp, size_t *mapped)
{
    struct pciem_stub_domain *sd = to_stub_domain(domain);
    unsigned long start_iova = iova;
    size_t cur;

    for (cur = 0; cur < pgsize * pgcount; cur += PCIEM_STUB_PAGE_SIZE) {
        void *old;

        old = xa_store(&sd->pfns, (iova + cur) / PCIEM_STUB_PAGE_SIZE,
                       xa_mk_value((paddr + cur) / PCIEM_STUB_PAGE_SIZE), gfp);
        if (xa_is_err(old)) {
            /* unwind whatever this call already stored */
            for (; start_iova != iova + cur; start_iova += PCIEM_STUB_PAGE_SIZE)
                xa_erase(&sd->pfns, start_iova / PCIEM_STUB_PAGE_SIZE);
            *mapped = 0;
            return xa_err(old);
        }
        WARN_ON(old);
    }

    *mapped = pgsize * pgcount;
    return 0;
}

static size_t pciem_stub_unmap_pages(struct iommu_domain *domain, unsigned long iova,
                                     size_t pgsize, size_t pgcount,
                                     struct iommu_iotlb_gather *gather)
{
    struct pciem_stub_domain *sd = to_stub_domain(domain);
    size_t size = pgsize * pgcount;
    size_t cur;

    for (cur = 0; cur < size; cur += PCIEM_STUB_PAGE_SIZE) {
        void *ent = xa_erase(&sd->pfns, (iova + cur) / PCIEM_STUB_PAGE_SIZE);

        if (!ent)
            pr_warn_ratelimited("unmap of untracked iova=0x%lx\n",
                                (unsigned long)(iova + cur));
    }

    return size;
}

static phys_addr_t pciem_stub_iova_to_phys(struct iommu_domain *domain, dma_addr_t iova)
{
    struct pciem_stub_domain *sd = to_stub_domain(domain);
    void *ent = xa_load(&sd->pfns, iova / PCIEM_STUB_PAGE_SIZE);

    if (!ent)
        return 0;

    return (xa_to_value(ent) * PCIEM_STUB_PAGE_SIZE) + (iova % PCIEM_STUB_PAGE_SIZE);
}

static void pciem_stub_iotlb_sync(struct iommu_domain *domain,
                                  struct iommu_iotlb_gather *gather)
{
    /* no hardware IOTLB to sync */
}

static void pciem_stub_flush_iotlb_all(struct iommu_domain *domain)
{
    /* no hardware IOTLB to flush */
}

static void pciem_stub_domain_free(struct iommu_domain *domain)
{
    struct pciem_stub_domain *sd = to_stub_domain(domain);

    xa_destroy(&sd->pfns);
    kfree(sd);
}

static const struct iommu_domain_ops pciem_stub_domain_ops = {
    .attach_dev      = pciem_stub_attach_dev,
    .map_pages       = pciem_stub_map_pages,
    .unmap_pages     = pciem_stub_unmap_pages,
    .iova_to_phys    = pciem_stub_iova_to_phys,
    .iotlb_sync      = pciem_stub_iotlb_sync,
    .flush_iotlb_all = pciem_stub_flush_iotlb_all,
    .free            = pciem_stub_domain_free,
};

/* Static "blocked" domain ops — modern iommu drivers expose a
 * single-instance ops->blocked_domain so the core never allocates one
 * via domain_alloc_paging. attach is a no-op (we don't actually
 * translate; for synthetic devices "blocked" and "anything" look the
 * same). free is NULL because the core never tries to free statics. */
static int pciem_stub_blocked_attach(struct iommu_domain *domain, struct device *dev)
{
    return 0;
}

static const struct iommu_domain_ops pciem_stub_blocked_ops = {
    .attach_dev = pciem_stub_blocked_attach,
};

static struct iommu_domain pciem_stub_blocked_domain = {
    .type = IOMMU_DOMAIN_BLOCKED,
    .ops  = &pciem_stub_blocked_ops,
};

/* ---------------------------------------------------------------- */
/* iommu_ops — per-device probe + per-device group + paging alloc   */
/* ---------------------------------------------------------------- */

static bool pciem_stub_capable(struct device *dev, enum iommu_cap cap)
{
    /* vfio_register_group_dev() refuses to bind a device whose IOMMU
     * doesn't advertise IOMMU_CAP_CACHE_COHERENCY (vfio_main.c:
     * "VFIO always sets IOMMU_CACHE..."). For our pass-through stub on
     * synthetic devices, cache coherency is trivially "true" — there is
     * no DMA to incoherent memory because there is no real DMA at all.
     */
    switch (cap) {
    case IOMMU_CAP_CACHE_COHERENCY:
    case IOMMU_CAP_DEFERRED_FLUSH:
        return true;
    default:
        return false;
    }
}

static struct iommu_device *pciem_stub_probe_device(struct device *dev)
{
    return &pciem_stub_iommu;
}

static void pciem_stub_release_device(struct device *dev)
{
    /* nothing to release; group is freed by the core when device leaves */
}

static struct iommu_group *pciem_stub_device_group(struct device *dev)
{
    /* One group per device. Synthetic pcim devices have no aliasing
     * concerns because there's no real shared bridge upstream — so
     * isolated single-device groups are correct. */
    return iommu_group_alloc();
}

static struct iommu_domain *pciem_stub_domain_alloc_paging(struct device *dev)
{
    struct pciem_stub_domain *sd = kzalloc(sizeof(*sd), GFP_KERNEL);
    if (!sd)
        return ERR_PTR(-ENOMEM);

    xa_init(&sd->pfns);

    /* No hardware page-size restriction to honour since we're not a
     * real walker — accept whatever granularity the caller maps at. */
    sd->domain.pgsize_bitmap = SZ_4K | SZ_2M | SZ_1G;
    sd->domain.ops           = &pciem_stub_domain_ops;

    /* Leaving geometry zeroed (the kzalloc default) makes
     * vfio_iommu_type1_attach_group() call vfio_iommu_aper_resize() with
     * aperture_start=aperture_end=0. On a fresh container that inserts a 
     * degenerate {0,0} range instead of leaving the range unrestricted, 
     * so every subsequent VFIO_IOMMU_MAP_DMA on a real userspace address 
     * fails -EINVAL in vfio_iommu_iova_dma_valid(). Advertise the full 
     * 64-bit space. */
    sd->domain.geometry.aperture_start = 0;
    sd->domain.geometry.aperture_end   = ~(dma_addr_t)0;
    sd->domain.geometry.force_aperture = true;
    return &sd->domain;
}

static const struct iommu_ops pciem_stub_iommu_ops = {
    .capable             = pciem_stub_capable,
    .device_group        = pciem_stub_device_group,
    .probe_device        = pciem_stub_probe_device,
    .release_device      = pciem_stub_release_device,
    .domain_alloc_paging = pciem_stub_domain_alloc_paging,
    .blocked_domain      = &pciem_stub_blocked_domain,
    .default_domain_ops  = &pciem_stub_domain_ops,
    .owner               = THIS_MODULE,
};

/* ---------------------------------------------------------------- */
/* bridge tracking — set of pciem-owned host_bridge devices         */
/* ---------------------------------------------------------------- */

struct pciem_stub_bridge {
    struct list_head list;
    struct device   *bridge_dev;
};

static LIST_HEAD(pciem_stub_bridges);
static DEFINE_MUTEX(pciem_stub_bridges_lock);

int pciem_iommu_stub_register_bridge(struct device *bridge_dev)
{
    struct pciem_stub_bridge *entry;

    if (!bridge_dev)
        return -EINVAL;

    entry = kzalloc(sizeof(*entry), GFP_KERNEL);
    if (!entry)
        return -ENOMEM;

    entry->bridge_dev = bridge_dev;

    mutex_lock(&pciem_stub_bridges_lock);
    list_add(&entry->list, &pciem_stub_bridges);
    mutex_unlock(&pciem_stub_bridges_lock);

    return 0;
}

void pciem_iommu_stub_unregister_bridge(struct device *bridge_dev)
{
    struct pciem_stub_bridge *entry, *tmp;

    if (!bridge_dev)
        return;

    mutex_lock(&pciem_stub_bridges_lock);
    list_for_each_entry_safe(entry, tmp, &pciem_stub_bridges, list) {
        if (entry->bridge_dev == bridge_dev) {
            list_del(&entry->list);
            kfree(entry);
            break;
        }
    }
    mutex_unlock(&pciem_stub_bridges_lock);
}

static bool pciem_stub_owns_bus(struct pci_bus *bus)
{
    struct pciem_stub_bridge *entry;
    struct device *bridge_dev;
    bool found = false;

    if (!bus || !bus->bridge)
        return false;

    bridge_dev = bus->bridge;

    mutex_lock(&pciem_stub_bridges_lock);
    list_for_each_entry(entry, &pciem_stub_bridges, list) {
        if (entry->bridge_dev == bridge_dev) {
            found = true;
            break;
        }
    }
    mutex_unlock(&pciem_stub_bridges_lock);

    return found;
}

/* ---------------------------------------------------------------- */
/* pci_bus_type notifier — installs fwspec before iommu core probes */
/* ---------------------------------------------------------------- */

static int pciem_stub_pci_notify(struct notifier_block *nb,
                                 unsigned long action, void *data)
{
    struct device *dev = data;
    struct pci_dev *pdev;
    struct fwnode_handle *fwnode;
    int rc;

    if (action != BUS_NOTIFY_ADD_DEVICE)
        return NOTIFY_DONE;
    if (!dev_is_pci(dev))
        return NOTIFY_DONE;

    pdev = to_pci_dev(dev);
    if (!pciem_stub_owns_bus(pdev->bus))
        return NOTIFY_DONE;

    fwnode = software_node_fwnode(&pciem_stub_iommu_swnode);
    if (!fwnode)
        return NOTIFY_DONE;

    rc = iommu_fwspec_init(dev, fwnode);
    if (rc && rc != -EALREADY) {
        pr_warn("pciem-iommu-stub: fwspec_init(%s) failed: %d\n",
                dev_name(dev), rc);
        return NOTIFY_DONE;
    }

    /* The iommu core's notifier (priority 0) will run next on the same
     * BUS_NOTIFY_ADD_DEVICE event and pick up the fwspec we just
     * installed. No manual probe call needed. */
    return NOTIFY_OK;
}

static struct notifier_block pciem_stub_pci_nb = {
    .notifier_call = pciem_stub_pci_notify,
    /* Must be > the iommu core's notifier (priority 0) so we install
     * fwspec first; the core's iommu_bus_notifier then probes us. */
    .priority      = 1,
};

/* ---------------------------------------------------------------- */
/* module-scoped init / exit                                        */
/* ---------------------------------------------------------------- */

int pciem_iommu_stub_init(void)
{
    int rc;

    rc = software_node_register(&pciem_stub_iommu_swnode);
    if (rc) {
        pr_err("pciem-iommu-stub: software_node_register failed: %d\n", rc);
        return rc;
    }

    pciem_stub_iommu.fwnode = software_node_fwnode(&pciem_stub_iommu_swnode);

    rc = iommu_device_sysfs_add(&pciem_stub_iommu, NULL, NULL, "pciem-iommu");
    if (rc) {
        pr_err("pciem-iommu-stub: sysfs_add failed: %d\n", rc);
        goto err_swnode;
    }

    rc = iommu_device_register(&pciem_stub_iommu, &pciem_stub_iommu_ops, NULL);
    if (rc) {
        pr_err("pciem-iommu-stub: iommu_device_register failed: %d\n", rc);
        goto err_sysfs;
    }

    rc = bus_register_notifier(&pci_bus_type, &pciem_stub_pci_nb);
    if (rc) {
        pr_err("pciem-iommu-stub: bus_register_notifier failed: %d\n", rc);
        goto err_iommu;
    }

    pr_info("pciem-iommu-stub: registered (no-translation; for vfio binding only)\n");
    return 0;

err_iommu:
    iommu_device_unregister(&pciem_stub_iommu);
err_sysfs:
    iommu_device_sysfs_remove(&pciem_stub_iommu);
err_swnode:
    software_node_unregister(&pciem_stub_iommu_swnode);
    return rc;
}

void pciem_iommu_stub_exit(void)
{
    struct pciem_stub_bridge *entry, *tmp;

    bus_unregister_notifier(&pci_bus_type, &pciem_stub_pci_nb);
    iommu_device_unregister(&pciem_stub_iommu);
    iommu_device_sysfs_remove(&pciem_stub_iommu);
    software_node_unregister(&pciem_stub_iommu_swnode);

    mutex_lock(&pciem_stub_bridges_lock);
    list_for_each_entry_safe(entry, tmp, &pciem_stub_bridges, list) {
        list_del(&entry->list);
        kfree(entry);
    }
    mutex_unlock(&pciem_stub_bridges_lock);
}
