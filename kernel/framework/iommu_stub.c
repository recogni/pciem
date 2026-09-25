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
 * Translation is real: ->map_pages records each 4 KiB page of a mapping
 * in a per-domain {iova -> paddr} table, ->unmap_pages erases it, and
 * ->iova_to_phys looks it up, returning 0 for an IOVA nothing mapped.
 * PCIEM_IOCTL_DMA resolves a device-side access through this table, so
 * a device model reaches exactly the buffers the driver mapped (for
 * vfio-pci, with VFIO_IOMMU_MAP_DMA) and faults on anything else. The
 * table is per page because the iommu core may split one logical map
 * or unmap into several calls.
 *
 * Hookup model:
 *
 * The stub is registered with no fwnode. For a device that has no
 * iommu_fwspec (no DMAR, IORT, VIOT or OF description — which is every
 * pciem virtual-root device), iommu_init_device() resolves ops through
 * iommu_ops_from_fwnode(NULL), i.e. the first registered IOMMU whose
 * fwnode is NULL, and calls its ->probe_device() with
 * iommu_probe_device_lock held. That is the core's own path for
 * firmware-less IOMMUs, reached both from the core's BUS_NOTIFY_ADD_DEVICE
 * notifier and from iommu_device_register()'s bus scan.
 *
 * pciem must not install a fwspec itself: iommu_fwspec_init() allocates
 * dev->iommu, which requires iommu_probe_device_lock (dev_iommu_get()
 * asserts it), and that lock is not exported. Calling it from a bus
 * notifier trips lockdep and races concurrent probes.
 *
 * So the claim is made in ->probe_device(): it returns the stub only for
 * a pci_dev whose bus sits under a host bridge pciem registered here, and
 * -ENODEV for everything else, which the core treats as "no IOMMU".
 * pci_bus->bridge is the &dev of the pci_host_bridge; pciem registers
 * each bridge it allocates before pci_scan_root_bus_bridge() adds the
 * devices. The lookup compares pointers rather than using
 * container_of(bus->sysdata, ...), which would be unsafe on real buses.
 *
 * Limitation: if a built-in firmware-less IOMMU (intel-iommu, amd-iommu)
 * registered first, the core resolves fwspec-less devices to it and the
 * stub claims nothing. The stub is for hosts without a real IOMMU.
 */

#include <linux/iommu.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/pci.h>
#include <linux/printk.h>
#include <linux/sizes.h>
#include <linux/slab.h>
#include <linux/xarray.h>
#include <linux/module.h>

#include "iommu_stub.h"

static struct iommu_device pciem_stub_iommu;

#define PCIEM_STUB_PAGE_SIZE SZ_4K

struct pciem_stub_domain {
    struct iommu_domain domain;
    /* index = iova / PCIEM_STUB_PAGE_SIZE, value = paddr / PCIEM_STUB_PAGE_SIZE */
    struct xarray pfns;
};

static struct pciem_stub_domain *to_stub_domain(struct iommu_domain *domain)
{
    return container_of(domain, struct pciem_stub_domain, domain);
}

/* ---------------------------------------------------------------- */
/* domain ops — per-page iova->phys bookkeeping                     */
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
    size_t size = pgsize * pgcount;
    size_t cur;

    for (cur = 0; cur < size; cur += PCIEM_STUB_PAGE_SIZE) {
        void *old = xa_store(&sd->pfns, (iova + cur) / PCIEM_STUB_PAGE_SIZE,
                             xa_mk_value((paddr + cur) / PCIEM_STUB_PAGE_SIZE), gfp);

        if (xa_is_err(old)) {
            size_t undo;

            for (undo = 0; undo < cur; undo += PCIEM_STUB_PAGE_SIZE)
                xa_erase(&sd->pfns, (iova + undo) / PCIEM_STUB_PAGE_SIZE);
            *mapped = 0;
            return xa_err(old);
        }
        WARN_ON_ONCE(old);
    }

    *mapped = size;
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
        if (!xa_erase(&sd->pfns, (iova + cur) / PCIEM_STUB_PAGE_SIZE))
            pr_warn_ratelimited("unmap of an untracked iova 0x%lx\n", iova + cur);
    }

    return size;
}

static phys_addr_t pciem_stub_iova_to_phys(struct iommu_domain *domain, dma_addr_t iova)
{
    struct pciem_stub_domain *sd = to_stub_domain(domain);
    void *ent = xa_load(&sd->pfns, iova / PCIEM_STUB_PAGE_SIZE);

    if (!ent)
        return 0;
    return (phys_addr_t)xa_to_value(ent) * PCIEM_STUB_PAGE_SIZE + iova % PCIEM_STUB_PAGE_SIZE;
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
 * via domain_alloc_paging. attach is a no-op: a blocked domain has no
 * table, and the stub never translates through it. free is NULL because the core never tries to free statics. */
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
     * "VFIO always sets IOMMU_CACHE..."). A synthetic device's DMA is a
     * CPU copy in PCIEM_IOCTL_DMA, so it is coherent by construction.
     */
    switch (cap) {
    case IOMMU_CAP_CACHE_COHERENCY:
    case IOMMU_CAP_DEFERRED_FLUSH:
        return true;
    default:
        return false;
    }
}

static bool pciem_stub_owns_bus(struct pci_bus *bus);

static struct iommu_device *pciem_stub_probe_device(struct device *dev)
{
    if (!dev_is_pci(dev) || !pciem_stub_owns_bus(to_pci_dev(dev)->bus))
        return ERR_PTR(-ENODEV);
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
    /* The table is kept per 4 KiB page whatever size the core maps in. */
    sd->domain.pgsize_bitmap = SZ_4K | SZ_2M | SZ_1G;
    sd->domain.ops           = &pciem_stub_domain_ops;
    /* vfio type1 takes its valid IOVA range from the geometry; a zeroed
     * one reserves everything and VFIO_IOMMU_MAP_DMA fails. */
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
/* module-scoped init / exit                                        */
/* ---------------------------------------------------------------- */

int pciem_iommu_stub_init(void)
{
    int rc;

    rc = iommu_device_sysfs_add(&pciem_stub_iommu, NULL, NULL, "pciem-iommu");
    if (rc) {
        pr_err("pciem-iommu-stub: sysfs_add failed: %d\n", rc);
        return rc;
    }

    rc = iommu_device_register(&pciem_stub_iommu, &pciem_stub_iommu_ops, NULL);
    if (rc) {
        pr_err("pciem-iommu-stub: iommu_device_register failed: %d\n", rc);
        goto err_sysfs;
    }

    pr_info("pciem-iommu-stub: registered (no-translation; for vfio binding only)\n");
    return 0;

err_sysfs:
    iommu_device_sysfs_remove(&pciem_stub_iommu);
    return rc;
}

void pciem_iommu_stub_exit(void)
{
    struct pciem_stub_bridge *entry, *tmp;

    iommu_device_unregister(&pciem_stub_iommu);
    iommu_device_sysfs_remove(&pciem_stub_iommu);

    mutex_lock(&pciem_stub_bridges_lock);
    list_for_each_entry_safe(entry, tmp, &pciem_stub_bridges, list) {
        list_del(&entry->list);
        kfree(entry);
    }
    mutex_unlock(&pciem_stub_bridges_lock);
}
