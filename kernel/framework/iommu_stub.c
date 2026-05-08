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
 * It does NOT provide real address translation. ->iova_to_phys is
 * passthrough (iova == paddr), and map/unmap callbacks are no-ops that
 * report success. This is fine for synthetic devices that don't
 * actually issue DMA — userspace driver code under test that calls
 * dma_map_*() will get a valid IOVA back, write it to the device, and
 * the device just doesn't dereference it (because it's emulated by
 * pciem-mock and doesn't really do DMA).
 *
 * If/when pciem grows real device-side DMA simulation, this stub becomes
 * the point where iova→userspace-vaddr translations are recorded so the
 * userspace daemon can resolve them.
 *
 * Hookup model (avoids fwnode-on-real-PCI-bus collision with intel-iommu
 * / amd-iommu / smmu): each synthetic pci_dev gets dev->iommu->fwspec
 * pointed at our software_node, and we explicitly call
 * iommu_probe_device(dev) after the device is on the bus. The platform
 * IOMMU on real PCI devices is unaffected — its devices come up via
 * dma_configure → ACPI/IORT → its own fwnode chain, which never matches
 * our software_node.
 */

#include <linux/iommu.h>
#include <linux/property.h>
#include <linux/slab.h>
#include <linux/sizes.h>
#include <linux/printk.h>
#include <linux/module.h>

#include "iommu_stub.h"

static struct iommu_device pciem_stub_iommu;

/* Synthetic fwnode used as the "iommu controller" identity. The real
 * PCIe devices in the system never reference this fwnode, so there's
 * no collision with intel-iommu / amd-iommu / smmu / etc.            */
static const struct software_node pciem_stub_iommu_swnode = {
    .name = "pciem-iommu-stub",
};

/* ---------------------------------------------------------------- */
/* domain ops — no-op map/unmap, passthrough iova_to_phys           */
/* ---------------------------------------------------------------- */

static int pciem_stub_attach_dev(struct iommu_domain *domain, struct device *dev)
{
    return 0;
}

static int pciem_stub_map_pages(struct iommu_domain *domain, unsigned long iova,
                                phys_addr_t paddr, size_t pgsize, size_t pgcount,
                                int prot, gfp_t gfp, size_t *mapped)
{
    /* Real driver-under-test that does dma_map_single() will pass an
     * IOVA the user picked (or the dma-iommu glue picked); our stub
     * accepts any mapping and reports success. iova == paddr at
     * iova_to_phys time, so the IOVA returned to userspace is just the
     * physical address — which is fine since our synthetic device
     * doesn't actually dereference it. */
    *mapped = pgsize * pgcount;
    return 0;
}

static size_t pciem_stub_unmap_pages(struct iommu_domain *domain, unsigned long iova,
                                     size_t pgsize, size_t pgcount,
                                     struct iommu_iotlb_gather *gather)
{
    return pgsize * pgcount;
}

static phys_addr_t pciem_stub_iova_to_phys(struct iommu_domain *domain, dma_addr_t iova)
{
    return (phys_addr_t)iova;   /* passthrough */
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
    kfree(domain);
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
    struct iommu_domain *domain = kzalloc(sizeof(*domain), GFP_KERNEL);
    if (!domain)
        return ERR_PTR(-ENOMEM);
    /* Pass-through translation, so any page size is acceptable for the
     * "mapping bookkeeping" we don't actually do. */
    domain->pgsize_bitmap = SZ_4K | SZ_2M | SZ_1G;
    domain->ops           = &pciem_stub_domain_ops;
    return domain;
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

    pr_info("pciem-iommu-stub: registered (no-translation; for vfio binding only)\n");
    return 0;

err_sysfs:
    iommu_device_sysfs_remove(&pciem_stub_iommu);
err_swnode:
    software_node_unregister(&pciem_stub_iommu_swnode);
    return rc;
}

void pciem_iommu_stub_exit(void)
{
    iommu_device_unregister(&pciem_stub_iommu);
    iommu_device_sysfs_remove(&pciem_stub_iommu);
    software_node_unregister(&pciem_stub_iommu_swnode);
}

/* ---------------------------------------------------------------- */
/* per-device hookup                                                */
/* ---------------------------------------------------------------- */

/*
 * !!! ILC_emulator PROTO / LOCAL HACK !!!
 *
 * The iommu_probe_device() symbol is not exported in mainline
 * (drivers/iommu/iommu.c). For pciem to retrigger iommu probe after
 * setting fwspec late on synthetic devices, we depend on a local
 * kernel patch that adds EXPORT_SYMBOL_GPL(iommu_probe_device).
 * Search-tag: ILC-PROTO-IOMMU-EXPORT.
 *
 * The upstream-clean path is one of:
 *   (1) export iommu_probe_device upstream
 *   (2) add iommu_register_synthetic_dev() helper symmetric with
 *       iommu_mock_device_add() but for already-bus-added devices
 *   (3) software_node "iommus" property honoured by pci_dma_configure
 * Both (1) and (2) are simple kernel patches; (3) is bigger.
 *
 * The forward declaration below lets iommu_stub.c build standalone
 * regardless of whether the export is present: in mainline the
 * declaration matches the (private) function and link succeeds because
 * the local kernel patch makes it visible. On unpatched mainline the
 * MODPOST step will report iommu_probe_device as undefined and pciem
 * fails to load — which is the correct behaviour, since this build
 * configuration cannot escape noiommu mode anyway.
 */
extern int iommu_probe_device(struct device *dev);

int pciem_iommu_stub_attach(struct device *dev)
{
    struct fwnode_handle *fwnode;
    int rc;

    fwnode = software_node_fwnode(&pciem_stub_iommu_swnode);
    if (!fwnode)
        return -ENODEV;

    rc = iommu_fwspec_init(dev, fwnode);
    if (rc && rc != -EALREADY) {
        pr_err("pciem-iommu-stub: fwspec_init(%s) failed: %d\n",
               dev_name(dev), rc);
        return rc;
    }

    /* Re-trigger iommu probe now that fwspec is set. The bus notifier
     * already fired with NULL fwspec at pci_device_add time, so we
     * have to drive this manually. Requires the local kernel patch
     * tagged ILC-PROTO-IOMMU-EXPORT. */
    rc = iommu_probe_device(dev);
    if (rc) {
        pr_warn("pciem-iommu-stub: iommu_probe_device(%s) failed: %d "
                "(kernel without EXPORT_SYMBOL_GPL(iommu_probe_device)?)\n",
                dev_name(dev), rc);
        return rc;
    }

    pr_info("pciem-iommu-stub: %s attached, iommu_group=%d\n",
            dev_name(dev),
            dev->iommu_group ? iommu_group_id(dev->iommu_group) : -1);
    return 0;
}
