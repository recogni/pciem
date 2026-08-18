// SPDX-License-Identifier: GPL-2.0-only
/*
 * pciem_vfio_pci — vfio-pci variant driver for pyxis-class synthetic
 * devices.
 *
 * Every vfio_device_ops entry falls through to the exact same
 * vfio_pci_core generic implementation stock vfio-pci.ko uses (config
 * space, MSI-X, standard BAR read/write/mmap, DMA/IOMMU group
 * integration via iommu_stub.c — untouched by this driver) EXCEPT
 * .read: for offsets registered via PCIEM_IOCTL_SET_BAR_READ_INTERCEPTS,
 * .read instead blocks (ordinary process context servicing the guest's
 * pread(), never atomic — unlike smptrace's kprobe/#PF trap, which
 * cannot legally sleep) on pciem_submit_mmio_read(), so a handler
 * running in the daemon can compute a real answer synchronously,
 * including for destructive reads (e.g. mailbox's pop[]) and cold
 * reads with no prior write. Every other offset, and every write
 * regardless of offset, is unaffected.
 */

#include <linux/module.h>
#include <linux/pci.h>
#include <linux/vfio.h>
#include <linux/vfio_pci_core.h>

#include "pciem.h"
#include "pciem_api.h"

#define PCIEM_VFIO_PCI_VENDOR_ID 0xfeed
#define PCIEM_VFIO_PCI_DEVICE_ID 0xd001

/* Generous default: a slow/busy daemon should surface as a bounded
 * -ETIMEDOUT to the guest, not an indefinite hang, but this should
 * never legitimately trip in a live device (it would mean the daemon's
 * event loop is stuck). Not yet exposed as tunable — v1 scope. */
#define PCIEM_VFIO_READ_TIMEOUT_MS 1000

struct pciem_vfio_pci_device {
    struct vfio_pci_core_device core_device;
};

/*
 * Is [pos, pos+count) entirely inside one range this BAR registered
 * via PCIEM_IOCTL_SET_BAR_READ_INTERCEPTS? read_intercepts/
 * num_read_intercepts are set once, before PCIEM_IOCTL_REGISTER, and
 * never mutated again while the device is live, so this is safe to
 * read without v->bars_lock.
 */
static bool pciem_vfio_read_intercepted(struct pciem_root_complex *v,
                                        unsigned int bar_index,
                                        u64 pos, size_t count)
{
    const struct pciem_bar_info *bar;
    unsigned int i;

    if (bar_index >= PCI_STD_NUM_BARS)
        return false;

    bar = &v->bars[bar_index];
    for (i = 0; i < bar->num_read_intercepts; i++)
    {
        u64 start = bar->read_intercepts[i].offset;
        u64 end   = start + bar->read_intercepts[i].len;

        if (pos >= start && pos + count <= end)
            return true;
    }

    return false;
}

static ssize_t pciem_vfio_pci_read(struct vfio_device *core_vdev,
                                   char __user *buf, size_t count,
                                   loff_t *ppos)
{
    struct vfio_pci_core_device *vdev =
        container_of(core_vdev, struct vfio_pci_core_device, vdev);
    unsigned int index = VFIO_PCI_OFFSET_TO_INDEX(*ppos);
    u64 pos = *ppos & VFIO_PCI_OFFSET_MASK;
    struct pciem_root_complex *v;
    u64 value = 0;
    int ret;

    if (index < PCI_STD_NUM_BARS && count > 0 && count <= sizeof(value))
    {
        v = pciem_lookup_root_complex(vdev->pdev);
        if (v && pciem_vfio_read_intercepted(v, index, pos, count))
        {
            ret = pciem_submit_mmio_read(v, index, pos, (u32)count, &value,
                                         PCIEM_VFIO_READ_TIMEOUT_MS);
            if (ret)
                return ret;

            if (copy_to_user(buf, &value, count))
                return -EFAULT;

            return count;
        }
    }

    /* Not a handler-backed offset (or not one of pciem's own devices,
     * which should never happen given our own pci_device_id table) —
     * identical to stock vfio-pci.ko's behavior. */
    return vfio_pci_core_read(core_vdev, buf, count, ppos);
}

static int pciem_vfio_pci_open_device(struct vfio_device *core_vdev)
{
    struct vfio_pci_core_device *vdev =
        container_of(core_vdev, struct vfio_pci_core_device, vdev);
    int ret;

    ret = vfio_pci_core_enable(vdev);
    if (ret)
        return ret;

    vfio_pci_core_finish_enable(vdev);
    return 0;
}

static const struct vfio_device_ops pciem_vfio_pci_ops = {
    .name           = "pciem-vfio-pci",
    .init           = vfio_pci_core_init_dev,
    .release        = vfio_pci_core_release_dev,
    .open_device    = pciem_vfio_pci_open_device,
    .close_device   = vfio_pci_core_close_device,
    .ioctl          = vfio_pci_core_ioctl,
    .device_feature = vfio_pci_core_ioctl_feature,
    .read           = pciem_vfio_pci_read,
    .write          = vfio_pci_core_write,
    .mmap           = vfio_pci_core_mmap,
    .request        = vfio_pci_core_request,
    .match          = vfio_pci_core_match,
    .match_token_uuid = vfio_pci_core_match_token_uuid,
    .bind_iommufd   = vfio_iommufd_physical_bind,
    .unbind_iommufd = vfio_iommufd_physical_unbind,
    .attach_ioas    = vfio_iommufd_physical_attach_ioas,
    .detach_ioas    = vfio_iommufd_physical_detach_ioas,
};

static int pciem_vfio_pci_probe(struct pci_dev *pdev,
                                const struct pci_device_id *id)
{
    struct pciem_vfio_pci_device *pdev_priv;
    int ret;

    pdev_priv = vfio_alloc_device(pciem_vfio_pci_device, core_device.vdev,
                                  &pdev->dev, &pciem_vfio_pci_ops);
    if (IS_ERR(pdev_priv))
        return PTR_ERR(pdev_priv);

    dev_set_drvdata(&pdev->dev, &pdev_priv->core_device);

    ret = vfio_pci_core_register_device(&pdev_priv->core_device);
    if (ret)
        goto out_put_vdev;

    return 0;

out_put_vdev:
    vfio_put_device(&pdev_priv->core_device.vdev);
    return ret;
}

static void pciem_vfio_pci_remove(struct pci_dev *pdev)
{
    struct vfio_pci_core_device *core_device = dev_get_drvdata(&pdev->dev);

    vfio_pci_core_unregister_device(core_device);
    vfio_put_device(&core_device->vdev);
}

static const struct pci_device_id pciem_vfio_pci_table[] = {
    { PCI_DEVICE(PCIEM_VFIO_PCI_VENDOR_ID, PCIEM_VFIO_PCI_DEVICE_ID) },
    { }
};
MODULE_DEVICE_TABLE(pci, pciem_vfio_pci_table);

static struct pci_driver pciem_vfio_pci_driver = {
    .name             = KBUILD_MODNAME,
    .id_table         = pciem_vfio_pci_table,
    .probe            = pciem_vfio_pci_probe,
    .remove           = pciem_vfio_pci_remove,
    .driver_managed_dma = true,
};
module_pci_driver(pciem_vfio_pci_driver);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("vfio-pci variant driver for pyxis-class synthetic devices");
