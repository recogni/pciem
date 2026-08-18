/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * pciem stub IOMMU — see kernel/framework/iommu_stub.c for rationale.
 */

#ifndef PCIEM_IOMMU_STUB_H
#define PCIEM_IOMMU_STUB_H

struct device;

int  pciem_iommu_stub_init(void);
void pciem_iommu_stub_exit(void);

/*
 * Register/unregister a host_bridge device (the &bridge->dev returned by
 * pci_alloc_host_bridge) as pciem-owned. Synthetic pci_devs that appear
 * on a bus under one of these bridges will have a pciem-stub iommu_fwspec
 * installed automatically by a high-priority pci_bus_type notifier
 * registered in pciem_iommu_stub_init(). The iommu core's own (lower
 * priority) notifier then runs iommu_probe_device() on the same
 * BUS_NOTIFY_ADD_DEVICE event, sees the fwspec we just installed, and
 * binds the device to the stub IOMMU — no manual probe call, no kernel
 * EXPORT patches, no fwspec-after-the-fact reprobe.
 *
 * Call register_bridge() between pci_alloc_host_bridge() and
 * pci_scan_root_bus_bridge() so the notifier is in place before any
 * synthetic device is added on the bus.
 */
int  pciem_iommu_stub_register_bridge(struct device *bridge_dev);
void pciem_iommu_stub_unregister_bridge(struct device *bridge_dev);

struct pci_bus;

/*
 * Is this bus one of pciem's own virtual-root buses? Shared with
 * pciem_lookup_root_complex() (pciem.c) so bus-ownership checking has a
 * single implementation instead of being duplicated per call site.
 */
bool pciem_stub_owns_bus(struct pci_bus *bus);

#endif /* PCIEM_IOMMU_STUB_H */
