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
 * pci_alloc_host_bridge) as pciem-owned. The stub's ->probe_device()
 * claims a pci_dev only if its bus is under one of these bridges; the
 * iommu core calls it when the device is added.
 *
 * Call register_bridge() between pci_alloc_host_bridge() and
 * pci_scan_root_bus_bridge() so the bridge is known before any
 * synthetic device is added on the bus.
 */
int  pciem_iommu_stub_register_bridge(struct device *bridge_dev);
void pciem_iommu_stub_unregister_bridge(struct device *bridge_dev);

#endif /* PCIEM_IOMMU_STUB_H */
