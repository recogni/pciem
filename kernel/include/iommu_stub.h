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
 * Wire @dev to the stub IOMMU and trigger iommu probe. Call once per
 * synthetic pci_dev created on a virtual-root bus, after the device has
 * been added to the bus (so dev->iommu is allocated by core).
 */
int  pciem_iommu_stub_attach(struct device *dev);

#endif /* PCIEM_IOMMU_STUB_H */
