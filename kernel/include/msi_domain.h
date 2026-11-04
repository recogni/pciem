/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef PCIEM_MSI_DOMAIN_H
#define PCIEM_MSI_DOMAIN_H

#include <linux/mutex.h>
#include <linux/xarray.h>

struct irq_domain;
struct pci_dev;
struct pciem_root_complex;

/*
 * MSI/MSI-X vector -> Linux irq, for vectors allocated in pciem's MSI domain.
 * @lock also keeps a vector's irq allocated while pciem_msi_deliver() runs
 * its handler.
 */
struct pciem_msi_vecs {
    struct mutex lock;
    struct xarray virqs;
};

int pciem_msi_domain_init(void);
void pciem_msi_domain_exit(void);
struct irq_domain *pciem_msi_domain(void);

void pciem_msi_vecs_init(struct pciem_msi_vecs *vecs);
void pciem_msi_vecs_destroy(struct pciem_msi_vecs *vecs);
struct pciem_msi_vecs *pciem_msi_vecs_from_pdev(struct pci_dev *pdev);
int pciem_msi_deliver(struct pciem_msi_vecs *vecs, int vector);

#endif /* PCIEM_MSI_DOMAIN_H */
