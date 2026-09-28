/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef PCIEM_MSI_DOMAIN_H
#define PCIEM_MSI_DOMAIN_H

struct irq_domain;
struct pciem_root_complex;

int pciem_msi_domain_init(void);
void pciem_msi_domain_exit(void);
struct irq_domain *pciem_msi_domain(void);

void pciem_msi_rc_init(struct pciem_root_complex *v);
void pciem_msi_rc_destroy(struct pciem_root_complex *v);
int pciem_msi_deliver(struct pciem_root_complex *v, int vector);

#endif /* PCIEM_MSI_DOMAIN_H */
