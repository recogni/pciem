// SPDX-License-Identifier: GPL-2.0-only
#define pr_fmt(fmt) KBUILD_MODNAME ": topo: " fmt

#include "pciem.h"
#include "capabilities.h"
#include "msi_domain.h"
#include "pool.h"
#include "topology.h"

#include <linux/ioport.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/sizes.h>
#include <linux/sort.h>

#define PCIEM_VENDOR_ID 0x1ab8
#define PCIEM_PORT_PCIE 0x40
#define PCIEM_PORT_MSI  0x80
#define PCIEM_PORT_AER  0x100
#define PCIEM_PORT_DPC  0x140

#define LNKCAP_SDERC  0x00080000
#define LNKCAP_DLLLARC 0x00100000
#define LNKCAP_LBNC   0x00200000
#define LNKCAP_ASPMOC 0x00400000
#define SLTCAP_NCCS   0x00040000
#define SLTCTL_HPIE   0x0020
#define SLTCTL_PDCE   0x0008
#define SLTCTL_CCIE   0x0010
#define SLTCTL_DLLSCE 0x1000
#define SLTSTA_PDC    0x0008
#define SLTSTA_CC     0x0010
#define SLTSTA_DLLSC  0x0100
#define LNKCTL_LD     0x0010
#define LNKCTL_RL     0x0020
#define LNKCTL_LBMIE  0x0400
#define LNKCTL_LABIE  0x0800
#define LNKSTA2_EQ_ALL 0x001e
#define BRCTL_SBR     0x0040
#define RTCTL_RRS_SVE 0x0010
#define UE_SDES       0x00000020
#define ROOT_ERR_COR  0x01
#define ROOT_ERR_MULTI_COR 0x02
#define ROOT_ERR_UNCOR 0x04
#define ROOT_ERR_MULTI_UNCOR 0x08
#define ROOT_ERR_FIRST_FATAL 0x10
#define ROOT_ERR_NONFATAL 0x20
#define ROOT_ERR_FATAL 0x40

static u16 r16(const struct pciem_port *p, int off)
{
	return get_unaligned_le16(&p->cfg[off]);
}

static u32 r32(const struct pciem_port *p, int off)
{
	return get_unaligned_le32(&p->cfg[off]);
}

static void w16(struct pciem_port *p, int off, u16 v)
{
	put_unaligned_le16(v, &p->cfg[off]);
}

static void w32(struct pciem_port *p, int off, u32 v)
{
	put_unaligned_le32(v, &p->cfg[off]);
}

static void set_mask(u8 *arr, int off, int len, u32 mask)
{
	int i;

	for (i = 0; i < len; i++)
		arr[off + i] = mask >> (8 * i);
}

static void rwm(struct pciem_port *p, int off, int len, u32 mask)
{
	set_mask(p->rw, off, len, mask);
}

static void w1cm(struct pciem_port *p, int off, int len, u32 mask)
{
	set_mask(p->w1c, off, len, mask);
}

static int port_index(const struct pciem_port *p)
{
	return p->role;
}

u8 pciem_topo_depth(const struct pciem_topo *t)
{
	return t->placement == PCIEM_PLACEMENT_SWITCH ? 3 : 1;
}

u8 pciem_port_tls(struct pciem_port *p)
{
	return r16(p, p->pcie + PCI_EXP_LNKCTL2) & PCI_EXP_LNKCTL2_TLS;
}

void pciem_topo_kick_work(struct pciem_topo *t)
{
	if (!READ_ONCE(t->dying))
		queue_work(system_wq, &t->work);
}

static const char *const pciem_placement_names[] = { "root-bus", "root-port", "switch" };

static const char *port_name(u8 role)
{
	static const char *const names[] = { "rp", "usp", "dsp" };

	return names[role];
}

static void port_build(struct pciem_port *p)
{
	struct pciem_topo *t = p->topo;
	bool rp = p->role == PCIEM_ROLE_RP;
	bool ds = p->downstream;
	bool slot = rp || p->role == PCIEM_ROLE_DSP;
	bool dpc = ds && (t->p.flags & PCIEM_TOPO_FLAG_DPC);
	int c = p->pcie;
	u32 lnkcap, sltcap = 0, uemsk, ue_impl, a = PCIEM_PORT_AER;
	u8 type = rp ? PCI_EXP_TYPE_ROOT_PORT :
			  p->role == PCIEM_ROLE_USP ? PCI_EXP_TYPE_UPSTREAM : PCI_EXP_TYPE_DOWNSTREAM;
	u8 speed = p->speed;

	memset(p->cfg, 0, sizeof(p->cfg));
	memset(p->rw, 0, sizeof(p->rw));
	memset(p->w1c, 0, sizeof(p->w1c));

	w16(p, PCI_VENDOR_ID, PCIEM_VENDOR_ID);
	w16(p, PCI_DEVICE_ID, 0xd130 + p->role);
	w16(p, PCI_STATUS, PCI_STATUS_CAP_LIST);
	rwm(p, PCI_COMMAND, 2, 0x0546);
	w1cm(p, PCI_STATUS, 2, 0xf900);
	p->cfg[PCI_CLASS_DEVICE] = 0x04;
	p->cfg[PCI_CLASS_DEVICE + 1] = 0x06;
	p->cfg[PCI_HEADER_TYPE] = PCI_HEADER_TYPE_BRIDGE;
	rwm(p, PCI_PRIMARY_BUS, 3, 0xffffff);
	w1cm(p, PCI_SEC_STATUS, 2, 0xf900);
	p->cfg[PCI_IO_BASE] = 0xf0;
	w16(p, PCI_MEMORY_BASE, 0xfff0);
	w16(p, PCI_MEMORY_LIMIT, 0x0000);
	rwm(p, PCI_MEMORY_BASE, 4, 0xfff0fff0);
	w16(p, PCI_PREF_MEMORY_BASE, 0xfff1);
	w16(p, PCI_PREF_MEMORY_LIMIT, 0x0001);
	rwm(p, PCI_PREF_MEMORY_BASE, 4, 0xfff0fff0);
	rwm(p, PCI_PREF_BASE_UPPER32, 8, ~0u);
	p->cfg[PCI_CAPABILITY_LIST] = PCIEM_PORT_PCIE;
	rwm(p, PCI_INTERRUPT_LINE, 1, 0xff);
	rwm(p, PCI_BRIDGE_CONTROL, 2, 0x007f);

	p->cfg[c] = PCI_CAP_ID_EXP;
	p->cfg[c + 1] = slot ? PCIEM_PORT_MSI : 0;
	w16(p, c + PCI_EXP_FLAGS, (type << 4) | 2 | (slot ? PCI_EXP_FLAGS_SLOT : 0));
	w32(p, c + PCI_EXP_DEVCAP, PCI_EXP_DEVCAP_RBER | 2);
	w16(p, c + PCI_EXP_DEVCTL, 0x2810);
	rwm(p, c + PCI_EXP_DEVCTL, 2, 0x7fff);
	w1cm(p, c + PCI_EXP_DEVSTA, 2, 0x000f);

	lnkcap = speed | ((u32)p->width << 4) | LNKCAP_ASPMOC;
	if (ds)
		lnkcap |= LNKCAP_SDERC | LNKCAP_DLLLARC | LNKCAP_LBNC;
	lnkcap |= (rp || p->role == PCIEM_ROLE_DSP ? 1u : 0u) << 24;
	w32(p, c + PCI_EXP_LNKCAP, lnkcap);
	rwm(p, c + PCI_EXP_LNKCTL, 2,
		(0x03 | (rp ? 0x08 : 0) | (ds ? 0x10 : 0) | 0xc0) |
		((0x02 | (ds ? 0x0c : 0)) << 8));
	w16(p, c + PCI_EXP_LNKSTA, PCIEM_LINK_SPEED_2_5GT);
	w1cm(p, c + PCI_EXP_LNKSTA, 2, PCI_EXP_LNKSTA_LBMS | PCI_EXP_LNKSTA_LABS);

	if (slot) {
		sltcap = SLTCAP_NCCS | ((u32)t->ep_bus << 19);
		if (p->hotplug)
			sltcap |= PCI_EXP_SLTCAP_HPS | PCI_EXP_SLTCAP_HPC;
		w32(p, c + PCI_EXP_SLTCAP, sltcap);
		rwm(p, c + PCI_EXP_SLTCTL, 2, 0x1fff);
		w16(p, c + PCI_EXP_SLTSTA, PCI_EXP_SLTSTA_PDS);
		w1cm(p, c + PCI_EXP_SLTSTA, 2, SLTSTA_PDC | SLTSTA_CC | SLTSTA_DLLSC);
	}
	if (rp) {
		rwm(p, c + PCI_EXP_RTCTL, 2, 0x001f);
		w16(p, c + PCI_EXP_RTCAP, 1);
		w1cm(p, c + PCI_EXP_RTSTA, 4, 0x00010000);
	}
	w32(p, c + PCI_EXP_LNKCAP2, (1u << (speed + 1)) - 2);
	w16(p, c + PCI_EXP_LNKCTL2, speed);
	rwm(p, c + PCI_EXP_LNKCTL2, 2, 0xffff);
	w1cm(p, c + PCI_EXP_LNKSTA2, 2, 0x0020);

	if (slot) {
		int m = PCIEM_PORT_MSI;

		p->cfg[m] = PCI_CAP_ID_MSI;
		w16(p, m + PCI_MSI_FLAGS, PCI_MSI_FLAGS_64BIT);
		rwm(p, m + PCI_MSI_FLAGS, 2, 0x0071);
		rwm(p, m + PCI_MSI_ADDRESS_LO, 4, 0xfffffffc);
		rwm(p, m + PCI_MSI_ADDRESS_HI, 4, ~0u);
		rwm(p, m + PCI_MSI_DATA_64, 2, 0xffff);
	}

	ue_impl = 0x001ff010 | (ds ? UE_SDES : 0);
	uemsk = 0x00100000 | ((ds && !(t->p.flags & PCIEM_TOPO_FLAG_UNMASK_SDES)) ? UE_SDES : 0);
	w32(p, a, PCI_EXT_CAP_ID_ERR | (2 << 16) | ((dpc ? PCIEM_PORT_DPC : 0) << 20));
	w1cm(p, a + PCI_ERR_UNCOR_STATUS, 4, ue_impl);
	w32(p, a + PCI_ERR_UNCOR_MASK, uemsk);
	rwm(p, a + PCI_ERR_UNCOR_MASK, 4, ue_impl);
	w32(p, a + PCI_ERR_UNCOR_SEVER, 0x00063010);
	rwm(p, a + PCI_ERR_UNCOR_SEVER, 4, ue_impl);
	w1cm(p, a + PCI_ERR_COR_STATUS, 4, 0x0000f1c1);
	w32(p, a + PCI_ERR_COR_MASK, 0x00002000);
	rwm(p, a + PCI_ERR_COR_MASK, 4, 0x0000f1c1);
	if (rp) {
		rwm(p, a + PCI_ERR_ROOT_COMMAND, 4, 0x7);
		w1cm(p, a + PCI_ERR_ROOT_STATUS, 4, 0x7f);
	}

	if (dpc) {
		int d = PCIEM_PORT_DPC;

		w32(p, d, PCI_EXT_CAP_ID_DPC | (1 << 16));
		w16(p, d + PCI_EXP_DPC_CAP, PCI_EXP_DPC_CAP_SW_TRIGGER | PCI_EXP_DPC_CAP_DL_ACTIVE);
		w16(p, d + PCI_EXP_DPC_CTL, 0);
		rwm(p, d + PCI_EXP_DPC_CTL, 2, 0xffff);
		w1cm(p, d + PCI_EXP_DPC_STATUS, 2, 0x0009);
	}
}

struct pciem_topo *pciem_topo_alloc(struct pciem_root_complex *v, u8 placement)
{
	struct pciem_topo *t = kzalloc(sizeof(*t), GFP_KERNEL);
	int i;

	if (!t)
		return NULL;
	t->v = v;
	t->placement = placement;
	t->nports = placement == PCIEM_PLACEMENT_SWITCH ? 3 : 1;
	raw_spin_lock_init(&t->lock);
	init_waitqueue_head(&t->trained_wq);
	t->reach_last = true;
	for (i = 0; i < 3; i++) {
		t->ports[i].topo = t;
		t->ports[i].role = i;
		t->ports[i].fn = i;
		t->ports[i].pcie = PCIEM_PORT_PCIE;
		t->ports[i].downstream = i != PCIEM_ROLE_USP;
	}
	return t;
}

void pciem_topo_free(struct pciem_topo *t)
{
	kfree(t);
}

static void topo_work_func(struct work_struct *work);

static u8 topo_default(u8 v, u8 def)
{
	return v ? v : def;
}

static bool speed_valid(u8 s)
{
	return s >= PCIEM_LINK_SPEED_2_5GT && s <= PCIEM_LINK_SPEED_64GT;
}

static bool width_valid(u8 w)
{
	return w == 1 || w == 2 || w == 4 || w == 8 || w == 12 || w == 16 || w == 32;
}

int pciem_topo_set_params(struct pciem_topo *t, const struct pciem_topology *in)
{
	struct pciem_topology p = *in;

	if (p.flags & ~(PCIEM_TOPO_FLAG_HOTPLUG | PCIEM_TOPO_FLAG_NATIVE_AER |
					PCIEM_TOPO_FLAG_UNMASK_SDES | PCIEM_TOPO_FLAG_DPC))
		return -EINVAL;
	if (memchr_inv(p.reserved, 0, sizeof(p.reserved)))
		return -EINVAL;
	if (t->placement == PCIEM_PLACEMENT_SWITCH) {
		if (!p.switch_ports || p.switch_ports > PCIEM_SWITCH_MAX_PORTS || p.port >= p.switch_ports)
			return -EINVAL;
	} else if (p.port || p.switch_ports) {
		return -EINVAL;
	}
	if ((p.rp_speed && !speed_valid(p.rp_speed)) || (p.dsp_speed && !speed_valid(p.dsp_speed)) ||
		(p.ep_speed && !speed_valid(p.ep_speed)))
		return -EINVAL;
	if ((p.rp_width && !width_valid(p.rp_width)) || (p.dsp_width && !width_valid(p.dsp_width)) ||
		(p.ep_width && !width_valid(p.ep_width)))
		return -EINVAL;
	if (t->placement == PCIEM_PLACEMENT_ROOT_PORT && (p.dsp_speed || p.dsp_width))
		return -EINVAL;
	if (p.eq_fail_above != PCIEM_EQ_LIMIT_NONE && p.eq_fail_above > PCIEM_LINK_SPEED_64GT)
		return -EINVAL;

	t->p = p;
	t->params_set = true;
	return 0;
}

void pciem_topo_set_reach_cb(struct pciem_topo *t, void (*cb)(void *data, bool reachable),
							 void *data)
{
	t->reach_cb = cb;
	t->reach_data = data;
}

static void topo_apply_defaults(struct pciem_topo *t)
{
	struct pciem_topology *p = &t->p;

	p->rp_speed = topo_default(p->rp_speed, PCIEM_LINK_SPEED_32GT);
	p->rp_width = topo_default(p->rp_width, 16);
	p->dsp_speed = topo_default(p->dsp_speed, PCIEM_LINK_SPEED_32GT);
	p->dsp_width = topo_default(p->dsp_width, 8);
	p->ep_speed = topo_default(p->ep_speed, PCIEM_LINK_SPEED_32GT);
	p->ep_width = topo_default(p->ep_width, 8);
	if (p->eq_fail_above == 0)
		p->eq_fail_above = pciem_link_default_eq_limit() ?: PCIEM_EQ_LIMIT_NONE;
	if (!p->rrs_ms)
		p->rrs_ms = min_t(u32, pciem_link_default_rrs_ms(), 60000);
}

struct bar_slot {
	u32 idx;
	resource_size_t size;
	resource_size_t off;
};

static int bar_cmp(const void *a, const void *b)
{
	const struct bar_slot *x = a, *y = b;

	if (x->size != y->size)
		return x->size > y->size ? -1 : 1;
	return (int)x->idx - (int)y->idx;
}

static int topo_layout_class(struct pciem_root_complex *v, bool pref, int ci,
							 struct list_head *windows)
{
	struct pciem_topo *t = v->topo;
	struct bar_slot slots[PCI_STD_NUM_BARS];
	resource_size_t cursor = 0, total, align = SZ_1M;
	struct pciem_topo_chunk *c = &t->chunk[ci];
	struct resource_entry *entry;
	struct resource *res;
	phys_addr_t base;
	int n = 0, i;

	for (i = 0; i < PCI_STD_NUM_BARS; i++) {
		struct pciem_bar_info *b = &v->bars[i];

		if (!b->size)
			continue;
		if (b->flags & PCI_BASE_ADDRESS_SPACE_IO) {
			pr_err("BAR%d: I/O BARs are not supported with a placement\n", i);
			return -EINVAL;
		}
		if (!!(b->flags & PCI_BASE_ADDRESS_MEM_PREFETCH) != pref)
			continue;
		slots[n].idx = i;
		slots[n].size = b->size;
		n++;
	}
	if (!n)
		return 0;

	sort(slots, n, sizeof(slots[0]), bar_cmp, NULL);
	for (i = 0; i < n; i++) {
		cursor = ALIGN(cursor, slots[i].size);
		slots[i].off = cursor;
		cursor += slots[i].size;
		align = max(align, slots[i].size);
	}
	total = ALIGN(cursor, SZ_1M);

	base = pciem_pool_alloc_aligned(total, align);
	if (!base)
		return -ENOMEM;
	if (!pref && base + total > SZ_4G) {
		pr_err("non-prefetchable BARs at 0x%llx are above 4 GiB, which a bridge memory window cannot cover\n",
			   (u64)base);
		pciem_pool_free(base, total);
		return -EINVAL;
	}

	res = kzalloc(sizeof(*res), GFP_KERNEL);
	if (!res) {
		pciem_pool_free(base, total);
		return -ENOMEM;
	}
	res->name = pref ? "PCI BAR chunk (prefetchable)" : "PCI BAR chunk";
	res->start = base;
	res->end = base + total - 1;
	res->flags = IORESOURCE_MEM | (pref ? IORESOURCE_PREFETCH | IORESOURCE_MEM_64 : 0);
	if (pciem_pool_insert(res)) {
		kfree(res);
		pciem_pool_free(base, total);
		return -EBUSY;
	}
	entry = resource_list_create_entry(res, 0);
	if (!entry) {
		release_resource(res);
		kfree(res);
		pciem_pool_free(base, total);
		return -ENOMEM;
	}
	resource_list_add_tail(entry, windows);

	c->res = res;
	c->start = base;
	c->size = total;

	for (i = 0; i < n; i++) {
		struct pciem_bar_info *b = &v->bars[slots[i].idx];

		b->carved_start = base + slots[i].off;
		b->carved_end = b->carved_start + b->size - 1;
		b->in_chunk = true;
	}
	return 0;
}

int pciem_topo_layout_bars(struct pciem_root_complex *v, struct list_head *windows)
{
	int ret;

	ret = topo_layout_class(v, true, 1, windows);
	if (!ret)
		ret = topo_layout_class(v, false, 0, windows);
	if (ret)
		pciem_topo_free_chunks(v->topo);
	return ret;
}

void pciem_topo_free_chunks(struct pciem_topo *t)
{
	int i;

	for (i = 0; i < 2; i++) {
		struct pciem_topo_chunk *c = &t->chunk[i];

		if (!c->res)
			continue;
		if (c->res->parent)
			release_resource(c->res);
		kfree(c->res);
		pciem_pool_free(c->start, c->size);
		memset(c, 0, sizeof(*c));
	}
}

static void port_set_buses(struct pciem_port *p, u8 pri, u8 sec, u8 sub)
{
	p->cfg[PCI_PRIMARY_BUS] = pri;
	p->cfg[PCI_SECONDARY_BUS] = sec;
	p->cfg[PCI_SUBORDINATE_BUS] = sub;
}

static void port_set_windows(struct pciem_port *p, struct pciem_topo *t)
{
	struct pciem_topo_chunk *np = &t->chunk[0], *pf = &t->chunk[1];

	if (np->size) {
		w16(p, PCI_MEMORY_BASE, (np->start >> 16) & 0xfff0);
		w16(p, PCI_MEMORY_LIMIT, ((np->start + np->size - 1) >> 16) & 0xfff0);
	}
	if (pf->size) {
		u64 end = pf->start + pf->size - 1;

		w16(p, PCI_PREF_MEMORY_BASE, ((pf->start >> 16) & 0xfff0) | 1);
		w16(p, PCI_PREF_MEMORY_LIMIT, ((end >> 16) & 0xfff0) | 1);
		w32(p, PCI_PREF_BASE_UPPER32, pf->start >> 32);
		w32(p, PCI_PREF_LIMIT_UPPER32, end >> 32);
	}
}

int pciem_topo_program(struct pciem_topo *t, int domain, u8 root_bus)
{
	struct pciem_root_complex *v = t->v;
	u8 depth = pciem_topo_depth(t);
	struct pciem_port *rp = PCIEM_PORT_RP(t), *usp = PCIEM_PORT_USP(t), *dsp = PCIEM_PORT_DSP(t);
	u8 eq;

	topo_apply_defaults(t);
	t->domain = domain;
	t->root_bus = root_bus;
	t->ep_bus = root_bus + depth;
	INIT_WORK(&t->work, topo_work_func);

	rp->speed = t->p.rp_speed;
	rp->width = t->p.rp_width;
	usp->speed = PCIEM_LINK_SPEED_32GT;
	usp->width = 16;
	dsp->speed = t->p.dsp_speed;
	dsp->width = t->p.dsp_width;
	rp->bus = root_bus;
	usp->bus = root_bus + 1;
	dsp->bus = root_bus + 2;

	rp->hotplug = (t->p.flags & PCIEM_TOPO_FLAG_HOTPLUG) && t->nports == 1;
	dsp->hotplug = (t->p.flags & PCIEM_TOPO_FLAG_HOTPLUG) && t->nports == 3;

	rp->vecs = &rp->msi_store;
	dsp->vecs = &dsp->msi_store;
	pciem_msi_vecs_init(rp->vecs);
	pciem_msi_vecs_init(dsp->vecs);

	port_build(rp);
	port_set_windows(rp, t);
	if (t->nports == 1) {
		port_set_buses(rp, root_bus, root_bus + 1, root_bus + 1);
		t->ep_link = &t->links[0];
	} else {
		port_build(usp);
		port_build(dsp);
		port_set_windows(usp, t);
		port_set_windows(dsp, t);
		port_set_buses(rp, root_bus, root_bus + 1, root_bus + 3);
		port_set_buses(usp, root_bus + 1, root_bus + 2, root_bus + 3);
		port_set_buses(dsp, root_bus + 2, root_bus + 3, root_bus + 3);
		t->ep_link = &t->links[1];
	}

	pciem_link_init(&t->links[0], t, rp, NULL);
	if (t->nports == 3)
		pciem_link_init(&t->links[1], t, dsp, &t->links[0]);

	eq = t->p.eq_fail_above == PCIEM_EQ_LIMIT_NONE ? 0 : t->p.eq_fail_above;
	t->ep_link->eq_limit = eq;
	t->links[0].rrs_ms = t->p.rrs_ms;
	t->links[1].rrs_ms = t->p.rrs_ms;

	return pciem_cap_pcie_topo_setup(v, t->p.ep_speed, t->p.ep_width);
}

static int topo_walk_fn(struct pci_dev *pdev, void *data)
{
	dev_set_msi_domain(&pdev->dev, pciem_msi_domain());
	return 0;
}

void pciem_topo_scanned(struct pciem_topo *t, struct pci_bus *root)
{
	int i;

	pci_walk_bus(root, topo_walk_fn, NULL);
	for (i = 0; i < t->nports; i++)
		t->ports[i].pdev = pci_get_domain_bus_and_slot(t->domain, t->ports[i].bus, 0);
}

void pciem_topo_release_pdevs(struct pciem_topo *t)
{
	int i;

	for (i = 0; i < 3; i++) {
		pci_dev_put(t->ports[i].pdev);
		t->ports[i].pdev = NULL;
	}
}

void pciem_topo_start(struct pciem_topo *t)
{
	struct pciem_plink *rpl = &t->links[0];

	pciem_trace_phase(t->v->trace, PT_PH_TRAIN_BEGIN);
	scoped_guard(raw_spinlock_irqsave, &t->lock) {
		t->registered = true;
		if (t->nports == 3) {
			rpl->partner = true;
			rpl->partner_speed = PCIEM_LINK_SPEED_32GT;
			rpl->partner_width = 16;
			t->links[1].partner = true;
			t->links[1].partner_speed = t->p.ep_speed;
			t->links[1].partner_width = t->p.ep_width;
		} else {
			rpl->partner = true;
			rpl->partner_speed = t->p.ep_speed;
			rpl->partner_width = t->p.ep_width;
		}
	}
	pciem_link_start(rpl);
	if (t->nports == 3)
		pciem_link_start(&t->links[1]);
}

static bool topo_settled(struct pciem_topo *t)
{
	bool ok;

	guard(raw_spinlock_irqsave)(&t->lock);
	ok = pciem_link_settled(&t->links[0]);
	if (t->nports == 3)
		ok = ok && pciem_link_settled(&t->links[1]);
	return ok;
}

void pciem_topo_wait_trained(struct pciem_topo *t)
{
	long left = wait_event_timeout(t->trained_wq, topo_settled(t),
								   msecs_to_jiffies(pciem_link_train_timeout_ms()));

	if (!left)
		pr_warn("links not settled after %u ms, continuing\n", pciem_link_train_timeout_ms());
	pciem_trace_phase(t->v->trace, PT_PH_TRAIN_DONE);
}

void pciem_topo_quiesce(struct pciem_topo *t)
{
	int i;

	WRITE_ONCE(t->dying, true);
	for (i = 0; i < (t->nports == 3 ? 2 : 1) && t->registered; i++)
		pciem_link_stop(&t->links[i]);
	if (t->registered)
		cancel_work_sync(&t->work);
}

static struct pciem_port *port_next(struct pciem_topo *t, struct pciem_port *p)
{
	switch (p->role) {
	case PCIEM_ROLE_RP:
		return t->nports == 3 ? PCIEM_PORT_USP(t) : NULL;
	case PCIEM_ROLE_USP:
		return PCIEM_PORT_DSP(t);
	default:
		return NULL;
	}
}

enum { RT_NONE, RT_UR, RT_PORT, RT_EP };

struct pciem_route {
	u8 kind;
	bool rrs;
	struct pciem_port *port;
};

static void topo_route(struct pciem_topo *t, u8 busnr, unsigned int devfn, struct pciem_route *rt)
{
	struct pciem_port *p = PCIEM_PORT_RP(t), *nxt;

	rt->kind = RT_NONE;
	rt->rrs = false;
	rt->port = NULL;

	if (busnr == t->root_bus) {
		if (devfn == 0) {
			rt->kind = RT_PORT;
			rt->port = p;
		}
		return;
	}

	for (;;) {
		u8 sec = p->cfg[PCI_SECONDARY_BUS], sub = p->cfg[PCI_SUBORDINATE_BUS];

		if (!sec || busnr < sec || busnr > sub)
			return;
		if (p->link && !p->link->dl_up) {
			rt->kind = RT_UR;
			return;
		}
		nxt = port_next(t, p);
		if (busnr == sec) {
			if (PCI_SLOT(devfn))
				return;
			if (!nxt) {
				if (PCI_FUNC(devfn))
					return;
				rt->kind = RT_EP;
				rt->rrs = ktime_before(ktime_get(), p->link->rrs_until);
				return;
			}
			if (PCI_FUNC(devfn) == 0) {
				rt->kind = RT_PORT;
				rt->port = nxt;
			}
			return;
		}
		if (!nxt)
			return;
		p = nxt;
	}
}

bool pciem_topo_bdf_is_ep(struct pciem_topo *t, struct pci_bus *bus, unsigned int devfn)
{
	struct pciem_route rt;

	guard(raw_spinlock_irqsave)(&t->lock);
	topo_route(t, bus->number, devfn, &rt);
	return rt.kind == RT_EP;
}

struct pciem_msi_vecs *pciem_topo_msi_vecs(struct pciem_topo *t, struct pci_bus *bus,
										   unsigned int devfn)
{
	struct pciem_route rt;

	guard(raw_spinlock_irqsave)(&t->lock);
	topo_route(t, bus->number, devfn, &rt);
	if (rt.kind == RT_EP)
		return &t->v->msi;
	if (rt.kind == RT_PORT)
		return rt.port->vecs;
	return NULL;
}

static u32 port_read(struct pciem_port *p, int off, int size)
{
	u32 val = 0;
	int i;

	for (i = 0; i < size; i++)
		if (off + i < PCIEM_PORT_CFG_SIZE)
			val |= (u32)p->cfg[off + i] << (8 * i);
	return val;
}

static void port_reset_regs(struct pciem_port *p)
{
	port_build(p);
	pciem_trace_reset(p->topo->v->trace, p->fn, PT_RESET_POWER_ON);
}

void pciem_topo_ep_reset_hot(struct pciem_topo *t)
{
	pciem_function_reset(t->v, PCIEM_RESET_HOT);
}

static void topo_reset_below(struct pciem_topo *t, struct pciem_port *p)
{
	if (p->role == PCIEM_ROLE_RP && t->nports == 3) {
		port_reset_regs(PCIEM_PORT_USP(t));
		port_reset_regs(PCIEM_PORT_DSP(t));
		pciem_link_hot_reset_from_above(&t->links[1]);
	} else if (p->role == PCIEM_ROLE_USP) {
		port_reset_regs(PCIEM_PORT_DSP(t));
		pciem_link_hot_reset_from_above(&t->links[1]);
	}
	pciem_topo_ep_reset_hot(t);
}

void pciem_port_irq(struct pciem_port *p, u8 cause)
{
	struct pciem_topo *t = p->topo;

	t->pending |= BIT(port_index(p) * 8 + cause);
	pciem_topo_kick_work(t);
}

void pciem_port_lnksta_set(struct pciem_port *p, int cls, int nlw, int lt, int dllla)
{
	int off = p->pcie + PCI_EXP_LNKSTA;
	u16 old = r16(p, off), new = old;

	if (cls >= 0)
		new = (new & ~PCI_EXP_LNKSTA_CLS) | (cls & PCI_EXP_LNKSTA_CLS);
	if (nlw >= 0)
		new = (new & ~PCI_EXP_LNKSTA_NLW) | ((nlw << 4) & PCI_EXP_LNKSTA_NLW);
	if (lt >= 0)
		new = lt ? new | PCI_EXP_LNKSTA_LT : new & ~PCI_EXP_LNKSTA_LT;
	if (dllla >= 0)
		new = dllla ? new | PCI_EXP_LNKSTA_DLLLA : new & ~PCI_EXP_LNKSTA_DLLLA;
	if (new == old)
		return;
	w16(p, off, new);
	pciem_trace_lnksta(p->topo->v->trace, p->fn, old, new, true);
}

void pciem_port_lnksta_mirror(struct pciem_port *p, u8 cls, u8 nlw)
{
	int off = p->pcie + PCI_EXP_LNKSTA;
	u16 old = r16(p, off);
	u16 new = (old & ~(PCI_EXP_LNKSTA_CLS | PCI_EXP_LNKSTA_NLW)) | cls | ((u16)nlw << 4);

	if (new == old)
		return;
	w16(p, off, new);
	pciem_trace_lnksta(p->topo->v->trace, p->fn, old, new, true);
}

void pciem_port_lnksta_flag(struct pciem_port *p, u16 flag)
{
	int off = p->pcie + PCI_EXP_LNKSTA;
	u16 old = r16(p, off);
	u16 ctl;

	if (old & flag)
		return;
	w16(p, off, old | flag);
	pciem_trace_lnksta(p->topo->v->trace, p->fn, old, old | flag, true);
	ctl = r16(p, p->pcie + PCI_EXP_LNKCTL);
	if (flag == PCI_EXP_LNKSTA_LBMS && (ctl & LNKCTL_LBMIE))
		pciem_port_irq(p, PT_IRQ_LBMS);
	if (flag == PCI_EXP_LNKSTA_LABS && (ctl & LNKCTL_LABIE))
		pciem_port_irq(p, PT_IRQ_LABS);
}

void pciem_port_lnksta2_eq(struct pciem_port *p, bool done)
{
	int off = p->pcie + PCI_EXP_LNKSTA2;
	u16 v = r16(p, off);

	w16(p, off, done ? v | LNKSTA2_EQ_ALL : v & ~LNKSTA2_EQ_ALL);
}

static void port_slot_status(struct pciem_port *p, u16 bit, u8 cause, u16 enable)
{
	int off = p->pcie + PCI_EXP_SLTSTA;
	u16 old = r16(p, off), ctl;

	if (p->role == PCIEM_ROLE_USP || (old & bit))
		return;
	w16(p, off, old | bit);
	pciem_trace_reg(p->topo->v->trace, PT_EV_SLTSTA, p->fn, PT_REG_SLTSTA, old, old | bit, true);
	ctl = r16(p, p->pcie + PCI_EXP_SLTCTL);
	if ((ctl & SLTCTL_HPIE) && (ctl & enable))
		pciem_port_irq(p, cause);
}

void pciem_port_dllsc(struct pciem_port *p)
{
	port_slot_status(p, SLTSTA_DLLSC, PT_IRQ_DLLSC, SLTCTL_DLLSCE);
}

static void root_report(struct pciem_port *rp, struct pciem_port *src, bool fatal)
{
	u32 st = r32(rp, PCIEM_PORT_AER + PCI_ERR_ROOT_STATUS), old = st;
	u32 cmd = r32(rp, PCIEM_PORT_AER + PCI_ERR_ROOT_COMMAND);
	u32 id = r32(rp, PCIEM_PORT_AER + PCI_ERR_ROOT_ERR_SRC);

	if (st & ROOT_ERR_UNCOR) {
		st |= ROOT_ERR_MULTI_UNCOR;
	} else {
		st |= ROOT_ERR_UNCOR;
		if (fatal)
			st |= ROOT_ERR_FIRST_FATAL;
	}
	st |= fatal ? ROOT_ERR_FATAL : ROOT_ERR_NONFATAL;
	id = (id & 0xffff) | ((u32)src->bus << 24);
	w32(rp, PCIEM_PORT_AER + PCI_ERR_ROOT_STATUS, st);
	w32(rp, PCIEM_PORT_AER + PCI_ERR_ROOT_ERR_SRC, id);
	pciem_trace_reg(rp->topo->v->trace, PT_EV_AER, rp->fn, PT_REG_ROOTSTA, old, st, true);
	if (cmd & (fatal ? 0x4 : 0x2))
		pciem_port_irq(rp, PT_IRQ_AER);
}

void pciem_port_sdes(struct pciem_port *p)
{
	int a = PCIEM_PORT_AER;
	u32 old = r32(p, a + PCI_ERR_UNCOR_STATUS);
	bool fatal;
	u16 devctl, devsta;

	if (!p->downstream)
		return;
	w32(p, a + PCI_ERR_UNCOR_STATUS, old | UE_SDES);
	pciem_trace_reg(p->topo->v->trace, PT_EV_AER, p->fn, PT_REG_UESTA, old, old | UE_SDES, true);
	if (r32(p, a + PCI_ERR_UNCOR_MASK) & UE_SDES)
		return;

	fatal = r32(p, a + PCI_ERR_UNCOR_SEVER) & UE_SDES;
	devsta = r16(p, p->pcie + PCI_EXP_DEVSTA);
	w16(p, p->pcie + PCI_EXP_DEVSTA, devsta | (fatal ? PCI_EXP_DEVSTA_FED : PCI_EXP_DEVSTA_NFED));
	devctl = r16(p, p->pcie + PCI_EXP_DEVCTL);
	if (devctl & (fatal ? PCI_EXP_DEVCTL_FERE : PCI_EXP_DEVCTL_NFERE))
		root_report(PCIEM_PORT_RP(p->topo), p, fatal);
}

static void port_post_write(struct pciem_port *p, u16 o_lnkctl, u16 o_lnkctl2, u16 o_brctl,
							u16 o_sltctl, u16 o_rootctl, u16 o_msi, u16 o_lnksta, u16 o_sltsta,
							u32 o_uesta, u32 o_rootsta, bool rl)
{
	struct pciem_topo *t = p->topo;
	struct pciem_root_complex *v = t->v;
	int c = p->pcie;
	u16 n;

	n = r16(p, c + PCI_EXP_LNKCTL);
	if (p->downstream) {
		if (rl) {
			pciem_trace_ctl(v->trace, p->fn, PT_CTL_RETRAIN, n);
			pciem_link_retrain(p->link);
		}
		if ((o_lnkctl ^ n) & LNKCTL_LD) {
			pciem_trace_ctl(v->trace, p->fn, n & LNKCTL_LD ? PT_CTL_LD_ON : PT_CTL_LD_OFF, n);
			pciem_link_disable(p->link, n & LNKCTL_LD);
		}
	}
	if ((o_lnkctl ^ n) & ~LNKCTL_RL & ~LNKCTL_LD)
		pciem_trace_ctl(v->trace, p->fn, PT_CTL_LNKCTL, n);

	n = r16(p, c + PCI_EXP_LNKCTL2);
	if ((o_lnkctl2 ^ n) & PCI_EXP_LNKCTL2_TLS)
		pciem_trace_ctl(v->trace, p->fn, PT_CTL_TLS, n & PCI_EXP_LNKCTL2_TLS);

	n = r16(p, PCI_BRIDGE_CONTROL);
	if ((o_brctl ^ n) & BRCTL_SBR) {
		bool set = n & BRCTL_SBR;

		pciem_trace_ctl(v->trace, p->fn, set ? PT_CTL_SBR_ON : PT_CTL_SBR_OFF, n);
		if (p->downstream) {
			pciem_link_sbr(p->link, set);
			if (set)
				topo_reset_below(t, p);
		} else if (set) {
			topo_reset_below(t, p);
		}
	}

	if (p->role != PCIEM_ROLE_USP) {
		n = r16(p, c + PCI_EXP_SLTCTL);
		if (n != o_sltctl)
			pciem_trace_ctl(v->trace, p->fn, PT_CTL_SLTCTL, n);
		n = r16(p, c + PCI_EXP_SLTSTA);
		if (n != o_sltsta)
			pciem_trace_reg(v->trace, PT_EV_SLTSTA, p->fn, PT_REG_SLTSTA, o_sltsta, n, false);
		n = r16(p, PCIEM_PORT_MSI + PCI_MSI_FLAGS);
		if (n != o_msi)
			pciem_trace_ctl(v->trace, p->fn, PT_CTL_MSI, n);
	}
	if (p->role == PCIEM_ROLE_RP) {
		n = r16(p, c + PCI_EXP_RTCTL);
		if (n != o_rootctl)
			pciem_trace_ctl(v->trace, p->fn, PT_CTL_ROOTCTL, n);
		if (r32(p, PCIEM_PORT_AER + PCI_ERR_ROOT_STATUS) != o_rootsta)
			pciem_trace_reg(v->trace, PT_EV_AER, p->fn, PT_REG_ROOTSTA, o_rootsta,
							r32(p, PCIEM_PORT_AER + PCI_ERR_ROOT_STATUS), false);
	}
	if (r32(p, PCIEM_PORT_AER + PCI_ERR_UNCOR_STATUS) != o_uesta)
		pciem_trace_reg(v->trace, PT_EV_AER, p->fn, PT_REG_UESTA, o_uesta,
						r32(p, PCIEM_PORT_AER + PCI_ERR_UNCOR_STATUS), false);
	n = r16(p, c + PCI_EXP_LNKSTA);
	if ((n ^ o_lnksta) & (PCI_EXP_LNKSTA_LBMS | PCI_EXP_LNKSTA_LABS))
		pciem_trace_lnksta(v->trace, p->fn, o_lnksta, n, false);
}

static void port_write(struct pciem_port *p, int off, int size, u32 val)
{
	int c = p->pcie;
	u16 o_lnkctl = r16(p, c + PCI_EXP_LNKCTL), o_lnkctl2 = r16(p, c + PCI_EXP_LNKCTL2);
	u16 o_brctl = r16(p, PCI_BRIDGE_CONTROL), o_lnksta = r16(p, c + PCI_EXP_LNKSTA);
	u16 o_sltctl = 0, o_sltsta = 0, o_rootctl = 0, o_msi = 0;
	u32 o_uesta = r32(p, PCIEM_PORT_AER + PCI_ERR_UNCOR_STATUS), o_rootsta = 0;
	bool rl = false;
	int i;

	if (p->role != PCIEM_ROLE_USP) {
		o_sltctl = r16(p, c + PCI_EXP_SLTCTL);
		o_sltsta = r16(p, c + PCI_EXP_SLTSTA);
		o_msi = r16(p, PCIEM_PORT_MSI + PCI_MSI_FLAGS);
	}
	if (p->role == PCIEM_ROLE_RP) {
		o_rootctl = r16(p, c + PCI_EXP_RTCTL);
		o_rootsta = r32(p, PCIEM_PORT_AER + PCI_ERR_ROOT_STATUS);
	}

	for (i = 0; i < size; i++) {
		int o = off + i;
		u8 b = val >> (8 * i);

		if (o >= PCIEM_PORT_CFG_SIZE)
			break;
		if (p->downstream && o == c + PCI_EXP_LNKCTL && (b & LNKCTL_RL))
			rl = true;
		p->cfg[o] &= ~(b & p->w1c[o]);
		p->cfg[o] = (p->cfg[o] & ~p->rw[o]) | (b & p->rw[o]);
	}

	port_post_write(p, o_lnkctl, o_lnkctl2, o_brctl, o_sltctl, o_rootctl, o_msi, o_lnksta, o_sltsta,
					o_uesta, o_rootsta, rl);
}

static u8 route_fn(const struct pciem_route *rt, unsigned int devfn)
{
	if (rt->kind == RT_PORT)
		return rt->port->fn;
	if (rt->kind == RT_EP)
		return PT_FN_EP0 + PCI_FUNC(devfn);
	return PT_FN_NONE;
}

int pciem_topo_cfg_read(struct pciem_topo *t, u8 busnr, unsigned int devfn, int where, int size,
						u32 *value, struct pciem_root_complex **ep)
{
	struct pciem_route rt;
	unsigned long flags;
	u8 res = PT_RES_OK;
	int ret = PCIBIOS_SUCCESSFUL;
	u32 val = ~0U;
	bool root_rrs;

	*ep = NULL;
	raw_spin_lock_irqsave(&t->lock, flags);
	topo_route(t, busnr, devfn, &rt);
	switch (rt.kind) {
	case RT_NONE:
		res = PT_RES_NODEV;
		ret = PCIBIOS_DEVICE_NOT_FOUND;
		break;
	case RT_UR:
		res = PT_RES_UR;
		break;
	case RT_PORT:
		if (where < 0 || where + size > PCI_CFG_SPACE_EXP_SIZE) {
			ret = PCIBIOS_DEVICE_NOT_FOUND;
			res = PT_RES_NODEV;
		} else {
			val = port_read(rt.port, where, size);
		}
		break;
	case RT_EP:
		if (!rt.rrs) {
			*ep = t->v;
			break;
		}
		res = PT_RES_RRS;
		root_rrs = r16(PCIEM_PORT_RP(t), PCIEM_PORT_PCIE + PCI_EXP_RTCTL) & RTCTL_RRS_SVE;
		if (root_rrs && where <= 0 && where + size > 0) {
			val = size == 4 ? 0xffff0001 : 0x0001;
			if (size == 1)
				val = 0x01;
		}
		break;
	}
	raw_spin_unlock_irqrestore(&t->lock, flags);

	if (!*ep) {
		*value = val;
		pciem_trace_cfg_access(t->v->trace, route_fn(&rt, devfn), busnr, devfn, false, where, size,
							   val, res);
	}
	return ret;
}

int pciem_topo_cfg_write(struct pciem_topo *t, u8 busnr, unsigned int devfn, int where, int size,
						 u32 value, struct pciem_root_complex **ep)
{
	struct pciem_route rt;
	unsigned long flags;
	u8 res = PT_RES_OK;
	int ret = PCIBIOS_SUCCESSFUL;

	*ep = NULL;
	raw_spin_lock_irqsave(&t->lock, flags);
	topo_route(t, busnr, devfn, &rt);
	switch (rt.kind) {
	case RT_NONE:
		res = PT_RES_NODEV;
		ret = PCIBIOS_DEVICE_NOT_FOUND;
		break;
	case RT_UR:
		res = PT_RES_UR;
		break;
	case RT_PORT:
		if (where < 0 || where + size > PCI_CFG_SPACE_EXP_SIZE) {
			ret = PCIBIOS_DEVICE_NOT_FOUND;
			res = PT_RES_NODEV;
		} else if (size != 1 && size != 2 && size != 4) {
			ret = PCIBIOS_FUNC_NOT_SUPPORTED;
		} else {
			port_write(rt.port, where, size, value);
		}
		break;
	case RT_EP:
		if (!rt.rrs) {
			*ep = t->v;
			break;
		}
		res = PT_RES_RRS;
		break;
	}
	raw_spin_unlock_irqrestore(&t->lock, flags);

	if (!*ep)
		pciem_trace_cfg_access(t->v->trace, route_fn(&rt, devfn), busnr, devfn, true, where, size,
							   value, res);
	return ret;
}

void pciem_topo_dev_down(struct pciem_topo *t)
{
	scoped_guard(raw_spinlock_irqsave, &t->lock) {
		t->dev_down = true;
		pciem_link_partner(t->ep_link, false, 0, 0);
	}
	pciem_topo_kick_work(t);
}

int pciem_topo_dev_up(struct pciem_topo *t, u8 speed, u8 width)
{
	scoped_guard(raw_spinlock_irqsave, &t->lock) {
		t->dev_down = false;
		pciem_link_partner(t->ep_link, true, speed, width);
	}
	pciem_topo_kick_work(t);
	return 0;
}

bool pciem_topo_dev_is_down(struct pciem_topo *t)
{
	guard(raw_spinlock_irqsave)(&t->lock);
	return t->dev_down;
}

int pciem_topo_set_eq_limit(struct pciem_topo *t, u8 speed)
{
	guard(raw_spinlock_irqsave)(&t->lock);
	pciem_link_set_eq_limit(t->ep_link, speed);
	return 0;
}

int pciem_topo_link_read(struct pciem_topo *t, char *buf, size_t len)
{
	struct pciem_port *p = t->ep_link->port;
	u16 sta;
	bool up;

	scoped_guard(raw_spinlock_irqsave, &t->lock) {
		up = !t->dev_down && t->ep_link->dl_up;
		sta = r16(p, p->pcie + PCI_EXP_LNKSTA);
	}
	if (!up)
		return scnprintf(buf, len, "down\n");
	return scnprintf(buf, len, "up %u %u\n", sta & PCI_EXP_LNKSTA_CLS,
					 (sta & PCI_EXP_LNKSTA_NLW) >> 4);
}

static void topo_work_func(struct work_struct *work)
{
	struct pciem_topo *t = container_of(work, struct pciem_topo, work);
	bool msi_en[3] = {};
	bool reach;
	u32 pend;
	int i;

	scoped_guard(raw_spinlock_irqsave, &t->lock) {
		pend = t->pending;
		t->pending = 0;
		reach = !t->dev_down && t->ep_link->dl_up;
		for (i = 0; i < t->nports; i++)
			if (t->ports[i].role != PCIEM_ROLE_USP)
				msi_en[i] = r16(&t->ports[i], PCIEM_PORT_MSI + PCI_MSI_FLAGS) & PCI_MSI_FLAGS_ENABLE;
	}

	for (i = 0; i < 3 * 8; i++) {
		struct pciem_port *p = &t->ports[i / 8];
		bool sent = false;

		if (!(pend & BIT(i)))
			continue;
		if (msi_en[i / 8] && p->vecs)
			sent = !pciem_msi_deliver(p->vecs, 0);
		pciem_trace_irq(t->v->trace, p->fn, i % 8, 0, sent);
	}

	if (t->reach_cb && reach != t->reach_last) {
		t->reach_last = reach;
		t->reach_cb(t->reach_data, reach);
	}
	wake_up(&t->trained_wq);
}

static int topology_show(struct seq_file *m, void *unused)
{
	pciem_topology_json_show(m->private, m);
	return 0;
}

static int topology_open(struct inode *inode, struct file *file)
{
	return single_open(file, topology_show, inode->i_private);
}

static const struct file_operations topology_fops = {
	.owner = THIS_MODULE,
	.open = topology_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

void pciem_topology_json_show(struct pciem_root_complex *v, struct seq_file *m)
{
	struct pciem_topo *t = v->topo;
	struct pciem_host_bridge_priv *priv = v->bridge_priv;
	int domain = v->mode_state.virtual_root.assigned_domain;
	int root = v->mode_state.virtual_root.assigned_busnr;
	int i, f;
	bool first = true;

	seq_printf(m, "{\"placement\":\"%s\",\"domain\":%d,\"root_bus\":%d,\"functions\":[",
			   pciem_placement_names[v->placement], domain, root);
	if (t) {
		scoped_guard(raw_spinlock_irqsave, &t->lock) {
			for (i = 0; i < t->nports; i++) {
				struct pciem_port *p = &t->ports[i];

				seq_printf(m, "%s{\"role\":\"%s\",\"bdf\":\"%04x:%02x:00.0\",\"sec\":%u,\"sub\":%u}",
						   first ? "" : ",", port_name(p->role), domain, p->bus,
						   p->cfg[PCI_SECONDARY_BUS], p->cfg[PCI_SUBORDINATE_BUS]);
				first = false;
			}
		}
		seq_printf(m, "%s{\"role\":\"ep0\",\"bdf\":\"%04x:%02x:00.0\"}", first ? "" : ",", domain,
				   t->ep_bus);
	} else {
		for (f = 0; priv && f < PCIEM_MAX_FUNCTIONS; f++) {
			if (!priv->funcs[f])
				continue;
			seq_printf(m, "%s{\"role\":\"ep%d\",\"bdf\":\"%04x:%02x:00.%d\"}", first ? "" : ",", f,
					   domain, root, f);
			first = false;
		}
	}
	seq_puts(m, "]}\n");
}

void pciem_topo_debugfs_create(struct pciem_topo *t, struct dentry *dir)
{
	int i;

	if (!t)
		return;
	for (i = 0; i < t->nports; i++) {
		struct pciem_port *p = &t->ports[i];

		if (!p->link)
			continue;
		p->link->dir = debugfs_create_dir(port_name(p->role), dir);
		pciem_plink_debugfs_create(p->link, p->link->dir);
	}
}

void pciem_topology_debugfs_file(struct pciem_root_complex *v, struct dentry *dir)
{
	debugfs_create_file("topology", 0400, dir, v, &topology_fops);
}
