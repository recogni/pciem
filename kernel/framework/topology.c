// SPDX-License-Identifier: GPL-2.0-only
#define pr_fmt(fmt) KBUILD_MODNAME ": topo: " fmt

#include "pciem.h"
#include "capabilities.h"
#include "msi_domain.h"
#include "pool.h"
#include "iommu_stub.h"
#include "topology.h"

#include <linux/ioport.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/sizes.h>
#include <linux/sort.h>

static const u16 pciem_bridge_ids[] = { PCIEM_BRIDGE_DEVICE_RP, PCIEM_BRIDGE_DEVICE_USP, PCIEM_BRIDGE_DEVICE_DSP };

#define PCIEM_PORT_PCIE 0x40
#define PCIEM_PORT_MSI  0x80
#define PCIEM_PORT_PM   0xa0
#define PCIEM_PORT_AER  0x100
#define PCIEM_PORT_DPC  0x140
#define PCIEM_PORT_ACS  0x180
#define ACS_CAPS       0x001f

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

u8 pciem_topo_depth(const struct pciem_topo *t)
{
	return t->placement == PCIEM_PLACEMENT_SWITCH ? 2 + t->p.switch_ports : 1;
}

static DEFINE_MUTEX(pciem_switch_lock);
static LIST_HEAD(pciem_switches);

struct mutex *pciem_switch_mutex(void)
{
	return &pciem_switch_lock;
}

struct pciem_trace *pciem_port_trace(struct pciem_port *p)
{
	if (p->slot && p->slot->v)
		return p->slot->v->trace;
	return p->topo->trace;
}

struct pciem_trace *pciem_link_trace(struct pciem_plink *l)
{
	return pciem_port_trace(l->port);
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
	bool acs = ds;
	int c = p->pcie;
	u32 lnkcap, sltcap = 0, uemsk, ue_impl, a = PCIEM_PORT_AER;
	u8 type = rp ? PCI_EXP_TYPE_ROOT_PORT :
			  p->role == PCIEM_ROLE_USP ? PCI_EXP_TYPE_UPSTREAM : PCI_EXP_TYPE_DOWNSTREAM;
	u8 speed = p->speed;

	memset(p->cfg, 0, sizeof(p->cfg));
	memset(p->rw, 0, sizeof(p->rw));
	memset(p->w1c, 0, sizeof(p->w1c));

	w16(p, PCI_VENDOR_ID, PCIEM_BRIDGE_VENDOR_ID);
	w16(p, PCI_DEVICE_ID, pciem_bridge_ids[p->role]);
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
	p->cfg[c + 1] = slot ? PCIEM_PORT_MSI : PCIEM_PORT_PM;
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
		sltcap = SLTCAP_NCCS | ((u32)p->slot_nr << 19);
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
		p->cfg[m + 1] = PCIEM_PORT_PM;
	}

	p->cfg[PCIEM_PORT_PM] = PCI_CAP_ID_PM;
	w16(p, PCIEM_PORT_PM + PCI_PM_PMC, 3);
	w16(p, PCIEM_PORT_PM + PCI_PM_CTRL, PCI_PM_CTRL_NO_SOFT_RESET);
	rwm(p, PCIEM_PORT_PM + PCI_PM_CTRL, 2, PCI_PM_CTRL_STATE_MASK);

	ue_impl = 0x001ff010 | (ds ? UE_SDES : 0);
	uemsk = 0x00100000 | ((ds && !(t->p.flags & PCIEM_TOPO_FLAG_UNMASK_SDES)) ? UE_SDES : 0);
	w32(p, a, PCI_EXT_CAP_ID_ERR | (2 << 16) |
			 ((dpc ? PCIEM_PORT_DPC : acs ? PCIEM_PORT_ACS : 0) << 20));
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

		w32(p, d, PCI_EXT_CAP_ID_DPC | (1 << 16) | ((acs ? PCIEM_PORT_ACS : 0) << 20));
		w16(p, d + PCI_EXP_DPC_CAP, PCI_EXP_DPC_CAP_SW_TRIGGER | PCI_EXP_DPC_CAP_DL_ACTIVE);
		w16(p, d + PCI_EXP_DPC_CTL, 0);
		rwm(p, d + PCI_EXP_DPC_CTL, 2, 0xffff);
		w1cm(p, d + PCI_EXP_DPC_STATUS, 2, 0x0009);
	}

	if (acs) {
		int x = PCIEM_PORT_ACS;

		w32(p, x, PCI_EXT_CAP_ID_ACS | (1 << 16));
		w16(p, x + PCI_ACS_CAP, ACS_CAPS);
		w16(p, x + PCI_ACS_CTRL, ACS_CAPS);
		rwm(p, x + PCI_ACS_CTRL, 2, ACS_CAPS);
	}
}

struct pciem_topo *pciem_topo_alloc(u8 placement)
{
	struct pciem_topo *t = kzalloc(sizeof(*t), GFP_KERNEL);

	if (!t)
		return NULL;
	t->placement = placement;
	raw_spin_lock_init(&t->lock);
	init_waitqueue_head(&t->trained_wq);
	INIT_LIST_HEAD(&t->node);
	return t;
}

static void topo_release_arrays(struct pciem_topo *t)
{
	int i;

	for (i = 0; t->ports && i < t->nports; i++)
		if (t->ports[i].vecs)
			pciem_msi_vecs_destroy(t->ports[i].vecs);
	kfree(t->ports);
	kfree(t->links);
	kfree(t->slots);
	t->ports = NULL;
	t->links = NULL;
	t->slots = NULL;
	t->nports = 0;
	t->nslots = 0;
}

void pciem_topo_free(struct pciem_topo *t)
{
	topo_release_arrays(t);
	if (t->trace_owned)
		pciem_trace_free(t->trace);
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

void pciem_topo_set_reach_cb(struct pciem_root_complex *v,
							 void (*cb)(void *data, bool reachable), void *data)
{
	v->topo_reach_cb = cb;
	v->topo_reach_data = data;
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
	bool sw = t->placement == PCIEM_PLACEMENT_SWITCH;
	struct bar_slot slots[PCI_STD_NUM_BARS];
	resource_size_t cursor = 0, total, region, align = SZ_1M;
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
	if (sw)
		total = ALIGN(total, align);

	if (sw && t->shared) {
		if (total > c->stride) {
			pr_err("port %u: BAR layout of 0x%llx bytes does not fit the switch chunk of 0x%llx\n",
				   v->topo_port, (u64)total, (u64)c->stride);
			return -ENOSPC;
		}
		base = c->start + (phys_addr_t)v->topo_port * c->stride;
		goto place;
	}

	region = sw ? total * t->p.switch_ports : total;
	base = pciem_pool_alloc_aligned(region, align);
	if (!base)
		return -ENOMEM;
	if (!pref && base + region > SZ_4G) {
		pr_err("non-prefetchable BARs at 0x%llx are above 4 GiB, which a bridge memory window cannot cover\n",
			   (u64)base);
		pciem_pool_free(base, region);
		return -EINVAL;
	}

	res = kzalloc(sizeof(*res), GFP_KERNEL);
	if (!res) {
		pciem_pool_free(base, region);
		return -ENOMEM;
	}
	res->name = pref ? "PCI BAR chunk (prefetchable)" : "PCI BAR chunk";
	res->start = base;
	res->end = base + region - 1;
	res->flags = IORESOURCE_MEM | (pref ? IORESOURCE_PREFETCH | IORESOURCE_MEM_64 : 0);
	if (pciem_pool_insert(res)) {
		kfree(res);
		pciem_pool_free(base, region);
		return -EBUSY;
	}
	entry = resource_list_create_entry(res, 0);
	if (!entry) {
		release_resource(res);
		kfree(res);
		pciem_pool_free(base, region);
		return -ENOMEM;
	}
	resource_list_add_tail(entry, windows);

	c->res = res;
	c->start = base;
	c->size = region;
	c->stride = total;
	if (sw)
		base += (phys_addr_t)v->topo_port * total;

place:
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

static void topo_free_chunks(struct pciem_topo *t)
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

void pciem_topo_free_chunks(struct pciem_topo *t)
{
	if (!t->shared)
		topo_free_chunks(t);
}

static void port_set_buses(struct pciem_port *p, u8 pri, u8 sec, u8 sub)
{
	p->cfg[PCI_PRIMARY_BUS] = pri;
	p->cfg[PCI_SECONDARY_BUS] = sec;
	p->cfg[PCI_SUBORDINATE_BUS] = sub;
}

static void port_set_windows(struct pciem_port *p, struct pciem_topo *t, int k)
{
	struct pciem_topo_chunk *np = &t->chunk[0], *pf = &t->chunk[1];

	if (np->size) {
		u64 start = np->start + (k >= 0 ? k * np->stride : 0);
		u64 size = k >= 0 ? np->stride : np->size;

		w16(p, PCI_MEMORY_BASE, (start >> 16) & 0xfff0);
		w16(p, PCI_MEMORY_LIMIT, ((start + size - 1) >> 16) & 0xfff0);
	}
	if (pf->size) {
		u64 start = pf->start + (k >= 0 ? k * pf->stride : 0);
		u64 size = k >= 0 ? pf->stride : pf->size;
		u64 end = start + size - 1;

		w16(p, PCI_PREF_MEMORY_BASE, ((start >> 16) & 0xfff0) | 1);
		w16(p, PCI_PREF_MEMORY_LIMIT, ((end >> 16) & 0xfff0) | 1);
		w32(p, PCI_PREF_BASE_UPPER32, start >> 32);
		w32(p, PCI_PREF_LIMIT_UPPER32, end >> 32);
	}
}

int pciem_topo_program(struct pciem_root_complex *v, int domain, u8 root_bus)
{
	struct pciem_topo *t = v->topo;
	bool sw = t->placement == PCIEM_PLACEMENT_SWITCH;
	int i, k, nslots = sw ? t->p.switch_ports : 1;
	struct pciem_port *rp, *usp;
	u8 eq;

	topo_apply_defaults(t);
	topo_release_arrays(t);
	t->nslots = nslots;
	t->nports = sw ? 2 + nslots : 1;
	t->ports = kcalloc(t->nports, sizeof(*t->ports), GFP_KERNEL);
	t->links = kcalloc(1 + (sw ? nslots : 0), sizeof(*t->links), GFP_KERNEL);
	t->slots = kcalloc(nslots, sizeof(*t->slots), GFP_KERNEL);
	if (!t->ports || !t->links || !t->slots) {
		topo_release_arrays(t);
		return -ENOMEM;
	}
	if (sw) {
		t->trace = pciem_trace_alloc();
		if (!t->trace) {
			topo_release_arrays(t);
			return -ENOMEM;
		}
		t->trace_owned = true;
	} else {
		t->trace = v->trace;
	}

	t->domain = domain;
	t->root_bus = root_bus;
	INIT_WORK(&t->work, topo_work_func);

	for (i = 0; i < t->nports; i++) {
		struct pciem_port *p = &t->ports[i];

		p->topo = t;
		p->role = i == 0 ? PCIEM_ROLE_RP : i == 1 && sw ? PCIEM_ROLE_USP : PCIEM_ROLE_DSP;
		p->fn = p->role;
		p->pcie = PCIEM_PORT_PCIE;
		p->downstream = p->role != PCIEM_ROLE_USP;
	}
	for (k = 0; k < nslots; k++) {
		t->slots[k].p = t->p;
		t->slots[k].reach_last = true;
	}

	rp = PCIEM_PORT_RP(t);
	rp->speed = t->p.rp_speed;
	rp->width = t->p.rp_width;
	rp->bus = root_bus;
	rp->vecs = &rp->msi_store;
	pciem_msi_vecs_init(rp->vecs);

	pciem_link_init(&t->links[0], t, rp, NULL);

	if (!sw) {
		struct pciem_topo_slot *s = &t->slots[0];

		s->v = v;
		s->ep_bus = root_bus + 1;
		s->link = &t->links[0];
		s->reach_cb = v->topo_reach_cb;
		s->reach_data = v->topo_reach_data;
		rp->slot = s;
		rp->slot_nr = s->ep_bus;
		rp->hotplug = t->p.flags & PCIEM_TOPO_FLAG_HOTPLUG;
		t->links[0].slot = s;
		port_build(rp);
		port_set_windows(rp, t, -1);
		port_set_buses(rp, root_bus, root_bus + 1, root_bus + 1);
		eq = t->p.eq_fail_above == PCIEM_EQ_LIMIT_NONE ? 0 : t->p.eq_fail_above;
		t->links[0].eq_limit = eq;
		t->links[0].rrs_ms = t->p.rrs_ms;
		return pciem_cap_pcie_topo_setup(v, t->p.ep_speed, t->p.ep_width);
	}

	usp = PCIEM_PORT_USP(t);
	usp->speed = PCIEM_LINK_SPEED_32GT;
	usp->width = 16;
	usp->bus = root_bus + 1;
	rp->slot_nr = root_bus + 1;
	t->links[0].rrs_ms = t->p.rrs_ms;
	port_build(rp);
	port_build(usp);
	port_set_windows(rp, t, -1);
	port_set_windows(usp, t, -1);
	port_set_buses(rp, root_bus, root_bus + 1, root_bus + 2 + nslots);
	port_set_buses(usp, root_bus + 1, root_bus + 2, root_bus + 2 + nslots);

	for (k = 0; k < nslots; k++) {
		struct pciem_port *d = PCIEM_PORT_DSP(t, k);
		struct pciem_topo_slot *s = &t->slots[k];
		struct pciem_plink *l = &t->links[1 + k];

		d->speed = t->p.dsp_speed;
		d->width = t->p.dsp_width;
		d->bus = root_bus + 2;
		d->devfn = PCI_DEVFN(k, 0);
		d->hotplug = t->p.flags & PCIEM_TOPO_FLAG_HOTPLUG;
		d->slot = s;
		d->slot_nr = root_bus + 3 + k;
		d->vecs = &d->msi_store;
		pciem_msi_vecs_init(d->vecs);
		s->ep_bus = root_bus + 3 + k;
		s->link = l;
		pciem_link_init(l, t, d, &t->links[0]);
		l->slot = s;
		l->rrs_ms = t->p.rrs_ms;
		port_build(d);
		port_set_windows(d, t, k);
		port_set_buses(d, root_bus + 2, root_bus + 3 + k, root_bus + 3 + k);
	}
	return 0;
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
		t->ports[i].pdev = pci_get_domain_bus_and_slot(t->domain, t->ports[i].bus,
														   t->ports[i].devfn);
}

void pciem_topo_release_pdevs(struct pciem_topo *t)
{
	int i;

	for (i = 0; i < t->nports; i++) {
		pci_dev_put(t->ports[i].pdev);
		t->ports[i].pdev = NULL;
	}
}

void pciem_topo_start(struct pciem_topo *t)
{
	struct pciem_plink *rpl = &t->links[0];
	bool sw = t->placement == PCIEM_PLACEMENT_SWITCH;
	int k;

	pciem_trace_phase(t->trace, PT_PH_TRAIN_BEGIN);
	scoped_guard(raw_spinlock_irqsave, &t->lock) {
		t->registered = true;
		rpl->partner = true;
		rpl->partner_speed = sw ? PCIEM_LINK_SPEED_32GT : t->p.ep_speed;
		rpl->partner_width = sw ? 16 : t->p.ep_width;
	}
	pciem_link_start(rpl);
	for (k = 0; sw && k < t->nslots; k++)
		pciem_link_start(&t->links[1 + k]);
}

static bool topo_link_settled(struct pciem_topo *t, struct pciem_plink *l)
{
	guard(raw_spinlock_irqsave)(&t->lock);
	return pciem_link_settled(l);
}

static void topo_wait_link(struct pciem_topo *t, struct pciem_plink *l)
{
	long left = wait_event_timeout(t->trained_wq, topo_link_settled(t, l),
								   msecs_to_jiffies(pciem_link_train_timeout_ms()));

	if (!left)
		pr_warn("link not settled after %u ms, continuing\n", pciem_link_train_timeout_ms());
}

void pciem_topo_wait_trained(struct pciem_topo *t)
{
	topo_wait_link(t, &t->links[0]);
	pciem_trace_phase(t->trace, PT_PH_TRAIN_DONE);
}

static void topo_stop(struct pciem_topo *t)
{
	int i, nlinks = t->placement == PCIEM_PLACEMENT_SWITCH ? 1 + t->nslots : 1;

	WRITE_ONCE(t->dying, true);
	if (!t->registered)
		return;
	for (i = 0; i < nlinks; i++)
		pciem_link_stop(&t->links[i]);
	cancel_work_sync(&t->work);
}

void pciem_topo_quiesce(struct pciem_topo *t)
{
	if (!t->shared)
		topo_stop(t);
}

enum { RT_NONE, RT_UR, RT_PORT, RT_EP };

struct pciem_route {
	u8 kind;
	bool rrs;
	struct pciem_port *port;
	struct pciem_topo_slot *slot;
};

static void route_ep(struct pciem_port *p, u8 busnr, unsigned int devfn, struct pciem_route *rt)
{
	if (busnr != p->cfg[PCI_SECONDARY_BUS] || PCI_SLOT(devfn) || PCI_FUNC(devfn) || !p->slot ||
		!p->slot->v)
		return;
	rt->kind = RT_EP;
	rt->slot = p->slot;
	rt->rrs = ktime_before(ktime_get(), p->link->rrs_until);
}

static void topo_route(struct pciem_topo *t, u8 busnr, unsigned int devfn, struct pciem_route *rt)
{
	struct pciem_port *p = PCIEM_PORT_RP(t);
	bool sw = t->placement == PCIEM_PLACEMENT_SWITCH;
	int k;

	rt->kind = RT_NONE;
	rt->rrs = false;
	rt->port = NULL;
	rt->slot = NULL;

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
		switch (p->role) {
		case PCIEM_ROLE_RP:
			if (!sw) {
				route_ep(p, busnr, devfn, rt);
				return;
			}
			if (busnr == sec) {
				if (devfn == 0) {
					rt->kind = RT_PORT;
					rt->port = PCIEM_PORT_USP(t);
				}
				return;
			}
			p = PCIEM_PORT_USP(t);
			break;
		case PCIEM_ROLE_USP:
			if (busnr == sec) {
				k = PCI_SLOT(devfn);
				if (!PCI_FUNC(devfn) && k < t->nslots) {
					rt->kind = RT_PORT;
					rt->port = PCIEM_PORT_DSP(t, k);
				}
				return;
			}
			for (k = 0; k < t->nslots; k++) {
				struct pciem_port *d = PCIEM_PORT_DSP(t, k);

				if (d->cfg[PCI_SECONDARY_BUS] && busnr >= d->cfg[PCI_SECONDARY_BUS] &&
					busnr <= d->cfg[PCI_SUBORDINATE_BUS])
					break;
			}
			if (k == t->nslots)
				return;
			p = PCIEM_PORT_DSP(t, k);
			break;
		default:
			route_ep(p, busnr, devfn, rt);
			return;
		}
	}
}

struct pciem_root_complex *pciem_topo_ep_dev(struct pciem_topo *t, struct pci_bus *bus,
											 unsigned int devfn)
{
	struct pciem_route rt;

	guard(raw_spinlock_irqsave)(&t->lock);
	topo_route(t, bus->number, devfn, &rt);
	return rt.kind == RT_EP ? rt.slot->v : NULL;
}

struct pciem_msi_vecs *pciem_topo_msi_vecs(struct pciem_topo *t, struct pci_bus *bus,
										   unsigned int devfn)
{
	struct pciem_route rt;

	guard(raw_spinlock_irqsave)(&t->lock);
	topo_route(t, bus->number, devfn, &rt);
	if (rt.kind == RT_EP)
		return &rt.slot->v->msi;
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
	pciem_trace_reset(pciem_port_trace(p), p->fn, PT_RESET_POWER_ON);
}

static void topo_reset_slot(struct pciem_topo_slot *s)
{
	if (s->v)
		pciem_function_reset(s->v, PCIEM_RESET_HOT);
}

static void topo_reset_below(struct pciem_topo *t, struct pciem_port *p)
{
	int k;

	if (p->role == PCIEM_ROLE_DSP || t->placement != PCIEM_PLACEMENT_SWITCH) {
		topo_reset_slot(p->slot);
		return;
	}
	if (p->role == PCIEM_ROLE_RP)
		port_reset_regs(PCIEM_PORT_USP(t));
	for (k = 0; k < t->nslots; k++) {
		port_reset_regs(PCIEM_PORT_DSP(t, k));
		pciem_link_hot_reset_from_above(&t->links[1 + k]);
		topo_reset_slot(&t->slots[k]);
	}
}

void pciem_port_irq(struct pciem_port *p, u8 cause)
{
	p->pend |= BIT(cause);
	pciem_topo_kick_work(p->topo);
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
	pciem_trace_lnksta(pciem_port_trace(p), p->fn, old, new, true);
}

void pciem_port_lnksta_mirror(struct pciem_port *p, u8 cls, u8 nlw)
{
	int off = p->pcie + PCI_EXP_LNKSTA;
	u16 old = r16(p, off);
	u16 new = (old & ~(PCI_EXP_LNKSTA_CLS | PCI_EXP_LNKSTA_NLW)) | cls | ((u16)nlw << 4);

	if (new == old)
		return;
	w16(p, off, new);
	pciem_trace_lnksta(pciem_port_trace(p), p->fn, old, new, true);
}

void pciem_port_lnksta_flag(struct pciem_port *p, u16 flag)
{
	int off = p->pcie + PCI_EXP_LNKSTA;
	u16 old = r16(p, off);
	u16 ctl;

	if (old & flag)
		return;
	w16(p, off, old | flag);
	pciem_trace_lnksta(pciem_port_trace(p), p->fn, old, old | flag, true);
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
	pciem_trace_reg(pciem_port_trace(p), PT_EV_SLTSTA, p->fn, PT_REG_SLTSTA, old, old | bit, true);
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
	id = (id & 0xffff) | ((u32)src->bus << 24) | ((u32)src->devfn << 16);
	w32(rp, PCIEM_PORT_AER + PCI_ERR_ROOT_STATUS, st);
	w32(rp, PCIEM_PORT_AER + PCI_ERR_ROOT_ERR_SRC, id);
	pciem_trace_reg(pciem_port_trace(rp), PT_EV_AER, rp->fn, PT_REG_ROOTSTA, old, st, true);
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
	pciem_trace_reg(pciem_port_trace(p), PT_EV_AER, p->fn, PT_REG_UESTA, old, old | UE_SDES, true);
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
	struct pciem_trace *tr = pciem_port_trace(p);
	int c = p->pcie;
	u16 n;

	n = r16(p, c + PCI_EXP_LNKCTL);
	if (p->downstream) {
		if (rl) {
			pciem_trace_ctl(tr, p->fn, PT_CTL_RETRAIN, n);
			pciem_link_retrain(p->link);
		}
		if ((o_lnkctl ^ n) & LNKCTL_LD) {
			pciem_trace_ctl(tr, p->fn, n & LNKCTL_LD ? PT_CTL_LD_ON : PT_CTL_LD_OFF, n);
			pciem_link_disable(p->link, n & LNKCTL_LD);
		}
	}
	if ((o_lnkctl ^ n) & ~LNKCTL_RL & ~LNKCTL_LD)
		pciem_trace_ctl(tr, p->fn, PT_CTL_LNKCTL, n);

	n = r16(p, c + PCI_EXP_LNKCTL2);
	if ((o_lnkctl2 ^ n) & PCI_EXP_LNKCTL2_TLS)
		pciem_trace_ctl(tr, p->fn, PT_CTL_TLS, n & PCI_EXP_LNKCTL2_TLS);

	n = r16(p, PCI_BRIDGE_CONTROL);
	if ((o_brctl ^ n) & BRCTL_SBR) {
		bool set = n & BRCTL_SBR;

		pciem_trace_ctl(tr, p->fn, set ? PT_CTL_SBR_ON : PT_CTL_SBR_OFF, n);
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
			pciem_trace_ctl(tr, p->fn, PT_CTL_SLTCTL, n);
		n = r16(p, c + PCI_EXP_SLTSTA);
		if (n != o_sltsta)
			pciem_trace_reg(tr, PT_EV_SLTSTA, p->fn, PT_REG_SLTSTA, o_sltsta, n, false);
		n = r16(p, PCIEM_PORT_MSI + PCI_MSI_FLAGS);
		if (n != o_msi)
			pciem_trace_ctl(tr, p->fn, PT_CTL_MSI, n);
	}
	if (p->role == PCIEM_ROLE_RP) {
		n = r16(p, c + PCI_EXP_RTCTL);
		if (n != o_rootctl)
			pciem_trace_ctl(tr, p->fn, PT_CTL_ROOTCTL, n);
		if (r32(p, PCIEM_PORT_AER + PCI_ERR_ROOT_STATUS) != o_rootsta)
			pciem_trace_reg(tr, PT_EV_AER, p->fn, PT_REG_ROOTSTA, o_rootsta,
							r32(p, PCIEM_PORT_AER + PCI_ERR_ROOT_STATUS), false);
	}
	if (r32(p, PCIEM_PORT_AER + PCI_ERR_UNCOR_STATUS) != o_uesta)
		pciem_trace_reg(tr, PT_EV_AER, p->fn, PT_REG_UESTA, o_uesta,
						r32(p, PCIEM_PORT_AER + PCI_ERR_UNCOR_STATUS), false);
	n = r16(p, c + PCI_EXP_LNKSTA);
	if ((n ^ o_lnksta) & (PCI_EXP_LNKSTA_LBMS | PCI_EXP_LNKSTA_LABS))
		pciem_trace_lnksta(tr, p->fn, o_lnksta, n, false);
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

static struct pciem_trace *route_trace(struct pciem_topo *t, const struct pciem_route *rt)
{
	if (rt->kind == RT_PORT)
		return pciem_port_trace(rt->port);
	if (rt->kind == RT_EP)
		return rt->slot->v->trace;
	return t->trace;
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
	struct pciem_trace *tr;
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
			*ep = rt.slot->v;
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
	tr = route_trace(t, &rt);
	raw_spin_unlock_irqrestore(&t->lock, flags);

	if (!*ep) {
		*value = val;
		pciem_trace_cfg_access(tr, route_fn(&rt, devfn), busnr, devfn, false, where, size, val, res);
	}
	return ret;
}

int pciem_topo_cfg_write(struct pciem_topo *t, u8 busnr, unsigned int devfn, int where, int size,
						 u32 value, struct pciem_root_complex **ep)
{
	struct pciem_route rt;
	struct pciem_trace *tr;
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
			*ep = rt.slot->v;
			break;
		}
		res = PT_RES_RRS;
		break;
	}
	tr = route_trace(t, &rt);
	raw_spin_unlock_irqrestore(&t->lock, flags);

	if (!*ep)
		pciem_trace_cfg_access(tr, route_fn(&rt, devfn), busnr, devfn, true, where, size, value,
							   res);
	return ret;
}

static struct pciem_topo_slot *dev_slot(struct pciem_root_complex *v)
{
	return &v->topo->slots[v->topo_port];
}

void pciem_topo_dev_down(struct pciem_root_complex *v)
{
	struct pciem_topo *t = v->topo;
	struct pciem_topo_slot *s = dev_slot(v);

	scoped_guard(raw_spinlock_irqsave, &t->lock) {
		s->dev_down = true;
		pciem_link_partner(s->link, false, 0, 0);
	}
	pciem_topo_kick_work(t);
}

int pciem_topo_dev_up(struct pciem_root_complex *v, u8 speed, u8 width)
{
	struct pciem_topo *t = v->topo;
	struct pciem_topo_slot *s = dev_slot(v);

	scoped_guard(raw_spinlock_irqsave, &t->lock) {
		s->dev_down = false;
		pciem_link_partner(s->link, true, speed, width);
	}
	pciem_topo_kick_work(t);
	return 0;
}

bool pciem_topo_dev_is_down(struct pciem_root_complex *v)
{
	guard(raw_spinlock_irqsave)(&v->topo->lock);
	return dev_slot(v)->dev_down;
}

int pciem_topo_set_eq_limit(struct pciem_root_complex *v, u8 speed)
{
	guard(raw_spinlock_irqsave)(&v->topo->lock);
	pciem_link_set_eq_limit(dev_slot(v)->link, speed);
	return 0;
}

void pciem_topo_dev_limits(struct pciem_root_complex *v, u8 *speed, u8 *width)
{
	struct pciem_topo_slot *s = dev_slot(v);

	*speed = s->p.ep_speed;
	*width = s->p.ep_width;
}

int pciem_topo_link_read(struct pciem_root_complex *v, char *buf, size_t len)
{
	struct pciem_topo_slot *s = dev_slot(v);
	struct pciem_port *p = s->link->port;
	u16 sta;
	bool up;

	scoped_guard(raw_spinlock_irqsave, &v->topo->lock) {
		up = !s->dev_down && s->link->dl_up;
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
	u8 pend[2 + PCIEM_SWITCH_MAX_PORTS] = {};
	bool msi_en[2 + PCIEM_SWITCH_MAX_PORTS] = {};
	bool reach[PCIEM_SWITCH_MAX_PORTS] = {};
	void (*cb[PCIEM_SWITCH_MAX_PORTS])(void *data, bool reachable) = {};
	void *cb_data[PCIEM_SWITCH_MAX_PORTS] = {};
	int i, c;

	scoped_guard(raw_spinlock_irqsave, &t->lock) {
		for (i = 0; i < t->nports; i++) {
			struct pciem_port *p = &t->ports[i];

			pend[i] = p->pend;
			p->pend = 0;
			if (p->role != PCIEM_ROLE_USP)
				msi_en[i] = r16(p, PCIEM_PORT_MSI + PCI_MSI_FLAGS) & PCI_MSI_FLAGS_ENABLE;
		}
		for (i = 0; i < t->nslots; i++) {
			struct pciem_topo_slot *s = &t->slots[i];

			reach[i] = s->v && !s->dev_down && s->link->dl_up;
			if (s->v && s->reach_cb && reach[i] != s->reach_last) {
				s->reach_last = reach[i];
				cb[i] = s->reach_cb;
				cb_data[i] = s->reach_data;
			}
		}
	}

	for (i = 0; i < t->nports; i++) {
		struct pciem_port *p = &t->ports[i];

		for (c = 0; c < 8; c++) {
			bool sent = false;

			if (!(pend[i] & BIT(c)))
				continue;
			if (msi_en[i] && p->vecs)
				sent = !pciem_msi_deliver(p->vecs, 0);
			pciem_trace_irq(pciem_port_trace(p), p->fn, c, 0, sent);
		}
	}

	for (i = 0; i < t->nslots; i++)
		if (cb[i])
			cb[i](cb_data[i], reach[i]);
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

static void json_port(struct seq_file *m, bool *first, struct pciem_port *p, int domain, bool sw)
{
	seq_printf(m, "%s{\"role\":\"%s\",\"bdf\":\"%04x:%02x:%02x.0\",\"sec\":%u,\"sub\":%u",
			   *first ? "" : ",", port_name(p->role), domain, p->bus, PCI_SLOT(p->devfn),
			   p->cfg[PCI_SECONDARY_BUS], p->cfg[PCI_SUBORDINATE_BUS]);
	if (sw && p->role == PCIEM_ROLE_DSP)
		seq_printf(m, ",\"port\":%u", PCI_SLOT(p->devfn));
	seq_puts(m, "}");
	*first = false;
}

static void json_ep(struct seq_file *m, bool *first, int domain, u8 bus, int port, bool sw)
{
	seq_printf(m, "%s{\"role\":\"ep0\",\"bdf\":\"%04x:%02x:00.0\"", *first ? "" : ",", domain, bus);
	if (sw)
		seq_printf(m, ",\"port\":%d", port);
	seq_puts(m, "}");
	*first = false;
}

void pciem_topology_json_show(struct pciem_root_complex *v, struct seq_file *m)
{
	struct pciem_topo *t = v->topo;
	struct pciem_host_bridge_priv *priv = v->bridge_priv;
	int domain = v->mode_state.virtual_root.assigned_domain;
	int root = v->mode_state.virtual_root.assigned_busnr;
	bool sw = t && t->placement == PCIEM_PLACEMENT_SWITCH;
	int i, f;
	bool first = true;

	seq_printf(m, "{\"placement\":\"%s\",\"domain\":%d,\"root_bus\":%d,", pciem_placement_names[v->placement],
			   domain, root);
	if (sw)
		seq_printf(m, "\"port\":%u,\"switch_ports\":%u,", v->topo_port, t->nslots);
	seq_puts(m, "\"functions\":[");
	if (t) {
		scoped_guard(raw_spinlock_irqsave, &t->lock) {
			for (i = 0; i < t->nports; i++) {
				struct pciem_port *p = &t->ports[i];

				if (sw && p->role == PCIEM_ROLE_DSP && p->slot != dev_slot(v))
					continue;
				json_port(m, &first, p, domain, sw);
			}
		}
		json_ep(m, &first, domain, dev_slot(v)->ep_bus, v->topo_port, sw);
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

static int switch_topology_show(struct seq_file *m, void *unused)
{
	struct pciem_topo *t = m->private;
	bool first = true;
	int i;

	seq_printf(m, "{\"placement\":\"switch\",\"domain\":%d,\"root_bus\":%u,\"switch_ports\":%u,\"functions\":[",
			   t->domain, t->root_bus, t->nslots);
	guard(raw_spinlock_irqsave)(&t->lock);
	for (i = 0; i < t->nports; i++)
		json_port(m, &first, &t->ports[i], t->domain, true);
	for (i = 0; i < t->nslots; i++)
		if (t->slots[i].v)
			json_ep(m, &first, t->domain, t->slots[i].ep_bus, i, true);
	seq_puts(m, "]}\n");
	return 0;
}

static int switch_topology_open(struct inode *inode, struct file *file)
{
	return single_open(file, switch_topology_show, inode->i_private);
}

static const struct file_operations switch_topology_fops = {
	.owner = THIS_MODULE,
	.open = switch_topology_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

static void switch_debugfs_create(struct pciem_topo *t)
{
	struct pciem_plink *l = &t->links[0];
	char name[32];

	snprintf(name, sizeof(name), "switch-%04x:%02x", t->domain, t->root_bus);
	t->dir = debugfs_create_dir(name, pciem_debugfs_root());
	pciem_trace_debugfs_create(t->dir, t->trace);
	debugfs_create_file("topology", 0400, t->dir, t, &switch_topology_fops);
	l->dir = debugfs_create_dir("rp", t->dir);
	pciem_plink_debugfs_create(l, l->dir);
}

void pciem_topo_debugfs_create(struct pciem_root_complex *v, struct dentry *dir)
{
	struct pciem_topo *t = v->topo;

	if (!t)
		return;
	if (t->placement == PCIEM_PLACEMENT_SWITCH) {
		struct pciem_plink *l = dev_slot(v)->link;

		l->dir = debugfs_create_dir("dsp", dir);
		pciem_plink_debugfs_create(l, l->dir);
		guard(mutex)(&pciem_switch_lock);
		if (!t->dir)
			switch_debugfs_create(t);
		return;
	}
	t->links[0].dir = debugfs_create_dir(port_name(PCIEM_ROLE_RP), dir);
	pciem_plink_debugfs_create(&t->links[0], t->links[0].dir);
}

void pciem_topology_debugfs_file(struct pciem_root_complex *v, struct dentry *dir)
{
	debugfs_create_file("topology", 0400, dir, v, &topology_fops);
}

static bool topo_params_match(const struct pciem_topology *a, const struct pciem_topology *b)
{
	return a->flags == b->flags && a->rp_speed == b->rp_speed && a->rp_width == b->rp_width &&
		   a->dsp_speed == b->dsp_speed && a->dsp_width == b->dsp_width &&
		   a->switch_ports == b->switch_ports;
}

static struct pciem_topo *switch_find(int domain, u8 bus)
{
	struct pciem_topo *t;

	list_for_each_entry(t, &pciem_switches, node)
		if (t->domain == domain && t->root_bus == bus)
			return t;
	return NULL;
}

int pciem_topo_join(struct pciem_root_complex *v)
{
	struct pciem_topo *mine = v->topo, *t;
	int domain = v->mode_state.virtual_root.assigned_domain;
	int bus = v->mode_state.virtual_root.assigned_busnr;

	lockdep_assert_held(&pciem_switch_lock);
	if (!mine->params_set)
		return -EINVAL;
	topo_apply_defaults(mine);
	v->topo_port = mine->p.port;
	if (bus + 2 + mine->p.switch_ports > 255)
		return -EINVAL;

	t = switch_find(domain, bus);
	if (!t)
		return 0;
	if (!topo_params_match(&t->p, &mine->p)) {
		pr_err("switch %04x:%02x: parameters differ from the switch's\n", domain, bus);
		return -EINVAL;
	}
	if (t->slots[v->topo_port].v) {
		pr_err("switch %04x:%02x: port %u is taken\n", domain, bus, v->topo_port);
		return -EBUSY;
	}

	t->slots[v->topo_port].p = mine->p;
	t->refs++;
	v->topo = t;
	pciem_topo_free(mine);
	return 0;
}

void pciem_topo_make_shared(struct pciem_root_complex *v, struct pci_host_bridge *bridge,
							struct pciem_host_bridge_priv *priv, struct platform_device *pdev)
{
	struct pciem_topo *t = v->topo;

	lockdep_assert_held(&pciem_switch_lock);
	t->bridge = bridge;
	t->bus = bridge->bus;
	t->priv = priv;
	t->pdev = pdev;
	t->refs = 1;
	t->shared = true;
	priv->trace = t->trace;
	list_add_tail(&t->node, &pciem_switches);
}

int pciem_topo_attach(struct pciem_root_complex *v)
{
	struct pciem_topo *t = v->topo;
	struct pciem_topo_slot *s = dev_slot(v);
	struct pciem_port *dsp = PCIEM_PORT_DSP(t, v->topo_port);
	struct pciem_plink *l = s->link;
	struct pci_bus *child = dsp->pdev ? dsp->pdev->subordinate : NULL;
	u8 eq = s->p.eq_fail_above == PCIEM_EQ_LIMIT_NONE ? 0 : s->p.eq_fail_above;
	int rc;

	lockdep_assert_held(&pciem_switch_lock);
	if (!child)
		return -ENODEV;
	rc = pciem_cap_pcie_topo_setup(v, s->p.ep_speed, s->p.ep_width);
	if (rc)
		return rc;

	v->root_bus = t->bus;
	v->bridge_priv = t->priv;
	v->mode_state.virtual_root.bridge = t->bridge;
	v->mode_state.virtual_root.assigned_domain = t->domain;
	v->mode_state.virtual_root.assigned_busnr = t->root_bus;

	pciem_trace_phase(v->trace, PT_PH_TRAIN_BEGIN);
	scoped_guard(raw_spinlock_irqsave, &t->lock) {
		s->v = v;
		s->dev_down = false;
		s->reach_last = true;
		s->reach_cb = v->topo_reach_cb;
		s->reach_data = v->topo_reach_data;
		l->rrs_ms = s->p.rrs_ms;
		l->eq_limit = eq;
		l->allow = 0xff;
		l->eq_done = 0;
		pciem_link_partner(l, true, s->p.ep_speed, s->p.ep_width);
	}
	pciem_topo_kick_work(t);
	topo_wait_link(t, l);
	pciem_trace_phase(v->trace, PT_PH_TRAIN_DONE);

	pciem_trace_phase(v->trace, PT_PH_SCAN_BEGIN);
	pci_lock_rescan_remove();
	pci_scan_slot(child, 0);
	pci_walk_bus(child, topo_walk_fn, NULL);
	pci_bus_claim_resources(child);
	v->pciem_pdev = pci_get_domain_bus_and_slot(t->domain, s->ep_bus, PCI_DEVFN(0, 0));
	if (v->pciem_pdev)
		pciem_mark_ep_bars(v);
	pci_unlock_rescan_remove();
	pciem_trace_phase(v->trace, PT_PH_SCAN_DONE);

	if (!v->pciem_pdev) {
		pr_err("port %u: no device found at %04x:%02x:00.0\n", v->topo_port, t->domain, s->ep_bus);
		scoped_guard(raw_spinlock_irqsave, &t->lock) {
			s->v = NULL;
			pciem_link_detach(l);
		}
		synchronize_rcu();
		return -ENODEV;
	}
	return 0;
}

static void switch_destroy(struct pciem_topo *t)
{
	int i;

	list_del(&t->node);
	topo_stop(t);
	debugfs_remove_recursive(t->dir);
	t->dir = NULL;
	if (t->bus) {
		if (t->bus->bridge)
			pciem_iommu_stub_unregister_bridge(t->bus->bridge);
		pci_lock_rescan_remove();
		pci_stop_root_bus(t->bus);
		pci_remove_root_bus(t->bus);
		pci_unlock_rescan_remove();
	}
	for (i = 0; i < t->nports; i++) {
		pci_dev_put(t->ports[i].pdev);
		t->ports[i].pdev = NULL;
	}
	topo_free_chunks(t);
	platform_device_unregister(t->pdev);
	pciem_topo_free(t);
}

void pciem_topo_leave(struct pciem_root_complex *v)
{
	struct pciem_topo *t = v->topo;
	struct pciem_topo_slot *s;

	if (!t || !t->shared)
		return;
	guard(mutex)(&pciem_switch_lock);
	s = dev_slot(v);
	if (s->v == v) {
		scoped_guard(raw_spinlock_irqsave, &t->lock) {
			s->v = NULL;
			s->reach_cb = NULL;
			pciem_link_detach(s->link);
		}
		synchronize_rcu();
		flush_work(&t->work);
	}
	v->topo = NULL;
	v->root_bus = NULL;
	v->bridge_priv = NULL;
	if (--t->refs == 0)
		switch_destroy(t);
}

void pciem_topo_activate(struct pciem_root_complex *v)
{
	struct pciem_topo *t = v->topo;
	struct pciem_port *chain[3];
	int i;

	if (!t)
		return;
	chain[0] = PCIEM_PORT_RP(t);
	chain[1] = PCIEM_PORT_USP(t);
	chain[2] = PCIEM_PORT_DSP(t, v->topo_port);
	scoped_guard(mutex, &pciem_switch_lock) {
		for (i = 0; i < 3; i++) {
			if (chain[i]->pdev && !chain[i]->added) {
				pci_bus_add_device(chain[i]->pdev);
				chain[i]->added = true;
			}
		}
	}
	if (v->pciem_pdev) {
		pci_lock_rescan_remove();
		pci_bus_add_devices(v->pciem_pdev->bus);
		pci_unlock_rescan_remove();
	}
}
