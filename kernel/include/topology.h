/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef PCIEM_TOPOLOGY_H
#define PCIEM_TOPOLOGY_H

#include <linux/hrtimer.h>
#include <linux/ktime.h>
#include <linux/pci.h>
#include <linux/bitfield.h>
#include <linux/spinlock.h>
#include <linux/wait.h>
#include <linux/workqueue.h>

#ifdef PCIEM_HAVE_LINUX_UNALIGNED
#include <linux/unaligned.h>
#else
#include <asm/unaligned.h>
#endif

#include "pciem_api.h"
#include "msi_domain.h"
#include "pcitrace.h"

struct pciem_root_complex;

#define PCIEM_PORT_CFG_SIZE 0x200

enum pciem_role { PCIEM_ROLE_RP, PCIEM_ROLE_USP, PCIEM_ROLE_DSP, PCIEM_ROLE_EP };

enum pciem_ltssm_state {
	LT_DETECT_QUIET,
	LT_DETECT_ACTIVE,
	LT_POLLING_ACTIVE,
	LT_POLLING_CONFIG,
	LT_CFG_LINKWIDTH,
	LT_CFG_LANENUM,
	LT_CFG_COMPLETE,
	LT_CFG_IDLE,
	LT_L0,
	LT_REC_RCVRLOCK,
	LT_REC_RCVRCFG,
	LT_REC_SPEED,
	LT_REC_EQ1,
	LT_REC_EQ2,
	LT_REC_EQ3,
	LT_REC_IDLE,
	LT_HOT_RESET,
	LT_DISABLED,
	LT_NSTATES,
};

enum pciem_ltssm_timing {
	T_DETECT_QUIET,
	T_DETECT_ACTIVE,
	T_POLLING_ACTIVE,
	T_POLLING_CONFIG,
	T_CFG_LINKWIDTH,
	T_CFG_LANENUM,
	T_CFG_COMPLETE,
	T_CFG_IDLE,
	T_DL_INIT,
	T_L0_SETTLE,
	T_RCVRLOCK,
	T_RCVRCFG,
	T_RECOVERY_SPEED,
	T_EQ_PHASE1,
	T_EQ_PHASE2,
	T_EQ_PHASE3,
	T_EQ_TIMEOUT,
	T_RECOVERY_IDLE,
	T_RECOVERY_TIMEOUT,
	T_HOT_RESET,
	T_NR,
};

enum pciem_rec_stage { STAGE_PRE, STAGE_POST, STAGE_EQ, STAGE_POST_EQ };

struct pciem_topo;
struct pciem_port;

struct pciem_plink {
	struct pciem_topo *topo;
	struct pciem_port *port;
	struct pciem_plink *parent;
	struct hrtimer timer;
	ktime_t deadline;
	bool armed;
	u8 fn;

	u8 state;
	u8 stage;
	u8 speed;
	u8 width;
	u8 step_to;
	u8 prev_speed;
	bool dl_up;
	bool stuck;
	bool eq_failing;
	bool sw_retrain;
	bool pending_lbms;
	bool pending_labs;
	bool autonomous_step;
	bool sbr;
	bool ld;
	bool hot_done;

	bool partner;
	u8 partner_speed;
	u8 partner_width;

	u8 eq_limit;
	u8 eq_done;
	u8 allow;
	u32 rrs_ms;
	ktime_t rrs_until;
	u32 timing[T_NR];

	struct dentry *dir;
};

struct pciem_port {
	struct pciem_topo *topo;
	u8 role;
	u8 fn;
	u8 bus;
	u8 pcie;
	u8 msi;
	u8 speed;
	u8 width;
	bool downstream;
	bool hotplug;
	struct pciem_plink *link;
	struct pciem_msi_vecs msi_store;
	struct pciem_msi_vecs *vecs;
	struct pci_dev *pdev;
	u8 cfg[PCIEM_PORT_CFG_SIZE];
	u8 rw[PCIEM_PORT_CFG_SIZE];
	u8 w1c[PCIEM_PORT_CFG_SIZE];
};

struct pciem_topo_chunk {
	struct resource *res;
	phys_addr_t start;
	resource_size_t size;
};

struct pciem_topo {
	struct pciem_root_complex *v;
	raw_spinlock_t lock;
	u8 placement;
	int domain;
	u8 root_bus;
	u8 ep_bus;
	u8 nports;
	bool params_set;
	bool registered;
	bool dying;
	bool dev_down;
	struct pciem_topology p;
	struct pciem_port ports[3];
	struct pciem_plink links[2];
	struct pciem_plink *ep_link;
	struct pciem_topo_chunk chunk[2];
	u32 pending;
	struct work_struct work;
	wait_queue_head_t trained_wq;
	void (*reach_cb)(void *data, bool reachable);
	void *reach_data;
	bool reach_last;
	struct dentry *dir;
};

#define PCIEM_PORT_RP(t)  (&(t)->ports[PCIEM_ROLE_RP])
#define PCIEM_PORT_USP(t) (&(t)->ports[PCIEM_ROLE_USP])
#define PCIEM_PORT_DSP(t) (&(t)->ports[PCIEM_ROLE_DSP])

struct pciem_topo *pciem_topo_alloc(struct pciem_root_complex *v, u8 placement);
void pciem_topo_free(struct pciem_topo *t);
int pciem_topo_set_params(struct pciem_topo *t, const struct pciem_topology *p);
void pciem_topo_set_reach_cb(struct pciem_topo *t, void (*cb)(void *data, bool reachable),
							 void *data);
u8 pciem_topo_depth(const struct pciem_topo *t);
int pciem_topo_layout_bars(struct pciem_root_complex *v, struct list_head *windows);
void pciem_topo_free_chunks(struct pciem_topo *t);
int pciem_topo_program(struct pciem_topo *t, int domain, u8 root_bus);
void pciem_topo_scanned(struct pciem_topo *t, struct pci_bus *root);
void pciem_topo_start(struct pciem_topo *t);
void pciem_topo_wait_trained(struct pciem_topo *t);
void pciem_topo_quiesce(struct pciem_topo *t);
void pciem_topo_release_pdevs(struct pciem_topo *t);
bool pciem_topo_bdf_is_ep(struct pciem_topo *t, struct pci_bus *bus, unsigned int devfn);
struct pciem_msi_vecs *pciem_topo_msi_vecs(struct pciem_topo *t, struct pci_bus *bus,
										   unsigned int devfn);

int pciem_topo_cfg_read(struct pciem_topo *t, u8 busnr, unsigned int devfn, int where, int size,
						u32 *value, struct pciem_root_complex **ep);
int pciem_topo_cfg_write(struct pciem_topo *t, u8 busnr, unsigned int devfn, int where, int size,
						 u32 value, struct pciem_root_complex **ep);

void pciem_topo_dev_down(struct pciem_topo *t);
int pciem_topo_dev_up(struct pciem_topo *t, u8 speed, u8 width);
bool pciem_topo_dev_is_down(struct pciem_topo *t);
int pciem_topo_set_eq_limit(struct pciem_topo *t, u8 speed);
int pciem_topo_link_read(struct pciem_topo *t, char *buf, size_t len);
void pciem_topo_ep_reset_hot(struct pciem_topo *t);

void pciem_topo_debugfs_create(struct pciem_topo *t, struct dentry *dir);
void pciem_topology_debugfs_file(struct pciem_root_complex *v, struct dentry *dir);
void pciem_topology_json_show(struct pciem_root_complex *v, struct seq_file *m);

void pciem_ltssm_defaults_init(void);
void pciem_link_init(struct pciem_plink *l, struct pciem_topo *t, struct pciem_port *p,
					 struct pciem_plink *parent);
void pciem_link_start(struct pciem_plink *l);
void pciem_link_stop(struct pciem_plink *l);
void pciem_link_partner(struct pciem_plink *l, bool present, u8 speed, u8 width);
void pciem_link_retrain(struct pciem_plink *l);
void pciem_link_disable(struct pciem_plink *l, bool disable);
void pciem_link_sbr(struct pciem_plink *l, bool set);
void pciem_link_hot_reset_from_above(struct pciem_plink *l);
void pciem_link_set_eq_limit(struct pciem_plink *l, u8 limit);
bool pciem_link_settled(struct pciem_plink *l);
void pciem_link_state_line(struct pciem_plink *l, char *buf, size_t len);
void pciem_plink_debugfs_create(struct pciem_plink *l, struct dentry *dir);
int pciem_link_timing_set(struct pciem_plink *l, const char *kv);
u32 pciem_link_default_rrs_ms(void);
u8 pciem_link_default_eq_limit(void);
u32 pciem_link_train_timeout_ms(void);

void pciem_port_lnksta_set(struct pciem_port *p, int cls, int nlw, int lt, int dllla);
void pciem_port_lnksta_flag(struct pciem_port *p, u16 flag);
void pciem_port_lnksta_mirror(struct pciem_port *p, u8 cls, u8 nlw);
void pciem_port_lnksta2_eq(struct pciem_port *p, bool done);
void pciem_port_dllsc(struct pciem_port *p);
void pciem_port_sdes(struct pciem_port *p);
void pciem_port_irq(struct pciem_port *p, u8 cause);
u8 pciem_port_tls(struct pciem_port *p);
void pciem_topo_kick_work(struct pciem_topo *t);

#endif
