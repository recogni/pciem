/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef PCIEM_PCITRACE_H
#define PCIEM_PCITRACE_H

#include <linux/debugfs.h>
#include <linux/spinlock.h>
#include <linux/types.h>

enum pciem_trace_fn {
	PT_FN_RP,
	PT_FN_USP,
	PT_FN_DSP,
	PT_FN_EP0,
	PT_FN_NONE = PT_FN_EP0 + 8,
};

enum pciem_trace_ev {
	PT_EV_CFG = 1,
	PT_EV_LTSSM,
	PT_EV_DL,
	PT_EV_LNKSTA,
	PT_EV_SLTSTA,
	PT_EV_AER,
	PT_EV_CTL,
	PT_EV_LINK_OP,
	PT_EV_RESET,
	PT_EV_IRQ,
	PT_EV_PHASE,
	PT_EV_MARK,
	PT_EV_MAX,
};

enum pciem_trace_why {
	PT_WHY_TIMER,
	PT_WHY_PARTNER_UP,
	PT_WHY_PARTNER_DOWN,
	PT_WHY_RETRAIN,
	PT_WHY_SBR,
	PT_WHY_HOT_RESET,
	PT_WHY_LINK_DISABLE,
	PT_WHY_LINK_ENABLE,
	PT_WHY_SPEED_STEP,
	PT_WHY_EQ_DONE,
	PT_WHY_EQ_FAIL,
	PT_WHY_TIMEOUT,
	PT_WHY_REGISTER,
	PT_WHY_MAX,
};

enum pciem_trace_ctl {
	PT_CTL_RETRAIN,
	PT_CTL_TLS,
	PT_CTL_SBR_ON,
	PT_CTL_SBR_OFF,
	PT_CTL_LD_ON,
	PT_CTL_LD_OFF,
	PT_CTL_LNKCTL,
	PT_CTL_SLTCTL,
	PT_CTL_ROOTCTL,
	PT_CTL_MSI,
	PT_CTL_MAX,
};

enum pciem_trace_reg { PT_REG_SLTSTA, PT_REG_UESTA, PT_REG_ROOTSTA };
enum pciem_trace_res { PT_RES_OK, PT_RES_UR, PT_RES_RRS, PT_RES_NODEV };
enum pciem_trace_reset { PT_RESET_FLR, PT_RESET_PM, PT_RESET_HOT, PT_RESET_POWER_ON };
enum pciem_trace_cause {
	PT_IRQ_LBMS, PT_IRQ_LABS, PT_IRQ_DLLSC, PT_IRQ_PDC, PT_IRQ_CC, PT_IRQ_AER, PT_IRQ_EP,
};
enum pciem_trace_phase {
	PT_PH_CREATE, PT_PH_TRAIN_BEGIN, PT_PH_TRAIN_DONE, PT_PH_SCAN_BEGIN, PT_PH_SCAN_DONE,
	PT_PH_ACTIVATE_BEGIN, PT_PH_ACTIVATE_DONE, PT_PH_TEARDOWN,
};
enum pciem_trace_src { PT_SRC_IOCTL, PT_SRC_DEBUGFS };

struct pciem_trace_rec {
	u64 t;
	u64 seq;
	u8 ev;
	u8 fn;
	union {
		struct { u8 bus, devfn, op, len, res; u16 off; u32 val; } cfg;
		struct { u8 from, to, speed, width, why; } ltssm;
		struct { u8 up, speed, width; } dl;
		struct { u16 old, new; u8 cls, nlw, lt, dllla, lbms, labs, hw; } lnksta;
		struct { u8 reg, hw; u32 old, new; } reg;
		struct { u8 what; u32 val; } ctl;
		struct { u8 op, speed, width, src; } link_op;
		struct { u8 kind; } reset;
		struct { u8 cause, vec, sent; } irq;
		struct { u8 name; u64 lc; } phase;
		struct { char text[32]; u64 lc; } mark;
	};
};

struct pciem_trace {
	raw_spinlock_t lock;
	struct pciem_trace_rec *recs;
	u32 size;
	u64 seq;
};

extern bool pciem_trace_cfg;
extern bool pciem_trace_ep_irq;

struct pciem_trace *pciem_trace_alloc(void);
void pciem_trace_free(struct pciem_trace *t);
void pciem_trace_clear(struct pciem_trace *t);

void pciem_trace_cfg_access(struct pciem_trace *t, u8 fn, u8 bus, u8 devfn, bool write,
							int off, int len, u32 val, u8 res);
void pciem_trace_ltssm(struct pciem_trace *t, u8 fn, u8 from, u8 to, u8 speed, u8 width, u8 why);
void pciem_trace_dl(struct pciem_trace *t, u8 fn, bool up, u8 speed, u8 width);
void pciem_trace_lnksta(struct pciem_trace *t, u8 fn, u16 old, u16 new, bool hw);
void pciem_trace_reg(struct pciem_trace *t, u8 ev, u8 fn, u8 reg, u32 old, u32 new, bool hw);
void pciem_trace_ctl(struct pciem_trace *t, u8 fn, u8 what, u32 val);
void pciem_trace_link_op(struct pciem_trace *t, u8 op, u8 speed, u8 width, u8 src);
void pciem_trace_reset(struct pciem_trace *t, u8 fn, u8 kind);
void pciem_trace_irq(struct pciem_trace *t, u8 fn, u8 cause, u8 vec, bool sent);
void pciem_trace_phase(struct pciem_trace *t, u8 name);
void pciem_trace_mark(struct pciem_trace *t, const char *text);

void pciem_trace_debugfs_create(struct dentry *dir, struct pciem_trace *t);

const char *pciem_ltssm_name(u8 state);

#endif
