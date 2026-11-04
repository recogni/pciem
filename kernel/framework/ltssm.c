// SPDX-License-Identifier: GPL-2.0-only
#define pr_fmt(fmt) KBUILD_MODNAME ": ltssm: " fmt

#include "pciem.h"
#include "capabilities.h"
#include "topology.h"

#include <linux/ctype.h>
#include <linux/module.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>

static char *pciem_ltssm_us;
module_param_named(ltssm_us, pciem_ltssm_us, charp, 0444);
MODULE_PARM_DESC(ltssm_us, "LTSSM timing defaults in microseconds: key=value,...");

static unsigned int pciem_mod_eq_fail_above;
module_param_named(eq_fail_above, pciem_mod_eq_fail_above, uint, 0644);
MODULE_PARM_DESC(eq_fail_above, "Equalization above this rate code fails (0: no limit)");

static unsigned int pciem_mod_rrs_ms;
module_param_named(rrs_ms, pciem_mod_rrs_ms, uint, 0644);
MODULE_PARM_DESC(rrs_ms, "Milliseconds a device answers config RRS after DL_Up");

static unsigned int pciem_train_timeout_ms = 1000;
module_param_named(train_timeout_ms, pciem_train_timeout_ms, uint, 0644);
MODULE_PARM_DESC(train_timeout_ms, "How long REGISTER waits for the links to settle");

static const char *const pciem_ltssm_names[LT_NSTATES] = {
	[LT_DETECT_QUIET] = "Detect.Quiet",
	[LT_DETECT_ACTIVE] = "Detect.Active",
	[LT_POLLING_ACTIVE] = "Polling.Active",
	[LT_POLLING_CONFIG] = "Polling.Configuration",
	[LT_CFG_LINKWIDTH] = "Configuration.Linkwidth",
	[LT_CFG_LANENUM] = "Configuration.Lanenum",
	[LT_CFG_COMPLETE] = "Configuration.Complete",
	[LT_CFG_IDLE] = "Configuration.Idle",
	[LT_L0] = "L0",
	[LT_REC_RCVRLOCK] = "Recovery.RcvrLock",
	[LT_REC_RCVRCFG] = "Recovery.RcvrCfg",
	[LT_REC_SPEED] = "Recovery.Speed",
	[LT_REC_EQ1] = "Recovery.Equalization.Phase1",
	[LT_REC_EQ2] = "Recovery.Equalization.Phase2",
	[LT_REC_EQ3] = "Recovery.Equalization.Phase3",
	[LT_REC_IDLE] = "Recovery.Idle",
	[LT_HOT_RESET] = "HotReset",
	[LT_DISABLED] = "Disabled",
};

static const char *const pciem_timing_names[T_NR] = {
	[T_DETECT_QUIET] = "detect_quiet",
	[T_DETECT_ACTIVE] = "detect_active",
	[T_POLLING_ACTIVE] = "polling_active",
	[T_POLLING_CONFIG] = "polling_config",
	[T_CFG_LINKWIDTH] = "cfg_linkwidth",
	[T_CFG_LANENUM] = "cfg_lanenum",
	[T_CFG_COMPLETE] = "cfg_complete",
	[T_CFG_IDLE] = "cfg_idle",
	[T_DL_INIT] = "dl_init",
	[T_L0_SETTLE] = "l0_settle",
	[T_RCVRLOCK] = "rcvrlock",
	[T_RCVRCFG] = "rcvrcfg",
	[T_RECOVERY_SPEED] = "recovery_speed",
	[T_EQ_PHASE1] = "eq_phase1",
	[T_EQ_PHASE2] = "eq_phase2",
	[T_EQ_PHASE3] = "eq_phase3",
	[T_EQ_TIMEOUT] = "eq_timeout",
	[T_RECOVERY_IDLE] = "recovery_idle",
	[T_RECOVERY_TIMEOUT] = "recovery_timeout",
	[T_HOT_RESET] = "hot_reset",
};

static u32 pciem_timing_defaults[T_NR] = {
	[T_DETECT_QUIET] = 12000, [T_DETECT_ACTIVE] = 100, [T_POLLING_ACTIVE] = 1000,
	[T_POLLING_CONFIG] = 100, [T_CFG_LINKWIDTH] = 200, [T_CFG_LANENUM] = 200,
	[T_CFG_COMPLETE] = 100, [T_CFG_IDLE] = 50, [T_DL_INIT] = 20, [T_L0_SETTLE] = 200,
	[T_RCVRLOCK] = 100, [T_RCVRCFG] = 100, [T_RECOVERY_SPEED] = 500, [T_EQ_PHASE1] = 1000,
	[T_EQ_PHASE2] = 4000, [T_EQ_PHASE3] = 4000, [T_EQ_TIMEOUT] = 32000,
	[T_RECOVERY_IDLE] = 50, [T_RECOVERY_TIMEOUT] = 24000, [T_HOT_RESET] = 2000,
};

static const s8 pciem_state_timing[LT_NSTATES] = {
	[LT_DETECT_QUIET] = T_DETECT_QUIET,
	[LT_DETECT_ACTIVE] = T_DETECT_ACTIVE,
	[LT_POLLING_ACTIVE] = T_POLLING_ACTIVE,
	[LT_POLLING_CONFIG] = T_POLLING_CONFIG,
	[LT_CFG_LINKWIDTH] = T_CFG_LINKWIDTH,
	[LT_CFG_LANENUM] = T_CFG_LANENUM,
	[LT_CFG_COMPLETE] = T_CFG_COMPLETE,
	[LT_CFG_IDLE] = T_CFG_IDLE,
	[LT_L0] = -1,
	[LT_REC_RCVRLOCK] = T_RCVRLOCK,
	[LT_REC_RCVRCFG] = T_RCVRCFG,
	[LT_REC_SPEED] = T_RECOVERY_SPEED,
	[LT_REC_EQ1] = T_EQ_PHASE1,
	[LT_REC_EQ2] = T_EQ_PHASE2,
	[LT_REC_EQ3] = T_EQ_PHASE3,
	[LT_REC_IDLE] = T_RECOVERY_IDLE,
	[LT_HOT_RESET] = T_HOT_RESET,
	[LT_DISABLED] = -1,
};

const char *pciem_ltssm_name(u8 state)
{
	return state < LT_NSTATES ? pciem_ltssm_names[state] : "?";
}

static int pciem_timing_parse(u32 *timing, char *s, bool commas)
{
	char *tok, *sep = commas ? "," : " \t\n";
	u32 tmp[T_NR];
	int ret = 0;

	memcpy(tmp, timing, sizeof(tmp));
	while ((tok = strsep(&s, sep))) {
		char *eq = strchr(tok, '=');
		unsigned int val;
		int i;

		if (!*tok)
			continue;
		if (!eq || kstrtouint(eq + 1, 10, &val)) {
			ret = -EINVAL;
			break;
		}
		*eq = '\0';
		for (i = 0; i < T_NR; i++)
			if (!strcmp(tok, pciem_timing_names[i]))
				break;
		if (i == T_NR || val > 10 * 1000 * 1000) {
			ret = -EINVAL;
			break;
		}
		tmp[i] = val;
	}
	if (!ret)
		memcpy(timing, tmp, sizeof(tmp));
	return ret;
}

void pciem_ltssm_defaults_init(void)
{
	char *dup;

	if (!pciem_ltssm_us || !*pciem_ltssm_us)
		return;
	dup = kstrdup(pciem_ltssm_us, GFP_KERNEL);
	if (!dup)
		return;
	if (pciem_timing_parse(pciem_timing_defaults, dup, true))
		pr_warn("ignoring malformed ltssm_us\n");
	kfree(dup);
}

u32 pciem_link_default_rrs_ms(void)
{
	return pciem_mod_rrs_ms;
}

u8 pciem_link_default_eq_limit(void)
{
	return min_t(unsigned int, pciem_mod_eq_fail_above, PCIEM_LINK_SPEED_64GT);
}

u32 pciem_link_train_timeout_ms(void)
{
	return pciem_train_timeout_ms;
}

static bool link_parent_ok(const struct pciem_plink *l)
{
	return !l->parent || l->parent->dl_up;
}

static bool link_state_training(u8 st)
{
	return (st >= LT_CFG_LINKWIDTH && st <= LT_CFG_IDLE) || (st >= LT_REC_RCVRLOCK && st <= LT_REC_IDLE);
}

static void link_arm(struct pciem_plink *l, u32 us)
{
	if (l->topo->dying)
		return;
	l->armed = true;
	l->deadline = ktime_add_us(ktime_get(), us);
	hrtimer_start(&l->timer, l->deadline, HRTIMER_MODE_ABS);
}

static void link_cancel(struct pciem_plink *l)
{
	l->armed = false;
	hrtimer_try_to_cancel(&l->timer);
}

static u8 link_target(const struct pciem_plink *l)
{
	u8 t = l->port->speed;
	u8 tls = pciem_port_tls(l->port);

	if (tls && tls < t)
		t = tls;
	if (l->partner_speed < t)
		t = l->partner_speed;
	if (l->allow < t)
		t = l->allow;
	return max_t(u8, t, PCIEM_LINK_SPEED_2_5GT);
}

static u8 link_plan_next(const struct pciem_plink *l)
{
	u8 target = link_target(l);

	if (!l->speed || l->speed == target)
		return 0;
	if (l->speed > target)
		return target;
	if (l->speed == PCIEM_LINK_SPEED_2_5GT && target == PCIEM_LINK_SPEED_5GT)
		return PCIEM_LINK_SPEED_5GT;
	if (l->speed < PCIEM_LINK_SPEED_8GT)
		return PCIEM_LINK_SPEED_8GT;
	return l->speed + 1;
}

static void link_goto(struct pciem_plink *l, u8 st, u8 why)
{
	u8 from = l->state;
	s8 t;

	l->state = st;
	pciem_trace_ltssm(l->topo->v->trace, l->fn, from, st, l->speed, l->width, why);
	pciem_port_lnksta_set(l->port, -1, -1, link_state_training(st), -1);

	t = pciem_state_timing[st];
	if (t < 0)
		return;
	if (st == LT_DETECT_QUIET && (!l->partner || !link_parent_ok(l)))
		return;
	link_arm(l, l->timing[t]);
}

static void link_dl_up(struct pciem_plink *l)
{
	struct pciem_topo *t = l->topo;

	l->dl_up = true;
	l->rrs_until = ktime_add_ms(ktime_get(), l->rrs_ms);
	pciem_trace_dl(t->v->trace, l->fn, true, l->speed, l->width);
	pciem_port_lnksta_set(l->port, -1, -1, -1, 1);
	pciem_port_dllsc(l->port);
	pciem_topo_kick_work(t);

	if (l == &t->links[PCIEM_ROLE_RP] && t->nports == 3) {
		struct pciem_plink *dsp = &t->links[1];

		if (dsp->state == LT_DETECT_QUIET && !dsp->armed && dsp->partner)
			link_arm(dsp, dsp->timing[T_DETECT_QUIET]);
	}
}

static void link_dl_down(struct pciem_plink *l, bool sdes)
{
	struct pciem_topo *t = l->topo;

	if (l->dl_up) {
		l->dl_up = false;
		pciem_trace_dl(t->v->trace, l->fn, false, l->speed, l->width);
		pciem_port_dllsc(l->port);
		if (sdes)
			pciem_port_sdes(l->port);
		pciem_topo_kick_work(t);
	}
	pciem_port_lnksta_set(l->port, PCIEM_LINK_SPEED_2_5GT, 0, 0, 0);
}

static void link_reset_training(struct pciem_plink *l)
{
	l->allow = 0xff;
	l->eq_done = 0;
	l->speed = 0;
	l->stuck = false;
	l->sw_retrain = false;
	l->eq_failing = false;
	l->pending_lbms = false;
	l->pending_labs = false;
	pciem_port_lnksta2_eq(l->port, false);
}

static void link_goto_detect(struct pciem_plink *l, u8 why)
{
	link_cancel(l);
	link_reset_training(l);
	link_goto(l, LT_DETECT_QUIET, why);
}

static void link_l0_entered(struct pciem_plink *l, u8 why)
{
	struct pciem_topo *t = l->topo;
	u8 width = min(l->port->width, l->partner_width);

	l->width = width;
	link_goto(l, LT_L0, why);
	pciem_port_lnksta_set(l->port, l->speed, width, 0, -1);
	if (l->pending_lbms)
		pciem_port_lnksta_flag(l->port, PCI_EXP_LNKSTA_LBMS);
	if (l->pending_labs)
		pciem_port_lnksta_flag(l->port, PCI_EXP_LNKSTA_LABS);
	l->pending_lbms = false;
	l->pending_labs = false;

	if (l == &t->links[PCIEM_ROLE_RP] && t->nports == 3)
		pciem_port_lnksta_mirror(PCIEM_PORT_USP(t), l->speed, width);
	if (l == t->ep_link)
		pciem_cap_pcie_set_lnksta(t->v, l->speed, width);

	if (!l->dl_up)
		link_arm(l, l->timing[T_DL_INIT]);
	else if (link_plan_next(l))
		link_arm(l, l->timing[T_L0_SETTLE]);
	pciem_topo_kick_work(t);
}

static void link_start_step(struct pciem_plink *l, u8 rate, u8 why)
{
	l->prev_speed = l->speed;
	l->step_to = rate;
	l->stage = STAGE_PRE;
	l->eq_failing = false;
	link_goto(l, LT_REC_RCVRLOCK, why);
}

static bool link_step_needs_eq(const struct pciem_plink *l)
{
	return l->step_to >= PCIEM_LINK_SPEED_8GT && l->step_to > l->prev_speed &&
		   !(l->eq_done & BIT(l->step_to));
}

static void link_finish_recovery(struct pciem_plink *l)
{
	u8 next;

	if (l->sw_retrain) {
		next = link_plan_next(l);
		if (next) {
			link_start_step(l, next, PT_WHY_SPEED_STEP);
			return;
		}
		l->pending_lbms = true;
		l->sw_retrain = false;
	} else if (l->speed > l->prev_speed) {
		l->pending_labs = true;
	}
	link_l0_entered(l, PT_WHY_TIMER);
}

static void link_advance_l0(struct pciem_plink *l)
{
	u8 next;

	if (!l->dl_up) {
		link_dl_up(l);
		if (link_plan_next(l))
			link_arm(l, max_t(u32, l->timing[T_L0_SETTLE], l->timing[T_DL_INIT]) -
							l->timing[T_DL_INIT] + 1);
		return;
	}
	next = link_plan_next(l);
	if (next)
		link_start_step(l, next, PT_WHY_SPEED_STEP);
}

static void link_advance(struct pciem_plink *l)
{
	u8 w = PT_WHY_TIMER;

	if (l->stuck) {
		l->stuck = false;
		link_dl_down(l, true);
		link_goto_detect(l, PT_WHY_TIMEOUT);
		return;
	}

	switch (l->state) {
	case LT_DETECT_QUIET:
		if (l->partner && link_parent_ok(l))
			link_goto(l, LT_DETECT_ACTIVE, w);
		break;
	case LT_DETECT_ACTIVE:
		if (!l->partner || !link_parent_ok(l))
			link_goto(l, LT_DETECT_QUIET, w);
		else
			link_goto(l, LT_POLLING_ACTIVE, w);
		break;
	case LT_POLLING_ACTIVE:
		link_goto(l, LT_POLLING_CONFIG, w);
		break;
	case LT_POLLING_CONFIG:
		link_goto(l, LT_CFG_LINKWIDTH, w);
		break;
	case LT_CFG_LINKWIDTH:
		link_goto(l, LT_CFG_LANENUM, w);
		break;
	case LT_CFG_LANENUM:
		link_goto(l, LT_CFG_COMPLETE, w);
		break;
	case LT_CFG_COMPLETE:
		link_goto(l, LT_CFG_IDLE, w);
		break;
	case LT_CFG_IDLE:
		l->speed = PCIEM_LINK_SPEED_2_5GT;
		link_l0_entered(l, w);
		break;
	case LT_L0:
		link_advance_l0(l);
		break;
	case LT_REC_RCVRLOCK:
		if (l->stage == STAGE_POST && link_step_needs_eq(l)) {
			l->stage = STAGE_EQ;
			link_goto(l, LT_REC_EQ1, w);
		} else {
			link_goto(l, LT_REC_RCVRCFG, w);
		}
		break;
	case LT_REC_RCVRCFG:
		if (l->stage == STAGE_PRE) {
			l->speed = l->step_to;
			link_goto(l, LT_REC_SPEED, w);
		} else {
			link_goto(l, LT_REC_IDLE, w);
		}
		break;
	case LT_REC_SPEED:
		l->stage = l->eq_failing ? STAGE_POST_EQ : STAGE_POST;
		l->eq_failing = false;
		link_goto(l, LT_REC_RCVRLOCK, w);
		break;
	case LT_REC_EQ1:
		l->eq_failing = l->eq_limit && l->step_to > l->eq_limit;
		link_goto(l, LT_REC_EQ2, w);
		break;
	case LT_REC_EQ2:
		if (l->eq_failing) {
			l->allow = l->step_to - 1;
			l->speed = l->prev_speed;
			l->pending_lbms = true;
			link_goto(l, LT_REC_SPEED, PT_WHY_EQ_FAIL);
		} else {
			link_goto(l, LT_REC_EQ3, w);
		}
		break;
	case LT_REC_EQ3:
		l->eq_done |= BIT(l->step_to);
		pciem_port_lnksta2_eq(l->port, true);
		l->stage = STAGE_POST_EQ;
		link_goto(l, LT_REC_RCVRLOCK, PT_WHY_EQ_DONE);
		break;
	case LT_REC_IDLE:
		link_finish_recovery(l);
		break;
	case LT_HOT_RESET:
		l->hot_done = true;
		if (!l->sbr)
			link_goto_detect(l, w);
		break;
	default:
		break;
	}
}

static enum hrtimer_restart link_timer_fn(struct hrtimer *timer)
{
	struct pciem_plink *l = container_of(timer, struct pciem_plink, timer);
	struct pciem_topo *t = l->topo;
	unsigned long flags;

	raw_spin_lock_irqsave(&t->lock, flags);
	if (l->armed && !t->dying &&
		!ktime_before(ktime_add_us(ktime_get(), 1), l->deadline)) {
		l->armed = false;
		link_advance(l);
	}
	raw_spin_unlock_irqrestore(&t->lock, flags);
	return HRTIMER_NORESTART;
}

void pciem_link_init(struct pciem_plink *l, struct pciem_topo *t, struct pciem_port *p,
					 struct pciem_plink *parent)
{
	l->topo = t;
	l->port = p;
	l->parent = parent;
	l->fn = p->fn;
	p->link = l;
	memcpy(l->timing, pciem_timing_defaults, sizeof(l->timing));
	l->allow = 0xff;
	l->state = LT_DETECT_QUIET;
#ifdef PCIEM_HAVE_HRTIMER_SETUP
	hrtimer_setup(&l->timer, link_timer_fn, CLOCK_MONOTONIC, HRTIMER_MODE_ABS);
#else
	hrtimer_init(&l->timer, CLOCK_MONOTONIC, HRTIMER_MODE_ABS);
	l->timer.function = link_timer_fn;
#endif
}

void pciem_link_start(struct pciem_plink *l)
{
	guard(raw_spinlock_irqsave)(&l->topo->lock);
	link_goto_detect(l, PT_WHY_REGISTER);
}

void pciem_link_stop(struct pciem_plink *l)
{
	hrtimer_cancel(&l->timer);
}

void pciem_link_partner(struct pciem_plink *l, bool present, u8 speed, u8 width)
{
	lockdep_assert_held(&l->topo->lock);

	if (present) {
		l->partner = true;
		l->partner_speed = speed;
		l->partner_width = width;
		if (l->stuck) {
			l->stuck = false;
			if (l->state == LT_REC_RCVRLOCK) {
				link_cancel(l);
				l->step_to = l->speed;
				l->prev_speed = l->speed;
				l->stage = STAGE_POST_EQ;
				link_goto(l, LT_REC_RCVRCFG, PT_WHY_PARTNER_UP);
			} else {
				link_goto_detect(l, PT_WHY_PARTNER_UP);
			}
		} else if (l->state == LT_DETECT_QUIET && !l->armed && link_parent_ok(l)) {
			link_arm(l, l->timing[T_DETECT_QUIET]);
		}
		return;
	}

	l->partner = false;
	switch (l->state) {
	case LT_DETECT_QUIET:
		link_cancel(l);
		break;
	case LT_DETECT_ACTIVE:
	case LT_POLLING_ACTIVE:
	case LT_POLLING_CONFIG:
		link_goto_detect(l, PT_WHY_PARTNER_DOWN);
		break;
	case LT_HOT_RESET:
	case LT_DISABLED:
		break;
	default:
		link_cancel(l);
		l->stuck = true;
		if (l->state == LT_L0)
			link_goto(l, LT_REC_RCVRLOCK, PT_WHY_PARTNER_DOWN);
		link_arm(l, l->timing[T_RECOVERY_TIMEOUT]);
		break;
	}
}

void pciem_link_retrain(struct pciem_plink *l)
{
	u8 next;

	lockdep_assert_held(&l->topo->lock);
	if (l->state != LT_L0 || !l->dl_up || l->topo->dying)
		return;

	l->allow = 0xff;
	l->eq_done = 0;
	l->sw_retrain = true;
	next = link_plan_next(l);
	link_cancel(l);
	link_start_step(l, next ?: l->speed, PT_WHY_RETRAIN);
}

void pciem_link_disable(struct pciem_plink *l, bool disable)
{
	lockdep_assert_held(&l->topo->lock);

	l->ld = disable;
	if (disable) {
		link_cancel(l);
		link_dl_down(l, false);
		link_reset_training(l);
		link_goto(l, LT_DISABLED, PT_WHY_LINK_DISABLE);
	} else if (l->state == LT_DISABLED) {
		link_goto_detect(l, PT_WHY_LINK_ENABLE);
	}
}

static void link_enter_hot_reset(struct pciem_plink *l, u8 why)
{
	link_cancel(l);
	link_dl_down(l, false);
	link_reset_training(l);
	l->hot_done = false;
	link_goto(l, LT_HOT_RESET, why);
}

void pciem_link_sbr(struct pciem_plink *l, bool set)
{
	lockdep_assert_held(&l->topo->lock);

	l->sbr = set;
	if (set)
		link_enter_hot_reset(l, PT_WHY_SBR);
	else if (l->state == LT_HOT_RESET && l->hot_done)
		link_goto_detect(l, PT_WHY_TIMER);
}

void pciem_link_hot_reset_from_above(struct pciem_plink *l)
{
	lockdep_assert_held(&l->topo->lock);
	link_enter_hot_reset(l, PT_WHY_HOT_RESET);
}

void pciem_link_set_eq_limit(struct pciem_plink *l, u8 limit)
{
	lockdep_assert_held(&l->topo->lock);
	l->eq_limit = limit;
	l->allow = 0xff;
	l->eq_done = 0;
}

bool pciem_link_settled(struct pciem_plink *l)
{
	return l->state == LT_L0 && l->dl_up && !l->stuck && !link_plan_next(l);
}

void pciem_link_state_line(struct pciem_plink *l, char *buf, size_t len)
{
	struct pciem_port *p = l->port;
	unsigned long flags;
	u16 sta;
	s64 left_ms = 0;

	raw_spin_lock_irqsave(&l->topo->lock, flags);
	sta = get_unaligned_le16(&p->cfg[p->pcie + PCI_EXP_LNKSTA]);
	if (ktime_after(l->rrs_until, ktime_get()))
		left_ms = ktime_ms_delta(l->rrs_until, ktime_get());
	scnprintf(buf, len,
			  "ltssm=%s speed=%u width=%u dl=%s lt=%u dllla=%u lbms=%u labs=%u tls=%u target=%u partner=%s partner_speed=%u partner_width=%u eq_limit=%u eq_done=0x%02x sbr=%u ld=%u rrs_left_ms=%lld\n",
			  pciem_ltssm_name(l->state), sta & PCI_EXP_LNKSTA_CLS,
			  (sta & PCI_EXP_LNKSTA_NLW) >> 4, l->dl_up ? "up" : "down",
			  !!(sta & PCI_EXP_LNKSTA_LT), !!(sta & PCI_EXP_LNKSTA_DLLLA),
			  !!(sta & PCI_EXP_LNKSTA_LBMS), !!(sta & PCI_EXP_LNKSTA_LABS), pciem_port_tls(p),
			  link_target(l), l->partner ? "up" : "down", l->partner_speed, l->partner_width,
			  l->eq_limit, l->eq_done, l->sbr, l->ld, left_ms);
	raw_spin_unlock_irqrestore(&l->topo->lock, flags);
}

int pciem_link_timing_set(struct pciem_plink *l, const char *kv)
{
	char *dup = kstrdup(kv, GFP_KERNEL);
	u32 tmp[T_NR];
	int ret;

	if (!dup)
		return -ENOMEM;
	scoped_guard(raw_spinlock_irqsave, &l->topo->lock)
		memcpy(tmp, l->timing, sizeof(tmp));
	ret = pciem_timing_parse(tmp, dup, false);
	kfree(dup);
	if (ret)
		return ret;
	guard(raw_spinlock_irqsave)(&l->topo->lock);
	memcpy(l->timing, tmp, sizeof(tmp));
	return 0;
}

static ssize_t link_state_read(struct file *file, char __user *buf, size_t count, loff_t *ppos)
{
	char line[320];

	pciem_link_state_line(file->private_data, line, sizeof(line));
	return simple_read_from_buffer(buf, count, ppos, line, strlen(line));
}

static ssize_t link_eq_read(struct file *file, char __user *buf, size_t count, loff_t *ppos)
{
	struct pciem_plink *l = file->private_data;
	char line[8];
	int len = scnprintf(line, sizeof(line), "%u\n", READ_ONCE(l->eq_limit));

	return simple_read_from_buffer(buf, count, ppos, line, len);
}

static ssize_t link_eq_write(struct file *file, const char __user *buf, size_t count, loff_t *ppos)
{
	struct pciem_plink *l = file->private_data;
	unsigned int v;
	int ret = kstrtouint_from_user(buf, count, 10, &v);

	if (ret)
		return ret;
	if (v > PCIEM_LINK_SPEED_64GT)
		return -EINVAL;
	scoped_guard(raw_spinlock_irqsave, &l->topo->lock)
		pciem_link_set_eq_limit(l, v);
	pciem_trace_link_op(l->topo->v->trace, PCIEM_LINK_EQ_LIMIT, v, 0, PT_SRC_DEBUGFS);
	return count;
}

static ssize_t link_rrs_read(struct file *file, char __user *buf, size_t count, loff_t *ppos)
{
	struct pciem_plink *l = file->private_data;
	char line[16];
	int len = scnprintf(line, sizeof(line), "%u\n", READ_ONCE(l->rrs_ms));

	return simple_read_from_buffer(buf, count, ppos, line, len);
}

static ssize_t link_rrs_write(struct file *file, const char __user *buf, size_t count, loff_t *ppos)
{
	struct pciem_plink *l = file->private_data;
	unsigned int v;
	int ret = kstrtouint_from_user(buf, count, 10, &v);

	if (ret)
		return ret;
	if (v > 60000)
		return -EINVAL;
	WRITE_ONCE(l->rrs_ms, v);
	return count;
}

static ssize_t link_timing_read(struct file *file, char __user *buf, size_t count, loff_t *ppos)
{
	struct pciem_plink *l = file->private_data;
	char *out = kmalloc(T_NR * 32, GFP_KERNEL);
	ssize_t ret;
	int i, len = 0;

	if (!out)
		return -ENOMEM;
	scoped_guard(raw_spinlock_irqsave, &l->topo->lock)
		for (i = 0; i < T_NR; i++)
			len += scnprintf(out + len, T_NR * 32 - len, "%s=%u\n", pciem_timing_names[i],
							 l->timing[i]);
	ret = simple_read_from_buffer(buf, count, ppos, out, len);
	kfree(out);
	return ret;
}

static ssize_t link_timing_write(struct file *file, const char __user *buf, size_t count,
								 loff_t *ppos)
{
	struct pciem_plink *l = file->private_data;
	char *line;
	int ret;

	if (count == 0 || count > 1024)
		return -EINVAL;
	line = memdup_user_nul(buf, count);
	if (IS_ERR(line))
		return PTR_ERR(line);
	ret = pciem_link_timing_set(l, line);
	kfree(line);
	return ret ?: count;
}

#define LINK_FOPS(name, rd, wr)                                                                    \
	static const struct file_operations name = {                                                   \
		.owner = THIS_MODULE, .open = simple_open, .read = rd, .write = wr,                        \
		.llseek = default_llseek,                                                                  \
	}

LINK_FOPS(link_state_fops, link_state_read, NULL);
LINK_FOPS(link_eq_fops, link_eq_read, link_eq_write);
LINK_FOPS(link_rrs_fops, link_rrs_read, link_rrs_write);
LINK_FOPS(link_timing_fops, link_timing_read, link_timing_write);

void pciem_plink_debugfs_create(struct pciem_plink *l, struct dentry *dir)
{
	debugfs_create_file("state", 0400, dir, l, &link_state_fops);
	debugfs_create_file("eq_limit", 0600, dir, l, &link_eq_fops);
	debugfs_create_file("timing", 0600, dir, l, &link_timing_fops);
	debugfs_create_file("rrs_ms", 0600, dir, l, &link_rrs_fops);
}
