// SPDX-License-Identifier: GPL-2.0-only
#define pr_fmt(fmt) KBUILD_MODNAME ": trace: " fmt

#include "pcitrace.h"
#include "pciem.h"

#include <linux/ctype.h>
#include <linux/module.h>
#include <linux/sched/clock.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/vmalloc.h>

#define PT_MIN_RECORDS 1024

bool pciem_trace_cfg;
module_param_named(trace_cfg, pciem_trace_cfg, bool, 0644);
MODULE_PARM_DESC(trace_cfg, "Record config space accesses in the per-device trace");

bool pciem_trace_ep_irq;
module_param_named(trace_ep_irq, pciem_trace_ep_irq, bool, 0644);
MODULE_PARM_DESC(trace_ep_irq, "Record the device's MSI and INTx in the per-device trace");

static unsigned int pciem_trace_records = 16384;
module_param_named(trace_records, pciem_trace_records, uint, 0444);
MODULE_PARM_DESC(trace_records, "Records in each device's trace ring (minimum 1024)");

static const char *const pt_fn_names[] = {
	"rp", "usp", "dsp", "ep0", "ep1", "ep2", "ep3", "ep4", "ep5", "ep6", "ep7", "none",
};

static const char *const pt_why_names[PT_WHY_MAX] = {
	"timer", "partner_up", "partner_down", "retrain", "sbr", "hot_reset", "link_disable",
	"link_enable", "speed_step", "eq_done", "eq_fail", "timeout", "register",
};

static const char *const pt_ctl_names[PT_CTL_MAX] = {
	"retrain", "tls", "sbr_on", "sbr_off", "ld_on", "ld_off", "lnkctl", "sltctl", "rootctl", "msi",
};

static const char *const pt_reg_names[] = { "sltsta", "uesta", "rootsta" };
static const char *const pt_res_names[] = { "ok", "ur", "rrs", "nodev" };
static const char *const pt_reset_names[] = { "flr", "pm", "hot", "power_on" };
static const char *const pt_cause_names[] = { "lbms", "labs", "dllsc", "pdc", "cc", "aer", "ep" };
static const char *const pt_phase_names[] = {
	"create", "train_begin", "train_done", "scan_begin", "scan_done", "activate_begin",
	"activate_done", "teardown",
};
static const char *const pt_link_op_names[] = { "", "down", "up", "eq_limit" };

struct pciem_trace *pciem_trace_alloc(void)
{
	struct pciem_trace *t;
	u32 n = max_t(u32, pciem_trace_records, PT_MIN_RECORDS);

	t = kzalloc(sizeof(*t), GFP_KERNEL);
	if (!t)
		return NULL;
	t->recs = kvcalloc(n, sizeof(*t->recs), GFP_KERNEL);
	if (!t->recs) {
		kfree(t);
		return NULL;
	}
	t->size = n;
	raw_spin_lock_init(&t->lock);
	return t;
}

void pciem_trace_free(struct pciem_trace *t)
{
	if (!t)
		return;
	kvfree(t->recs);
	kfree(t);
}

void pciem_trace_clear(struct pciem_trace *t)
{
	guard(raw_spinlock_irqsave)(&t->lock);
	t->seq = 0;
}

static struct pciem_trace_rec *pt_begin(struct pciem_trace *t, u8 ev, u8 fn)
{
	struct pciem_trace_rec *r = &t->recs[t->seq % t->size];

	memset(r, 0, sizeof(*r));
	r->t = ktime_get_ns();
	r->seq = t->seq++;
	r->ev = ev;
	r->fn = fn;
	return r;
}

void pciem_trace_cfg_access(struct pciem_trace *t, u8 fn, u8 bus, u8 devfn, bool write,
							int off, int len, u32 val, u8 res)
{
	struct pciem_trace_rec *r;
	unsigned long flags;

	if (!t || !READ_ONCE(pciem_trace_cfg))
		return;
	raw_spin_lock_irqsave(&t->lock, flags);
	r = pt_begin(t, PT_EV_CFG, fn);
	r->cfg.bus = bus;
	r->cfg.devfn = devfn;
	r->cfg.op = write;
	r->cfg.len = len;
	r->cfg.res = res;
	r->cfg.off = off;
	r->cfg.val = val;
	raw_spin_unlock_irqrestore(&t->lock, flags);
}

void pciem_trace_ltssm(struct pciem_trace *t, u8 fn, u8 from, u8 to, u8 speed, u8 width, u8 why)
{
	struct pciem_trace_rec *r;
	unsigned long flags;

	if (!t)
		return;
	raw_spin_lock_irqsave(&t->lock, flags);
	r = pt_begin(t, PT_EV_LTSSM, fn);
	r->ltssm.from = from;
	r->ltssm.to = to;
	r->ltssm.speed = speed;
	r->ltssm.width = width;
	r->ltssm.why = why;
	raw_spin_unlock_irqrestore(&t->lock, flags);
}

void pciem_trace_dl(struct pciem_trace *t, u8 fn, bool up, u8 speed, u8 width)
{
	struct pciem_trace_rec *r;
	unsigned long flags;

	if (!t)
		return;
	raw_spin_lock_irqsave(&t->lock, flags);
	r = pt_begin(t, PT_EV_DL, fn);
	r->dl.up = up;
	r->dl.speed = speed;
	r->dl.width = width;
	raw_spin_unlock_irqrestore(&t->lock, flags);
}

void pciem_trace_lnksta(struct pciem_trace *t, u8 fn, u16 old, u16 new, bool hw)
{
	struct pciem_trace_rec *r;
	unsigned long flags;

	if (!t)
		return;
	raw_spin_lock_irqsave(&t->lock, flags);
	r = pt_begin(t, PT_EV_LNKSTA, fn);
	r->lnksta.old = old;
	r->lnksta.new = new;
	r->lnksta.cls = new & 0xf;
	r->lnksta.nlw = (new >> 4) & 0x3f;
	r->lnksta.lt = !!(new & 0x0800);
	r->lnksta.dllla = !!(new & 0x2000);
	r->lnksta.lbms = !!(new & 0x4000);
	r->lnksta.labs = !!(new & 0x8000);
	r->lnksta.hw = hw;
	raw_spin_unlock_irqrestore(&t->lock, flags);
}

void pciem_trace_reg(struct pciem_trace *t, u8 ev, u8 fn, u8 reg, u32 old, u32 new, bool hw)
{
	struct pciem_trace_rec *r;
	unsigned long flags;

	if (!t)
		return;
	raw_spin_lock_irqsave(&t->lock, flags);
	r = pt_begin(t, ev, fn);
	r->reg.reg = reg;
	r->reg.old = old;
	r->reg.new = new;
	r->reg.hw = hw;
	raw_spin_unlock_irqrestore(&t->lock, flags);
}

void pciem_trace_ctl(struct pciem_trace *t, u8 fn, u8 what, u32 val)
{
	struct pciem_trace_rec *r;
	unsigned long flags;

	if (!t)
		return;
	raw_spin_lock_irqsave(&t->lock, flags);
	r = pt_begin(t, PT_EV_CTL, fn);
	r->ctl.what = what;
	r->ctl.val = val;
	raw_spin_unlock_irqrestore(&t->lock, flags);
}

void pciem_trace_link_op(struct pciem_trace *t, u8 op, u8 speed, u8 width, u8 src)
{
	struct pciem_trace_rec *r;
	unsigned long flags;

	if (!t)
		return;
	raw_spin_lock_irqsave(&t->lock, flags);
	r = pt_begin(t, PT_EV_LINK_OP, PT_FN_NONE);
	r->link_op.op = op;
	r->link_op.speed = speed;
	r->link_op.width = width;
	r->link_op.src = src;
	raw_spin_unlock_irqrestore(&t->lock, flags);
}

void pciem_trace_reset(struct pciem_trace *t, u8 fn, u8 kind)
{
	struct pciem_trace_rec *r;
	unsigned long flags;

	if (!t)
		return;
	raw_spin_lock_irqsave(&t->lock, flags);
	r = pt_begin(t, PT_EV_RESET, fn);
	r->reset.kind = kind;
	raw_spin_unlock_irqrestore(&t->lock, flags);
}

void pciem_trace_irq(struct pciem_trace *t, u8 fn, u8 cause, u8 vec, bool sent)
{
	struct pciem_trace_rec *r;
	unsigned long flags;

	if (!t)
		return;
	raw_spin_lock_irqsave(&t->lock, flags);
	r = pt_begin(t, PT_EV_IRQ, fn);
	r->irq.cause = cause;
	r->irq.vec = vec;
	r->irq.sent = sent;
	raw_spin_unlock_irqrestore(&t->lock, flags);
}

void pciem_trace_phase(struct pciem_trace *t, u8 name)
{
	struct pciem_trace_rec *r;
	unsigned long flags;

	if (!t)
		return;
	raw_spin_lock_irqsave(&t->lock, flags);
	r = pt_begin(t, PT_EV_PHASE, PT_FN_NONE);
	r->phase.name = name;
	r->phase.lc = local_clock();
	raw_spin_unlock_irqrestore(&t->lock, flags);
}

void pciem_trace_mark(struct pciem_trace *t, const char *text)
{
	struct pciem_trace_rec *r;
	unsigned long flags;

	if (!t)
		return;
	raw_spin_lock_irqsave(&t->lock, flags);
	r = pt_begin(t, PT_EV_MARK, PT_FN_NONE);
	strscpy(r->mark.text, text, sizeof(r->mark.text));
	r->mark.lc = local_clock();
	raw_spin_unlock_irqrestore(&t->lock, flags);
}

struct pt_iter {
	struct pciem_trace *t;
	u64 first;
	u64 snap;
};

static u64 pt_oldest(struct pciem_trace *t)
{
	return t->seq > t->size ? t->seq - t->size : 0;
}

static void pt_render(struct seq_file *m, const struct pciem_trace_rec *r)
{
	const char *fn = pt_fn_names[min_t(u8, r->fn, PT_FN_NONE)];

	seq_printf(m, "{\"t\":%llu,\"seq\":%llu,", r->t, r->seq);

	switch (r->ev) {
	case PT_EV_CFG:
		seq_printf(m, "\"ev\":\"cfg\",\"fn\":\"%s\",\"bus\":%u,\"devfn\":%u,\"op\":\"%c\",\"off\":%u,\"len\":%u,\"val\":%u,\"res\":\"%s\"}\n",
				   fn, r->cfg.bus, r->cfg.devfn, r->cfg.op ? 'w' : 'r', r->cfg.off, r->cfg.len,
				   r->cfg.val, pt_res_names[min_t(u8, r->cfg.res, PT_RES_NODEV)]);
		break;
	case PT_EV_LTSSM:
		seq_printf(m, "\"ev\":\"ltssm\",\"fn\":\"%s\",\"from\":\"%s\",\"to\":\"%s\",\"speed\":%u,\"width\":%u,\"why\":\"%s\"}\n",
				   fn, pciem_ltssm_name(r->ltssm.from), pciem_ltssm_name(r->ltssm.to),
				   r->ltssm.speed, r->ltssm.width,
				   pt_why_names[min_t(u8, r->ltssm.why, PT_WHY_MAX - 1)]);
		break;
	case PT_EV_DL:
		seq_printf(m, "\"ev\":\"dl\",\"fn\":\"%s\",\"up\":%s,\"speed\":%u,\"width\":%u}\n", fn,
				   r->dl.up ? "true" : "false", r->dl.speed, r->dl.width);
		break;
	case PT_EV_LNKSTA:
		seq_printf(m, "\"ev\":\"lnksta\",\"fn\":\"%s\",\"old\":%u,\"new\":%u,\"cls\":%u,\"nlw\":%u,\"lt\":%u,\"dllla\":%u,\"lbms\":%u,\"labs\":%u,\"why\":\"%s\"}\n",
				   fn, r->lnksta.old, r->lnksta.new, r->lnksta.cls, r->lnksta.nlw, r->lnksta.lt,
				   r->lnksta.dllla, r->lnksta.lbms, r->lnksta.labs, r->lnksta.hw ? "hw" : "sw");
		break;
	case PT_EV_SLTSTA:
	case PT_EV_AER:
		seq_printf(m, "\"ev\":\"%s\",\"fn\":\"%s\",\"reg\":\"%s\",\"old\":%u,\"new\":%u,\"why\":\"%s\"}\n",
				   r->ev == PT_EV_AER ? "aer" : "sltsta", fn,
				   pt_reg_names[min_t(u8, r->reg.reg, PT_REG_ROOTSTA)], r->reg.old, r->reg.new,
				   r->reg.hw ? "hw" : "sw");
		break;
	case PT_EV_CTL:
		seq_printf(m, "\"ev\":\"ctl\",\"fn\":\"%s\",\"what\":\"%s\",\"val\":%u}\n", fn,
				   pt_ctl_names[min_t(u8, r->ctl.what, PT_CTL_MAX - 1)], r->ctl.val);
		break;
	case PT_EV_LINK_OP:
		seq_printf(m, "\"ev\":\"link_op\",\"fn\":\"%s\",\"op\":\"%s\",\"speed\":%u,\"width\":%u,\"src\":\"%s\"}\n",
				   fn, pt_link_op_names[min_t(u8, r->link_op.op, 3)], r->link_op.speed,
				   r->link_op.width, r->link_op.src == PT_SRC_IOCTL ? "ioctl" : "debugfs");
		break;
	case PT_EV_RESET:
		seq_printf(m, "\"ev\":\"reset\",\"fn\":\"%s\",\"kind\":\"%s\"}\n", fn,
				   pt_reset_names[min_t(u8, r->reset.kind, PT_RESET_POWER_ON)]);
		break;
	case PT_EV_IRQ:
		seq_printf(m, "\"ev\":\"irq\",\"fn\":\"%s\",\"cause\":\"%s\",\"vec\":%u,\"sent\":%s}\n", fn,
				   pt_cause_names[min_t(u8, r->irq.cause, PT_IRQ_EP)], r->irq.vec,
				   r->irq.sent ? "true" : "false");
		break;
	case PT_EV_PHASE:
		seq_printf(m, "\"ev\":\"phase\",\"fn\":\"%s\",\"name\":\"%s\",\"lc\":%llu}\n", fn,
				   pt_phase_names[min_t(u8, r->phase.name, PT_PH_TEARDOWN)], r->phase.lc);
		break;
	case PT_EV_MARK:
		seq_printf(m, "\"ev\":\"mark\",\"fn\":\"%s\",\"text\":\"%s\",\"lc\":%llu}\n", fn,
				   r->mark.text, r->mark.lc);
		break;
	default:
		seq_printf(m, "\"ev\":\"unknown\",\"fn\":\"%s\"}\n", fn);
	}
}

static void *pt_seq_start(struct seq_file *m, loff_t *pos)
{
	struct pt_iter *it = m->private;
	u64 total = it->snap - it->first + (it->first ? 1 : 0);

	return (u64)*pos < total ? it : NULL;
}

static void *pt_seq_next(struct seq_file *m, void *v, loff_t *pos)
{
	(*pos)++;
	return pt_seq_start(m, pos);
}

static void pt_seq_stop(struct seq_file *m, void *v)
{
}

static int pt_seq_show(struct seq_file *m, void *v)
{
	struct pt_iter *it = m->private;
	struct pciem_trace *t = it->t;
	struct pciem_trace_rec rec;
	loff_t pos = m->index;
	u64 seq, oldest;
	unsigned long flags;

	if (it->first && pos == 0) {
		raw_spin_lock_irqsave(&t->lock, flags);
		rec = t->recs[it->first % t->size];
		raw_spin_unlock_irqrestore(&t->lock, flags);
		seq_printf(m, "{\"t\":%llu,\"seq\":%llu,\"ev\":\"lost\",\"fn\":\"none\",\"n\":%llu}\n",
				   rec.t, it->first - 1, it->first);
		return 0;
	}

	seq = it->first + pos - (it->first ? 1 : 0);
	raw_spin_lock_irqsave(&t->lock, flags);
	oldest = pt_oldest(t);
	rec = t->recs[seq % t->size];
	raw_spin_unlock_irqrestore(&t->lock, flags);

	if (seq < oldest || rec.seq != seq)
		return 0;
	pt_render(m, &rec);
	return 0;
}

static const struct seq_operations pt_seq_ops = {
	.start = pt_seq_start,
	.next = pt_seq_next,
	.stop = pt_seq_stop,
	.show = pt_seq_show,
};

static int pt_open(struct inode *inode, struct file *file)
{
	struct pt_iter *it;
	int ret;

	ret = seq_open_private(file, &pt_seq_ops, sizeof(*it));
	if (ret)
		return ret;
	it = ((struct seq_file *)file->private_data)->private;
	it->t = inode->i_private;
	scoped_guard(raw_spinlock_irqsave, &it->t->lock) {
		it->snap = it->t->seq;
		it->first = pt_oldest(it->t);
	}
	return 0;
}

static const struct file_operations pt_fops = {
	.owner = THIS_MODULE,
	.open = pt_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = seq_release_private,
};

static ssize_t pt_ctl_write(struct file *file, const char __user *buf, size_t count, loff_t *ppos)
{
	struct pciem_trace *t = file->private_data;
	char line[64], *text;
	size_t i;

	if (count == 0 || count >= sizeof(line))
		return -EINVAL;
	if (copy_from_user(line, buf, count))
		return -EFAULT;
	line[count] = '\0';
	strim(line);

	if (!strcmp(line, "clear")) {
		pciem_trace_clear(t);
		return count;
	}
	if (strncmp(line, "mark ", 5))
		return -EINVAL;
	text = skip_spaces(line + 5);
	if (!*text || strlen(text) > 31)
		return -EINVAL;
	for (i = 0; text[i]; i++)
		if (!isalnum(text[i]) && !strchr("_.:=-", text[i]))
			return -EINVAL;
	pciem_trace_mark(t, text);
	return count;
}

static const struct file_operations pt_ctl_fops = {
	.owner = THIS_MODULE,
	.open = simple_open,
	.write = pt_ctl_write,
};

void pciem_trace_debugfs_create(struct dentry *dir, struct pciem_trace *t)
{
	debugfs_create_file("trace", 0400, dir, t, &pt_fops);
	debugfs_create_file("trace_ctl", 0200, dir, t, &pt_ctl_fops);
}
