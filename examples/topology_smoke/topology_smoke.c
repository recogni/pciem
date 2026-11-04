// SPDX-License-Identifier: MIT
#define _GNU_SOURCE
#include <ctype.h>
#include <dirent.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/klog.h>
#include <sys/mman.h>
#include <linux/pci_regs.h>

#include "pciem_api.h"

#define EP_VENDOR 0x1ab8
#define EP_DEVICE 0xd124
#define BAR0_SIZE (1u << 20)
#define BAR2_SIZE (16u << 20)
#define MAX_CHAIN 4
#define TRACE_MAX (64u << 20)

static int ctl_fd = -1;
static int instance_fd = -1;
static struct pciem_shared_ring *ring;
static int failures;
static int eq_mode;
static int placement;
static uint32_t topo_flags;

static char chain[MAX_CHAIN][16];
static int depth;
static char ep_bdf[16];
static char port_bdf[16];
static char dbg[160];
static char portdir[200];
static int port_is_dsp;

static void report(int ok, const char *fmt, ...)
{
	va_list ap;

	printf("%s: ", ok ? "ok" : "FAIL");
	va_start(ap, fmt);
	vprintf(fmt, ap);
	va_end(ap);
	putchar('\n');
	fflush(stdout);
	if (!ok)
		failures++;
}

static void note(const char *fmt, ...)
{
	va_list ap;

	printf("info: ");
	va_start(ap, fmt);
	vprintf(fmt, ap);
	va_end(ap);
	putchar('\n');
	fflush(stdout);
}

static long now_ms(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static int ev_resets[8];

static void drain_events(int *unused)
{
	(void)unused;
	int head = atomic_load(&ring->head);
	int tail = atomic_load_explicit(&ring->tail, memory_order_acquire);

	while (head != tail) {
		struct pciem_event *ev = &ring->events[head];

		if (ev->type == PCIEM_EVENT_RESET && ev->data < 8)
			ev_resets[ev->data]++;
		head = (head + 1) % PCIEM_RING_SIZE;
	}
	atomic_store_explicit(&ring->head, head, memory_order_release);
}

static void sleep_ms(int ms)
{
	long end = now_ms() + ms;

	while (now_ms() < end) {
		drain_events(NULL);
		usleep(5000);
	}
}

static ssize_t slurp(const char *path, char *buf, size_t size)
{
	int fd = open(path, O_RDONLY);
	size_t got = 0;
	ssize_t n;

	if (fd < 0)
		return -1;
	while (got + 1 < size && (n = read(fd, buf + got, size - 1 - got)) > 0)
		got += n;
	close(fd);
	buf[got] = '\0';
	return got;
}

static int read_text(const char *path, char *buf, size_t size)
{
	ssize_t n = slurp(path, buf, size);

	if (n < 0)
		return -1;
	while (n > 0 && (buf[n - 1] == '\n' || buf[n - 1] == ' '))
		buf[--n] = '\0';
	return 0;
}

static int write_str(const char *path, const char *s)
{
	int fd = open(path, O_WRONLY);
	ssize_t n;
	int saved;

	if (fd < 0)
		return -1;
	n = write(fd, s, strlen(s));
	saved = errno;
	close(fd);
	errno = saved;
	return n == (ssize_t)strlen(s) ? 0 : -1;
}

static long read_hex(const char *path)
{
	char buf[32];

	if (read_text(path, buf, sizeof(buf)))
		return -1;
	return strtol(buf, NULL, 16);
}

static int sys_read(const char *bdf, const char *name, char *buf, size_t size)
{
	char path[200];

	snprintf(path, sizeof(path), "/sys/bus/pci/devices/%s/%s", bdf, name);
	return read_text(path, buf, size);
}

static int cfg_read(const char *bdf, unsigned int off, int len, uint32_t *val)
{
	char path[200];
	uint8_t b[4] = {};
	int fd;

	snprintf(path, sizeof(path), "/sys/bus/pci/devices/%s/config", bdf);
	fd = open(path, O_RDONLY);
	if (fd < 0 || pread(fd, b, len, off) != len) {
		if (fd >= 0)
			close(fd);
		return -1;
	}
	close(fd);
	*val = b[0] | b[1] << 8 | b[2] << 16 | (uint32_t)b[3] << 24;
	return 0;
}

static int cfg_write16(const char *bdf, unsigned int off, uint16_t v)
{
	char path[200];
	int fd, ok;

	snprintf(path, sizeof(path), "/sys/bus/pci/devices/%s/config", bdf);
	fd = open(path, O_WRONLY);
	if (fd < 0)
		return -1;
	ok = pwrite(fd, &v, 2, off) == 2;
	close(fd);
	return ok ? 0 : -1;
}

static int cfg_write32(const char *bdf, unsigned int off, uint32_t v)
{
	char path[200];
	int fd, ok;

	snprintf(path, sizeof(path), "/sys/bus/pci/devices/%s/config", bdf);
	fd = open(path, O_WRONLY);
	if (fd < 0)
		return -1;
	ok = pwrite(fd, &v, 4, off) == 4;
	close(fd);
	return ok ? 0 : -1;
}

static int pcie_cap(const char *bdf)
{
	uint32_t ptr, hdr;
	int guard = 0;

	if (cfg_read(bdf, PCI_CAPABILITY_LIST, 1, &ptr))
		return -1;
	while (ptr && guard++ < 48) {
		if (cfg_read(bdf, ptr, 2, &hdr))
			return -1;
		if ((hdr & 0xff) == PCI_CAP_ID_EXP)
			return ptr;
		ptr = hdr >> 8;
	}
	return -1;
}

static char *dbg_path(const char *rel)
{
	static char path[320];

	snprintf(path, sizeof(path), "%s/%s", dbg, rel);
	return path;
}

static char *port_file(const char *name)
{
	static char path[320];

	snprintf(path, sizeof(path), "%s/%s", portdir, name);
	return path;
}

static int state_get(const char *key, char *out, size_t size)
{
	char buf[512], pat[64], *p, *e;

	if (read_text(port_file("state"), buf, sizeof(buf)))
		return -1;
	snprintf(pat, sizeof(pat), "%s=", key);
	p = strstr(buf, pat);
	while (p && p != buf && p[-1] != ' ')
		p = strstr(p + 1, pat);
	if (!p)
		return -1;
	p += strlen(pat);
	e = strchr(p, ' ');
	snprintf(out, size, "%.*s", (int)(e ? e - p : (int)strlen(p)), p);
	return 0;
}

static int state_is(const char *key, const char *want)
{
	char v[64];

	return !state_get(key, v, sizeof(v)) && !strcmp(v, want);
}

static int wait_state(int timeout_ms, int nkv, ...)
{
	const char *kv[8];
	va_list ap;
	long end = now_ms() + timeout_ms;
	int i;

	va_start(ap, nkv);
	for (i = 0; i < nkv && i < 8; i++)
		kv[i] = va_arg(ap, const char *);
	va_end(ap);
	do {
		int ok = 1;

		for (i = 0; i < nkv; i += 2)
			ok = ok && state_is(kv[i], kv[i + 1]);
		if (ok)
			return 0;
		drain_events(NULL);
		usleep(2000);
	} while (now_ms() < end);
	return -1;
}

static char *trace_buf;
static size_t trace_len;

static void trace_load(void)
{
	if (!trace_buf)
		trace_buf = malloc(TRACE_MAX);
	if (!trace_buf)
		err(1, "malloc");
	if (slurp(dbg_path("trace"), trace_buf, TRACE_MAX) < 0)
		err(1, "read trace");
	trace_len = strlen(trace_buf);
}

static void trace_mark(const char *text)
{
	char cmd[64];

	snprintf(cmd, sizeof(cmd), "mark %s", text);
	if (write_str(dbg_path("trace_ctl"), cmd))
		err(1, "write trace_ctl");
}

static const char *after_mark(const char *text)
{
	char pat[80], *p;

	snprintf(pat, sizeof(pat), "\"text\":\"%s\"", text);
	trace_load();
	p = strstr(trace_buf, pat);
	if (!p)
		return NULL;
	p = strchr(p, '\n');
	return p ? p + 1 : trace_buf + trace_len;
}

static int count_after(const char *from, const char *needle)
{
	int n = 0;
	const char *p = from;

	while (from && (p = strstr(p, needle))) {
		n++;
		p += strlen(needle);
	}
	return n;
}

static int lnksta_lbms_after(const char *from)
{
	const char *p = from;

	while (p && (p = strstr(p, "\"ev\":\"lnksta\""))) {
		const char *e = strchr(p, '\n');
		const char *l = strstr(p, "\"lbms\":1");

		if (l && (!e || l < e))
			return 1;
		p = e ? e : p + 1;
	}
	return 0;
}

static int dmesg_read(char **out)
{
	int size = klogctl(10, NULL, 0);
	char *buf;
	int n;

	if (size <= 0)
		size = 1 << 20;
	buf = malloc(size + 1);
	if (!buf)
		return -1;
	n = klogctl(3, buf, size);
	if (n < 0) {
		free(buf);
		return -1;
	}
	buf[n] = '\0';
	*out = buf;
	return n;
}

static int dmesg_count(const char *needle)
{
	char *buf;
	int n = 0;
	const char *p;

	if (dmesg_read(&buf) < 0)
		return 0;
	for (p = buf; (p = strstr(p, needle)); p += strlen(needle))
		n++;
	free(buf);
	return n;
}

static int link_op(uint8_t op, uint8_t speed, uint8_t width)
{
	struct pciem_link link = { .func = 0, .op = op, .speed = speed, .width = width };

	return ioctl(ctl_fd, PCIEM_IOCTL_LINK, &link) < 0 ? errno : 0;
}

static void create_device(void)
{
	struct pciem_create_device create = {
		.flags = PCIEM_CREATE_FLAG_BUS_MODE_VIRTUAL | PCIEM_CREATE_FLAG_PLACEMENT(placement),
	};
	struct pciem_topology topo = {
		.flags = topo_flags,
		.eq_fail_above = eq_mode ? PCIEM_LINK_SPEED_5GT : 0,
	};
	struct pciem_bar_config bar0 = {
		.bar_index = 0, .flags = PCI_BASE_ADDRESS_MEM_TYPE_64 | PCI_BASE_ADDRESS_MEM_PREFETCH,
		.size = BAR0_SIZE,
	};
	struct pciem_bar_config bar2 = {
		.bar_index = 2, .flags = PCI_BASE_ADDRESS_MEM_TYPE_64 | PCI_BASE_ADDRESS_MEM_PREFETCH,
		.size = BAR2_SIZE,
	};
	struct pciem_cap_config pcie = {
		.cap_type = PCIEM_CAP_PCIE, .pcie.flags = PCIEM_CAP_PCIE_FLAG_FLR,
	};
	struct pciem_cap_config msi = {
		.cap_type = PCIEM_CAP_MSI, .msi = { .num_vectors_log2 = 0, .has_64bit = 1 },
	};
	struct pciem_cap_config pm = { .cap_type = PCIEM_CAP_PM };
	struct pciem_config_space cfg = {
		.vendor_id = EP_VENDOR, .device_id = EP_DEVICE, .class_code = { 0x10, 0x02, 0x05 },
	};

	ctl_fd = open("/dev/pciem", O_RDWR);
	if (ctl_fd < 0)
		err(1, "open /dev/pciem");
	ring = mmap(NULL, sizeof(*ring), PROT_READ | PROT_WRITE, MAP_SHARED, ctl_fd, 0);
	if (ring == MAP_FAILED)
		err(1, "mmap event ring");
	if (ioctl(ctl_fd, PCIEM_IOCTL_CREATE_DEVICE, &create) < 0)
		err(1, "PCIEM_IOCTL_CREATE_DEVICE");
	if (ioctl(ctl_fd, PCIEM_IOCTL_SET_TOPOLOGY, &topo) < 0)
		err(1, "PCIEM_IOCTL_SET_TOPOLOGY");
	if (ioctl(ctl_fd, PCIEM_IOCTL_ADD_BAR, &bar0) < 0 || ioctl(ctl_fd, PCIEM_IOCTL_ADD_BAR, &bar2) < 0)
		err(1, "PCIEM_IOCTL_ADD_BAR");
	if (ioctl(ctl_fd, PCIEM_IOCTL_ADD_CAPABILITY, &pcie) < 0 ||
	    ioctl(ctl_fd, PCIEM_IOCTL_ADD_CAPABILITY, &msi) < 0 ||
	    ioctl(ctl_fd, PCIEM_IOCTL_ADD_CAPABILITY, &pm) < 0)
		err(1, "PCIEM_IOCTL_ADD_CAPABILITY");
	if (ioctl(ctl_fd, PCIEM_IOCTL_SET_CONFIG, &cfg) < 0)
		err(1, "PCIEM_IOCTL_SET_CONFIG");
	instance_fd = ioctl(ctl_fd, PCIEM_IOCTL_REGISTER);
	if (instance_fd < 0)
		err(1, "PCIEM_IOCTL_REGISTER");
	if (ioctl(ctl_fd, PCIEM_IOCTL_START) < 0)
		err(1, "PCIEM_IOCTL_START");
}

static int find_ep(void)
{
	for (int attempt = 0; attempt < 100; attempt++) {
		DIR *dir = opendir("/sys/bus/pci/devices");
		struct dirent *de;

		if (!dir)
			err(1, "opendir /sys/bus/pci/devices");
		while ((de = readdir(dir))) {
			char path[300], link[PATH_MAX];

			if (strlen(de->d_name) != 12)
				continue;
			snprintf(path, sizeof(path), "/sys/bus/pci/devices/%s/vendor", de->d_name);
			if (read_hex(path) != EP_VENDOR)
				continue;
			snprintf(path, sizeof(path), "/sys/bus/pci/devices/%s/device", de->d_name);
			if (read_hex(path) != EP_DEVICE)
				continue;
			snprintf(path, sizeof(path), "/sys/bus/pci/devices/%s", de->d_name);
			if (!realpath(path, link))
				continue;
			snprintf(ep_bdf, sizeof(ep_bdf), "%s", de->d_name);
			closedir(dir);
			return 0;
		}
		closedir(dir);
		usleep(100000);
	}
	return -1;
}

static void split_chain(void)
{
	char path[300], real[PATH_MAX], *tok, *save;

	snprintf(path, sizeof(path), "/sys/bus/pci/devices/%s", ep_bdf);
	if (!realpath(path, real))
		err(1, "realpath");
	depth = 0;
	for (tok = strtok_r(real, "/", &save); tok; tok = strtok_r(NULL, "/", &save)) {
		unsigned int d, b, s, f;

		if (sscanf(tok, "%x:%x:%x.%x", &d, &b, &s, &f) == 4 && depth < MAX_CHAIN)
			snprintf(chain[depth++], sizeof(chain[0]), "%s", tok);
	}
	snprintf(port_bdf, sizeof(port_bdf), "%s", chain[depth - 2]);
	port_is_dsp = placement == PCIEM_PLACEMENT_SWITCH;
	snprintf(dbg, sizeof(dbg), "/sys/kernel/debug/pciem/%s", ep_bdf);
	snprintf(portdir, sizeof(portdir), "%s/%s", dbg, port_is_dsp ? "dsp" : "rp");
}

static int service_present(const char *bdf, const char *svc)
{
	char path[200];

	snprintf(path, sizeof(path), "/sys/bus/pci_express/devices/%s:%s", bdf, svc);
	return access(path, F_OK) == 0;
}

static int wait_service(const char *bdf, const char *svc, int ms)
{
	long end = now_ms() + ms;

	do {
		if (service_present(bdf, svc))
			return 1;
		usleep(20000);
	} while (now_ms() < end);
	return 0;
}

static void step_enumerate(void)
{
	int want_depth = placement == PCIEM_PLACEMENT_SWITCH ? 4 : 2;
	static const uint16_t ids[] = { 0xd130, 0xd131, 0xd132 };
	char buf[64];
	int i;

	report(depth == want_depth, "EP %s sits at path depth %d (expected %d)", ep_bdf, depth, want_depth);
	for (i = 0; i < depth - 1; i++) {
		uint16_t want = placement == PCIEM_PLACEMENT_SWITCH ? ids[i] : ids[0];
		long dev, ven, cls;
		char p[200];

		snprintf(p, sizeof(p), "/sys/bus/pci/devices/%s/device", chain[i]);
		dev = read_hex(p);
		snprintf(p, sizeof(p), "/sys/bus/pci/devices/%s/vendor", chain[i]);
		ven = read_hex(p);
		snprintf(p, sizeof(p), "/sys/bus/pci/devices/%s/class", chain[i]);
		cls = read_hex(p);
		report(ven == 0x1ab8 && dev == want && cls == 0x060400,
		       "%s is %04lx:%04lx class %06lx (expected %04x:%04x class 060400)", chain[i], ven, dev,
		       cls, 0x1ab8, want);
	}
	report(wait_service(chain[0], "pcie001", 3000), "RP %s has the PME service", chain[0]);
	report(wait_service(chain[0], "pcie010", 3000), "RP %s has the bandwidth controller service",
	       chain[0]);
	if (!(topo_flags & PCIEM_TOPO_FLAG_NATIVE_AER))
		report(!service_present(chain[0], "pcie002"), "RP %s has no AER service", chain[0]);
	if (placement == PCIEM_PLACEMENT_SWITCH) {
		report(!service_present(chain[1], "pcie001") && !service_present(chain[1], "pcie010"),
		       "USP %s binds with no services", chain[1]);
		report(wait_service(chain[2], "pcie210", 3000), "DSP %s has the bandwidth controller service",
		       chain[2]);
	}
	if (sys_read(ep_bdf, "resource", buf, sizeof(buf)) == 0)
		note("EP resource0 line: %s", buf);
}

static const char *speed_text(int rate)
{
	static const char *const t[] = { "?", "2.5 GT/s PCIe", "5.0 GT/s PCIe", "8.0 GT/s PCIe",
					 "16.0 GT/s PCIe", "32.0 GT/s PCIe" };

	return t[rate];
}

static void step_initial_link(void)
{
	int rate = eq_mode ? 2 : 5;
	char spd[64], w[64], want[16];
	int ok;

	snprintf(want, sizeof(want), "%d", rate);
	ok = wait_state(3000, 6, "ltssm", "L0", "dl", "up", "speed", want) == 0 &&
	     state_is("width", "8");
	report(ok, "%s link is up at speed=%d width=8", port_is_dsp ? "DSP" : "RP", rate);
	sleep_ms(100);
	sys_read(ep_bdf, "current_link_speed", spd, sizeof(spd));
	sys_read(ep_bdf, "current_link_width", w, sizeof(w));
	report(!strcmp(spd, speed_text(rate)) && !strcmp(w, "8"), "EP reads %s x%s", spd, w);
	sys_read(port_bdf, "current_link_speed", spd, sizeof(spd));
	report(!strcmp(spd, speed_text(rate)), "port reads %s", spd);
}

static uint32_t saved_bar0, saved_bar1, saved_bar2, saved_bar3, saved_cmd;

static void save_ep_cfg(void)
{
	cfg_read(ep_bdf, PCI_BASE_ADDRESS_0, 4, &saved_bar0);
	cfg_read(ep_bdf, PCI_BASE_ADDRESS_1, 4, &saved_bar1);
	cfg_read(ep_bdf, PCI_BASE_ADDRESS_2, 4, &saved_bar2);
	cfg_read(ep_bdf, PCI_BASE_ADDRESS_3, 4, &saved_bar3);
	cfg_read(ep_bdf, PCI_COMMAND, 2, &saved_cmd);
}

static void restore_ep_cfg(void)
{
	cfg_write32(ep_bdf, PCI_BASE_ADDRESS_0, saved_bar0);
	cfg_write32(ep_bdf, PCI_BASE_ADDRESS_1, saved_bar1);
	cfg_write32(ep_bdf, PCI_BASE_ADDRESS_2, saved_bar2);
	cfg_write32(ep_bdf, PCI_BASE_ADDRESS_3, saved_bar3);
	cfg_write16(ep_bdf, PCI_COMMAND, saved_cmd);
}

static void step_down_up(void)
{
	uint32_t v = 0, sta = 0, bar0 = 0, bar1 = 0;
	int cap = pcie_cap(port_bdf), rc;
	long t0;

	report(cap > 0, "port PCIe capability at 0x%02x", cap);
	rc = link_op(PCIEM_LINK_DOWN, 0, 0);
	report(rc == 0, "PCIEM_LINK_DOWN: %s", strerror(rc));
	t0 = now_ms();
	report(wait_state(100, 2, "dl", "down") == 0, "dl=down within %ld ms", now_ms() - t0);
	cfg_read(ep_bdf, PCI_VENDOR_ID, 4, &v);
	report(v == 0xffffffff, "EP config reads 0x%08x with the link down", v);
	cfg_read(port_bdf, cap + PCI_EXP_LNKSTA, 2, &sta);
	report(!(sta & PCI_EXP_LNKSTA_DLLLA) && !(sta & PCI_EXP_LNKSTA_NLW),
	       "port LnkSta 0x%04x has DLLLA=0 NLW=0", sta);
	report(link_op(PCIEM_LINK_DOWN, 0, 0) == EALREADY, "second PCIEM_LINK_DOWN gives EALREADY");

	rc = link_op(PCIEM_LINK_UP, PCIEM_LINK_SPEED_32GT, 8);
	report(rc == 0, "PCIEM_LINK_UP 5 8: %s", strerror(rc));
	report(link_op(PCIEM_LINK_UP, PCIEM_LINK_SPEED_32GT, 8) == EALREADY,
	       "second PCIEM_LINK_UP gives EALREADY");
	t0 = now_ms();
	report(wait_state(1000, 2, "dl", "up") == 0, "dl=up within %ld ms", now_ms() - t0);
	report(wait_state(2000, 4, "ltssm", "L0", "speed", eq_mode ? "2" : "5") == 0,
	       "link steps up to speed %d", eq_mode ? 2 : 5);
	sleep_ms(50);
	cfg_read(ep_bdf, PCI_BASE_ADDRESS_0, 4, &bar0);
	cfg_read(ep_bdf, PCI_BASE_ADDRESS_1, 4, &bar1);
	report(bar1 == 0 && (bar0 & ~0xfu) == 0, "EP BARs read 0x%08x%08x after the link came back", bar1, bar0);
	restore_ep_cfg();
}

static void step_rrs(void)
{
	uint32_t v = 0;
	long t0, t_id = 0;
	int rrs = 0, other = 0;

	write_str(port_file("rrs_ms"), "200");
	link_op(PCIEM_LINK_DOWN, 0, 0);
	wait_state(200, 2, "dl", "down");
	link_op(PCIEM_LINK_UP, PCIEM_LINK_SPEED_32GT, 8);
	t0 = now_ms();
	while (now_ms() < t0 + 2000) {
		cfg_read(ep_bdf, PCI_VENDOR_ID, 4, &v);
		if (v == 0xffff0001) {
			rrs++;
		} else if (v == (uint32_t)(EP_VENDOR | (EP_DEVICE << 16))) {
			t_id = now_ms();
			break;
		} else if (v != 0xffffffff) {
			other++;
		}
		usleep(5000);
	}
	report(rrs > 0 && !other && t_id - t0 >= 150 && t_id - t0 < 600,
	       "RRS window: %d reads returned 0xffff0001, the vendor ID came %ld ms after the link up",
	       rrs, t_id - t0);
	write_str(port_file("rrs_ms"), "0");
	wait_state(5000, 4, "ltssm", "L0", "dl", "up");
	restore_ep_cfg();
}

static void set_tls_and_retrain(int tls)
{
	int cap = pcie_cap(port_bdf);
	uint32_t v = 0;

	cfg_read(port_bdf, cap + PCI_EXP_LNKCTL2, 2, &v);
	cfg_write16(port_bdf, cap + PCI_EXP_LNKCTL2, (v & ~0xf) | tls);
	cfg_read(port_bdf, cap + PCI_EXP_LNKCTL, 2, &v);
	cfg_write16(port_bdf, cap + PCI_EXP_LNKCTL, v | PCI_EXP_LNKCTL_RL);
}

static void step_retrain(void)
{
	const char *from;
	int cap = pcie_cap(port_bdf), want, i;
	char w[8];
	uint32_t v;

	trace_mark("rl1");
	cfg_read(port_bdf, cap + PCI_EXP_LNKCTL, 2, &v);
	cfg_write16(port_bdf, cap + PCI_EXP_LNKCTL, v | PCI_EXP_LNKCTL_RL);
	report(wait_state(3000, 4, "lt", "0", "ltssm", "L0") == 0, "retrain returns to L0 with LT=0");
	sleep_ms(50);
	from = after_mark("rl1");
	report(count_after(from, "\"to\":\"Recovery.RcvrLock\"") > 0, "trace has Recovery records after the retrain");
	report(lnksta_lbms_after(from), "trace has an lnksta record with lbms 1");

	for (i = 0; i < 2; i++) {
		int tls = i == 0 ? 3 : 5;

		want = eq_mode && tls > 2 ? 2 : tls;
		snprintf(w, sizeof(w), "%d", want);
		set_tls_and_retrain(tls);
		report(wait_state(5000, 4, "ltssm", "L0", "speed", w) == 0 && state_is("lt", "0"),
		       "TLS=%d then Retrain Link ends at speed %d", tls, want);
		sleep_ms(50);
	}
}

static void step_sbr(void)
{
	int *kinds = ev_resets;
	char path[200];
	uint32_t v = 0, bar0 = 0, bar2 = 0, cmd = 0;
	char buf[200], res_before[600], res_after[600];
	int rc;

	sys_read(ep_bdf, "resource", res_before, sizeof(res_before));
	drain_events(NULL);
	memset(ev_resets, 0, sizeof(ev_resets));
	snprintf(path, sizeof(path), "/sys/bus/pci/devices/%s/reset_subordinate", port_bdf);
	rc = write_str(path, "1");
	report(rc == 0, "reset_subordinate on %s: %s", port_bdf, strerror(rc ? errno : 0));
	report(wait_state(5000, 6, "ltssm", "L0", "dl", "up", "lt", "0") == 0, "link back in L0 after the reset");
	sleep_ms(300);
	report(kinds[PCIEM_RESET_HOT] == 1, "exactly one PCIEM_RESET_HOT event arrived (%d, flr %d, pm %d)",
	       kinds[PCIEM_RESET_HOT], kinds[PCIEM_RESET_FLR], kinds[PCIEM_RESET_PM]);
	cfg_read(ep_bdf, PCI_VENDOR_ID, 4, &v);
	cfg_read(ep_bdf, PCI_BASE_ADDRESS_0, 4, &bar0);
	cfg_read(ep_bdf, PCI_BASE_ADDRESS_2, 4, &bar2);
	cfg_read(ep_bdf, PCI_COMMAND, 2, &cmd);
	snprintf(buf, sizeof(buf), "vendor/device 0x%08x BAR0 0x%08x BAR2 0x%08x", v, bar0, bar2);
	report(v == (uint32_t)(EP_VENDOR | (EP_DEVICE << 16)) && bar0 == saved_bar0 && bar2 == saved_bar2,
	       "EP config restored by Linux: %s", buf);
	sys_read(ep_bdf, "resource", res_after, sizeof(res_after));
	report(!strcmp(res_before, res_after), "EP BAR addresses unchanged");
}

static void step_eq_fallback(void)
{
	const char *from;
	int rc;

	write_str(port_file("eq_limit"), "2");
	trace_mark("eq1");
	rc = link_op(PCIEM_LINK_DOWN, 0, 0);
	report(rc == 0, "down for the equalization test: %s", strerror(rc));
	report(wait_state(200, 2, "dl", "down") == 0, "dl=down");
	rc = link_op(PCIEM_LINK_UP, PCIEM_LINK_SPEED_32GT, 8);
	report(rc == 0, "PCIEM_LINK_UP 5 8: %s", strerror(rc));
	report(wait_state(5000, 4, "ltssm", "L0", "speed", "2") == 0 && state_is("lt", "0"),
	       "equalization limit 2: link ends at speed 2");
	sleep_ms(100);
	from = after_mark("eq1");
	report(count_after(from, "\"why\":\"eq_fail\"") > 0, "trace has an eq_fail transition");
	report(lnksta_lbms_after(from), "trace has an lnksta record with lbms 1");
	restore_ep_cfg();
}

static _Atomic pid_t reset_tid;

static void *reset_thread(void *arg)
{
	char path[200];

	reset_tid = gettid();
	snprintf(path, sizeof(path), "/sys/bus/pci/devices/%s/reset_subordinate", port_bdf);
	*(int *)arg = write_str(path, "1");
	return NULL;
}

static void print_dmesg_lines(const char *needle)
{
	char *buf, *p;

	if (dmesg_read(&buf) < 0)
		return;
	for (p = strtok(buf, "\n"); p; p = strtok(NULL, "\n"))
		if (strstr(p, needle))
			printf("info:   %s\n", p);
	free(buf);
}

static void step_quirk(void)
{
	static const char *const keys[] = {
		"broken device, retraining non-functional downstream link at 2.5GT/s",
		"removing 2.5GT/s downstream link speed restriction",
		"retraining failed",
	};
	int before[3], i, rc = 0;
	pthread_t th;

	write_str(port_file("eq_limit"), "2");
	trace_mark("q1");
	for (i = 0; i < 3; i++)
		before[i] = dmesg_count(keys[i]);
	rc = link_op(PCIEM_LINK_DOWN, 0, 0);
	report(rc == 0 || rc == EALREADY, "down for the quirk test: %s", strerror(rc));
	pthread_create(&th, NULL, reset_thread, &rc);
	sleep_ms(600);
	if (getenv("TOPO_STACK") && *getenv("TOPO_STACK")) {
		char sp[64], sb[4096];

		(void)sp;
		(void)sb;
		write_str("/proc/sysrq-trigger", "t");
	}
	sleep_ms(500);
	link_op(PCIEM_LINK_UP, PCIEM_LINK_SPEED_32GT, 8);
	pthread_join(th, NULL);
	sleep_ms(500);
	for (i = 0; i < 3; i++)
		note("quirk line %d (%s): %d new", i, keys[i], dmesg_count(keys[i]) - before[i]);
	report(dmesg_count(keys[0]) - before[0] > 0,
	       "dmesg shows the pcie_failed_link_retrain quirk firing");
	print_dmesg_lines("downstream link");
	print_dmesg_lines("after bus reset");
	print_dmesg_lines("not ready");
	wait_state(5000, 4, "ltssm", "L0", "dl", "up");
	restore_ep_cfg();
}

static void dump_trace(const char *ev)
{
	char *copy, *line, *save, needle[64];

	snprintf(needle, sizeof(needle), "\"ev\":\"%s\"", ev);

	trace_load();
	copy = strdup(trace_buf);
	for (line = strtok_r(copy, "\n", &save); line; line = strtok_r(NULL, "\n", &save))
		if (strstr(line, needle))
			printf("info:   %s\n", line);
	free(copy);
}

static int check_trace(void)
{
	if (getenv("TOPO_DUMP") && *getenv("TOPO_DUMP"))
		dump_trace(getenv("TOPO_DUMP"));
	if (getenv("TOPO_AFTER") && *getenv("TOPO_AFTER")) {
		char *copy, *line, *save;
		const char *from = after_mark("q1");

		copy = strdup(from ? from : "");
		for (line = strtok_r(copy, "\n", &save); line; line = strtok_r(NULL, "\n", &save))
			if (strstr(line, getenv("TOPO_AFTER")) && !strstr(line, "\"fn\":\"ep0\"") && !strstr(line, "\"fn\":\"none\""))
				printf("info:   %s\n", line);
		free(copy);
	}
	char *line, *save;
	long prev = -1;
	int n = 0, bad = 0, scan_begin = 0, scan_done = 0, cfgs = 0;
	char *copy;

	trace_load();
	copy = strdup(trace_buf);
	for (line = strtok_r(copy, "\n", &save); line; line = strtok_r(NULL, "\n", &save)) {
		long seq;
		char *s = strstr(line, "\"seq\":");
		size_t len = strlen(line);

		n++;
		if (strncmp(line, "{\"t\":", 5) || line[len - 1] != '}' || !s || sscanf(s + 6, "%ld", &seq) != 1) {
			bad++;
			continue;
		}
		if (seq <= prev)
			bad++;
		prev = seq;
		if (strstr(line, "\"name\":\"scan_begin\""))
			scan_begin++;
		if (strstr(line, "\"name\":\"scan_done\""))
			scan_done++;
		if (strstr(line, "\"ev\":\"cfg\""))
			cfgs++;
	}
	free(copy);
	report(bad == 0 && n > 0, "trace: %d lines parse and seq increases", n);
	report(scan_begin && scan_done, "trace has scan_begin and scan_done");
	report(cfgs > 0, "trace has %d cfg records", cfgs);
	return 0;
}

static int bdf_gone(void)
{
	int i;

	for (i = 0; i < depth; i++) {
		char path[200];

		snprintf(path, sizeof(path), "/sys/bus/pci/devices/%s", chain[i]);
		if (access(path, F_OK) == 0)
			return 0;
	}
	return 1;
}

static int ep_present(void)
{
	char path[200];

	snprintf(path, sizeof(path), "/sys/bus/pci/devices/%s/vendor", ep_bdf);
	return access(path, F_OK) == 0;
}

static int wait_ep(int present, int ms)
{
	long end = now_ms() + ms;

	do {
		if (ep_present() == present)
			return 1;
		usleep(20000);
	} while (now_ms() < end);
	return 0;
}

static void options_run(int hotplug)
{
	char before[600], after[600];
	uint32_t v = 0;
	int cap, rc;

	step_enumerate();
	cap = pcie_cap(port_bdf);
	if (hotplug) {
		report(wait_service(port_bdf, port_is_dsp ? "pcie204" : "pcie004", 3000),
		       "hot-plug service bound on %s", port_bdf);
		sys_read(ep_bdf, "resource", before, sizeof(before));
		rc = link_op(PCIEM_LINK_DOWN, 0, 0);
		report(rc == 0, "PCIEM_LINK_DOWN: %s", strerror(rc));
		report(wait_ep(0, 5000), "pciehp removed the EP after the link went down");
		rc = link_op(PCIEM_LINK_UP, PCIEM_LINK_SPEED_32GT, 8);
		report(rc == 0, "PCIEM_LINK_UP: %s", strerror(rc));
		report(wait_ep(1, 10000), "pciehp enumerated the EP again");
		sleep_ms(500);
		sys_read(ep_bdf, "resource", after, sizeof(after));
		if (strcmp(before, after))
			note("EP BARs came back unassigned: Linux cannot allocate inside the e820 reserved pool (needs pci=no_e820)");
		else
			report(1, "EP BARs came back at the same addresses");
		if (getenv("TOPO_IOMEM"))
			(void)!system("grep -n -B2 -A6 '0000:01' /proc/iomem; lspci -vv -s 01:00.0 | grep -i 'prefetch\\|behind'");
		cfg_read(ep_bdf, PCI_VENDOR_ID, 4, &v);
		report(v == (uint32_t)(EP_VENDOR | (EP_DEVICE << 16)), "EP vendor/device read 0x%08x", v);
		report(dmesg_count("Link Down") > 0 && dmesg_count("Card present") > 0,
		       "dmesg has Slot Link Down and Card present");
		dump_trace("sltsta");
		dump_trace("irq");
	} else {
		uint32_t ue = 0, rs = 0, cmd;

		report(wait_service(chain[0], "pcie002", 3000), "RP %s has the AER service", chain[0]);
		report(wait_service(chain[0], "pcie008", 3000), "RP %s has the DPC service", chain[0]);
		cfg_read(port_bdf, 0x140, 4, &v);
		report((v & 0xffff) == PCI_EXT_CAP_ID_DPC, "DPC capability at 0x140 on the port above the EP");
		rc = link_op(PCIEM_LINK_DOWN, 0, 0);
		report(rc == 0, "PCIEM_LINK_DOWN: %s", strerror(rc));
		sleep_ms(300);
		cfg_read(port_bdf, 0x104, 4, &ue);
		cfg_read(chain[0], 0x130, 4, &rs);
		cfg_read(chain[0], cap + PCI_EXP_RTCTL, 2, &cmd);
		report(ue & 0x20 || dmesg_count("AER:") > 0, "Surprise Down logged (UESta 0x%08x, Root Error Status 0x%08x)", ue, rs);
		dump_trace("aer");
		rc = link_op(PCIEM_LINK_UP, PCIEM_LINK_SPEED_32GT, 8);
		report(rc == 0, "PCIEM_LINK_UP: %s", strerror(rc));
		report(wait_state(5000, 4, "ltssm", "L0", "dl", "up") == 0, "link back");
	}
}

static void teardown_cycles(void)
{
	static const char *const what[] = {
		"idle", "link down", "link down then up, still training", "eq limit and retrain",
		"reset in flight", "link disable",
	};
	int i;

	for (i = 0; i < 6; i++) {
		pthread_t th = 0;
		int rc = 0, hold_reset = 0;
		char path[200];

		create_device();
		if (find_ep())
			errx(1, "device did not appear");
		split_chain();
		switch (i) {
		case 1:
			link_op(PCIEM_LINK_DOWN, 0, 0);
			break;
		case 2:
			link_op(PCIEM_LINK_DOWN, 0, 0);
			link_op(PCIEM_LINK_UP, PCIEM_LINK_SPEED_32GT, 8);
			break;
		case 3:
			write_str(port_file("eq_limit"), "2");
			link_op(PCIEM_LINK_DOWN, 0, 0);
			link_op(PCIEM_LINK_UP, PCIEM_LINK_SPEED_32GT, 8);
			usleep(20000);
			set_tls_and_retrain(5);
			break;
		case 4:
			link_op(PCIEM_LINK_DOWN, 0, 0);
			pthread_create(&th, NULL, reset_thread, &rc);
			hold_reset = 1;
			usleep(300000);
			break;
		case 5:
			snprintf(path, sizeof(path), "/sys/bus/pci/devices/%s/config", port_bdf);
			set_tls_and_retrain(5);
			cfg_write16(port_bdf, pcie_cap(port_bdf) + PCI_EXP_LNKCTL, PCI_EXP_LNKCTL_LD);
			break;
		}
		munmap(ring, sizeof(*ring));
		close(instance_fd);
		close(ctl_fd);
		if (hold_reset)
			pthread_join(th, NULL);
		report(1, "teardown cycle %d (%s) returned", i, what[i]);
	}
}

int main(int argc, char **argv)
{
	int warn_before, bug_before;
	long end;

	if (argc < 2 || (strcmp(argv[1], "root-port") && strcmp(argv[1], "switch"))) {
		fprintf(stderr, "usage: %s root-port|switch [eq]\n", argv[0]);
		return 2;
	}
	placement = !strcmp(argv[1], "switch") ? PCIEM_PLACEMENT_SWITCH : PCIEM_PLACEMENT_ROOT_PORT;
	eq_mode = argc > 2 && !strcmp(argv[2], "eq");
	warn_before = dmesg_count("WARNING:");
	bug_before = dmesg_count("BUG:");
	if (argc > 2 && (!strcmp(argv[2], "hotplug") || !strcmp(argv[2], "aer"))) {
		int hp = !strcmp(argv[2], "hotplug");

		topo_flags = hp ? PCIEM_TOPO_FLAG_HOTPLUG :
				  PCIEM_TOPO_FLAG_NATIVE_AER | PCIEM_TOPO_FLAG_UNMASK_SDES | PCIEM_TOPO_FLAG_DPC;
		create_device();
		if (find_ep())
			errx(1, "device did not appear");
		split_chain();
		options_run(hp);
		munmap(ring, sizeof(*ring));
		close(instance_fd);
		close(ctl_fd);
		end = now_ms() + 5000;
		while (!bdf_gone() && now_ms() < end)
			usleep(50000);
		report(bdf_gone(), "no BDF of the chain remains after teardown");
		report(dmesg_count("WARNING:") == warn_before && dmesg_count("BUG:") == bug_before,
		       "dmesg has no new WARNING: or BUG: lines");
		printf("RESULT: %s\n", failures ? "FAIL" : "PASS");
		return failures ? 1 : 0;
	}
	if (argc > 2 && !strcmp(argv[2], "teardown")) {
		teardown_cycles();
		sleep_ms(300);
		report(dmesg_count("WARNING:") == warn_before && dmesg_count("BUG:") == bug_before,
		       "dmesg has no new WARNING: or BUG: lines");
		return failures ? 1 : 0;
	}

	create_device();
	if (find_ep())
		errx(1, "device %04x:%04x did not appear", EP_VENDOR, EP_DEVICE);
	split_chain();
	printf("EP at %s, chain:", ep_bdf);
	for (int i = 0; i < depth; i++)
		printf(" %s", chain[i]);
	putchar('\n');
	fflush(stdout);
	(void)!system("lspci -tv 2>/dev/null");

	step_enumerate();
	if (getenv("TOPO_HOLD") && *getenv("TOPO_HOLD"))
		sleep(atoi(getenv("TOPO_HOLD")));
	step_initial_link();
	save_ep_cfg();
	step_down_up();
	step_rrs();
	step_retrain();
	step_sbr();
	step_eq_fallback();
	step_quirk();
	check_trace();

	munmap(ring, sizeof(*ring));
	close(instance_fd);
	close(ctl_fd);
	end = now_ms() + 5000;
	while (!bdf_gone() && now_ms() < end)
		usleep(50000);
	report(bdf_gone(), "no BDF of the chain remains after teardown");
	report(dmesg_count("WARNING:") == warn_before && dmesg_count("BUG:") == bug_before,
	       "dmesg has no new WARNING: or BUG: lines");

	if (failures) {
		printf("RESULT: FAIL (%d)\n", failures);
		return 1;
	}
	printf("RESULT: PASS\n");
	return 0;
}
