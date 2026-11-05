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
#define SW_BUS 0xb0
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

static int dma_read_iova0(int fd)
{
	uint64_t buf = 0;
	struct pciem_dma_op op = {
		.user_addr = (uintptr_t)&buf, .length = sizeof(buf), .flags = PCIEM_DMA_FLAG_READ,
	};

	return ioctl(fd, PCIEM_IOCTL_DMA, &op) < 0 ? errno : 0;
}

static int inject_irq(int fd, uint8_t flags)
{
	struct pciem_irq_inject inject = { .flags = flags };

	return ioctl(fd, PCIEM_IOCTL_INJECT_IRQ, &inject) < 0 ? errno : 0;
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

	if (placement == PCIEM_PLACEMENT_SWITCH) {
		create.flags |= PCIEM_CREATE_FLAG_FIXED_ADDRESS;
		create.bus = SW_BUS;
		topo.switch_ports = 1;
	}
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
	rc = dma_read_iova0(ctl_fd);
	report(rc == ENOLINK, "DMA with the link down: %s (expected ENOLINK)", strerror(rc));
	rc = inject_irq(ctl_fd, 0);
	report(rc == ENOLINK, "INJECT_IRQ with the link down: %s (expected ENOLINK)", strerror(rc));
	rc = inject_irq(ctl_fd, PCIEM_IRQ_INJECT_FLAG_LEVEL);
	report(rc == ENOLINK, "INJECT_IRQ LEVEL with the link down: %s (expected ENOLINK)", strerror(rc));
	rc = inject_irq(ctl_fd, PCIEM_IRQ_INJECT_FLAG_DEASSERT);
	report(rc == 0, "INJECT_IRQ DEASSERT with the link down: %s", strerror(rc));

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
	rc = dma_read_iova0(ctl_fd);
	report(rc != ENOLINK, "DMA after the link came back reaches translation: %s", strerror(rc));
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

static void step_recovery_resume(void)
{
	char timing[1024];
	const char *from;
	uint32_t v = 0, bar0 = 0;
	int cap = pcie_cap(port_bdf), rc;

	if (read_text(port_file("timing"), timing, sizeof(timing)))
		err(1, "read timing");
	write_str(port_file("timing"), "recovery_speed=300000 recovery_timeout=1000000");
	trace_mark("rr1");
	cfg_read(port_bdf, cap + PCI_EXP_LNKCTL, 2, &v);
	cfg_write16(port_bdf, cap + PCI_EXP_LNKCTL, v | PCI_EXP_LNKCTL_RL);
	report(wait_state(500, 2, "ltssm", "Recovery.Speed") == 0, "Retrain Link reaches Recovery.Speed");
	rc = link_op(PCIEM_LINK_DOWN, 0, 0);
	if (!rc)
		rc = link_op(PCIEM_LINK_UP, PCIEM_LINK_SPEED_32GT, 8);
	report(rc == 0, "PCIEM_LINK_DOWN then PCIEM_LINK_UP in Recovery.Speed: %s", strerror(rc));
	report(wait_state(5000, 6, "ltssm", "L0", "dl", "up", "lt", "0") == 0, "the link finishes Recovery in L0");
	write_str(port_file("timing"), timing);
	sleep_ms(50);
	from = after_mark("rr1");
	report(from && !count_after(from, "\"ev\":\"dl\""), "no DL_Down or DL_Up since the retrain");
	cfg_read(ep_bdf, PCI_BASE_ADDRESS_0, 4, &bar0);
	report(bar0 == saved_bar0, "EP BAR0 kept its address through the Recovery (0x%08x)", bar0);
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

#define MAXDEV 9

struct mdev {
	int ctl, inst;
	struct pciem_shared_ring *ring;
	int port, hot;
	uint32_t bar0, bar1, bar2, bar3, cmd;
	char ep[16], dsp[16], dbg[160];
};

static struct mdev md[MAXDEV + 1];
static struct mdev *cur;
static int nports = 3;
static char sw_rp[16], sw_usp[16], sw_dbg[160];

static void mflush(void)
{
	if (!cur)
		return;
	drain_events(NULL);
	cur->hot += ev_resets[PCIEM_RESET_HOT];
	memset(ev_resets, 0, sizeof(ev_resets));
}

static void msel(struct mdev *m)
{
	mflush();
	cur = m;
	ctl_fd = m->ctl;
	ring = m->ring;
	snprintf(ep_bdf, sizeof(ep_bdf), "%s", m->ep);
	snprintf(port_bdf, sizeof(port_bdf), "%s", m->dsp);
	snprintf(dbg, sizeof(dbg), "%s", m->dbg);
	snprintf(portdir, sizeof(portdir), "%s/dsp", m->dbg);
	port_is_dsp = 1;
}

static int mdev_create(int port, int total, uint32_t tflags, uint32_t bar2_size, int fixed)
{
	struct mdev *m = &md[port];
	struct pciem_create_device create = {
		.flags = PCIEM_CREATE_FLAG_BUS_MODE_VIRTUAL |
			 PCIEM_CREATE_FLAG_PLACEMENT(PCIEM_PLACEMENT_SWITCH) |
			 (fixed ? PCIEM_CREATE_FLAG_FIXED_ADDRESS : 0),
		.bus = SW_BUS,
	};
	struct pciem_topology topo = { .flags = tflags, .port = port, .switch_ports = total };
	struct pciem_bar_config bar0 = {
		.bar_index = 0, .flags = PCI_BASE_ADDRESS_MEM_TYPE_64 | PCI_BASE_ADDRESS_MEM_PREFETCH,
		.size = BAR0_SIZE,
	};
	struct pciem_bar_config bar2 = {
		.bar_index = 2, .flags = PCI_BASE_ADDRESS_MEM_TYPE_64 | PCI_BASE_ADDRESS_MEM_PREFETCH,
		.size = bar2_size,
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
	int rc = 0;

	memset(m, 0, sizeof(*m));
	m->port = port;
	m->ctl = open("/dev/pciem", O_RDWR);
	if (m->ctl < 0)
		err(1, "open /dev/pciem");
	m->ring = mmap(NULL, sizeof(*m->ring), PROT_READ | PROT_WRITE, MAP_SHARED, m->ctl, 0);
	if (m->ring == MAP_FAILED)
		err(1, "mmap event ring");
	m->inst = -1;
	if (ioctl(m->ctl, PCIEM_IOCTL_CREATE_DEVICE, &create) < 0)
		rc = errno;
	else if (total > 0 && ioctl(m->ctl, PCIEM_IOCTL_SET_TOPOLOGY, &topo) < 0)
		rc = errno;
	else if (ioctl(m->ctl, PCIEM_IOCTL_ADD_BAR, &bar0) < 0 || ioctl(m->ctl, PCIEM_IOCTL_ADD_BAR, &bar2) < 0)
		rc = errno;
	else if (ioctl(m->ctl, PCIEM_IOCTL_ADD_CAPABILITY, &pcie) < 0 ||
		 ioctl(m->ctl, PCIEM_IOCTL_ADD_CAPABILITY, &msi) < 0 ||
		 ioctl(m->ctl, PCIEM_IOCTL_ADD_CAPABILITY, &pm) < 0)
		rc = errno;
	else if (ioctl(m->ctl, PCIEM_IOCTL_SET_CONFIG, &cfg) < 0)
		rc = errno;
	else if ((m->inst = ioctl(m->ctl, PCIEM_IOCTL_REGISTER)) < 0)
		rc = errno;
	else if (ioctl(m->ctl, PCIEM_IOCTL_START) < 0)
		rc = errno;
	snprintf(m->ep, sizeof(m->ep), "0000:%02x:00.0", SW_BUS + 3 + port);
	snprintf(m->dsp, sizeof(m->dsp), "0000:%02x:%02x.0", SW_BUS + 2, port);
	snprintf(m->dbg, sizeof(m->dbg), "/sys/kernel/debug/pciem/0000:%02x:00.0", SW_BUS + 3 + port);
	return rc;
}

static void mdev_close(struct mdev *m)
{
	if (cur == m) {
		mflush();
		cur = NULL;
	}
	if (m->ctl < 0)
		return;
	munmap(m->ring, sizeof(*m->ring));
	if (m->inst >= 0)
		close(m->inst);
	close(m->ctl);
	m->ctl = -1;
}

static int path_exists(const char *fmt, const char *a)
{
	char path[300];

	snprintf(path, sizeof(path), fmt, a);
	return access(path, F_OK) == 0;
}

static int wait_path(const char *fmt, const char *a, int present, int ms)
{
	long end = now_ms() + ms;

	do {
		if (path_exists(fmt, a) == present)
			return 1;
		usleep(20000);
	} while (now_ms() < end);
	return 0;
}

static void msave(struct mdev *m)
{
	cfg_read(m->ep, PCI_BASE_ADDRESS_0, 4, &m->bar0);
	cfg_read(m->ep, PCI_BASE_ADDRESS_1, 4, &m->bar1);
	cfg_read(m->ep, PCI_BASE_ADDRESS_2, 4, &m->bar2);
	cfg_read(m->ep, PCI_BASE_ADDRESS_3, 4, &m->bar3);
	cfg_read(m->ep, PCI_COMMAND, 2, &m->cmd);
}

static void mrestore(struct mdev *m)
{
	cfg_write32(m->ep, PCI_BASE_ADDRESS_0, m->bar0);
	cfg_write32(m->ep, PCI_BASE_ADDRESS_1, m->bar1);
	cfg_write32(m->ep, PCI_BASE_ADDRESS_2, m->bar2);
	cfg_write32(m->ep, PCI_BASE_ADDRESS_3, m->bar3);
	cfg_write16(m->ep, PCI_COMMAND, m->cmd);
}

static int vendor_ok(const char *bdf)
{
	uint32_t v = 0;

	return !cfg_read(bdf, PCI_VENDOR_ID, 4, &v) && v == (uint32_t)(EP_VENDOR | (EP_DEVICE << 16));
}

static int mlink_up(struct mdev *m)
{
	msel(m);
	return state_is("ltssm", "L0") && state_is("dl", "up") && state_is("lt", "0");
}

static int count_ids(uint16_t dev)
{
	DIR *d = opendir("/sys/bus/pci/devices");
	struct dirent *de;
	int n = 0;

	if (!d)
		err(1, "opendir");
	while ((de = readdir(d))) {
		char p[300];

		if (strlen(de->d_name) != 12)
			continue;
		snprintf(p, sizeof(p), "/sys/bus/pci/devices/%s/vendor", de->d_name);
		if (read_hex(p) != 0x1ab8)
			continue;
		snprintf(p, sizeof(p), "/sys/bus/pci/devices/%s/device", de->d_name);
		if (read_hex(p) == dev)
			n++;
	}
	closedir(d);
	return n;
}

static int group_of(const char *bdf)
{
	char path[300], link[300], *b;
	ssize_t n;

	snprintf(path, sizeof(path), "/sys/bus/pci/devices/%s/iommu_group", bdf);
	n = readlink(path, link, sizeof(link) - 1);
	if (n < 0)
		return -1;
	link[n] = '\0';
	b = strrchr(link, '/');
	return atoi(b ? b + 1 : link);
}

static int group_size(int g)
{
	char path[100];
	DIR *d;
	struct dirent *de;
	int n = 0;

	snprintf(path, sizeof(path), "/sys/kernel/iommu_groups/%d/devices", g);
	d = opendir(path);
	if (!d)
		return -1;
	while ((de = readdir(d)))
		if (de->d_name[0] != '.')
			n++;
	closedir(d);
	return n;
}

static int ext_cap(const char *bdf, int id)
{
	uint32_t hdr;
	int off = 0x100, guard = 0;

	while (off >= 0x100 && guard++ < 32) {
		if (cfg_read(bdf, off, 4, &hdr) || !hdr || hdr == 0xffffffff)
			return -1;
		if ((hdr & 0xffff) == (uint32_t)id)
			return off;
		off = hdr >> 20;
	}
	return -1;
}

static void multi_enumerate(int n)
{
	char b[600], js[4096];
	int g[MAXDEV], k, j, distinct = 1, alone = 1, acs_ok = 1;

	report(count_ids(0xd130) == 1 && count_ids(0xd131) == 1 && count_ids(0xd132) == n,
	       "one Root Port, one Upstream Port and %d Downstream Ports (%d, %d, %d)", n,
	       count_ids(0xd130), count_ids(0xd131), count_ids(0xd132));
	for (k = 0; k < n; k++) {
		char path[300], real[PATH_MAX];

		snprintf(path, sizeof(path), "/sys/bus/pci/devices/%s", md[k].ep);
		report(realpath(path, real) && strstr(real, sw_rp) && strstr(real, sw_usp) && strstr(real, md[k].dsp),
		       "EP %s sits below RP %s, USP %s, DSP %s", md[k].ep, sw_rp, sw_usp, md[k].dsp);
		report(mlink_up(&md[k]), "port %d link is in L0", k);
		g[k] = group_of(md[k].ep);
	}
	for (k = 0; k < n; k++) {
		if (g[k] < 0 || group_size(g[k]) != 1)
			alone = 0;
		for (j = k + 1; j < n; j++)
			if (g[k] == g[j])
				distinct = 0;
	}
	b[0] = '\0';
	for (k = 0; k < n; k++)
		snprintf(b + strlen(b), sizeof(b) - strlen(b), " %d", g[k]);
	if (g[0] < 0)
		note("no IOMMU claims these devices, so they have no IOMMU group");
	else
		report(distinct && alone, "each EP is alone in its IOMMU group (groups:%s)", b);
	note("port groups: RP %d, USP %d, DSP0 %d", group_of(sw_rp), group_of(sw_usp), group_of(md[0].dsp));
	for (k = 0; k < n; k++) {
		int off = ext_cap(md[k].dsp, PCI_EXT_CAP_ID_ACS);
		uint32_t ctl = 0;

		if (off < 0 || cfg_read(md[k].dsp, off + PCI_ACS_CTRL, 2, &ctl) || (ctl & 0x1f) != 0x1f)
			acs_ok = 0;
	}
	report(ext_cap(sw_rp, PCI_EXT_CAP_ID_ACS) > 0 && acs_ok, "RP and every DSP have ACS with SV TB RR CR UF enabled");
	{
		uint32_t rp = 0, usp = 0, dsp = 0;

		cfg_read(sw_rp, PCI_PRIMARY_BUS, 4, &rp);
		cfg_read(sw_usp, PCI_PRIMARY_BUS, 4, &usp);
		cfg_read(md[n - 1].dsp, PCI_PRIMARY_BUS, 4, &dsp);
		report((rp & 0xffffff) == (unsigned)(SW_BUS | (SW_BUS + 1) << 8 | (SW_BUS + 2 + n) << 16) &&
		       (usp & 0xffffff) == (unsigned)((SW_BUS + 1) | (SW_BUS + 2) << 8 | (SW_BUS + 2 + n) << 16) &&
		       (dsp & 0xffffff) == (unsigned)((SW_BUS + 2) | (SW_BUS + 2 + n) << 8 | (SW_BUS + 2 + n) << 16),
		       "bus numbers: RP %06x USP %06x last DSP %06x", rp & 0xffffff, usp & 0xffffff, dsp & 0xffffff);
	}
	snprintf(sw_dbg, sizeof(sw_dbg), "/sys/kernel/debug/pciem/switch-0000:%02x", SW_BUS);
	report(path_exists("%s/trace", sw_dbg) && path_exists("%s/trace_ctl", sw_dbg) &&
	       path_exists("%s/topology", sw_dbg) && path_exists("%s/rp/state", sw_dbg),
	       "switch debugfs directory %s has trace, trace_ctl, topology and rp/state", sw_dbg);
	{
		char path[200];

		snprintf(path, sizeof(path), "%s/topology", md[n - 1].dbg);
		slurp(path, b, sizeof(b));
		report(strstr(b, "\"switch_ports\":") && strstr(b, md[n - 1].dsp) && strstr(b, md[n - 1].ep) &&
		       strstr(b, sw_rp) && strstr(b, sw_usp),
		       "device topology lists the shared RP, USP, its DSP and its EP");
		snprintf(path, sizeof(path), "%s/topology", sw_dbg);
		slurp(path, js, sizeof(js));
		report(strstr(js, md[0].dsp) && strstr(js, md[n - 1].dsp) && strstr(js, md[n - 1].ep),
		       "switch topology lists every DSP and EP");
	}
}

static int trace_events_after(struct mdev *m, const char *mark, const char *ev)
{
	char needle[64];

	msel(m);
	snprintf(needle, sizeof(needle), "\"ev\":\"%s\"", ev);
	return count_after(after_mark(mark), needle);
}

static int switch_events_after(const char *mark, const char *ev)
{
	char path[200], needle[64], *p;
	int n = 0;

	snprintf(path, sizeof(path), "%s/trace", sw_dbg);
	trace_load();
	if (slurp(path, trace_buf, TRACE_MAX) < 0)
		return -1;
	snprintf(needle, sizeof(needle), "\"text\":\"%s\"", mark);
	p = strstr(trace_buf, needle);
	if (!p)
		return -1;
	snprintf(needle, sizeof(needle), "\"ev\":\"%s\"", ev);
	for (p = strstr(p, needle); p; p = strstr(p + 1, needle))
		n++;
	return n;
}

static void mark_all(int n, const char *text)
{
	char cmd[80], path[200];
	int k;

	for (k = 0; k < n; k++) {
		snprintf(path, sizeof(path), "%s/trace_ctl", md[k].dbg);
		snprintf(cmd, sizeof(cmd), "mark %s", text);
		write_str(path, cmd);
	}
	snprintf(path, sizeof(path), "%s/trace_ctl", sw_dbg);
	write_str(path, cmd);
}

static void multi_isolation(int n)
{
	int picks[3] = { 0, n / 2, n - 1 }, pi;

	for (pi = 0; pi < 3; pi++) {
		int k = picks[pi], j, others_up = 1, others_quiet = 1, rc;
		char mk[16];

		if (pi && k == picks[pi - 1])
			continue;
		for (j = 0; j < n; j++)
			msave(&md[j]);
		snprintf(mk, sizeof(mk), "iso%d", k);
		mark_all(n, mk);
		msel(&md[k]);
		rc = link_op(PCIEM_LINK_DOWN, 0, 0);
		report(rc == 0, "port %d: PCIEM_LINK_DOWN: %s", k, strerror(rc));
		report(wait_state(300, 2, "dl", "down") == 0, "port %d dl=down", k);
		sleep_ms(100);
		for (j = 0; j < n; j++) {
			if (j == k)
				continue;
			others_up = others_up && mlink_up(&md[j]) && vendor_ok(md[j].ep);
			others_quiet = others_quiet && !trace_events_after(&md[j], mk, "dl") &&
				       !trace_events_after(&md[j], mk, "ltssm");
		}
		report(others_up, "port %d down: the other %d links stay in L0 and their EPs answer", k, n - 1);
		report(others_quiet, "port %d down: no dl or ltssm record in the other devices' traces", k);
		report(switch_events_after(mk, "dl") == 0 && switch_events_after(mk, "ltssm") == 0,
		       "port %d down: the switch trace has no dl or ltssm record", k);
		report(!vendor_ok(md[k].ep), "port %d down: its EP does not answer", k);
		msel(&md[k]);
		rc = link_op(PCIEM_LINK_UP, PCIEM_LINK_SPEED_32GT, 8);
		report(rc == 0, "port %d: PCIEM_LINK_UP: %s", k, strerror(rc));
		report(wait_state(3000, 4, "ltssm", "L0", "dl", "up") == 0, "port %d link back in L0", k);
		sleep_ms(300);
		msel(&md[k]);
		report(wait_state(3000, 4, "ltssm", "L0", "speed", "5") == 0, "port %d link at full speed again", k);
		mrestore(&md[k]);
		others_quiet = 1;
		for (j = 0; j < n; j++)
			if (j != k)
				others_quiet = others_quiet && !trace_events_after(&md[j], mk, "dl");
		report(others_quiet && vendor_ok(md[k].ep), "port %d up: only its own trace saw the link events", k);
	}
}

static int resets_of(int j)
{
	msel(&md[j]);
	mflush();
	return md[j].hot;
}

static int link_up_rp(void)
{
	char path[200], buf[400];

	snprintf(path, sizeof(path), "%s/rp/state", sw_dbg);
	return !read_text(path, buf, sizeof(buf)) && strstr(buf, "ltssm=L0") && strstr(buf, "dl=up");
}

static void multi_sbr(int n)
{
	int k = n > 1 ? 1 : 0, j, all_ok = 1, only = 1, rc;
	char path[200];

	for (j = 0; j < n; j++) {
		msave(&md[j]);
		resets_of(j);
		md[j].hot = 0;
	}
	mark_all(n, "sbr1");
	snprintf(path, sizeof(path), "/sys/bus/pci/devices/%s/reset_subordinate", md[k].dsp);
	rc = write_str(path, "1");
	report(rc == 0, "reset_subordinate on DSP %s: %s", md[k].dsp, strerror(rc ? errno : 0));
	sleep_ms(500);
	report(mlink_up(&md[k]) && vendor_ok(md[k].ep), "DSP %d reset: device %d is back", k, k);
	for (j = 0; j < n; j++) {
		int h = resets_of(j);

		if (j == k ? h != 1 : h != 0)
			only = 0;
		if (j != k && (trace_events_after(&md[j], "sbr1", "dl") || !mlink_up(&md[j])))
			all_ok = 0;
	}
	report(only, "SBR on DSP %d: PCIEM_RESET_HOT reached device %d only", k, k);
	report(all_ok, "SBR on DSP %d: the other links saw no dl record", k);
	mrestore(&md[k]);

	for (j = 0; j < n; j++) {
		msave(&md[j]);
		resets_of(j);
		md[j].hot = 0;
	}
	mark_all(n, "sbr2");
	snprintf(path, sizeof(path), "/sys/bus/pci/devices/%s/reset_subordinate", sw_rp);
	rc = write_str(path, "1");
	report(rc == 0, "reset_subordinate on RP %s: %s", sw_rp, strerror(rc ? errno : 0));
	sleep_ms(1500);
	all_ok = 1;
	only = 1;
	for (j = 0; j < n; j++) {
		int h = resets_of(j);

		if (h != 1)
			only = 0;
		if (!mlink_up(&md[j]) || !vendor_ok(md[j].ep))
			all_ok = 0;
	}
	report(only, "SBR on the RP: every device got exactly one PCIEM_RESET_HOT");
	{
		int seen = 1;

		for (j = 0; j < n; j++) {
			msel(&md[j]);
			seen = seen && count_after(after_mark("sbr2"), "\"kind\":\"hot\"") >= 1;
		}
		report(seen, "SBR on the RP: every device's trace has a hot reset record");
	}
	report(all_ok, "SBR on the RP: every link is back in L0 and every EP answers");
	report(switch_events_after("sbr2", "reset") > 0, "SBR on the RP: the switch trace has reset records");
	{
		uint32_t b[MAXDEV] = {};
		int same = 1;

		for (j = 0; j < n; j++) {
			cfg_read(md[j].ep, PCI_BASE_ADDRESS_2, 4, &b[j]);
			same = same && b[j] == md[j].bar2;
		}
		report(same, "SBR on the RP: BARs restored by Linux");
	}
}

static void multi_usp_sbr(int n)
{
	int j, only = 1, all_ok = 1, rc;
	char path[200];

	for (j = 0; j < n; j++) {
		msave(&md[j]);
		resets_of(j);
		md[j].hot = 0;
	}
	snprintf(path, sizeof(path), "/sys/bus/pci/devices/%s/reset_subordinate", sw_usp);
	rc = write_str(path, "1");
	report(rc == 0, "reset_subordinate on USP %s: %s", sw_usp, strerror(rc ? errno : 0));
	sleep_ms(1500);
	for (j = 0; j < n; j++) {
		only = only && resets_of(j) == 1;
		all_ok = all_ok && mlink_up(&md[j]) && vendor_ok(md[j].ep);
	}
	report(only, "SBR on the USP: every device got exactly one PCIEM_RESET_HOT");
	report(all_ok, "SBR on the USP: every link is back in L0 and every EP answers");
	report(link_up_rp(), "SBR on the USP: the RP link was not disturbed");
}

static void multi_detach(int n)
{
	int order[3] = { n > 1 ? 1 : 0, 0, n - 1 }, oi;

	for (oi = 0; oi < 3; oi++) {
		int k = order[oi], j, others = 1, rc;

		if (oi && k == order[oi - 1])
			continue;
		mdev_close(&md[k]);
		report(wait_path("/sys/bus/pci/devices/%s", md[k].ep, 0, 5000), "port %d detached: EP %s is gone", k, md[k].ep);
		report(path_exists("/sys/bus/pci/devices/%s", sw_rp) && path_exists("/sys/bus/pci/devices/%s", md[k].dsp),
		       "port %d detached: RP and its DSP remain", k);
		for (j = 0; j < n; j++)
			if (j != k)
				others = others && mlink_up(&md[j]) && vendor_ok(md[j].ep);
		report(others, "port %d detached: the other devices are unaffected", k);
		rc = mdev_create(k, n, 0, BAR2_SIZE, 1);
		report(rc == 0, "port %d attached again: %s", k, strerror(rc));
		report(wait_path("/sys/bus/pci/devices/%s", md[k].ep, 1, 5000) && mlink_up(&md[k]) && vendor_ok(md[k].ep),
		       "port %d attached again: EP %s is back with its link in L0", k, md[k].ep);
	}
}

static void multi_errors(int n)
{
	struct mdev saved = md[n - 1];
	int rc;

	rc = mdev_create(n - 1, n, 0, BAR2_SIZE, 1);
	report(rc == EBUSY, "a second device on port %d: %s (expected EBUSY)", n - 1, strerror(rc));
	mdev_close(&md[n - 1]);
	md[n - 1] = saved;

	rc = mdev_create(n, n + 1, 0, BAR2_SIZE, 1);
	report(rc == EINVAL, "a device with another switch_ports: %s (expected EINVAL)", strerror(rc));
	mdev_close(&md[n]);

	rc = mdev_create(n, n, 0, BAR2_SIZE, 1);
	report(rc == EINVAL, "a device on port %d of %d: %s (expected EINVAL)", n, n, strerror(rc));
	mdev_close(&md[n]);
}

static void multi_errors_free_port(int n)
{
	int rc;

	rc = mdev_create(n - 1, n, PCIEM_TOPO_FLAG_UNMASK_SDES, BAR2_SIZE, 1);
	report(rc == EINVAL, "a device with other flags than the switch's: %s (expected EINVAL)", strerror(rc));
	mdev_close(&md[n - 1]);
	rc = mdev_create(n - 1, n, 0, 64u << 20, 1);
	report(rc == ENOSPC, "a device with BARs larger than the chunk: %s (expected ENOSPC)", strerror(rc));
	rc = ioctl(md[n - 1].ctl, PCIEM_IOCTL_REGISTER) < 0 ? errno : 0;
	report(rc == EINVAL, "REGISTER again after the failed one: %s (expected EINVAL)", strerror(rc));
	mdev_close(&md[n - 1]);
	rc = mdev_create(n - 1, 0, 0, BAR2_SIZE, 1);
	report(rc == EINVAL, "a switch device without SET_TOPOLOGY: %s (expected EINVAL)", strerror(rc));
	mdev_close(&md[n - 1]);
}

static void multi_run_close_all(int n, const int *order)
{
	int i;

	for (i = 0; i < n; i++)
		mdev_close(&md[order[i]]);
}

static int multi_partial(void)
{
	static const int ports[] = { 2, 0 };
	int i, rc;

	for (i = 0; i <= MAXDEV; i++)
		md[i].ctl = -1;
	for (i = 0; i < 2; i++) {
		rc = mdev_create(ports[i], 3, 0, BAR2_SIZE, 1);
		report(rc == 0, "device on port %d registered: %s", ports[i], strerror(rc));
		if (rc)
			return 1;
		report(wait_path("/sys/bus/pci/devices/%s", md[ports[i]].ep, 1, 5000), "EP %s appeared", md[ports[i]].ep);
	}
	printf("RESULT: %s\n", failures ? "FAIL" : "PASS");
	return failures ? 1 : 0;
}

static int multi_main(int n)
{
	int warn_before = dmesg_count("WARNING:"), bug_before = dmesg_count("BUG:");
	int k, rc, order[MAXDEV], i;
	long end;

	if (n < 1 || n > MAXDEV)
		errx(1, "ports must be 1..%d", MAXDEV);
	nports = n;
	snprintf(sw_rp, sizeof(sw_rp), "0000:%02x:00.0", SW_BUS);
	snprintf(sw_usp, sizeof(sw_usp), "0000:%02x:00.0", SW_BUS + 1);
	for (k = 0; k <= MAXDEV; k++)
		md[k].ctl = -1;

	rc = mdev_create(0, n, 0, BAR2_SIZE, 0);
	report(rc == EINVAL, "a switch device without FIXED_ADDRESS: %s (expected EINVAL)", strerror(rc));
	mdev_close(&md[0]);

	for (k = 0; k < n; k++) {
		if (k == n - 1 && n > 1)
			multi_errors_free_port(n);
		rc = mdev_create(k, n, 0, BAR2_SIZE, 1);
		report(rc == 0, "device on port %d registered: %s", k, strerror(rc));
		if (rc)
			errx(1, "cannot continue");
	}
	for (k = 0; k < n; k++)
		report(wait_path("/sys/bus/pci/devices/%s", md[k].ep, 1, 5000), "EP %s appeared", md[k].ep);
	(void)!system("lspci -tv 2>/dev/null | grep -v '^ |'");
	multi_enumerate(n);
	if (getenv("TOPO_HOLD") && *getenv("TOPO_HOLD"))
		sleep(atoi(getenv("TOPO_HOLD")));
	multi_isolation(n);
	multi_sbr(n);
	multi_usp_sbr(n);
	multi_detach(n);
	if (n > 1)
		multi_errors(n);

	for (i = 0; i < n; i++)
		order[i] = n - 1 - i;
	multi_run_close_all(n, order);
	end = now_ms() + 5000;
	while (now_ms() < end && (count_ids(0xd130) || count_ids(0xd131) || count_ids(0xd132)))
		usleep(50000);
	report(!count_ids(0xd130) && !count_ids(0xd131) && !count_ids(0xd132),
	       "no port of the switch remains after the last device left");
	report(!path_exists("%s", sw_dbg), "the switch debugfs directory is gone");
	report(dmesg_count("WARNING:") == warn_before && dmesg_count("BUG:") == bug_before,
	       "dmesg has no new WARNING: or BUG: lines");
	printf("RESULT: %s\n", failures ? "FAIL" : "PASS");
	return failures ? 1 : 0;
}

int main(int argc, char **argv)
{
	int warn_before, bug_before;
	long end;

	if (argc < 2 || (strcmp(argv[1], "root-port") && strcmp(argv[1], "switch") &&
			 strcmp(argv[1], "switch-multi"))) {
		fprintf(stderr, "usage: %s root-port|switch [eq] | switch-multi [ports|partial]\n", argv[0]);
		return 2;
	}
	if (!strcmp(argv[1], "switch-multi"))
		return argc > 2 && !strcmp(argv[2], "partial") ? multi_partial() : multi_main(argc > 2 ? atoi(argv[2]) : 3);
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
		usleep(300000);
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
	step_recovery_resume();
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
