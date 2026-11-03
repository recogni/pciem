// SPDX-License-Identifier: MIT
#include <dirent.h>
#include <errno.h>
#include <err.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <linux/pci_regs.h>

#include "pciem_api.h"

#define VENDOR_ID 0x1ab8
#define DEVICE_ID 0xd122
#define BAR_SIZE (1u << 20)
#define MODEL_PATTERN 0x5a5aa5a5u
#define HOST_WRITE_DOWN 0x11111111u
#define HOST_WRITE_UP 0x22222222u
#define PAGE 4096

static int ctl_fd = -1;
static int instance_fd = -1;
static char bdf[16];
static char sysdir[64];
static char knob[96];
static int failures;

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

static ssize_t read_file(const char *path, void *buf, size_t size)
{
	int fd = open(path, O_RDONLY);
	ssize_t n;

	if (fd < 0)
		return -1;
	n = read(fd, buf, size);
	close(fd);
	return n;
}

static int read_text(const char *path, char *buf, size_t size)
{
	ssize_t n = read_file(path, buf, size - 1);

	if (n < 0)
		return -1;
	while (n > 0 && buf[n - 1] == '\n')
		n--;
	buf[n] = '\0';
	return 0;
}

static int read_sys(const char *name, char *buf, size_t size)
{
	char path[128];

	snprintf(path, sizeof(path), "%s/%s", sysdir, name);
	return read_text(path, buf, size);
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

static int write_sys(const char *name, const char *s)
{
	char path[128];

	snprintf(path, sizeof(path), "%s/%s", sysdir, name);
	return write_str(path, s);
}

static int read_config(uint8_t cfg[256])
{
	char path[128];

	snprintf(path, sizeof(path), "%s/config", sysdir);
	return read_file(path, cfg, 256) == 256 ? 0 : -1;
}

static uint32_t cfg_u32(const uint8_t *cfg, unsigned int off)
{
	return cfg[off] | cfg[off + 1] << 8 | cfg[off + 2] << 16 | (uint32_t)cfg[off + 3] << 24;
}

static uint16_t cfg_u16(const uint8_t *cfg, unsigned int off)
{
	return cfg[off] | cfg[off + 1] << 8;
}

static int all_ones(const uint8_t *buf, size_t n)
{
	for (size_t i = 0; i < n; i++)
		if (buf[i] != 0xff)
			return 0;
	return 1;
}

static int ids_match(const uint8_t *cfg)
{
	return cfg_u16(cfg, PCI_VENDOR_ID) == VENDOR_ID && cfg_u16(cfg, PCI_DEVICE_ID) == DEVICE_ID;
}

static int link_op(uint8_t op, uint8_t speed, uint8_t width, uint32_t flags)
{
	struct pciem_link link = {
		.func = 0,
		.op = op,
		.speed = speed,
		.width = width,
		.flags = flags,
	};

	return ioctl(ctl_fd, PCIEM_IOCTL_LINK, &link) < 0 ? errno : 0;
}

static void create_device(void)
{
	struct pciem_create_device create = {
		.flags = PCIEM_CREATE_FLAG_BUS_MODE_VIRTUAL,
	};
	struct pciem_bar_config bar = {
		.bar_index = 0,
		.flags = PCI_BASE_ADDRESS_MEM_TYPE_64,
		.size = BAR_SIZE,
	};
	struct pciem_cap_config cap = {
		.cap_type = PCIEM_CAP_PCIE,
		.pcie.flags = PCIEM_CAP_PCIE_FLAG_FLR,
	};
	struct pciem_config_space cfg = {
		.vendor_id = VENDOR_ID,
		.device_id = DEVICE_ID,
		.class_code = { 0x00, 0x00, 0x02 },
	};
	struct pciem_trace_bar trace = {
		.bar_index = 0,
		.flags = PCIEM_TRACE_READS | PCIEM_TRACE_WRITES,
	};

	ctl_fd = open("/dev/pciem", O_RDWR);
	if (ctl_fd < 0)
		err(1, "open /dev/pciem");
	if (ioctl(ctl_fd, PCIEM_IOCTL_CREATE_DEVICE, &create) < 0)
		err(1, "PCIEM_IOCTL_CREATE_DEVICE");
	if (ioctl(ctl_fd, PCIEM_IOCTL_ADD_BAR, &bar) < 0)
		err(1, "PCIEM_IOCTL_ADD_BAR");
	if (ioctl(ctl_fd, PCIEM_IOCTL_ADD_CAPABILITY, &cap) < 0)
		err(1, "PCIEM_IOCTL_ADD_CAPABILITY");
	if (ioctl(ctl_fd, PCIEM_IOCTL_SET_CONFIG, &cfg) < 0)
		err(1, "PCIEM_IOCTL_SET_CONFIG");
	if (ioctl(ctl_fd, PCIEM_IOCTL_TRACE_BAR, &trace) < 0)
		err(1, "PCIEM_IOCTL_TRACE_BAR");
	instance_fd = ioctl(ctl_fd, PCIEM_IOCTL_REGISTER);
	if (instance_fd < 0)
		err(1, "PCIEM_IOCTL_REGISTER");
	if (ioctl(ctl_fd, PCIEM_IOCTL_START) < 0)
		err(1, "PCIEM_IOCTL_START");
}

static long read_hex(const char *path)
{
	char buf[32];

	if (read_text(path, buf, sizeof(buf)))
		return -1;
	return strtol(buf, NULL, 16);
}

static int find_device(void)
{
	for (int attempt = 0; attempt < 100; attempt++) {
		DIR *dir = opendir("/sys/bus/pci/devices");
		struct dirent *de;

		if (!dir)
			err(1, "opendir /sys/bus/pci/devices");
		while ((de = readdir(dir))) {
			char path[160];

			if (strlen(de->d_name) >= sizeof(bdf))
				continue;
			snprintf(path, sizeof(path), "/sys/bus/pci/devices/%.15s/vendor", de->d_name);
			if (read_hex(path) != VENDOR_ID)
				continue;
			snprintf(path, sizeof(path), "/sys/bus/pci/devices/%.15s/device", de->d_name);
			if (read_hex(path) != DEVICE_ID)
				continue;
			snprintf(bdf, sizeof(bdf), "%.15s", de->d_name);
			closedir(dir);
			return 0;
		}
		closedir(dir);
		usleep(100000);
	}
	return -1;
}

static volatile uint32_t *map_resource0(void)
{
	char path[128];
	void *p;
	int fd, tries;

	snprintf(path, sizeof(path), "%s/resource0", sysdir);
	for (tries = 0; tries < 50; tries++) {
		fd = open(path, O_RDWR | O_SYNC);
		if (fd >= 0 || errno != ENOENT)
			break;
		usleep(100000);
	}
	if (fd < 0)
		err(1, "open %s", path);
	p = mmap(NULL, PAGE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	close(fd);
	if (p == MAP_FAILED)
		err(1, "mmap %s", path);
	return p;
}

static void check_down(const char *how, volatile uint32_t *host, volatile uint32_t *model,
		       uint32_t model_value)
{
	uint8_t cfg[256];
	char buf[64];
	uint32_t v;

	if (read_config(cfg))
		err(1, "read config");
	report(all_ones(cfg, sizeof(cfg)), "%s: config reads all-ones", how);
	if (read_sys("vendor", buf, sizeof(buf)))
		err(1, "read vendor");
	report(strtol(buf, NULL, 16) == VENDOR_ID, "%s: sysfs vendor still %s", how, buf);
	v = host[0];
	report(v == 0xffffffff, "%s: MMIO read returns 0x%08x", how, v);
	host[0] = HOST_WRITE_DOWN;
	v = model[0];
	report(v == model_value, "%s: MMIO write dropped, BAR holds 0x%08x", how, v);
}

static void check_up(const char *how, const char *speed_str, const char *resource_before,
		     volatile uint32_t *host, volatile uint32_t *model, uint32_t model_value,
		     uint32_t host_value)
{
	uint8_t cfg[256];
	char buf[4096];
	uint32_t bar0, bar1, v;
	uint16_t cmd;

	if (read_config(cfg))
		err(1, "read config");
	report(ids_match(cfg), "%s: vendor/device read back (%04x:%04x)", how,
	       cfg_u16(cfg, PCI_VENDOR_ID), cfg_u16(cfg, PCI_DEVICE_ID));
	bar0 = cfg_u32(cfg, PCI_BASE_ADDRESS_0);
	bar1 = cfg_u32(cfg, PCI_BASE_ADDRESS_1);
	report(bar0 == PCI_BASE_ADDRESS_MEM_TYPE_64 && bar1 == 0,
	       "%s: BAR0 reads 0 but for its type bits (0x%08x%08x)", how, bar1, bar0);
	cmd = cfg_u16(cfg, PCI_COMMAND);
	report(cmd == 0, "%s: COMMAND reads 0x%04x", how, cmd);
	if (read_sys("resource", buf, sizeof(buf)))
		err(1, "read resource");
	report(!strcmp(buf, resource_before), "%s: sysfs resource unchanged", how);
	if (read_sys("enable", buf, sizeof(buf)))
		err(1, "read enable");
	report(!strcmp(buf, "1"), "%s: sysfs enable still %s", how, buf);
	if (read_sys("current_link_speed", buf, sizeof(buf)))
		err(1, "read current_link_speed");
	report(!strcmp(buf, speed_str), "%s: current_link_speed is %s", how, buf);
	if (read_sys("current_link_width", buf, sizeof(buf)))
		err(1, "read current_link_width");
	report(!strcmp(buf, "16"), "%s: current_link_width is %s", how, buf);
	v = host[0];
	report(v == model_value, "%s: MMIO read sees the BAR again (0x%08x)", how, v);
	host[0] = host_value;
	v = model[0];
	report(v == host_value, "%s: MMIO write reaches the BAR (0x%08x)", how, v);
}

int main(void)
{
	char resource_before[4096], buf[64];
	volatile uint32_t *host, *model;
	uint8_t cfg[256];
	uint32_t bar0, bar1, v;
	uint16_t cmd;
	int rc;

	create_device();
	if (find_device())
		errx(1, "device %04x:%04x did not appear", VENDOR_ID, DEVICE_ID);
	snprintf(sysdir, sizeof(sysdir), "/sys/bus/pci/devices/%s", bdf);
	snprintf(knob, sizeof(knob), "/sys/kernel/debug/pciem/%s/link", bdf);
	printf("device at %s\n", bdf);

	model = mmap(NULL, PAGE, PROT_READ | PROT_WRITE, MAP_SHARED, instance_fd, 0);
	if (model == MAP_FAILED)
		err(1, "mmap BAR0 through the instance fd");
	model[0] = MODEL_PATTERN;
	host = map_resource0();

	if (read_config(cfg))
		err(1, "read config");
	report(ids_match(cfg), "enumerated as %04x:%04x", cfg_u16(cfg, PCI_VENDOR_ID),
	       cfg_u16(cfg, PCI_DEVICE_ID));
	bar0 = cfg_u32(cfg, PCI_BASE_ADDRESS_0);
	bar1 = cfg_u32(cfg, PCI_BASE_ADDRESS_1);
	report((bar0 & PCI_BASE_ADDRESS_MEM_MASK) || bar1, "BAR0 assigned at 0x%08x%08x", bar1, bar0);
	report((bar0 & PCI_BASE_ADDRESS_MEM_TYPE_MASK) == PCI_BASE_ADDRESS_MEM_TYPE_64, "BAR0 is 64-bit");
	if (read_sys("resource", resource_before, sizeof(resource_before)))
		err(1, "read resource");

	if (write_sys("enable", "1"))
		err(1, "write enable");
	if (read_config(cfg))
		err(1, "read config");
	cmd = cfg_u16(cfg, PCI_COMMAND);
	report(cmd & PCI_COMMAND_MEMORY, "memory decode enabled through sysfs (COMMAND 0x%04x)", cmd);
	v = host[0];
	report(v == MODEL_PATTERN, "MMIO read through resource0 sees the BAR (0x%08x)", v);

	rc = link_op(PCIEM_LINK_DOWN, 0, 0, 0);
	report(rc == 0, "PCIEM_LINK_DOWN: %s", strerror(rc));
	check_down("ioctl down", host, model, MODEL_PATTERN);
	rc = link_op(PCIEM_LINK_DOWN, 0, 0, 0);
	report(rc == EALREADY, "PCIEM_LINK_DOWN while down: %s", strerror(rc));
	rc = link_op(PCIEM_LINK_UP, PCIEM_LINK_SPEED_5GT, 16, 1);
	report(rc == EINVAL, "flags set: %s", strerror(rc));
	rc = link_op(PCIEM_LINK_UP, 0, 16, 0);
	report(rc == EINVAL, "speed 0: %s", strerror(rc));
	rc = link_op(PCIEM_LINK_UP, PCIEM_LINK_SPEED_5GT, 3, 0);
	report(rc == EINVAL, "width 3: %s", strerror(rc));
	rc = link_op(3, 0, 0, 0);
	report(rc == EINVAL, "op 3: %s", strerror(rc));

	rc = link_op(PCIEM_LINK_UP, PCIEM_LINK_SPEED_5GT, 16, 0);
	report(rc == 0, "PCIEM_LINK_UP 5GT/s x16: %s", strerror(rc));
	check_up("ioctl up", "5.0 GT/s PCIe", resource_before, host, model, MODEL_PATTERN,
		 HOST_WRITE_UP);
	rc = link_op(PCIEM_LINK_UP, PCIEM_LINK_SPEED_5GT, 16, 0);
	report(rc == EALREADY, "PCIEM_LINK_UP while up: %s", strerror(rc));
	rc = link_op(PCIEM_LINK_DOWN, PCIEM_LINK_SPEED_5GT, 0, 0);
	report(rc == EINVAL, "PCIEM_LINK_DOWN with a speed: %s", strerror(rc));

	if (access(knob, F_OK)) {
		report(0, "debugfs knob %s is missing (is debugfs mounted?)", knob);
	} else {
		rc = write_str(knob, "down");
		report(rc == 0, "debugfs write down: %s", strerror(rc ? errno : 0));
		check_down("debugfs down", host, model, HOST_WRITE_UP);
		if (read_text(knob, buf, sizeof(buf)))
			err(1, "read %s", knob);
		report(!strcmp(buf, "down"), "debugfs reads \"%s\"", buf);
		rc = write_str(knob, "sideways");
		report(rc < 0 && errno == EINVAL, "debugfs write garbage: %s", strerror(rc ? errno : 0));
		rc = write_str(knob, "up 5 16");
		report(rc == 0, "debugfs write up 5 16: %s", strerror(rc ? errno : 0));
		check_up("debugfs up", "32.0 GT/s PCIe", resource_before, host, model, HOST_WRITE_UP,
			 MODEL_PATTERN);
		if (read_text(knob, buf, sizeof(buf)))
			err(1, "read %s", knob);
		report(!strcmp(buf, "up 5 16"), "debugfs reads \"%s\"", buf);
	}

	munmap((void *)host, PAGE);
	munmap((void *)model, PAGE);
	close(instance_fd);
	close(ctl_fd);

	if (failures) {
		printf("RESULT: FAIL (%d)\n", failures);
		return 1;
	}
	printf("RESULT: PASS\n");
	return 0;
}
