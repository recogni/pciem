// SPDX-License-Identifier: MIT
/*
 * pciem_vroot_smoke.c - minimal virtual-root registration helper
 *
 * This helper intentionally exercises the arm64 virtual-root path that used
 * to oops during synthetic host-bridge registration. It creates two separate
 * root complexes, keeps both instance fds open, and then waits until killed.
 *
 * With a domain argument (hex), it puts them at DOMAIN:00 and DOMAIN:01 with
 * PCIEM_CREATE_FLAG_FIXED_ADDRESS, then checks that a third device asking for
 * DOMAIN:00 is refused with EEXIST.
 */
#include <errno.h>
#include <err.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>

#include "pciem_api.h"

#define PCIEM_VROOT_VENDOR_ID 0x1AB8
#define PCIEM_VROOT_DEV0_ID   0xD120
#define PCIEM_VROOT_DEV1_ID   0xD121

struct vroot_device {
	int ctl_fd;
	int instance_fd;
};

static struct vroot_device devices[2] = {
	{ .ctl_fd = -1, .instance_fd = -1 },
	{ .ctl_fd = -1, .instance_fd = -1 },
};

static void close_device(struct vroot_device *dev)
{
	if (dev->instance_fd >= 0) {
		close(dev->instance_fd);
		dev->instance_fd = -1;
	}

	if (dev->ctl_fd >= 0) {
		close(dev->ctl_fd);
		dev->ctl_fd = -1;
	}
}

static void cleanup(int sig)
{
	(void)sig;
	close_device(&devices[1]);
	close_device(&devices[0]);
	_exit(0);
}

/* Returns 0, or the REGISTER errno when allow_fail is set. */
static int create_device(struct vroot_device *dev, unsigned int device_id,
			 int domain, unsigned int bus, int allow_fail)
{
	struct pciem_create_device create = {
		.flags = PCIEM_CREATE_FLAG_BUS_MODE_VIRTUAL,
	};
	struct pciem_config_space cfg = {
		.vendor_id = PCIEM_VROOT_VENDOR_ID,
		.device_id = device_id,
		.class_code = { 0x00, 0x00, 0x02 },
	};

	if (domain >= 0) {
		create.flags |= PCIEM_CREATE_FLAG_FIXED_ADDRESS;
		create.domain = (uint16_t)domain;
		create.bus = (uint8_t)bus;
	}

	dev->ctl_fd = open("/dev/pciem", O_RDWR);
	if (dev->ctl_fd < 0)
		err(1, "open /dev/pciem");

	if (ioctl(dev->ctl_fd, PCIEM_IOCTL_CREATE_DEVICE, &create) < 0)
		err(1, "PCIEM_IOCTL_CREATE_DEVICE (device %04x)", device_id);

	if (ioctl(dev->ctl_fd, PCIEM_IOCTL_SET_CONFIG, &cfg) < 0)
		err(1, "PCIEM_IOCTL_SET_CONFIG (device %04x)", device_id);

	dev->instance_fd = ioctl(dev->ctl_fd, PCIEM_IOCTL_REGISTER);
	if (dev->instance_fd < 0) {
		if (allow_fail)
			return errno;
		err(1, "PCIEM_IOCTL_REGISTER (device %04x)", device_id);
	}
	return 0;
}

int main(int argc, char **argv)
{
	int domain = argc > 1 ? (int)strtol(argv[1], NULL, 16) : -1;

	signal(SIGINT, cleanup);
	signal(SIGTERM, cleanup);

	create_device(&devices[0], PCIEM_VROOT_DEV0_ID, domain, 0, 0);
	create_device(&devices[1], PCIEM_VROOT_DEV1_ID, domain, 1, 0);

	if (domain >= 0) {
		struct vroot_device taken = { .ctl_fd = -1, .instance_fd = -1 };
		int rc = create_device(&taken, PCIEM_VROOT_DEV0_ID, domain, 0, 1);

		close_device(&taken);
		if (rc != EEXIST)
			errx(1, "a third device at %04x:00 got %s, not EEXIST",
			     domain, rc ? strerror(rc) : "registered");
		printf("a third device at %04x:00 was refused with EEXIST\n", domain);
	}

	printf("registered two virtual-root devices: %04x:%04x and %04x:%04x\n",
	       PCIEM_VROOT_VENDOR_ID, PCIEM_VROOT_DEV0_ID,
	       PCIEM_VROOT_VENDOR_ID, PCIEM_VROOT_DEV1_ID);
	fflush(stdout);

	for (;;)
		pause();

	return 0;
}
