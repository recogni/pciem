// SPDX-License-Identifier: MIT
/*
 * api_version.c - print the loaded module's interface version and check it
 * against the header this was built with.
 *
 * Exits 0 when the module has the same major version and at least this
 * header's minor version, 1 otherwise.
 */
#include <err.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/ioctl.h>

#include "pciem_api.h"

static int compatible(uint32_t major, uint32_t minor, uint32_t want_major, uint32_t want_minor)
{
	return major == want_major && minor >= want_minor;
}

int main(void)
{
	struct pciem_api_version v = { 0 };
	int fd = open("/dev/pciem", O_RDWR);

	if (fd < 0)
		err(1, "open /dev/pciem");
	if (ioctl(fd, PCIEM_IOCTL_GET_API_VERSION, &v) < 0)
		err(1, "PCIEM_IOCTL_GET_API_VERSION");
	close(fd);

	printf("module %u.%u, header %u.%u\n", v.major, v.minor,
	       PCIEM_API_VERSION_MAJOR, PCIEM_API_VERSION_MINOR);
	if (!compatible(v.major, v.minor, PCIEM_API_VERSION_MAJOR, PCIEM_API_VERSION_MINOR)) {
		fprintf(stderr, "incompatible: need %u.%u or a later %u.x\n",
			PCIEM_API_VERSION_MAJOR, PCIEM_API_VERSION_MINOR,
			PCIEM_API_VERSION_MAJOR);
		return 1;
	}
	return 0;
}
