# SPDX-License-Identifier: MIT

THIS_MAKEFILE := $(lastword $(MAKEFILE_LIST))
THIS_DIR      := $(abspath $(dir $(THIS_MAKEFILE)))
PCIEM_ROOT    := $(THIS_DIR)/../..

CFLAGS := -Wall -Wextra -O2 -I$(PCIEM_ROOT)/include
LDFLAGS ?= -static
LDLIBS := -lpthread

.PHONY: all clean

all: topology_smoke

topology_smoke: topology_smoke.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(LDLIBS)

clean:
	rm -f topology_smoke
