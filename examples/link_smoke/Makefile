# SPDX-License-Identifier: MIT

THIS_MAKEFILE := $(lastword $(MAKEFILE_LIST))
THIS_DIR      := $(abspath $(dir $(THIS_MAKEFILE)))
PCIEM_ROOT    := $(THIS_DIR)/../..

CFLAGS := -Wall -Wextra -O2 -I$(PCIEM_ROOT)/include
LDFLAGS ?=

.PHONY: all clean

all: link_smoke

link_smoke: link_smoke.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^

clean:
	rm -f link_smoke
