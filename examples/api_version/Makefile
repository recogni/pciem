# SPDX-License-Identifier: MIT

THIS_MAKEFILE := $(lastword $(MAKEFILE_LIST))
THIS_DIR      := $(abspath $(dir $(THIS_MAKEFILE)))
PCIEM_ROOT    := $(THIS_DIR)/../..

CFLAGS := -Wall -Wextra -O2 -I$(PCIEM_ROOT)/include
LDFLAGS ?=

.PHONY: all clean

all: api_version

api_version: api_version.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^

clean:
	rm -f api_version
