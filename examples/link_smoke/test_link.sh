#!/bin/sh
# SPDX-License-Identifier: MIT

set -eu

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PCIEM_KO="${PCIEM_KO:-$SCRIPT_DIR/../../kernel/pciem.ko}"
HELPER="${HELPER:-$SCRIPT_DIR/link_smoke}"
PCIEM_PHYS_REGION="${PCIEM_PHYS_REGION:-}"
LOADED=0

die() {
	echo "FATAL: $*" >&2
	exit 1
}

cleanup() {
	if [ "$LOADED" -eq 1 ]; then
		rmmod pciem 2>/dev/null || true
	fi
}

[ "$(id -u)" -eq 0 ] || die "this script must be run as root"
[ -x "$HELPER" ] || die "helper not found: $HELPER"

trap cleanup EXIT INT TERM

if ! grep -q '^pciem ' /proc/modules; then
	[ -f "$PCIEM_KO" ] || die "pciem.ko not found: $PCIEM_KO"
	[ -n "$PCIEM_PHYS_REGION" ] ||
		die "pciem is not loaded: set PCIEM_PHYS_REGION=0xADDR:0xSIZE (a region reserved with memmap=) for the BAR pool, or load pciem first"
	insmod "$PCIEM_KO" pciem_phys_region="$PCIEM_PHYS_REGION"
	LOADED=1
fi

[ -d /sys/kernel/debug/pciem ] || mount -t debugfs none /sys/kernel/debug 2>/dev/null || true

"$HELPER"
