#!/bin/sh
# SPDX-License-Identifier: MIT
#
# Usage: test_topology.sh [root-port|switch|switch-multi|all] [eq]

set -eu

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PCIEM_KO="${PCIEM_KO:-$SCRIPT_DIR/../../kernel/pciem.ko}"
HELPER="${HELPER:-$SCRIPT_DIR/topology_smoke}"
PCIEM_PHYS_REGION="${PCIEM_PHYS_REGION:-}"
WHICH="${1:-all}"
EQ="${2:-}"
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
case "$WHICH" in
root-port | switch | switch-multi | all) ;;
*) die "usage: $0 [root-port|switch|switch-multi|all] [eq]" ;;
esac
case "$EQ" in
"" | eq) ;;
*) die "usage: $0 [root-port|switch|switch-multi|all] [eq]" ;;
esac

trap cleanup EXIT INT TERM

if ! grep -q '^pciem ' /proc/modules; then
	[ -f "$PCIEM_KO" ] || die "pciem.ko not found: $PCIEM_KO"
	[ -n "$PCIEM_PHYS_REGION" ] ||
		die "pciem is not loaded: set PCIEM_PHYS_REGION=0xADDR:0xSIZE (a region reserved with memmap=) for the BAR pool, or load pciem first"
	insmod "$PCIEM_KO" pciem_phys_region="$PCIEM_PHYS_REGION"
	LOADED=1
fi

[ -d /sys/kernel/debug/pciem ] || mount -t debugfs none /sys/kernel/debug 2>/dev/null || true
echo 1 > /sys/module/pciem/parameters/trace_cfg

if [ "$WHICH" = all ]; then
	PLACEMENTS="root-port switch switch-multi"
else
	PLACEMENTS="$WHICH"
fi

rc=0
for p in $PLACEMENTS; do
	echo "=== placement $p ${EQ:+with an equalization limit}"
	if [ "$p" = switch-multi ]; then
		"$HELPER" switch-multi 3 || rc=1
		"$HELPER" switch-multi partial || rc=1
		sleep 1
	else
		"$HELPER" "$p" $EQ || rc=1
	fi
done

if [ "$LOADED" -eq 1 ]; then
	if rmmod pciem; then
		LOADED=0
	else
		echo "FAIL: rmmod pciem"
		rc=1
	fi
fi

if [ "$rc" -eq 0 ]; then
	echo "RESULT: PASS"
else
	echo "RESULT: FAIL"
fi
exit "$rc"
