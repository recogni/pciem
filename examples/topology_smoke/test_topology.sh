#!/bin/sh
# SPDX-License-Identifier: MIT
#
# Usage: test_topology.sh [root-port|switch|all] [eq]

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
root-port | switch | all) ;;
*) die "usage: $0 [root-port|switch|all] [eq]" ;;
esac
case "$EQ" in
"" | eq) ;;
*) die "usage: $0 [root-port|switch|all] [eq]" ;;
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
	PLACEMENTS="root-port switch"
else
	PLACEMENTS="$WHICH"
fi

rc=0
for p in $PLACEMENTS; do
	echo "=== placement $p ${EQ:+with an equalization limit}"
	"$HELPER" "$p" $EQ || rc=1
done

if [ "$rc" -eq 0 ]; then
	echo "RESULT: PASS"
else
	echo "RESULT: FAIL"
fi
exit "$rc"
