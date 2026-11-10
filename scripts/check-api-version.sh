#!/usr/bin/env bash
# Require a version bump for non-comment header changes since BASE (default origin/dev).
set -euo pipefail

base=${1:-origin/dev}
header=include/pciem_api.h

strip() { gcc -fpreprocessed -dD -E -P -x c - 2>/dev/null | tr -s ' \t' ' ' | sed '/^ *$/d'; }
version() { grep -E '^#define PCIEM_API_VERSION_(MAJOR|MINOR) ' || true; }

old=$(git show "$(git merge-base "$base" HEAD):$header" 2>/dev/null || true)
new=$(cat "$header")

if [[ "$(strip <<<"$old")" == "$(strip <<<"$new")" ]]; then
    echo "$header: no interface change"
    exit 0
fi
if [[ "$(version <<<"$old")" == "$(version <<<"$new")" ]]; then
    echo "$header changed, but PCIEM_API_VERSION_MAJOR/MINOR did not." >&2
    echo "Bump MINOR for an addition an older user can ignore, MAJOR for anything else." >&2
    exit 1
fi
echo "$header: interface changed and its version moved"
