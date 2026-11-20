#!/bin/bash
# Checks the list merge: garbage and >50% shrink keep the previous copy, wide/private nets are dropped.
set -e
GUARD_LIB_ONLY=1 source "$(dirname "$0")/../guard.sh"
t=$(mktemp -d); trap 'rm -rf "$t"' EXIT
mkdir -p "$t/w" "$t/s"
ALLOW="$t/allow"

if merge_lists "$t/w" "$t/s" "$t/out" a b; then exit 1; fi

printf '1.2.3.0/24\n1.2.4.0/24\n5.6.7.8\n10.0.0.0/8\n2.0.0.0/8\n2a00::/48\n# ФГУП «c»\n' >"$t/w/a"
printf '9.9.9.0/24\n' >"$t/w/b"
[[ $(merge_lists "$t/w" "$t/s" "$t/out" a b) == "4 1" ]]
grep -qx '5.6.7.8/32' "$t/out"
if grep -qE '10.0.0.0|2.0.0.0' "$t/out"; then exit 1; fi

printf '<html>error</html>\n' >"$t/w/a"; rm "$t/w/b"
[[ $(merge_lists "$t/w" "$t/s" "$t/out" a b) == "4 1" ]]

printf '1.2.3.0/24\n' >"$t/w/a"
[[ $(merge_lists "$t/w" "$t/s" "$t/out" a b) == "4 1" ]]

printf '1.2.3.0/25\n5.6.7.8\n2a00::/48\n' >"$ALLOW"
[[ $(merge_lists "$t/w" "$t/s" "$t/out" a b) == "3 0" ]]
grep -qx '1.2.3.128/25' "$t/out"
if grep -qFx '1.2.3.0/24' "$t/out"; then exit 1; fi
echo ok
