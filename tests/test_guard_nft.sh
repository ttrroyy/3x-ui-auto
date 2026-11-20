#!/bin/bash
# Exercise the native rules without touching the host firewall.
set -eu
if ! command -v nft >/dev/null || ! unshare -n true 2>/dev/null; then
    echo 'skip: nftables and a private network namespace are required'
    exit 0
fi

unshare -n bash -se -- "$(dirname "$0")/../guard.sh" <<'TEST'
GUARD_LIB_ONLY=1 source "$1"
tmp=$(mktemp -d)
trap 'rm -rf -- "$tmp"' EXIT
ssh_ports() { echo 22; }

nft add table inet unrelated
printf '192.0.2.0/24\n2001:db8::/29\n' >"$tmp/lists"
apply_rules "$tmp/lists"
nft list set inet "$TABLE" scanners4 | grep -Fq '192.0.2.0/24'
nft list set inet "$TABLE" scanners6 | grep -Fq '2001:db8::/29'
before=$(nft list table inet "$TABLE")
printf 'invalid-element\n' >"$tmp/lists"
if apply_rules "$tmp/lists" 2>/dev/null; then exit 1; fi
[[ $(nft list table inet "$TABLE") == "$before" ]]
nft list table inet unrelated >/dev/null
echo ok
TEST
