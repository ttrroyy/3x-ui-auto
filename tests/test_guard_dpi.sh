#!/bin/bash
# Linux root, nftables, and a binary built by assets/vh-dpid/build.sh.
set -eu
src=$(realpath -- "$(dirname -- "$0")/../torrent.sh")
binary=$(realpath -- "${1:?pass the path to vh-dpid}")
unshare -n bash -se -- "$src" "$binary" <<'TEST'
TORRENT_LIB_ONLY=1 source "$1"
tmp=$(mktemp -d)
trap '[[ -z ${daemon:-} ]] || { kill "$daemon" 2>/dev/null || true; wait "$daemon" || true; }; rm -rf -- "$tmp"' EXIT
ip link set lo up
apply_torrent_rules
"$2" --mode enforce --stats "$tmp/stats.json" &
daemon=$!
for attempt in {1..50}; do
    [[ -s "$tmp/stats.json" ]] && break
    kill -0 "$daemon"
    sleep 0.1
done
[[ -s "$tmp/stats.json" ]]

python3 - <<'PY'
import errno
import socket
import time

def exercise(family, address):
    with socket.socket(family, socket.SOCK_DGRAM) as receiver:
        receiver.bind((address, 0))
        receiver.settimeout(.2)
        peer = receiver.getsockname()
        with socket.socket(family, socket.SOCK_DGRAM) as torrent:
            # The uTP data header and peer-wire handshake bypass the fixed nft signatures.
            torrent.sendto(b'\x01' + bytes(19) + b'\x13BitTorrent protocol' + bytes(48), peer)
            try:
                assert receiver.recv(1024)[0] == 1
            except TimeoutError:
                pass
            deadline = time.monotonic() + 2
            while True:
                try:
                    torrent.sendto(b'follow-up', peer)
                    assert receiver.recv(1024) == b'follow-up'
                except TimeoutError:
                    break
                except PermissionError as error:
                    assert error.errno == errno.EPERM
                    break
                assert time.monotonic() < deadline, "DPI never blocked this uTP flow"
                time.sleep(.03)

        with socket.socket(family, socket.SOCK_DGRAM) as ordinary:
            for i in range(15):
                data = b'ordinary datagram peer_id=ok' + bytes([i])
                ordinary.sendto(data, peer)
                assert receiver.recv(1024) == data

exercise(socket.AF_INET, '127.0.0.1')
exercise(socket.AF_INET6, '::1')
PY
nft list chain inet "$TABLE" torrent | grep -E 'packets [1-9][0-9]* .*comment "dpi-mark"'
kill "$daemon"
wait "$daemon"
daemon=
python3 - "$tmp/stats.json" <<'PY'
import json
import sys

with open(sys.argv[1]) as f:
    stats = json.load(f)
assert stats["marked"] >= 2, stats
print("DPI marked IPv4 and IPv6 uTP flows. Other flows to the same endpoints passed.")
PY
TEST
