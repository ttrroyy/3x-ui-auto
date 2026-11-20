#!/bin/bash
set -euo pipefail

src=$(cd -- "$(dirname -- "$0")/src" && pwd)
output=$(realpath -m -- "$1")
build=$(mktemp -d)
trap 'rm -rf -- "$build"' EXIT
cd "$build"

ref=1a5293396337f9a72dfee1fa070b2c4b0a0a3aaf
curl -fsSL --retry 2 --connect-timeout 15 --max-time 600 --speed-time 45 --speed-limit 1024 \
    --proto '=https' --proto-redir '=https' \
    "https://codeload.github.com/ntop/nDPI/tar.gz/$ref" -o ndpi.tgz
sha256sum -c <<< 'c7d488379fb309696171ece0f86e4a44f1ea60cb976fd274db55aabc23b04151  ndpi.tgz'
tar -xzf ndpi.tgz --strip-components=1
./autogen.sh
./configure --disable-shared
make -j2 -C src/lib libndpi.a
cc -O2 -Wall -Wextra -Werror -Isrc/include -Isrc/lib/third_party/include \
    "$src/engine.c" "$src/live.c" src/lib/libndpi.a -lmnl -lm -lpthread -o "$output"
