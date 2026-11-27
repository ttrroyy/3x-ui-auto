#!/bin/bash
set -euo pipefail

src=$(cd -- "$(dirname -- "$0")/src" && pwd)
output=$(realpath -m -- "$1")
build=$(mktemp -d)
download_pid=
trap 'if [[ -n "$download_pid" ]]; then kill "$download_pid" 2>/dev/null || true; wait "$download_pid" 2>/dev/null || true; fi; rm -rf -- "$build"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
cd "$build"

ref=1a5293396337f9a72dfee1fa070b2c4b0a0a3aaf
download_args=(-fsSL --retry 2 --connect-timeout 15 --max-time 600 --speed-time 45 --speed-limit 1024
    --proto '=https' --proto-redir '=https' "https://codeload.github.com/ntop/nDPI/tar.gz/$ref" -o ndpi.tgz)
# The pinned archive has a known size even when codeload omits Content-Length.
total=48659903
width=30
echo "Скачиваю nDPI 6.0..."
[[ -t 9 ]] || exec 9>&1
if [[ -t 9 ]]; then
    curl "${download_args[@]}" &
    download_pid=$!
    while kill -0 "$download_pid" 2>/dev/null; do
        size=$(stat -c %s ndpi.tgz 2>/dev/null || echo 0)
        percent=$(( size * 100 / total ))
        (( percent < 100 )) || percent=99
        filled=$(( percent * width / 100 ))
        printf -v bar '%*s' "$filled" ''
        printf -v rest '%*s' "$(( width - filled ))" ''
        printf '\r  %-20s [%s%s] %3d%%' 'nDPI 6.0' "${bar// /#}" "${rest// /*}" "$percent" >&9
        sleep 0.3
    done
    result=0
    wait "$download_pid" || result=$?
    download_pid=
    printf '\r\033[K' >&9
    (( result == 0 )) || exit "$result"
else
    curl "${download_args[@]}"
fi
printf -v bar '%*s' "$width" ''
printf '  %-20s [%s] 100%%\n' 'nDPI 6.0' "${bar// /#}"
echo "Проверяю SHA-256 и распаковываю nDPI..."
sha256sum -c <<< 'c7d488379fb309696171ece0f86e4a44f1ea60cb976fd274db55aabc23b04151  ndpi.tgz'
tar -xzf ndpi.tgz --strip-components=1
echo "Подготавливаю конфигурацию сборки nDPI..."
./autogen.sh
./configure --disable-shared
echo "Компилирую nDPI в два потока..."
make -j2 -C src/lib libndpi.a
echo "Собираю исполняемый файл детектора..."
cc -O2 -Wall -Wextra -Werror -Isrc/include -Isrc/lib/third_party/include \
    "$src/engine.c" "$src/live.c" src/lib/libndpi.a -lmnl -lm -lpthread -o "$output"
