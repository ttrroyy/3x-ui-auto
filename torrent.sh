#!/bin/bash
# Independent BitTorrent detector and nftables rules.

export DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=l NEEDRESTART_SUSPEND=1 LC_ALL=C

LIB=/usr/local/lib/3x-ui-auto
SELF=$LIB/torrent.sh
DPI=$LIB/vh-dpid
STATS=/run/3x-ui-guard-dpi/stats.json
LOG=/var/log/3x-ui-torrent.log
UNIT=3x-ui-guard-dpi.service
TABLE=xa_torrent

apply_torrent_rules() {
    nft -f - <<EOF
add table inet $TABLE
delete table inet $TABLE
table inet $TABLE {
    chain input {
        type filter hook input priority -9; policy accept;
        jump torrent
    }
    chain output {
        type filter hook output priority -9; policy accept;
        jump torrent
    }
    chain forward {
        type filter hook forward priority -9; policy accept;
        jump torrent
    }
    chain torrent {
        # NFLOG group, capture size and conntrack bit match the local vh-dpid sources.
        ct mark & 0x00100000 != 0 counter drop comment "dpi-mark"
        meta l4proto { tcp, udp } ct packets 1-12 limit rate 10000/second burst 10000 packets log group 4711 snaplen 512 queue-threshold 1
        meta l4proto tcp @ih,0,64 0x13426974546f7272 @ih,64,96 0x656e742070726f746f636f6c counter drop comment "bt-handshake"
        meta l4proto udp @ih,0,88 0x64313a6164323a69643230 @ih,88,8 0x3a counter drop comment "dht-query"
        meta l4proto udp @ih,0,88 0x64313a7264323a69643230 @ih,88,8 0x3a counter drop comment "dht-reply"
        meta l4proto udp @ih,0,96 0x000004172710198000000000 counter drop comment "udp-tracker"
    }
}
EOF
}

# Migrate the previous combined guard before managing BitTorrent separately.
split_old_guard() (
    local tmp action=split
    if grep -qs '^SET4=xa-scan4$' "$LIB/guard.sh"; then
        action=-install
    elif ! nft list chain inet xa_guard torrent >/dev/null 2>&1; then
        exit 0
    fi
    tmp=$(mktemp) || exit 1
    trap 'rm -f -- "$tmp"' EXIT
    curl -fsSL --connect-timeout 15 --max-time 120 --proto '=https' --proto-redir '=https' \
        https://raw.githubusercontent.com/ttrroyy/3x-ui-auto/main/guard.sh -o "$tmp" &&
        bash "$tmp" "$action" y
)

install_unit() {
    cat >"/etc/systemd/system/$UNIT" <<EOF
[Unit]
Description=3x-ui-auto BitTorrent detector
After=nftables.service

[Service]
Type=exec
DynamicUser=yes
AmbientCapabilities=CAP_NET_ADMIN
CapabilityBoundingSet=CAP_NET_ADMIN
RestrictAddressFamilies=AF_NETLINK
RuntimeDirectory=3x-ui-guard-dpi
RuntimeDirectoryMode=0750
ExecStartPre=+$SELF load
ExecStart=$DPI --mode enforce --stats $STATS
Restart=always
RestartSec=3s

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload && systemctl enable --now "$UNIT" >/dev/null
}

build_dpi() {
    local tmp=$1
    curl -fsSL --retry 2 --connect-timeout 15 --max-time 120 --proto '=https' --proto-redir '=https' \
        https://codeload.github.com/ttrroyy/3x-ui-auto/tar.gz/refs/heads/main -o "$tmp/repo.tgz" &&
        tar -xzf "$tmp/repo.tgz" -C "$tmp" --strip-components=2 3x-ui-auto-main/assets/vh-dpid &&
        bash "$tmp/vh-dpid/build.sh" "$tmp/vh-dpid.bin"
}

cmd_install() (
    local tmp attempt
    echo "Устанавливаю зависимости и собираю детектор BitTorrent..."
    if ! { apt-get update -q && apt-get install -y -q --no-install-recommends ca-certificates curl nftables util-linux \
        build-essential autoconf automake libtool pkg-config libmnl-dev libpcap-dev; } >>"$LOG" 2>&1; then
        echo "Не удалось установить зависимости. Журнал $LOG" >&2
        return 1
    fi
    tmp=$(mktemp -d) || return 1
    trap 'rm -rf -- "$tmp"' EXIT
    exec 8>/run/3x-ui-torrent.lock && flock -w 600 8 || return 1
    if ! build_dpi "$tmp" >>"$LOG" 2>&1; then
        echo "Не удалось собрать детектор. Журнал $LOG" >&2
        return 1
    fi
    split_old_guard || return 1
    if [[ -f "/etc/systemd/system/$UNIT" ]]; then systemctl stop "$UNIT" || return 1; fi
    install -d -m 0755 "$LIB" || return 1
    if [[ "$(readlink -f "$0")" != "$SELF" ]]; then install -m 0755 "$0" "$SELF" || return 1; fi
    install -m 0755 "$tmp/vh-dpid.bin" "$DPI" && install_unit || return 1
    for attempt in {1..10}; do
        [[ -s "$STATS" ]] && break
        sleep 1
    done
    cmd_status
)

cmd_status() {
    if ! nft list table inet "$TABLE" >/dev/null 2>&1; then
        echo "Фильтр BitTorrent выключен."
        return 1
    fi
    if ! systemctl is-active --quiet "$UNIT" || [[ ! -s "$STATS" ]]; then
        echo "Работают сигнатуры nftables. Детектор выключен." >&2
        return 1
    fi
    echo "Фильтр BitTorrent включён."
}

cmd_uninstall() (
    exec 8>/run/3x-ui-torrent.lock && flock -w 600 8 || return 1
    split_old_guard || return 1
    if [[ -f "/etc/systemd/system/$UNIT" ]]; then
        systemctl disable --now "$UNIT" >/dev/null || return 1
        rm -f -- "/etc/systemd/system/$UNIT" && systemctl daemon-reload || return 1
    fi
    if nft list table inet "$TABLE" >/dev/null 2>&1; then
        nft delete table inet "$TABLE" || return 1
    fi
    rm -f -- "$SELF" "$DPI" "$LOG" || return 1
    rmdir "$LIB" 2>/dev/null || true
    echo "Фильтр BitTorrent удалён."
)

main() {
    [[ $EUID -eq 0 ]] || { echo "Run as root: sudo bash $0"; return 1; }
    case "${1:-}" in
        -install) cmd_install ;;
        -status) cmd_status ;;
        -uninstall) cmd_uninstall ;;
        load) apply_torrent_rules ;;
        *) echo "Использование: bash $0 -install | -status | -uninstall"; return 2 ;;
    esac
}

[[ "${TORRENT_LIB_ONLY:-}" == 1 ]] || main "$@"
