#!/bin/bash
# Scanner subnet firewall using a dedicated nftables table.

export DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=l NEEDRESTART_SUSPEND=1 LC_ALL=C

msg_ok()  { echo -e "\e[1;42m $1 \e[0m"; }
msg_err() { echo -e "\e[1;41m $1 \e[0m"; }
msg_inf() { echo -e "\e[1;34m$1\e[0m"; }

REPO_RAW=https://raw.githubusercontent.com/ttrroyy/3x-ui-auto/main
LIB=/usr/local/lib/3x-ui-auto
SELF=$LIB/guard.sh
CONF_DIR=/etc/3x-ui-auto
SOURCES=$CONF_DIR/guard-sources.list
ALLOW=$CONF_DIR/guard-allow.cidr
STATE=/var/lib/3x-ui-auto/guard
LOG=/var/log/3x-ui-guard.log
TABLE=xa_guard
LIST_EVERY=21600
UNITS=(3x-ui-guard.service 3x-ui-guard-tick.service 3x-ui-guard-tick.timer)

DEFAULT_SOURCES=(
    https://raw.githubusercontent.com/shadow-netlab/traffic-guard-lists/refs/heads/main/public/government_networks.list
    https://raw.githubusercontent.com/shadow-netlab/traffic-guard-lists/refs/heads/main/public/antiscanner.list
    https://raw.githubusercontent.com/shadow-netlab/traffic-guard-lists/refs/heads/main/public/skipa.list
    https://raw.githubusercontent.com/C24Be/AS_Network_List/main/blacklists/blacklist.txt
    https://raw.githubusercontent.com/tread-lightly/CyberOK_Skipa_ips/main/lists/skipa_cidr.txt
    https://cdn.jsdelivr.net/gh/notacircle/greatlists@main/gn.lst
    https://cdn.jsdelivr.net/gh/notacircle/greatlists@main/sn.lst
)

# ─── Scanner lists ───────────────────────────────────────────────────────────
source_urls() {
    local url
    if [[ -f "$SOURCES" ]]; then
        while IFS= read -r url || [[ -n "$url" ]]; do
            url=${url%%#*}; url=${url//[[:space:]]/}
            [[ -n "$url" ]] && echo "$url"
        done <"$SOURCES"
    else
        printf '%s\n' "${DEFAULT_SOURCES[@]}"
    fi
}

url_key() { printf '%s' "$1" | sha1sum | cut -c1-16; }

# merge_lists WORK STATE OUT KEY...: accept fresh downloads from WORK into STATE (per source,
# keeping the last good copy on garbage or a >50% shrink), then write the union of STATE to OUT.
merge_lists() {
    python3 -I - "$ALLOW" "$@" <<'PY'
import ipaddress, sys
from pathlib import Path

allow, work, state, out = map(Path, sys.argv[1:5])
keys = sys.argv[5:]

def parse(path, exclusions=False):
    nets = set()
    for raw in path.read_text(encoding='utf-8-sig').splitlines():
        line = raw.split('#', 1)[0].strip()
        if not line:
            continue
        net = ipaddress.ip_network(line, strict=False)  # ValueError rejects HTML/garbage
        if not exclusions and (net.prefixlen == 0 or net.version == 6 and net.network_address.ipv4_mapped):
            raise ValueError('invalid scanner prefix')
        if exclusions or (net.is_global and not net.is_multicast):
            nets.add(net)
    return nets

for key in keys:
    fresh, kept = work / key, state / key
    if not fresh.exists():
        continue
    try:
        new = parse(fresh)
    except ValueError:
        print(f'{key}: invalid list, keeping previous copy', file=sys.stderr)
        continue
    old = len(parse(kept)) if kept.exists() else 0
    if not new or (old and len(new) < old / 2):
        print(f'{key}: {old} -> {len(new)} networks, keeping previous copy', file=sys.stderr)
        continue
    staged = kept.with_suffix('.new')
    staged.write_text(''.join(f'{n}\n' for n in sorted(new, key=lambda n: (n.version, n))))
    staged.replace(kept)
    (work / '.accepted').touch()

nets = {4: set(), 6: set()}
for key in keys:
    if (state / key).exists():
        for n in parse(state / key):
            nets[n.version].add(n)
if not any(nets.values()):
    raise SystemExit('no usable scanner networks in downloads or cache')
if allow.exists():
    for exclusion in parse(allow, exclusions=True):
        version = exclusion.version
        nets[version] = {remaining for net in nets[version] for remaining in (
            net.address_exclude(exclusion) if exclusion.subnet_of(net) else
            () if net.subnet_of(exclusion) else (net,)
        )}
merged = {v: list(ipaddress.collapse_addresses(n)) for v, n in nets.items()}
out.write_text(''.join(f'{n}\n' for v in (4, 6) for n in merged[v]))
print(len(merged[4]), len(merged[6]))
PY
}

# refresh_lists [download]: rebuild the sets from cache, downloading first when asked.
refresh_lists() {
    local work url key keys=() counts rc=0
    mkdir -p "$STATE/src" || return 1
    work=$(mktemp -d) || return 1
    while IFS= read -r url; do
        key=$(url_key "$url"); keys+=("$key")
        [[ "${1:-}" == download ]] || continue
        curl -fsSL --proto '=https' --proto-redir '=https' --connect-timeout 10 --max-time 60 --max-filesize 16777216 --retry 2 \
            "$url" -o "$work/$key" || { rm -f "$work/$key"; echo "download failed, keeping previous copy: $url" >&2; }
    done < <(source_urls)
    if counts=$(merge_lists "$work" "$STATE/src" "$work/merged" "${keys[@]}"); then
        apply_rules "$work/merged" || rc=1
        (( rc )) || echo "$counts" >"$STATE/counts"
    else
        rc=1
    fi
    [[ -f "$work/.accepted" && $rc -eq 0 ]] && date +%s >"$STATE/updated"
    rm -rf "$work"
    return $rc
}

ssh_ports() {
    local ports
    ports=$(sshd -T 2>/dev/null | awk '$1=="port"{print $2}' | sort -un)
    echo "${ports:-22}"
}

# Replace both address sets and the rules in a single transaction.
apply_rules() {
    local list=$1 ip4 ip6 ssh elements4='' elements6=''
    ip4=$(awk '!/:/' "$list" | paste -sd, -)
    ip6=$(awk '/:/' "$list" | paste -sd, -)
    ssh=$(ssh_ports | paste -sd, -)
    [[ -z "$ip4" ]] || printf -v elements4 'add element inet %s scanners4 { %s }' "$TABLE" "$ip4"
    [[ -z "$ip6" ]] || printf -v elements6 'add element inet %s scanners6 { %s }' "$TABLE" "$ip6"
    nft -f - <<EOF
add table inet $TABLE
delete table inet $TABLE
table inet $TABLE {
    set scanners4 { type ipv4_addr; flags interval; }
    set scanners6 { type ipv6_addr; flags interval; }
    chain input {
        type filter hook input priority -10; policy accept;
        ct state new tcp dport { $ssh } return
        ct state new fib saddr type != local ip saddr @scanners4 counter drop
        ct state new fib saddr type != local ip6 saddr @scanners6 counter drop
    }
}
$elements4
$elements6
EOF
}

legacy_guard() {
    [[ -f "$SELF" ]] && grep -q '^SET4=xa-scan4$' "$SELF"
}

migrate_legacy_guard() (
    local tmp file rc=0
    tmp=$(mktemp -d) || return 1
    trap 'rm -rf -- "$tmp"' EXIT
    for file in "$SOURCES" "$ALLOW"; do
        if [[ -f "$file" ]]; then cp -p -- "$file" "$tmp/" || return 1; fi
    done
    bash "$SELF" -uninstall y || rc=1
    for file in "$tmp"/*; do
        [[ -f "$file" ]] || continue
        install -d -m 0755 "$CONF_DIR" && mv -f -- "$file" "$CONF_DIR/" || return 1
    done
    return "$rc"
)

# ─── Lifecycle ───────────────────────────────────────────────────────────────
lock() { exec 8>/run/3x-ui-guard.lock && flock -w 120 8; }

older_than() {
    local stamp
    stamp=$(cat "$1" 2>/dev/null) || return 0
    [[ "$stamp" =~ ^[0-9]+$ ]] || return 0
    (( $(date +%s) - stamp >= $2 ))
}

cmd_load() {
    lock && refresh_lists
}

cmd_tick() {
    lock || return 1
    if older_than "$STATE/updated" "$LIST_EVERY"; then
        refresh_lists download
    elif ! nft list table inet "$TABLE" >/dev/null 2>&1; then
        refresh_lists
    fi
}

install_units() {
    cat >/etc/systemd/system/3x-ui-guard.service <<EOF
[Unit]
Description=3x-ui-auto scanner guard
After=nftables.service
Before=network-pre.target
Wants=network-pre.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=$SELF load

[Install]
WantedBy=multi-user.target
EOF
    cat >/etc/systemd/system/3x-ui-guard-tick.service <<EOF
[Unit]
Description=3x-ui-auto guard check and list update
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=$SELF tick
EOF
    cat >/etc/systemd/system/3x-ui-guard-tick.timer <<'EOF'
[Unit]
Description=3x-ui-auto guard check every 5 minutes

[Timer]
OnBootSec=2min
OnUnitActiveSec=5min
RandomizedDelaySec=30

[Install]
WantedBy=timers.target
EOF
    systemctl daemon-reload && systemctl enable 3x-ui-guard.service >/dev/null 2>&1 &&
        systemctl enable --now 3x-ui-guard-tick.timer >/dev/null 2>&1
}

install_self() {
    local src=$0
    install -d -m 0755 "$LIB" "$CONF_DIR" && install -d -m 0700 "$STATE" || return 1
    [[ "$(readlink -f "$src")" == "$SELF" ]] && return 0
    if [[ -f "$src" ]] && bash -n "$src"; then
        install -m 0755 "$src" "$SELF"
    else
        curl -fsSL --proto '=https' "$REPO_RAW/guard.sh" -o "$SELF.new" && bash -n "$SELF.new" &&
            chmod 755 "$SELF.new" && mv -f "$SELF.new" "$SELF"
    fi
}

cmd_install() {
    local counts
    msg_inf "Устанавливаю зависимости защиты..."
    if ! { apt-get update -q && apt-get -o DPkg::Lock::Timeout=300 install -y -q ca-certificates curl nftables python3 util-linux; } >>"$LOG" 2>&1; then
        msg_err "Не удалось установить зависимости. Журнал: $LOG"; return 1
    fi
    if legacy_guard; then
        migrate_legacy_guard || return 1
    fi
    if [[ -e "$STATE" || -e "$SELF" ]]; then
        msg_inf 'Удаляю правила, кеш и службы предыдущей установки защиты...'
        stop_units || return 1
    fi
    lock || return 1
    if [[ -e "$STATE" || -e "$SELF" ]]; then
        clear_runtime || return 1
    fi
    install_self || { msg_err "Не удалось установить скрипт защиты в $SELF"; return 1; }

    msg_inf "Загружаю списки подсетей сканеров..."
    if ! refresh_lists download >>"$LOG" 2>&1; then
        msg_err "Не удалось применить защиту от сканеров. Журнал: $LOG"; return 1
    fi
    read -r -a counts <"$STATE/counts"
    msg_ok "Защита от сканеров включена: IPv4 подсетей ${counts[0]}, IPv6 подсетей ${counts[1]:-0}."

    install_units || { msg_err "Не удалось включить автообновление защиты."; return 1; }
    msg_ok "Внешние списки подсетей проверяются каждые 6 часов."
}

stop_units() {
    local unit
    for unit in "${UNITS[2]}" "${UNITS[1]}" "${UNITS[0]}"; do
        if [[ -f "/etc/systemd/system/$unit" ]]; then
            systemctl stop "$unit" || return 1
            if [[ "$(systemctl is-enabled "$unit" 2>/dev/null)" == enabled ]]; then
                systemctl disable "$unit" >/dev/null || return 1
            fi
        fi
    done
}

clear_runtime() {
    if command -v nft >/dev/null && nft list table inet "$TABLE" >/dev/null 2>&1; then
        nft delete table inet "$TABLE" || return 1
    fi
    systemctl reset-failed "${UNITS[@]}" >/dev/null 2>&1 || true
    rm -f "${UNITS[@]/#//etc/systemd/system/}" && systemctl daemon-reload && rm -rf -- "$STATE"
}

cmd_uninstall() {
    if legacy_guard; then bash "$SELF" -uninstall y; return $?; fi
    stop_units && lock && clear_runtime || return 1
    rm -f -- "$SOURCES" "$ALLOW" "$SELF" "$SELF.new" "$LOG" || return 1
    rmdir "$CONF_DIR" "$LIB" /var/lib/3x-ui-auto 2>/dev/null
    msg_ok "Защита от сканеров удалена."
}

cmd_status() {
    local counts=() when
    [[ -f "$STATE/counts" ]] && read -r -a counts <"$STATE/counts"
    when=$(cat "$STATE/updated" 2>/dev/null)
    if nft list table inet "$TABLE" >/dev/null 2>&1; then
        msg_ok "Защита активна: IPv4 ${counts[0]:-0}, IPv6 ${counts[1]:-0}, последнее обновление ${when:+$(date -d "@$when" '+%F %T')}."
    else
        msg_err "Защита nftables выключена."
    fi
    systemctl is-active --quiet 3x-ui-guard-tick.timer && msg_inf "Автообновление: включено" || msg_err "Автообновление: выключено"
}

usage() {
    echo "Использование: bash $0 -install y | -uninstall y | -status y"
}

main() {
    [[ $EUID -eq 0 ]] || { echo "Run as root: sudo bash $0"; exit 1; }
    case "${1:-}" in
        -install)   cmd_install ;;
        -uninstall) cmd_uninstall ;;
        -status)    cmd_status ;;
        split)
            lock || return 1
            nft list chain inet "$TABLE" torrent >/dev/null 2>&1 || return 0
            install_self && { refresh_lists || refresh_lists download; }
            ;;
        load)       cmd_load ;;
        tick)       cmd_tick ;;
        *)          usage; return 1 ;;
    esac
}

[[ "${GUARD_LIB_ONLY:-}" == 1 ]] || main "$@"
