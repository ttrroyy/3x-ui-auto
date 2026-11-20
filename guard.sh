#!/bin/bash
# 3x-ui-auto guard: blocks scanner subnets (ipset) and BitTorrent traffic (string signatures).
# Scanner lists refresh by atomic ipset swap and filter NEW connections only, so live sessions survive.

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
CHAIN=XA_SCAN
SET4=xa-scan4
SET6=xa-scan6
MAXELEM=262144
LIST_EVERY=21600   # scanner lists: 6 hours
TCHAIN=XA_TORRENT
UNITS=(3x-ui-guard.service 3x-ui-guard-tick.service 3x-ui-guard-tick.timer)

# Peer-wire handshake (including its length byte), DHT messages, and UDP tracker connect requests.
TORRENT_SIGNATURES='tcp|bt-handshake|hex:|13|BitTorrent protocol
udp|dht-query|d1:ad2:id20:
udp|dht-reply|d1:rd2:id20:
udp|udp-tracker|hex:|000004172710198000000000|'

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
MIN_PREFIX = {4: 16, 6: 32}  # a hijacked list must not cut off whole providers

def parse(path, exclusions=False):
    nets = set()
    for raw in path.read_text(encoding='utf-8', errors='replace').splitlines():
        line = raw.split('#', 1)[0].strip()
        if not line:
            continue
        net = ipaddress.ip_network(line, strict=False)  # ValueError rejects HTML/garbage
        if exclusions or (net.prefixlen >= MIN_PREFIX[net.version] and net.is_global and not net.is_multicast):
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

# swap_set SET FAMILY LIST: build SET-new and swap it in atomically.
swap_set() {
    local set=$1 family=$2 list=$3 pattern='^[^:]+$'
    [[ "$family" == inet6 ]] && pattern=':'
    ipset create "$set" hash:net family "$family" maxelem "$MAXELEM" -exist 2>/dev/null || return 1
    ipset destroy "$set-new" 2>/dev/null
    {
        echo "create $set-new hash:net family $family maxelem $MAXELEM"
        grep -E "$pattern" "$list" | sed "s/^/add $set-new /"
    } | ipset restore || { ipset destroy "$set-new" 2>/dev/null; return 1; }
    ipset swap "$set-new" "$set" && ipset destroy "$set-new"
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
        swap_set "$SET4" inet "$work/merged" || rc=1
        # Kernels booted without IPv6 still get IPv4 blocking.
        [[ -d /proc/sys/net/ipv6 ]] && { swap_set "$SET6" inet6 "$work/merged" || rc=1; }
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

# ensure_rules: (re)build the chain only when it differs from the wanted state.
ensure_rules() {
    local cmd set want have port
    for cmd in iptables ip6tables; do
        set=$SET4; [[ "$cmd" == ip6tables ]] && set=$SET6
        command -v "$cmd" >/dev/null 2>&1 && ipset list -n "$set" >/dev/null 2>&1 || continue
        want="-N $CHAIN"$'\n'"-A $CHAIN -m addrtype --src-type LOCAL -j RETURN"
        for port in $(ssh_ports); do
            want+=$'\n'"-A $CHAIN -p tcp -m tcp --dport $port -j RETURN"
        done
        want+=$'\n'"-A $CHAIN -m set --match-set $set src -j DROP"
        have=$("$cmd" -w -S "$CHAIN" 2>/dev/null)
        if [[ "$have" != "$want" ]]; then
            "$cmd" -w -N "$CHAIN" 2>/dev/null || "$cmd" -w -F "$CHAIN" || return 1
            "$cmd" -w -A "$CHAIN" -m addrtype --src-type LOCAL -j RETURN || return 1
            for port in $(ssh_ports); do
                "$cmd" -w -A "$CHAIN" -p tcp --dport "$port" -j RETURN || return 1
            done
            "$cmd" -w -A "$CHAIN" -m set --match-set "$set" src -j DROP || return 1
        fi
        # Exactly one jump, inserted at the top of INPUT (UFW appends its chains below it).
        have=$("$cmd" -w -S INPUT | grep -c -- "-j $CHAIN\$")
        while (( have > 1 )); do
            "$cmd" -w -D INPUT -m conntrack --ctstate NEW -j "$CHAIN" || return 1
            have=$((have - 1))
        done
        (( have == 1 )) || "$cmd" -w -I INPUT 1 -m conntrack --ctstate NEW -j "$CHAIN" || return 1
    done
}

remove_rules() {
    local cmd set
    for cmd in iptables ip6tables; do
        command -v "$cmd" >/dev/null 2>&1 || continue
        while "$cmd" -w -C INPUT -m conntrack --ctstate NEW -j "$CHAIN" 2>/dev/null; do
            "$cmd" -w -D INPUT -m conntrack --ctstate NEW -j "$CHAIN" || return 1
        done
        if "$cmd" -w -S "$CHAIN" >/dev/null 2>&1; then
            "$cmd" -w -F "$CHAIN" && "$cmd" -w -X "$CHAIN" || return 1
        fi
    done
    for set in "$SET4" "$SET6" "$SET4-new" "$SET6-new"; do
        if ipset list -n "$set" >/dev/null 2>&1; then
            ipset destroy "$set" || return 1
        fi
    done
    return 0
}

# ─── BitTorrent signatures ───────────────────────────────────────────────────
torrent_hooks() {
    echo INPUT; echo OUTPUT; echo FORWARD
    "$1" -w -n -L DOCKER-USER >/dev/null 2>&1 && echo DOCKER-USER
}

# ensure_torrent_rules [force]: rebuild the chain when its signature set changed, keep one jump per hook.
ensure_torrent_rules() {
    local cmd protocol tag name pattern hook n rules
    tag="xa-sig-v3:$(printf '%s' "$TORRENT_SIGNATURES" | sha1sum | cut -c1-12)"
    rules=$( {
        printf '*filter\n:%s - [0:0]\n' "$TCHAIN"
        # shortcut: packet inspection only, use stream-aware classification when required.
        printf -- '-A %s -m connbytes --connbytes 4097: --connbytes-dir both --connbytes-mode bytes -j RETURN\n' "$TCHAIN"
        while IFS='|' read -r protocol name pattern; do
            [[ -n "$name" ]] || continue
            if [[ "$pattern" == hex:* ]]; then
                printf -- '-A %s -p %s -m string --algo kmp --hex-string "%s" -m comment --comment xa:%s -j DROP\n' \
                    "$TCHAIN" "$protocol" "${pattern#hex:}" "$name"
            else
                printf -- '-A %s -p %s -m string --algo kmp --string "%s" -m comment --comment xa:%s -j DROP\n' \
                    "$TCHAIN" "$protocol" "$pattern" "$name"
            fi
        done <<<"$TORRENT_SIGNATURES"
        printf -- '-A %s -m comment --comment %s -j RETURN\nCOMMIT\n' "$TCHAIN" "$tag"
    } ) || return 1
    for cmd in iptables ip6tables; do
        command -v "$cmd" >/dev/null 2>&1 || continue
        [[ "$cmd" != ip6tables || -d /proc/sys/net/ipv6 ]] || continue
        if [[ "${1:-}" == force ]] || ! "$cmd" -w -S "$TCHAIN" 2>/dev/null | grep -q -- "$tag"; then
            "${cmd}-restore" --wait --noflush <<<"$rules" || return 1
        fi
        for hook in $(torrent_hooks "$cmd"); do
            n=$("$cmd" -w -S "$hook" | grep -c -- "-j $TCHAIN\$")
            while (( n > 1 )); do "$cmd" -w -D "$hook" -j "$TCHAIN" || return 1; n=$((n - 1)); done
            (( n == 1 )) || "$cmd" -w -I "$hook" 1 -j "$TCHAIN" || return 1
        done
    done
}

remove_torrent_rules() {
    local cmd hook
    for cmd in iptables ip6tables; do
        command -v "$cmd" >/dev/null 2>&1 || continue
        for hook in INPUT OUTPUT FORWARD DOCKER-USER; do
            while "$cmd" -w -C "$hook" -j "$TCHAIN" 2>/dev/null; do "$cmd" -w -D "$hook" -j "$TCHAIN" || return 1; done
        done
        if "$cmd" -w -S "$TCHAIN" >/dev/null 2>&1; then
            "$cmd" -w -F "$TCHAIN" && "$cmd" -w -X "$TCHAIN" || return 1
        fi
    done
}

# ─── Lifecycle ───────────────────────────────────────────────────────────────
lock() { exec 8>/run/3x-ui-guard.lock && flock -w 120 8; }

older_than() {
    local stamp
    stamp=$(cat "$1" 2>/dev/null) || return 0
    [[ "$stamp" =~ ^[0-9]+$ ]] || return 0
    (( $(date +%s) - stamp >= $2 ))
}

# Boot: restore sets from cache and hook the chain, no network needed.
cmd_load() {
    lock || return 1
    local rc=0
    refresh_lists && ensure_rules || rc=1
    ensure_torrent_rules || rc=1
    return "$rc"
}

# Every 5 minutes: keep rules in place and refresh scanner lists when due.
cmd_tick() {
    lock || return 1
    local rc=0
    if older_than "$STATE/updated" "$LIST_EVERY"; then
        refresh_lists download || rc=1
    elif ! ipset list -n "$SET4" >/dev/null 2>&1 ||
        { [[ -d /proc/sys/net/ipv6 ]] && ! ipset list -n "$SET6" >/dev/null 2>&1; }; then
        refresh_lists || rc=1
    fi
    ensure_rules || rc=1
    ensure_torrent_rules || rc=1
    return "$rc"
}

install_units() {
    cat >/etc/systemd/system/3x-ui-guard.service <<EOF
[Unit]
Description=3x-ui-auto scanner guard
After=network-pre.target ufw.service netfilter-persistent.service docker.service
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
    if ! { apt-get update -q && apt-get install -y -q ca-certificates curl ipset iptables python3 util-linux; } >>"$LOG" 2>&1; then
        msg_err "Не удалось установить зависимости. Журнал: $LOG"; return 1
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
    if ! refresh_lists download >>"$LOG" 2>&1 || ! ensure_rules >>"$LOG" 2>&1; then
        msg_err "Не удалось применить защиту от сканеров. Журнал: $LOG"; return 1
    fi
    read -r -a counts <"$STATE/counts"
    msg_ok "Защита от сканеров включена: IPv4 подсетей ${counts[0]}, IPv6 подсетей ${counts[1]:-0}."

    msg_inf "Включаю защиту от торрентов..."
    if ! ensure_torrent_rules force >>"$LOG" 2>&1; then
        msg_err "Не удалось установить защиту от торрентов. Журнал: $LOG"; return 1
    fi
    msg_ok "Защита от торрентов включена: $(grep -c '|' <<<"$TORRENT_SIGNATURES") сигнатуры BitTorrent, DHT и UDP-трекеров."
    install_units || { msg_err "Не удалось включить автообновление защиты."; return 1; }
    msg_ok "Внешние списки подсетей проверяются каждые 6 часов. BitTorrent-правила встроены в guard.sh."
}

stop_units() {
    local unit
    for unit in "${UNITS[2]}" "${UNITS[1]}" "${UNITS[0]}"; do
        if [[ -f "/etc/systemd/system/$unit" ]]; then
            systemctl stop "$unit" || return 1
            if systemctl is-enabled --quiet "$unit"; then
                systemctl disable "$unit" >/dev/null || return 1
            fi
        fi
    done
}

clear_runtime() {
    remove_rules || { msg_err "Не удалось удалить правила защиты от сканеров."; return 1; }
    remove_torrent_rules || { msg_err "Не удалось полностью удалить защиту от торрентов."; return 1; }
    systemctl reset-failed "${UNITS[@]}" >/dev/null 2>&1 || true
    rm -f "${UNITS[@]/#//etc/systemd/system/}" && systemctl daemon-reload && rm -rf -- "$STATE"
}

cmd_uninstall() {
    stop_units && lock && clear_runtime || return 1
    rm -f -- "$SOURCES" "$ALLOW" "$SELF" "$SELF.new" "$LOG" || return 1
    rmdir "$CONF_DIR" "$LIB" /var/lib/3x-ui-auto 2>/dev/null
    msg_ok "Защита от сканеров и торрентов удалена. Остальные правила firewall не изменены."
}

cmd_status() {
    local counts=() when signatures
    [[ -f "$STATE/counts" ]] && read -r -a counts <"$STATE/counts"
    when=$(cat "$STATE/updated" 2>/dev/null)
    if iptables -w -C INPUT -m conntrack --ctstate NEW -j "$CHAIN" 2>/dev/null &&
        iptables -w -C "$CHAIN" -m set --match-set "$SET4" src -j DROP 2>/dev/null; then
        msg_ok "Сканеры: активна, IPv4 ${counts[0]:-0}, IPv6 ${counts[1]:-0}, списки от ${when:+$(date -d "@$when" '+%F %T')}"
    else
        msg_err "Сканеры: не активна"
    fi
    signatures=$(iptables -w -S "$TCHAIN" 2>/dev/null | grep -c 'xa:.*-j DROP$')
    if [[ "$signatures" -eq $(grep -c '^' <<<"$TORRENT_SIGNATURES") ]] &&
        iptables -w -C INPUT -j "$TCHAIN" 2>/dev/null; then
        msg_ok "Торренты: активна ($signatures сигнатур)"
    else
        msg_err "Торренты: не активна"
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
        load)       cmd_load ;;
        tick)       cmd_tick ;;
        *)          usage; return 1 ;;
    esac
}

[[ "${GUARD_LIB_ONLY:-}" == 1 ]] || main "$@"
