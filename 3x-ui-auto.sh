#!/bin/bash
# 3x-ui-auto: 3x-ui with nginx SNI routing, REALITY + XHTTP on 443, optional Hysteria 2,
# AdGuard Home DoH, cover site, BBR/FQ, fail2ban, certbot renewal and the scanner/torrent guard.

export DEBIAN_FRONTEND=noninteractive
export NEEDRESTART_MODE=l
export NEEDRESTART_SUSPEND=1
[[ $EUID -ne 0 ]] && { echo "Run as root: sudo bash $0"; exit 1; }

# ─── Output helpers ──────────────────────────────────────────────────────────
msg_ok()  { echo -e "\e[1;42m $1 \e[0m"; }
msg_err() { echo -e "\e[1;41m $1 \e[0m"; }
msg_inf() { echo -e "\e[1;34m$1\e[0m"; }

echo
msg_inf '  ____        _   _ ___       _         _        '
msg_inf ' |___ /_  __ | | | |_ _|     / \  _   _| |_ ___  '
msg_inf '   |_ \ \/ / | | | || |_____/ _ \| | | | __/ _ \ '
msg_inf '  ___) >  <  | |_| || |_____/ ___ \ |_| | || (_) |'
msg_inf ' |____/_/\_\  \___/|___|   /_/   \_\__,_|\__\___/ '
echo
_os_id=$(grep -oP '(?<=^ID=).+' /etc/os-release 2>/dev/null | tr -d '"')
_os_ver=$(grep -oP '(?<=^VERSION_ID=).+' /etc/os-release 2>/dev/null | tr -d '"')
echo "The OS release is: ${_os_id^} ${_os_ver}"
echo

# ─── Pre-flight checks ───────────────────────────────────────────────────────
check_os() {
    [[ -r /etc/os-release ]] || { msg_err "Unable to read /etc/os-release"; exit 1; }
    # shellcheck disable=SC1091
    . /etc/os-release
    case "${ID:-}:${VERSION_ID:-}" in
        ubuntu:24.04|ubuntu:26.04|debian:12|debian:13) return 0 ;;
    esac
    msg_err "Unsupported OS: ${ID:-} ${VERSION_ID:-}"
    echo -e "\nThis script supports:\n  Ubuntu 24.04 / 26.04\n  Debian 12 / 13"
    exit 1
}

check_cpu() {
    if grep -m1 'model name' /proc/cpuinfo 2>/dev/null | grep -qi 'QEMU'; then
        msg_err "QEMU virtual CPU detected!"
        echo -e "\nYour VPS is running with an emulated QEMU processor."
        echo -e "Please contact your hosting provider and ask them to switch the CPU type"
        echo -e "to \e[1;33mhost-passthrough\e[0m (expose real CPU model to the VM)."
        echo -e "\nThis is required for correct operation of the Xray core."
        exit 1
    fi
}

check_os
check_cpu

# ─── Constants ───────────────────────────────────────────────────────────────
XUIDB="/etc/x-ui/x-ui.db"
GITHUB_RAW="https://raw.githubusercontent.com/ttrroyy/3x-ui-auto/main"
PANEL_REPO="MHSanaei/3x-ui"
LIB_DIR="/usr/local/lib/3x-ui-auto"
COVER_GENERATOR_SHA256="76d4b7b1b9858b626888200b7d546518a5399245e073a153a217b0fec6f674b0"
COVER_GENERATOR_DIR="${LIB_DIR}/cover-generator"
STATE_DIR="/var/lib/3x-ui-auto/install"
COVER_STATE="${STATE_DIR}/cover-generator.json"
INSTALL_IN_PROGRESS_FILE="${STATE_DIR}/install-in-progress"
GUARD_SELF="${LIB_DIR}/guard.sh"
ADGUARD_INFO=/root/.3x-ui-auto-adguard-info

# ─── Arguments ───────────────────────────────────────────────────────────────
INSTALL=""; UNINSTALL=""; ADGUARD_ONLY=""; ADGUARD_UNINSTALL=""; PANEL_VERSION=""
domain=""; DEPLOY_AGH=""; DNS_CHOICE=""; DEPLOY_HY2=""; DEPLOY_GUARD=""
CUSTOM_DOH_URL=""; CUSTOM_DOH_HOST=""; CUSTOM_DOH_IP=""

usage() {
    cat <<'EOF'
Usage:
  bash 3x-ui-auto.sh -install y [-version v3.11.0]
  bash 3x-ui-auto.sh -uninstall y
  bash 3x-ui-auto.sh -adguard y
  bash 3x-ui-auto.sh -adguard-uninstall y
EOF
}

require_arg_value() {
    [[ $# -ge 2 && -n "${2:-}" && "${2:-}" != -* ]] || { msg_err "Option ${1} requires a value."; usage; exit 2; }
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        -install)    require_arg_value "$@"; INSTALL="$2";         shift 2 ;;
        -uninstall)  require_arg_value "$@"; UNINSTALL="$2";       shift 2 ;;
        -adguard)    require_arg_value "$@"; ADGUARD_ONLY="$2";    shift 2 ;;
        -adguard-uninstall) require_arg_value "$@"; ADGUARD_UNINSTALL="$2"; shift 2 ;;
        -version)    require_arg_value "$@"; PANEL_VERSION="$2";   shift 2 ;;
        -h|--help)   usage; exit 0 ;;
        *)           msg_err "Unknown option: $1"; usage; exit 2 ;;
    esac
done

_action_count=0
for _v in "$INSTALL" "$UNINSTALL" "$ADGUARD_ONLY" "$ADGUARD_UNINSTALL"; do
    [[ -z "$_v" || "$_v" == y ]] || { msg_err "Action options accept only the value: y"; usage; exit 2; }
    [[ "$_v" == y ]] && _action_count=$((_action_count + 1))
done
(( _action_count == 1 )) || { msg_err "Specify exactly one action."; usage; exit 2; }

# ─── Generators ──────────────────────────────────────────────────────────────
get_port() { echo $(( ((RANDOM<<15)|RANDOM) % 49152 + 10000 )); }

gen_random_string() {
    head -c 4096 /dev/urandom | tr -dc 'a-zA-Z0-9' | head -c "$1"
    echo
}

# Matches the panel's host group_id format (16 lowercase alphanumerics)
gen_group_id() {
    head -c 4096 /dev/urandom | tr -dc 'a-z0-9' | head -c 16
    echo
}

port_busy() { ss -Hltnu "sport = :$1" 2>/dev/null | grep -q .; }

make_port() {
    local port
    while true; do
        port=$(get_port)
        port_busy "$port" || { echo "$port"; return; }
    done
}

sub_port=$(make_port)
panel_port=$(make_port)
clash_port=$(make_port)
while [[ "$clash_port" == "$sub_port" || "$clash_port" == "$panel_port" ]]; do clash_port=$(make_port); done
while [[ "$sub_port" == "$panel_port" ]]; do sub_port=$(make_port); done
hy2_port=""

sub_path=$(gen_random_string 10)
json_path=$(gen_random_string 10)
panel_path=$(gen_random_string 10)
xhttp_path=$(gen_random_string 10)
config_username=$(gen_random_string 10)
config_password=$(gen_random_string 10)

# ─── Terminal input ──────────────────────────────────────────────────────────
tty_read() {
    # Read one answer from the terminal even when the script itself came through a pipe.
    if [[ -t 0 && -r /dev/tty ]]; then read -r REPLY </dev/tty; else read -r REPLY; fi
}

# ask_choice VAR "question" "option 1" "option 2" ...: empty or invalid input repeats the question.
ask_choice() {
    # Locals carry a __ prefix so printf -v reaches a caller variable of any name.
    local __var=$1 __question=$2 __count __i __item
    shift 2
    __count=$#
    while true; do
        echo
        msg_inf '────────────────────────────────────────────────────────────────────────────────'
        msg_inf "$__question"
        __i=1
        for __item in "$@"; do echo "  $__i) $__item"; __i=$((__i + 1)); done
        msg_inf '────────────────────────────────────────────────────────────────────────────────'
        echo -en "Выбор [1-${__count}]: "
        tty_read || return 1
        __item=${REPLY//[[:space:]]/}
        if [[ "$__item" =~ ^[0-9]+$ ]] && (( __item >= 1 && __item <= __count )); then
            printf -v "$__var" '%s' "$__item"
            echo
            return 0
        fi
    done
}

# ─── Server IP and domain ────────────────────────────────────────────────────
IP4_REGEX="^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$"
IP6_REGEX="([a-f0-9:]+:+)+[a-f0-9]+"

get_server_ip() {
    local pub
    IP4=$(timeout 3 ip -4 route get 8.8.8.8 2>/dev/null | grep -Po -- 'src \K\S*' | head -1)
    pub=$(curl -4 -fsS --connect-timeout 3 --max-time 8 ipv4.icanhazip.com 2>/dev/null | tr -d '[:space:]')
    [[ $pub =~ $IP4_REGEX ]] && IP4="$pub"
    IP6=""
    if timeout 1 ip -6 route show default 2>/dev/null | grep -q .; then
        IP6=$(timeout 2 ip -6 route get 2620:fe::fe 2>/dev/null | grep -Po -- 'src \K\S*' | head -1)
        [[ $IP6 =~ $IP6_REGEX ]] || IP6=$(curl -6 -fsS --connect-timeout 2 --max-time 5 ipv6.icanhazip.com 2>/dev/null | tr -d '[:space:]')
    fi
}

domain_a_ok() {
    local d="$1"
    [[ -n "$d" && -n "${IP4:-}" ]] || return 1
    if command -v python3 >/dev/null 2>&1; then
        timeout 12 python3 - "$d" "$IP4" <<'PY'
import random, socket, struct, sys
name = sys.argv[1].strip().rstrip(".").lower()
want = sys.argv[2].strip()
def encode_name(n):
    out = bytearray()
    for label in n.split("."):
        lab = label.encode("ascii")
        if not (1 <= len(lab) <= 63):
            raise ValueError("bad label")
        out.append(len(lab)); out.extend(lab)
    out.append(0)
    return bytes(out)
def skip_name(data, off):
    while True:
        if off >= len(data):
            raise ValueError("trunc")
        l = data[off]
        if l == 0:
            return off + 1
        if l & 0xC0 == 0xC0:
            return off + 2
        if l & 0xC0:
            raise ValueError("edns")
        off += 1 + l
def udp_lookup(server, timeout=1.2):
    tid = random.randint(0, 65535)
    pkt = struct.pack(">HHHHHH", tid, 0x0100, 1, 0, 0, 0) + encode_name(name) + struct.pack(">HH", 1, 1)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(pkt, (server, 53))
        data, _ = sock.recvfrom(4096)
    finally:
        sock.close()
    if len(data) < 12:
        raise ValueError("short")
    rtid, flags, qd, an, ns, ar = struct.unpack(">HHHHHH", data[:12])
    if rtid != tid:
        raise ValueError("tid")
    if flags & 0xF not in (0, 3):
        raise ValueError("rcode")
    off = 12
    for _ in range(qd):
        off = skip_name(data, off) + 4
    ips = []
    for _ in range(an):
        off = skip_name(data, off)
        typ, clas, ttl, rdlen = struct.unpack(">HHIH", data[off:off+10])
        off += 10
        rdata = data[off:off+rdlen]; off += rdlen
        if typ == 1 and rdlen == 4:
            ips.append(socket.inet_ntoa(rdata))
    return ips
answered = False
ips = set()
for srv in ("1.1.1.1", "8.8.8.8"):
    try:
        ips.update(udp_lookup(srv))
        answered = True
        if want in ips:
            raise SystemExit(0)
    except SystemExit:
        raise
    except Exception:
        pass
if answered:
    raise SystemExit(1)
try:
    ips.update(info[4][0] for info in socket.getaddrinfo(name, None, socket.AF_INET, socket.SOCK_STREAM))
except Exception:
    pass
if want in ips:
    raise SystemExit(0)
import json, urllib.request
for url in ("https://cloudflare-dns.com/dns-query?name=%s&type=A" % name, "https://dns.google/resolve?name=%s&type=A" % name):
    try:
        req = urllib.request.Request(url, headers={"Accept": "application/dns-json"})
        with urllib.request.urlopen(req, timeout=2.5) as resp:
            data = json.loads(resp.read().decode())
        for ans in data.get("Answer") or []:
            if ans.get("type") == 1 and ans.get("data"):
                ips.add(str(ans["data"]).strip())
        if want in ips:
            raise SystemExit(0)
        if int(data.get("Status", 0)) in (0, 3):
            raise SystemExit(1)
    except SystemExit:
        raise
    except Exception:
        pass
raise SystemExit(0 if want in ips else 1)
PY
        return $?
    fi
    [[ "$(timeout 3 getent ahostsv4 "$d" 2>/dev/null | awk 'NR==1{print $1}')" == "$IP4" ]]
}

choose_domain() {
    local d
    get_server_ip
    [[ $IP4 =~ $IP4_REGEX ]] || { msg_err "Не удалось определить IPv4 сервера."; return 1; }
    while true; do
        echo
        msg_inf '────────────────────────────────────────────────────────────────────────────────'
        msg_inf "Домен для панели, подписок, REALITY, XHTTP и Hysteria 2"
        echo "  Создайте A-запись домена на IP ${IP4}"
        msg_inf '────────────────────────────────────────────────────────────────────────────────'
        echo -en 'Домен: '
        tty_read || return 1
        d=$(printf '%s' "$REPLY" | tr -d '[:space:]' | LC_ALL=C tr '[:upper:]' '[:lower:]')
        [[ -n "$d" ]] || continue
        if [[ ! "$d" =~ ^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$ ]]; then
            msg_err "Некорректный домен: ${d}"
            continue
        fi
        if ! domain_a_ok "$d"; then
            msg_err "A-запись ${d} не указывает на ${IP4}."
            continue
        fi
        domain="$d"
        msg_ok "A-запись ${domain} указывает на ${IP4}."
        return 0
    done
}

# ─── Install questions ───────────────────────────────────────────────────────
choose_adguard() {
    ask_choice DEPLOY_AGH 'Развернуть self-hosted DNS-over-HTTPS (AdGuard Home) на домене панели?' 'Да' 'Нет'
}

resolve_doh_for_hosts() {
    python3 - "$1" <<'PY'
import socket, sys, urllib.parse
raw = (sys.argv[1] or "").strip()
p = urllib.parse.urlparse(raw)
if p.scheme != "https" or not p.hostname:
    raise SystemExit(1)
try:
    infos = socket.getaddrinfo(p.hostname, 443, socket.AF_INET, socket.SOCK_STREAM)
except Exception:
    raise SystemExit(1)
ip = infos[0][4][0] if infos else ""
if not ip:
    raise SystemExit(1)
print(p.hostname); print(ip); print(raw)
PY
}

choose_xray_dns() {
    local resolved
    while true; do
        ask_choice DNS_CHOICE 'Настройка DNS в X-UI:' 'Оставить по умолчанию' 'DoH Cloudflare' 'DoH Google' \
            'DoH Quad9' 'Использовать self-hosted DoH' 'Свой DoH' || return 1
        if [[ "$DNS_CHOICE" == 5 && "$DEPLOY_AGH" != 1 ]]; then
            choose_adguard || return 1
            [[ "$DEPLOY_AGH" == 1 ]] || continue
        fi
        if [[ "$DNS_CHOICE" == 6 ]]; then
            echo -en 'DoH URL: '
            tty_read || return 1
            resolved=$(resolve_doh_for_hosts "${REPLY//[[:space:]]/}" 2>/dev/null) || { msg_err 'Некорректный или недоступный DoH URL.'; continue; }
            CUSTOM_DOH_HOST=$(sed -n 1p <<<"$resolved")
            CUSTOM_DOH_IP=$(sed -n 2p <<<"$resolved")
            CUSTOM_DOH_URL=$(sed -n 3p <<<"$resolved")
        fi
        return 0
    done
}

choose_hy2() {
    local p
    ask_choice DEPLOY_HY2 'Добавить инбаунд Hysteria 2?' 'Да' 'Нет' || return 1
    [[ "$DEPLOY_HY2" == 1 ]] || return 0
    while true; do
        echo
        msg_inf '────────────────────────────────────────────────────────────────────────────────'
        msg_inf 'UDP-порт для Hysteria 2:'
        echo '  Enter без ввода выберет случайный свободный порт'
        msg_inf '────────────────────────────────────────────────────────────────────────────────'
        echo -en 'Порт: '
        tty_read || return 1
        p=${REPLY//[[:space:]]/}
        if [[ -z "$p" ]]; then
            # Random port from the same 10000-59151 range as the panel ports, free over UDP.
            while true; do
                p=$(get_port)
                [[ "$p" != "$sub_port" && "$p" != "$panel_port" && "$p" != "$clash_port" ]] || continue
                ss -Hlnu "sport = :$p" 2>/dev/null | grep -q . || break
            done
            hy2_port="$p"
            msg_ok "Выбран случайный порт Hysteria 2: ${hy2_port}/udp"
            break
        fi
        if [[ ! "$p" =~ ^[0-9]+$ ]] || (( p < 1 || p > 65535 )); then
            msg_err "Некорректный порт."
            continue
        fi
        # TCP listeners (including nginx :443) do not occupy UDP ports.
        if ss -Hlnu "sport = :$p" 2>/dev/null | grep -q .; then
            msg_err "Порт ${p} занят."
            continue
        fi
        hy2_port="$p"
        break
    done
    echo
}

choose_guard() {
    ask_choice DEPLOY_GUARD 'Установить защиту от сканеров и торрентов?' \
        'Да (подсети сканеров РКН и сигнатуры BitTorrent, списки обновляются сами)' 'Нет'
}

# ─── Preserve state for a reversible full uninstall ──────────────────────────
save_firewall_state() {
    local state_dir="${STATE_DIR}/firewall"
    [[ -f "${state_dir}/saved" ]] && return 0
    mkdir -p "$state_dir"
    {
        if command -v ufw >/dev/null 2>&1; then
            echo 'UFW_WAS_INSTALLED=1'
            if ufw status 2>/dev/null | grep -q '^Status: active'; then echo 'UFW_WAS_ACTIVE=1'; else echo 'UFW_WAS_ACTIVE=0'; fi
        else
            echo 'UFW_WAS_INSTALLED=0'
            echo 'UFW_WAS_ACTIVE=0'
        fi
    } > "${state_dir}/state"
    tar -cpf "${state_dir}/ufw-config.tar" /etc/ufw /etc/default/ufw 2>/dev/null || true
    command -v iptables-save >/dev/null 2>&1 && iptables-save > "${state_dir}/iptables.v4" 2>/dev/null || true
    command -v ip6tables-save >/dev/null 2>&1 && ip6tables-save > "${state_dir}/iptables.v6" 2>/dev/null || true
    touch "${state_dir}/saved"
}

# The guard owns its rules and reloads them itself, so snapshots never carry them back.
strip_guard_rules() {
    sed -e '/^:\(XA_SCAN\|XA_TORRENT\) /d' -e '/^-A \(XA_SCAN\|XA_TORRENT\) /d' -e '/ -[jg] \(XA_SCAN\|XA_TORRENT\)$/d' "$1"
}

restore_firewall_state() {
    local state_dir="${STATE_DIR}/firewall"
    local UFW_WAS_INSTALLED=0 UFW_WAS_ACTIVE=0
    [[ -f "${state_dir}/saved" && -f "${state_dir}/state" ]] || return 0
    # shellcheck disable=SC1090
    source "${state_dir}/state"
    if command -v ufw >/dev/null 2>&1; then
        ufw --force disable >/dev/null 2>&1 || true
        ufw --force reset >/dev/null 2>&1 || true
    fi
    if [[ "$UFW_WAS_INSTALLED" == 1 ]]; then
        [[ -f "${state_dir}/ufw-config.tar" ]] && tar -xpf "${state_dir}/ufw-config.tar" -C / 2>/dev/null || true
        [[ "$UFW_WAS_ACTIVE" == 1 ]] && ufw --force enable >/dev/null 2>&1 || true
    fi
    [[ -s "${state_dir}/iptables.v4" ]] && command -v iptables-restore >/dev/null 2>&1 &&
        strip_guard_rules "${state_dir}/iptables.v4" | iptables-restore 2>/dev/null || true
    [[ -s "${state_dir}/iptables.v6" ]] && command -v ip6tables-restore >/dev/null 2>&1 &&
        strip_guard_rules "${state_dir}/iptables.v6" | ip6tables-restore 2>/dev/null || true
    [[ -x "$GUARD_SELF" ]] && "$GUARD_SELF" load >/dev/null 2>&1 || true
    msg_ok "Firewall restored to its pre-install state."
}

save_renewal_state() {
    local dir="$1" unit
    mkdir -p "$dir" || return 1
    if command -v crontab >/dev/null 2>&1 && crontab -l > "$dir/root-crontab" 2>/dev/null; then
        touch "$dir/crontab-present" || return 1
    else
        : > "$dir/root-crontab" || return 1
    fi
    for unit in certbot.timer cron; do
        systemctl is-enabled "$unit" > "$dir/$unit-enabled" 2>/dev/null || true
        systemctl is-active "$unit" > "$dir/$unit-active" 2>/dev/null || true
    done
}

restore_renewal_state() {
    local dir="$1" unit enabled active failed=0
    [[ -d "$dir" ]] || return 0
    if command -v crontab >/dev/null 2>&1; then
        if [[ -f "$dir/crontab-present" ]]; then
            crontab "$dir/root-crontab" || failed=1
        elif crontab -l >/dev/null 2>&1; then
            crontab -r || failed=1
        fi
    fi
    for unit in certbot.timer cron; do
        enabled=$(cat "$dir/$unit-enabled" 2>/dev/null)
        active=$(cat "$dir/$unit-active" 2>/dev/null)
        case "$enabled" in
            masked*) systemctl mask --now "$unit" >/dev/null 2>&1 || failed=1 ;;
            *)
                systemctl unmask "$unit" >/dev/null 2>&1 || failed=1
                case "$enabled" in
                    enabled*) systemctl enable "$unit" >/dev/null 2>&1 || failed=1 ;;
                    disabled) systemctl disable "$unit" >/dev/null 2>&1 || failed=1 ;;
                esac
                if [[ "$active" == active ]]; then
                    systemctl start "$unit" >/dev/null 2>&1 || failed=1
                elif [[ "$active" != unknown && "$enabled" != not-found && -n "$enabled" ]]; then
                    systemctl stop "$unit" >/dev/null 2>&1 || failed=1
                fi ;;
        esac
    done
    return "$failed"
}

OWNED_PATHS=(/etc/nginx /var/www/html /var/www/subpage /etc/sysctl.conf /etc/default/x-ui /etc/fail2ban
             /etc/modules-load.d/3x-ui-auto-network.conf /etc/sysctl.d/99-bbr-x-ui.conf
             /etc/sysctl.d/99-zz-3x-ui-auto-tuning.conf)
OWNED_PACKAGES=(nginx-full nginx nginx-common nginx-core fail2ban ufw cron sqlite3 jq)

save_preinstall_state() {
    local dir="${STATE_DIR}" path
    umask 077
    install -d -m 0700 "$dir"
    : > "$dir/existing-paths"
    for path in "${OWNED_PATHS[@]}"; do
        if [[ -e "$path" || -L "$path" ]]; then
            printf '%s\n' "$path" >> "$dir/existing-paths"
            tar -rpf "$dir/baseline.tar" -C / "${path#/}" || return 1
        fi
    done
    : > "$dir/packages"
    for path in "${OWNED_PACKAGES[@]}" certbot python3-certbot-nginx; do
        dpkg-query -W -f='${Status}' "$path" 2>/dev/null | grep -qx 'install ok installed' &&
            printf '%s\n' "$path" >> "$dir/packages"
    done
    systemctl is-enabled --quiet nginx 2>/dev/null && touch "$dir/nginx-enabled" || true
    systemctl is-active --quiet nginx 2>/dev/null && touch "$dir/nginx-active" || true
    save_renewal_state "$dir/renewal-baseline" || return 1
    sysctl -n net.core.default_qdisc > "$dir/qdisc" 2>/dev/null || true
    sysctl -n net.ipv4.tcp_congestion_control > "$dir/congestion-control" 2>/dev/null || true
    save_firewall_state || return 1
    printf '%s\n' "$domain" > "$dir/domains"
    touch "$dir/owned-by-3x-ui-auto"
    umask 022
}

restore_preinstall_state() {
    local dir="$STATE_DIR" path package
    msg_inf "Восстанавливаю файлы и настройки, сохранённые до установки..."
    for path in "${OWNED_PATHS[@]}"; do
        grep -Fxq "$path" "$dir/existing-paths" || rm -rf -- "$path"
    done
    # Certificates and certbot state stay: never roll back a renewed certificate.
    [[ ! -s "$dir/baseline.tar" ]] || tar -xpf "$dir/baseline.tar" -C / \
        --exclude='etc/letsencrypt' --exclude='etc/letsencrypt/*' || {
            msg_err "Не удалось восстановить исходные файлы из снимка."
            return 1
        }
    sysctl -w "net.core.default_qdisc=$(cat "$dir/qdisc")" >/dev/null 2>&1 || true
    sysctl -w "net.ipv4.tcp_congestion_control=$(cat "$dir/congestion-control")" >/dev/null 2>&1 || true
    restore_firewall_state
    restore_renewal_state "$dir/renewal-baseline" || return 1
    if [[ -f "$dir/nginx-enabled" ]]; then systemctl enable nginx >/dev/null 2>&1 || true
    else systemctl disable nginx >/dev/null 2>&1 || true; fi
    [[ -f "$dir/nginx-active" ]] && systemctl start nginx >/dev/null 2>&1 || true
    # No autoremove: it could remove packages installed by the administrator.
    msg_inf "Удаляю пакеты, установленные вместе с панелью (certbot сохраняется)..."
    for package in "${OWNED_PACKAGES[@]}"; do
        if ! grep -Fxq "$package" "$dir/packages" &&
           dpkg-query -W -f='${Status}' "$package" 2>/dev/null | grep -qx 'install ok installed'; then
            msg_inf "  Удаляю пакет: ${package}"
            apt-get -y purge "$package" >/dev/null 2>&1 || msg_err "Не удалось удалить пакет ${package}; проверьте его вручную."
        fi
    done
}

run_log_policy() {
    install -d -m 0755 /usr/local/lib/3x-ui-auto
    cat > /usr/local/lib/3x-ui-auto/log-policy.py <<'PY_XA_LOG_POLICY'
#!/usr/bin/env python3
"""Keep nginx logs enabled; bound each log family and the default journal."""
import argparse
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import time

BUDGET = 100 * 1024 * 1024
AGE = 3 * 24 * 60 * 60
HEADER = '# Managed by 3x-ui-auto log policy\n'
ROTATE = HEADER + '''/var/log/nginx/*.log {
    hourly
    maxsize 25M
    rotate 72
    maxage 3
    missingok
    notifempty
    compress
    delaycompress
    nodateext
    create 0640 www-data adm
    sharedscripts
    postrotate
        if systemctl is-active --quiet nginx.service; then
            systemctl kill --kill-who=main --signal=USR1 nginx.service
        fi
    endscript
}
'''
JOURNAL = HEADER + '''[Journal]
SystemMaxUse=100M
RuntimeMaxUse=100M
SystemMaxFileSize=25M
RuntimeMaxFileSize=25M
MaxRetentionSec=3day
MaxFileSec=1day
'''
SERVICE = '''[Unit]
Description=Limit nginx log archives and system journal
After=nginx.service systemd-journald.service

[Service]
Type=oneshot
ExecStart=/usr/bin/python3 /usr/local/lib/3x-ui-auto/log-policy.py maintain
Nice=10
IOSchedulingClass=idle
TimeoutStartSec=180
'''
TIMER = '''[Unit]
Description=Check 3x-ui-auto log retention every minute

[Timer]
OnActiveSec=1min
OnUnitActiveSec=1min
AccuracySec=10s
Unit=xa-log-policy.service

[Install]
WantedBy=timers.target
'''
CONFIGS = ('etc/logrotate.d/nginx', 'etc/systemd/journald.conf.d/99-3x-ui-auto-logs.conf')


def command(*args, allowed=(0,)):
    result = subprocess.run(args, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=150)
    if result.returncode not in allowed:
        raise RuntimeError(args[0] + ': ' + result.stderr.strip())
    return result


def write(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + '.xa-tmp')
    temporary.write_text(text, encoding='utf-8')
    temporary.chmod(0o644)
    os.replace(temporary, path)


def install(root):
    if root == Path('/') and not shutil.which('logrotate'):
        command('apt-get', 'install', '-y', '--no-install-recommends', 'logrotate')
    state = root / 'var/lib/3x-ui-auto/install/log-policy-baseline'
    marker = state / 'state.json'
    if not marker.is_file():
        state.mkdir(parents=True, exist_ok=True); state.chmod(0o700)
        saved = {}
        for index, relative in enumerate(CONFIGS):
            path = root / relative
            present = path.is_file()
            saved[relative] = present
            if present:
                shutil.copy2(path, state / str(index))
        marker.write_text(json.dumps(saved), encoding='utf-8'); marker.chmod(0o600)
    for relative, text in zip(CONFIGS, (ROTATE, JOURNAL)):
        write(root / relative, text)
    units = root / 'etc/systemd/system'
    write(units / 'xa-log-policy.service', SERVICE)
    write(units / 'xa-log-policy.timer', TIMER)
    if root == Path('/'):
        command('logrotate', '--debug', '/etc/logrotate.d/nginx')
        command('systemctl', 'daemon-reload')
        command('systemctl', 'restart', 'systemd-journald.service')
        # Close old active journal files once so the initial vacuum can remove
        # the backlog. Normal maintenance need not rotate journald every minute.
        command('journalctl', '--rotate')
        maintain(root)
        command('systemctl', 'enable', '--now', 'xa-log-policy.timer')
        command('systemctl', 'restart', 'xa-log-policy.timer')
    print('Log policy: nginx ~100 MiB per log including archives; journal 100 MiB; retention up to 3 days.')


def prune(directory, budget=BUDGET, age=AGE, now=None):
    """Delete only nginx numbered archives; never truncate live log files."""
    now = time.time() if now is None else now
    groups = {}
    for path in directory.iterdir() if directory.is_dir() else ():
        if path.is_symlink() or not path.is_file():
            continue
        match = re.fullmatch(r'(.+\.log)(?:\.([0-9]+)(?:\.gz)?)?', path.name)
        if not match:
            continue
        active = match[2] is None
        if not active and path.stat().st_mtime < now - age:
            path.unlink(); continue
        groups.setdefault(match[1], []).append((path, active))
    for entries in groups.values():
        total = sum(path.stat().st_size for path, _ in entries)
        archives = sorted((path for path, active in entries if not active), key=lambda path: path.stat().st_mtime)
        for path in archives:
            if total <= budget:
                break
            total -= path.stat().st_size; path.unlink()


def maintain(root):
    if root == Path('/'):
        import fcntl
        lock = root / 'run/lock/xa-log-policy.lock'
        with lock.open('w') as handle:
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
            # Reuse the system state/lock; a concurrent system logrotate run
            # returns 3 and will perform the same rotation itself.
            result = command('logrotate', '/etc/logrotate.d/nginx', allowed=(0, 3))
            if result.returncode == 0:
                prune(root / 'var/log/nginx')
            command('journalctl', '--vacuum-size=100M', '--vacuum-time=3d')
    else:
        prune(root / 'var/log/nginx')


def remove(root):
    state = root / 'var/lib/3x-ui-auto/install/log-policy-baseline'
    marker = state / 'state.json'
    if not marker.is_file():
        return
    if root == Path('/'):
        command('systemctl', 'disable', '--now', 'xa-log-policy.timer', allowed=(0, 1))
        command('systemctl', 'stop', 'xa-log-policy.service', allowed=(0, 1, 5))
    saved = json.loads(marker.read_text(encoding='utf-8'))
    for index, relative in enumerate(CONFIGS):
        path = root / relative
        if saved[relative]:
            path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(state / str(index), path)
        else:
            path.unlink(missing_ok=True)
    for suffix in ('service', 'timer'):
        (root / f'etc/systemd/system/xa-log-policy.{suffix}').unlink(missing_ok=True)
    if root == Path('/'):
        command('systemctl', 'daemon-reload')
        command('systemctl', 'restart', 'systemd-journald.service')
    print('Previous nginx rotation and journald configuration restored.')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('action', choices=('install', 'maintain', 'remove'))
    parser.add_argument('--root', type=Path, default=Path('/'))
    args = parser.parse_args()
    globals()[args.action](args.root.resolve())


if __name__ == '__main__':
    main()
PY_XA_LOG_POLICY
    chmod 0755 /usr/local/lib/3x-ui-auto/log-policy.py
    python3 /usr/local/lib/3x-ui-auto/log-policy.py "$@"
}

# ─── Packages ────────────────────────────────────────────────────────────────
install_packages() {
    local nginx_repair=0
    ufw disable 2>/dev/null || true
    apt-get -y update || return 1
    apt-get -y install curl wget jq bash sudo openssl nginx-full certbot python3-certbot-nginx sqlite3 ufw \
        python3 cron iproute2 logrotate tar ca-certificates psmisc || return 1
    # A previous interrupted install can leave nginx installed without its config.
    [[ -f /etc/nginx/nginx.conf ]] || nginx_repair=1
    [[ -d /etc/nginx/sites-available && -d /etc/nginx/sites-enabled ]] || nginx_repair=1
    if [[ "$nginx_repair" == 1 ]]; then
        msg_inf "Repairing nginx package/configuration from a partial previous install..."
        apt-get -y install --reinstall -o Dpkg::Options::=--force-confmiss nginx-common nginx-full || return 1
    fi
    install -d -m 0755 /etc/nginx /etc/nginx/sites-available /etc/nginx/sites-enabled \
        /etc/nginx/stream-enabled /etc/nginx/snippets
    [[ -f /etc/nginx/nginx.conf ]] || { msg_err "nginx.conf is still missing after package repair."; return 1; }
    systemctl daemon-reload
    systemctl reset-failed nginx 2>/dev/null || true
    systemctl enable nginx >/dev/null 2>&1 || return 1
    # nginx starts only after configure_nginx() wrote and tested the full config.
    systemctl stop nginx 2>/dev/null || true
}

# ─── SSL certificates ────────────────────────────────────────────────────────
ensure_panel_cert_links() {
    local d="$1" name link
    mkdir -p "/root/cert/${d}"
    chmod 755 /root/cert /root/cert/* 2>/dev/null || true
    for name in fullchain.pem privkey.pem; do
        link="/root/cert/${d}/${name}"
        if [[ -L "$link" && ! -e "$link" ]]; then rm -f -- "$link"; fi
        [[ -e "$link" || -L "$link" ]] || ln -s "/etc/letsencrypt/live/${d}/${name}" "$link" || return 1
    done
}

get_ssl_certs() {
    local d="$domain"
    if [[ -s "/etc/letsencrypt/live/${d}/fullchain.pem" && -s "/etc/letsencrypt/live/${d}/privkey.pem" ]]; then
        msg_inf "Using existing certificate for ${d}."
    else
        systemctl stop nginx 2>/dev/null || true
        fuser -k 80/tcp 2>/dev/null || true
        certbot certonly --standalone --non-interactive --agree-tos \
            --register-unsafely-without-email --cert-name "$d" -d "$d" || {
                msg_err "$d SSL could not be generated! Check Domain/IP."; return 1;
            }
        printf '%s\n' "$d" > "${STATE_DIR}/new-certificate"
    fi
    ensure_panel_cert_links "$d"
}

# ─── Firewall ────────────────────────────────────────────────────────────────
ssh_ports() {
    local ports
    ports=$(sshd -T 2>/dev/null | awk '$1=="port"{print $2}' | sort -un)
    echo "${ports:-22}"
}

setup_firewall() {
    local port
    ufw --force disable >/dev/null
    ufw default deny incoming
    ufw default allow outgoing
    ufw default allow routed
    for port in $(ssh_ports); do ufw allow "${port}/tcp"; done
    ufw allow 80/tcp
    ufw allow 443/tcp
    [[ "$DEPLOY_HY2" == 1 && -n "$hy2_port" ]] && ufw allow "${hy2_port}/udp"
    ufw --force enable
    # ufw rebuilds INPUT: put the guard chains back on top right away.
    [[ -x "$GUARD_SELF" ]] && "$GUARD_SELF" load >/dev/null 2>&1 || true
}

# ─── Panel (official 3x-ui installer, non-interactive) ───────────────────────
resolve_panel_tag() {
    local url tag
    if [[ -n "$PANEL_VERSION" ]]; then
        tag="v${PANEL_VERSION#v}"
    else
        url=$(curl -sSLI -o /dev/null -w '%{url_effective}' --retry 3 --connect-timeout 15 --max-time 60 \
            "https://github.com/${PANEL_REPO}/releases/latest")
        tag=${url##*/tag/}
    fi
    [[ "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || { msg_err "Не удалось определить версию 3x-ui: ${tag:-нет ответа GitHub}"; return 1; }
    PANEL_TAG="$tag"
}

install_panel() {
    local installer log=/var/log/3x-ui-auto-panel-install.log
    resolve_panel_tag || return 1
    installer=$(mktemp) || return 1
    if ! curl -fsSL --retry 3 --connect-timeout 15 --max-time 120 \
        "https://raw.githubusercontent.com/${PANEL_REPO}/${PANEL_TAG}/install.sh" -o "$installer" || ! bash -n "$installer"; then
        rm -f "$installer"
        msg_err "Не удалось скачать установщик 3x-ui ${PANEL_TAG}."
        return 1
    fi
    msg_inf "Устанавливаю 3x-ui ${PANEL_TAG} штатным установщиком..."
    if ! XUI_NONINTERACTIVE=1 XUI_SSL_MODE=none XUI_USERNAME="$config_username" XUI_PASSWORD="$config_password" \
         XUI_PANEL_PORT="$panel_port" XUI_WEB_BASE_PATH="$panel_path" XUI_ENABLE_FAIL2BAN=true \
         bash "$installer" "$PANEL_TAG" </dev/null >"$log" 2>&1; then
        rm -f "$installer"
        tail -20 "$log"
        msg_err "Установка 3x-ui завершилась с ошибкой. Журнал: $log"
        return 1
    fi
    rm -f "$installer"
    # The installer's own credentials file is replaced by our results screen.
    rm -f /etc/x-ui/install-result.env
    systemctl stop x-ui 2>/dev/null || true
    [[ -f "$XUIDB" ]] || { msg_err "x-ui.db not found after installation."; return 1; }
    grep -q 'fail2ban' "$log" && msg_inf "Fail2ban для IP Limit настроен штатным установщиком."
    msg_ok "3x-ui ${PANEL_TAG} installed."
}

wait_for_xui_active() {
    local i
    for ((i=0; i<${1:-15}; i++)); do
        systemctl is-active --quiet x-ui && return 0
        sleep 1
    done
    return 1
}

restart_xui_wait() {
    systemctl restart x-ui >/dev/null 2>&1 || true
    wait_for_xui_active 15 && return 0
    systemctl reset-failed x-ui 2>/dev/null || true
    systemctl restart x-ui >/dev/null 2>&1 || true
    wait_for_xui_active 15 && return 0
    msg_err "3x-ui did not become active after restart."
    systemctl status x-ui --no-pager -l 2>/dev/null || true
    journalctl -u x-ui -n 40 --no-pager 2>/dev/null || true
    return 1
}

# ─── Nginx ───────────────────────────────────────────────────────────────────
configure_nginx() {
    install -d -m 0755 /etc/nginx/sites-available /etc/nginx/sites-enabled /etc/nginx/stream-enabled /etc/nginx/snippets

    # nginx >= 1.25.1 deprecates "listen ... http2" in favor of "http2 on;"
    local ngx_ver http2_listen="" http2_on=""
    ngx_ver=$(nginx -v 2>&1 | grep -oP '[0-9]+\.[0-9]+\.[0-9]+' || echo 0)
    if [[ "$(printf '%s\n' 1.25.1 "$ngx_ver" | sort -V | head -1)" == "1.25.1" ]]; then
        http2_on="http2 on;"
    else
        http2_listen=" http2"
    fi

    # SNI stream on 443: REALITY first (8443), the TLS site/panel is the fallback (7443).
    cat > /etc/nginx/stream-enabled/stream.conf <<EOF
map \$ssl_preread_server_name \$sni_name {
    hostnames;
    ${domain}    xray;
    default      xray;
}

upstream xray {
    server 127.0.0.1:8443 max_fails=0;
    server 127.0.0.1:7443 backup;
}
upstream www  { server 127.0.0.1:7443; }

server {
    proxy_protocol on;
    set_real_ip_from unix:;
    listen     443;
    listen     [::]:443;
    proxy_pass \$sni_name;
    ssl_preread on;
}
EOF

    grep -xqFR "stream { include /etc/nginx/stream-enabled/*.conf; }" /etc/nginx/* \
        || echo "stream { include /etc/nginx/stream-enabled/*.conf; }" >> /etc/nginx/nginx.conf
    grep -xqFR "load_module modules/ngx_stream_module.so;" /etc/nginx/* \
        || sed -i '1s/^/load_module \/usr\/lib\/nginx\/modules\/ngx_stream_module.so; /' /etc/nginx/nginx.conf
    grep -xqFR "worker_rlimit_nofile 16384;" /etc/nginx/* \
        || echo "worker_rlimit_nofile 16384;" >> /etc/nginx/nginx.conf
    sed -i "/worker_connections/c\worker_connections 4096;" /etc/nginx/nginx.conf

    cat > /etc/nginx/sites-available/80.conf <<EOF
server {
    listen 80;
    server_name ${domain};
    return 301 https://\$host\$request_uri;
}
EOF

    # Shared proxy locations for xray inbounds and subscriptions
    cat > /etc/nginx/snippets/includes.conf <<EOF
    # Mihomo proxy provider: the panel's own Clash output for one client.
    location ~ ^/__xa_provider/(?<xa_provider_id>[^/]+)/?\$ {
        if (\$hack = 1) { return 404; }
        rewrite ^ /mihomo/\$xa_provider_id break;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_redirect off;
        proxy_pass https://127.0.0.1:${sub_port};
    }
    # Clash link displayed by the panel gets the full Mihomo profile.
    location ~ ^/mihomo/(?<panel_clash_sub_id>[^/]+)/?\$ {
        if (\$hack = 1) { return 404; }
        rewrite ^ /__xa_clash?sub_id=\$panel_clash_sub_id last;
    }
    # One-level client URL: Clash/Mihomo gets YAML, other clients get panel output.
    location ~ ^/${sub_path}/(?<clash_sub_id>[^/]+)\$ {
        if (\$hack = 1) { return 404; }
        if (\$serve_clash_yaml = 1) { rewrite ^ /__xa_clash?sub_id=\$clash_sub_id last; }
        proxy_redirect off;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_pass https://127.0.0.1:${sub_port};
    }
    location /${sub_path}/ {
        if (\$hack = 1) { return 404; }
        proxy_redirect off;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_pass https://127.0.0.1:${sub_port};
    }
    location = /${sub_path} {
        if (\$hack = 1) { return 404; }
        proxy_redirect off;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_pass https://127.0.0.1:${sub_port};
    }
    location /assets  { proxy_pass https://127.0.0.1:${sub_port}; }
    location /assets/ { proxy_pass https://127.0.0.1:${sub_port}; }

    #Subscription (json)
    location /${json_path} {
        if (\$hack = 1) { return 404; }
        proxy_redirect off;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_pass https://127.0.0.1:${sub_port};
    }
    location /${json_path}/ {
        if (\$hack = 1) { return 404; }
        proxy_redirect off;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_pass https://127.0.0.1:${sub_port};
    }

    #XHTTP: all server modes, real IP from the trusted public SNI entry point.
    location ^~ /${xhttp_path}/ {
        client_max_body_size 0;
        client_body_timeout 1h;
        grpc_read_timeout 1h;
        grpc_send_timeout 1h;
        grpc_set_header Connection "";
        grpc_set_header Host \$host;
        grpc_set_header X-Real-IP \$remote_addr;
        grpc_set_header X-Forwarded-For \$remote_addr;
        grpc_pass grpc://127.0.0.1:10080;
    }

    #Xray generic proxy (WS / gRPC by port+path)
    location ~ ^/(?<fwdport>\d+)/(?<fwdpath>.*)\$ {
        if (\$hack = 1) { return 404; }
        client_max_body_size 0;
        client_body_timeout 1d;
        grpc_read_timeout 1d;
        grpc_socket_keepalive on;
        proxy_read_timeout 1d;
        proxy_http_version 1.1;
        proxy_buffering off;
        proxy_request_buffering off;
        proxy_socket_keepalive on;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        if (\$content_type ~* "GRPC") {
            grpc_pass grpc://127.0.0.1:\$fwdport\$is_args\$args;
            break;
        }
        if (\$http_upgrade ~* "(WEBSOCKET|WS)") {
            proxy_pass http://127.0.0.1:\$fwdport\$is_args\$args;
            break;
        }
        if (\$request_method ~* ^(PUT|POST|GET)\$) {
            proxy_pass http://127.0.0.1:\$fwdport\$is_args\$args;
            break;
        }
    }

    location / { try_files \$uri \$uri/ =404; }
EOF

    cat > /etc/nginx/sites-available/00-clash-maps.conf <<'EOF'
map $http_user_agent $xa_clash_ua {
    ~*(clash|mihomo|stash|surfboard) 1;
    default 0;
}
map "$xa_clash_ua:$arg_provider" $serve_clash_yaml {
    "1:" 1;
    default 0;
}
EOF
    ln -sf /etc/nginx/sites-available/00-clash-maps.conf /etc/nginx/sites-enabled/00-clash-maps.conf

    # Main vhost: TLS termination at 7443 behind the SNI stream, cover site, panel and subscriptions.
    cat > "/etc/nginx/sites-available/${domain}" <<EOF
server {
    server_tokens off;
    server_name ${domain};
    listen 127.0.0.1:7443 ssl${http2_listen} proxy_protocol;
    ${http2_on}
    index index.html index.htm index.php;
    root /var/www/html/;
    real_ip_header proxy_protocol;
    set_real_ip_from 127.0.0.1;
    # Public port is 443: keep redirects relative instead of leaking :7443.
    absolute_redirect off;
    http2_body_preread_size 128k;
    client_body_buffer_size 512k;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!eNULL:!MD5:!DES:!RC4:!ADH:!SSLv3:!EXP:!PSK:!DSS;
    ssl_certificate     /etc/letsencrypt/live/${domain}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/${domain}/privkey.pem;
    if (\$host !~* ^(.+\.)?${domain}\$)            { return 444; }
    if (\$scheme ~* https)                          { set \$safe 1; }
    if (\$ssl_server_name !~* ^(.+\.)?${domain}\$) { set \$safe "\${safe}0"; }
    if (\$safe = 10)                                { return 444; }
    if (\$request_uri ~ "(\"|'|\`|~|,|:|;|%|\\$|&&|\?\?|0x00|0X00|\||\\|\{|\}|\[|\]|<|>|\.\.\.|\.\.\/|\/\/\/)") { set \$hack 1; }
    error_page 400 401 402 403 500 501 502 503 504 =404 /404;
    proxy_intercept_errors on;

    location /${panel_path}/ {
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
        proxy_pass https://127.0.0.1:${panel_port};
    }
    location /${panel_path} {
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
        proxy_pass https://127.0.0.1:${panel_port};
    }

    location = /__xa_clash {
        internal;
        proxy_pass http://127.0.0.1:${clash_port}/api/clash\$is_args\$args;
        proxy_set_header Host \$host;
    }

    include /etc/nginx/snippets/includes.conf;
}
EOF

    rm -f /etc/nginx/sites-enabled/default /etc/nginx/sites-available/default
    ln -sf "/etc/nginx/sites-available/${domain}" /etc/nginx/sites-enabled/
    ln -sf /etc/nginx/sites-available/80.conf /etc/nginx/sites-enabled/
    nginx -t || { msg_err "nginx config check failed!"; return 1; }
    systemctl start nginx || return 1
}

# ─── Clash / Mihomo subscription ─────────────────────────────────────────────
install_clash_subscription() {
    install -d -m 0755 /var/www/subpage "$LIB_DIR"
    # Based on mozaroc/3x-ui-pro assets/clash/clash.yaml (a2c430c).
    cat > /var/www/subpage/clash.yaml.tpl <<'XA_CLASH_TEMPLATE'
mode: rule
log-level: info
mixed-port: 10000
unified-delay: true
allow-lan: true
tcp-concurrent: true
enable-process: true
find-process-mode: always
profile:
  store-selected: true
  store-fake-ip: true
sniffer:
  enable: true
  force-dns-mapping: true
  parse-pure-ip: true
  sniff:
    HTTP:
      ports:
        - 80
        - 8080-8880
      override-destination: true
    TLS:
      ports:
        - 443
        - 8443
dns:
  enable: true
  prefer-h3: true
  use-hosts: true
  use-system-hosts: true
  listen: 127.0.0.1:6868
  ipv6: false
  enhanced-mode: redir-host
  default-nameserver:
    - tls://77.88.8.8#DIRECT # Yandex DNS over TLS
    - 195.208.4.1#DIRECT # НСДИ
    - system
  proxy-server-nameserver:
    - tls://77.88.8.8#DIRECT # Yandex DNS over TLS
    - 195.208.4.1#DIRECT # НСДИ
    - system
  direct-nameserver:
    - tls://77.88.8.8#DIRECT # Yandex DNS over TLS
    - 195.208.4.1#DIRECT # НСДИ
    - system
  nameserver:
    - https://cloudflare-dns.com/dns-query#PROXY
proxy-providers:
  sub:
    type: http
    proxy: DIRECT
    url: https://${DOMAIN}/__xa_provider/${SUB_ID}
    path: ./proxy_providers/${DOMAIN}_${SUB_PATH}_${SUB_ID}.yaml
    interval: 3600
    override:
      override-expr:
        - '(select(.type == "vless" and .["reality-opts"] != null) | .["client-fingerprint"]) = "chrome"'
        - '(select(.type == "vless" and .["reality-opts"] != null) | .["reality-opts"]["support-x25519mlkem768"]) = true'
    health-check:
      enable: true
      url: https://www.gstatic.com/generate_204
      interval: 300
      timeout: 5000
      lazy: true
      expected-status: 204
proxy-groups:
  - name: 🌍 VPN
    icon: https://cdn.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Hijacking.png
    type: select
    use:
      - sub
    proxies:
      - ⚡️ Fastest
  - name: ▶️ YouTube
    icon: https://cdn.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/YouTube.png
    type: select
    use:
      - sub
    proxies:
      - 🌍 VPN
  - name: 💬 Discord
    icon: https://cdn.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Discord.png
    type: select
    use:
      - sub
    proxies:
      - 🌍 VPN
  - name: ⚡️ Fastest
    icon: https://cdn.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Auto.png
    type: url-test
    tolerance: 150
    url: https://cp.cloudflare.com/generate_204
    interval: 300
    use:
      - sub
  - name: ➤ Telegram
    icon: https://cdn.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Telegram.png
    type: select
    use:
      - sub
    proxies:
      - 🌍 VPN
  - name: ➤ WhatsApp
    icon: https://cdn.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Facebook.png
    type: select
    use:
      - sub
    proxies:
      - 🌍 VPN
  - name: PROXY
    type: select
    hidden: true
    use:
      - sub
    proxies:
      - 🌍 VPN
rule-providers:
  facebook-ips:
    type: http
    behavior: ipcidr
    format: mrs
    interval: 86400
    url: https://github.com/MetaCubeX/meta-rules-dat/raw/meta/geo/geoip/facebook.mrs
    path: ./rule-sets/facebook-ips.mrs
  whatsapp-domains:
    type: http
    behavior: domain
    format: mrs
    interval: 86400
    url: https://github.com/MetaCubeX/meta-rules-dat/raw/meta/geo/geosite/whatsapp.mrs
    path: ./rule-sets/whatsapp-domains.mrs
  telegram-ips:
    type: http
    behavior: ipcidr
    format: mrs
    interval: 86400
    url: https://github.com/MetaCubeX/meta-rules-dat/raw/meta/geo/geoip/telegram.mrs
    path: ./rule-sets/telegram-ips.mrs
  telegram-domains:
    type: http
    behavior: domain
    format: mrs
    interval: 86400
    url: https://github.com/MetaCubeX/meta-rules-dat/raw/meta/geo/geosite/telegram.mrs
    path: ./rule-sets/telegram-domains.mrs
  discord_domains:
    type: http
    behavior: domain
    format: mrs
    url: https://github.com/MetaCubeX/meta-rules-dat/raw/meta/geo/geosite/discord.mrs
    path: ./rule-sets/discord_domains.mrs
  discord_voiceips:
    type: http
    behavior: ipcidr
    format: mrs
    url: https://github.com/legiz-ru/mihomo-rule-sets/raw/main/other/discord-voice-ip-list.mrs
    path: ./rule-sets/discord_voiceips.mrs
  refilter_domains:
    type: http
    behavior: domain
    format: mrs
    url: https://github.com/legiz-ru/mihomo-rule-sets/raw/main/re-filter/domain-rule.mrs
    path: ./re-filter/domain-rule.mrs
    interval: 86400
  refilter_ipsum:
    type: http
    behavior: ipcidr
    format: mrs
    url: https://github.com/legiz-ru/mihomo-rule-sets/raw/main/re-filter/ip-rule.mrs
    path: ./re-filter/ip-rule.mrs
    interval: 86400
  youtube:
    type: http
    behavior: domain
    format: mrs
    url: https://github.com/MetaCubeX/meta-rules-dat/raw/meta/geo/geosite/youtube.mrs
    path: ./rule-sets/youtube.mrs
  oisd_big:
    type: http
    behavior: domain
    format: mrs
    url: https://github.com/legiz-ru/mihomo-rule-sets/raw/main/oisd/big.mrs
    path: ./oisd/big.mrs
  torrent-trackers:
    type: http
    behavior: domain
    format: mrs
    url: https://github.com/legiz-ru/mihomo-rule-sets/raw/main/other/torrent-trackers.mrs
    path: ./rule-sets/torrent-trackers.mrs
    interval: 86400
  torrent-clients:
    type: http
    behavior: classical
    format: yaml
    url: https://github.com/legiz-ru/mihomo-rule-sets/raw/main/other/torrent-clients.yaml
    path: ./rule-sets/torrent-clients.yaml
    interval: 86400
  ru-bundle:
    type: http
    behavior: domain
    format: mrs
    url: https://github.com/legiz-ru/mihomo-rule-sets/raw/main/ru-bundle/rule.mrs
    path: ./ru-bundle/rule.mrs
    interval: 86400
rules:
  - OR,((DOMAIN,ipwhois.app),(DOMAIN,ipwho.is),(DOMAIN,api.ip.sb),(DOMAIN,ipapi.co),(DOMAIN,ipinfo.io),(DOMAIN,ip-api.com),(DOMAIN,cloudflare-dns.com)),🌍 VPN
  - RULE-SET,oisd_big,REJECT
  - OR,((RULE-SET,telegram-ips),(RULE-SET,telegram-domains)),➤ Telegram
  - OR,((RULE-SET,facebook-ips),(RULE-SET,whatsapp-domains)),➤ WhatsApp
  - OR,((RULE-SET,torrent-clients),(RULE-SET,torrent-trackers)),DIRECT
  - RULE-SET,youtube,▶️ YouTube
  - OR,((RULE-SET,discord_domains),(RULE-SET,discord_voiceips),(PROCESS-NAME,Discord.exe)),💬 Discord
  - RULE-SET,ru-bundle,🌍 VPN
  - RULE-SET,refilter_domains,🌍 VPN
  - RULE-SET,refilter_ipsum,🌍 VPN
  - MATCH,DIRECT
XA_CLASH_TEMPLATE
    python3 - "$domain" "$sub_path" <<'PY_CLASH_TEMPLATE'
from pathlib import Path
import sys
path = Path('/var/www/subpage/clash.yaml.tpl')
text = path.read_text(encoding='utf-8')
path.write_text(text.replace('${DOMAIN}', sys.argv[1]).replace('${SUB_PATH}', sys.argv[2]), encoding='utf-8')
PY_CLASH_TEMPLATE
    chmod 0644 /var/www/subpage/clash.yaml.tpl
    cat > "${LIB_DIR}/clash-sub-server.py" <<'PY_CLASH_SERVER'
#!/usr/bin/env python3
"""Local per-client YAML renderer, with identical GET/HEAD response headers."""
import argparse
import re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

TEMPLATE = Path('/var/www/subpage/clash.yaml.tpl')


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.render()

    def do_HEAD(self):
        self.render()

    def render(self):
        parsed = urlsplit(self.path)
        if parsed.path == '/health':
            return self.reply(200, b'ok', 'text/plain')
        if parsed.path != '/api/clash':
            return self.reply(404, b'not found', 'text/plain')
        sub_id = parse_qs(parsed.query).get('sub_id', [''])[0]
        if not re.fullmatch(r'[A-Za-z0-9._~-]{1,256}', sub_id):
            return self.reply(400, b'invalid subscription id', 'text/plain')
        try:
            body = TEMPLATE.read_text(encoding='utf-8').replace('${SUB_ID}', sub_id).encode('utf-8')
        except OSError:
            return self.reply(503, b'template unavailable', 'text/plain')
        self.reply(200, body, 'text/yaml; charset=utf-8')

    def reply(self, status, body, content_type):
        self.send_response(status)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        if status == 200 and content_type.startswith('text/yaml'):
            self.send_header('Content-Disposition', 'attachment; filename="clash.yaml"')
        self.end_headers()
        if self.command != 'HEAD':
            self.wfile.write(body)

    def log_message(self, fmt, *args):
        # nginx already logs requests; keep subscription IDs out of the journal.
        pass


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--port', type=int, required=True)
    args = parser.parse_args()
    ThreadingHTTPServer(('127.0.0.1', args.port), Handler).serve_forever()
PY_CLASH_SERVER
    chmod 0755 "${LIB_DIR}/clash-sub-server.py"
    cat > /etc/systemd/system/xa-clash-sub.service <<EOF
[Unit]
Description=3x-ui-auto Clash subscription renderer
After=network.target

[Service]
Type=simple
User=www-data
Group=www-data
ExecStart=/usr/bin/python3 ${LIB_DIR}/clash-sub-server.py --port ${clash_port}
Restart=on-failure
RestartSec=2
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable --now xa-clash-sub.service || return 1
    local attempt
    for attempt in 1 2 3 4 5; do
        if curl -fsS --max-time 2 "http://127.0.0.1:${clash_port}/health" >/dev/null 2>&1; then
            msg_ok "Clash/Mihomo subscription ready."
            return 0
        fi
        sleep 1
    done
    msg_err "Clash subscription renderer did not start."
    return 1
}

# ─── Database: settings, REALITY, XHTTP ──────────────────────────────────────
configure_xui_db() {
    [[ -f $XUIDB ]] || { msg_err "x-ui.db not found — panel may not be installed."; return 1; }
    systemctl stop x-ui 2>/dev/null || true

    local output private_key public_key emoji_flag xray_bin
    xray_bin=$(ls /usr/local/x-ui/bin/xray-linux-* 2>/dev/null | head -1)
    [[ -x "$xray_bin" ]] || { msg_err "Xray binary not found."; return 1; }
    output=$("$xray_bin" x25519)
    private_key=$(echo "$output" | grep "^PrivateKey:" | awk '{print $2}')
    public_key=$(echo "$output"  | grep "^Password"   | awk '{print $NF}')
    [[ -n "$private_key" && -n "$public_key" ]] || { msg_err "Failed to generate REALITY keys."; return 1; }
    emoji_flag=$(LC_ALL=en_US.UTF-8 curl -s --max-time 10 https://ipwho.is/ | jq -r '.flag.emoji' 2>/dev/null)
    [[ -z "$emoji_flag" || "$emoji_flag" == "null" ]] && emoji_flag="🌐"
    EMOJI_FLAG="$emoji_flag"

    local HP="https://${domain}" shor i
    shor=()
    for i in 1 2 3 4 5 6 7 8; do shor+=("$(openssl rand -hex 8)"); done

    python3 - "$XUIDB" <<PY_XA_DB || { msg_err "Failed to write the panel database."; return 1; }
import json, sqlite3, sys
db = sqlite3.connect(sys.argv[1], timeout=30)
settings = {
    "subPort": "${sub_port}", "subPath": "/${sub_path}/", "subURI": "${HP}/${sub_path}/",
    "subJsonPath": "/${json_path}/", "subJsonURI": "${HP}/${json_path}/", "subJsonEnable": "true",
    "subClashEnable": "true", "subClashPath": "/mihomo/", "subClashURI": "${HP}/mihomo/",
    "subEnable": "true", "subEnableRouting": "false", "subListen": "", "subDomain": "",
    "subCertFile": "", "subKeyFile": "", "subUpdates": "12", "subEncrypt": "true",
    "webListen": "", "webDomain": "", "sessionMaxAge": "60", "pageSize": "50",
    "expireDiff": "0", "trafficDiff": "0", "tgBotEnable": "false", "timeLocation": "Europe/Moscow",
    "datepicker": "gregorian",
}
for key, value in settings.items():
    db.execute("DELETE FROM settings WHERE key=?", (key,))
    db.execute("INSERT INTO settings (key, value) VALUES (?, ?)", (key, value))

sniffing = json.dumps({"enabled": True, "destOverride": ["http", "tls", "quic", "fakedns"], "metadataOnly": False, "routeOnly": False})
clients = json.dumps({"clients": [], "decryption": "none", "encryption": "none", "fallbacks": []}, indent=2)
reality = {
    "network": "tcp", "security": "reality",
    "realitySettings": {
        # One domain: non-REALITY TLS falls through to the nginx site on 7443 with PROXY protocol.
        "show": False, "xver": 1, "target": "127.0.0.1:7443", "serverNames": ["${domain}"],
        "privateKey": "${private_key}", "minClientVer": "", "maxClientVer": "", "maxTimediff": 0,
        "shortIds": "${shor[*]}".split(),
        "settings": {"publicKey": "${public_key}", "fingerprint": "firefox", "serverName": "", "spiderX": "/"},
    },
    "tcpSettings": {"acceptProxyProtocol": True, "header": {"type": "none"}},
}
xhttp = {
    "network": "xhttp", "security": "none",
    "xhttpSettings": {"host": "${domain}", "path": "/${xhttp_path}", "mode": "auto"},
    "sockopt": {"trustedXForwardedFor": ["X-Forwarded-For"]},
}
flag = """${emoji_flag}"""
ids = {}
for tag, remark, port, stream in (("inbound-8443", "tcp-reality", 8443, reality), ("inbound-10080", "xhttp-tls", 10080, xhttp)):
    cur = db.execute(
        "INSERT INTO inbounds (user_id, up, down, total, remark, enable, expiry_time, listen, port, protocol, settings, stream_settings, tag, sniffing)"
        " VALUES (1, 0, 0, 0, ?, 1, 0, '127.0.0.1', ?, 'vless', ?, ?, ?, ?)",
        ("%s %s" % (flag, remark), port, clients, json.dumps(stream, indent=2), tag, sniffing))
    ids[tag] = cur.lastrowid
columns = {r[1] for r in db.execute("PRAGMA table_info(hosts)")}
for inbound_id, group_id, remark, xhttp_host in ((ids["inbound-8443"], "$(gen_group_id)", "tcp-reality", False),
                                                  (ids["inbound-10080"], "$(gen_group_id)", "xhttp-tls", True)):
    host = {"inbound_id": inbound_id, "group_id": group_id, "sort_order": 0, "remark": remark,
            "address": "${domain}", "port": 443, "security": "tls" if xhttp_host else "same",
            "fingerprint": "firefox" if xhttp_host else "", "alpn": '["h2","http/1.1"]' if xhttp_host else "[]",
            "sni": "${domain}", "host_header": "${domain}" if xhttp_host else "", "path": "", "cipher_suites": "",
            "override_sni_from_address": 0, "keep_sni_blank": 0, "pinned_peer_cert_sha256": "[]",
            "verify_peer_cert_by_name": "", "allow_insecure": 0, "ech_config_list": "", "mux_params": "",
            "sockopt_params": "", "final_mask": "", "vless_route": "", "snis": "[]", "sni_shared_random": 0}
    host = {k: v for k, v in host.items() if k in columns}
    db.execute("INSERT INTO hosts (%s) VALUES (%s)" % (",".join(host), ",".join("?" * len(host))), list(host.values()))
db.commit()
db.close()
PY_XA_DB

    /usr/local/x-ui/x-ui setting -username "${config_username}" -password "${config_password}" \
        -port "${panel_port}" -webBasePath "${panel_path}" >/dev/null || return 1
    /usr/local/x-ui/x-ui cert -webCert "/root/cert/${domain}/fullchain.pem" \
        -webCertKey "/root/cert/${domain}/privkey.pem" >/dev/null || return 1
    msg_ok "Inbounds VLESS TCP REALITY and VLESS XHTTP TLS created."
}

# ─── Xray template: DNS ──────────────────────────────────────────────────────
has_global_ipv6() { ip -6 addr show scope global 2>/dev/null | grep -q 'inet6'; }

apply_xray_template() {
    [[ -f $XUIDB ]] || { msg_err "x-ui.db not found — cannot apply Xray template."; return 1; }
    local qstrat="" freedom_strat="" enable_he=0 dns_mode="${DNS_CHOICE:-1}"
    [[ "$dns_mode" != 1 ]] || return 0
    if has_global_ipv6; then qstrat='UseIP'; freedom_strat='ForceIP'; enable_he=1
    else qstrat='UseIPv4'; freedom_strat='ForceIPv4'; fi
    [[ -n "${IP4:-}" ]] || get_server_ip
    systemctl stop x-ui 2>/dev/null || true
    python3 - "$XUIDB" "$dns_mode" "$qstrat" "$freedom_strat" "$enable_he" \
        "${domain:-}" "${IP4:-}" "${CUSTOM_DOH_URL:-}" "${CUSTOM_DOH_HOST:-}" "${CUSTOM_DOH_IP:-}" <<'PY'
import json, sqlite3, sys
db, choice, qstrat, freedom_strat, enable_he, domain, ip4, custom_url, custom_host, custom_ip = sys.argv[1:11]
# 3x-ui built-in template (internal/web/service/config.json), used when the DB has none yet.
DEFAULT = {"api": {"services": ["HandlerService", "LoggerService", "StatsService", "RoutingService"], "tag": "api"},
    "inbounds": [{"listen": "127.0.0.1", "port": 62789, "protocol": "tunnel", "settings": {"rewriteAddress": "127.0.0.1"}, "tag": "api"}],
    "log": {"access": "none", "dnsLog": False, "error": "", "loglevel": "warning", "maskAddress": ""},
    "metrics": {"listen": "127.0.0.1:11111", "tag": "metrics_out"},
    "outbounds": [{"protocol": "freedom", "tag": "direct", "settings": {"finalRules": [{"action": "block", "ip": ["geoip:private"]}, {"action": "allow"}]}},
                  {"protocol": "blackhole", "settings": {}, "tag": "blocked"}],
    "policy": {"levels": {"0": {"statsUserDownlink": True, "statsUserUplink": True}},
               "system": {"statsInboundDownlink": True, "statsInboundUplink": True, "statsOutboundDownlink": False, "statsOutboundUplink": False}},
    "routing": {"domainStrategy": "AsIs", "rules": [{"inboundTag": ["api"], "outboundTag": "api", "type": "field"},
        {"ip": ["geoip:private"], "outboundTag": "blocked", "type": "field"},
        {"outboundTag": "blocked", "protocol": ["bittorrent"], "type": "field"}]},
    "stats": {}}
profiles = {"2": {"address": "https://cloudflare-dns.com/dns-query", "hosts": {"cloudflare-dns.com": "1.1.1.1", "one.one.one.one": "1.1.1.1"}},
            "3": {"address": "https://dns.google/dns-query", "hosts": {"dns.google": "8.8.8.8"}},
            "4": {"address": "https://dns.quad9.net/dns-query", "hosts": {"dns.quad9.net": "9.9.9.9"}}}
if choice == "5":
    if not domain or not ip4: raise SystemExit("self-hosted DoH needs panel domain and IP")
    profiles["5"] = {"address": "https://%s/dns-query" % domain, "hosts": {domain: ip4}}
if choice == "6":
    if not custom_url or not custom_host or not custom_ip: raise SystemExit("custom DoH missing host/ip")
    profiles["6"] = {"address": custom_url, "hosts": {custom_host: custom_ip}}
def set_direct_freedom_strategy(cfg, strategy, he):
    outs = cfg.get("outbounds")
    if not isinstance(outs, list): outs = []; cfg["outbounds"] = outs
    direct = None; tag_taken = False
    for ob in outs:
        if not isinstance(ob, dict): continue
        if str(ob.get("protocol", "")).lower() == "freedom" and ob.get("tag") == "direct":
            direct = ob; break
        if ob.get("tag") == "direct": tag_taken = True
    if direct is None:
        if tag_taken: raise SystemExit("tag 'direct' is taken by a non-freedom outbound")
        direct = {"protocol": "freedom", "tag": "direct", "settings": {}}; outs.append(direct)
    settings = direct.get("settings") if isinstance(direct.get("settings"), dict) else {}
    for k in ("domainStrategy", "targetStrategy"): settings.pop(k, None)
    direct["settings"] = settings; direct.pop("targetStrategy", None)
    stream = direct.get("streamSettings") if isinstance(direct.get("streamSettings"), dict) else {}
    sockopt = stream.get("sockopt") if isinstance(stream.get("sockopt"), dict) else {}
    sockopt["domainStrategy"] = strategy
    if he: sockopt["happyEyeballs"] = {"tryDelayMs": 250, "prioritizeIPv6": False, "interleave": 1, "maxConcurrentTry": 4}
    else: sockopt.pop("happyEyeballs", None)
    stream["sockopt"] = sockopt
    direct["streamSettings"] = stream
con = sqlite3.connect(db, timeout=30); cur = con.cursor()
row = cur.execute("SELECT value FROM settings WHERE key='xrayTemplateConfig' ORDER BY id DESC LIMIT 1").fetchone()
try:
    cfg = json.loads(row[0]) if row and row[0] else DEFAULT
    if isinstance(cfg, str): cfg = json.loads(cfg)
except Exception:
    cfg = DEFAULT
if not isinstance(cfg, dict): cfg = DEFAULT
prof = profiles[choice]
routing = cfg.get("routing") if isinstance(cfg.get("routing"), dict) else {}
routing["domainStrategy"] = "IPIfNonMatch"; cfg["routing"] = routing
set_direct_freedom_strategy(cfg, freedom_strat, enable_he == "1")
cfg["dns"] = {"tag": "dns_inbound", "queryStrategy": qstrat, "disableCache": False, "disableFallback": True, "disableFallbackIfMatch": True,
    "useSystemHosts": False, "enableParallelQuery": False, "serveStale": False, "serveExpiredTTL": 0,
    "hosts": prof["hosts"],
    "servers": [{"address": prof["address"], "skipFallback": True, "queryStrategy": qstrat, "timeoutMs": 4000}]}
cfg["fakedns"] = None
cur.execute("DELETE FROM settings WHERE key='xrayTemplateConfig'")
cur.execute("INSERT INTO settings (key, value) VALUES ('xrayTemplateConfig', ?)", (json.dumps(cfg, ensure_ascii=False, indent=2),))
con.commit()
con.close()
PY
    [[ $? -eq 0 ]] || { msg_err "Failed to write xrayTemplateConfig (DNS)."; return 1; }
    msg_ok "Xray DNS saved (option ${dns_mode})."
}

# ─── Hysteria 2 ──────────────────────────────────────────────────────────────
insert_hy2_inbound() {
    [[ "$DEPLOY_HY2" == 1 && -n "$hy2_port" ]] || return 0
    [[ -f $XUIDB ]] || { msg_err "x-ui.db not found — cannot add Hysteria2 inbound."; return 1; }
    local salamander_pass
    salamander_pass=$(gen_random_string 16 | tr '[:upper:]' '[:lower:]')
    systemctl stop x-ui 2>/dev/null || true
    python3 - "$XUIDB" "$hy2_port" "$salamander_pass" "$domain" "$(gen_group_id)" "${EMOJI_FLAG:-🌐}" <<'PY'
import json, sqlite3, sys
db, port, salamander, domain, group_id, flag = sys.argv[1:7]
port = int(port)
cert = "/root/cert/%s/fullchain.pem" % domain
key = "/root/cert/%s/privkey.pem" % domain
settings = {"version": 2, "clients": []}
stream = {
    "network": "hysteria",
    "security": "tls",
    "hysteriaSettings": {"version": 2, "udpIdleTimeout": 60},
    "tlsSettings": {
        "serverName": domain, "minVersion": "1.2", "maxVersion": "1.3", "cipherSuites": "",
        "rejectUnknownSni": False, "disableSystemRoot": False, "enableSessionResumption": False, "alpn": ["h3"],
        "certificates": [{"useFile": True, "certificateFile": cert, "keyFile": key, "certificate": [], "key": [],
                          "ocspStapling": 0, "oneTimeLoading": False, "usage": "encipherment", "buildChain": False}],
        "settings": {"fingerprint": "", "echConfigList": "", "pinnedPeerCertSha256": [], "verifyPeerCertByName": ""},
    },
    "finalmask": {"tcp": [], "udp": [{"type": "salamander", "settings": {"password": salamander}}]},
}
sniffing = {"enabled": True, "destOverride": ["http", "tls", "quic", "fakedns"], "metadataOnly": False, "routeOnly": False}
con = sqlite3.connect(db, timeout=30)
cur = con.execute(
    "INSERT INTO inbounds (user_id, up, down, total, remark, enable, expiry_time, listen, port, protocol, settings, stream_settings, tag, sniffing)"
    " VALUES (1, 0, 0, 0, ?, 1, 0, '', ?, 'hysteria', ?, ?, ?, ?)",
    (("%s hy2" % flag).strip(), port, json.dumps(settings), json.dumps(stream, indent=2), "inbound-%s" % port, json.dumps(sniffing)))
con.execute(
    "INSERT INTO hosts (inbound_id, group_id, sort_order, remark, address, port, security, fingerprint, alpn)"
    " VALUES (?, ?, 0, 'hy2', ?, ?, 'same', '', '[]')", (cur.lastrowid, group_id, domain, port))
con.commit()
con.close()
PY
    [[ $? -eq 0 ]] || { msg_err "Failed to insert Hysteria2 inbound."; return 1; }
    msg_ok "Inbound Hysteria2 created (UDP ${hy2_port})."
}

# ─── Cover site ──────────────────────────────────────────────────────────────
install_cover_generator() {
    local archive cached="${COVER_GENERATOR_DIR}/.package-sha256"
    if [[ -f "$cached" && -f "$COVER_GENERATOR_DIR/generator.py" && "$(cat "$cached")" == "$COVER_GENERATOR_SHA256" ]]; then
        return 0
    fi
    archive=$(mktemp) || return 1
    if ! curl -fSL --connect-timeout 15 --max-time 120 --retry 2 \
        "${GITHUB_RAW}/assets/cover-generator/cover-generator-v1.tar.gz" -o "$archive"; then
        rm -f "$archive"
        msg_err "Failed to download the cover generator."
        return 1
    fi
    if ! python3 - "$archive" "$COVER_GENERATOR_DIR" "$COVER_GENERATOR_SHA256" <<'PY_COVER_PACKAGE'
from pathlib import Path, PurePosixPath
import hashlib, shutil, sys, tarfile, tempfile
archive, destination, expected = Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3]
if hashlib.sha256(archive.read_bytes()).hexdigest() != expected:
    raise SystemExit('Cover package checksum mismatch')
if destination.is_symlink():
    raise SystemExit('Cover source directory is a symlink')
destination.parent.mkdir(parents=True, exist_ok=True)
stage = Path(tempfile.mkdtemp(prefix='.cover-source-', dir=destination.parent))
try:
    with tarfile.open(archive, 'r:gz') as bundle:
        members = bundle.getmembers()
        for member in members:
            name = PurePosixPath(member.name)
            if name.is_absolute() or '..' in name.parts or '\\' in member.name or not (member.isfile() or member.isdir()):
                raise ValueError('Unsafe cover package member')
        # Extract only regular files/directories; never links/devices.
        for member in members:
            target = stage / member.name
            target.parent.mkdir(parents=True, exist_ok=True)
            if member.isdir():
                target.mkdir(exist_ok=True)
            else:
                with bundle.extractfile(member) as source, target.open('wb') as output:
                    shutil.copyfileobj(source, output)
                target.chmod(0o644)
    for required in ('generator.py', 'manifest.json', 'content/topics.json', 'content/names.json'):
        if not (stage / required).is_file():
            raise ValueError('Incomplete cover package')
    for directory in [stage] + [p for p in stage.rglob('*') if p.is_dir()]:
        directory.chmod(0o755)
    (stage / '.package-sha256').write_text(expected + '\n', encoding='ascii')
    if destination.exists():
        shutil.rmtree(destination)
    stage.rename(destination)
finally:
    if stage.exists(): shutil.rmtree(stage)
PY_COVER_PACKAGE
    then
        rm -f "$archive"
        msg_err "Cover generator package validation failed."
        return 1
    fi
    rm -f "$archive"
}

cover() { python3 "$COVER_GENERATOR_DIR/generator.py" "$@" --state "$COVER_STATE"; }

install_cover_site() {
    install_cover_generator || return 1
    cover generate || return 1
    cover check || return 1
    chown -R www-data:www-data /var/www/html || return 1
    msg_ok "Local cover site generated and checked."
}

cleanup_cover_site() {
    [[ -f "$COVER_STATE" ]] || return 0
    [[ -f "$COVER_GENERATOR_DIR/generator.py" ]] || {
        msg_err "Cover cleanup helper is missing. Restore generator sources before full removal."
        return 1
    }
    cover cleanup
}

# ─── Extra geodata: ROSCOM and RUNET next to the stock files ─────────────────
GEO_UPDATER="${LIB_DIR}/geo-update.sh"

install_extra_geo() {
    install -d -m 0755 "$LIB_DIR"
    cat > "$GEO_UPDATER" <<'XA_GEO_UPDATE'
#!/bin/bash
# Keeps geoip/geosite ROSCOM and RUNET in the panel bin folder. Never restarts xray: it reads geodata
# at start, so new files apply at the next x-ui restart (certificate renewal, panel update, settings change).
set -u
DEST=/usr/local/x-ui/bin
GH=https://github.com
RAW=https://raw.githubusercontent.com
CDN=https://cdn.jsdelivr.net/gh
failed=0

# fetch NAME URL FALLBACK: download, reject HTML/short files, replace only on change.
fetch() {
    local name=$1 tmp="$DEST/.$1.tmp" url size
    for url in "$2" "$3"; do
        rm -f "$tmp"
        curl -fsSL --retry 3 --connect-timeout 15 --max-time 600 "$url" -o "$tmp" || continue
        size=$(stat -c %s "$tmp")
        head -c 64 "$tmp" | tr -d '\0' | grep -qiE '<html|<!doctype|^Not Found|^404' && continue
        (( size >= 50000 )) || continue
        if cmp -s "$tmp" "$DEST/$name"; then rm -f "$tmp"; echo "$name: up to date"; return 0; fi
        chmod 0644 "$tmp" && mv -f "$tmp" "$DEST/$name" && echo "$name: updated ($size bytes)" && return 0
    done
    rm -f "$tmp"
    echo "$name: download failed, keeping the current file" >&2
    failed=1
}

[[ -d "$DEST" ]] || exit 0
fetch geoip_ROSCOM.dat "$GH/hydraponique/roscomvpn-geoip/releases/latest/download/geoip.dat" "$CDN/hydraponique/roscomvpn-geoip/release/geoip.dat"
fetch geosite_ROSCOM.dat "$GH/hydraponique/roscomvpn-geosite/releases/latest/download/geosite.dat" "$CDN/hydraponique/roscomvpn-geosite/release/geosite.dat"
fetch geoip_RUNET.dat "$RAW/runetfreedom/russia-v2ray-rules-dat/release/geoip.dat" "$GH/runetfreedom/russia-v2ray-rules-dat/raw/release/geoip.dat"
fetch geosite_RUNET.dat "$RAW/runetfreedom/russia-v2ray-rules-dat/release/geosite.dat" "$GH/runetfreedom/russia-v2ray-rules-dat/raw/release/geosite.dat"
exit $failed
XA_GEO_UPDATE
    chmod 0755 "$GEO_UPDATER"
    cat > /etc/systemd/system/xa-geo-update.service <<EOF
[Unit]
Description=Update ROSCOM and RUNET geodata for 3x-ui
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=${GEO_UPDATER}
EOF
    # Weekly, at night, like the stock geodata schedule of lucx-ui-pro.
    cat > /etc/systemd/system/xa-geo-update.timer <<'EOF'
[Unit]
Description=Weekly ROSCOM and RUNET geodata update

[Timer]
OnCalendar=Sun *-*-* 04:00:00
RandomizedDelaySec=30min
Persistent=true

[Install]
WantedBy=timers.target
EOF
    msg_inf "Загружаю гео ROSCOM и RUNET..."
    "$GEO_UPDATER" || { msg_err "Не удалось загрузить гео ROSCOM/RUNET."; return 1; }
    systemctl daemon-reload && systemctl enable --now xa-geo-update.timer >/dev/null 2>&1 || return 1
    msg_ok "Гео ROSCOM и RUNET установлены, обновление раз в неделю."
}

# ─── AdGuard Home ────────────────────────────────────────────────────────────
uninstall_adguard() {
    local quiet="${1:-}" had_adguard=0 dns_state answer
    [[ -d /opt/AdGuardHome || -f /etc/nginx/snippets/adguard.conf || -f "$ADGUARD_INFO" ]] && had_adguard=1
    if [[ "$quiet" != quiet && $had_adguard == 1 && -f "$XUIDB" ]]; then
        dns_state=$(python3 - "$XUIDB" "$STATE_DIR/domains" <<'PY_ADGUARD_DNS_DEPENDENCY'
from contextlib import closing
import json, sqlite3, sys
from pathlib import Path
from urllib.parse import urlsplit
domains = set(Path(sys.argv[2]).read_text().lower().split())
with closing(sqlite3.connect(Path(sys.argv[1]).as_uri() + '?mode=ro', uri=True)) as db:
    row = db.execute("SELECT value FROM settings WHERE key='xrayTemplateConfig' ORDER BY id DESC LIMIT 1").fetchone()
config = json.loads(row[0]) if row and row[0] else {}
if isinstance(config, str): config = json.loads(config)
dependent = False
for server in (config.get('dns') or {}).get('servers', []) or []:
    url = urlsplit(server if isinstance(server, str) else server.get('address', ''))
    dependent |= url.scheme == 'https' and url.hostname in domains and url.port in (None, 443) and url.path.rstrip('/') == '/dns-query'
print('dependent' if dependent else 'clear')
PY_ADGUARD_DNS_DEPENDENCY
        ) || { msg_err 'Не удалось проверить зависимость DNS Xray. AdGuard Home не удалён.'; return 1; }
        if [[ "$dns_state" != clear ]]; then
            msg_err 'Предупреждение: Xray использует DoH AdGuard Home. После удаления этот DNS перестанет работать.'
            msg_inf 'DNS в панели нужно будет сменить самостоятельно. Настройки Xray автоматически не изменяются.'
            ask_choice answer 'Удалить AdGuard Home?' 'Удалить' 'Отмена' || return 1
            [[ "$answer" == 1 ]] || { msg_inf 'Удаление AdGuard Home отменено.'; return 2; }
        fi
    fi
    systemctl stop AdGuardHome 2>/dev/null || true
    [[ -x /opt/AdGuardHome/AdGuardHome ]] && /opt/AdGuardHome/AdGuardHome -s uninstall 2>/dev/null || true
    rm -rf /opt/AdGuardHome /etc/nginx/snippets/adguard.conf "$ADGUARD_INFO"
    rm -f "$STATE_DIR/adguard-installed"
    for f in /etc/nginx/sites-available/*; do
        [[ -f "$f" ]] && sed -i '\|snippets/adguard.conf|d' "$f"
    done
    if command -v nginx >/dev/null 2>&1 && ! nginx -t &>/dev/null; then
        [[ "$quiet" == quiet ]] || msg_err "AdGuard Home удалён, но конфигурация nginx не прошла проверку."
        return 1
    fi
    command -v nginx >/dev/null 2>&1 && systemctl reload nginx 2>/dev/null || true
    [[ "$quiet" != quiet && $had_adguard -eq 1 ]] && msg_ok "AdGuard Home удалён."
    return 0
}

install_adguard() {
    local AGH_DIR=/opt/AdGuardHome AGH_YAML=/opt/AdGuardHome/AdGuardHome.yaml
    local AGH_SNIPPET=/etc/nginx/snippets/adguard.conf AGH_SERVICE=AdGuardHome
    local vhost agh_path agh_web_port agh_dns_port agh_arch agh_user agh_pass agh_hash agh_up=0 p
    [[ -n "${domain:-}" ]] || domain=$(head -1 "$STATE_DIR/domains" 2>/dev/null)
    vhost="/etc/nginx/sites-available/${domain}"
    [[ -n "$domain" && -f "$vhost" ]] || { msg_err 'Не найден vhost панели. Сначала установите панель.'; return 1; }
    [[ -n "${IP4:-}" ]] || get_server_ip
    agh_path=""
    [[ -f "$AGH_SNIPPET" ]] && agh_path=$(grep -oP 'location /\Kadg-[a-zA-Z0-9]+' "$AGH_SNIPPET" | head -1 || true)
    [[ -n "$agh_path" ]] || agh_path="adg-$(gen_random_string 12)"
    agh_web_port=""
    [[ -f "$AGH_YAML" ]] && agh_web_port=$(grep -oP '^\s*address:\s*127\.0\.0\.1:\K\d+' "$AGH_YAML" | head -1 || true)
    [[ -n "$agh_web_port" ]] || agh_web_port=$(make_port)
    agh_dns_port=$(make_port)
    apt-get install -y -q curl tar ca-certificates apache2-utils >/dev/null || return 1
    case "$(uname -m)" in x86_64) agh_arch="amd64";; aarch64) agh_arch="arm64";; armv7l) agh_arch="armv7";; *) msg_err "Unsupported architecture"; return 1;; esac
    if [[ ! -x "${AGH_DIR}/AdGuardHome" ]]; then
        mkdir -p /opt
        curl -fsSL "https://github.com/AdguardTeam/AdGuardHome/releases/latest/download/AdGuardHome_linux_${agh_arch}.tar.gz" | tar -xz -C /opt
        [[ -x "${AGH_DIR}/AdGuardHome" ]] || { msg_err "AdGuard Home download failed."; return 1; }
    fi
    agh_user="admin"; agh_pass=""
    if [[ ! -f "$AGH_YAML" ]]; then
        agh_pass=$(gen_random_string 20)
        agh_hash=$(htpasswd -nbB x "$agh_pass" | cut -d: -f2)
        [[ "$agh_hash" == \$2* ]] || { msg_err "bcrypt hash generation failed."; return 1; }
        systemctl stop "$AGH_SERVICE" 2>/dev/null || true
        cat > "$AGH_YAML" <<EOF
http:
  address: 127.0.0.1:${agh_web_port}
users:
  - name: ${agh_user}
    password: ${agh_hash}
auth_attempts: 5
block_auth_min: 15
theme: auto
dns:
  bind_hosts:
    - 127.0.0.1
  port: ${agh_dns_port}
  upstream_dns:
    - https://dns.cloudflare.com/dns-query
    - https://dns.google/dns-query
    - https://dns.quad9.net/dns-query
  bootstrap_dns:
    - 1.1.1.1
    - 8.8.8.8
    - 9.9.9.9
  trusted_proxies:
    - 127.0.0.0/8
tls:
  enabled: false
  allow_unencrypted_doh: true
filters:
  - enabled: true
    url: https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt
    name: AdGuard DNS filter
    id: 1
schema_version: 28
EOF
        chmod 600 "$AGH_YAML"
        (umask 077; printf 'AGH_USER=%s\nAGH_PASS=%s\nAGH_PATH=%s\nAGH_DOMAIN=%s\nAGH_IP=%s\n' \
            "$agh_user" "$agh_pass" "$agh_path" "$domain" "$IP4" > "$ADGUARD_INFO")
    fi
    if systemctl list-unit-files --type=service 2>/dev/null | grep -q "^${AGH_SERVICE}\.service"; then systemctl restart "$AGH_SERVICE"
    else "${AGH_DIR}/AdGuardHome" -s install >/dev/null 2>&1; fi
    for _ in $(seq 1 20); do curl -fso /dev/null "http://127.0.0.1:${agh_web_port}/" && { agh_up=1; break; }; sleep 0.5; done
    [[ $agh_up -eq 1 ]] || { msg_err "AdGuard Home did not start"; return 1; }
    cat > "$AGH_SNIPPET" <<EOF
    location /dns-query {
        proxy_pass http://127.0.0.1:${agh_web_port};
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        proxy_buffering off;
        access_log off;
    }
    location /${agh_path}/ {
        proxy_pass http://127.0.0.1:${agh_web_port}/;
        proxy_redirect / /${agh_path}/;
        proxy_cookie_path / /${agh_path}/;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
    }
    location = /${agh_path} { return 302 /${agh_path}/; }
EOF
    grep -q 'snippets/adguard.conf' "$vhost" ||
        sed -i 's|^\(\s*\)include /etc/nginx/snippets/includes.conf;|\1include /etc/nginx/snippets/adguard.conf;\n\1include /etc/nginx/snippets/includes.conf;|' "$vhost"
    nginx -t >/dev/null 2>&1 || { msg_err "AdGuard Home настроен, но проверка nginx завершилась с ошибкой."; nginx -t; return 1; }
    systemctl reload nginx || { msg_err "nginx не удалось перезагрузить."; return 1; }
    touch "$STATE_DIR/adguard-installed"
    msg_ok "AdGuard Home установлен."
}

print_adguard_results() {
    local AGH_PATH="" AGH_USER=admin AGH_PASS="" AGH_DOMAIN="${domain:-}" AGH_IP="${IP4:-}"
    [[ -f /etc/nginx/snippets/adguard.conf ]] || return 0
    # shellcheck disable=SC1090
    [[ -f "$ADGUARD_INFO" ]] && . "$ADGUARD_INFO"
    [[ -n "$AGH_PATH" ]] || AGH_PATH=$(grep -oP 'location /\Kadg-[a-zA-Z0-9]+' /etc/nginx/snippets/adguard.conf | head -1)
    [[ -n "$AGH_DOMAIN" ]] || return 0
    echo
    msg_inf '────────────────────────────────────────────────────────────────────────────────'
    echo -e "AdGuard Home:  https://${AGH_DOMAIN}/${AGH_PATH}/\n"
    echo -e "Login:         ${AGH_USER}\n"
    if [[ -n "$AGH_PASS" ]]; then echo -e "Password:      ${AGH_PASS}\n"
    else echo -e "Password:      (already set / bcrypt in AdGuardHome.yaml)\n"; fi
    echo -e "DoH:           https://${AGH_DOMAIN}/dns-query\n"
    echo -e "Hosts:         ${AGH_DOMAIN} ${AGH_IP}\n"
    msg_inf '────────────────────────────────────────────────────────────────────────────────'
}

# ─── Scanner and torrent guard (separate script) ─────────────────────────────
run_guard() {
    local script rc
    script=$(mktemp) || return 1
    if ! curl -fsSL --connect-timeout 15 --max-time 120 "${GITHUB_RAW}/guard.sh" -o "$script" || ! bash -n "$script"; then
        rm -f "$script"; msg_err "Не удалось скачать скрипт защиты."; return 1
    fi
    bash "$script" "$1" y
    rc=$?
    rm -f "$script"
    return $rc
}

# ─── BBR / FQ and kernel tuning ──────────────────────────────────────────────
# The panel owns BBR/FQ sysctl state in 99-bbr-x-ui.conf; we own module loading and other tuning.
XA_MODULES_FILE=/etc/modules-load.d/3x-ui-auto-network.conf
XA_TUNING_FILE=/etc/sysctl.d/99-zz-3x-ui-auto-tuning.conf
XA_BBR_FILE=/etc/sysctl.d/99-bbr-x-ui.conf

patch_panel_bbr_script() {
    local script
    for script in /usr/bin/x-ui /usr/local/x-ui/x-ui.sh; do
        [[ -f "$script" ]] || continue
        python3 - "$script" <<'PY_BBR_PATCH'
import sys
path=sys.argv[1]
text=open(path,encoding="utf-8",errors="surrogateescape").read()
old="""enable_bbr() {
    if [[ $(sysctl -n net.ipv4.tcp_congestion_control) == "bbr" ]] && [[ $(sysctl -n net.core.default_qdisc) =~ ^(fq|cake)$ ]]; then"""
new="""enable_bbr() {
    # 3x-ui-auto persists BBR/FQ modules; load them now so the toggle works before reboot.
    modprobe tcp_bbr >/dev/null 2>&1 || true
    modprobe sch_fq >/dev/null 2>&1 || true
    if [[ $(sysctl -n net.ipv4.tcp_congestion_control) == "bbr" ]] && [[ $(sysctl -n net.core.default_qdisc) =~ ^(fq|cake)$ ]]; then"""
if old in text and 'modprobe tcp_bbr >/dev/null 2>&1 || true' not in text:
    text=text.replace(old,new,1)
needle="""        {
            echo "#$(sysctl -n net.core.default_qdisc):$(sysctl -n net.ipv4.tcp_congestion_control)"
            echo "net.core.default_qdisc = fq"""
repl="""        mkdir -p /etc/x-ui
        printf '%s:%s\\n' "$(sysctl -n net.core.default_qdisc)" "$(sysctl -n net.ipv4.tcp_congestion_control)" > /etc/x-ui/.xa-bbr-restore
        {
            echo "#$(sysctl -n net.core.default_qdisc):$(sysctl -n net.ipv4.tcp_congestion_control)"
            echo "net.core.default_qdisc = fq"""
if needle in text and '/etc/x-ui/.xa-bbr-restore' not in text:
    text=text.replace(needle,repl,1)
# A disabled choice must survive reboot too.
start=text.find('disable_bbr() {')
end=text.find('\nenable_bbr()',start)
if start >= 0 and end > start:
    block=text[start:end]
    line="        old_settings=$(head -1 /etc/sysctl.d/99-bbr-x-ui.conf | tr -d '#')"
    fallback="""
        # 3X-UI-AUTO BBR disabled persistence
        if [[ "${old_settings#*:}" == "bbr" ]]; then
            modprobe tcp_cubic >/dev/null 2>&1 || true
            modprobe sch_fq_codel >/dev/null 2>&1 || true
            old_settings="fq_codel:cubic"
        fi"""
    if line in block and '3X-UI-AUTO BBR disabled persistence' not in block:
        block=block.replace(line,line+fallback,1)
    removal='        rm /etc/sysctl.d/99-bbr-x-ui.conf'
    persist=r"""        # Keep one panel-owned file for both enabled and disabled choices.
        printf '#%s\nnet.core.default_qdisc = %s\nnet.ipv4.tcp_congestion_control = %s\n' \
            "$old_settings" "${old_settings%:*}" "${old_settings#*:}" > /etc/sysctl.d/99-bbr-x-ui.conf"""
    if removal in block:
        block=block.replace(removal,persist,1)
    text=text[:start]+block+text[end:]
open(path,'w',encoding='utf-8',errors='surrogateescape').write(text)
PY_BBR_PATCH
        chmod +x "$script" 2>/dev/null || true
    done
}

persist_network_modules() {
    local modules=() qdisc_module
    mkdir -p /etc/modules-load.d
    # The panel may enable BBR later: persist what the kernel exposes.
    modprobe tcp_bbr 2>/dev/null && modules+=(tcp_bbr)
    modprobe sch_fq 2>/dev/null && modules+=(sch_fq)
    case "$(sysctl -n net.core.default_qdisc 2>/dev/null)" in
        fq_codel) qdisc_module=sch_fq_codel ;;
        cake)     qdisc_module=sch_cake ;;
        fq)       qdisc_module=sch_fq ;;
        *)        qdisc_module="" ;;
    esac
    [[ -n "$qdisc_module" ]] && modprobe "$qdisc_module" 2>/dev/null && modules+=("$qdisc_module")
    if [[ ${#modules[@]} -gt 0 ]]; then
        printf '%s\n' "${modules[@]}" | awk 'NF && !seen[$0]++' > "$XA_MODULES_FILE"
        chmod 0644 "$XA_MODULES_FILE"
    else
        rm -f "$XA_MODULES_FILE"
    fi
}

seed_panel_bbr_state() {
    local current_cc current_qdisc available_cc fallback_cc fallback_qdisc qdisc
    current_cc=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo cubic)
    current_qdisc=$(sysctl -n net.core.default_qdisc 2>/dev/null || echo fq_codel)
    available_cc=$(sysctl -n net.ipv4.tcp_available_congestion_control 2>/dev/null || true)
    # The user may already have chosen BBR on/off through the panel menu.
    [[ -f "$XA_BBR_FILE" ]] && return 0
    if grep -qw bbr <<< "$available_cc" || modprobe tcp_bbr 2>/dev/null; then
        if modprobe sch_fq 2>/dev/null &&
           sysctl -w net.ipv4.tcp_congestion_control=bbr >/dev/null 2>&1 &&
           sysctl -w net.core.default_qdisc=fq >/dev/null 2>&1; then
            mkdir -p /etc/sysctl.d /etc/x-ui
            # A pre-existing BBR runtime is not a usable disabled state.
            if [[ "$current_cc" == bbr ]]; then current_cc=cubic; current_qdisc=fq_codel; fi
            printf '%s:%s\n' "$current_qdisc" "$current_cc" > /etc/x-ui/.xa-bbr-restore
            printf '#%s:%s\nnet.core.default_qdisc = fq\nnet.ipv4.tcp_congestion_control = bbr\n' \
                "$current_qdisc" "$current_cc" > "$XA_BBR_FILE"
            chmod 0644 "$XA_BBR_FILE"
            sysctl -p "$XA_BBR_FILE" >/dev/null 2>&1 || return 1
            msg_ok "TCP tuning: BBR + fq enabled (panel-owned config)."
            return 0
        fi
    fi
    # BBR unavailable: leave the distro fallback, the panel can enable BBR later.
    available_cc=$(sysctl -n net.ipv4.tcp_available_congestion_control 2>/dev/null || true)
    if grep -qw cubic <<< "$available_cc"; then fallback_cc=cubic; else fallback_cc="$current_cc"; fi
    sysctl -w "net.ipv4.tcp_congestion_control=${fallback_cc}" >/dev/null 2>&1 || true
    modprobe sch_fq_codel 2>/dev/null || true
    fallback_qdisc=""
    for qdisc in fq_codel "$current_qdisc" pfifo_fast; do
        sysctl -w "net.core.default_qdisc=${qdisc}" >/dev/null 2>&1 && { fallback_qdisc="$qdisc"; break; }
    done
    msg_inf "BBR is unavailable; using ${fallback_cc} + ${fallback_qdisc:-current qdisc}."
}

configure_runtime_qdisc() {
    local helper=/usr/local/sbin/xa-apply-qdisc
    # default_qdisc affects only new qdiscs: apply it to the default-route interfaces at boot
    # and whenever the panel changes sysctl files.
    mkdir -p /usr/local/sbin
    cat > "$helper" <<'EOF'
#!/bin/bash
set -u
QDISC="$(sysctl -n net.core.default_qdisc 2>/dev/null || true)"
[[ -n "$QDISC" ]] || QDISC=fq_codel
get_default_ifaces() {
    ip -o route show default 2>/dev/null |
        awk '{ for (i = 1; i <= NF; i++) if ($i == "dev" && (i + 1) <= NF) { print $(i + 1); break } }' | sort -u
}
ifaces=""
for _attempt in 1 2 3 4 5 6 7 8 9 10; do
    ifaces=$(get_default_ifaces)
    [[ -n "$ifaces" ]] && break
    sleep 2
done
[[ -n "$ifaces" ]] || exit 1
status=0
while IFS= read -r iface; do
    [[ -n "$iface" && -e "/sys/class/net/$iface" ]] || continue
    tc qdisc replace dev "$iface" root "$QDISC" || status=1
done <<< "$ifaces"
exit "$status"
EOF
    chmod 0755 "$helper"
    cat > /etc/systemd/system/xa-apply-qdisc.service <<'EOF'
[Unit]
Description=Apply the selected qdisc to default-route interfaces
Wants=network-online.target
After=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/xa-apply-qdisc
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
    cat > /etc/systemd/system/xa-qdisc-sync.service <<'EOF'
[Unit]
Description=Sync qdisc after sysctl policy changes
Wants=network-online.target
After=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/xa-apply-qdisc
EOF
    cat > /etc/systemd/system/xa-qdisc-sync.path <<'EOF'
[Unit]
Description=Watch sysctl policy for qdisc changes

[Path]
PathChanged=/etc/sysctl.d
Unit=xa-qdisc-sync.service

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable xa-apply-qdisc.service >/dev/null 2>&1 || return 1
    systemctl enable --now xa-qdisc-sync.path >/dev/null 2>&1 || return 1
    "$helper"
}

tune_system() {
    local active_cc active_qdisc iface iface_qdisc
    persist_network_modules
    seed_panel_bbr_state || return 1
    persist_network_modules
    # Keep BBR/FQ out of sysctl.conf so the panel remains the only persistent owner.
    touch /etc/sysctl.conf
    sed -i -E -e '/^[[:space:]]*net\.core\.default_qdisc[[:space:]]*=/d' \
        -e '/^[[:space:]]*net\.ipv4\.tcp_congestion_control[[:space:]]*=/d' /etc/sysctl.conf
    printf '%s\n' "fs.file-max=2097152" "net.ipv4.tcp_timestamps=1" "net.ipv4.tcp_sack=1" \
        "net.ipv4.tcp_window_scaling=1" > "$XA_TUNING_FILE"
    sysctl -p "$XA_TUNING_FILE" >/dev/null || { msg_err "Failed to apply system tuning parameters."; return 1; }
    active_cc=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || true)
    active_qdisc=$(sysctl -n net.core.default_qdisc 2>/dev/null || true)
    configure_runtime_qdisc || { msg_err "Failed to apply the current qdisc to the default-route interface."; return 1; }
    while IFS= read -r iface; do
        [[ -n "$iface" ]] || continue
        iface_qdisc=$(tc qdisc show dev "$iface" 2>/dev/null | awk '$4 == "root" { print $2; exit }')
        [[ "$iface_qdisc" == "$active_qdisc" ]] || {
            msg_err "Qdisc verification failed on ${iface}: expected ${active_qdisc}, got ${iface_qdisc:-unknown}."
            return 1
        }
    done < <(ip -o route show default 2>/dev/null |
        awk '{ for (i = 1; i <= NF; i++) if ($i == "dev" && (i + 1) <= NF) { print $(i + 1); break } }' | sort -u)
    msg_ok "TCP tuning verified: ${active_cc} + ${active_qdisc}."
}

# ─── Certificate renewal ─────────────────────────────────────────────────────
CERT_CRON='0 1 * * * certbot renew --non-interactive --pre-hook "systemctl stop nginx" --deploy-hook "systemctl restart x-ui" --post-hook "systemctl start nginx" >/dev/null 2>&1'

setup_cron() {
    local saved next
    saved=$(mktemp -d) || return 1
    save_renewal_state "$saved" || { rm -rf -- "$saved"; return 1; }
    next="$saved/next-crontab"
    # Write the complete table once; preserve unrelated jobs and comments.
    awk -v cert="$CERT_CRON" '$0 != cert' "$saved/root-crontab" > "$next" && printf '%s\n' "$CERT_CRON" >> "$next" || {
        rm -rf -- "$saved"; return 1;
    }
    if ! { systemctl enable --now cron && systemctl mask --now certbot.timer && crontab "$next"; }; then
        restore_renewal_state "$saved" || msg_err 'Не удалось полностью восстановить планировщик сертификатов.'
        rm -rf -- "$saved"
        return 1
    fi
    rm -rf -- "$saved"
}

remove_cron_job() {
    local file
    command -v crontab >/dev/null 2>&1 || return 0
    file=$(mktemp) || return 1
    crontab -l 2>/dev/null | awk -v cert="$CERT_CRON" '$0 != cert' > "$file"
    crontab "$file"
    rm -f "$file"
}

# ─── Results ─────────────────────────────────────────────────────────────────
show_results() {
    clear
    if systemctl is-active --quiet x-ui && systemctl is-active --quiet nginx && nginx -t >/dev/null 2>&1; then
        msg_inf "────────────────────────────────────────────────────────────────────────────────"
        msg_inf "3x-ui ${PANEL_TAG:-}: https://${domain}/${panel_path}/\n"
        echo -e "Username:  ${config_username}\n"
        echo -e "Password:  ${config_password}\n"
        msg_inf "────────────────────────────────────────────────────────────────────────────────"
        echo -e "Подписка:  https://${domain}/${sub_path}/<subId>"
        echo -e "JSON:      https://${domain}/${json_path}/<subId>"
        echo -e "Mihomo:    https://${domain}/mihomo/<subId>"
        [[ "$DEPLOY_HY2" == 1 ]] && echo -e "Hysteria 2: ${domain}:${hy2_port}/udp"
        print_adguard_results
        [[ -x "$GUARD_SELF" ]] && bash "$GUARD_SELF" -status y
        msg_inf "Please save this screen!"
        return 0
    fi
    nginx -t
    msg_err "x-ui or nginx check failed. Try on a clean Linux install."
    return 1
}

# ─── Uninstall ───────────────────────────────────────────────────────────────
uninstall_xui() {
    local dir="$STATE_DIR"
    [[ -f "$dir/owned-by-3x-ui-auto" && -f "$dir/existing-paths" ]] || {
        msg_err "Ownership snapshot missing. Cannot safely uninstall a foreign installation."
        return 1
    }
    msg_inf "Начинаю удаление 3x-ui..."
    run_log_policy remove || true
    cleanup_cover_site || return 1
    systemctl stop x-ui nginx AdGuardHome xa-clash-sub xa-apply-qdisc xa-qdisc-sync.path 2>/dev/null || true
    if [[ -f "$dir/guard-installed" && -x "$GUARD_SELF" ]]; then
        msg_inf "Удаляю защиту от сканеров и торрентов..."
        bash "$GUARD_SELF" -uninstall y || msg_err "Не удалось полностью удалить защиту."
    fi
    if [[ -f "$dir/adguard-installed" ]]; then
        msg_inf "Удаляю AdGuard Home..."
        uninstall_adguard quiet || msg_err "Не удалось полностью удалить AdGuard Home."
    fi
    msg_inf "Отключаю службы и удаляю задание продления сертификата..."
    systemctl disable --now xa-geo-update.timer 2>/dev/null || true
    systemctl disable x-ui AdGuardHome xa-clash-sub xa-apply-qdisc xa-qdisc-sync.path 2>/dev/null || true
    remove_cron_job
    # fail2ban jail and filters installed by the panel's own setup.
    rm -f /etc/fail2ban/jail.d/3x-ipl.conf /etc/fail2ban/filter.d/3x-ipl.conf /etc/fail2ban/action.d/3x-ipl.conf
    msg_inf "Удаляю файлы панели и созданные конфигурации..."
    rm -rf /etc/x-ui /usr/local/x-ui /var/log/x-ui /opt/AdGuardHome "$ADGUARD_INFO" \
           /etc/systemd/system/x-ui.service.d "$COVER_GENERATOR_DIR"
    rm -f /usr/bin/x-ui /etc/systemd/system/x-ui.service /etc/systemd/system/AdGuardHome.service \
          /etc/systemd/system/xa-clash-sub.service /etc/systemd/system/xa-apply-qdisc.service \
          /etc/systemd/system/xa-qdisc-sync.service /etc/systemd/system/xa-qdisc-sync.path \
          /etc/systemd/system/xa-geo-update.service /etc/systemd/system/xa-geo-update.timer "$GEO_UPDATER" \
          /usr/local/sbin/xa-apply-qdisc "${LIB_DIR}/clash-sub-server.py" "${LIB_DIR}/log-policy.py" \
          /etc/x-ui/.xa-bbr-restore /var/log/3x-ui-auto-panel-install.log
    rm -f "/etc/nginx/sites-enabled/$(cat "$dir/domains")" "/etc/nginx/sites-available/$(cat "$dir/domains")" \
          /etc/nginx/sites-enabled/80.conf /etc/nginx/sites-available/80.conf \
          /etc/nginx/sites-enabled/00-clash-maps.conf /etc/nginx/sites-available/00-clash-maps.conf \
          /etc/nginx/stream-enabled/stream.conf /etc/nginx/snippets/includes.conf \
          /etc/nginx/snippets/adguard.conf /var/www/subpage/clash.yaml.tpl
    systemctl daemon-reload 2>/dev/null || true
    msg_inf "Сертификаты сайтов и данные их продления сохраняются."
    restore_preinstall_state || return 1
    rm -rf -- "$dir"
    rmdir "$LIB_DIR" /var/lib/3x-ui-auto 2>/dev/null || true
    msg_ok "Удаление 3x-ui завершено."
}

existing_install_detected() {
    [[ -e /etc/x-ui || -e /usr/local/x-ui || -e /usr/bin/x-ui || -e /etc/systemd/system/x-ui.service || -e "$STATE_DIR" ]]
}

confirm_reinstall() {
    local answer
    ask_choice answer 'Ваша панель и все её данные будут безвозвратно удалены. Продолжить?' 'Да' 'Нет' || return 1
    [[ "$answer" == 1 ]]
}

# ─── Main ────────────────────────────────────────────────────────────────────
main() {
    local step
    choose_domain || return 1
    choose_adguard || return 1
    choose_xray_dns || return 1
    choose_hy2 || return 1
    choose_guard || return 1

    save_preinstall_state || return 1
    : > "$INSTALL_IN_PROGRESS_FILE"
    for step in install_packages get_ssl_certs setup_firewall install_panel install_clash_subscription \
                configure_nginx "run_log_policy install" configure_xui_db apply_xray_template insert_hy2_inbound \
                install_cover_site install_extra_geo tune_system patch_panel_bbr_script setup_cron; do
        $step || return 1
    done
    if [[ "$DEPLOY_AGH" == 1 ]]; then install_adguard || return 1; fi
    systemctl enable x-ui >/dev/null 2>&1
    restart_xui_wait || return 1
    nginx -t && systemctl reload nginx || return 1
    if [[ "$DEPLOY_GUARD" == 1 ]]; then
        run_guard -install || return 1
        touch "$STATE_DIR/guard-installed"
    fi
    show_results || return 1
    rm -f "$INSTALL_IN_PROGRESS_FILE"
}

if [[ "$UNINSTALL" == y ]]; then
    uninstall_xui || exit 1
    exit 0
fi

if [[ "$ADGUARD_ONLY" == y || "$ADGUARD_UNINSTALL" == y ]]; then
    [[ -f "$STATE_DIR/owned-by-3x-ui-auto" ]] || { msg_err 'Сначала установите панель через 3x-ui-auto.'; exit 1; }
    domain=$(head -1 "$STATE_DIR/domains")
    if [[ "$ADGUARD_UNINSTALL" == y ]]; then
        uninstall_adguard
        [[ $? != 1 ]] || exit 1
        exit 0
    fi
    install_adguard && print_adguard_results || exit 1
    exit 0
fi

if existing_install_detected; then
    [[ -f "$STATE_DIR/owned-by-3x-ui-auto" ]] || {
        msg_err "Found a panel not installed by 3x-ui-auto; refusing to remove it automatically."
        exit 1
    }
    if ! confirm_reinstall; then
        msg_inf "Повторная установка отменена. Панель не изменена."
        exit 0
    fi
    uninstall_xui || exit 1
    msg_ok "Previous installation completely removed."
fi

if ! main; then
    msg_err "Установка остановлена из-за ошибки. Проверьте сообщения выше."
    exit 1
fi
