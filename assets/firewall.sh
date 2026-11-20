#!/bin/bash
# The project's port policy and Fail2ban action for the panel's IP Limit.
set -euo pipefail

CONFIG=/etc/3x-ui-auto/firewall.nft
UNIT=3x-ui-auto-firewall.service
UNIT_PATH=/etc/systemd/system/$UNIT

ssh_ports() {
    {
        sshd -T 2>/dev/null | awk '$1=="port" {print $2}' || true
        awk 'NF==4 {print $4}' <<<"${SSH_CONNECTION:-}"
    } | sort -un
}

install_firewall() (
    local ssh udp=${1:-} tmp udp_rule=''
    ssh=$(ssh_ports | paste -sd, -)
    ssh=${ssh:-22}
    [[ "$ssh" =~ ^[0-9]+(,[0-9]+)*$ && "$udp" =~ ^([0-9]+(,[0-9]+)*)?$ ]]
    [[ -z "$udp" ]] || udp_rule="udp dport { $udp } accept"
    install -d -m 0755 "$(dirname "$CONFIG")"
    tmp=$(mktemp "${CONFIG}.XXXXXX")
    trap 'rm -f -- "$tmp"' EXIT
    cat >"$tmp" <<EOF
add table inet xa_host
delete table inet xa_host
table inet xa_host {
    chain input {
        type filter hook input priority filter; policy drop;
        iifname "lo" accept
        ct state established,related accept
        ct state invalid drop
        meta l4proto { icmp, ipv6-icmp } accept
        meta nfproto ipv4 udp sport 67 udp dport 68 accept
        meta nfproto ipv6 udp sport 547 udp dport 546 accept
        tcp dport { $ssh, 80, 443 } accept
        $udp_rule
    }
}
EOF
    nft -c -f "$tmp"
    install -m 0644 "$tmp" "$CONFIG"
    cat >"$UNIT_PATH" <<EOF
[Unit]
Description=3x-ui-auto ingress firewall
After=nftables.service
Before=network-pre.target
Wants=network-pre.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/sbin/nft -f $CONFIG
ExecReload=/usr/sbin/nft -f $CONFIG
ExecStop=-/usr/sbin/nft delete table inet xa_host

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable "$UNIT"
    systemctl reload-or-restart "$UNIT"
)

remove_firewall() {
    if [[ -f "$UNIT_PATH" ]]; then
        systemctl disable --now "$UNIT"
    fi
    if command -v nft >/dev/null && nft list table inet xa_host >/dev/null 2>&1; then
        nft delete table inet xa_host
    fi
    rm -f -- "$UNIT_PATH" "$CONFIG"
    systemctl daemon-reload
    rmdir /etc/3x-ui-auto 2>/dev/null || true
}

configure_iplimit() {
    local panel=${1:-} ssh exempt check
    local sshd_override=/etc/fail2ban/jail.d/99-3x-ui-auto-sshd-journal.local
    ssh=$(ssh_ports | paste -sd, -)
    exempt=${ssh:-22}${panel:+,$panel}
    [[ "$exempt" =~ ^[0-9]+(,[0-9]+)*$ ]]
    install -d -m 0755 /var/log/x-ui /etc/fail2ban/{jail,filter,action}.d
    touch /var/log/x-ui/{3xipl,3xipl-banned}.log
    if [[ ! -f /etc/fail2ban/jail.d/3x-ipl.conf ]]; then
        cat >/etc/fail2ban/jail.d/3x-ipl.conf <<'EOF'
[3x-ipl]
enabled = true
backend = polling
filter = 3x-ipl
action = 3x-ipl
logpath = /var/log/x-ui/3xipl.log
maxretry = 1
findtime = 32
bantime = 30m
EOF
    fi
    cat >/etc/fail2ban/filter.d/3x-ipl.conf <<'EOF'
[Definition]
datepattern = ^%%Y/%%m/%%d %%H:%%M:%%S
failregex = \[LIMIT_IP\]\s*Email\s*=\s*<F-USER>.+</F-USER>\s*\|\|\s*Disconnecting OLD IP\s*=\s*<ADDR>\s*\|\|\s*Timestamp\s*=\s*\d+
EOF
    cat >/etc/fail2ban/action.d/3x-ipl.conf <<'EOF'
[INCLUDES]
before = nftables.conf

[Definition]
type = custom
rule_match-custom = meta l4proto \{ tcp, udp \} th dport != \{ <exemptports> \}
actionban = <nftables> add element <table_family> <table> <addr_set> \{ <ip> \} && echo "$(date +"%%Y/%%m/%%d %%H:%%M:%%S") BAN [Email] = <F-USER> [IP] = <ip> banned for <bantime> seconds." >> /var/log/x-ui/3xipl-banned.log
actionunban = <nftables> delete element <table_family> <table> <addr_set> \{ <ip> \} && echo "$(date +"%%Y/%%m/%%d %%H:%%M:%%S") UNBAN [IP] = <ip> unbanned." >> /var/log/x-ui/3xipl-banned.log

[Init]
table = xa_iplimit
chain = input
blocktype = drop
EOF
    printf 'exemptports = %s\n' "$exempt" >>/etc/fail2ban/action.d/3x-ipl.conf
    if check=$(LC_ALL=C fail2ban-client -t 2>&1); then
        printf '%s\n' "$check"
        return 0
    fi
    if [[ "$check" != *'Have not found any log file for sshd jail'* || -e "$sshd_override" || -L "$sshd_override" ]]; then
        printf '%s\n' "$check" >&2
        return 1
    fi
    printf '[sshd]\nbackend = systemd\n' >"$sshd_override"
    if ! fail2ban-client -t; then
        rm -f -- "$sshd_override"
        return 1
    fi
}

case ${1:-} in
    install) install_firewall "${2:-}" ;;
    remove) remove_firewall ;;
    iplimit) configure_iplimit "${2:-}" ;;
    *) exit 2 ;;
esac
