#!/usr/bin/env bash
# 3x-ui-backup.sh — backup and restore a 3x-ui-auto installation: panel, nginx, certificates, modules.
# Usage:
#   3x-ui-backup.sh backup           — create timestamped backup
#   3x-ui-backup.sh restore <file>   — restore from backup archive (installs packages first)
#   3x-ui-backup.sh list             — list available backups
export DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=l NEEDRESTART_SUSPEND=1
set -Eeuo pipefail
umask 077

BACKUP_STORE="/var/backups/x-ui"
REPO_RAW=https://raw.githubusercontent.com/ttrroyy/3x-ui-auto/main
PACKAGES="ca-certificates curl wget jq bash sudo openssl nginx-full certbot python3-certbot-nginx sqlite3 nftables python3 cron iproute2 fail2ban logrotate tar psmisc"

BACKUP_PATHS=(
    /etc/nginx /etc/x-ui /etc/default/x-ui /etc/fail2ban /etc/cron.d
    /usr/local/x-ui /usr/bin/x-ui /usr/local/lib/3x-ui-auto /usr/local/sbin/xa-apply-qdisc
    /etc/letsencrypt /var/lib/letsencrypt /root/cert
    /var/www/html /var/www/3x-ui-auto-cover /var/www/subpage
    /opt/AdGuardHome /root/.3x-ui-auto-adguard-info
    /var/lib/3x-ui-auto /etc/3x-ui-auto
    /etc/sysctl.conf /etc/sysctl.d/99-bbr-x-ui.conf /etc/sysctl.d/99-zz-3x-ui-auto-tuning.conf
    /etc/modules-load.d/3x-ui-auto-network.conf
    /etc/logrotate.d/nginx /etc/systemd/journald.conf.d/99-3x-ui-auto-logs.conf
)

SYSTEMD_UNITS=(
    x-ui.service xa-clash-sub.service AdGuardHome.service
    xa-apply-qdisc.service xa-qdisc-sync.service xa-qdisc-sync.path
    xa-log-policy.service xa-log-policy.timer xa-geo-update.service xa-geo-update.timer
    3x-ui-auto-firewall.service 3x-ui-guard.service 3x-ui-guard-tick.service 3x-ui-guard-tick.timer
)
# Services whose enabled/active state is recorded and replayed, in start order.
SERVICES=(3x-ui-auto-firewall x-ui nginx xa-clash-sub AdGuardHome fail2ban xa-apply-qdisc xa-qdisc-sync.path xa-log-policy.timer xa-geo-update.timer
          3x-ui-guard 3x-ui-guard-tick.timer)

red()   { printf '\033[31m%s\033[0m\n' "$*"; }
green() { printf '\033[32m%s\033[0m\n' "$*"; }
blue()  { printf '\033[34m%s\033[0m\n' "$*"; }
die()   { red "ERROR: $*" >&2; exit 1; }

require_root() { [[ $EUID -eq 0 ]] || die "Run as root (sudo $0 $*)"; }
avail_kb() { df -Pk "$1" | awk 'NR==2 {print $4}'; }

# Staging must not live in /tmp: on newer Ubuntu /tmp is a small tmpfs.
make_staging() {
    install -d -m 0700 "${BACKUP_STORE}"
    mktemp -d "${BACKUP_STORE}/.$1-XXXXXX"
}

# ── backup ────────────────────────────────────────────────────────────────────
cmd_backup() {
    require_root
    local ts dest staging est_kb need_kb have_kb svc enabled active path xui_ver size
    ts=$(date +%Y%m%d-%H%M%S)
    dest="${BACKUP_STORE}/3x-ui-backup-${ts}.tar.gz"

    # Staging holds an uncompressed copy, the archive lands next to it.
    est_kb=$(du -skc "${BACKUP_PATHS[@]}" 2>/dev/null | awk 'END {print $1}' || true)
    need_kb=$(( est_kb * 2 + 102400 ))
    install -d -m 0700 "${BACKUP_STORE}"
    have_kb=$(avail_kb "${BACKUP_STORE}")
    (( have_kb >= need_kb )) || die "Not enough free space in ${BACKUP_STORE}: need ~$(( need_kb / 1024 )) MB, have $(( have_kb / 1024 )) MB"

    staging=$(make_staging staging)
    BACKUP_WAS_ACTIVE=0
    systemctl is-active --quiet x-ui && BACKUP_WAS_ACTIVE=1 || true
    BACKUP_STAGING="$staging"; BACKUP_DEST="$dest"
    trap 'if (( BACKUP_WAS_ACTIVE )); then systemctl start x-ui 2>/dev/null || true; fi; rm -rf -- "$BACKUP_STAGING" "${BACKUP_DEST}.partial"' EXIT

    blue "==> Stopping x-ui for consistent DB snapshot..."
    if (( BACKUP_WAS_ACTIVE )); then systemctl stop x-ui || die "Failed to stop x-ui for consistent backup"; fi

    : > "${staging}/services-state"
    for svc in "${SERVICES[@]}"; do
        enabled=0; active=0
        systemctl is-enabled --quiet "$svc" 2>/dev/null && enabled=1 || true
        systemctl is-active --quiet "$svc" 2>/dev/null && active=1 || true
        [[ "$svc" == x-ui ]] && active="$BACKUP_WAS_ACTIVE"
        printf '%s %s %s\n' "$svc" "$enabled" "$active" >> "${staging}/services-state"
    done

    blue "==> Collecting files..."
    for path in "${BACKUP_PATHS[@]}"; do
        [[ -e "$path" || -L "$path" ]] || continue
        mkdir -p "${staging}/files$(dirname "$path")"
        cp -a "$path" "${staging}/files${path}"
    done
    mkdir -p "${staging}/files/etc/systemd/system"
    for path in "${SYSTEMD_UNITS[@]}"; do
        [[ -f "/etc/systemd/system/${path}" ]] && cp -a "/etc/systemd/system/${path}" "${staging}/files/etc/systemd/system/"
    done
    [[ -d /etc/systemd/system/x-ui.service.d ]] && cp -a /etc/systemd/system/x-ui.service.d "${staging}/files/etc/systemd/system/"
    crontab -l > "${staging}/root-crontab" 2>/dev/null || true

    xui_ver=$(/usr/local/x-ui/x-ui -v 2>/dev/null | head -1 || echo unknown)
    printf '{\n  "created": "%s",\n  "hostname": "%s",\n  "x-ui": "%s",\n  "kernel": "%s"\n}\n' \
        "$ts" "$(hostname -f 2>/dev/null || hostname)" "$xui_ver" "$(uname -r)" > "${staging}/meta.json"

    blue "==> Restarting x-ui..."
    if (( BACKUP_WAS_ACTIVE )); then systemctl start x-ui || die "Failed to restart x-ui"; fi
    BACKUP_WAS_ACTIVE=0

    blue "==> Compressing..."
    tar -czf "${dest}.partial" -C "$staging" .
    mv -f "${dest}.partial" "$dest"
    chmod 0600 "$dest"
    (cd "$BACKUP_STORE" && sha256sum "$(basename "$dest")" > "$(basename "$dest").sha256")
    size=$(du -sh "$dest" | cut -f1)
    green "==> Backup saved: ${dest} (${size})"
}

# ── restore ───────────────────────────────────────────────────────────────────
# Reject archives with absolute paths, "..", links outside the tree or device files.
verify_backup_archive() {
    python3 - "$1" <<'PY'
import sys, tarfile
from pathlib import PurePosixPath
total = 0
with tarfile.open(sys.argv[1], 'r:gz') as tar:
    for m in tar.getmembers():
        p = PurePosixPath(m.name)
        if p.is_absolute() or '..' in p.parts:
            raise SystemExit('Unsafe path in archive: ' + m.name)
        if not (m.isfile() or m.isdir() or m.issym() or m.islnk()):
            raise SystemExit('Unsupported member in archive: ' + m.name)
        if m.islnk() and ('..' in PurePosixPath(m.linkname).parts or m.linkname.startswith('/')):
            raise SystemExit('Unsafe hard link in archive: ' + m.name)
        total += m.size
    if 'meta.json' not in {PurePosixPath(m.name).as_posix().lstrip('./') for m in tar.getmembers()}:
        raise SystemExit('Not a 3x-ui-backup archive (meta.json missing)')
print(total)
PY
}

restore_unit_state() {
    local unit="$1" staging="$2" saved_en saved_active
    read -r saved_en saved_active < <(awk -v u="$unit" '$1==u {print $2, $3; exit}' "${staging}/services-state") || return 0
    if [[ "$saved_en" == 1 ]]; then systemctl enable "$unit" 2>/dev/null || true; else systemctl disable "$unit" 2>/dev/null || true; fi
    if [[ "$saved_active" == 1 ]]; then systemctl start "$unit" 2>/dev/null || true; else systemctl stop "$unit" 2>/dev/null || true; fi
}

restore_port_policy() {
    local helper=/usr/local/lib/3x-ui-auto/firewall.sh db=/etc/x-ui/x-ui.db udp
    udp=$(sqlite3 "$db" "SELECT DISTINCT port FROM inbounds WHERE enable AND protocol = 'hysteria' ORDER BY port;" | paste -sd, -)
    bash "$helper" install "$udp"
}

migrate_legacy_backup() {
    local staging=$1 helper=/usr/local/lib/3x-ui-auto/firewall.sh panel
    install -m 0755 "$staging/firewall.sh" "$helper"
    restore_port_policy
    panel=$(sqlite3 /etc/x-ui/x-ui.db "SELECT value FROM settings WHERE key = 'webPort' LIMIT 1;")
    bash "$helper" iplimit "$panel"
    if [[ -f "$staging/guard.sh" ]]; then
        bash "$staging/guard.sh" -install y
    fi
}

cmd_restore() {
    require_root
    local backup_file="${1:-}" unpacked_bytes unpacked_kb have_kb staging path src cert_path module legacy=0
    [[ -n "$backup_file" ]] || die "Usage: $0 restore <backup.tar.gz>"
    [[ -f "$backup_file" ]] || die "File not found: ${backup_file}"
    command -v python3 >/dev/null 2>&1 || { apt-get update -qq && apt-get install -y -q python3; }
    unpacked_bytes=$(verify_backup_archive "$backup_file") || die "Backup archive rejected"

    unpacked_kb=$(( (unpacked_bytes + 1023) / 1024 ))
    mkdir -p "$BACKUP_STORE"
    have_kb=$(avail_kb "$BACKUP_STORE")
    (( have_kb >= unpacked_kb * 2 + 102400 )) || die "Not enough free space in ${BACKUP_STORE}"
    staging=$(make_staging restore)
    RESTORE_STAGING="$staging"
    trap 'rm -rf -- "$RESTORE_STAGING"' EXIT

    blue "==> Extracting backup: ${backup_file}"
    tar -xzf "$backup_file" -C "$staging"
    cat "${staging}/meta.json"
    echo
    [[ ! -f /var/lib/3x-ui-auto/install/firewall/saved ]] || die 'Сначала удалите прежнюю установку через -uninstall y.'

    blue "==> Installing packages..."
    apt-get update -qq
    # shellcheck disable=SC2086
    apt-get install -y $PACKAGES
    if [[ -f "$staging/ufw-state" ]]; then
        legacy=1
        curl -fsSL --proto '=https' --proto-redir '=https' "$REPO_RAW/assets/firewall.sh" -o "$staging/firewall.sh"
        bash -n "$staging/firewall.sh"
        if [[ -f "$staging/files/usr/local/lib/3x-ui-auto/guard.sh" ]]; then
            curl -fsSL --proto '=https' --proto-redir '=https' "$REPO_RAW/guard.sh" -o "$staging/guard.sh"
            bash -n "$staging/guard.sh"
        fi
        rm -f -- "$staging/files/var/lib/3x-ui-auto/install/firewall/saved"
    fi

    blue "==> Stopping services..."
    for path in "${SERVICES[@]}"; do systemctl stop "$path" 2>/dev/null || true; done
    if grep -qs '^SET4=xa-scan4$' /usr/local/lib/3x-ui-auto/guard.sh; then
        bash /usr/local/lib/3x-ui-auto/guard.sh -uninstall y
    elif nft list table inet xa_guard >/dev/null 2>&1; then
        nft delete table inet xa_guard
    fi

    blue "==> Restoring files..."
    # Certificates: never replace a newer local certificate with an older archived one.
    for cert_path in etc/letsencrypt var/lib/letsencrypt root/cert; do
        if [[ -e "${staging}/files/${cert_path}" ]]; then
            mkdir -p "/${cert_path}"
            cp -an "${staging}/files/${cert_path}/." "/${cert_path}/"
            rm -rf -- "${staging}/files/${cert_path}"
        fi
    done
    for path in "${BACKUP_PATHS[@]}"; do
        src="${staging}/files${path}"
        [[ -e "$src" || -L "$src" ]] || continue
        install -d -m 0755 "$(dirname "$path")"
        if [[ -d "$src" && ! -L "$src" ]]; then
            rm -rf -- "$path"
            cp -a "$src" "$path"
        else
            cp -a --remove-destination "$src" "$path"
        fi
    done
    [[ -d "${staging}/files/etc/systemd/system" ]] && cp -a "${staging}/files/etc/systemd/system/." /etc/systemd/system/
    chown -R www-data:www-data /var/www/html /var/www/subpage 2>/dev/null || true

    if [[ -f /etc/modules-load.d/3x-ui-auto-network.conf ]]; then
        while IFS= read -r module; do
            [[ -n "$module" && "$module" != \#* ]] && modprobe "$module" >/dev/null 2>&1 || true
        done < /etc/modules-load.d/3x-ui-auto-network.conf
    fi
    sysctl -p /etc/sysctl.d/99-bbr-x-ui.conf >/dev/null 2>&1 || true
    sysctl -p /etc/sysctl.d/99-zz-3x-ui-auto-tuning.conf >/dev/null 2>&1 || true

    blue "==> Enabling and starting services..."
    systemctl daemon-reload
    nginx -t || die "nginx config test failed after restore"
    if (( legacy )); then
        migrate_legacy_backup "$staging"
    elif grep -q '^3x-ui-auto-firewall [01] 1$' "${staging}/services-state"; then
        restore_port_policy
    fi
    for path in "${SERVICES[@]}"; do restore_unit_state "$path" "$staging"; done
    if systemctl is-active --quiet 3x-ui-guard-tick.timer; then
        bash /usr/local/lib/3x-ui-auto/guard.sh load
    fi

    blue "==> Restoring cron..."
    [[ -s "${staging}/root-crontab" ]] && crontab "${staging}/root-crontab"
    if crontab -l 2>/dev/null | grep -q 'certbot renew'; then
        systemctl enable --now cron >/dev/null 2>&1 || true
        systemctl mask --now certbot.timer >/dev/null 2>&1 || true
    fi

    for path in x-ui nginx 3x-ui-auto-firewall 3x-ui-guard-tick.timer; do
        if [[ "$(awk -v u="$path" '$1==u {print $3; exit}' "${staging}/services-state")" == 1 ]] && ! systemctl is-active --quiet "$path"; then
            die "Restored service is inactive: ${path}"
        fi
    done
    green "==> Restore complete."
    green "    Check status with: systemctl status x-ui nginx"
}

# ── list ──────────────────────────────────────────────────────────────────────
cmd_list() {
    local archives f
    mapfile -t archives < <(ls -t "${BACKUP_STORE}"/*.tar.gz 2>/dev/null || true)
    if [[ ${#archives[@]} -eq 0 ]]; then
        echo "No backups in ${BACKUP_STORE}"
        return
    fi
    blue "Backups in ${BACKUP_STORE}:"
    for f in "${archives[@]}"; do
        printf "  %-55s  %s\n" "$(basename "$f")" "$(du -sh "$f" | cut -f1)"
    done
}

case "${1:-}" in
    backup)  cmd_backup ;;
    restore) cmd_restore "${2:-}" ;;
    list)    cmd_list ;;
    *)
        cat <<EOF
Usage: $(basename "$0") {backup|restore <file>|list}

  backup            create timestamped backup in ${BACKUP_STORE}/
  restore <file>    restore from backup archive (installs packages first)
  list              list available backups

Backed up: panel DB and binaries, nginx, certificates, cover site, Clash/Mihomo renderer,
AdGuard Home, scanner/torrent guard, BBR/qdisc settings, Fail2ban, nftables, systemd units and cron.
EOF
        exit 1
        ;;
esac
