
#!/bin/bash
# merged client installer:
# original join-dns-and-enable-full-logging.sh (untouched), plus added watchdog + systemd unit
DNS_IP="$1"
DOMAIN="$2"
CLIENT_NAME="$3"

[ -z "$DNS_IP" ] || [ -z "$DOMAIN" ] || [ -z "$CLIENT_NAME" ] && {
    echo "Usage: sudo $0 <server-ip> <domain> <client-name>"
    echo "Example: sudo $0 192.168.29.206 cst.com client1"
    exit 1
}

SYSLOG_SERVER="$DNS_IP"
PORT="514"

# === FORCE FREE PORT 514 (kill anything using it) ===
echo "Checking and freeing port $PORT if in use..."
for proto in tcp udp; do
    pids=$(ss -lpn "sport = :$PORT" 2>/dev/null | grep -o 'pid=[0-9]\+' | grep -o '[0-9]\+' | sort -u)
    [ -n "$pids" ] && {
        echo "Port $PORT/$proto used by PID(s): $pids → killing them..."
        kill -9 $pids 2>/dev/null || true
    }
done
# Extra safety: stop common services that might bind to 514
systemctl stop rsyslog syslog-ng auditd 2>/dev/null || true
sleep 2

# === DNS + hostname ===
nmcli con show --active 2>/dev/null | awk '{print $1}' | while read c; do
    nmcli con mod "$c" ipv4.dns "$DNS_IP" ipv4.dns-search "$DOMAIN" ipv4.ignore-auto-dns yes &>/dev/null
    nmcli con up "$c" &>/dev/null
done
printf "search %s\nnameserver %s\n" "$DOMAIN" "$DNS_IP" > /etc/resolv.conf
hostnamectl set-hostname "$CLIENT_NAME.$DOMAIN"

# === Install packages ===
dnf install -y audit rsyslog &>/dev/null || yum install -y audit rsyslog &>/dev/null || \
apt install -y auditd rsyslog &>/dev/null || true

# === BULLETPROOF clean command logger (zero noise, zero errors) ===
cat > /etc/profile.d/remote-cmd-log.sh <<'EOD'
export REMOTE_SYSLOG_HOST="__IP__"
export REMOTE_SYSLOG_PORT="514"

_remote_cmd_logger() {
    # Skip profile/bashrc loading
    [[ "${BASH_SOURCE[1]:-}" == *"/etc/profile"* || "${BASH_SOURCE[1]:-}" == *"/etc/bash"* ]] && return

    # Skip known noise
    case "$BASH_COMMAND" in
        "" | *__vte_* | resize | history* | "set +o "* | "set -o "* ) return ;;
    esac

    # Only interactive shells
    [[ -n "$PS1" ]] || return

    logger -n "$REMOTE_SYSLOG_HOST" -P 514 -t "remote-cmd" -p local0.notice \
        "$(whoami)@$(hostname -f 2>/dev/null || hostname): $BASH_COMMAND" 2>/dev/null || true
}
trap '_remote_cmd_logger' DEBUG
EOD

sed -i "s|__IP__|$SYSLOG_SERVER|g" /etc/profile.d/remote-cmd-log.sh
chmod 644 /etc/profile.d/remote-cmd-log.sh

# === Audit rules ===
cat > /etc/audit/rules.d/99-execve.rules <<'AR'
-a always,exit -F arch=b64 -S execve,execveat -k exec_log
-a always,exit -F arch=b32 -S execve,execveat -k exec_log
-w /bin/ -p x -k exec_log
-w /sbin/ -p x -k exec_log
-w /usr/bin/ -p x -k exec_log
-w /usr/sbin/ -p x -k exec_log
AR
augenrules --load &>/dev/null || systemctl restart auditd &>/dev/null

# === Forward audit + interactive commands ===
cat > /etc/rsyslog.d/99-forward.conf <<RSY
module(load="imfile" mode="inotify")
input(type="imfile" File="/var/log/audit/audit.log" Tag="auditd:" Severity="info" Facility="local0")
local0.* @@$SYSLOG_SERVER:514
RSY

# === Final start (now port 514 is 100% free) ===
systemctl restart rsyslog auditd &>/dev/null
systemctl enable --now rsyslog auditd &>/dev/null

# === Only ONE green line ===
echo -e "\033[1;32mCLIENT 100% READY!\033[0m"

# === WATCHDOG FEATURE (ADDED) ===
# Adds client watchdog script and systemd service to enforce:
#  - first outage -> 40s grace then poweroff
#  - after first enforced poweroff -> 15s grace on next boot
# It reads REMOTE_SYSLOG_HOST from /etc/profile.d/remote-cmd-log.sh (already created above).

cat > /usr/local/bin/client-watchdog.sh <<'CW'
#!/usr/bin/env bash
# client-watchdog.sh
# Monitors reachability to REMOTE_SYSLOG_HOST (port 514). Enforces:
#  - first enforced poweroff: 40 seconds grace
#  - after first enforced poweroff (marker): 15 seconds grace on next boots

set -euo pipefail

STATE_DIR="/var/lib/client-watchdog"
mkdir -p "$STATE_DIR"
touch "$STATE_DIR/.watchdog-ok"

# Read REMOTE_SYSLOG_HOST from existing profile script if present
REMOTE=""
if [ -f /etc/profile.d/remote-cmd-log.sh ]; then
  REMOTE="$(grep -Eo 'REMOTE_SYSLOG_HOST=[^ ]+' /etc/profile.d/remote-cmd-log.sh 2>/dev/null | cut -d= -f2 | tr -d '\"')"
fi

# Allow passing IP as first arg if not found
if [ -z "$REMOTE" ]; then
  REMOTE="${1:-}"
fi

if [ -z "$REMOTE" ]; then
  echo "Client watchdog: REMOTE_SYSLOG_HOST not found. Usage: /usr/local/bin/client-watchdog.sh <server-ip>"
  exit 2
fi

TCP_PORT=514
CHECK_INTERVAL=4
FIRST_GRACE=40
FOLLOWUP_GRACE=15

if [ -f "$STATE_DIR/first_off_happened" ]; then
  ACTIVE_GRACE=$FOLLOWUP_GRACE
else
  ACTIVE_GRACE=$FIRST_GRACE
fi

log() {
  logger -t client-watchdog "$1" || true
  echo "$(date -Is) - $1"
}

is_reachable() {
  timeout 2 bash -c "cat < /dev/null > /dev/tcp/$REMOTE/$TCP_PORT" >/dev/null 2>&1 && return 0
  ping -c1 -W1 "$REMOTE" >/dev/null 2>&1 && return 0
  return 1
}

lost_since=0
while true; do
  if is_reachable; then
    if [ "$lost_since" -ne 0 ]; then
      log "Connectivity restored to $REMOTE. Cancelling shutdown timer."
    fi
    lost_since=0
    if [ -f "$STATE_DIR/first_off_happened" ]; then
      ACTIVE_GRACE=$FOLLOWUP_GRACE
    else
      ACTIVE_GRACE=$FIRST_GRACE
    fi
  else
    if [ "$lost_since" -eq 0 ]; then
      lost_since=$(date +%s)
      log "Lost connectivity to $REMOTE — starting $ACTIVE_GRACE second grace timer."
    else
      now=$(date +%s)
      elapsed=$((now - lost_since))
      remain=$((ACTIVE_GRACE - elapsed))
      if [ "$remain" -le 0 ]; then
        if ! is_reachable; then
          log "Grace period elapsed and $REMOTE still unreachable -> powering off NOW."
          touch "$STATE_DIR/first_off_happened"
          sync
          systemctl poweroff -i || shutdown -h now || poweroff -f
          break
        else
          log "Connectivity returned just before timeout — cancelling shutdown."
          lost_since=0
        fi
      else
        log "Server $REMOTE still unreachable — $remain sec remaining before enforced poweroff."
      fi
    fi
  fi
  sleep "$CHECK_INTERVAL"
done
CW

chmod +x /usr/local/bin/client-watchdog.sh

# systemd service for watchdog
cat > /etc/systemd/system/client-watchdog.service <<'UNIT'
[Unit]
Description=Client Watchdog: poweroff if syslog server unreachable
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/client-watchdog.sh
Restart=always
RestartSec=5
User=root

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable --now client-watchdog.service

echo -e "\033[1;32mCLIENT WATCHDOG INSTALLED & STARTED\033[0m"
echo "Check logs: journalctl -u client-watchdog.service -f"

echo "Created /usr/local/bin/join-dns-and-enable-full-logging.sh and made it executable."
