#!/bin/bash
# merged server installer:
# DNS + rsyslog + admin blocking helper.

IP="$1"
FQDN="$2"
DOMAIN="$3"

[ -z "$IP" ] || [ -z "$FQDN" ] || [ -z "$DOMAIN" ] && {
    echo "Usage: sudo $0 <server-ip> <fqdn> <domain>"
    echo "Example: sudo $0 192.168.29.206 server.cst.com cst.com"
    exit 1
}

echo "Setting up DNS + Remote Syslog Server — MERGED VERSION (hostname logs + green + zero noise + admin-block)..."

# === helper: auto-configure yum from RHEL ISO ===
auto_config_local_iso_repo() {
    echo "Trying to auto-configure local yum repo from ISO..."

    local MOUNTPOINT=""
    local ISO_FILE=""
    local REPO_FILE="/etc/yum.repos.d/local-iso.repo"

    # 1) Check for already-mounted ISO (iso9660)
    local EXISTING_MOUNT
    EXISTING_MOUNT=$(awk '$3=="iso9660"{print $2}' /etc/mtab | head -n1)

    if [ -n "$EXISTING_MOUNT" ]; then
        MOUNTPOINT="$EXISTING_MOUNT"
        echo "Found existing ISO mount at: $MOUNTPOINT"
    else
        echo "No existing ISO mount found, searching for *.iso (this may take a bit)..."
        ISO_FILE=$(find / -maxdepth 5 -type f -name "*.iso" 2>/dev/null | head -n1)

        if [ -z "$ISO_FILE" ]; then
            echo "No ISO file found on the system. Cannot auto-configure yum."
            return 1
        fi

        echo "Found ISO file: $ISO_FILE"

        MOUNTPOINT="/mnt/local-iso"
        mkdir -p "$MOUNTPOINT"

        if mount | grep -q " $MOUNTPOINT "; then
            echo "Mountpoint $MOUNTPOINT already in use."
        else
            if ! mount -o loop "$ISO_FILE" "$MOUNTPOINT"; then
                echo "Failed to mount ISO: $ISO_FILE -> $MOUNTPOINT"
                return 1
            fi
            echo "Mounted ISO at $MOUNTPOINT"
        fi
    fi

    echo "Scanning $MOUNTPOINT for repodata directories..."
    mapfile -t REPO_DIRS < <(find "$MOUNTPOINT" -type d -name repodata 2>/dev/null | head -n 20)

    if [ ${#REPO_DIRS[@]} -eq 0 ]; then
        echo "No repodata directories found under $MOUNTPOINT. ISO may not be a valid RHEL repo source."
        return 1
    fi

    # Create / overwrite repo file
    echo "Creating $REPO_FILE ..."
    : > "$REPO_FILE"

    local idx=1
    for rd in "${REPO_DIRS[@]}"; do
        local parent
        parent=$(dirname "$rd")

        cat >> "$REPO_FILE" <<EOF
[local-iso-$idx]
name=Local ISO repo $idx
baseurl=file://$parent
enabled=1
gpgcheck=0

EOF
        idx=$((idx+1))
    done

    echo "Local ISO repo configuration written to $REPO_FILE"

    echo "Running dnf clean all && dnf makecache..."
    dnf clean all >/dev/null 2>&1 || true
    dnf makecache || true

    return 0
}

# === FORCE TAKE PORT 514 ===
echo "Force-killing anything using port 514..."
for proto in udp tcp; do
    ss -lpn "sport = :514" 2>/dev/null | awk '{print $6}' | grep -o 'pid=[0-9]\+' | cut -d= -f2 | sort -u | xargs -r kill -9 2>/dev/null
done
systemctl stop rsyslog syslog-ng auditd 2>/dev/null || true
sleep 2

# === DNS (RHEL / Rocky / Alma) ===
echo "Installing BIND (bind + bind-utils via dnf)..."
if ! dnf install -y bind bind-utils; then
    echo "Initial dnf install failed. Likely no enabled repositories."
    echo "Attempting to configure local ISO-based yum repo automatically..."
    if auto_config_local_iso_repo; then
        echo "Retrying dnf install of bind and bind-utils..."
        if ! dnf install -y bind bind-utils; then
            echo "ERROR: Failed to install bind/bind-utils even after ISO repo setup."
            exit 1
        fi
    else
        echo "ERROR: Could not auto-configure local ISO repo. Fix yum/dnf repos manually."
        exit 1
    fi
fi

hostnamectl set-hostname "$FQDN"

# Make sure zone directory exists
mkdir -p /var/named

cat > /etc/named.conf <<EON
options {
    listen-on port 53 { any; };
    allow-query { any; };
    recursion yes;
    forwarders { 8.8.8.8; 8.8.4.4; };
    directory "/var/named";
};
zone "$DOMAIN" { type master; file "$DOMAIN.zone"; };
include "/etc/named.rfc1912.zones";
include "/etc/named.root.key";
EON

cat > /var/named/$DOMAIN.zone <<EOZ
\$TTL 86400
@ IN SOA $FQDN. root.$DOMAIN. ( $(date +%Y%m%d)01 3H 1H 1W 1D )
@ IN NS $FQDN.
$(echo $FQDN | cut -d. -f1) IN A $IP
EOZ

# Set ownership if 'named' user exists
if id named &>/dev/null; then
    chown -R named:named /var/named
fi

# Enable and start named only if the unit exists
if systemctl list-unit-files | grep -q '^named.service'; then
    systemctl enable --now named
else
    echo "WARNING: named.service not found. Check if BIND is installed correctly."
fi

firewall-cmd --add-service=dns --permanent &>/dev/null || true
firewall-cmd --reload &>/dev/null || true

# === add-client.sh (FIXED VERSION) ===
cat > /usr/local/bin/add-client.sh <<'ADD'
#!/bin/bash

NAME="$1"
IP="$2"
DOMAIN="${3:-}"
ZONE_DIR="/var/named"

# Validate inputs
if [ -z "$NAME" ] || [ -z "$IP" ]; then
    echo "Usage: sudo $0 <name> <ip> [domain]"
    exit 1
fi

# Auto-detect domain if not passed
if [ -z "$DOMAIN" ]; then
    shopt -s nullglob
    ZONES=("$ZONE_DIR"/*.zone)
    if [ ${#ZONES[@]} -eq 1 ]; then
        DOMAIN="$(basename "${ZONES[0]}" .zone)"
    else
        echo "Multiple or no zone files found — provide domain manually."
        exit 2
    fi
fi

ZONE="$ZONE_DIR/$DOMAIN.zone"

if [ ! -f "$ZONE" ]; then
    echo "Zone file does not exist: $ZONE"
    exit 3
fi

# Add A record
echo "$NAME IN A $IP" >> "$ZONE"

# Fix SOA serial
sed -i "/SOA/ s/[0-9]\{8,12\}/$(date +%Y%m%d)99/" "$ZONE"

# Reload DNS zone
rndc reload "$DOMAIN" &>/dev/null || true

echo "Added → $NAME.$DOMAIN ($IP)"
ADD

chmod +x /usr/local/bin/add-client.sh

# === FINAL RSYSLOG CONFIG ===
dnf install -y rsyslog &>/dev/null || true
mkdir -p /var/log/remote
chmod 750 /var/log/remote

cat > /etc/rsyslog.d/50-remote-logger.conf <<'RSYS'
module(load="imuxsock")
module(load="imjournal")

$ModLoad imudp
$UDPServerRun 514
$ModLoad imtcp
$InputTCPServerRun 514

$PreserveFQDN on

$template HostFile,"/var/log/remote/%hostname%.logs"
$template GreenCmd,"\033[1;32m%timestamp:::date-rfc3339%  %msg:F,58:2%@%hostname%  %msg:R,ERE,0,FIELD:: (.*)--end%\033[0m\n"

if $syslogtag == 'remote-cmd:' and $fromhost-ip != '127.0.0.1' and $fromhost-ip != '::1' then {
    action(type="omfile" dynaFile="HostFile" template="GreenCmd")
    stop
}

if $fromhost-ip != '127.0.0.1' and $fromhost-ip != '::1' then {
    action(type="omfile" dynaFile="HostFile")
}
RSYS

cat > /etc/logrotate.d/remote-logs <<'LR'
/var/log/remote/*.logs {
    daily
    rotate 7
    compress
    missingok
    create 0640 root adm
    sharedscripts
    postrotate
        systemctl restart rsyslog &>/dev/null || true
    endscript
}
LR

firewall-cmd --add-port=514/tcp --add-port=514/udp --permanent &>/dev/null || true
firewall-cmd --reload &>/dev/null || true

[ "$(getenforce 2>/dev/null || echo Disabled)" = "Enforcing" ] && {
    semanage fcontext -a -t var_log_t '/var/log/remote(/.*)?' 2>/dev/null || true
    restorecon -R /var/log/remote 2>/dev/null || true
}

systemctl restart rsyslog
systemctl enable --now rsyslog

echo
echo -e "\033[1;32mSERVER 100% READY!\033[0m"
echo -e "\033[1;32mPort 514: FORCE OWNED\033[0m"
echo -e "\033[1;32mLogs: /var/log/remote/<hostname>.logs\033[0m"
echo
echo "Add clients:"
echo "   sudo add-client.sh client1 192.168.29.210"
echo "   sudo add-client.sh db01    192.168.29.215"
echo

# === ADMIN BLOCK HELPER (ADDED FEATURE) ===
cat > /usr/local/bin/admin-block-client.sh <<'AB'
#!/usr/bin/env bash
# Usage:
#   sudo admin-block-client.sh block 192.168.29.210
#   sudo admin-block-client.sh unblock 192.168.29.210
#   sudo admin-block-client.sh status 192.168.29.210
ACTION="$1"
IP="$2"
DROP_MARKER_DIR="/var/lib/admin-block-client"
mkdir -p "$DROP_MARKER_DIR"

if [ -z "$ACTION" ] || [ -z "$IP" ]; then
  echo "Usage: sudo $0 <block|unblock|status> <client-ip>"
  exit 2
fi

case "$ACTION" in
  block)
    if command -v firewall-cmd >/dev/null 2>&1; then
      firewall-cmd --permanent --add-rich-rule="rule family='ipv4' source address='$IP' drop" >/dev/null 2>&1 || true
      firewall-cmd --reload >/dev/null 2>&1 || true
    else
      iptables -C INPUT -s "$IP" -j DROP >/dev/null 2>&1 || iptables -I INPUT -s "$IP" -j DROP 2>/dev/null || true
      ip6tables -C INPUT -s "$IP" -j DROP >/dev/null 2>&1 || ip6tables -I INPUT -s "$IP" -j DROP 2>/dev/null || true
    fi
    touch "$DROP_MARKER_DIR/$IP.blocked"
    echo "Blocked $IP on this server."
    ;;
  unblock)
    if command -v firewall-cmd >/dev/null 2>&1; then
      firewall-cmd --permanent --remove-rich-rule="rule family='ipv4' source address='$IP' drop" >/dev/null 2>&1 || true
      firewall-cmd --reload >/dev/null 2>&1 || true
    else
      iptables -D INPUT -s "$IP" -j DROP 2>/dev/null || true
      ip6tables -D INPUT -s "$IP" -j DROP 2>/dev/null || true
    fi
    rm -f "$DROP_MARKER_DIR/$IP.blocked" 2>/dev/null || true
    echo "Unblocked $IP on this server."
    ;;
  status)
    if [ -f "$DROP_MARKER_DIR/$IP.blocked" ]; then
      echo "$IP is marked blocked (marker present)."
    else
      echo "No marker for $IP. Check firewall rules."
    fi
    if command -v firewall-cmd >/dev/null 2>&1; then
      firewall-cmd --list-rich-rules | grep "$IP" || true
    else
      iptables -S | grep "$IP" || true
    fi
    ;;
  *)
    echo "Unknown action. Use block|unblock|status"
    exit 3
    ;;
esac
AB

chmod +x /usr/local/bin/admin-block-client.sh
echo "Admin helper installed: /usr/local/bin/admin-block-client.sh"
echo "Use: sudo /usr/local/bin/admin-block-client.sh block|unblock|status <client-ip>"

# ensure marker dir exists
mkdir -p /var/lib/admin-block-client

echo "Created /usr/local/bin/setup-server.sh and made it executable."
