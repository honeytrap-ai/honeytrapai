#!/usr/bin/env bash
# HoneytrapAI — Installer for Raspberry Pi 4B (Raspberry Pi OS Lite 64-bit)
# Also compatible with Debian 12/13 ARM64
# Usage: sudo bash install.sh
# No cloud. No subscription. No monthly fees. Ever.

set -euo pipefail
HONEYTRAPAI_VERSION=$(cat VERSION)
APP_DIR="/opt/honeytrapai"
SERVICE_USER="honeytrapai"
LOG_DIR="/var/log/maltrail"
MALTRAIL_DIR="/opt/maltrail"
ADGUARD_DIR="/opt/AdGuardHome"
ADGUARD_VERSION="v0.107.43"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()    { echo -e "${GREEN}[✓]${NC} $*"; }
warn()    { echo -e "${YELLOW}[!]${NC} $*"; }
error()   { echo -e "${RED}[✗]${NC} $*"; exit 1; }
section() { echo -e "\n${YELLOW}━━━ $* ━━━${NC}"; }

[[ $EUID -ne 0 ]] && error "Run as root: sudo bash install.sh"

section "1. System update"
apt-get update -qq
apt-get upgrade -y -qq
apt-get install -y -qq \
    python3 python3-pip python3-venv \
    git curl wget nginx avahi-daemon \
    nmap net-tools dnsutils \
    unattended-upgrades logrotate \
    pyyaml 2>/dev/null || true
pip3 install pyyaml --quiet 2>/dev/null || true

section "2. Fix systemd-resolved port 53 conflict (Pi OS / Debian)"
# This is the most common blocker for AdGuard Home on Pi OS
if systemctl is-active --quiet systemd-resolved 2>/dev/null; then
    warn "systemd-resolved is running — disabling stub listener to free port 53"
    mkdir -p /etc/systemd/resolved.conf.d
    cat > /etc/systemd/resolved.conf.d/honeytrapai.conf << 'EOF'
[Resolve]
DNSStubListener=no
EOF
    systemctl restart systemd-resolved
    # Remove the symlink that points /etc/resolv.conf to stub
    rm -f /etc/resolv.conf
    ln -sf /run/systemd/resolve/resolv.conf /etc/resolv.conf
    info "systemd-resolved stub listener disabled"
fi

section "3. Create service user"
if ! id "$SERVICE_USER" &>/dev/null; then
    useradd --system --no-create-home --shell /usr/sbin/nologin "$SERVICE_USER"
    info "Created user: $SERVICE_USER"
fi

section "4. Install HoneytrapAI app"
mkdir -p "$APP_DIR"
cp -r . "$APP_DIR/"
mkdir -p "$APP_DIR/config"
python3 -m venv "$APP_DIR/venv"
"$APP_DIR/venv/bin/pip" install --quiet flask gunicorn pyyaml

# Generate secret key
SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")
echo "$SECRET_KEY" > "$APP_DIR/config/secret_key"
chmod 600 "$APP_DIR/config/secret_key"

# Write VERSION file
echo "$HONEYTRAPAI_VERSION" > "$APP_DIR/VERSION"

chown -R "$SERVICE_USER:$SERVICE_USER" "$APP_DIR"
info "HoneytrapAI installed to $APP_DIR"

section "5. Install Maltrail"
if [[ ! -d "$MALTRAIL_DIR" ]]; then
    git clone --depth 1 https://github.com/stamparm/maltrail.git "$MALTRAIL_DIR"
fi
mkdir -p "$LOG_DIR"
chown "$SERVICE_USER:$SERVICE_USER" "$LOG_DIR"

# Maltrail sensor config
cat > /etc/maltrail-sensor.conf << EOF
SENSOR_INTERFACE eth0
LOG_DIR $LOG_DIR
USE_HEURISTICS true
ENABLE_SUDO_INTERFACE true
EOF

info "Maltrail installed"

section "6. Install AdGuard Home"
ARCH="arm64"
AGH_URL="https://github.com/AdguardTeam/AdGuardHome/releases/download/${ADGUARD_VERSION}/AdGuardHome_linux_${ARCH}.tar.gz"

if [[ ! -f "$ADGUARD_DIR/AdGuardHome" ]]; then
    mkdir -p "$ADGUARD_DIR"
    wget -q "$AGH_URL" -O /tmp/adguard.tar.gz
    tar -xzf /tmp/adguard.tar.gz -C /tmp/
    cp /tmp/AdGuardHome/AdGuardHome "$ADGUARD_DIR/"
    chmod +x "$ADGUARD_DIR/AdGuardHome"
    rm -rf /tmp/adguard.tar.gz /tmp/AdGuardHome
fi
info "AdGuard Home binary installed"

section "7. Configure AdGuard Home headlessly"
# Start AdGuard temporarily to perform first-run setup via API
"$ADGUARD_DIR/AdGuardHome" &
AGH_PID=$!

# Wait for port 3000 to open
for i in $(seq 1 30); do
    if curl -s -L http://127.0.0.1:3000 >/dev/null 2>&1; then
        break
    fi
    sleep 1
done

# Complete first-run setup via API
sleep 2
kill $AGH_PID 2>/dev/null || true
wait $AGH_PID 2>/dev/null || true

# Generate AdGuard credentials
ADGUARD_PASSWORD="$(openssl rand -base64 12)"
ADGUARD_HASH="$(python3 -c 'import bcrypt; print(bcrypt.hashpw(b"'"${ADGUARD_PASSWORD}"'", bcrypt.gensalt(10)).decode())')"
info "AdGuard password generated"

# Write baseline AdGuard config
cat > "$ADGUARD_DIR/AdGuardHome.yaml" << EOF
http:
  pprof:
    port: 6060
    enabled: false
  address: 127.0.0.1:3000
  session_ttl: 720h
users:
  - name: admin
    password: ${ADGUARD_HASH}
dns:
  bind_hosts:
    - 0.0.0.0
  port: 53
  upstream_dns:
    - https://dns.cloudflare.com/dns-query
    - https://dns.google/dns-query
  bootstrap_dns:
    - 1.1.1.1
    - 8.8.8.8
  fallback_dns:
    - 1.1.1.1
  use_http3_upstreams: false
  enable_dnssec: true
  safe_browsing_enabled: true
  parental_enabled: false
  filtering_enabled: true
  querylog_enabled: true
  querylog_file_enabled: true
  querylog_interval: 720h
  querylog_size_memory: 1000
filters:
  - enabled: true
    url: https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt
    name: AdGuard DNS filter
    id: 1
  - enabled: true
    url: https://adaway.org/hosts.txt
    name: AdAway Default Blocklist
    id: 2
  - enabled: true
    url: https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-agh.txt
    name: URLhaus Malware Domains
    id: 3
  - enabled: true
    url: https://raw.githubusercontent.com/nicehash/NiceHash-Domains/master/nicehash.txt
    name: NiceHash Cryptomining Domains
    id: 4
statistics:
  interval: 168h
log:
  compress: false
  localtime: false
  max_backups: 0
  max_age: 3
  max_size: 100
  verbose: false
schema_version: 27
EOF

chown -R "$SERVICE_USER:$SERVICE_USER" "$ADGUARD_DIR"
info "AdGuard Home configured headlessly — web UI bound to localhost only"

# Write AdGuard credentials to config.json so the dashboard can authenticate
python3 -c "
import json, os
cfg_path = '${APP_DIR}/config/config.json'
cfg = json.load(open(cfg_path)) if os.path.exists(cfg_path) else {}
cfg['adguard_user'] = 'admin'
cfg['adguard_password'] = '${ADGUARD_PASSWORD}'
json.dump(cfg, open(cfg_path, 'w'), indent=2)
"
info "AdGuard credentials written to config.json"
chown "$SERVICE_USER:$SERVICE_USER" "$APP_DIR/config/config.json"

sudo apt install -y nginx python3-pcapy
echo "127.0.0.1 honeytrapai" >> /etc/hosts
sudo mkdir -p /etc/nginx/sites-available
sudo mkdir -p /etc/nginx/sites-enabled
section "8. Configure nginx reverse proxy"

cat > /etc/nginx/sites-available/honeytrapai << 'EOF'
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name honeytrap.local _;

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_read_timeout 30s;
    }
}
EOF

rm -f /etc/nginx/sites-enabled/default
ln -sf /etc/nginx/sites-available/honeytrapai /etc/nginx/sites-enabled/
nginx -t && systemctl reload nginx
info "nginx configured"

section "9. Configure mDNS (honeytrap.local)"
hostname honeytrapai
echo "honeytrapai" > /etc/hostname
# Enable avahi for .local mDNS resolution
systemctl enable avahi-daemon
systemctl start avahi-daemon
info "mDNS configured — device accessible at http://honeytrap.local"

section "10. Configure logrotate"
cat > /etc/logrotate.d/maltrail << 'EOF'
/var/log/maltrail/*.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    create 640 honeytrapai honeytrapai
}
EOF
info "Log rotation configured (30-day retention)"

section "11. Configure unattended upgrades (OS security patches)"
cat > /etc/apt/apt.conf.d/20honeytrapai-unattended << 'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
EOF
info "Unattended OS security upgrades enabled"

section "12. Create systemd services"

# HoneytrapAI dashboard (gunicorn)
SECRET=$(cat "$APP_DIR/config/secret_key")
cat > /etc/systemd/system/honeytrapai.service << EOF
[Unit]
Description=HoneytrapAI Dashboard
After=network.target

[Service]
Type=simple
User=$SERVICE_USER
WorkingDirectory=$APP_DIR
Environment="SECRET_KEY=$SECRET"
Environment="MALTRAIL_LOG=$LOG_DIR/maltrail.log"
ExecStart=$APP_DIR/venv/bin/gunicorn --workers 2 --bind 127.0.0.1:5000 app:app
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

# HoneytrapAI notifier daemon
cat > /etc/systemd/system/honeytrapai-notifier.service << EOF
[Unit]
Description=HoneytrapAI Email Notifier
After=network.target honeytrapai.service

[Service]
Type=simple
User=$SERVICE_USER
WorkingDirectory=$APP_DIR
Environment="MALTRAIL_LOG=$LOG_DIR/maltrail.log"
ExecStart=/usr/bin/python3 $APP_DIR/notifier.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# Maltrail sensor
cat > /etc/systemd/system/maltrail-sensor.service << EOF
[Unit]
Description=Maltrail Sensor
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/bin/python3 $MALTRAIL_DIR/sensor.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# AdGuard Home
cat > /etc/systemd/system/adguardhome.service << EOF
[Unit]
Description=AdGuard Home DNS Server
After=network.target

[Service]
Type=simple
User=root
ExecStart=$ADGUARD_DIR/AdGuardHome -s run
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

# OTA update check timer (daily, randomised offset)
cat > /etc/systemd/system/honeytrapai-update.service << EOF
[Unit]
Description=HoneytrapAI Update Check

[Service]
Type=oneshot
User=$SERVICE_USER
WorkingDirectory=$APP_DIR
ExecStart=/usr/bin/python3 $APP_DIR/updater.py
EOF

cat > /etc/systemd/system/honeytrapai-update.timer << 'EOF'
[Unit]
Description=HoneytrapAI Daily Update Check

[Timer]
OnCalendar=daily
RandomizedDelaySec=3600
Persistent=true

[Install]
WantedBy=timers.target
EOF

# Privileged OTA update worker
cat > /etc/systemd/system/honeytrapai-updater.service << 'EOF'
[Unit]
Description=HoneytrapAI OTA Update Worker
After=network.target

[Service]
Type=oneshot
User=root
ExecStart=/usr/bin/python3 /opt/honeytrapai/updater_worker.py
StandardOutput=journal
StandardError=journal
Restart=no
EOF

# USB factory reset monitor
cat > /etc/systemd/system/reset-monitor.service << EOF
[Unit]
Description=HoneytrapAI USB Factory Reset Monitor
After=local-fs.target udisks2.service
Wants=udisks2.service
DefaultDependencies=no

[Service]
Type=oneshot
ExecStart=/usr/bin/python3 $APP_DIR/reset_monitor.py
RemainAfterExit=no
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

# Sudoers — allow honeytrapai service user to run privileged helpers without password
# Defaults:honeytrapai !authenticate — required for locked service accounts (no password set)
# Wildcard * on helper scripts — allows arguments to be passed
cat > /etc/sudoers.d/honeytrapai-updater << EOF
Defaults:honeytrapai !authenticate
honeytrapai ALL=(root) NOPASSWD: /usr/bin/systemctl start honeytrapai-updater.service
honeytrapai ALL=(root) NOPASSWD: /usr/bin/python3 $APP_DIR/set_static_ip_helper.py *
honeytrapai ALL=(root) NOPASSWD: /usr/bin/python3 $APP_DIR/reset_monitor.py *
EOF
visudo -c -f /etc/sudoers.d/honeytrapai-updater || { error "Sudoers syntax check failed — aborting"; }
chmod 440 /etc/sudoers.d/honeytrapai-updater
info "Sudoers rules added"

section "13. Enable and start services"
systemctl daemon-reload
systemctl enable honeytrapai honeytrapai-notifier adguardhome maltrail-sensor honeytrapai-update.timer
systemctl enable reset-monitor.service
systemctl start adguardhome
sleep 3
systemctl start maltrail-sensor
sleep 2
systemctl start honeytrapai honeytrapai-notifier
systemctl start honeytrapai-update.timer
systemctl start reset-monitor.service

section "Installation complete!"
echo ""
echo -e "${GREEN}🐝 HoneytrapAI $HONEYTRAPAI_VERSION is installed and running.${NC}"
echo ""
echo "  Dashboard:  http://honeytrap.local"
echo "  Local IP:   http://$(hostname -I | awk '{print $1}')"
echo ""
echo "  Next step: point your router's Primary DNS to this device's IP"
echo "  Then visit the dashboard to complete setup."
echo ""
echo "  No cloud. No subscription. No monthly fees. Ever."
echo ""