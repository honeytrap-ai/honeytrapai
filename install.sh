#!/usr/bin/env bash
# HoneytrapAI — Installer for Raspberry Pi 4B (Raspberry Pi OS Lite 64-bit)
# Also compatible with Debian 12/13 ARM64
# Version: v0.3.48
# Revised: 2026-03-19
# Rev: 8
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
    chrony traceroute \
    whois openssl
pip3 install pyyaml --quiet 2>/dev/null || true

systemctl enable chrony
systemctl start chrony
info "chrony installed and running (NTP time sync)"

section "2. Fix systemd-resolved port 53 conflict (Pi OS / Debian)"
if systemctl is-active --quiet systemd-resolved 2>/dev/null; then
    warn "systemd-resolved is running — disabling stub listener to free port 53"
    mkdir -p /etc/systemd/resolved.conf.d
    cat > /etc/systemd/resolved.conf.d/honeytrapai.conf << 'EOF'
[Resolve]
DNSStubListener=no
EOF
    systemctl restart systemd-resolved
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
"$APP_DIR/venv/bin/pip" install --quiet flask gunicorn pyyaml geoip2

SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")
echo "$SECRET_KEY" > "$APP_DIR/config/secret_key"
chmod 600 "$APP_DIR/config/secret_key"

echo "$HONEYTRAPAI_VERSION" > "$APP_DIR/VERSION"

chown -R "$SERVICE_USER:$SERVICE_USER" "$APP_DIR"
info "HoneytrapAI installed to $APP_DIR"

section "5. Install Maltrail"
if [[ ! -d "$MALTRAIL_DIR" ]]; then
    git clone --depth 1 https://github.com/stamparm/maltrail.git "$MALTRAIL_DIR"
fi
mkdir -p "$LOG_DIR"
chown "$SERVICE_USER:$SERVICE_USER" "$LOG_DIR"

cat > /etc/maltrail-sensor.conf << EOF
SENSOR_INTERFACE eth0
LOG_DIR $LOG_DIR
USE_HEURISTICS true
ENABLE_SUDO_INTERFACE true
EOF

# Ensure any existing Maltrail dated logs are readable by the honeytrapai service user
chmod -f o+r "$LOG_DIR"/*.log 2>/dev/null || true
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
"$ADGUARD_DIR/AdGuardHome" &
AGH_PID=$!

for i in $(seq 1 30); do
    if curl -s -L http://127.0.0.1:3000 >/dev/null 2>&1; then break; fi
    sleep 1
done

sleep 2
kill $AGH_PID 2>/dev/null || true
wait $AGH_PID 2>/dev/null || true

ADGUARD_PASSWORD="$(openssl rand -base64 12)"
ADGUARD_HASH="$(python3 -c 'import bcrypt; print(bcrypt.hashpw(b"'"${ADGUARD_PASSWORD}"'", bcrypt.gensalt(10)).decode())')"
info "AdGuard password generated"

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

python3 -c "
import json, os
cfg_path = '${APP_DIR}/config/config.json'
cfg = json.load(open(cfg_path)) if os.path.exists(cfg_path) else {}
cfg['adguard_user'] = 'admin'
cfg['adguard_password'] = '${ADGUARD_PASSWORD}'
cfg['password_changed'] = False
json.dump(cfg, open(cfg_path, 'w'), indent=2)
"
info "AdGuard credentials written to config.json"
chown "$SERVICE_USER:$SERVICE_USER" "$APP_DIR/config/config.json"

sudo apt install -y nginx python3-pcapy
echo "127.0.0.1 honeytrapai" >> /etc/hosts
sudo mkdir -p /etc/nginx/sites-available
sudo mkdir -p /etc/nginx/sites-enabled

section "8. Set timezone"
DEFAULT_TZ="UTC"
echo ""
echo "Available timezones can be listed with: timedatectl list-timezones"
echo "Examples: America/Los_Angeles, America/New_York, America/Chicago, America/Denver, Europe/London"
read -r -p "Enter timezone [${DEFAULT_TZ}]: " USER_TZ
USER_TZ="${USER_TZ:-$DEFAULT_TZ}"

if timedatectl list-timezones | grep -qx "$USER_TZ"; then
    timedatectl set-timezone "$USER_TZ"
    info "Timezone set to $USER_TZ"
else
    warn "Invalid timezone '$USER_TZ' — defaulting to $DEFAULT_TZ"
    timedatectl set-timezone "$DEFAULT_TZ"
    info "Timezone set to $DEFAULT_TZ"
fi

section "9. Generate self-signed TLS certificate"
CERT_DIR="/etc/ssl/honeytrapai"
DEVICE_IP=$(hostname -I | awk '{print $1}')
mkdir -p "$CERT_DIR"

openssl req -x509 -nodes -newkey rsa:2048 \
    -keyout "$CERT_DIR/server.key" \
    -out "$CERT_DIR/server.crt" \
    -days 3650 \
    -subj "/CN=honeytrap.local/O=HoneytrapAI/C=US" \
    -addext "subjectAltName=DNS:honeytrap.local,IP:${DEVICE_IP}"

cp "$CERT_DIR/server.crt" "$APP_DIR/static/ca.crt"
chown "$SERVICE_USER:$SERVICE_USER" "$APP_DIR/static/ca.crt"
chmod 644 "$CERT_DIR/server.crt"
chmod 600 "$CERT_DIR/server.key"
info "Self-signed TLS certificate generated (SAN: honeytrap.local, $DEVICE_IP)"

section "10. Configure nginx reverse proxy (HTTPS)"
cat > /etc/nginx/sites-available/honeytrapai << EOF
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name honeytrap.local _;
    return 301 https://\$host\$request_uri;
}

server {
    listen 443 ssl default_server;
    listen [::]:443 ssl default_server;
    server_name honeytrap.local _;

    ssl_certificate     $CERT_DIR/server.crt;
    ssl_certificate_key $CERT_DIR/server.key;
    ssl_protocols       TLSv1.2 TLSv1.3;
    ssl_ciphers         HIGH:!aNULL:!MD5;
    location /static/ {
        alias $APP_DIR/static/;
    }
    location /ca.crt {
        alias $APP_DIR/static/ca.crt;
        default_type application/x-x509-ca-cert;
    }

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        proxy_read_timeout 30s;
    }
}
EOF

rm -f /etc/nginx/sites-enabled/default
ln -sf /etc/nginx/sites-available/honeytrapai /etc/nginx/sites-enabled/
nginx -t && systemctl reload nginx
info "nginx configured (HTTPS on 443, HTTP redirects to HTTPS)"

section "11. Configure mDNS (honeytrap.local)"
hostname honeytrapai
echo "honeytrapai" > /etc/hostname
systemctl enable avahi-daemon
systemctl start avahi-daemon
info "mDNS configured — device accessible at https://honeytrap.local"

section "12. Configure logrotate"
# create 0644 root root — Maltrail sensor (root) writes dated logs world-readable
# postrotate chmod — ensures rotated/new dated logs remain readable by honeytrapai service user
cat > /etc/logrotate.d/maltrail << 'EOF'
/var/log/maltrail/*.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    create 0644 root root
    postrotate
        chmod -f o+r /var/log/maltrail/*.log || true
    endscript
}
EOF
info "Log rotation configured (30-day retention, world-readable logs)"

section "13. Configure unattended upgrades (OS security patches)"
cat > /etc/apt/apt.conf.d/20honeytrapai-unattended << 'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
EOF
info "Unattended OS security upgrades enabled"

section "14. Download world map data (Live Threat Map)"
mkdir -p "$APP_DIR/static"
curl -L "https://cdn.jsdelivr.net/npm/world-atlas@2/countries-110m.json" \
    -o "$APP_DIR/static/countries-110m.json"
chown "$SERVICE_USER:$SERVICE_USER" "$APP_DIR/static/countries-110m.json"
info "Natural Earth 110m world map data downloaded"

section "15. Create systemd services"

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

# OTA update check timer
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
honeytrapai ALL=(root) NOPASSWD: /usr/bin/python3 $APP_DIR/log_inject_helper.py *
EOF
visudo -c -f /etc/sudoers.d/honeytrapai-updater || { error "Sudoers syntax check failed — aborting"; }
chmod 440 /etc/sudoers.d/honeytrapai-updater
info "Sudoers rules added"

section "16. Enable and start services"
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
echo "  Dashboard:  https://honeytrap.local"
echo "  Local IP:   https://$(hostname -I | awk '{print $1}')"
echo ""
echo "  Note: Your browser will show a security warning — this is expected."
echo "  The device uses a self-signed certificate. You can safely proceed."
echo "  To remove this warning, visit https://$(hostname -I | awk '{print $1}')/ca.crt"
echo "  to download and install the device certificate on your browser."
echo ""
echo "  Next step: point your router's Primary DNS to this device's IP"
echo "  Then visit the dashboard to complete setup."
echo ""
echo "  No cloud. No subscription. No monthly fees. Ever."