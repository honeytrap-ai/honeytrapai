# HoneytrapAI — app.py
# Version: v0.3.54
# Revised: 2026-03-20
# Rev: 38
# Copyright (c) 2026 HoneytrapAI / Anthony Watts — MIT License
#!/usr/bin/env python3
"""
HoneytrapAI — Flask web dashboard core
No cloud. No subscription. No monthly fees. Ever.
"""

import os
import re
import glob
import json
import time
import random
import hashlib
import secrets
import subprocess
import ipaddress
import threading
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session, jsonify, make_response
import geoip2.database

app = Flask(__name__)

# Cache for /api/my-location — ISSUE-35
_my_location_cache = None

# Cache for /api/network-visibility — ISSUE-40
_net_visibility_cache = None
_devices_cache = None
_DEVICES_TTL = 60
_blocked_domains_cache = None
_BLOCKED_DOMAINS_TTL = 60
_allowlist_cache = None
_ALLOWLIST_TTL   = 30
_NET_VIS_TTL = 300

# Cache for ip-api.com geo lookups — ISSUE-39
_geo_cache = {}

# Rate limit tracker for ip-api.com — ISSUE-39
_geo_rate_lock = threading.Lock()
_geo_rate = {"count": 0, "window_start": None}
_GEO_RATE_LIMIT = 40

# Auto OTA scheduler state — ISSUE-46
_auto_ota_thread_started = False

app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))

# --- Paths ---
BASE_DIR    = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.join(BASE_DIR, "config", "config.json")
SMTP_PATH   = os.path.join(BASE_DIR, "config", "smtp.json")
VERSION_PATH= os.path.join(BASE_DIR, "VERSION")
LOG_PATH    = os.environ.get("MALTRAIL_LOG", "/var/log/maltrail/maltrail.log")
DEV_MODE    = os.environ.get("HONEYTRAPAI_DEV", "0") == "1"

# --- Country CIDR sources ---
IPDENY_URL       = "https://www.ipdeny.com/ipblocks/data/countries/{cc}.zone"
HERRBISCHOFF_URL = "https://raw.githubusercontent.com/herrbischoff/country-ip-blocks/master/ipv4/{cc}.cidr"

# --- Parental Controls — ISSUE-11 ---
PARENTAL_CATEGORIES = {
    "adult":    "Adult/Pornography",
    "gambling": "Gambling",
    "dating":   "Dating Sites",
    "drugs":    "Drug-Related Content",
    "violence": "Violence/Gore",
    "piracy":   "Piracy/Torrents",
    "vpn":      "Proxy/VPN Bypass Sites",
}

def _pc_tag(category):
    return f"# honeytrapai-parental-{category}"

# --- Lifetime blocked counter state ---
_last_num_blocked      = None
_lifetime_blocked_lock = threading.Lock()

# --- Country centroid lookup ---
COUNTRY_CENTROIDS = {
    "AD":(42.55,1.57),"AE":(24.00,54.00),"AF":(33.00,65.00),"AG":(17.07,-61.80),
    "AL":(41.00,20.00),"AM":(40.00,45.00),"AO":(-11.20,17.87),"AR":(-34.00,-64.00),
    "AT":(47.33,13.33),"AU":(-27.00,133.00),"AZ":(40.50,47.50),"BA":(44.00,17.50),
    "BB":(13.17,-59.53),"BD":(24.00,90.00),"BE":(50.83,4.00),"BF":(13.00,-2.00),
    "BG":(43.00,25.00),"BH":(26.00,50.55),"BI":(-3.50,30.00),"BJ":(9.50,2.25),
    "BN":(4.50,114.67),"BO":(-17.00,-65.00),"BR":(-10.00,-55.00),"BS":(24.25,-76.00),
    "BT":(27.50,90.50),"BW":(-22.00,24.00),"BY":(53.00,28.00),"BZ":(17.25,-88.75),
    "CA":(60.00,-95.00),"CD":(-4.00,25.00),"CF":(7.00,21.00),"CG":(-1.00,15.00),
    "CH":(47.00,8.00),"CI":(8.00,-5.00),"CL":(-30.00,-71.00),"CM":(6.00,12.00),
    "CN":(35.00,105.00),"CO":(4.00,-72.00),"CR":(10.00,-84.00),"CU":(21.50,-80.00),
    "CV":(16.00,-24.00),"CY":(35.00,33.00),"CZ":(49.75,15.50),"DE":(51.00,9.00),
    "DJ":(11.50,43.00),"DK":(56.00,10.00),"DM":(15.42,-61.33),"DO":(19.00,-70.67),
    "DZ":(28.00,3.00),"EC":(-2.00,-77.50),"EE":(59.00,26.00),"EG":(27.00,30.00),
    "ER":(15.00,39.00),"ES":(40.00,-4.00),"ET":(8.00,38.00),"FI":(64.00,26.00),
    "FJ":(-18.00,175.00),"FR":(46.00,2.00),"GA":(-1.00,11.75),"GB":(54.00,-2.00),
    "GD":(12.12,-61.67),"GE":(42.00,43.50),"GH":(8.00,-2.00),"GM":(13.47,-16.57),
    "GN":(11.00,-10.00),"GQ":(2.00,10.00),"GR":(39.00,22.00),"GT":(15.50,-90.25),
    "GW":(12.00,-15.00),"GY":(5.00,-59.00),"HN":(15.00,-86.50),"HR":(45.17,15.50),
    "HT":(19.00,-72.42),"HU":(47.00,20.00),"ID":(-5.00,120.00),"IE":(53.00,-8.00),
    "IL":(31.50,34.75),"IN":(20.00,77.00),"IQ":(33.00,44.00),"IR":(32.00,53.00),
    "IS":(65.00,-18.00),"IT":(42.83,12.83),"JM":(18.25,-77.50),"JO":(31.00,36.00),
    "JP":(36.00,138.00),"KE":(1.00,38.00),"KG":(41.00,75.00),"KH":(13.00,105.00),
    "KI":(1.42,173.00),"KM":(-12.17,44.25),"KN":(17.33,-62.75),"KP":(40.00,127.00),
    "KR":(37.00,127.50),"KW":(29.34,47.66),"KZ":(48.00,68.00),"LA":(18.00,105.00),
    "LB":(33.83,35.83),"LC":(13.88,-60.97),"LI":(47.17,9.53),"LK":(7.00,81.00),
    "LR":(6.50,-9.50),"LS":(-29.50,28.50),"LT":(56.00,24.00),"LU":(49.75,6.17),
    "LV":(57.00,25.00),"LY":(25.00,17.00),"MA":(32.00,-5.00),"MC":(43.73,7.40),
    "MD":(47.00,29.00),"ME":(42.50,19.30),"MG":(-20.00,47.00),"MH":(9.00,168.00),
    "MK":(41.83,22.00),"ML":(17.00,-4.00),"MM":(22.00,98.00),"MN":(46.00,105.00),
    "MR":(20.00,-12.00),"MT":(35.83,14.58),"MU":(-20.28,57.55),"MV":(3.25,73.00),
    "MW":(-13.50,34.00),"MX":(23.00,-102.00),"MY":(2.50,112.50),"MZ":(-18.25,35.00),
    "NA":(-22.00,17.00),"NE":(16.00,8.00),"NG":(10.00,8.00),"NI":(13.00,-85.00),
    "NL":(52.50,5.75),"NO":(62.00,10.00),"NP":(28.00,84.00),"NR":(-0.53,166.92),
    "NZ":(-41.00,174.00),"OM":(22.00,58.00),"PA":(9.00,-80.00),"PE":(-10.00,-76.00),
    "PG":(-6.00,147.00),"PH":(13.00,122.00),"PK":(30.00,70.00),"PL":(52.00,20.00),
    "PT":(39.50,-8.00),"PW":(7.51,134.58),"PY":(-23.00,-58.00),"QA":(25.50,51.25),
    "RO":(46.00,25.00),"RS":(44.00,21.00),"RU":(60.00,100.00),"RW":(-2.00,30.00),
    "SA":(25.00,45.00),"SB":(-8.00,159.00),"SC":(-4.67,55.47),"SD":(15.00,30.00),
    "SE":(62.00,15.00),"SG":(1.37,103.80),"SI":(46.12,14.82),"SK":(48.67,19.50),
    "SL":(8.50,-11.50),"SM":(43.77,12.42),"SN":(14.00,-14.00),"SO":(10.00,49.00),
    "SR":(4.00,-56.00),"SS":(8.00,30.00),"ST":(1.00,7.00),"SV":(13.83,-88.92),
    "SY":(35.00,38.00),"SZ":(-26.50,31.50),"TD":(15.00,19.00),"TG":(8.00,1.17),
    "TH":(15.00,100.00),"TJ":(39.00,71.00),"TL":(-8.87,125.73),"TM":(40.00,60.00),
    "TN":(34.00,9.00),"TO":(-20.00,-175.00),"TR":(39.00,35.00),"TT":(11.00,-61.00),
    "TV":(-8.00,178.00),"TZ":(-6.00,35.00),"UA":(49.00,32.00),"UG":(1.00,32.00),
    "US":(38.00,-97.00),"UY":(-33.00,-56.00),"UZ":(41.00,64.00),"VA":(41.90,12.45),
    "VC":(13.25,-61.20),"VE":(8.00,-66.00),"VN":(16.00,106.00),"VU":(-16.00,167.00),
    "WS":(-13.58,-172.33),"YE":(15.00,48.00),"ZA":(-29.00,25.00),"ZM":(-15.00,30.00),
    "ZW":(-20.00,30.00),
}

# --- Geo lookup helper — ISSUE-39 ---

def _resolve_geo(ip, country_code):
    global _geo_cache, _geo_rate

    if ip in _geo_cache:
        c = _geo_cache[ip]
        return c["lat"], c["lon"], c.get("city", "")

    now = datetime.utcnow()
    can_call = False
    with _geo_rate_lock:
        if _geo_rate["window_start"] is None or \
                (now - _geo_rate["window_start"]).total_seconds() >= 60:
            _geo_rate["window_start"] = now
            _geo_rate["count"] = 0
        if _geo_rate["count"] < _GEO_RATE_LIMIT:
            _geo_rate["count"] += 1
            can_call = True

    if can_call:
        try:
            import urllib.request as _ur
            url = f"http://ip-api.com/json/{ip}?fields=status,lat,lon,city"
            req = _ur.Request(url, headers={"User-Agent": "HoneytrapAI/1.0"})
            with _ur.urlopen(req, timeout=3) as r:
                data = json.loads(r.read().decode())
            if data.get("status") == "success":
                lat  = float(data["lat"])
                lon  = float(data["lon"])
                city = data.get("city", "")
                _geo_cache[ip] = {"lat": lat, "lon": lon, "city": city}
                return lat, lon, city
        except Exception:
            pass

    if country_code in COUNTRY_CENTROIDS:
        lat, lon = COUNTRY_CENTROIDS[country_code]
        _geo_cache[ip] = {"lat": lat, "lon": lon, "city": ""}
        return lat, lon, ""

    return None, None, ""


# --- Config helpers ---
def load_config():
    if os.path.exists(CONFIG_PATH):
        with open(CONFIG_PATH) as f:
            return json.load(f)
    return {}

def save_config(data):
    os.makedirs(os.path.dirname(CONFIG_PATH), exist_ok=True)
    tmp = CONFIG_PATH + ".tmp"
    with open(tmp, "w") as f:
        json.dump(data, f, indent=2)
    os.replace(tmp, CONFIG_PATH)

def get_version():
    if os.path.exists(VERSION_PATH):
        with open(VERSION_PATH) as f:
            return f.read().strip()
    return "v0.1.0"

def hash_password(password):
    salt = secrets.token_hex(16)
    h = hashlib.sha256((salt + password).encode()).hexdigest()
    return f"{salt}:{h}"

def verify_password(password, stored):
    try:
        salt, h = stored.split(":")
        return hashlib.sha256((salt + password).encode()).hexdigest() == h
    except Exception:
        return False

# --- Auto OTA helpers — ISSUE-46 ---

def _get_or_init_ota_schedule():
    """Return (hour, minute) for daily OTA check. Generate and persist if missing."""
    cfg = load_config()
    h = cfg.get("ota_check_hour")
    m = cfg.get("ota_check_minute")
    if h is None or m is None:
        h = random.randint(2, 3)
        m = random.randint(0, 59)
        cfg["ota_check_hour"]   = h
        cfg["ota_check_minute"] = m
        save_config(cfg)
    return int(h), int(m)

def _send_ota_email(subject, body_text):
    """Send an OTA status email using saved SMTP config. Best-effort — never raises."""
    try:
        if not os.path.exists(SMTP_PATH):
            return
        with open(SMTP_PATH) as f:
            smtp = json.load(f)
        if not smtp.get("host"):
            return
        cfg = load_config()
        if cfg.get("email_disabled", False):
            return
        to_addr = cfg.get("alert_email", "").strip()
        if not to_addr:
            return

        import smtplib
        from email.mime.text import MIMEText
        from email.mime.multipart import MIMEMultipart

        host      = smtp["host"]
        port      = int(smtp.get("port", 587))
        user      = smtp.get("username", "")
        pw        = smtp.get("password", "")
        from_addr = smtp.get("from_addr", user)
        use_ssl   = smtp.get("ssl", False)
        use_tls   = smtp.get("tls", True)

        msg            = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"]    = from_addr
        msg["To"]      = to_addr
        msg.attach(MIMEText(body_text, "plain"))

        if use_ssl:
            srv = smtplib.SMTP_SSL(host, port, timeout=15)
        else:
            srv = smtplib.SMTP(host, port, timeout=15)
            srv.ehlo()
            if use_tls:
                srv.starttls()
                srv.ehlo()
        if user and pw:
            srv.login(user, pw)
        srv.sendmail(from_addr, [to_addr], msg.as_string())
        srv.quit()
    except Exception as e:
        app.logger.warning(f"Auto OTA email failed: {e}")

def _auto_ota_scheduler():
    """Background thread: check for updates once daily at a random 2–4 AM local time.
    Only proceeds if uptime >= 30 min and auto_ota_enabled is True."""
    from updater import check_for_update, perform_update, get_update_status

    # Wait for app to fully start
    time.sleep(60)

    while True:
        try:
            cfg = load_config()
            if not cfg.get("auto_ota_enabled", True):
                time.sleep(300)
                continue

            h, m = _get_or_init_ota_schedule()
            now    = datetime.now()
            target = now.replace(hour=h, minute=m, second=0, microsecond=0)
            if target <= now:
                target += timedelta(days=1)

            wait_secs = (target - now).total_seconds()
            app.logger.info(f"Auto OTA: next check at {target.strftime('%H:%M')} local "
                            f"({int(wait_secs/3600)}h {int((wait_secs % 3600)/60)}m away)")
            time.sleep(wait_secs)

            # Re-check enabled flag after sleeping
            cfg = load_config()
            if not cfg.get("auto_ota_enabled", True):
                continue

            # Uptime check — only proceed if uptime >= 30 minutes
            try:
                with open("/proc/uptime") as f:
                    uptime_secs = float(f.read().split()[0])
                if uptime_secs < 1800:
                    app.logger.info("Auto OTA: uptime < 30 min, skipping this window")
                    time.sleep(3600)
                    continue
            except Exception:
                pass

            # Check for update
            info = check_for_update(force=True)
            if not info.get("update_available"):
                app.logger.info("Auto OTA: already up to date")
                continue

            latest = info.get("latest_version", "unknown")
            app.logger.info(f"Auto OTA: update available ({latest}), installing…")

            # Attempt install — retry once on failure
            for attempt in range(1, 3):
                perform_update()
                # Poll status for up to 3 minutes
                deadline    = time.time() + 180
                final_state = "unknown"
                while time.time() < deadline:
                    time.sleep(5)
                    st    = get_update_status()
                    state = st.get("state", "")
                    if state in ("complete", "error"):
                        final_state = state
                        break

                if final_state == "complete":
                    new_ver = get_update_status().get("new_version", latest)
                    app.logger.info(f"Auto OTA: updated to {new_ver}")
                    _send_ota_email(
                        f"HoneytrapAI updated to {new_ver}",
                        f"Your HoneytrapAI appliance has been automatically updated.\n\n"
                        f"New version: {new_ver}\n\n"
                        f"No cloud. No subscription. No monthly fees. Ever.\n— HoneytrapAI"
                    )
                    break
                else:
                    app.logger.warning(f"Auto OTA: install attempt {attempt} failed (state={final_state})")
                    if attempt == 2:
                        _send_ota_email(
                            f"HoneytrapAI update to {latest} failed",
                            f"Your HoneytrapAI appliance attempted to update to {latest} "
                            f"but failed after 2 attempts.\n\n"
                            f"You can install it manually from the dashboard.\n\n"
                            f"No cloud. No subscription. No monthly fees. Ever.\n— HoneytrapAI"
                        )
                    else:
                        time.sleep(60)

        except Exception as e:
            app.logger.error(f"Auto OTA scheduler error: {e}")
            time.sleep(3600)

# --- Markdown renderer ---
def render_markdown(text):
    import html as html_mod
    lines = text.splitlines()
    out = []
    in_list = False
    in_para = False

    def close_list():
        nonlocal in_list
        if in_list:
            out.append("</ul>")
            in_list = False

    def close_para():
        nonlocal in_para
        if in_para:
            out.append("</p>")
            in_para = False

    def inline(s):
        s = html_mod.escape(s)
        s = re.sub(r'\*\*\*(.+?)\*\*\*', r'<strong><em>\1</em></strong>', s)
        s = re.sub(r'\*\*(.+?)\*\*',     r'<strong>\1</strong>', s)
        s = re.sub(r'\*(.+?)\*',         r'<em>\1</em>', s)
        s = re.sub(r'`(.+?)`',           r'<code>\1</code>', s)
        return s

    for line in lines:
        stripped = line.strip()
        if not stripped:
            close_list(); close_para(); continue
        if re.match(r'^-{3,}$', stripped):
            close_list(); close_para(); out.append("<hr>"); continue
        m = re.match(r'^(#{1,3})\s+(.*)', stripped)
        if m:
            close_list(); close_para()
            lvl = len(m.group(1))
            out.append(f"<h{lvl}>{inline(m.group(2))}</h{lvl}>"); continue
        m = re.match(r'^[-*]\s+(.*)', stripped)
        if m:
            close_para()
            if not in_list:
                out.append("<ul>"); in_list = True
            out.append(f"<li>{inline(m.group(1))}</li>"); continue
        close_list()
        if not in_para:
            out.append("<p>"); in_para = True
        else:
            out.append(" ")
        out.append(inline(stripped))

    close_list(); close_para()
    return "\n".join(out)

# --- Network helpers ---
def is_private_ip(ip_str):
    try:
        addr = ipaddress.ip_address(ip_str)
        return addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_unspecified
    except ValueError:
        return False

def get_network_info(iface="eth0"):
    if DEV_MODE:
        return {
            "ip": "192.168.1.199", "prefix_len": "24",
            "gateway": "192.168.1.1", "dns": "192.168.1.1",
            "network": "192.168.1.0/24",
        }
    info = {"ip": "", "prefix_len": "", "gateway": "", "dns": "", "network": ""}
    try:
        out = subprocess.check_output(
            ["ip", "-4", "addr", "show", iface], text=True, stderr=subprocess.DEVNULL)
        for line in out.splitlines():
            line = line.strip()
            if line.startswith("inet "):
                parts = line.split()
                iface_obj = ipaddress.IPv4Interface(parts[1])
                info["ip"]         = str(iface_obj.ip)
                info["prefix_len"] = str(iface_obj.network.prefixlen)
                info["network"]    = str(iface_obj.network)
                break
    except Exception:
        pass
    try:
        out = subprocess.check_output(
            ["ip", "route", "show", "default"], text=True, stderr=subprocess.DEVNULL)
        for line in out.splitlines():
            parts = line.split()
            if "via" in parts:
                info["gateway"] = parts[parts.index("via") + 1]; break
    except Exception:
        pass
    try:
        with open("/etc/resolv.conf") as f:
            for line in f:
                line = line.strip()
                if line.startswith("nameserver"):
                    info["dns"] = line.split()[1]; break
    except Exception:
        pass
    return info

def validate_same_subnet(ip_str, network_str):
    try:
        ip  = ipaddress.IPv4Address(ip_str)
        net = ipaddress.IPv4Network(network_str, strict=False)
        return ip in net and ip != net.network_address and ip != net.broadcast_address
    except Exception:
        return False

def set_static_ip(iface, ip, prefix_len, gateway, dns):
    helper = os.path.join(BASE_DIR, "set_static_ip_helper.py")
    result = subprocess.run(
        ["sudo", "python3", helper, iface, ip, str(prefix_len), gateway, dns],
        capture_output=True, text=True)
    if result.returncode != 0:
        raise Exception(result.stderr.strip() or "set_static_ip_helper failed")

# --- Input validation helpers ---
def is_safe_host(host):
    if not host or len(host) > 253:
        return False
    if re.search(r'[;|&$`\'"\\\n\r]', host):
        return False
    return True

def is_safe_port(port):
    try:
        p = int(port)
        return 1 <= p <= 65535
    except Exception:
        return False

# --- Auth decorators ---
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("authenticated"):
            return redirect(url_for("login"))
        cfg = load_config()
        if not cfg.get("password_changed", True):
            if request.endpoint != "change_password":
                return redirect(url_for("change_password"))
        return f(*args, **kwargs)
    return decorated

def setup_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        cfg = load_config()
        if not cfg.get("setup_complete"):
            return redirect(url_for("setup"))
        return f(*args, **kwargs)
    return decorated

def terms_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        cfg = load_config()
        if not cfg.get("terms_accepted"):
            return redirect(url_for("terms"))
        return f(*args, **kwargs)
    return decorated

# --- Routes ---
@app.route("/")
def index():
    cfg = load_config()
    if not cfg.get("setup_complete"):
        return redirect(url_for("setup"))
    if not session.get("authenticated"):
        return redirect(url_for("login"))
    return redirect(url_for("dashboard"))

@app.route("/login", methods=["GET", "POST"])
def login():
    cfg = load_config()
    if not cfg.get("setup_complete"):
        return redirect(url_for("setup"))
    error = None
    if request.method == "POST":
        password = request.form.get("password", "")
        stored   = cfg.get("password_hash", "")
        if verify_password(password, stored):
            session["authenticated"] = True
            session.permanent = True
            app.permanent_session_lifetime = timedelta(days=30)
            return redirect(url_for("dashboard"))
        error = "Incorrect password."
    return render_template("login.html", error=error, version=get_version())

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

@app.route("/change-password", methods=["GET", "POST"])
@login_required
def change_password():
    """Force password change on first login — ISSUE-50"""
    error   = None
    success = None
    if request.method == "POST":
        cfg     = load_config()
        new_pw  = request.form.get("new_password", "")
        confirm = request.form.get("confirm", "")
        if len(new_pw) < 8:
            error = "Password must be at least 8 characters."
        elif new_pw != confirm:
            error = "Passwords do not match."
        else:
            cfg["password_hash"]    = hash_password(new_pw)
            cfg["password_changed"] = True
            save_config(cfg)
            return redirect(url_for("dashboard"))
    return render_template("change_password.html", error=error, version=get_version())

@app.route("/setup", methods=["GET", "POST"])
def setup():
    cfg = load_config()
    if cfg.get("setup_complete"):
        return redirect(url_for("login"))

    error = None
    step  = int(request.form.get("step", 1))
    net   = get_network_info()

    if request.method == "POST":

        if step == 1:
            password = request.form.get("password", "")
            confirm  = request.form.get("confirm", "")
            if len(password) < 8:
                error = "Password must be at least 8 characters."; step = 1
            elif password != confirm:
                error = "Passwords do not match."; step = 1
            else:
                cfg["password_hash"] = hash_password(password)
                cfg["password_changed"] = True
                save_config(cfg); step = 2

        elif step == 2:
            tz = request.form.get("timezone", "").strip()
            if not tz:
                error = "Please confirm your timezone before continuing."; step = 2
            elif not re.match(r'^[A-Za-z_]+(/[A-Za-z_]+){0,2}$', tz) and tz != "UTC":
                error = "Invalid timezone selected."; step = 2
            else:
                try:
                    subprocess.run(
                        ["sudo", "timedatectl", "set-timezone", tz],
                        capture_output=True, text=True, timeout=10, check=True
                    )
                except Exception as e:
                    error = f"Could not set timezone: {e}"; step = 2
                if not error:
                    cfg["timezone"] = tz
                    save_config(cfg)
                    step = 3

        elif step == 3:
            action = request.form.get("action", "save")
            if action == "skip":
                cfg["static_ip_skipped"] = True
                cfg["interface"] = "eth0"
                save_config(cfg); step = 4
            else:
                entered_ip = request.form.get("static_ip", "").strip()
                if not entered_ip:
                    error = "Please enter an IP address, or choose Skip."; step = 3
                elif not validate_same_subnet(entered_ip, net["network"]):
                    error = (
                        f"'{entered_ip}' is not a valid address within your subnet "
                        f"({net['network']}). Please enter an IP in that range."
                    ); step = 3
                else:
                    try:
                        set_static_ip(
                            iface="eth0", ip=entered_ip,
                            prefix_len=net["prefix_len"],
                            gateway=net["gateway"],
                            dns=net["dns"] or net["gateway"],
                        )
                        cfg["static_ip"]         = entered_ip
                        cfg["static_ip_skipped"] = False
                        cfg["gateway"]           = net["gateway"]
                        cfg["interface"]         = "eth0"
                        save_config(cfg); step = 4
                    except Exception as e:
                        error = f"Could not write static IP configuration: {e}"; step = 3

        elif step == 4:
            alert_email = request.form.get("alert_email", "").strip()
            cfg["alert_email"]    = alert_email
            cfg["setup_complete"] = True
            cfg["setup_date"]     = datetime.utcnow().isoformat()
            save_config(cfg)

            smtp_host = request.form.get("smtp_host", "").strip()
            if smtp_host:
                smtp = {}
                if os.path.exists(SMTP_PATH):
                    with open(SMTP_PATH) as f:
                        smtp = json.load(f)
                smtp["host"]      = smtp_host
                smtp["port"]      = int(request.form.get("smtp_port", 587) or 587)
                smtp["username"]  = request.form.get("smtp_user", "").strip()
                smtp["from_addr"] = request.form.get("smtp_from", "").strip()
                enc = request.form.get("smtp_enc", "starttls")
                smtp["tls"] = enc == "starttls"
                smtp["ssl"] = enc == "ssl"
                pw = request.form.get("smtp_pass", "").strip()
                if pw:
                    smtp["password"] = pw
                os.makedirs(os.path.dirname(SMTP_PATH), exist_ok=True)
                with open(SMTP_PATH, "w") as f:
                    json.dump(smtp, f, indent=2)

            session["authenticated"] = True
            return redirect(url_for("dashboard"))

    return render_template(
        "setup.html", step=step, error=error,
        version=get_version(), net=net,
    )

@app.route("/dashboard")
@login_required
@setup_required
@terms_required
def dashboard():
    resp = make_response(render_template("dashboard.html", version=get_version(), dev_mode=DEV_MODE))
    resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    resp.headers["Pragma"] = "no-cache"
    resp.headers["Expires"] = "0"
    return resp

@app.route("/terms")
@login_required
@setup_required
def terms():
    cfg = load_config()
    if cfg.get("terms_accepted"):
        return redirect(url_for("dashboard"))
    terms_path = os.path.join(BASE_DIR, "TERMS.md")
    terms_html = ""
    if os.path.exists(terms_path):
        with open(terms_path) as f:
            terms_html = render_markdown(f.read())
    resp = make_response(render_template("terms.html", terms_html=terms_html, version=get_version()))
    resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    resp.headers["Pragma"] = "no-cache"
    resp.headers["Expires"] = "0"
    return resp

@app.route("/api/terms/accept", methods=["POST"])
@login_required
@setup_required
def api_terms_accept():
    cfg = load_config()
    cfg["terms_accepted"]      = True
    cfg["terms_accepted_date"] = datetime.utcnow().isoformat()
    save_config(cfg)
    return jsonify({"status": "ok"})

@app.route("/api/setup/timezone", methods=["POST"])
def api_setup_timezone():
    data = request.get_json() or {}
    tz   = data.get("timezone", "").strip()
    if not tz or len(tz) > 64:
        return jsonify({"error": "Invalid timezone."}), 400
    if not re.match(r'^[A-Za-z_]+(/[A-Za-z_]+){0,2}$', tz) and tz != "UTC":
        return jsonify({"error": "Invalid timezone format."}), 400
    try:
        result = subprocess.run(
            ["sudo", "timedatectl", "set-timezone", tz],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode != 0:
            raise Exception(result.stderr.strip() or "timedatectl failed")
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    cfg = load_config()
    cfg["timezone"] = tz
    save_config(cfg)
    return jsonify({"status": "ok", "timezone": tz})

# --- API endpoints ---
@app.route("/api/stats")
@login_required
def api_stats():
    global _last_num_blocked
    from log_parser import parse_logs, get_summary

    cfg     = load_config()
    events  = parse_logs(LOG_PATH, dev_mode=DEV_MODE)
    events  = [e for e in events if not is_private_ip(e.get("src_ip", ""))]
    summary = get_summary(events)

    current_blocked = None
    try:
        import urllib.request, base64
        ag_user = cfg.get("adguard_user", "admin")
        ag_pass = cfg.get("adguard_password", "")
        token   = base64.b64encode(f"{ag_user}:{ag_pass}".encode()).decode()
        req     = urllib.request.Request(
            "http://127.0.0.1:3000/control/stats",
            headers={"Authorization": f"Basic {token}"}
        )
        with urllib.request.urlopen(req, timeout=3) as r:
            ag_data = json.loads(r.read())
        current_blocked = int(ag_data.get("num_blocked_filtering", 0))
    except Exception:
        pass

    if current_blocked is not None:
        with _lifetime_blocked_lock:
            if _last_num_blocked is None:
                if "lifetime_blocked" not in cfg:
                    try:
                        import urllib.request, base64 as _b64
                        ag_user = cfg.get("adguard_user", "admin")
                        ag_pass = cfg.get("adguard_password", "")
                        token   = _b64.b64encode(f"{ag_user}:{ag_pass}".encode()).decode()
                        req     = urllib.request.Request(
                            "http://127.0.0.1:3000/control/stats",
                            headers={"Authorization": f"Basic {token}"}
                        )
                        with urllib.request.urlopen(req, timeout=3) as r:
                            ag_hist = json.loads(r.read())
                        history_total = sum(ag_hist.get("blocked_filtering", []))
                        cfg["lifetime_blocked"] = history_total
                        save_config(cfg)
                    except Exception:
                        cfg["lifetime_blocked"] = current_blocked
                        save_config(cfg)
                _last_num_blocked = current_blocked
            else:
                delta = current_blocked - _last_num_blocked
                if delta > 0:
                    cfg["lifetime_blocked"] = cfg.get("lifetime_blocked", 0) + delta
                    save_config(cfg)
                _last_num_blocked = current_blocked

    lifetime_blocked = cfg.get("lifetime_blocked", 0)

    return jsonify({
        "events":           events[:100],
        "summary":          summary,
        "interface":        cfg.get("interface", "eth0"),
        "version":          get_version(),
        "lifetime_blocked": lifetime_blocked,
    })

@app.route("/api/threat-map")
@login_required
def api_threat_map():
    try:
        db_path  = "/opt/honeytrapai/data/GeoLite2-Country.mmdb"
        log_dir  = "/var/log/maltrail/"
        cutoff   = datetime.utcnow() - timedelta(hours=24)
        events   = []

        log_files = []
        for delta in (0, 1):
            d = datetime.utcnow() - timedelta(days=delta)
            p = os.path.join(log_dir, d.strftime("%Y-%m-%d") + ".log")
            log_files.extend(glob.glob(p))
        maltrail_log = os.path.join(log_dir, "maltrail.log")
        if os.path.exists(maltrail_log):
            log_files.append(maltrail_log)

        def parse_line(line):
            line = line.strip()
            if not line:
                return None
            if line.startswith('"'):
                try:
                    ts_str, rest = line[1:].split('"', 1)
                    ts    = datetime.strptime(ts_str[:19], "%Y-%m-%d %H:%M:%S")
                    parts = rest.strip().split(" ")
                    if len(parts) < 7:
                        return None
                    src_ip = parts[1]
                    trail  = parts[6]
                    info   = " ".join(parts[7:]) if len(parts) > 7 else ""
                    return ts, src_ip, trail, info
                except Exception:
                    return None
            else:
                try:
                    parts = line.split(" ")
                    if len(parts) < 10:
                        return None
                    ts     = datetime.strptime(f"{parts[0]} {parts[1]}", "%Y-%m-%d %H:%M:%S")
                    src_ip = parts[3]
                    trail  = parts[8]
                    info   = " ".join(parts[9:]) if len(parts) > 9 else ""
                    return ts, src_ip, trail, info
                except Exception:
                    return None

        with geoip2.database.Reader(db_path) as reader:
            for log_file in log_files:
                try:
                    with open(log_file, "r") as f:
                        for line in f:
                            parsed = parse_line(line)
                            if not parsed:
                                continue
                            ts, src_ip, trail, info = parsed

                            if ts < cutoff:
                                continue

                            if is_private_ip(src_ip):
                                continue

                            try:
                                geo          = reader.country(src_ip)
                                country_code = geo.country.iso_code or ""
                                country_name = geo.country.name or "Unknown"
                            except Exception:
                                continue

                            lat, lon, city = _resolve_geo(src_ip, country_code)
                            if lat is None or lon is None:
                                continue

                            il = info.lower()
                            if any(x in il for x in ["malware","c2","botnet","ransomware","rat","backdoor","trojan","exploit"]):
                                severity = "high"
                            elif any(x in il for x in ["scanner","suspicious","threat","attack","probe","brute","phishing","tor","spam","adware","tracking"]):
                                severity = "medium"
                            else:
                                severity = "low"

                            events.append({
                                "ip":           src_ip,
                                "country_code": country_code,
                                "country_name": country_name,
                                "city":         city,
                                "lat":          lat,
                                "lon":          lon,
                                "trail":        trail,
                                "severity":     severity,
                                "timestamp":    ts.strftime("%Y-%m-%d %H:%M UTC"),
                            })
                except Exception:
                    continue

        return jsonify({"events": events})

    except Exception as e:
        return jsonify({"error": str(e), "events": []})

@app.route("/api/services/status")
@login_required
def api_services_status():
    statuses = {}
    for svc in ["honeytrapai", "adguardhome", "maltrail-sensor", "honeytrapai-notifier"]:
        try:
            r = subprocess.run(["systemctl", "is-active", svc],
                               capture_output=True, text=True)
            statuses[svc] = r.stdout.strip() == "active"
        except Exception:
            statuses[svc] = False

    try:
        import socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(1)
        query = b'\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x01'
        sock.sendto(query, ("127.0.0.1", 53))
        sock.recv(512)
        sock.close()
        statuses["dns"] = True
    except Exception:
        statuses["dns"] = False

    critical      = ["adguardhome", "maltrail-sensor"]
    all_ok        = all(statuses.get(s) for s in critical) and statuses.get("dns") and statuses.get("honeytrapai-notifier")
    critical_down = not all(statuses.get(s) for s in critical)

    if critical_down:
        overall = "red"
    elif not all_ok:
        overall = "amber"
    else:
        overall = "green"

    return jsonify({"services": statuses, "overall": overall})

@app.route("/api/adguard/stats")
@login_required
def api_adguard_stats():
    if DEV_MODE:
        return jsonify({
            "num_dns_queries": 14823, "num_blocked_filtering": 1247,
            "num_replaced_safebrowsing": 12, "num_replaced_parental": 0,
            "avg_processing_time": 2.4,
            "top_queried_domains": [{"google.com":342},{"apple.com":187},{"netflix.com":143}],
            "top_blocked_domains": [{"doubleclick.net":89},{"googlesyndication.com":67},{"facebook.com":45}]
        })
    try:
        import urllib.request, base64
        cfg    = load_config()
        ag_user= cfg.get("adguard_user", "admin")
        ag_pass= cfg.get("adguard_password", "")
        token  = base64.b64encode(f"{ag_user}:{ag_pass}".encode()).decode()
        req    = urllib.request.Request(
            "http://127.0.0.1:3000/control/stats",
            headers={"Authorization": f"Basic {token}"}
        )
        with urllib.request.urlopen(req, timeout=3) as r:
            data = json.loads(r.read())
        queries_24h = sum(data.get("dns_queries",       [])[-24:])
        blocked_24h = sum(data.get("blocked_filtering", [])[-24:])
        data["num_dns_queries"]      = queries_24h
        data["num_blocked_filtering"] = blocked_24h
        return jsonify(data)
    except Exception as e:
        return jsonify({"error": str(e)}), 503

@app.route("/api/adguard/history")
@login_required
def api_adguard_history():
    if DEV_MODE:
        import random
        now_h   = datetime.now().hour
        hours   = [f"{(now_h - 23 + i) % 24:02d}:00" for i in range(24)]
        base    = [random.randint(300, 900) for _ in range(24)]
        blocked = [int(b * random.uniform(0.05, 0.18)) for b in base]
        return jsonify({"hours": hours, "queries": base, "blocked": blocked})

    try:
        import urllib.request, base64
        cfg     = load_config()
        ag_user = cfg.get("adguard_user", "admin")
        ag_pass = cfg.get("adguard_password", "")
        token   = base64.b64encode(f"{ag_user}:{ag_pass}".encode()).decode()
        req     = urllib.request.Request(
            "http://127.0.0.1:3000/control/stats",
            headers={"Authorization": f"Basic {token}"}
        )
        with urllib.request.urlopen(req, timeout=3) as r:
            data = json.loads(r.read())

        queries_all = data.get("dns_queries",       [])
        blocked_all = data.get("blocked_filtering", [])

        if not queries_all:
            return jsonify({"hours": [], "queries": [], "blocked": []})

        queries = list(queries_all)[-24:]
        blocked = list(blocked_all)[-24:]

        while len(queries) < 24:
            queries.insert(0, 0)
        while len(blocked) < 24:
            blocked.insert(0, 0)

        now_h = datetime.now().hour
        hours = [f"{(now_h - 23 + i) % 24:02d}:00" for i in range(24)]

        return jsonify({"hours": hours, "queries": queries, "blocked": blocked})

    except Exception as e:
        return jsonify({"error": str(e)}), 503

@app.route("/api/settings", methods=["GET", "POST"])
@login_required
def api_settings():
    cfg  = load_config()
    smtp = {}
    if os.path.exists(SMTP_PATH):
        with open(SMTP_PATH) as f:
            smtp = json.load(f)

    if request.method == "POST":
        data = request.get_json()
        if "alert_email"     in data: cfg["alert_email"]     = data["alert_email"]
        if "interface"       in data: cfg["interface"]       = data["interface"]
        if "alert_threshold" in data: cfg["alert_threshold"] = data["alert_threshold"]
        if "email_disabled"  in data: cfg["email_disabled"]  = bool(data["email_disabled"])
        save_config(cfg)
        return jsonify({"status": "ok"})

    return jsonify({
        "alert_email":     cfg.get("alert_email", ""),
        "interface":       cfg.get("interface", "eth0"),
        "alert_threshold": cfg.get("alert_threshold", "medium"),
        "email_disabled":  bool(cfg.get("email_disabled", False)),
        "smtp_configured": bool(smtp.get("host")),
        "setup_date":      cfg.get("setup_date", "")
    })

@app.route("/api/password", methods=["POST"])
@login_required
def api_change_password():
    cfg    = load_config()
    data   = request.get_json()
    current= data.get("current", "")
    new_pw = data.get("new_password", "")
    confirm= data.get("confirm", "")

    if not verify_password(current, cfg.get("password_hash", "")):
        return jsonify({"error": "Current password is incorrect."}), 400
    if len(new_pw) < 8:
        return jsonify({"error": "New password must be at least 8 characters."}), 400
    if new_pw != confirm:
        return jsonify({"error": "New passwords do not match."}), 400

    cfg["password_hash"]    = hash_password(new_pw)
    cfg["password_changed"] = True
    save_config(cfg)
    return jsonify({"status": "ok"})

@app.route("/api/update/check")
@login_required
def api_update_check():
    try:
        from updater import check_for_update
        return jsonify(check_for_update(force="force" in request.args))
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/update/install", methods=["POST"])
@login_required
def api_update_install():
    try:
        import threading
        from updater import perform_update
        threading.Thread(target=perform_update, daemon=True).start()
        return jsonify({"status": "started"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/update/status")
@login_required
def api_update_status():
    try:
        from updater import get_update_status
        return jsonify(get_update_status())
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/update/schedule", methods=["GET", "POST"])
@login_required
def api_update_schedule():
    """ISSUE-46 — Auto OTA schedule config."""
    if request.method == "POST":
        data = request.get_json() or {}
        cfg  = load_config()
        if "auto_ota_enabled" in data:
            cfg["auto_ota_enabled"] = bool(data["auto_ota_enabled"])
            save_config(cfg)
        return jsonify({"status": "ok"})

    cfg     = load_config()
    h, m    = _get_or_init_ota_schedule()
    enabled = cfg.get("auto_ota_enabled", True)

    now    = datetime.now()
    target = now.replace(hour=h, minute=m, second=0, microsecond=0)
    if target <= now:
        target += timedelta(days=1)
    day_str  = "today" if target.date() == now.date() else "tomorrow"
    time_str = target.strftime("%I:%M %p").lstrip("0")

    return jsonify({
        "auto_ota_enabled": enabled,
        "ota_check_hour":   h,
        "ota_check_minute": m,
        "next_check":       f"{day_str} at {time_str}",
    })

@app.route("/api/backup")
@login_required
def api_backup():
    cfg  = load_config()
    smtp = {}
    if os.path.exists(SMTP_PATH):
        with open(SMTP_PATH) as f:
            smtp = json.load(f)
    backup = {"config": cfg, "smtp": smtp, "version": get_version(),
              "backup_date": datetime.utcnow().isoformat()}
    data = json.dumps(backup, indent=2).encode()
    return app.response_class(
        response=data, status=200, mimetype="application/json",
        headers={"Content-Disposition": "attachment; filename=honeytrapai-backup.json"}
    )

@app.route("/api/factory-reset", methods=["POST"])
@login_required
def api_factory_reset():
    cfg      = load_config()
    data     = request.get_json()
    password = data.get("password", "")

    if not verify_password(password, cfg.get("password_hash", "")):
        return jsonify({"error": "Incorrect password."}), 400

    _perform_factory_reset()

    import threading
    def _reboot():
        import time
        time.sleep(2)
        subprocess.run(["sudo", "reboot"], check=False)
    threading.Thread(target=_reboot, daemon=True).start()
    return jsonify({"status": "ok"})

def _perform_factory_reset():
    """ISSUE-66 — clear AdGuard PC rules before wiping config."""
    existing = {}
    if os.path.exists(CONFIG_PATH):
        try:
            with open(CONFIG_PATH) as f:
                existing = json.load(f)
        except Exception:
            pass
    ag_user          = existing.get("adguard_user", "admin")
    ag_pass          = existing.get("adguard_password", "")
    lifetime_blocked = existing.get("lifetime_blocked", 0)

    try:
        existing_rules = _get_adguard_user_rules(existing)
        clean_rules = [r for r in existing_rules
                       if not r.strip().startswith("# honeytrapai-parental-")]
        _set_adguard_user_rules(existing, clean_rules)
    except Exception:
        pass

    for path in [CONFIG_PATH, SMTP_PATH]:
        if os.path.exists(path):
            os.remove(path)

    helper = os.path.join(BASE_DIR, "set_static_ip_helper.py")
    subprocess.run(["sudo", "python3", helper, "--remove"], capture_output=True)

    preserved = {"lifetime_blocked": lifetime_blocked, "password_changed": False}
    if ag_pass:
        preserved["adguard_user"]     = ag_user
        preserved["adguard_password"] = ag_pass
    os.makedirs(os.path.dirname(CONFIG_PATH), exist_ok=True)
    with open(CONFIG_PATH, "w") as f:
        json.dump(preserved, f, indent=2)

# --- Country blocking helpers ---

def _fetch_cidrs(cc):
    import urllib.request as _ur
    cc_lower = cc.lower()
    for url_tpl in (IPDENY_URL, HERRBISCHOFF_URL):
        url = url_tpl.format(cc=cc_lower)
        try:
            req = _ur.Request(url, headers={"User-Agent": "HoneytrapAI/1.0"})
            with _ur.urlopen(req, timeout=15) as r:
                text = r.read().decode("utf-8", errors="ignore")
            cidrs = [line.strip() for line in text.splitlines()
                     if line.strip() and not line.startswith("#")]
            if cidrs:
                return cidrs
        except Exception:
            continue
    raise Exception(f"Could not fetch CIDR list for {cc} from any source.")

def _adguard_rule(cidr):
    return f"||{cidr}^$network"

def _ag_request(cfg, method, path, payload=None):
    import urllib.request as _ur, base64 as _b64
    ag_user = cfg.get("adguard_user", "admin")
    ag_pass = cfg.get("adguard_password", "")
    token   = _b64.b64encode(f"{ag_user}:{ag_pass}".encode()).decode()
    data    = json.dumps(payload).encode() if payload is not None else None
    headers = {"Authorization": f"Basic {token}"}
    if data:
        headers["Content-Type"] = "application/json"
    req = _ur.Request(f"http://127.0.0.1:3000{path}", data=data,
                      headers=headers, method=method)
    with _ur.urlopen(req, timeout=10) as r:
        return r.status, r.read()

def _get_adguard_user_rules(cfg):
    try:
        status, body = _ag_request(cfg, "GET", "/control/filtering/status")
        data = json.loads(body)
        return data.get("user_rules") or []
    except Exception:
        return []

def _set_adguard_user_rules(cfg, rules):
    try:
        status, _ = _ag_request(cfg, "POST", "/control/filtering/set_rules",
                                 {"rules": rules})
        return status in (200, 204)
    except Exception:
        return False

def _add_adguard_rules(cfg, rules):
    if not rules:
        return 0, None
    existing = _get_adguard_user_rules(cfg)
    existing_set = set(existing)
    new_rules = [r for r in rules if r not in existing_set]
    if not new_rules:
        return 0, None
    merged = existing + new_rules
    if _set_adguard_user_rules(cfg, merged):
        return len(new_rules), None
    return 0, "AdGuard rejected the rule update."

def _remove_adguard_rules(cfg, rules):
    if not rules:
        return 0
    rules_set = set(rules)
    existing  = _get_adguard_user_rules(cfg)
    kept      = [r for r in existing if r not in rules_set]
    removed   = len(existing) - len(kept)
    if removed > 0:
        _set_adguard_user_rules(cfg, kept)
    return removed

# --- Country blocking routes ---

@app.route("/api/country/blocked")
@login_required
def api_country_blocked():
    cfg     = load_config()
    blocked = cfg.get("blocked_countries", {})
    return jsonify({"blocked": list(blocked.keys())})

@app.route("/api/country/block", methods=["POST"])
@login_required
def api_country_block():
    data = request.get_json() or {}
    cc   = (data.get("country_code") or "").upper().strip()
    if not cc or len(cc) != 2 or not cc.isalpha():
        return jsonify({"error": "Invalid country code."}), 400

    cfg     = load_config()
    blocked = cfg.get("blocked_countries", {})

    if cc in blocked:
        return jsonify({"status": "already_blocked", "country_code": cc})

    try:
        cidrs = _fetch_cidrs(cc)
    except Exception as e:
        return jsonify({"error": str(e)}), 502

    if not cidrs:
        return jsonify({"error": f"No CIDRs found for {cc}."}), 404

    rules = [_adguard_rule(c) for c in cidrs]

    pushed, err = _add_adguard_rules(cfg, rules)
    if err:
        return jsonify({"error": err}), 502

    blocked[cc]              = rules
    cfg["blocked_countries"] = blocked
    save_config(cfg)

    return jsonify({
        "status":       "blocked",
        "country_code": cc,
        "cidr_count":   len(cidrs),
        "rules_pushed": pushed,
    })

@app.route("/api/country/unblock", methods=["POST"])
@login_required
def api_country_unblock():
    data = request.get_json() or {}
    cc   = (data.get("country_code") or "").upper().strip()
    if not cc or len(cc) != 2 or not cc.isalpha():
        return jsonify({"error": "Invalid country code."}), 400

    cfg     = load_config()
    blocked = cfg.get("blocked_countries", {})

    if cc not in blocked:
        return jsonify({"status": "not_blocked", "country_code": cc})

    rules   = blocked[cc]
    removed = _remove_adguard_rules(cfg, rules)

    del blocked[cc]
    cfg["blocked_countries"] = blocked
    save_config(cfg)

    return jsonify({
        "status":        "unblocked",
        "country_code":  cc,
        "rules_removed": removed,
    })

@app.route("/api/smtp", methods=["GET", "POST"])
@login_required
def api_smtp():
    if request.method == "POST":
        data = request.get_json() or {}
        smtp = {}
        if os.path.exists(SMTP_PATH):
            with open(SMTP_PATH) as f:
                smtp = json.load(f)
        smtp["host"]      = data.get("host",      smtp.get("host", ""))
        smtp["port"]      = int(data.get("port",  smtp.get("port", 587)))
        smtp["username"]  = data.get("username",  smtp.get("username", ""))
        smtp["from_addr"] = data.get("from_addr", smtp.get("from_addr", ""))
        smtp["tls"]       = data.get("tls",       smtp.get("tls", True))
        smtp["ssl"]       = data.get("ssl",       smtp.get("ssl", False))
        if "password" in data and data["password"]:
            smtp["password"] = data["password"]
        os.makedirs(os.path.dirname(SMTP_PATH), exist_ok=True)
        with open(SMTP_PATH, "w") as f:
            json.dump(smtp, f, indent=2)
        return jsonify({"status": "ok"})

    smtp = {}
    if os.path.exists(SMTP_PATH):
        with open(SMTP_PATH) as f:
            smtp = json.load(f)
    return jsonify({
        "host":       smtp.get("host", ""),
        "port":       smtp.get("port", 587),
        "username":   smtp.get("username", ""),
        "from_addr":  smtp.get("from_addr", ""),
        "tls":        smtp.get("tls", True),
        "ssl":        smtp.get("ssl", False),
        "configured": bool(smtp.get("host")),
    })

@app.route("/api/email/test", methods=["POST"])
@login_required
def api_email_test():
    data  = request.get_json() or {}
    email = data.get("email", "").strip()
    if not email:
        return jsonify({"error": "No email address provided."}), 400

    cfg = load_config()
    if cfg.get("email_disabled", False):
        return jsonify({"error": "Alert emails are disabled. Uncheck 'Disable Sending Alert Emails' in settings first."}), 400

    smtp = {}
    if os.path.exists(SMTP_PATH):
        with open(SMTP_PATH) as f:
            smtp = json.load(f)

    if not smtp.get("host"):
        return jsonify({"error": "SMTP is not configured. Add your SMTP settings first."}), 400

    host = smtp.get("host", "")
    port = int(smtp.get("port", 587))
    user = smtp.get("username", "")
    pw   = smtp.get("password", "")

    try:
        import smtplib
        from email.mime.text import MIMEText
        from email.mime.multipart import MIMEMultipart

        msg            = MIMEMultipart("alternative")
        msg["Subject"] = "HoneytrapAI — Test Email"
        msg["From"]    = smtp.get("from_addr", user)
        msg["To"]      = email

        body_text = (
            "This is a test email from your HoneytrapAI appliance.\n\n"
            "If you received this, your alert email settings are working correctly.\n\n"
            "No cloud. No subscription. No monthly fees. Ever.\n"
            "— HoneytrapAI"
        )
        body_html = """
        <div style="font-family:-apple-system,sans-serif;background:#0f0f1a;color:#e0e0e0;
                    padding:2rem;max-width:480px;margin:0 auto;border-radius:10px">
          <div style="font-size:2rem;margin-bottom:.5rem">&#x1F41D;</div>
          <div style="color:#f5a623;font-size:1.1rem;font-weight:700;margin-bottom:.8rem">
            HoneytrapAI — Test Email
          </div>
          <p style="color:#aaa;font-size:.9rem;line-height:1.7;margin-bottom:1rem">
            This is a test email from your HoneytrapAI appliance.<br>
            If you received this, your alert email settings are working correctly.
          </p>
          <hr style="border:none;border-top:1px solid #2a2a4a;margin:1rem 0">
          <div style="font-size:.75rem;color:#555">
            No cloud. No subscription. No monthly fees. Ever.
          </div>
        </div>"""

        msg.attach(MIMEText(body_text, "plain"))
        msg.attach(MIMEText(body_html, "html"))

        use_ssl = smtp.get("ssl", False)
        use_tls = smtp.get("tls", True)

        if use_ssl:
            server = smtplib.SMTP_SSL(host, port, timeout=10)
            server.ehlo()
        else:
            server = smtplib.SMTP(host, port, timeout=10)
            server.ehlo()
            if use_tls:
                server.starttls()
                server.ehlo()

        if user and pw:
            server.login(user, pw)
        server.sendmail(msg["From"], [email], msg.as_string())
        server.quit()

        return jsonify({"status": "ok"})

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/simulate/threat", methods=["POST"])
@login_required
def api_simulate_threat():
    import random
    data        = request.get_json() or {}
    threat_type = data.get("threat_type", "malware")
    src_ip_in   = data.get("src_ip") or None

    THREAT_PROFILES = {
        "malware":    (["evil-payload.ru",  "malware-drop.cn",  "bad-actor.xyz"],    "malware dropper",     "high"),
        "c2":         (["c2-beacon.io",     "botnet-ctrl.net",  "rat-server.ru"],    "C2 beacon",           "high"),
        "ransomware": (["ransom-key.org",   "lockbit-cdn.io",   "encrypt-srv.net"],  "ransomware C2",       "high"),
        "phishing":   (["login-secure.xyz", "paypal-verify.cc", "account-check.net"],"phishing domain",     "medium"),
        "scanner":    (["masscan.host",     "shodan.io",        "scanner-bot.net"],  "port scanner",        "medium"),
        "tor":        (["tor-exit-42.org",  "onion-relay.net",  "tor-gw.io"],        "Tor exit node",       "medium"),
        "tracker":    (["telemetry.co",     "analytics-cdn.io", "track.pixel.net"],  "tracker / telemetry", "low"),
    }
    trails, info, severity = THREAT_PROFILES.get(threat_type, THREAT_PROFILES["malware"])
    trail = random.choice(trails)

    src_ip = src_ip_in or (
        f"{random.randint(1,223)}.{random.randint(0,255)}"
        f".{random.randint(0,255)}.{random.randint(1,254)}"
    )
    dst_ip   = "192.168.1.1"
    src_port = random.randint(1024, 65535)
    dst_port = random.choice([53, 80, 443, 8080])
    proto    = random.choice(["DNS", "TCP", "UDP"])
    ts       = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    line     = f"{ts} honeytrap {src_ip} {src_port} {dst_ip} {dst_port} {proto} {trail} {info};https://honeytrap.ai/simulate\n"

    try:
        helper = os.path.join(BASE_DIR, "log_inject_helper.py")
        result = subprocess.run(
            ["sudo", "python3", helper, line],
            capture_output=True, text=True
        )
        if result.returncode != 0:
            raise Exception(result.stderr.strip() or "log_inject_helper failed")
    except Exception as e:
        return jsonify({"error": str(e)}), 500

    trigger_path = os.path.join(BASE_DIR, "config", "notifier_trigger")
    try:
        os.makedirs(os.path.dirname(trigger_path), exist_ok=True)
        open(trigger_path, "w").close()
    except Exception:
        pass

    return jsonify({"status": "ok", "trail": trail, "src_ip": src_ip,
                    "severity": severity, "info": info})

@app.route("/api/threats/export")
@login_required
def api_threats_export():
    import csv, io
    from log_parser import parse_logs
    events   = parse_logs(LOG_PATH, dev_mode=DEV_MODE)
    events   = [e for e in events if not is_private_ip(e.get("src_ip", ""))]
    output   = io.StringIO()
    fieldnames = ["timestamp","severity","src_ip","dst_ip","proto","trail","info","reference"]
    writer   = csv.DictWriter(output, fieldnames=fieldnames)
    writer.writeheader()
    for e in events:
        writer.writerow({k: e.get(k, "") for k in fieldnames})
    filename = f"honeytrapai-threats-{datetime.utcnow().strftime('%Y%m%d-%H%M%S')}.csv"
    return app.response_class(
        response=output.getvalue().encode(), status=200, mimetype="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )

@app.route("/api/threats/purge", methods=["POST"])
@login_required
def api_threats_purge():
    try:
        open(LOG_PATH, "w").close()
        return jsonify({"status": "ok"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/restore", methods=["POST"])
@login_required
def api_restore():
    """ISSUE-65 — re-sync AdGuard parental control rules after restore."""
    try:
        f = request.files.get("backup")
        if not f:
            return jsonify({"error": "No file provided"}), 400
        backup = json.load(f)
        if "config" in backup:
            save_config(backup["config"])
        if "smtp" in backup and backup["smtp"]:
            os.makedirs(os.path.dirname(SMTP_PATH), exist_ok=True)
            with open(SMTP_PATH, "w") as sf:
                json.dump(backup["smtp"], sf, indent=2)
        cfg = load_config()
        pc  = cfg.get("parental_controls", {})
        if pc:
            try:
                _pc_apply_all(cfg, pc)
            except Exception:
                pass
        return jsonify({"status": "ok"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# --- Tools API routes ---

@app.route("/api/tools/ping", methods=["POST"])
@login_required
def api_tools_ping():
    data = request.get_json() or {}
    host = data.get("host", "").strip()
    if not is_safe_host(host):
        return jsonify({"error": "Invalid host."}), 400
    try:
        result = subprocess.run(
            ["ping", "-c", "4", "-W", "5", host],
            capture_output=True, text=True, timeout=30
        )
        output = result.stdout or result.stderr
        return jsonify({"output": output, "success": result.returncode == 0})
    except subprocess.TimeoutExpired:
        return jsonify({"error": "Ping timed out."}), 504
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/tools/dns", methods=["POST"])
@login_required
def api_tools_dns():
    import socket
    data = request.get_json() or {}
    host = data.get("host", "").strip()
    if not is_safe_host(host):
        return jsonify({"error": "Invalid host."}), 400
    try:
        results = socket.getaddrinfo(host, None)
        seen = set()
        lines = [f"DNS lookup: {host}", ""]
        for r in results:
            addr = r[4][0]
            family = "IPv4" if r[0].name == "AF_INET" else "IPv6"
            key = (family, addr)
            if key not in seen:
                seen.add(key)
                lines.append(f"{family:<6}  {addr}")
        if len(lines) == 2:
            lines.append("No records found.")
        output = "\n".join(lines)
        return jsonify({"output": output, "success": True})
    except socket.gaierror as e:
        return jsonify({"output": f"DNS lookup failed: {e}", "success": False})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/tools/traceroute", methods=["POST"])
@login_required
def api_tools_traceroute():
    data = request.get_json() or {}
    host = data.get("host", "").strip()
    if not is_safe_host(host):
        return jsonify({"error": "Invalid host."}), 400
    try:
        result = subprocess.run(
            ["traceroute", "-m", "20", "-w", "3", host],
            capture_output=True, text=True, timeout=90
        )
        output = result.stdout or result.stderr
        return jsonify({"output": output, "success": result.returncode == 0})
    except subprocess.TimeoutExpired:
        return jsonify({"error": "Traceroute timed out."}), 504
    except FileNotFoundError:
        return jsonify({"error": "traceroute not installed. Run: sudo apt-get install -y traceroute"}), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/tools/portscan", methods=["POST"])
@login_required
def api_tools_portscan():
    import socket
    data  = request.get_json() or {}
    host  = data.get("host", "").strip()
    ports_raw = data.get("ports", "22,80,443,3000,8080").strip()

    if not is_safe_host(host):
        return jsonify({"error": "Invalid host."}), 400

    ports = []
    try:
        for part in ports_raw.split(","):
            part = part.strip()
            if "-" in part:
                lo, hi = part.split("-", 1)
                ports.extend(range(int(lo), int(hi) + 1))
            else:
                ports.append(int(part))
        ports = [p for p in ports if is_safe_port(p)]
        ports = list(dict.fromkeys(ports))[:50]
    except Exception:
        return jsonify({"error": "Invalid port specification."}), 400

    if not ports:
        return jsonify({"error": "No valid ports specified."}), 400

    lines = [f"Port scan: {host}", f"Scanning {len(ports)} port(s)...", ""]
    open_count = 0
    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex((host, port))
            sock.close()
            if result == 0:
                try:
                    svc = socket.getservbyport(port)
                except Exception:
                    svc = "unknown"
                lines.append(f"  {port:<6}  OPEN    {svc}")
                open_count += 1
            else:
                lines.append(f"  {port:<6}  closed")
        except Exception as e:
            lines.append(f"  {port:<6}  error: {e}")

    lines += ["", f"{open_count} open port(s) found."]
    return jsonify({"output": "\n".join(lines), "success": True})

# --- Device list — ISSUE-18 ---

@app.route('/api/devices')
@login_required
def api_devices():
    import time as _time
    global _devices_cache
    now = _time.time()
    if _devices_cache is not None:
        result, ts = _devices_cache
        if now - ts < _DEVICES_TTL:
            return jsonify(result)
    try:
        import urllib.request as _ur, json as _json, base64 as _b64, socket as _sock
        cfg    = load_config()
        user   = cfg.get('adguard_user', 'admin')
        passwd = cfg.get('adguard_password', 'admin')
        creds  = _b64.b64encode(f"{user}:{passwd}".encode()).decode()
        req = _ur.Request(
            'http://127.0.0.1:3000/control/stats',
            headers={'Authorization': f'Basic {creds}'}
        )
        with _ur.urlopen(req, timeout=5) as resp:
            data = _json.loads(resp.read().decode())
        clients = data.get('top_clients', [])
        devices = []
        for entry in clients:
            for ip, count in entry.items():
                try:
                    hostname = _sock.gethostbyaddr(ip)[0]
                except Exception:
                    hostname = ''
                devices.append({'ip': ip, 'hostname': hostname, 'queries': count})
        devices.sort(key=lambda d: d['queries'], reverse=True)
        result = {'devices': devices}
        _devices_cache = (result, now)
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 502

# --- My location — ISSUE-35 ---

@app.route('/api/my-location')
@login_required
def api_my_location():
    global _my_location_cache
    if _my_location_cache is not None:
        return jsonify(_my_location_cache)
    try:
        import urllib.request, json as _json
        with urllib.request.urlopen('http://ip-api.com/json/?fields=status,lat,lon,city,isp,timezone', timeout=5) as resp:
            data = _json.loads(resp.read().decode())
        if data.get('status') == 'success':
            _my_location_cache = {
                'lat':      data['lat'],
                'lon':      data['lon'],
                'city':     data.get('city', ''),
                'isp':      data.get('isp', ''),
                'timezone': data.get('timezone', ''),
            }
            return jsonify(_my_location_cache)
        return jsonify({'error': 'ip-api lookup failed'}), 502
    except Exception as e:
        return jsonify({'error': str(e)}), 502

# --- Network visibility — ISSUE-40 ---

@app.route('/api/network-visibility')
@login_required
def api_network_visibility():
    import time as _time
    global _net_visibility_cache
    now = _time.time()
    if _net_visibility_cache is not None:
        result, ts = _net_visibility_cache
        if now - ts < _NET_VIS_TTL:
            return jsonify(result)
    try:
        import urllib.request as _ur, json as _json, base64 as _b64
        cfg    = load_config()
        user   = cfg.get('adguard_user', 'admin')
        passwd = cfg.get('adguard_password', 'admin')
        creds  = _b64.b64encode(f"{user}:{passwd}".encode()).decode()
        req    = _ur.Request(
            'http://127.0.0.1:3000/control/stats',
            headers={'Authorization': f'Basic {creds}'}
        )
        with _ur.urlopen(req, timeout=5) as resp:
            data = _json.loads(resp.read().decode())
        pi_ip   = cfg.get('static_ip', '192.168.1.199')
        gateway = cfg.get('gateway', '')
        pi_ips  = {'127.0.0.1', '::1', pi_ip}
        clients  = data.get('top_clients', [])
        external = [ip for entry in clients for ip in entry.keys() if ip not in pi_ips]
        if not external:
            result = {'visible': False, 'reason': 'no_clients'}
        elif gateway and all(ip == gateway for ip in external):
            result = {'visible': False, 'reason': 'proxied'}
        else:
            result = {'visible': True}
    except Exception as e:
        result = {'visible': True, 'error': str(e)}
    _net_visibility_cache = (result, now)
    return jsonify(result)

# --- Top blocked domains — ISSUE-17 ---

@app.route('/api/blocked-domains')
@login_required
def api_blocked_domains():
    import time as _time
    global _blocked_domains_cache
    now = _time.time()
    if _blocked_domains_cache is not None:
        result, ts = _blocked_domains_cache
        if now - ts < _BLOCKED_DOMAINS_TTL:
            return jsonify(result)
    try:
        import urllib.request as _ur, json as _json, base64 as _b64
        cfg    = load_config()
        user   = cfg.get('adguard_user', 'admin')
        passwd = cfg.get('adguard_password', 'admin')
        creds  = _b64.b64encode(f"{user}:{passwd}".encode()).decode()
        req = _ur.Request(
            'http://127.0.0.1:3000/control/stats',
            headers={'Authorization': f'Basic {creds}'}
        )
        with _ur.urlopen(req, timeout=5) as resp:
            data = _json.loads(resp.read().decode())
        raw = data.get('top_blocked_domains', [])
        domains = []
        for entry in raw:
            for domain, count in entry.items():
                domains.append({'domain': domain, 'count': count})
        domains.sort(key=lambda d: d['count'], reverse=True)
        domains = domains[:10]
        result = {'domains': domains}
        _blocked_domains_cache = (result, now)
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 502

# --- Whois — ISSUE-21 ---

@app.route('/api/whois')
def api_whois():
    domain = request.args.get('domain', '').strip().lower()
    if not domain:
        return jsonify({'error': 'No domain provided'})
    import re as _re
    domain = _re.sub(r'^https?://', '', domain).split('/')[0]
    try:
        result = subprocess.run(
            ['whois', domain],
            capture_output=True, text=True, timeout=15
        )
        raw = result.stdout
    except subprocess.TimeoutExpired:
        return jsonify({'error': 'Whois lookup timed out'})
    except Exception as e:
        return jsonify({'error': str(e)})

    def _extract(patterns, text):
        for pat in patterns:
            m = re.search(pat, text, re.IGNORECASE | re.MULTILINE)
            if m:
                return m.group(1).strip()
        return ''

    registrar = _extract([r'^Registrar:\s*(.+)$', r'^registrar:\s*(.+)$'], raw)
    created   = _extract([r'^Creation Date:\s*(.+)$', r'^created:\s*(.+)$', r'^Registered on:\s*(.+)$'], raw)
    expires   = _extract([r'^Registry Expiry Date:\s*(.+)$', r'^Expiry Date:\s*(.+)$', r'^expires:\s*(.+)$'], raw)
    org       = _extract([r'^Registrant Organization:\s*(.+)$', r'^org-name:\s*(.+)$', r'^Organization:\s*(.+)$'], raw)
    country   = _extract([r'^Registrant Country:\s*(.+)$', r'^country:\s*(.+)$'], raw)

    return jsonify({
        'domain':    domain,
        'registrar': registrar[:80] if registrar else '',
        'created':   created.split('T')[0] if 'T' in created else created,
        'expires':   expires.split('T')[0] if 'T' in expires else expires,
        'org':       org[:80] if org else '',
        'country':   country,
    })

# --- Domain allowlist — ISSUE-44 ---

@app.route('/api/allowlist')
@login_required
def api_allowlist():
    import time as _time
    global _allowlist_cache
    now = _time.time()
    if _allowlist_cache is not None:
        result, ts = _allowlist_cache
        if now - ts < _ALLOWLIST_TTL:
            return jsonify(result)
    try:
        cfg   = load_config()
        rules = _get_adguard_user_rules(cfg)
        domains = []
        for rule in rules:
            rule = rule.strip()
            if rule.startswith('@@||'):
                inner  = rule[4:]
                domain = inner.split('^')[0]
                if domain:
                    domains.append(domain)
        result = {'domains': domains}
        _allowlist_cache = (result, now)
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 502

@app.route('/api/allowlist/add', methods=['POST'])
@login_required
def api_allowlist_add():
    global _allowlist_cache
    data   = request.get_json() or {}
    domain = data.get('domain', '').strip().lower()
    if not domain or not is_safe_host(domain):
        return jsonify({'error': 'Invalid domain.'}), 400
    cfg  = load_config()
    rule = f'@@||{domain}^'
    added, err = _add_adguard_rules(cfg, [rule])
    if err:
        return jsonify({'error': err}), 502
    _allowlist_cache = None
    return jsonify({'ok': True, 'domain': domain})

@app.route('/api/allowlist/remove', methods=['POST'])
@login_required
def api_allowlist_remove():
    global _allowlist_cache
    data   = request.get_json() or {}
    domain = data.get('domain', '').strip().lower()
    if not domain or not is_safe_host(domain):
        return jsonify({'error': 'Invalid domain.'}), 400
    cfg  = load_config()
    rule = f'@@||{domain}^'
    _remove_adguard_rules(cfg, [rule])
    _allowlist_cache = None
    return jsonify({'ok': True, 'domain': domain})

# --- AdGuard filtering toggle — ISSUE-15 ---

@app.route('/api/filtering/status')
@login_required
def api_filtering_status():
    try:
        cfg    = load_config()
        status, body = _ag_request(cfg, "GET", "/control/filtering/status")
        data   = json.loads(body)
        return jsonify({"enabled": bool(data.get("enabled", True))})
    except Exception as e:
        return jsonify({"error": str(e)}), 502

@app.route('/api/filtering/toggle', methods=['POST'])
@login_required
def api_filtering_toggle():
    data    = request.get_json() or {}
    enabled = bool(data.get("enabled", True))
    try:
        cfg = load_config()
        _ag_request(cfg, "POST", "/control/filtering/config", {"enabled": enabled})
        return jsonify({"enabled": enabled})
    except Exception as e:
        return jsonify({"error": str(e)}), 502

# --- Security Score — ISSUE-57 ---
# Scoring breakdown (100pts total):
#   AdGuard Running        15pts
#   DNS Filtering ON       15pts
#   HTTPS Enabled          10pts
#   Password Changed       10pts
#   Email Notifications    10pts
#   Parental Controls      10pts
#   Threat Block Rate 24h   0-30pts

@app.route('/api/security-score')
@login_required
def api_security_score():
    score   = 0
    signals = {}
    cfg     = load_config()

    # AdGuard service running (15pts)
    try:
        r = subprocess.run(["systemctl", "is-active", "adguardhome"],
                           capture_output=True, text=True)
        ag_running = r.stdout.strip() == "active"
    except Exception:
        ag_running = False
    signals["adguard_running"] = {
        "label": "AdGuard Running", "ok": ag_running,
        "points": 15, "earned": 15 if ag_running else 0, "fix": None
    }
    score += signals["adguard_running"]["earned"]

    # AdGuard DNS filtering ON (15pts)
    try:
        _, body = _ag_request(cfg, "GET", "/control/filtering/status")
        ag_on = bool(json.loads(body).get("enabled", False))
    except Exception:
        ag_on = False
    signals["adguard_filtering"] = {
        "label": "DNS Filtering", "ok": ag_on,
        "points": 15, "earned": 15 if ag_on else 0, "fix": "filtering"
    }
    score += signals["adguard_filtering"]["earned"]

    # HTTPS enabled — nginx listening on 443 (10pts)
    try:
        r = subprocess.run(["ss", "-tlnp", "sport", "=", ":443"],
                           capture_output=True, text=True, timeout=5)
        https_on = ":443" in r.stdout
    except Exception:
        https_on = False
    signals["https"] = {
        "label": "HTTPS Enabled", "ok": https_on,
        "points": 10, "earned": 10 if https_on else 0, "fix": None
    }
    score += signals["https"]["earned"]

    # Password changed from default (10pts)
    pw_changed = bool(cfg.get("password_changed", False))
    signals["password_changed"] = {
        "label": "Password Changed", "ok": pw_changed,
        "points": 10, "earned": 10 if pw_changed else 0, "fix": "password"
    }
    score += signals["password_changed"]["earned"]

    # Email notifications configured (10pts)
    smtp_ok = False
    try:
        if os.path.exists(SMTP_PATH):
            with open(SMTP_PATH) as f:
                smtp_ok = bool(json.load(f).get("host", "").strip())
    except Exception:
        smtp_ok = False
    signals["email_configured"] = {
        "label": "Email Notifications", "ok": smtp_ok,
        "points": 10, "earned": 10 if smtp_ok else 0, "fix": "notifications"
    }
    score += signals["email_configured"]["earned"]

    # Parental Controls enabled (10pts)
    pc_cfg = cfg.get("parental_controls", {})
    pc_on  = bool(pc_cfg.get("enabled", False))
    signals["parental_controls"] = {
        "label": "Parental Controls", "ok": pc_on,
        "points": 10, "earned": 10 if pc_on else 0, "fix": "parental"
    }
    score += signals["parental_controls"]["earned"]

    # Block rate last 24h (0-30pts, no grace — 0 queries = 0pts)
    block_pts = 0
    block_pct = None
    queries_24h = 0
    blocked_24h = 0
    try:
        import urllib.request as _ur, base64 as _b64
        ag_user = cfg.get("adguard_user", "admin")
        ag_pass = cfg.get("adguard_password", "")
        token   = _b64.b64encode(f"{ag_user}:{ag_pass}".encode()).decode()
        req     = _ur.Request("http://127.0.0.1:3000/control/stats",
                              headers={"Authorization": f"Basic {token}"})
        with _ur.urlopen(req, timeout=3) as r:
            ag_stats = json.loads(r.read())
        queries_24h = sum(list(ag_stats.get("dns_queries",       []))[-24:])
        blocked_24h = sum(list(ag_stats.get("blocked_filtering", []))[-24:])
        if queries_24h > 0:
            block_pct = blocked_24h / queries_24h
            block_pts = round(block_pct * 30)
    except Exception:
        pass
    signals["block_rate"] = {
        "label":       "Threat Block Rate (24h)",
        "ok":          block_pts >= 15,
        "points":      30,
        "earned":      block_pts,
        "fix":         None,
        "block_pct":   round(block_pct * 100, 1) if block_pct is not None else None,
        "queries_24h": queries_24h,
        "blocked_24h": blocked_24h,
    }
    score += block_pts

    # Grade
    if score >= 90:
        grade = "A"
    elif score >= 75:
        grade = "B"
    elif score >= 50:
        grade = "C"
    elif score >= 25:
        grade = "D"
    else:
        grade = "F"

    return jsonify({
        "score":   score,
        "grade":   grade,
        "signals": signals,
    })

# --- Parental Controls — ISSUE-11 ---

PARENTAL_RULES = {
    "adult": [
        "||pornhub.com^", "||xvideos.com^", "||xnxx.com^", "||xhamster.com^",
        "||redtube.com^", "||youporn.com^", "||tube8.com^", "||spankbang.com^",
        "||beeg.com^", "||tnaflix.com^", "||porntrex.com^", "||4tube.com^",
        "||keezmovies.com^", "||xtube.com^", "||slutload.com^",
    ],
    "gambling": [
        "||bet365.com^", "||draftkings.com^", "||fanduel.com^", "||betway.com^",
        "||888casino.com^", "||pokerstars.com^", "||bovada.lv^", "||mybookie.ag^",
        "||betonline.ag^", "||sportsbetting.ag^", "||betmgm.com^", "||caesars.com^",
        "||pointsbet.com^", "||unibet.com^", "||williamhill.com^",
    ],
    "dating": [
        "||tinder.com^", "||match.com^", "||okcupid.com^", "||plentyoffish.com^",
        "||eharmony.com^", "||bumble.com^", "||hinge.co^", "||grindr.com^",
        "||scruff.com^", "||adult-friend-finder.com^", "||adultfriendfinder.com^",
        "||ashley-madison.com^", "||ashleymadison.com^", "||zoosk.com^",
    ],
    "drugs": [
        "||silk-road.com^", "||weedmaps.com^", "||leafly.com^",
        "||erowid.org^", "||bluelight.org^", "||shroomery.org^",
        "||dea.gov^$badfilter",
    ],
    "violence": [
        "||bestgore.com^", "||liveleak.com^", "||goregrish.com^",
        "||theync.com^", "||ogrish.com^", "||efukt.com^",
    ],
    "piracy": [
        "||thepiratebay.org^", "||1337x.to^", "||rarbg.to^", "||nyaa.si^",
        "||kickasstorrents.to^", "||limetorrents.info^", "||torrentgalaxy.to^",
        "||torlock.com^", "||yts.mx^", "||eztv.re^", "||zooqle.com^",
        "||glotorrents.pw^", "||torrent9.ph^", "||torrentz2.eu^",
    ],
    "vpn": [
        "||ultrasurf.us^", "||psiphon.ca^", "||anonymouse.org^",
        "||hidemyass.com^", "||proxify.com^", "||kproxy.com^",
        "||hide.me^", "||proxysite.com^", "||filterbypass.me^",
        "||unblockproject.cyou^", "||croxyproxy.com^",
    ],
}

def _pc_rules_for_category(category):
    return PARENTAL_RULES.get(category, [])

def _pc_tagged_rules(category):
    tag = _pc_tag(category)
    rules = _pc_rules_for_category(category)
    if not rules:
        return []
    return [tag] + rules

def _pc_remove_category_rules(cfg, category):
    tag = _pc_tag(category)
    existing = _get_adguard_user_rules(cfg)
    kept = []
    skip = False
    for rule in existing:
        if rule.strip() == tag:
            skip = True
            continue
        if skip and rule.strip().startswith("# honeytrapai-parental-"):
            skip = False
        if not skip:
            kept.append(rule)
    if len(kept) != len(existing):
        _set_adguard_user_rules(cfg, kept)

def _pc_add_category_rules(cfg, category):
    tag = _pc_tag(category)
    existing = _get_adguard_user_rules(cfg)
    if tag in existing:
        return
    new_rules = _pc_tagged_rules(category)
    if new_rules:
        _set_adguard_user_rules(cfg, existing + new_rules)

def _pc_apply_all(cfg, pc_cfg):
    if not pc_cfg.get("enabled"):
        for cat in PARENTAL_CATEGORIES:
            _pc_remove_category_rules(cfg, cat)
        return
    cats_on = pc_cfg.get("categories", {})
    for cat in PARENTAL_CATEGORIES:
        if cats_on.get(cat, True):
            _pc_add_category_rules(cfg, cat)
        else:
            _pc_remove_category_rules(cfg, cat)

def _pc_apply_to_clients(cfg, pc_cfg):
    # Stub for future per-device implementation
    pass

@app.route('/api/parental-controls', methods=['GET', 'POST'])
@login_required
def api_parental_controls():
    cfg = load_config()

    if request.method == 'GET':
        pc = cfg.get("parental_controls", {
            "enabled": False,
            "categories": {cat: True for cat in PARENTAL_CATEGORIES},
            "devices": [],
            "custom_domains": [],
        })
        pc.setdefault("categories", {cat: True for cat in PARENTAL_CATEGORIES})
        pc.setdefault("devices", [])
        pc.setdefault("custom_domains", [])
        return jsonify({"parental_controls": pc, "category_labels": PARENTAL_CATEGORIES})

    data = request.get_json() or {}
    pc = data.get("parental_controls", {})

    if not isinstance(pc, dict):
        return jsonify({"error": "Invalid payload."}), 400
    pc.setdefault("enabled", False)
    pc.setdefault("categories", {cat: True for cat in PARENTAL_CATEGORIES})
    pc.setdefault("devices", [])
    pc.setdefault("custom_domains", [])

    clean_domains = []
    for d in pc.get("custom_domains", []):
        d = d.strip().lower()
        if d and is_safe_host(d):
            clean_domains.append(d)
    pc["custom_domains"] = clean_domains

    cfg["parental_controls"] = pc
    save_config(cfg)

    try:
        _pc_apply_all(cfg, pc)
    except Exception as e:
        return jsonify({"error": f"Settings saved but AdGuard sync failed: {e}"}), 500

    try:
        custom_tag = "# honeytrapai-parental-custom"
        existing = _get_adguard_user_rules(cfg)
        kept = []
        skip = False
        for rule in existing:
            if rule.strip() == custom_tag:
                skip = True
                continue
            if skip and rule.strip().startswith("# honeytrapai-"):
                skip = False
            if not skip:
                kept.append(rule)
        if pc["enabled"] and clean_domains:
            custom_rules = [custom_tag] + [f"||{d}^" for d in clean_domains]
            kept = kept + custom_rules
        _set_adguard_user_rules(cfg, kept)
    except Exception as e:
        return jsonify({"error": f"Settings saved but custom domain sync failed: {e}"}), 500

    return jsonify({"status": "ok"})


# --- Start Auto OTA scheduler thread — ISSUE-46 ---
def _start_auto_ota_thread():
    global _auto_ota_thread_started
    if not _auto_ota_thread_started:
        _auto_ota_thread_started = True
        t = threading.Thread(target=_auto_ota_scheduler, daemon=True, name="auto-ota")
        t.start()
        app.logger.info("Auto OTA scheduler thread started.")

_start_auto_ota_thread()


if __name__ == "__main__":
    port  = int(os.environ.get("PORT", 5000))
    debug = DEV_MODE
    app.run(host="0.0.0.0", port=port, debug=debug)
