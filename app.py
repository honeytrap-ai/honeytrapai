# HoneytrapAI — app.py
# Version: v0.3.34
# Revised: 2026-03-12
# Rev: 24
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
# Stores (result_dict, timestamp_float) tuple; None until first call
_net_visibility_cache = None
_NET_VIS_TTL = 300  # 5-minute cache — avoids hammering AdGuard on every page load

# Cache for ip-api.com geo lookups — ISSUE-39
# Key: IP string → {"lat": float, "lon": float, "city": str}
_geo_cache = {}

# Rate limit tracker for ip-api.com — ISSUE-39
# Free tier: 45 req/min. Reset every 60s.
_geo_rate_lock = threading.Lock()
_geo_rate = {"count": 0, "window_start": None}
_GEO_RATE_LIMIT = 40  # stay safely under the 45/min hard limit

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

# --- Lifetime blocked counter state ---
_last_num_blocked      = None
_lifetime_blocked_lock = threading.Lock()

# --- Country centroid lookup — ISO 3166-1 alpha-2 → (lat, lon) ---
# Used as fallback when ip-api.com is unavailable or rate-limited (ISSUE-39)
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
    """Return (lat, lon, city) for a threat IP.

    Priority:
      1. Process-lifetime _geo_cache hit → free, instant
      2. ip-api.com live lookup → city-level precision
         (skipped if rate limit reached this window)
      3. COUNTRY_CENTROIDS fallback → country-center dot (same as pre-ISSUE-39)

    Rate limit: ip-api.com free tier = 45 req/min.
    We cap at _GEO_RATE_LIMIT (40) per 60s window to stay safely under.
    """
    global _geo_cache, _geo_rate

    # 1. Cache hit
    if ip in _geo_cache:
        c = _geo_cache[ip]
        return c["lat"], c["lon"], c.get("city", "")

    # 2. Rate limit check
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
            pass  # fall through to centroid

    # 3. COUNTRY_CENTROIDS fallback
    if country_code in COUNTRY_CENTROIDS:
        lat, lon = COUNTRY_CENTROIDS[country_code]
        # Cache centroid result too so we don't keep hitting the rate check
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
    """Return True if ip_str is RFC1918, loopback, link-local, or otherwise non-routable."""
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
                save_config(cfg); step = 2

        elif step == 2:
            action = request.form.get("action", "save")
            if action == "skip":
                cfg["static_ip_skipped"] = True
                cfg["interface"] = "eth0"
                save_config(cfg); step = 3
            else:
                entered_ip = request.form.get("static_ip", "").strip()
                if not entered_ip:
                    error = "Please enter an IP address, or choose Skip."; step = 2
                elif not validate_same_subnet(entered_ip, net["network"]):
                    error = (
                        f"'{entered_ip}' is not a valid address within your subnet "
                        f"({net['network']}). Please enter an IP in that range."
                    ); step = 2
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
                        save_config(cfg); step = 3
                    except Exception as e:
                        error = f"Could not write static IP configuration: {e}"; step = 2

        elif step == 3:
            alert_email = request.form.get("alert_email", "").strip()
            cfg["alert_email"]   = alert_email
            cfg["setup_complete"]= True
            cfg["setup_date"]    = datetime.utcnow().isoformat()
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
    # Rev 4 — ISSUE-39: city-level dots via ip-api.com; COUNTRY_CENTROIDS as fallback
    try:
        db_path  = "/opt/honeytrapai/data/GeoLite2-Country.mmdb"
        log_dir  = "/var/log/maltrail/"
        cutoff   = datetime.utcnow() - timedelta(hours=24)
        events   = []

        # Dated sensor logs (today + yesterday) + rolling maltrail.log (simulated threats)
        log_files = []
        for delta in (0, 1):
            d = datetime.utcnow() - timedelta(days=delta)
            p = os.path.join(log_dir, d.strftime("%Y-%m-%d") + ".log")
            log_files.extend(glob.glob(p))
        maltrail_log = os.path.join(log_dir, "maltrail.log")
        if os.path.exists(maltrail_log):
            log_files.append(maltrail_log)

        def parse_line(line):
            """Parse both log formats. Returns (ts, src_ip, trail, info) or None."""
            line = line.strip()
            if not line:
                return None
            if line.startswith('"'):
                # Sensor format:
                # "2026-03-10 21:11:32.588435" host src_ip src_port dst_ip dst_port proto trail info...
                try:
                    ts_str, rest = line[1:].split('"', 1)
                    ts    = datetime.strptime(ts_str[:19], "%Y-%m-%d %H:%M:%S")
                    parts = rest.strip().split(" ")
                    if len(parts) < 7:
                        return None
                    src_ip = parts[1]   # 0=host, 1=src_ip
                    trail  = parts[6]
                    info   = " ".join(parts[7:]) if len(parts) > 7 else ""
                    return ts, src_ip, trail, info
                except Exception:
                    return None
            else:
                # Simulated format:
                # 2026-03-11 03:06:11 honeytrap src_ip src_port dst_ip dst_port proto trail info...
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

                            # Skip private/loopback
                            if is_private_ip(src_ip):
                                continue

                            # GeoIP lookup — still needed for country_code (country blocking)
                            try:
                                geo          = reader.country(src_ip)
                                country_code = geo.country.iso_code or ""
                                country_name = geo.country.name or "Unknown"
                            except Exception:
                                continue

                            # City-level geo — ISSUE-39
                            # _resolve_geo tries ip-api.com first, falls back to COUNTRY_CENTROIDS
                            lat, lon, city = _resolve_geo(src_ip, country_code)
                            if lat is None or lon is None:
                                continue

                            # Severity classification
                            il = info.lower()
                            if any(x in il for x in ["malware","c2","botnet","ransomware","rat","backdoor","trojan","exploit"]):
                                severity = "high"
                            elif any(x in il for x in ["scanner","suspicious","threat","attack","probe","brute"]):
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

    cfg["password_hash"] = hash_password(new_pw)
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

    for path in [CONFIG_PATH, SMTP_PATH]:
        if os.path.exists(path):
            os.remove(path)

    helper = os.path.join(BASE_DIR, "set_static_ip_helper.py")
    subprocess.run(["sudo", "python3", helper, "--remove"], capture_output=True)

    preserved = {"lifetime_blocked": lifetime_blocked}
    if ag_pass:
        preserved["adguard_user"]     = ag_user
        preserved["adguard_password"] = ag_pass
    os.makedirs(os.path.dirname(CONFIG_PATH), exist_ok=True)
    with open(CONFIG_PATH, "w") as f:
        json.dump(preserved, f, indent=2)

# --- Country blocking helpers ---

def _fetch_cidrs(cc):
    """Fetch CIDR list for country code cc. Primary: ipdeny, fallback: herrbischoff.
    Returns list of CIDR strings, or raises Exception on total failure."""
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
    """Make an authenticated request to the local AdGuard API."""
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
    """Fetch current user rules list from AdGuard. Returns list of rule strings."""
    try:
        status, body = _ag_request(cfg, "GET", "/control/filtering/status")
        data = json.loads(body)
        return data.get("user_rules") or []
    except Exception:
        return []

def _set_adguard_user_rules(cfg, rules):
    """Replace AdGuard user rules with the given list. Returns True on success."""
    try:
        status, _ = _ag_request(cfg, "POST", "/control/filtering/set_rules",
                                 {"rules": rules})
        return status in (200, 204)
    except Exception:
        return False

def _add_adguard_rules(cfg, rules):
    """Add rules to AdGuard by merging with existing user rules.
    Returns (added_count, error_or_None)."""
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
    """Remove rules from AdGuard user rules list.
    Returns count of rules removed."""
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

if __name__ == "__main__":
    port  = int(os.environ.get("PORT", 5000))
    debug = DEV_MODE
    app.run(host="0.0.0.0", port=port, debug=debug)

@app.route('/api/my-location')
@login_required
def api_my_location():
    # Rev 1 - ISSUE-35 You Are Here marker
    global _my_location_cache
    if _my_location_cache is not None:
        return jsonify(_my_location_cache)
    try:
        import urllib.request, json as _json
        with urllib.request.urlopen('http://ip-api.com/json/?fields=status,lat,lon,city,isp', timeout=5) as resp:
            data = _json.loads(resp.read().decode())
        if data.get('status') == 'success':
            _my_location_cache = {
                'lat': data['lat'],
                'lon': data['lon'],
                'city': data.get('city', ''),
                'isp': data.get('isp', '')
            }
            return jsonify(_my_location_cache)
        return jsonify({'error': 'ip-api lookup failed'}), 502
    except Exception as e:
        return jsonify({'error': str(e)}), 502

@app.route('/api/network-visibility')
@login_required
def api_network_visibility():
    # Rev 1 - ISSUE-40 network visibility detection
    # Returns {"visible": true/false} — false means Pi is not seeing external DNS clients,
    # which indicates the router is proxying DNS rather than forwarding to the Pi directly.
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
        # top_clients is a list of single-key dicts: [{"1.2.3.4": 42}, ...]
        clients  = data.get('top_clients', [])
        external = [ip for entry in clients for ip in entry.keys() if ip not in pi_ips]
        if not external:
            result = {'visible': False, 'reason': 'no_clients'}
        elif gateway and all(ip == gateway for ip in external):
            result = {'visible': False, 'reason': 'proxied'}
        else:
            result = {'visible': True}
    except Exception as e:
        # Fail open — don't false-alarm if AdGuard is temporarily unreachable
        result = {'visible': True, 'error': str(e)}
    _net_visibility_cache = (result, now)
    return jsonify(result)