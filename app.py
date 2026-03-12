# =============================================================================
# HoneytrapAI — app.py
# Copyright (c) 2026 HoneytrapAI / Anthony Watts
# License: MIT
# Rev 19 — Country blocking: /api/country/block, /api/country/unblock,
#           /api/country/blocked endpoints; CIDR fetch with fallback;
#           AdGuard rule push/remove; config persistence
# =============================================================================

import os, json, re, subprocess, ipaddress, logging, threading, time, requests
from datetime import datetime, timezone
from flask import Flask, jsonify, request, render_template, redirect, url_for, session
from log_parser import parse_logs

app = Flask(__name__)
app.secret_key = os.urandom(24)

CONFIG_PATH   = "/opt/honeytrapai/config/config.json"
VERSION_PATH  = "/opt/honeytrapai/VERSION"
ADGUARD_URL   = "http://127.0.0.1:3000"
ADGUARD_AUTH  = ("admin", "honeytrapai")

logging.basicConfig(level=logging.INFO)
log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def load_config():
    try:
        with open(CONFIG_PATH) as f:
            return json.load(f)
    except Exception:
        return {}

def save_config(cfg):
    with open(CONFIG_PATH, "w") as f:
        json.dump(cfg, f, indent=2)

def get_version():
    try:
        return open(VERSION_PATH).read().strip()
    except Exception:
        return "unknown"

def is_private_ip(ip):
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False

# ---------------------------------------------------------------------------
# COUNTRY_CENTROIDS (ISO 3166-1 alpha-2 → [lat, lon])
# ---------------------------------------------------------------------------
COUNTRY_CENTROIDS = {
    "AF":[33.9,67.7],"AL":[41.2,20.2],"DZ":[28.0,1.7],"AO":[-11.2,17.9],
    "AR":[-38.4,-63.6],"AM":[40.1,45.0],"AU":[-25.3,133.8],"AT":[47.5,14.6],
    "AZ":[40.1,47.6],"BD":[23.7,90.4],"BE":[50.5,4.5],"BJ":[9.3,2.3],
    "BO":[-16.3,-63.6],"BA":[43.9,17.7],"BW":[-22.3,24.7],"BR":[-14.2,-51.9],
    "BG":[42.7,25.5],"KH":[12.6,104.9],"CM":[3.9,11.5],"CA":[56.1,-106.3],
    "CF":[6.6,20.9],"TD":[15.5,18.7],"CL":[-35.7,-71.5],"CN":[35.9,104.2],
    "CO":[4.6,-74.3],"CG":[-0.2,15.8],"CR":[9.7,-83.8],"HR":[45.1,15.2],
    "CU":[21.5,-77.8],"CZ":[49.8,15.5],"CD":[-2.9,23.7],"DK":[56.3,9.5],
    "DO":[18.7,-70.2],"EC":[-1.8,-78.2],"EG":[26.8,30.8],"SV":[13.8,-88.9],
    "ET":[9.1,40.5],"FI":[61.9,25.7],"FR":[46.2,2.2],"GA":[-0.8,11.6],
    "DE":[51.2,10.5],"GH":[7.9,-1.0],"GR":[39.1,21.8],"GT":[15.8,-90.2],
    "GN":[11.0,-10.9],"HT":[18.9,-72.7],"HN":[15.2,-86.2],"HU":[47.2,19.5],
    "IN":[20.6,78.9],"ID":[-0.8,113.9],"IR":[32.4,53.7],"IQ":[33.2,43.7],
    "IE":[53.4,-8.2],"IL":[31.0,34.9],"IT":[41.9,12.6],"JM":[18.1,-77.3],
    "JP":[36.2,138.3],"JO":[30.6,36.2],"KZ":[48.0,66.9],"KE":[-0.0,37.9],
    "KP":[40.3,127.5],"KR":[35.9,127.8],"KW":[29.3,47.5],"LA":[19.9,102.5],
    "LB":[33.9,35.9],"LY":[26.3,17.2],"LT":[55.2,23.9],"MG":[-18.8,46.9],
    "MW":[-13.3,34.3],"MY":[4.2,108.0],"ML":[17.6,-2.0],"MR":[21.0,-10.9],
    "MX":[23.6,-102.6],"MD":[47.4,28.4],"MN":[46.9,103.8],"MA":[31.8,-7.1],
    "MZ":[-18.7,35.5],"NA":[-22.9,18.5],"NP":[28.4,84.1],"NL":[52.1,5.3],
    "NZ":[-40.9,174.9],"NI":[12.9,-85.2],"NE":[17.6,8.1],"NG":[9.1,8.7],
    "MK":[41.6,21.7],"NO":[60.5,8.5],"OM":[21.5,55.9],"PK":[30.4,69.3],
    "PA":[8.5,-80.8],"PG":[-6.3,143.9],"PY":[-23.4,-58.4],"PE":[-9.2,-75.0],
    "PH":[12.9,121.8],"PL":[51.9,19.1],"PT":[39.4,-8.2],"PR":[18.2,-66.6],
    "RO":[45.9,24.9],"RU":[61.5,105.3],"RW":[-1.9,29.9],"SA":[23.9,45.1],
    "SN":[14.5,-14.5],"SL":[8.5,-11.8],"SO":[5.2,46.2],"ZA":[-29.0,25.1],
    "SS":[7.9,29.7],"ES":[40.5,-3.7],"LK":[7.9,80.7],"SD":[15.6,32.5],
    "SE":[60.1,18.6],"CH":[46.8,8.2],"SY":[35.0,38.0],"TW":[23.7,121.0],
    "TZ":[-6.4,34.9],"TH":[15.9,100.9],"TG":[8.6,0.8],"TN":[33.9,9.5],
    "TR":[38.9,35.2],"TM":[38.9,59.6],"UG":[1.4,32.3],"UA":[48.4,31.2],
    "AE":[24.0,54.0],"GB":[55.4,-3.4],"US":[37.1,-95.7],"UY":[-32.5,-55.8],
    "UZ":[41.4,64.6],"VE":[6.4,-66.6],"VN":[14.1,108.3],"YE":[15.6,48.5],
    "ZM":[-13.1,27.9],"ZW":[-19.0,29.2]
}

# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------

def is_setup_complete():
    cfg = load_config()
    return cfg.get("setup_complete", False)

def login_required(f):
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("logged_in"):
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated

# ---------------------------------------------------------------------------
# Routes — pages
# ---------------------------------------------------------------------------

@app.route("/")
@login_required
def index():
    if not is_setup_complete():
        return redirect(url_for("setup"))
    return render_template("dashboard.html", version=get_version())

@app.route("/login", methods=["GET", "POST"])
def login():
    cfg = load_config()
    if request.method == "POST":
        if request.form.get("password") == cfg.get("dashboard_password", "honeytrapai"):
            session["logged_in"] = True
            return redirect(url_for("index"))
        return render_template("login.html", error="Invalid password")
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

@app.route("/setup", methods=["GET", "POST"])
def setup():
    return render_template("setup.html")

# ---------------------------------------------------------------------------
# API — stats
# ---------------------------------------------------------------------------

@app.route("/api/stats")
@login_required
def api_stats():
    cfg = load_config()
    events = [e for e in parse_logs() if not is_private_ip(e.get("src_ip", ""))]
    high   = sum(1 for e in events if e.get("severity") == "high")
    medium = sum(1 for e in events if e.get("severity") == "medium")
    low    = sum(1 for e in events if e.get("severity") == "low")

    # AdGuard stats
    ag_stats = {}
    try:
        r = requests.get(f"{ADGUARD_URL}/control/stats", auth=ADGUARD_AUTH, timeout=3)
        ag_stats = r.json()
    except Exception:
        pass

    return jsonify({
        "threats_today": len(events),
        "high": high, "medium": medium, "low": low,
        "recent_alerts": events[-20:][::-1],
        "lifetime_blocked": cfg.get("lifetime_blocked", 0),
        "adguard": {
            "dns_queries": ag_stats.get("num_dns_queries", 0),
            "blocked": ag_stats.get("num_blocked_filtering", 0),
        }
    })

@app.route("/api/threats/export")
@login_required
def api_threats_export():
    import csv, io
    events = [e for e in parse_logs() if not is_private_ip(e.get("src_ip", ""))]
    out = io.StringIO()
    w = csv.DictWriter(out, fieldnames=["timestamp","src_ip","trail","info","severity"])
    w.writeheader()
    w.writerows(events)
    from flask import Response
    return Response(out.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition": "attachment; filename=threats.csv"})

@app.route("/api/threat_map")
@login_required
def api_threat_map():
    # Rev 4 — unified: uses parse_logs() so severity and 24h cutoff
    # always match api_stats(). Eliminates duplicate inline parser.
    import geoip2.database
    DB_PATH = "/opt/honeytrapai/data/GeoLite2-Country.mmdb"
    events = parse_logs(LOG_PATH, dev_mode=DEV_MODE)
    dots = []
    try:
        with geoip2.database.Reader(DB_PATH) as reader:
            for e in events:
                ip = e.get("src_ip", "")
                if is_private_ip(ip):
                    continue
                try:
                    geo = reader.country(ip)
                    cc  = geo.country.iso_code
                    if not cc or cc not in COUNTRY_CENTROIDS:
                        continue
                    lat, lon = COUNTRY_CENTROIDS[cc]
                    dots.append({
                        "ip":           ip,
                        "lat":          lat,
                        "lon":          lon,
                        "trail":        e.get("trail", ""),
                        "info":         e.get("info", ""),
                        "severity":     e.get("severity", "low"),
                        "country":      cc,
                        "country_name": geo.country.name or "Unknown",
                        "timestamp":    e.get("timestamp", ""),
                    })
                except Exception:
                    continue
    except Exception as ex:
        log.warning(f"GeoIP error: {ex}")
        return jsonify({"error": str(ex), "dots": []})
    return jsonify({"events": dots})

# ---------------------------------------------------------------------------
# API — config
# ---------------------------------------------------------------------------

@app.route("/api/config", methods=["GET"])
@login_required
def api_config_get():
    cfg = load_config()
    safe = {k: v for k, v in cfg.items() if k != "dashboard_password"}
    return jsonify(safe)

@app.route("/api/config", methods=["POST"])
@login_required
def api_config_post():
    cfg = load_config()
    data = request.get_json(force=True)
    cfg.update(data)
    save_config(cfg)
    return jsonify({"ok": True})

# ---------------------------------------------------------------------------
# API — updates
# ---------------------------------------------------------------------------

@app.route("/api/version")
def api_version():
    return jsonify({"version": get_version()})

@app.route("/api/update/check")
@login_required
def api_update_check():
    try:
        r = requests.get(
            "https://api.github.com/repos/honeytrap-ai/honeytrapai/releases/latest",
            timeout=5)
        data = r.json()
        latest = data.get("tag_name","").lstrip("v")
        current = get_version()
        return jsonify({"current": current, "latest": latest,
                        "update_available": latest != current,
                        "url": data.get("tarball_url","")})
    except Exception as ex:
        return jsonify({"error": str(ex)}), 500

@app.route("/api/update/install", methods=["POST"])
@login_required
def api_update_install():
    from updater import perform_update
    threading.Thread(target=perform_update, daemon=True).start()
    return jsonify({"ok": True})

@app.route("/api/update/status")
@login_required
def api_update_status():
    from updater import get_status
    return jsonify(get_status())

# ---------------------------------------------------------------------------
# API — email / alert settings
# ---------------------------------------------------------------------------

@app.route("/api/alert_email", methods=["POST"])
@login_required
def api_alert_email():
    cfg = load_config()
    data = request.get_json(force=True)
    for k in ["smtp_host","smtp_port","smtp_user","smtp_pass","smtp_encryption",
              "alert_email_to","alert_email_enabled"]:
        if k in data:
            cfg[k] = data[k]
    save_config(cfg)
    subprocess.run(["sudo","systemctl","restart","honeytrapai-notifier"], check=False)
    return jsonify({"ok": True})

# ---------------------------------------------------------------------------
# API — simulate threat
# ---------------------------------------------------------------------------

@app.route("/api/simulate", methods=["POST"])
@login_required
def api_simulate():
    import random
    profiles = [
        ("Port Scan","port_scan","high"),
        ("C2 Beacon","c2_beacon","high"),
        ("DNS Exfil","dns_exfiltration","medium"),
        ("Brute Force","brute_force","high"),
        ("Tor Exit","tor_exit","medium"),
        ("Crypto Miner","crypto_miner","low"),
        ("Ad Tracker","ad_tracker","low"),
    ]
    name, trail, severity = random.choice(profiles)
    ip = f"{random.randint(1,254)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    line = f"{ts} {ip} {trail} Simulated {name}\n"
    LOG_PATH = "/var/log/maltrail/maltrail.log"
    try:
        with open(LOG_PATH, "a") as f:
            f.write(line)
    except PermissionError:
        tmp = f"/tmp/sim_{int(time.time())}.log"
        with open(tmp, "w") as f:
            f.write(line)
        subprocess.run(["sudo","tee","-a",LOG_PATH], input=line.encode(), check=False)
    return jsonify({"ok": True, "event": {"ip": ip, "trail": trail, "severity": severity}})

# ---------------------------------------------------------------------------
# API — factory reset
# ---------------------------------------------------------------------------

@app.route("/api/factory_reset", methods=["POST"])
@login_required
def api_factory_reset():
    default = {"setup_complete": False, "lifetime_blocked": 0, "blocked_countries": []}
    save_config(default)
    session.clear()
    subprocess.run(["sudo","systemctl","restart","honeytrapai"], check=False)
    return jsonify({"ok": True})

# ---------------------------------------------------------------------------
# API — log purge
# ---------------------------------------------------------------------------

@app.route("/api/logs/purge", methods=["POST"])
@login_required
def api_logs_purge():
    LOG_PATH = "/var/log/maltrail/maltrail.log"
    try:
        open(LOG_PATH, "w").close()
    except Exception:
        subprocess.run(["sudo","truncate","-s","0",LOG_PATH], check=False)
    return jsonify({"ok": True})

# ---------------------------------------------------------------------------
# API — country blocking  (ISSUE-09 Part 2)
# ---------------------------------------------------------------------------

IPDENY_URL  = "https://www.ipdeny.com/ipblocks/data/countries/{cc}.zone"
HERRBISCHOFF_URL = "https://raw.githubusercontent.com/herrbischoff/country-ip-blocks/master/ipv4/{cc}.cidr"

def _fetch_cidrs(cc):
    """Fetch CIDR list for country code. Returns list of strings or raises."""
    cc_lower = cc.lower()
    for url_tpl in [IPDENY_URL, HERRBISCHOFF_URL]:
        url = url_tpl.format(cc=cc_lower)
        try:
            r = requests.get(url, timeout=10)
            if r.status_code == 200 and r.text.strip():
                cidrs = [ln.strip() for ln in r.text.strip().splitlines()
                         if ln.strip() and not ln.startswith("#")]
                if cidrs:
                    log.info(f"[country_block] Got {len(cidrs)} CIDRs for {cc} from {url}")
                    return cidrs
        except Exception as ex:
            log.warning(f"[country_block] CIDR fetch failed ({url}): {ex}")
    raise RuntimeError(f"Could not fetch CIDRs for {cc} from any source")

def _adguard_rule(cidr):
    """Convert a CIDR to AdGuard Home network blocking rule."""
    return f"||{cidr}^$network"

def _add_adguard_rules(rules):
    """Push a list of rule strings to AdGuard custom filtering."""
    # AdGuard accepts rules one at a time via /control/filtering/rules/add
    failed = 0
    for rule in rules:
        try:
            r = requests.post(
                f"{ADGUARD_URL}/control/filtering/rules/add",
                json={"rule": rule},
                auth=ADGUARD_AUTH,
                timeout=5)
            if r.status_code not in (200, 204):
                failed += 1
        except Exception as ex:
            log.warning(f"[country_block] AdGuard add rule failed: {ex}")
            failed += 1
    return failed

def _remove_adguard_rules(rules):
    """Remove a list of rule strings from AdGuard custom filtering."""
    failed = 0
    for rule in rules:
        try:
            r = requests.post(
                f"{ADGUARD_URL}/control/filtering/rules/remove",
                json={"rule": rule},
                auth=ADGUARD_AUTH,
                timeout=5)
            if r.status_code not in (200, 204):
                failed += 1
        except Exception as ex:
            log.warning(f"[country_block] AdGuard remove rule failed: {ex}")
            failed += 1
    return failed

def _country_rule_prefix(cc):
    """Marker comment prefix stored alongside rules so we can identify them."""
    # We store rules in config keyed by cc; no inline comment needed in AdGuard.
    # This helper is reserved for future tagged rule format if needed.
    return f"# honeytrapai-country-{cc.upper()}"

@app.route("/api/country/block", methods=["POST"])
@login_required
def api_country_block():
    data = request.get_json(force=True)
    cc = (data.get("cc") or "").upper().strip()
    if not re.match(r"^[A-Z]{2}$", cc):
        return jsonify({"ok": False, "error": "Invalid country code"}), 400

    cfg = load_config()
    blocked = cfg.get("blocked_countries", {})
    if not isinstance(blocked, dict):
        blocked = {}  # migrate old list format

    if cc in blocked:
        return jsonify({"ok": True, "already_blocked": True, "count": len(blocked[cc])})

    try:
        cidrs = _fetch_cidrs(cc)
    except RuntimeError as ex:
        return jsonify({"ok": False, "error": str(ex)}), 502

    rules = [_adguard_rule(c) for c in cidrs]
    failed = _add_adguard_rules(rules)

    # Persist rules so we can remove them later
    blocked[cc] = rules
    cfg["blocked_countries"] = blocked
    save_config(cfg)

    return jsonify({
        "ok": True,
        "cc": cc,
        "cidr_count": len(cidrs),
        "rules_added": len(rules) - failed,
        "rules_failed": failed
    })

@app.route("/api/country/unblock", methods=["POST"])
@login_required
def api_country_unblock():
    data = request.get_json(force=True)
    cc = (data.get("cc") or "").upper().strip()
    if not re.match(r"^[A-Z]{2}$", cc):
        return jsonify({"ok": False, "error": "Invalid country code"}), 400

    cfg = load_config()
    blocked = cfg.get("blocked_countries", {})
    if not isinstance(blocked, dict):
        blocked = {}

    if cc not in blocked:
        return jsonify({"ok": True, "was_not_blocked": True})

    rules = blocked[cc]
    failed = _remove_adguard_rules(rules)

    del blocked[cc]
    cfg["blocked_countries"] = blocked
    save_config(cfg)

    return jsonify({
        "ok": True,
        "cc": cc,
        "rules_removed": len(rules) - failed,
        "rules_failed": failed
    })

@app.route("/api/country/blocked")
@login_required
def api_country_blocked():
    cfg = load_config()
    blocked = cfg.get("blocked_countries", {})
    if not isinstance(blocked, dict):
        blocked = {}
    # Return just the list of blocked country codes
    return jsonify({"blocked": list(blocked.keys())})

# ---------------------------------------------------------------------------
# Setup API endpoints
# ---------------------------------------------------------------------------

@app.route("/api/setup/complete", methods=["POST"])
def api_setup_complete():
    data = request.get_json(force=True)
    cfg = load_config()
    cfg["setup_complete"] = True
    if "password" in data:
        cfg["dashboard_password"] = data["password"]
    if "static_ip" in data:
        cfg["static_ip"] = data["static_ip"]
    cfg.setdefault("blocked_countries", {})
    save_config(cfg)
    session["logged_in"] = True
    return jsonify({"ok": True})

# ---------------------------------------------------------------------------

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)