# HoneytrapAI — app.py
# Version: v0.3.18
# Revised: 2026-03-09
# Rev: 6
#!/usr/bin/env python3
"""
HoneytrapAI — Flask web dashboard core
No cloud. No subscription. No monthly fees. Ever.
"""

import os
import re
import json
import hashlib
import secrets
import subprocess
import ipaddress
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session, jsonify, make_response

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))

# --- Paths ---
BASE_DIR    = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.join(BASE_DIR, "config", "config.json")
SMTP_PATH   = os.path.join(BASE_DIR, "config", "smtp.json")
VERSION_PATH= os.path.join(BASE_DIR, "VERSION")
LOG_PATH    = os.environ.get("MALTRAIL_LOG", "/var/log/maltrail/maltrail.log")
DEV_MODE    = os.environ.get("HONEYTRAPAI_DEV", "0") == "1"

# --- Config helpers ---
def load_config():
    if os.path.exists(CONFIG_PATH):
        with open(CONFIG_PATH) as f:
            return json.load(f)
    return {}

def save_config(data):
    os.makedirs(os.path.dirname(CONFIG_PATH), exist_ok=True)
    with open(CONFIG_PATH, "w") as f:
        json.dump(data, f, indent=2)

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
    """
    Lightweight markdown-to-HTML renderer for TERMS.md.
    Handles: h1/h2/h3, bold, italic, inline code, bullet lists, hr, paragraphs.
    No external dependencies.
    """
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
    """Accept hostnames and IPv4 addresses. Reject empty, shell metacharacters."""
    if not host or len(host) > 253:
        return False
    if re.search(r'[;|&$`\'"\\\n\r]', host):
        return False
    return True

def is_safe_port(port):
    """Accept integers 1–65535."""
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
    from log_parser import parse_logs, get_summary
    cfg     = load_config()
    events  = parse_logs(LOG_PATH, dev_mode=DEV_MODE)
    summary = get_summary(events)
    return jsonify({
        "events":    events[:100],
        "summary":   summary,
        "interface": cfg.get("interface", "eth0"),
        "version":   get_version()
    })

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
            return jsonify(json.loads(r.read()))
    except Exception as e:
        return jsonify({"error": str(e)}), 503

@app.route("/api/adguard/history")
@login_required
def api_adguard_history():
    """
    Return 24-hour DNS query history as hourly buckets.
    AdGuard /control/stats returns dns_queries[] and blocked_filtering[]
    as 24-element arrays (oldest → newest, one entry per hour).
    We derive hour labels from the current local time going back 23 hours.
    """
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

        queries = data.get("dns_queries",       [0] * 24)
        blocked = data.get("blocked_filtering", [0] * 24)

        # Pad or trim to exactly 24 elements
        queries = (queries + [0] * 24)[:24]
        blocked = (blocked + [0] * 24)[:24]

        # Build hour labels: current hour is the last bucket
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
    # Preserve AdGuard credentials — they survive the reset because
    # AdGuard itself is not reinstalled; without them the DNS stats
    # panel goes dark after every factory reset.
    existing = {}
    if os.path.exists(CONFIG_PATH):
        try:
            with open(CONFIG_PATH) as f:
                existing = json.load(f)
        except Exception:
            pass
    ag_user = existing.get("adguard_user", "admin")
    ag_pass = existing.get("adguard_password", "")

    # Wipe config and SMTP
    for path in [CONFIG_PATH, SMTP_PATH]:
        if os.path.exists(path):
            os.remove(path)

    # Remove static IP from dhcpcd.conf
    helper = os.path.join(BASE_DIR, "set_static_ip_helper.py")
    subprocess.run(["sudo", "python3", helper, "--remove"], capture_output=True)

    # Re-write AdGuard credentials so the stats API works after setup completes
    if ag_pass:
        os.makedirs(os.path.dirname(CONFIG_PATH), exist_ok=True)
        with open(CONFIG_PATH, "w") as f:
            json.dump({"adguard_user": ag_user, "adguard_password": ag_pass}, f, indent=2)

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
    """Send a test email to verify SMTP configuration."""
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
        msg["Subject"] = "🐝 HoneytrapAI — Test Email"
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
          <div style="font-size:2rem;margin-bottom:.5rem">🐝</div>
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
    """Inject a synthetic Maltrail-format entry into the threat log for testing."""
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
    """Export the Maltrail threat log as a CSV download."""
    import csv, io
    from log_parser import parse_logs
    events   = parse_logs(LOG_PATH, dev_mode=DEV_MODE)
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
    """Truncate the Maltrail log file."""
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
    """Ping a host — 4 packets, 5s timeout per packet."""
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
    """DNS lookup using Python socket — no external tools required."""
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
    """Traceroute to a host — max 20 hops."""
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
    """Port scan using Python socket — no nmap required.
    Scans a comma-separated list of ports or a range (e.g. 80,443 or 20-25).
    Max 50 ports per request.
    """
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

    lines = [f"Port scan: {host}", f"Scanning {len(ports)} port(s)…", ""]
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