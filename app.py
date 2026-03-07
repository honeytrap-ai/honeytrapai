# HoneytrapAI — app.py
# Version: v0.2.3
# Revised: 2026-03-07
# Rev: 1
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
from flask import Flask, render_template, request, redirect, url_for, session, jsonify

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))

# --- Paths ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.join(BASE_DIR, "config", "config.json")
SMTP_PATH = os.path.join(BASE_DIR, "config", "smtp.json")
VERSION_PATH = os.path.join(BASE_DIR, "VERSION")
LOG_PATH = os.environ.get("MALTRAIL_LOG", "/var/log/maltrail/maltrail.log")
DEV_MODE = os.environ.get("HONEYTRAPAI_DEV", "0") == "1"

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
        # Escape HTML first, then apply inline markdown
        s = html_mod.escape(s)
        # Bold+italic ***text***
        s = re.sub(r'\*\*\*(.+?)\*\*\*', r'<strong><em>\1</em></strong>', s)
        # Bold **text**
        s = re.sub(r'\*\*(.+?)\*\*', r'<strong>\1</strong>', s)
        # Italic *text*
        s = re.sub(r'\*(.+?)\*', r'<em>\1</em>', s)
        # Inline code `text`
        s = re.sub(r'`(.+?)`', r'<code>\1</code>', s)
        return s

    for line in lines:
        stripped = line.strip()

        # Blank line — close open blocks
        if not stripped:
            close_list()
            close_para()
            continue

        # HR ---
        if re.match(r'^-{3,}$', stripped):
            close_list()
            close_para()
            out.append("<hr>")
            continue

        # Headings
        m = re.match(r'^(#{1,3})\s+(.*)', stripped)
        if m:
            close_list()
            close_para()
            lvl = len(m.group(1))
            out.append(f"<h{lvl}>{inline(m.group(2))}</h{lvl}>")
            continue

        # Bullet list item
        m = re.match(r'^[-*]\s+(.*)', stripped)
        if m:
            close_para()
            if not in_list:
                out.append("<ul>")
                in_list = True
            out.append(f"<li>{inline(m.group(1))}</li>")
            continue

        # Regular paragraph text
        close_list()
        if not in_para:
            out.append("<p>")
            in_para = True
        else:
            out.append(" ")
        out.append(inline(stripped))

    close_list()
    close_para()
    return "\n".join(out)

# --- Network helpers ---
def get_network_info(iface="eth0"):
    """
    Return dict with keys: ip, prefix_len, gateway, dns, network (as string e.g. '192.168.1.0/24').
    Falls back to empty strings on any failure. In DEV_MODE returns plausible fake values.
    """
    if DEV_MODE:
        return {
            "ip": "192.168.1.199",
            "prefix_len": "24",
            "gateway": "192.168.1.1",
            "dns": "192.168.1.1",
            "network": "192.168.1.0/24",
        }
    info = {"ip": "", "prefix_len": "", "gateway": "", "dns": "", "network": ""}
    try:
        out = subprocess.check_output(
            ["ip", "-4", "addr", "show", iface], text=True, stderr=subprocess.DEVNULL
        )
        for line in out.splitlines():
            line = line.strip()
            if line.startswith("inet "):
                parts = line.split()
                cidr = parts[1]
                iface_obj = ipaddress.IPv4Interface(cidr)
                info["ip"] = str(iface_obj.ip)
                info["prefix_len"] = str(iface_obj.network.prefixlen)
                info["network"] = str(iface_obj.network)
                break
    except Exception:
        pass
    try:
        out = subprocess.check_output(
            ["ip", "route", "show", "default"], text=True, stderr=subprocess.DEVNULL
        )
        for line in out.splitlines():
            parts = line.split()
            if "via" in parts:
                info["gateway"] = parts[parts.index("via") + 1]
                break
    except Exception:
        pass
    try:
        with open("/etc/resolv.conf") as f:
            for line in f:
                line = line.strip()
                if line.startswith("nameserver"):
                    info["dns"] = line.split()[1]
                    break
    except Exception:
        pass
    return info


def validate_same_subnet(ip_str, network_str):
    try:
        ip = ipaddress.IPv4Address(ip_str)
        net = ipaddress.IPv4Network(network_str, strict=False)
        return ip in net and ip != net.network_address and ip != net.broadcast_address
    except Exception:
        return False


def set_static_ip(iface, ip, prefix_len, gateway, dns):
    helper = os.path.join(BASE_DIR, "set_static_ip_helper.py")
    result = subprocess.run(
        ["sudo", "python3", helper, iface, ip, str(prefix_len), gateway, dns],
        capture_output=True, text=True
    )
    if result.returncode != 0:
        raise Exception(result.stderr.strip() or "set_static_ip_helper failed")


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
        stored = cfg.get("password_hash", "")
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
    step = int(request.form.get("step", 1))
    net = get_network_info()

    if request.method == "POST":
        if step == 1:
            password = request.form.get("password", "")
            confirm  = request.form.get("confirm", "")
            if len(password) < 8:
                error = "Password must be at least 8 characters."
                step = 1
            elif password != confirm:
                error = "Passwords do not match."
                step = 1
            else:
                cfg["password_hash"] = hash_password(password)
                save_config(cfg)
                step = 2

        elif step == 2:
            action = request.form.get("action", "save")
            if action == "skip":
                cfg["static_ip_skipped"] = True
                cfg["interface"] = "eth0"
                save_config(cfg)
                step = 3
            else:
                entered_ip = request.form.get("static_ip", "").strip()
                if not entered_ip:
                    error = "Please enter an IP address, or choose Skip."
                    step = 2
                elif not validate_same_subnet(entered_ip, net["network"]):
                    error = (
                        f"'{entered_ip}' is not a valid address within your subnet "
                        f"({net['network']}). Please enter an IP in that range."
                    )
                    step = 2
                else:
                    try:
                        set_static_ip(
                            iface="eth0",
                            ip=entered_ip,
                            prefix_len=net["prefix_len"],
                            gateway=net["gateway"],
                            dns=net["dns"] or net["gateway"],
                        )
                        cfg["static_ip"] = entered_ip
                        cfg["static_ip_skipped"] = False
                        cfg["interface"] = "eth0"
                        save_config(cfg)
                        step = 3
                    except Exception as e:
                        error = f"Could not write static IP configuration: {e}"
                        step = 2

        elif step == 3:
            alert_email = request.form.get("alert_email", "").strip()
            cfg["alert_email"] = alert_email
            cfg["setup_complete"] = True
            cfg["setup_date"] = datetime.utcnow().isoformat()
            save_config(cfg)

            # Save SMTP config if host was provided
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
        "setup.html",
        step=step,
        error=error,
        version=get_version(),
        net=net,
    )

@app.route("/dashboard")
@login_required
@setup_required
@terms_required
def dashboard():
    return render_template("dashboard.html", version=get_version(), dev_mode=DEV_MODE)

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
    return render_template("terms.html", terms_html=terms_html, version=get_version())

@app.route("/api/terms/accept", methods=["POST"])
@login_required
@setup_required
def api_terms_accept():
    cfg = load_config()
    cfg["terms_accepted"] = True
    cfg["terms_accepted_date"] = datetime.utcnow().isoformat()
    save_config(cfg)
    return jsonify({"status": "ok"})

# --- API endpoints ---
@app.route("/api/stats")
@login_required
def api_stats():
    from log_parser import parse_logs, get_summary
    cfg = load_config()
    events = parse_logs(LOG_PATH, dev_mode=DEV_MODE)
    summary = get_summary(events)
    return jsonify({
        "events": events[:100],
        "summary": summary,
        "interface": cfg.get("interface", "eth0"),
        "version": get_version()
    })

@app.route("/api/services/status")
@login_required
def api_services_status():
    import shutil
    statuses = {}

    # Check systemd services
    for svc in ["honeytrapai", "adguardhome", "maltrail-sensor", "nginx"]:
        try:
            r = subprocess.run(
                ["systemctl", "is-active", svc],
                capture_output=True, text=True
            )
            statuses[svc] = r.stdout.strip() == "active"
        except Exception:
            statuses[svc] = False

    # Check DNS port 53 is responding
    try:
        import socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(1)
        # Send a minimal DNS query for "." (root)
        query = b'\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x01'
        sock.sendto(query, ("127.0.0.1", 53))
        sock.recv(512)
        sock.close()
        statuses["dns"] = True
    except Exception:
        statuses["dns"] = False

    # Overall health
    critical = ["adguardhome", "maltrail-sensor", "nginx"]
    all_ok   = all(statuses.get(s) for s in critical) and statuses.get("dns")
    any_down = not all_ok
    critical_down = not all(statuses.get(s) for s in ["adguardhome", "maltrail-sensor"])

    if critical_down:
        overall = "red"
    elif any_down:
        overall = "amber"
    else:
        overall = "green"

    return jsonify({"services": statuses, "overall": overall})

@app.route("/api/adguard/stats")
@login_required
def api_adguard_stats():
    if DEV_MODE:
        return jsonify({
            "num_dns_queries": 14823,
            "num_blocked_filtering": 1247,
            "num_replaced_safebrowsing": 12,
            "num_replaced_parental": 0,
            "avg_processing_time": 2.4,
            "top_queried_domains": [
                {"google.com": 342},
                {"apple.com": 187},
                {"netflix.com": 143}
            ],
            "top_blocked_domains": [
                {"doubleclick.net": 89},
                {"googlesyndication.com": 67},
                {"facebook.com": 45}
            ]
        })
    try:
        import urllib.request, base64
        cfg = load_config()
        ag_user = cfg.get("adguard_user", "admin")
        ag_pass = cfg.get("adguard_password", "")
        token = base64.b64encode(f"{ag_user}:{ag_pass}".encode()).decode()
        req = urllib.request.Request(
            "http://127.0.0.1:3000/control/stats",
            headers={"Authorization": f"Basic {token}"}
        )
        with urllib.request.urlopen(req, timeout=3) as r:
            return jsonify(json.loads(r.read()))
    except Exception as e:
        return jsonify({"error": str(e)}), 503

@app.route("/api/settings", methods=["GET", "POST"])
@login_required
def api_settings():
    cfg = load_config()
    smtp = {}
    if os.path.exists(SMTP_PATH):
        with open(SMTP_PATH) as f:
            smtp = json.load(f)

    if request.method == "POST":
        data = request.get_json()
        if "alert_email" in data:
            cfg["alert_email"] = data["alert_email"]
        if "interface" in data:
            cfg["interface"] = data["interface"]
        if "alert_threshold" in data:
            cfg["alert_threshold"] = data["alert_threshold"]
        save_config(cfg)
        return jsonify({"status": "ok"})

    return jsonify({
        "alert_email": cfg.get("alert_email", ""),
        "interface": cfg.get("interface", "eth0"),
        "alert_threshold": cfg.get("alert_threshold", "medium"),
        "smtp_configured": bool(smtp.get("host")),
        "setup_date": cfg.get("setup_date", "")
    })

@app.route("/api/password", methods=["POST"])
@login_required
def api_change_password():
    cfg = load_config()
    data = request.get_json()
    current = data.get("current", "")
    new_pw  = data.get("new_password", "")
    confirm = data.get("confirm", "")

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
        result = check_for_update(force="force" in request.args)
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/update/install", methods=["POST"])
@login_required
def api_update_install():
    try:
        import threading
        from updater import perform_update
        t = threading.Thread(target=perform_update, daemon=True)
        t.start()
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
    cfg = load_config()
    smtp = {}
    if os.path.exists(SMTP_PATH):
        with open(SMTP_PATH) as f:
            smtp = json.load(f)
    backup = {"config": cfg, "smtp": smtp, "version": get_version(),
              "backup_date": datetime.utcnow().isoformat()}
    data = json.dumps(backup, indent=2).encode()
    return app.response_class(
        response=data,
        status=200,
        mimetype="application/json",
        headers={"Content-Disposition": "attachment; filename=honeytrapai-backup.json"}
    )

@app.route("/api/factory-reset", methods=["POST"])
@login_required
def api_factory_reset():
    cfg = load_config()
    data = request.get_json()
    password = data.get("password", "")

    if not verify_password(password, cfg.get("password_hash", "")):
        return jsonify({"error": "Incorrect password."}), 400

    _perform_factory_reset()

    import threading
    def _reboot():
        import time, subprocess as sp
        time.sleep(2)
        sp.run(["sudo", "reboot"], check=False)
    threading.Thread(target=_reboot, daemon=True).start()

    return jsonify({"status": "ok"})


def _perform_factory_reset():
    for path in [CONFIG_PATH, SMTP_PATH]:
        if os.path.exists(path):
            os.remove(path)
    helper = os.path.join(BASE_DIR, "set_static_ip_helper.py")
    subprocess.run(
        ["sudo", "python3", helper, "--remove"],
        capture_output=True
    )


@app.route("/api/smtp", methods=["GET", "POST"])
@login_required
def api_smtp():
    if request.method == "POST":
        data = request.get_json() or {}
        smtp = {}
        # Load existing so we preserve the password if none was submitted
        if os.path.exists(SMTP_PATH):
            with open(SMTP_PATH) as f:
                smtp = json.load(f)
        smtp["host"]      = data.get("host", smtp.get("host", ""))
        smtp["port"]      = int(data.get("port", smtp.get("port", 587)))
        smtp["username"]  = data.get("username", smtp.get("username", ""))
        smtp["from_addr"] = data.get("from_addr", smtp.get("from_addr", ""))
        smtp["tls"]       = data.get("tls", smtp.get("tls", True))
        smtp["ssl"]       = data.get("ssl", smtp.get("ssl", False))
        if "password" in data and data["password"]:
            smtp["password"] = data["password"]
        os.makedirs(os.path.dirname(SMTP_PATH), exist_ok=True)
        with open(SMTP_PATH, "w") as f:
            json.dump(smtp, f, indent=2)
        return jsonify({"status": "ok"})

    # GET — return config but never expose password
    smtp = {}
    if os.path.exists(SMTP_PATH):
        with open(SMTP_PATH) as f:
            smtp = json.load(f)
    return jsonify({
        "host":      smtp.get("host", ""),
        "port":      smtp.get("port", 587),
        "username":  smtp.get("username", ""),
        "from_addr": smtp.get("from_addr", ""),
        "tls":       smtp.get("tls", True),
        "ssl":       smtp.get("ssl", False),
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

    smtp = {}
    if os.path.exists(SMTP_PATH):
        with open(SMTP_PATH) as f:
            smtp = json.load(f)

    if not smtp.get("host"):
        return jsonify({"error": "SMTP is not configured. Add your SMTP settings first."}), 400

    try:
        import smtplib
        from email.mime.text import MIMEText
        from email.mime.multipart import MIMEMultipart

        msg = MIMEMultipart("alternative")
        msg["Subject"] = "🐝 HoneytrapAI — Test Email"
        msg["From"]    = smtp.get("from_address", smtp.get("username", ""))
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

        use_tls = smtp.get("tls", True)
        use_ssl = smtp.get("ssl", False)

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
    data = request.get_json() or {}
    threat_type = data.get("threat_type", "malware")
    src_ip_in   = data.get("src_ip") or None

    # Threat type → (trail, info, severity)
    THREAT_PROFILES = {
        "malware":     (["evil-payload.ru", "malware-drop.cn", "bad-actor.xyz"],    "malware dropper",       "high"),
        "c2":          (["c2-beacon.io",    "botnet-ctrl.net", "rat-server.ru"],    "C2 beacon",             "high"),
        "ransomware":  (["ransom-key.org",  "lockbit-cdn.io",  "encrypt-srv.net"],  "ransomware C2",         "high"),
        "phishing":    (["login-secure.xyz","paypal-verify.cc","account-check.net"],"phishing domain",       "medium"),
        "scanner":     (["masscan.host",    "shodan.io",       "scanner-bot.net"],  "port scanner",          "medium"),
        "tor":         (["tor-exit-42.org", "onion-relay.net", "tor-gw.io"],        "Tor exit node",         "medium"),
        "tracker":     (["telemetry.co",    "analytics-cdn.io","track.pixel.net"],  "tracker / telemetry",   "low"),
    }
    trails, info, severity = THREAT_PROFILES.get(threat_type, THREAT_PROFILES["malware"])
    trail = random.choice(trails)

    # Random source IP from a realistic external range if not provided
    if not src_ip_in:
        src_ip = f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
    else:
        src_ip = src_ip_in

    dst_ip   = "192.168.1.1"
    src_port = random.randint(1024, 65535)
    dst_port = random.choice([53, 80, 443, 8080])
    proto    = random.choice(["DNS", "TCP", "UDP"])
    sensor   = "honeytrap"
    ref      = "https://honeytrap.ai/simulate"
    ts       = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

    line = f"{ts} {sensor} {src_ip} {src_port} {dst_ip} {dst_port} {proto} {trail} {info};{ref}\n"

    try:
        with open(LOG_PATH, "a") as f:
            f.write(line)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

    return jsonify({
        "status":   "ok",
        "trail":    trail,
        "src_ip":   src_ip,
        "severity": severity,
        "info":     info,
    })

@app.route("/api/threats/export")
@login_required
def api_threats_export():
    """Export the Maltrail threat log as a CSV download."""
    import csv, io
    from log_parser import parse_logs, get_summary
    events = parse_logs(LOG_PATH, dev_mode=DEV_MODE)
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=["timestamp","severity","src_ip","dst_ip","proto","trail","info","reference"])
    writer.writeheader()
    for e in events:
        writer.writerow({k: e.get(k, "") for k in writer.fieldnames})
    csv_bytes = output.getvalue().encode()
    filename = f"honeytrapai-threats-{datetime.utcnow().strftime('%Y%m%d-%H%M%S')}.csv"
    return app.response_class(
        response=csv_bytes,
        status=200,
        mimetype="text/csv",
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

if __name__ == "__main__":
    port  = int(os.environ.get("PORT", 5000))
    debug = DEV_MODE
    app.run(host="0.0.0.0", port=port, debug=debug)