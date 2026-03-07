#!/usr/bin/env python3
"""
HoneytrapAI — Flask web dashboard core
No cloud. No subscription. No monthly fees. Ever.
"""

import os
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
DHCPCD_PATH = "/etc/dhcpcd.conf"
DHCPCD_BLOCK_MARKER = "# HoneytrapAI static IP — do not edit this block manually"

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
        # IP + prefix length
        out = subprocess.check_output(
            ["ip", "-4", "addr", "show", iface], text=True, stderr=subprocess.DEVNULL
        )
        for line in out.splitlines():
            line = line.strip()
            if line.startswith("inet "):
                parts = line.split()
                cidr = parts[1]          # e.g. "192.168.1.199/24"
                iface_obj = ipaddress.IPv4Interface(cidr)
                info["ip"] = str(iface_obj.ip)
                info["prefix_len"] = str(iface_obj.network.prefixlen)
                info["network"] = str(iface_obj.network)
                break
    except Exception:
        pass
    try:
        # Default gateway
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
        # First nameserver from resolv.conf
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
    """
    Return True if ip_str is a valid IPv4 address within network_str (e.g. '192.168.1.0/24').
    Returns False on any parse error or if the IP is the network/broadcast address.
    """
    try:
        ip = ipaddress.IPv4Address(ip_str)
        net = ipaddress.IPv4Network(network_str, strict=False)
        return ip in net and ip != net.network_address and ip != net.broadcast_address
    except Exception:
        return False


def set_static_ip(iface, ip, prefix_len, gateway, dns):
    """
    Write (or replace) the HoneytrapAI static IP block in /etc/dhcpcd.conf.
    Idempotent — removes any previous block before writing.
    Raises on any I/O or subprocess error.
    """
    # Read existing file
    if os.path.exists(DHCPCD_PATH):
        with open(DHCPCD_PATH) as f:
            lines = f.readlines()
    else:
        lines = []

    # Strip any previous HoneytrapAI block
    new_lines = []
    skip = False
    for line in lines:
        if line.strip() == DHCPCD_BLOCK_MARKER:
            skip = True
        if not skip:
            new_lines.append(line)
        if skip and line.strip() == "# end HoneytrapAI static IP":
            skip = False

    # Append new block
    block = (
        f"\n{DHCPCD_BLOCK_MARKER}\n"
        f"interface {iface}\n"
        f"static ip_address={ip}/{prefix_len}\n"
        f"static routers={gateway}\n"
        f"static domain_name_servers={dns}\n"
        f"# end HoneytrapAI static IP\n"
    )
    new_lines.append(block)

    with open(DHCPCD_PATH, "w") as f:
        f.writelines(new_lines)


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

    # Network info needed for step 2 (GET and POST re-render)
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
            action = request.form.get("action", "save")   # "save" or "skip"

            if action == "skip":
                # Stay on DHCP — record that the user skipped, move to step 3
                cfg["static_ip_skipped"] = True
                cfg["interface"] = "eth0"
                save_config(cfg)
                step = 3

            else:
                entered_ip = request.form.get("static_ip", "").strip()

                # Validate: must be a valid IPv4 in the same subnet
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
def dashboard():
    return render_template("dashboard.html", version=get_version(), dev_mode=DEV_MODE)

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
        import urllib.request
        with urllib.request.urlopen(
            "http://127.0.0.1:3000/control/stats", timeout=3
        ) as r:
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
    import io
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
    """
    Password-protected factory reset.
    Clears setup_complete, password hash, static IP config, alert settings.
    Removes the HoneytrapAI dhcpcd block, then reboots.
    """
    cfg = load_config()
    data = request.get_json()
    password = data.get("password", "")

    if not verify_password(password, cfg.get("password_hash", "")):
        return jsonify({"error": "Incorrect password."}), 400

    _perform_factory_reset()

    # Reboot in a background thread so we can return the response first
    import threading
    def _reboot():
        import time, subprocess as sp
        time.sleep(2)
        sp.run(["sudo", "reboot"], check=False)
    threading.Thread(target=_reboot, daemon=True).start()

    return jsonify({"status": "ok"})


def _perform_factory_reset():
    """
    Core reset logic — shared by dashboard reset and USB reset monitor.
    Wipes config, removes static IP block from dhcpcd.conf.
    Does NOT reboot — caller is responsible for that.
    """
    # Wipe config files
    for path in [CONFIG_PATH, SMTP_PATH]:
        if os.path.exists(path):
            os.remove(path)

    # Remove HoneytrapAI static IP block from dhcpcd.conf
    if os.path.exists(DHCPCD_PATH):
        with open(DHCPCD_PATH) as f:
            lines = f.readlines()
        new_lines, skip = [], False
        for line in lines:
            if line.strip() == DHCPCD_BLOCK_MARKER:
                skip = True
            if not skip:
                new_lines.append(line)
            if skip and line.strip() == "# end HoneytrapAI static IP":
                skip = False
        with open(DHCPCD_PATH, "w") as f:
            f.writelines(new_lines)


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