#!/usr/bin/env python3
"""
HoneytrapAI — Flask web dashboard core
No cloud. No subscription. No monthly fees. Ever.
"""

import os
import json
import hashlib
import secrets
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

# --- Auth decorator ---
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

    if request.method == "POST":
        if step == 1:
            password = request.form.get("password", "")
            confirm = request.form.get("confirm", "")
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
            interface = request.form.get("interface", "eth0").strip()
            cfg["interface"] = interface
            save_config(cfg)
            step = 3

        elif step == 3:
            alert_email = request.form.get("alert_email", "").strip()
            cfg["alert_email"] = alert_email
            cfg["setup_complete"] = True
            cfg["setup_date"] = datetime.utcnow().isoformat()
            save_config(cfg)
            session["authenticated"] = True
            return redirect(url_for("dashboard"))

    return render_template("setup.html", step=step, error=error, version=get_version())

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
    """Fetch stats from local AdGuard Home API"""
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
            "http://127.0.0.1:3000/control/stats",
            timeout=3
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
    new_pw = data.get("new_password", "")
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
    """Download config backup as JSON"""
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

@app.route("/api/restore", methods=["POST"])
@login_required
def api_restore():
    """Restore config from backup JSON"""
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
    port = int(os.environ.get("PORT", 5000))
    debug = DEV_MODE
    app.run(host="0.0.0.0", port=port, debug=debug)
