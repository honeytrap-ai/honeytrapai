#!/usr/bin/env python3
"""
HoneytrapAI — CLI SMTP configuration wizard
Run: sudo python3 smtp_setup.py
"""

import os
import json
import smtplib
import getpass

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SMTP_PATH = os.path.join(BASE_DIR, "config", "smtp.json")

PRESETS = {
    "1": {"name": "Gmail",     "host": "smtp.gmail.com",       "port": 587, "tls": True},
    "2": {"name": "Outlook",   "host": "smtp.office365.com",   "port": 587, "tls": True},
    "3": {"name": "Yahoo",     "host": "smtp.mail.yahoo.com",  "port": 587, "tls": True},
    "4": {"name": "iCloud",    "host": "smtp.mail.me.com",     "port": 587, "tls": True},
    "5": {"name": "FastMail",  "host": "smtp.fastmail.com",    "port": 587, "tls": True},
    "6": {"name": "Custom",    "host": "",                     "port": 587, "tls": True},
}

def print_banner():
    print("\n🐝 HoneytrapAI — SMTP Email Setup")
    print("   No cloud. No subscription. No monthly fees. Ever.")
    print("=" * 48)

def choose_preset():
    print("\nSelect your email provider:")
    for k, v in PRESETS.items():
        print(f"  {k}. {v['name']}")
    while True:
        choice = input("\nEnter number: ").strip()
        if choice in PRESETS:
            return PRESETS[choice]
        print("Invalid choice. Try again.")

def get_smtp_config():
    preset = choose_preset()

    if preset["name"] == "Custom":
        host = input("SMTP host: ").strip()
        port = int(input("SMTP port [587]: ").strip() or "587")
        tls = input("Use TLS? [Y/n]: ").strip().lower() != "n"
    else:
        print(f"\nUsing {preset['name']} SMTP settings.")
        host = preset["host"]
        port = preset["port"]
        tls = preset["tls"]

    from_addr = input("From address (e.g. noreply@honeytrap.ai): ").strip()
    username = input("SMTP username (usually your email): ").strip()
    password = getpass.getpass("SMTP password (app password recommended): ")

    return {
        "host": host,
        "port": port,
        "tls": tls,
        "from_addr": from_addr,
        "username": username,
        "password": password
    }

def test_smtp(cfg):
    print(f"\nTesting connection to {cfg['host']}:{cfg['port']}...")
    try:
        with smtplib.SMTP(cfg["host"], cfg["port"], timeout=10) as s:
            s.ehlo()
            if cfg["tls"]:
                s.starttls()
                s.ehlo()
            if cfg["username"] and cfg["password"]:
                s.login(cfg["username"], cfg["password"])
        print("✅ SMTP connection successful.")
        return True
    except Exception as e:
        print(f"❌ SMTP test failed: {e}")
        return False

def save_config(cfg):
    os.makedirs(os.path.dirname(SMTP_PATH), exist_ok=True)
    with open(SMTP_PATH, "w") as f:
        json.dump(cfg, f, indent=2)
    os.chmod(SMTP_PATH, 0o600)
    print(f"✅ SMTP config saved to {SMTP_PATH}")

def main():
    print_banner()
    cfg = get_smtp_config()
    if test_smtp(cfg):
        save_config(cfg)
        print("\n✅ Email alerts are now configured.")
        print("   The notifier daemon will use these settings automatically.")
    else:
        retry = input("\nSave anyway? [y/N]: ").strip().lower()
        if retry == "y":
            save_config(cfg)
        else:
            print("Configuration not saved.")

if __name__ == "__main__":
    main()


# ─────────────────────────────────────────────
# requirements.txt (save as separate file)
# ─────────────────────────────────────────────
# flask>=3.0.0
# gunicorn>=21.0.0
# pyyaml>=6.0
