#!/usr/bin/env python3
# HoneytrapAI — notifier.py
# Copyright (c) 2026 HoneytrapAI / Anthony Watts
# Licensed under the HoneytrapAI Source Available License — see LICENSE file for details
# Version: v0.3.14
# Revised: 2026-03-09
# Rev: 3
"""
HoneytrapAI — Email notifier daemon
Polls the Maltrail log every 60s and sends digest alert emails for new threats.
Responds immediately to a trigger file written by api_simulate_threat().
No cloud. No subscription. No monthly fees. Ever.
"""

import os
import json
import time
import socket
import smtplib
import logging
from datetime import datetime, timezone
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# --- Paths ---
BASE_DIR      = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH   = os.path.join(BASE_DIR, "config", "config.json")
SMTP_PATH     = os.path.join(BASE_DIR, "config", "smtp.json")
STATE_PATH    = os.path.join(BASE_DIR, "config", "notifier_state.json")
TRIGGER_PATH  = os.path.join(BASE_DIR, "config", "notifier_trigger")
LOG_PATH      = os.environ.get("MALTRAIL_LOG", "/var/log/maltrail/maltrail.log")
POLL_INTERVAL = 60  # seconds

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [notifier] %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
log = logging.getLogger("notifier")

# --- Config helpers ---
def load_config():
    try:
        if os.path.exists(CONFIG_PATH):
            with open(CONFIG_PATH) as f:
                return json.load(f)
    except Exception as e:
        log.warning(f"Could not load config: {e}")
    return {}

def load_smtp():
    try:
        if os.path.exists(SMTP_PATH):
            with open(SMTP_PATH) as f:
                return json.load(f)
    except Exception as e:
        log.warning(f"Could not load smtp config: {e}")
    return {}

def load_state():
    try:
        if os.path.exists(STATE_PATH):
            with open(STATE_PATH) as f:
                return json.load(f)
    except Exception:
        pass
    return {"log_position": 0}

def save_state(state):
    try:
        os.makedirs(os.path.dirname(STATE_PATH), exist_ok=True)
        with open(STATE_PATH, "w") as f:
            json.dump(state, f, indent=2)
    except Exception as e:
        log.warning(f"Could not save state: {e}")

# --- Log parsing ---
SEVERITY_MAP = {
    "malware dropper":     "high",
    "ransomware":          "high",
    "c2 beacon":           "high",
    "ransomware c2":       "high",
    "phishing domain":     "medium",
    "port scanner":        "medium",
    "tor exit node":       "medium",
    "tracker":             "low",
    "tracker / telemetry": "low",
}
SEVERITY_ORDER = {"high": 3, "medium": 2, "low": 1}

def infer_severity(info):
    info_lower = info.lower()
    for key, sev in SEVERITY_MAP.items():
        if key in info_lower:
            return sev
    return "low"

def meets_threshold(severity, threshold):
    return SEVERITY_ORDER.get(severity, 0) >= SEVERITY_ORDER.get(threshold, 1)

# BUG-28: resolve hostname to IP address for src_ip field
def resolve_to_ip(value):
    """Return value unchanged if already an IP; resolve hostname to IP otherwise."""
    try:
        socket.inet_aton(value)   # raises if not a valid IPv4 address
        return value
    except socket.error:
        pass
    try:
        return socket.gethostbyname(value)
    except Exception:
        return value              # fall back to original if resolution fails

def parse_new_lines(position):
    """
    Read new lines from the Maltrail log since the last known byte position.
    Returns (events, new_position).
    Each event: {timestamp, src_ip, trail, info, severity}
    """
    events = []
    if not os.path.exists(LOG_PATH):
        return events, position
    try:
        with open(LOG_PATH, "r", errors="replace") as f:
            f.seek(position)
            for line in f:
                line = line.strip()
                if not line:
                    continue
                parts = line.split()
                # Maltrail log format:
                # timestamp sensor src_ip src_port dst_ip dst_port proto trail info;ref
                # Note: info field may contain spaces (e.g. "malware dropper") so
                # we must rejoin everything from field 8 onward before splitting on ";"
                if len(parts) < 9:
                    continue
                try:
                    ts       = f"{parts[0]} {parts[1]}"
                    src_ip   = resolve_to_ip(parts[2])             # BUG-28: ensure IP not hostname
                    trail    = parts[7]
                    info_raw = " ".join(parts[8:])                  # BUG-21: rejoin multi-word info field
                    info     = info_raw.split(";")[0].strip()       # strip ref URL and whitespace
                    sev      = infer_severity(info)
                    events.append({
                        "timestamp": ts,
                        "src_ip":    src_ip,
                        "trail":     trail,
                        "info":      info,
                        "severity":  sev,
                    })
                except Exception:
                    continue
            new_position = f.tell()
        return events, new_position
    except Exception as e:
        log.warning(f"Log read error: {e}")
        return events, position

# --- Email sending ---
SEV_COLORS = {"high": "#e74c3c", "medium": "#f39c12", "low": "#27ae60"}
SEV_BG     = {"high": "#2a1010", "medium": "#2a1f10", "low": "#0f2a1a"}

def build_email_html(events):
    count = len(events)
    rows  = ""
    for e in events:
        col = SEV_COLORS.get(e["severity"], "#aaa")
        bg  = SEV_BG.get(e["severity"], "#12122a")
        rows += f"""
        <tr>
          <td style="padding:.4rem .6rem;border-bottom:1px solid #1a1a2e">
            <span style="background:{bg};color:{col};border-left:3px solid {col};
                         padding:.15rem .5rem;border-radius:3px;font-size:.75rem;
                         font-weight:700">{e["severity"].upper()}</span>
          </td>
          <td style="padding:.4rem .6rem;border-bottom:1px solid #1a1a2e;
                     color:#666;font-size:.8rem;white-space:nowrap">{e["timestamp"][11:19]}</td>
          <td style="padding:.4rem .6rem;border-bottom:1px solid #1a1a2e;
                     font-family:monospace;color:#aaa;font-size:.8rem">{e["src_ip"]}</td>
          <td style="padding:.4rem .6rem;border-bottom:1px solid #1a1a2e;
                     color:#f5a623;font-size:.8rem">{e["trail"]}</td>
          <td style="padding:.4rem .6rem;border-bottom:1px solid #1a1a2e;
                     color:#aaa;font-size:.8rem">{e["info"]}</td>
        </tr>"""

    return f"""
    <div style="font-family:-apple-system,sans-serif;background:#0f0f1a;color:#e0e0e0;
                padding:2rem;max-width:620px;margin:0 auto;border-radius:10px">
      <div style="font-size:2rem;margin-bottom:.5rem">🐝</div>
      <div style="color:#f5a623;font-size:1.1rem;font-weight:700;margin-bottom:.4rem">
        HoneytrapAI — {count} new threat{"s" if count != 1 else ""} detected
      </div>
      <p style="color:#aaa;font-size:.85rem;line-height:1.6;margin-bottom:1.2rem">
        The following threat{"s were" if count != 1 else " was"} detected on your network.
        Log in to your HoneytrapAI dashboard for full details.
      </p>
      <table style="width:100%;border-collapse:collapse;font-size:.82rem;
                    background:#1a1a2e;border-radius:6px;overflow:hidden">
        <thead>
          <tr style="border-bottom:1px solid #2a2a4a">
            <th style="padding:.4rem .6rem;text-align:left;color:#666;
                       font-size:.72rem;text-transform:uppercase;letter-spacing:.05em">Severity</th>
            <th style="padding:.4rem .6rem;text-align:left;color:#666;
                       font-size:.72rem;text-transform:uppercase;letter-spacing:.05em">Time</th>
            <th style="padding:.4rem .6rem;text-align:left;color:#666;
                       font-size:.72rem;text-transform:uppercase;letter-spacing:.05em">Source IP</th>
            <th style="padding:.4rem .6rem;text-align:left;color:#666;
                       font-size:.72rem;text-transform:uppercase;letter-spacing:.05em">Trail</th>
            <th style="padding:.4rem .6rem;text-align:left;color:#666;
                       font-size:.72rem;text-transform:uppercase;letter-spacing:.05em">Info</th>
          </tr>
        </thead>
        <tbody>{rows}</tbody>
      </table>
      <hr style="border:none;border-top:1px solid #2a2a4a;margin:1.2rem 0">
      <div style="font-size:.72rem;color:#555">
        No cloud. No subscription. No monthly fees. Ever. —
        <a href="https://honeytrap.ai" style="color:#f5a623;text-decoration:none">HoneytrapAI&#8482;</a>
      </div>
    </div>"""

def build_email_text(events):
    count = len(events)
    lines = [
        f"HoneytrapAI — {count} new threat{'s' if count != 1 else ''} detected",
        "=" * 50,
        ""
    ]
    for e in events:
        lines.append(
            f"[{e['severity'].upper()}] {e['timestamp'][11:19]}  "
            f"{e['src_ip']}  {e['trail']}  {e['info']}"
        )
    lines += ["", "No cloud. No subscription. No monthly fees. Ever.", "— HoneytrapAI  https://honeytrap.ai"]
    return "\n".join(lines)

def send_digest(events, cfg, smtp):
    to_addr   = cfg.get("alert_email", "").strip()
    from_addr = smtp.get("from_addr", smtp.get("username", "")).strip()
    host      = smtp.get("host", "")
    port      = int(smtp.get("port", 587))
    user      = smtp.get("username", "")
    pw        = smtp.get("password", "")
    use_ssl   = smtp.get("ssl", False)
    use_tls   = smtp.get("tls", True)

    if not to_addr or not host:
        log.warning("Cannot send digest — alert_email or SMTP host not configured")
        return False

    count = len(events)
    msg   = MIMEMultipart("alternative")
    msg["Subject"] = f"🐝 HoneytrapAI — {count} new threat{'s' if count != 1 else ''} detected"
    msg["From"]    = from_addr
    msg["To"]      = to_addr
    msg.attach(MIMEText(build_email_text(events), "plain"))
    msg.attach(MIMEText(build_email_html(events), "html"))

    try:
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
        server.sendmail(from_addr, [to_addr], msg.as_string())
        server.quit()
        log.info(f"Digest sent to {to_addr} — {count} event(s)")
        return True
    except Exception as e:
        log.error(f"Failed to send digest: {e}")
        return False

# --- Trigger file helpers ---
def check_trigger():
    if os.path.exists(TRIGGER_PATH):
        try:
            os.remove(TRIGGER_PATH)
        except Exception:
            pass
        return True
    return False

# --- Main loop ---
def run():
    log.info("HoneytrapAI notifier started")
    state = load_state()

    # On first start, fast-forward to end of log so we don't
    # re-alert on historical entries
    if state.get("log_position", 0) == 0 and os.path.exists(LOG_PATH):
        try:
            state["log_position"] = os.path.getsize(LOG_PATH)
            save_state(state)
            log.info(f"Fast-forwarded log position to {state['log_position']} bytes")
        except Exception:
            pass

    last_run = 0

    while True:
        triggered = check_trigger()
        time_due  = (time.time() - last_run) >= POLL_INTERVAL

        if not (triggered or time_due):
            time.sleep(1)
            continue

        last_run = time.time()
        cfg  = load_config()
        smtp = load_smtp()

        # Skip if emails disabled
        if cfg.get("email_disabled", False):
            state_now = load_state()
            # Still advance position so we don't build up a backlog
            _, new_pos = parse_new_lines(state_now.get("log_position", 0))
            state_now["log_position"] = new_pos
            save_state(state_now)
            if triggered:
                log.info("Trigger received but email_disabled — skipping")
            time.sleep(1)
            continue

        threshold = cfg.get("alert_threshold", "medium")
        position  = state.get("log_position", 0)

        events, new_position = parse_new_lines(position)
        state["log_position"] = new_position
        state["last_run"]     = datetime.now(timezone.utc).isoformat()
        save_state(state)

        qualifying = [e for e in events if meets_threshold(e["severity"], threshold)]

        if qualifying:
            send_digest(qualifying, cfg, smtp)
        elif triggered:
            log.info(f"Trigger received — {len(events)} event(s) parsed, "
                     f"none met threshold '{threshold}'")

        time.sleep(1)

if __name__ == "__main__":
    run()