#!/usr/bin/env python3
"""
HoneytrapAI — Email alert daemon
Watches Maltrail logs and sends digest emails for high-severity threats.
Runs as a systemd service. Batches alerts to avoid inbox flooding.
"""

import os
import json
import time
import smtplib
import hashlib
import logging
from datetime import datetime, timedelta
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.join(BASE_DIR, "config", "config.json")
SMTP_PATH = os.path.join(BASE_DIR, "config", "smtp.json")
LOG_PATH = os.environ.get("MALTRAIL_LOG", "/var/log/maltrail/maltrail.log")
STATE_PATH = os.path.join(BASE_DIR, "config", "notifier_state.json")

BATCH_INTERVAL = 300       # seconds between digest sends (5 min)
DEDUP_WINDOW = 3600        # seconds before same trail re-alerts (1 hour)
MIN_SEVERITY = "medium"    # minimum severity to alert on
SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2}

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [notifier] %(levelname)s %(message)s"
)
log = logging.getLogger(__name__)

def load_json(path, default=None):
    if os.path.exists(path):
        try:
            with open(path) as f:
                return json.load(f)
        except Exception:
            pass
    return default if default is not None else {}

def save_json(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        json.dump(data, f, indent=2)

def load_state():
    return load_json(STATE_PATH, {"last_position": 0, "sent_hashes": {}, "last_send": 0})

def save_state(state):
    save_json(STATE_PATH, state)

def event_hash(event):
    key = f"{event['trail']}:{event['src_ip']}"
    return hashlib.md5(key.encode()).hexdigest()

def read_new_events(state):
    """Read new lines from Maltrail log since last position."""
    from log_parser import parse_line
    if not os.path.exists(LOG_PATH):
        return [], state["last_position"]

    events = []
    pos = state.get("last_position", 0)

    try:
        with open(LOG_PATH) as f:
            f.seek(pos)
            for line in f:
                ev = parse_line(line)
                if ev:
                    events.append(ev)
            new_pos = f.tell()
    except Exception as e:
        log.error(f"Error reading log: {e}")
        return [], pos

    return events, new_pos

def filter_events(events, state, min_severity):
    """Filter events by severity and dedup window."""
    now = time.time()
    filtered = []
    sent = state.get("sent_hashes", {})
    min_level = SEVERITY_ORDER.get(min_severity, 1)

    for ev in events:
        if SEVERITY_ORDER.get(ev["severity"], 0) < min_level:
            continue
        h = event_hash(ev)
        last_sent = sent.get(h, 0)
        if now - last_sent > DEDUP_WINDOW:
            filtered.append(ev)
            sent[h] = now

    state["sent_hashes"] = sent
    return filtered

def build_email_body(events):
    """Build plain-text + HTML digest email."""
    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    high = [e for e in events if e["severity"] == "high"]
    medium = [e for e in events if e["severity"] == "medium"]

    subject = f"🐝 HoneytrapAI Alert — {len(high)} high, {len(medium)} medium severity threats"

    # Plain text
    text_lines = [
        f"HoneytrapAI Threat Digest — {now}",
        f"Total alerts: {len(events)} ({len(high)} high, {len(medium)} medium)",
        "",
    ]
    for ev in events:
        sev = ev["severity"].upper()
        text_lines.append(
            f"[{sev}] {ev['timestamp']} | {ev['src_ip']} → {ev['trail']} | {ev['info']}"
        )
    text_lines += [
        "",
        "View full details at http://honeytrap.local",
        "",
        "HoneytrapAI · No cloud · No subscription · No monthly fees. Ever.",
        "🐝 Join the Pro Club — https://honeytrap.ai/community"
    ]
    text_body = "\n".join(text_lines)

    # HTML
    rows = ""
    for ev in events:
        colour = {"high": "#c0392b", "medium": "#e67e22", "low": "#27ae60"}.get(ev["severity"], "#888")
        rows += (
            f"<tr>"
            f"<td style='color:{colour};font-weight:bold;padding:4px 8px'>{ev['severity'].upper()}</td>"
            f"<td style='padding:4px 8px'>{ev['timestamp']}</td>"
            f"<td style='padding:4px 8px'>{ev['src_ip']}</td>"
            f"<td style='padding:4px 8px'>{ev['trail']}</td>"
            f"<td style='padding:4px 8px'>{ev['info']}</td>"
            f"</tr>"
        )

    html_body = f"""
<html><body style='font-family:sans-serif;color:#333'>
<div style='max-width:700px;margin:0 auto'>
  <div style='background:#1a1a2e;padding:16px;border-radius:8px 8px 0 0'>
    <span style='color:#f5a623;font-size:1.3em;font-weight:bold'>🐝 HoneytrapAI Threat Digest</span>
    <span style='color:#aaa;font-size:0.9em;margin-left:12px'>{now}</span>
  </div>
  <div style='background:#f9f9f9;padding:16px;border:1px solid #ddd'>
    <p><strong>{len(events)} threats detected</strong> — {len(high)} high severity, {len(medium)} medium severity</p>
    <table style='width:100%;border-collapse:collapse;font-size:0.9em'>
      <thead>
        <tr style='background:#eee'>
          <th style='padding:4px 8px;text-align:left'>Severity</th>
          <th style='padding:4px 8px;text-align:left'>Time</th>
          <th style='padding:4px 8px;text-align:left'>Source IP</th>
          <th style='padding:4px 8px;text-align:left'>Trail</th>
          <th style='padding:4px 8px;text-align:left'>Info</th>
        </tr>
      </thead>
      <tbody>{rows}</tbody>
    </table>
    <p style='margin-top:16px'>
      <a href='http://honeytrap.local' style='background:#f5a623;color:#fff;padding:8px 16px;border-radius:4px;text-decoration:none'>
        View Dashboard
      </a>
    </p>
  </div>
  <div style='background:#eee;padding:8px 16px;font-size:0.8em;color:#888;border-radius:0 0 8px 8px'>
    HoneytrapAI · No cloud · No subscription · No monthly fees. Ever.<br>
    🐝 <a href='https://honeytrap.ai/community'>Join the Pro Club</a>
  </div>
</div>
</body></html>
"""
    return subject, text_body, html_body

def send_email(subject, text_body, html_body, smtp_cfg, to_addr):
    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = smtp_cfg.get("from_addr", "noreply@honeytrap.ai")
    msg["To"] = to_addr

    msg.attach(MIMEText(text_body, "plain"))
    msg.attach(MIMEText(html_body, "html"))

    host = smtp_cfg["host"]
    port = int(smtp_cfg.get("port", 587))
    user = smtp_cfg.get("username", "")
    pw = smtp_cfg.get("password", "")
    use_tls = smtp_cfg.get("tls", True)

    try:
        with smtplib.SMTP(host, port, timeout=15) as s:
            s.ehlo()
            if use_tls:
                s.starttls()
                s.ehlo()
            if user and pw:
                s.login(user, pw)
            s.sendmail(msg["From"], [to_addr], msg.as_string())
        log.info(f"Alert email sent to {to_addr}")
        return True
    except Exception as e:
        log.error(f"Failed to send email: {e}")
        return False

def run():
    log.info("HoneytrapAI notifier daemon starting...")
    while True:
        try:
            cfg = load_json(CONFIG_PATH)
            smtp_cfg = load_json(SMTP_PATH)
            state = load_state()

            to_addr = cfg.get("alert_email", "")
            min_sev = cfg.get("alert_threshold", MIN_SEVERITY)

            if not to_addr or not smtp_cfg.get("host"):
                time.sleep(BATCH_INTERVAL)
                continue

            events, new_pos = read_new_events(state)
            state["last_position"] = new_pos

            filtered = filter_events(events, state, min_sev)

            now = time.time()
            if filtered and (now - state.get("last_send", 0)) >= BATCH_INTERVAL:
                subject, text_body, html_body = build_email_body(filtered)
                if send_email(subject, text_body, html_body, smtp_cfg, to_addr):
                    state["last_send"] = now

            save_state(state)

        except Exception as e:
            log.error(f"Notifier loop error: {e}")

        time.sleep(60)  # check every minute, batch every BATCH_INTERVAL

if __name__ == "__main__":
    run()
