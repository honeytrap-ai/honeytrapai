# HoneytrapAI — log_parser.py
# Version: v0.3.26
# Revised: 2026-03-11
# Rev: 3
#!/usr/bin/env python3
"""
HoneytrapAI — Maltrail log parser with severity scoring
Parses both HoneytrapAI custom log format and Maltrail native dated log format.
"""

import os
import glob
import re
from datetime import datetime, timedelta
from collections import Counter

# HoneytrapAI custom log format (maltrail.log):
# timestamp sensor src_ip src_port dst_ip dst_port proto trail info;reference
#
# Maltrail native log format (YYYY-MM-DD.log):
# "timestamp_with_microseconds" sensor src_ip src_port dst_ip dst_port proto trail info

SEVERITY_HIGH = [
    "malware", "c2", "botnet", "ransomware", "rat", "backdoor",
    "trojan", "exploit", "shellcode", "miner", "coinminer",
    "emotet", "mirai", "trickbot", "dridex", "qakbot"
]
SEVERITY_MEDIUM = [
    "phishing", "suspicious", "scanner", "bruteforce", "spam",
    "proxy", "tor", "vpn", "p2p", "adware", "pua"
]
SEVERITY_LOW = [
    "tracker", "ads", "analytics", "telemetry", "cdn"
]

# Maltrail native log: quoted timestamp at start
_NATIVE_RE = re.compile(r'^"([^"]+)"\s+(.+)$')

DEV_SAMPLE_EVENTS = [
    {
        "timestamp": (datetime.utcnow() - timedelta(minutes=2)).strftime("%Y-%m-%d %H:%M:%S"),
        "src_ip": "196.181.98.171",
        "dst_ip": "185.220.101.47",
        "proto": "TCP",
        "trail": "masscan.host",
        "info": "port scanner",
        "severity": "medium",
        "reference": "https://abuse.ch"
    },
    {
        "timestamp": (datetime.utcnow() - timedelta(minutes=8)).strftime("%Y-%m-%d %H:%M:%S"),
        "src_ip": "84.209.135.20",
        "dst_ip": "185.220.101.47",
        "proto": "TCP",
        "trail": "encrypt-srv.net",
        "info": "ransomware C2",
        "severity": "high",
        "reference": "https://abuse.ch"
    },
    {
        "timestamp": (datetime.utcnow() - timedelta(minutes=15)).strftime("%Y-%m-%d %H:%M:%S"),
        "src_ip": "85.159.192.183",
        "dst_ip": "91.108.4.0",
        "proto": "TCP",
        "trail": "rat-server.ru",
        "info": "C2 beacon",
        "severity": "high",
        "reference": "https://maltrail.github.io"
    },
    {
        "timestamp": (datetime.utcnow() - timedelta(minutes=22)).strftime("%Y-%m-%d %H:%M:%S"),
        "src_ip": "168.41.231.251",
        "dst_ip": "phishing-login.xyz",
        "proto": "DNS",
        "trail": "analytics-cdn.io",
        "info": "tracker / telemetry",
        "severity": "low",
        "reference": "ET Open"
    },
    {
        "timestamp": (datetime.utcnow() - timedelta(minutes=45)).strftime("%Y-%m-%d %H:%M:%S"),
        "src_ip": "33.15.97.6",
        "dst_ip": "evil-payload.ru",
        "proto": "DNS",
        "trail": "evil-payload.ru",
        "info": "malware dropper",
        "severity": "high",
        "reference": "https://abuse.ch"
    },
    {
        "timestamp": (datetime.utcnow() - timedelta(hours=1, minutes=10)).strftime("%Y-%m-%d %H:%M:%S"),
        "src_ip": "119.110.86.15",
        "dst_ip": "bad-actor.xyz",
        "proto": "DNS",
        "trail": "bad-actor.xyz",
        "info": "malware dropper",
        "severity": "high",
        "reference": "https://abuse.ch"
    },
]

def score_severity(trail, info):
    """Score a trail/info string and return high/medium/low."""
    combined = (trail + " " + info).lower()
    for kw in SEVERITY_HIGH:
        if kw in combined:
            return "high"
    for kw in SEVERITY_MEDIUM:
        if kw in combined:
            return "medium"
    for kw in SEVERITY_LOW:
        if kw in combined:
            return "low"
    return "medium"

def tail_file(path, max_lines=2000):
    """Memory-efficient tail of a file."""
    if not os.path.exists(path):
        return []
    try:
        with open(path, "rb") as f:
            f.seek(0, 2)
            size = f.tell()
            block = min(size, 1024 * 256)  # 256KB max read
            f.seek(-block, 2)
            lines = f.read().decode("utf-8", errors="replace").splitlines()
        return lines[-max_lines:]
    except Exception:
        return []

def parse_line(line):
    """Parse a HoneytrapAI custom format log line into a dict."""
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    parts = line.split(" ")
    if len(parts) < 9:
        return None
    try:
        timestamp = parts[0] + " " + parts[1]
        src_ip    = parts[3]
        dst_ip    = parts[5]
        proto     = parts[7]
        trail     = parts[8]
        info      = " ".join(parts[9:]) if len(parts) > 9 else ""
        reference = ""
        if ";" in info:
            info, reference = info.rsplit(";", 1)
        severity = score_severity(trail, info)
        return {
            "timestamp": timestamp,
            "src_ip":    src_ip,
            "dst_ip":    dst_ip,
            "proto":     proto,
            "trail":     trail,
            "info":      info.strip(),
            "severity":  severity,
            "reference": reference.strip()
        }
    except Exception:
        return None

def parse_native_line(line):
    """Parse a Maltrail native dated log line into a dict.

    Format: "YYYY-MM-DD HH:MM:SS.ffffff" sensor src_ip src_port dst_ip dst_port proto trail info
    """
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    m = _NATIVE_RE.match(line)
    if not m:
        return None
    try:
        # Truncate microseconds for uniform timestamp format
        ts_raw = m.group(1)
        timestamp = ts_raw.split(".")[0]

        parts = m.group(2).split(" ")
        if len(parts) < 7:
            return None
        # sensor = parts[0]
        src_ip = parts[1]
        # src_port = parts[2]
        dst_ip = parts[3]
        # dst_port = parts[4]
        proto  = parts[5]
        trail  = parts[6]
        info   = " ".join(parts[7:]) if len(parts) > 7 else ""

        # Strip surrounding quotes from info/trail if present
        trail = trail.strip('"')
        info  = info.strip().strip('"')

        severity = score_severity(trail, info)
        return {
            "timestamp": timestamp,
            "src_ip":    src_ip,
            "dst_ip":    dst_ip,
            "proto":     proto,
            "trail":     trail,
            "info":      info,
            "severity":  severity,
            "reference": ""
        }
    except Exception:
        return None

def get_native_log_paths(log_dir="/var/log/maltrail"):
    """Return today's and yesterday's Maltrail native dated log paths (they cover the 24h window)."""
    paths = []
    for delta in (0, 1):
        date_str = (datetime.utcnow() - timedelta(days=delta)).strftime("%Y-%m-%d")
        path = os.path.join(log_dir, f"{date_str}.log")
        if os.path.exists(path):
            paths.append(path)
    return paths

def parse_logs(log_path, max_events=500, dev_mode=False):
    """Return list of parsed threat events from all sources, newest first.

    Reads both the HoneytrapAI custom maltrail.log and Maltrail native
    dated log files, merges and deduplicates by (timestamp, src_ip, trail).
    """
    if dev_mode:
        return DEV_SAMPLE_EVENTS

    events   = []
    seen     = set()  # dedup key: (timestamp, src_ip, trail)
    cutoff   = datetime.utcnow() - timedelta(hours=24)

    def _add(ev):
        if ev is None:
            return
        try:
            ts = datetime.strptime(ev["timestamp"], "%Y-%m-%d %H:%M:%S")
        except ValueError:
            return
        if ts < cutoff:
            return
        key = (ev["timestamp"], ev["src_ip"], ev["trail"])
        if key in seen:
            return
        seen.add(key)
        events.append(ev)

    # --- Source 1: HoneytrapAI custom log ---
    for line in tail_file(log_path, max_lines=2000):
        _add(parse_line(line))

    # --- Source 2: Maltrail native dated logs ---
    for path in get_native_log_paths():
        for line in tail_file(path, max_lines=2000):
            _add(parse_native_line(line))

    # Sort newest first
    events.sort(key=lambda e: e["timestamp"], reverse=True)
    return events[:max_events]

def get_summary(events):
    """Return summary statistics from a list of events."""
    if not events:
        return {
            "total": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "top_sources": [],
            "top_trails": [],
            "top_threat_types": []
        }

    high   = [e for e in events if e["severity"] == "high"]
    medium = [e for e in events if e["severity"] == "medium"]
    low    = [e for e in events if e["severity"] == "low"]

    SEV_ORDER = {"high": 3, "medium": 2, "low": 1}

    src_count    = Counter()
    src_severity = {}
    trail_count  = Counter()
    trail_sev    = {}
    type_count   = Counter()
    type_sev     = {}

    for e in events:
        sev = e["severity"]

        ip = e["src_ip"]
        src_count[ip] += 1
        if SEV_ORDER.get(sev, 0) > SEV_ORDER.get(src_severity.get(ip, "low"), 0):
            src_severity[ip] = sev

        trail = e["trail"]
        trail_count[trail] += 1
        if SEV_ORDER.get(sev, 0) > SEV_ORDER.get(trail_sev.get(trail, "low"), 0):
            trail_sev[trail] = sev

        info_lower = e["info"].lower()
        for kw in SEVERITY_HIGH + SEVERITY_MEDIUM + SEVERITY_LOW:
            if kw in info_lower:
                type_count[kw] += 1
                if SEV_ORDER.get(sev, 0) > SEV_ORDER.get(type_sev.get(kw, "low"), 0):
                    type_sev[kw] = sev
                break

    return {
        "total":  len(events),
        "high":   len(high),
        "medium": len(medium),
        "low":    len(low),
        "top_sources": [
            {"ip": ip, "count": c, "severity": src_severity.get(ip, "low")}
            for ip, c in src_count.most_common(5)
        ],
        "top_trails": [
            {"trail": t, "count": c, "severity": trail_sev.get(t, "low")}
            for t, c in trail_count.most_common(5)
        ],
        "top_threat_types": [
            {"type": t, "count": c, "severity": type_sev.get(t, "low")}
            for t, c in type_count.most_common(5)
        ],
    }