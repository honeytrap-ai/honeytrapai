#!/usr/bin/env python3
"""
HoneytrapAI — GitHub-based OTA update system
Checks github.com/honeytrap-ai/honeytrapai for new releases.
Never auto-installs — always prompts user via dashboard.
"""

import os
import json
import time
import logging
import urllib.request
from datetime import datetime

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
VERSION_PATH = os.path.join(BASE_DIR, "VERSION")
CACHE_PATH = os.path.join(BASE_DIR, "config", "update_cache.json")
STATUS_PATH = os.path.join(BASE_DIR, "config", "update_status.json")
PENDING_PATH = "/tmp/honeytrapai-update-pending"

GITHUB_API = "https://api.github.com/repos/honeytrap-ai/honeytrapai/releases/latest"
CACHE_TTL = 3600  # 1 hour cache

log = logging.getLogger(__name__)

def get_current_version():
    if os.path.exists(VERSION_PATH):
        with open(VERSION_PATH) as f:
            return f.read().strip()
    return "v0.1.0"

def parse_version(v):
    """Parse vX.Y.Z into tuple for comparison."""
    v = v.lstrip("v")
    try:
        return tuple(int(x) for x in v.split(".")[:3])
    except Exception:
        return (0, 0, 0)

def clear_cache():
    """Delete the update cache, e.g. after a successful install."""
    if os.path.exists(CACHE_PATH):
        try:
            os.remove(CACHE_PATH)
        except Exception:
            pass

def load_cache():
    if os.path.exists(CACHE_PATH):
        try:
            with open(CACHE_PATH) as f:
                return json.load(f)
        except Exception:
            pass
    return {}

def save_cache(data):
    os.makedirs(os.path.dirname(CACHE_PATH), exist_ok=True)
    with open(CACHE_PATH, "w") as f:
        json.dump(data, f, indent=2)

def set_status(status):
    os.makedirs(os.path.dirname(STATUS_PATH), exist_ok=True)
    with open(STATUS_PATH, "w") as f:
        json.dump(status, f, indent=2)

def get_update_status():
    if os.path.exists(STATUS_PATH):
        try:
            with open(STATUS_PATH) as f:
                return json.load(f)
        except Exception:
            pass
    return {"state": "idle"}

def check_for_update(force=False):
    """Check GitHub for a newer release. Returns dict with update info."""
    cache = load_cache()
    now = time.time()
    current = get_current_version()

    if not force and cache.get("checked_at", 0) + CACHE_TTL > now:
        result = cache.get("result", {"update_available": False})
        # Defence: if cache says an update is available but we're already on
        # that version (e.g. just installed), invalidate and re-check live.
        if result.get("update_available") and \
                parse_version(result.get("latest_version", "")) <= parse_version(current):
            clear_cache()
            return check_for_update(force=True)
        return result

    try:
        req = urllib.request.Request(
            GITHUB_API,
            headers={"Accept": "application/vnd.github.v3+json",
                     "User-Agent": f"HoneytrapAI/{current}"}
        )
        with urllib.request.urlopen(req, timeout=10) as r:
            release = json.loads(r.read())

        latest = release.get("tag_name", current)
        notes = release.get("body", "")
        tarball = release.get("tarball_url", "")

        update_available = parse_version(latest) > parse_version(current)

        result = {
            "update_available": update_available,
            "current_version": current,
            "latest_version": latest,
            "release_notes": notes[:500] if notes else "",
            "tarball_url": tarball,
            "checked_at": datetime.utcnow().isoformat()
        }

        save_cache({"checked_at": now, "result": result})
        return result

    except Exception as e:
        log.error(f"Update check failed: {e}")
        return {
            "update_available": False,
            "current_version": current,
            "error": str(e),
            "checked_at": datetime.utcnow().isoformat()
        }

def perform_update():
    """
    Write pending update info and trigger the privileged updater worker
    via systemd. The worker (updater_worker.py) runs as root and handles
    the actual download, file swap, and service restart.
    """
    try:
        info = check_for_update(force=True)
        if not info.get("update_available"):
            set_status({"state": "idle", "message": "Already up to date."})
            return

        # Write pending info for the worker to consume
        with open(PENDING_PATH, "w") as f:
            json.dump({
                "tarball_url": info["tarball_url"],
                "latest_version": info["latest_version"],
            }, f)

        set_status({"state": "downloading", "message": "Downloading update..."})

        # Trigger the privileged worker service
        os.system("sudo systemctl start honeytrapai-updater.service")

    except Exception as e:
        log.error(f"Failed to trigger update: {e}")
        set_status({"state": "error", "message": f"Failed to trigger update: {str(e)}"})

if __name__ == "__main__":
    result = check_for_update(force=True)
    print(json.dumps(result, indent=2))