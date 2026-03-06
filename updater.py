#!/usr/bin/env python3
"""
HoneytrapAI — GitHub-based OTA update system
Checks github.com/honeytrap-ai/honeytrapai for new releases.
Never auto-installs — always prompts user via dashboard.
"""

import os
import json
import time
import shutil
import tarfile
import logging
import urllib.request
from datetime import datetime

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
VERSION_PATH = os.path.join(BASE_DIR, "VERSION")
CACHE_PATH = os.path.join(BASE_DIR, "config", "update_cache.json")
STATUS_PATH = os.path.join(BASE_DIR, "config", "update_status.json")

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

    if not force and cache.get("checked_at", 0) + CACHE_TTL > now:
        return cache.get("result", {"update_available": False})

    current = get_current_version()

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
    """Download and install the latest release. Preserves user config."""
    set_status({"state": "downloading", "message": "Downloading update..."})
    try:
        info = check_for_update(force=True)
        if not info.get("update_available"):
            set_status({"state": "idle", "message": "Already up to date."})
            return

        tarball_url = info["tarball_url"]
        tmp_tar = "/tmp/honeytrapai-update.tar.gz"
        tmp_dir = "/tmp/honeytrapai-update"

        # Download
        urllib.request.urlretrieve(tarball_url, tmp_tar)
        set_status({"state": "installing", "message": "Installing update..."})

        # Extract
        if os.path.exists(tmp_dir):
            shutil.rmtree(tmp_dir)
        os.makedirs(tmp_dir)
        with tarfile.open(tmp_tar, "r:gz") as t:
            t.extractall(tmp_dir)

        # Find extracted root dir (GitHub tarballs have a prefix dir)
        extracted = [d for d in os.listdir(tmp_dir) if os.path.isdir(os.path.join(tmp_dir, d))]
        if not extracted:
            raise Exception("Unexpected tarball structure")
        src = os.path.join(tmp_dir, extracted[0])

        # Files to never overwrite (user data)
        PRESERVE = {"config", "config.json", "smtp.json"}

        # Swap files
        for item in os.listdir(src):
            if item in PRESERVE:
                continue
            src_path = os.path.join(src, item)
            dst_path = os.path.join(BASE_DIR, item)
            if os.path.isdir(src_path):
                if os.path.exists(dst_path):
                    shutil.rmtree(dst_path)
                shutil.copytree(src_path, dst_path)
            else:
                shutil.copy2(src_path, dst_path)

        # Restart services
        set_status({"state": "restarting", "message": "Restarting services..."})
        os.system("sudo systemctl restart honeytrapai gunicorn 2>/dev/null || true")

        set_status({
            "state": "complete",
            "message": f"Updated to {info['latest_version']}",
            "new_version": info["latest_version"]
        })

    except Exception as e:
        log.error(f"Update failed: {e}")
        set_status({"state": "error", "message": f"Update failed: {str(e)}"})

if __name__ == "__main__":
    result = check_for_update(force=True)
    print(json.dumps(result, indent=2))
