#!/usr/bin/env python3
"""
HoneytrapAI — Privileged OTA update worker.
Runs as root via systemd. Called by updater.py via systemctl start.
Handles download, extract, file swap, and service restart.
Never called directly by the Flask app.
"""

import os
import json
import shutil
import tarfile
import logging
import urllib.request
from datetime import datetime

BASE_DIR = "/opt/honeytrapai"
VERSION_PATH = os.path.join(BASE_DIR, "VERSION")
CACHE_PATH = os.path.join(BASE_DIR, "config", "update_cache.json")
STATUS_PATH = os.path.join(BASE_DIR, "config", "update_status.json")
PENDING_PATH = "/tmp/honeytrapai-update-pending"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [updater-worker] %(levelname)s %(message)s",
)
log = logging.getLogger("updater-worker")

# Files and directories to never overwrite during update
PRESERVE = {"config", "config.json", "smtp.json"}


def set_status(status):
    os.makedirs(os.path.dirname(STATUS_PATH), exist_ok=True)
    with open(STATUS_PATH, "w") as f:
        json.dump(status, f, indent=2)


def clear_cache():
    """Delete the update cache so the next check hits GitHub fresh."""
    if os.path.exists(CACHE_PATH):
        try:
            os.remove(CACHE_PATH)
            log.info("Update cache cleared.")
        except Exception as e:
            log.warning("Could not clear update cache: %s", e)


def load_pending():
    """Load the pending update info written by updater.py."""
    try:
        with open(PENDING_PATH) as f:
            return json.load(f)
    except Exception as e:
        log.error("Could not read pending update file: %s", e)
        return None


def get_current_version():
    if os.path.exists(VERSION_PATH):
        with open(VERSION_PATH) as f:
            return f.read().strip()
    return "v0.1.0"


def run():
    log.info("HoneytrapAI update worker starting.")
    set_status({"state": "downloading", "message": "Downloading update..."})

    info = load_pending()
    if not info:
        set_status({"state": "error", "message": "No pending update info found."})
        return

    tarball_url = info.get("tarball_url")
    latest_version = info.get("latest_version")

    if not tarball_url or not latest_version:
        set_status({"state": "error", "message": "Pending update info is incomplete."})
        return

    tmp_tar = "/tmp/honeytrapai-update.tar.gz"
    tmp_dir = "/tmp/honeytrapai-update"

    try:
        # Download — follow redirects (GitHub tarball URLs redirect to S3)
        log.info("Downloading %s", tarball_url)
        req = urllib.request.Request(
            tarball_url,
            headers={
                "Accept": "application/vnd.github.v3+json",
                "User-Agent": f"HoneytrapAI/{get_current_version()}"
            }
        )
        with urllib.request.urlopen(req, timeout=60) as resp:
            with open(tmp_tar, "wb") as f:
                f.write(resp.read())
        log.info("Download complete.")

        # Extract
        set_status({"state": "installing", "message": "Installing update..."})
        if os.path.exists(tmp_dir):
            shutil.rmtree(tmp_dir)
        os.makedirs(tmp_dir)
        with tarfile.open(tmp_tar, "r:gz") as t:
            t.extractall(tmp_dir)

        # Find extracted root dir (GitHub tarballs have a hash prefix dir)
        extracted = [
            d for d in os.listdir(tmp_dir)
            if os.path.isdir(os.path.join(tmp_dir, d))
        ]
        if not extracted:
            raise Exception("Unexpected tarball structure — no subdirectory found.")
        src = os.path.join(tmp_dir, extracted[0])
        log.info("Extracted to %s", src)

        # Swap files — skip preserved user data
        for item in os.listdir(src):
            if item in PRESERVE:
                log.info("Skipping preserved item: %s", item)
                continue
            src_path = os.path.join(src, item)
            dst_path = os.path.join(BASE_DIR, item)
            if os.path.isdir(src_path):
                if os.path.exists(dst_path):
                    shutil.rmtree(dst_path)
                shutil.copytree(src_path, dst_path)
            else:
                shutil.copy2(src_path, dst_path)
            log.info("Copied %s", item)

        # Fix ownership — all files back to honeytrapai user
        os.system(f"chown -R honeytrapai:honeytrapai {BASE_DIR}")

        # Clean up temp files
        os.remove(tmp_tar)
        shutil.rmtree(tmp_dir)
        if os.path.exists(PENDING_PATH):
            os.remove(PENDING_PATH)

        # Clear the update cache so the dashboard doesn't show a stale banner
        clear_cache()

        # Restart services
        set_status({"state": "restarting", "message": "Restarting services..."})
        log.info("Restarting services.")
        os.system("systemctl restart honeytrapai honeytrapai-notifier")

        new_version = get_current_version()
        log.info("Update complete. Now running %s", new_version)
        set_status({
            "state": "complete",
            "message": f"Updated to {new_version}",
            "new_version": new_version
        })

    except Exception as e:
        log.error("Update failed: %s", e)
        set_status({"state": "error", "message": f"Update failed: {str(e)}"})


if __name__ == "__main__":
    run()