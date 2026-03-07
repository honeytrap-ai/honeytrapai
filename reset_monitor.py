#!/usr/bin/env python3
"""
HoneytrapAI — USB factory reset monitor.

Runs at boot (after filesystem mounts). Scans all mounted block devices for a
file named 'honeytrap-reset.txt'. If found:
  1. Deletes the trigger file from the USB drive (so it doesn't loop)
  2. Calls the shared _perform_factory_reset() logic from app.py
  3. Reboots the appliance

Designed to be run once at boot via systemd, not as a persistent daemon.
"""

import os
import sys
import glob
import time
import logging
import subprocess

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [reset-monitor] %(levelname)s %(message)s",
)
log = logging.getLogger("reset-monitor")

TRIGGER_FILENAME = "honeytrap-reset.txt"

# Mount point search paths — covers typical Linux USB automount locations
SEARCH_PATHS = [
    "/media",
    "/mnt",
    "/run/media",
]


def find_trigger_file():
    """Return the full path to the trigger file if found on any mounted volume, else None."""
    for base in SEARCH_PATHS:
        if not os.path.isdir(base):
            continue
        # Walk up to two levels deep (e.g. /media/pi/USBDRIVE/honeytrap-reset.txt)
        for match in glob.glob(os.path.join(base, "**", TRIGGER_FILENAME), recursive=True):
            return match
    return None


def perform_reset(trigger_path):
    """Delete trigger file, run reset logic, reboot."""
    log.info("Trigger file found: %s — initiating factory reset.", trigger_path)

    # Delete trigger file first so a reboot loop can't happen
    try:
        os.remove(trigger_path)
        log.info("Trigger file deleted.")
    except OSError as e:
        log.warning("Could not delete trigger file: %s", e)

    # Import and call the shared reset function from app.py
    # app.py lives in the same directory as this script
    script_dir = os.path.dirname(os.path.abspath(__file__))
    sys.path.insert(0, script_dir)
    try:
        from app import _perform_factory_reset
        _perform_factory_reset()
        log.info("Factory reset complete. Rebooting in 3 seconds…")
    except Exception as e:
        log.error("Reset function raised an exception: %s", e)
        log.error("Aborting reset to avoid partial state.")
        return

    time.sleep(3)
    subprocess.run(["sudo", "reboot"], check=False)


def main():
    log.info("HoneytrapAI USB reset monitor starting.")

    # Give USB automount a moment to settle (systemd After= handles most of this,
    # but a small sleep is cheap insurance on slow cards)
    time.sleep(5)

    trigger = find_trigger_file()
    if trigger:
        perform_reset(trigger)
    else:
        log.info("No reset trigger found. Nothing to do.")


if __name__ == "__main__":
    main()