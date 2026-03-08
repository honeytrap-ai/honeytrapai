# HoneytrapAI — log_inject_helper.py
# Version: v0.2.5
# Revised: 2026-03-08
# Rev: 1
#!/usr/bin/env python3
"""
Privileged helper — appends a single log line to the Maltrail log file.
Called via sudo by the honeytrapai service user.
Usage: sudo python3 log_inject_helper.py <log_line>
"""

import sys
import os

LOG_PATH = os.environ.get("MALTRAIL_LOG", "/var/log/maltrail/maltrail.log")

def main():
    if len(sys.argv) < 2:
        print("Usage: log_inject_helper.py <log_line>", file=sys.stderr)
        sys.exit(1)

    line = sys.argv[1]

    # Basic sanity check — must be a non-empty string, no null bytes
    if not line or "\x00" in line:
        print("Invalid log line.", file=sys.stderr)
        sys.exit(1)

    # Ensure it ends with a newline
    if not line.endswith("\n"):
        line += "\n"

    try:
        with open(LOG_PATH, "a") as f:
            f.write(line)
    except Exception as e:
        print(f"Error writing to log: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()