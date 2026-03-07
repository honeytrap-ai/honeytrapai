#!/usr/bin/env python3
"""
HoneytrapAI — Privileged static IP helper.
Runs as root via sudo. Called by app.py during setup wizard Step 2.
Writes or replaces the HoneytrapAI static IP block in /etc/dhcpcd.conf.
Never called directly by the user.

Usage:
    sudo python3 set_static_ip_helper.py <iface> <ip> <prefix_len> <gateway> <dns>

Example:
    sudo python3 set_static_ip_helper.py eth0 192.168.1.199 24 192.168.1.1 192.168.1.1
"""

import sys

DHCPCD_PATH = "/etc/dhcpcd.conf"
BLOCK_MARKER = "# HoneytrapAI static IP — do not edit this block manually"
BLOCK_END    = "# end HoneytrapAI static IP"


def write_static_ip(iface, ip, prefix_len, gateway, dns):
    # Read existing file
    try:
        with open(DHCPCD_PATH) as f:
            lines = f.readlines()
    except FileNotFoundError:
        lines = []

    # Strip any previous HoneytrapAI block
    new_lines, skip = [], False
    for line in lines:
        if line.strip() == BLOCK_MARKER:
            skip = True
        if not skip:
            new_lines.append(line)
        if skip and line.strip() == BLOCK_END:
            skip = False

    # Append new block
    block = (
        f"\n{BLOCK_MARKER}\n"
        f"interface {iface}\n"
        f"static ip_address={ip}/{prefix_len}\n"
        f"static routers={gateway}\n"
        f"static domain_name_servers={dns}\n"
        f"{BLOCK_END}\n"
    )
    new_lines.append(block)

    with open(DHCPCD_PATH, "w") as f:
        f.writelines(new_lines)


def remove_static_ip():
    """Remove the HoneytrapAI block entirely — used by factory reset."""
    try:
        with open(DHCPCD_PATH) as f:
            lines = f.readlines()
    except FileNotFoundError:
        return

    new_lines, skip = [], False
    for line in lines:
        if line.strip() == BLOCK_MARKER:
            skip = True
        if not skip:
            new_lines.append(line)
        if skip and line.strip() == BLOCK_END:
            skip = False

    with open(DHCPCD_PATH, "w") as f:
        f.writelines(new_lines)


if __name__ == "__main__":
    if len(sys.argv) == 2 and sys.argv[1] == "--remove":
        remove_static_ip()
        sys.exit(0)

    if len(sys.argv) != 6:
        print(f"Usage: {sys.argv[0]} <iface> <ip> <prefix_len> <gateway> <dns>")
        print(f"   or: {sys.argv[0]} --remove")
        sys.exit(1)

    _, iface, ip, prefix_len, gateway, dns = sys.argv
    write_static_ip(iface, ip, prefix_len, gateway, dns)
    sys.exit(0)