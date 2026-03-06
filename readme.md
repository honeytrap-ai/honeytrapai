# 🐝 HoneytrapAI

**Home network security monitor. No cloud. No subscription. No monthly fees. Ever.**

[![License: GPLv3](https://img.shields.io/badge/License-GPLv3-blue.svg)](LICENSE)
[![Follow on X](https://img.shields.io/twitter/follow/HoneytrapAI?style=social)](https://x.com/HoneytrapAI)

---

## Why HoneytrapAI?

| Feature | HoneytrapAI | StingBox Monthly | StingBox Yearly | Firewalla | BitDefender BOX |
|---|---|---|---|---|---|
| **Device price** | ~$99 one-time | $50 device | $50 device | $179–399 | $149 |
| **Monthly cost** | **$0 forever** | $25/month | ~$16.67/month | $0 | $8.25/month |
| **1-year total cost** | **~$99** | ~$350 | ~$250 | $179–399 | ~$248 |
| **2-year total cost** | **~$99** | ~$650 | ~$450 | $179–399 | ~$347 |
| **5-year total cost** | **~$99** | ~$1,550 | ~$1,050 | $179–399 | ~$644 |
| **Works without subscription** | ✅ Forever | ❌ Device useless | ❌ Device useless | ✅ Yes | ❌ No |
| **Works if vendor closes** | ✅ Forever | ❌ Brick | ❌ Brick | ❌ Reduced | ❌ Reduced |
| **Sends data to vendor** | ❌ Never | ✅ Every 5 min | ✅ Every 5 min | ✅ Yes | ✅ Yes |
| **Detection method** | DNS inspection + threat feeds | TCP port scanning only | TCP port scanning only | Traffic analysis | Traffic analysis |
| **Blocks ads & trackers** | ✅ DNS blocking | ❌ No | ❌ No | ✅ Yes | ✅ Yes |
| **Open source** | ✅ GPLv3 | ❌ No | ❌ No | ❌ No | ❌ No |
| **No cloud required** | ✅ Never | ❌ Cloud-dependent | ❌ Cloud-dependent | ❌ Cloud-dependent | ❌ Cloud-dependent |

> *Why pay $1,550 over 5 years when $99 does more — forever?*
>
> *StingBox sends your device hostnames and MAC addresses to their servers every 5 minutes — forever.*
> *HoneytrapAI never sees your data. It never leaves your home.*

---

## Detect. Block. Protect.
### Hackers. Malware. Trackers. Ads.

HoneytrapAI uses DNS-level inspection to block threats before they reach any device on your network — including smart TVs, phones, and IoT devices that can't run their own ad blockers.

---

## How It Works

```
Internet → Modem → Router → [ All your devices ]
                       ↕
               HoneytrapAI (DNS server)

Every device: "Where is evil-c2-server.ru?"
HoneytrapAI:  *checks 1M+ threat feeds*  → BLOCKED.
```

**Setup takes 2 minutes:**
1. Plug HoneytrapAI into any spare router port
2. In your router settings, change the Primary DNS to HoneytrapAI's IP
3. Done — every DNS query on your network is now monitored and filtered

No port mirroring. No inline bridging. No managed switch. One setting.

---

## Features

- **DNS threat blocking** — catches malware, C2 servers, phishing, trackers, and ads before connections are made
- **Maltrail passive sensor** — detects known-bad IPs and traffic patterns
- **Local dashboard** — real-time threat feed, top offenders, severity filtering
- **AdGuard Home integration** — DNS query stats, blocklist management, safe browsing
- **Email alerts** — digest emails for high-severity threats (Gmail, Outlook, Yahoo, iCloud, FastMail, custom SMTP)
- **Auto-updating threat feeds** — pulls from ET Open, Maltrail feeds, AdGuard lists (~1M+ domains)
- **OTA software updates** — one-click updates via GitHub Releases, never auto-installs
- **Backup & restore** — export/import your full configuration
- **Fully local** — zero cloud dependency, works forever regardless of our company's fate
- **Open source** — GPLv3, audit every line, contribute back

---

## Hardware

HoneytrapAI runs on the **Raspberry Pi 4B** (development/Alpha) and the **NanoPi NEO3 Plus** (production).

### Raspberry Pi 4B (Development / Alpha)
| Component | Notes |
|---|---|
| Raspberry Pi 4B (4GB RAM) | Available from many retailers |
| Quality microSD (Samsung/SanDisk Endurance) | 32GB minimum — use Endurance series for 24/7 reliability |
| USB-C power adapter | Official Pi PSU recommended |

### NanoPi NEO3 Plus (Production / Kickstarter)
| Component | Cost |
|---|---|
| NanoPi NEO3 Plus board | $24 |
| 32GB eMMC module | $23 |
| Aluminum case | $8 |
| USB-C power adapter | $6 |
| **Total BOM** | **~$61** |

> The 32GB eMMC is critical for 24/7 reliability in production units — consumer microSD cards fail within months under constant log-write loads. eMMC is designed for embedded use.

---

## Quick Start

### Option A — Flash a pre-built image (recommended for hardware units)
```bash
xzcat honeytrapai-rpi4-v0.1.0-YYYYMMDD.img.xz | sudo dd of=/dev/sdX bs=4M status=progress
```
Visit `http://honeytrap.local` and follow the setup wizard.

### Option B — Install on existing Raspberry Pi OS Lite 64-bit or Debian 12/13
```bash
git clone https://github.com/honeytrap-ai/honeytrapai
cd honeytrapai
sudo bash install.sh
```

### Option C — Dev mode (no hardware needed)
```bash
git clone https://github.com/honeytrap-ai/honeytrapai
cd honeytrapai
pip install flask gunicorn
HONEYTRAPAI_DEV=1 python3 app.py
```
Visit `http://localhost:5000`

---

## Architecture

```
honeytrapai/
├── app.py              # Flask web server — dashboard, API, settings
├── log_parser.py       # Maltrail log parser + severity scoring
├── notifier.py         # Email alert daemon (runs as systemd service)
├── updater.py          # GitHub-based OTA update system
├── smtp_setup.py       # CLI SMTP configuration wizard
├── install.sh          # Single-command installer (Raspberry Pi OS / Debian ARM64)
├── build-image.sh      # Production .img builder (rpi4 and neo3plus targets)
├── requirements.txt    # Python deps (flask, gunicorn, pyyaml)
├── VERSION             # Current version string
└── templates/
    ├── login.html      # Password screen
    ├── setup.html      # First-run wizard (3 steps)
    └── dashboard.html  # Live monitoring dashboard + settings
```

**Software stack:**
- [Maltrail](https://github.com/stamparm/maltrail) — passive traffic sensor and threat intelligence
- [AdGuard Home](https://github.com/AdguardTeam/AdGuardHome) — DNS-level blocking (headless, LAN-only)
- [Flask](https://flask.palletsprojects.com) + [Gunicorn](https://gunicorn.org) — web dashboard
- [nginx](https://nginx.org) — reverse proxy
- [Avahi](https://avahi.org) — mDNS (`honeytrap.local`)
- Raspberry Pi OS Lite 64-bit / Debian 12+ — OS base

---

## Privacy Promise

HoneytrapAI is designed from the ground up to never exfiltrate your data:

- **No check-in calls** — the device never contacts our servers (we don't have any)
- **No telemetry** — zero usage data collected
- **No account required** — no registration, no email, no cloud
- **Threat feeds are pull-only** — the device fetches updates from public sources (GitHub, abuse.ch, ET Open) — your network data never leaves
- **Local dashboard only** — your threat logs exist only on your device
- **AdGuard Home web UI bound to localhost** — never accessible from your LAN
- **Open source** — every line is auditable; we can't hide backdoors

If our company closes tomorrow, your device keeps working forever.

---

## Roadmap

- [x] v0.1 — Core dashboard + Maltrail + AdGuard Home + email alerts + OTA updates
- [ ] v0.2 — Network device inventory (replaces StingBox's main feature)
- [ ] v0.3 — DNS configuration status check + first-run empty state improvements
- [ ] v0.4 — Mobile-friendly PWA dashboard
- [ ] v0.5 — Threat timeline chart (24h sparklines)
- [ ] v0.6 — OpenWrt router agent mode
- [ ] v1.0 — Kickstarter launch (NanoPi NEO3 Plus production hardware)
- [ ] v2.0 — Pro tier: NanoPi R4S inline bridge mode + Suricata IDS

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). PRs welcome — especially hardware compatibility reports and threat feed integrations.

**We will not merge:** cloud dependencies, telemetry, or any feature that sends user data off-device.

---

## License

GPLv3 — see [LICENSE](LICENSE).

---

*HoneytrapAI · [honeytrap.ai](https://honeytrap.ai) · [@HoneytrapAI](https://x.com/HoneytrapAI)*
*No cloud. No subscription. No monthly fees. Ever.*
*🐝 [Join the Pro Club](https://honeytrap.ai/community) — early access, roadmap voting, threat digest, community support*
