# Contributing to HoneytrapAI

Thank you for your interest in contributing. HoneytrapAI is a privacy-first, no-subscription home network security appliance. Every contribution should reinforce those values.

---

## Core Principles

Before submitting anything, ensure your contribution aligns with these non-negotiable values:

- **No cloud dependencies** — the device must function fully without any internet connectivity after initial threat feed updates
- **No telemetry** — zero user data may be collected, transmitted, or logged off-device
- **No accounts required** — users should never need to register or authenticate with any external service
- **Threat feeds are pull-only** — the device fetches from public sources; it never pushes user data anywhere

**We will not merge** any PR that adds cloud dependencies, telemetry, off-device data transmission, or account requirements — regardless of how useful the feature might otherwise be.

---

## Ways to Contribute

### 🐛 Bug Reports
Open a GitHub Issue using the **Bug Report** template. Include:
- Your hardware (Raspberry Pi 4B, NanoPi NEO3 Plus, other)
- OS version (`cat /etc/os-release`)
- HoneytrapAI version (`cat /opt/honeytrapai/VERSION`)
- Steps to reproduce
- Expected vs actual behaviour
- Relevant log output (`journalctl -u honeytrapai -n 50`)

### 💡 Feature Requests
Open a GitHub Issue using the **Feature Request** template. Describe:
- The problem you're solving
- Your proposed solution
- Any privacy or cloud dependency implications

### 🔧 Pull Requests
1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Make your changes — keep them focused on one thing
4. Test on real hardware if possible (Pi 4B or NEO3 Plus)
5. Update documentation if your change affects user-facing behaviour
6. Submit a PR with a clear description of what changed and why

### 🖥️ Hardware Compatibility Reports
Tested HoneytrapAI on hardware not listed in the README? Open an Issue with:
- Board name and specs
- OS image used
- install.sh result (success/failure, any errors)
- Any modifications required

These reports are extremely valuable — they help us expand the supported hardware list.

### 🌐 Threat Feed Integrations
Know of a high-quality, publicly available threat feed not currently included? Open a PR that adds it to the AdGuard Home baseline config in `install.sh`. Feed must be:
- Publicly accessible (no authentication)
- Actively maintained
- Compatible with AdGuard Home's filter format

---

## Development Setup

```bash
git clone https://github.com/honeytrap-ai/honeytrapai
cd honeytrapai
pip install flask gunicorn pyyaml
HONEYTRAPAI_DEV=1 python3 app.py
```

Dev mode (`HONEYTRAPAI_DEV=1`) serves sample threat data so you can develop without real hardware. Visit `http://localhost:5000`.

---

## Code Style

- Python: follow PEP 8, use descriptive variable names
- Bash: `set -euo pipefail` at the top of all scripts
- HTML/CSS/JS: keep it self-contained — no external CDN dependencies in production templates
- Comments: explain *why*, not *what*

---

## What We Won't Accept

- Any feature that requires a cloud account or external service
- Telemetry, analytics, or usage tracking of any kind
- Dependencies that phone home (check with `strace` or `tcpdump` if unsure)
- Proprietary or non-open-source dependencies
- Features that degrade privacy in exchange for convenience

---

## Questions?

Open an Issue or reach out via [honeytrap.ai](https://honeytrap.ai).

🐝 *No cloud. No subscription. No monthly fees. Ever.*
