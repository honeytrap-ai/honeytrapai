# Security Policy

## Supported Versions

| Version | Supported |
|---|---|
| v0.1.x (current) | ✅ Yes |
| Earlier | ❌ No |

---

## Reporting a Vulnerability

**Please do not report security vulnerabilities via public GitHub Issues.**

If you discover a security vulnerability in HoneytrapAI, please report it responsibly:

**Email:** security@honeytrap.ai
**Subject line:** `[SECURITY] Brief description`

Please include:
- A description of the vulnerability
- Steps to reproduce
- Potential impact assessment
- Any suggested remediation (optional but appreciated)

You will receive an acknowledgement within 48 hours. We aim to resolve confirmed vulnerabilities within 14 days and will credit reporters in the release notes unless you prefer anonymity.

---

## Security Architecture

HoneytrapAI is designed with a minimal attack surface:

**Network exposure:**
- Port 80 (nginx → gunicorn, LAN only) — dashboard
- Port 53 (AdGuard Home) — DNS, required for core function
- No ports exposed to the internet by default
- AdGuard Home web UI bound to `127.0.0.1:3000` — not reachable from LAN

**Authentication:**
- Dashboard protected by password (bcrypt-equivalent salted SHA-256)
- Sessions expire after 30 days
- No default credentials — setup wizard enforces password creation

**Data handling:**
- All threat logs stored locally on-device only
- No data transmitted off-device except pull-only threat feed updates
- Config files stored at `/opt/honeytrapai/config/` with 600 permissions
- SMTP credentials stored at `config/smtp.json` with 600 permissions

**Update security:**
- OTA updates fetched from GitHub Releases over HTTPS
- SHA-256 checksums provided for all release images
- Updates never install automatically — user confirmation required

---

## Known Limitations

- The dashboard runs over HTTP (port 80) by default. HTTPS with a self-signed certificate is on the v0.3 roadmap. Until then, treat the dashboard as LAN-only and do not expose port 80 to the internet.
- The device runs as a non-root service user (`honeytrapai`) for the dashboard and notifier. Maltrail sensor and AdGuard Home require root for raw packet capture and port 53 binding respectively.

---

## Scope

In-scope for security reports:
- Authentication bypass
- Remote code execution
- Privilege escalation
- Data exfiltration vulnerabilities
- Dependency vulnerabilities with exploitable impact

Out of scope:
- Attacks requiring physical access to the device
- Denial of service against the local dashboard
- Issues in upstream dependencies (Maltrail, AdGuard Home) — report those to their respective projects

---

*HoneytrapAI · [honeytrap.ai](https://honeytrap.ai)*
*No cloud. No subscription. No monthly fees. Ever.*
