# HoneytrapAI — Third-Party Notices

This file contains attribution notices for third-party software components
that HoneytrapAI depends on or interacts with at runtime. These components
are not included in this repository and are licensed separately from
HoneytrapAI. See `LICENSE` for the terms governing HoneytrapAI's own source
code, `IMAGE-LICENSE` for the terms governing the appliance image, and
`DISTRIBUTION.md` for a plain-language summary of all distribution terms.

---

## Maltrail

- **Project:** Maltrail — Malicious Traffic Detection System
- **Homepage:** https://github.com/stamparm/maltrail
- **Copyright:** Copyright (c) 2014-2026 Maltrail developers
- **License:** MIT License
- **License text:** https://github.com/stamparm/maltrail/blob/master/LICENSE
- **Distributed in appliance image:** Yes — pre-installed
- **Usage:** HoneytrapAI installs and invokes Maltrail as an independent system
  process via systemd. No Maltrail source code is included in this repository.
  HoneytrapAI reads Maltrail's log output to detect and display threat events.
- **Note:** The MIT License permits use, copying, modification, and distribution
  with no copyleft restrictions, provided the above copyright notice is retained
  in all copies or substantial portions of the software.

---

## AdGuard Home

- **Project:** AdGuard Home — Network-wide ad and tracker blocking DNS server
- **Homepage:** https://github.com/AdguardTeam/AdGuardHome
- **Copyright:** Copyright (c) AdGuard Software Ltd. and contributors
- **License:** GNU General Public License v3.0 (GPL-3.0)
- **License text:** https://www.gnu.org/licenses/gpl-3.0.html
- **Distributed in appliance image:** No — downloaded at first run
- **Usage:** AdGuard Home is intentionally excluded from the shipped appliance
  image. It is downloaded directly from AdGuard's official GitHub repository
  during the first-run setup wizard (Step 0), where the user accepts its
  GPL-3.0 license terms before installation. HoneytrapAI communicates with
  AdGuard Home solely via its local HTTP API as an independent process to
  retrieve DNS statistics for display purposes. No AdGuard Home source code
  or binaries are included in this repository.
- **Note:** The AdGuard End-User License Agreement (adguard.com/en/eula.html)
  governs AdGuard's separate commercial products (Ad Blocker, VPN, etc.) and
  does not apply to AdGuard Home, which is free and open-source software.

---

## Linux Kernel / Raspberry Pi OS

- **Project:** Linux Kernel
- **Homepage:** https://kernel.org
- **Copyright:** Copyright (c) Linus Torvalds and contributors
- **License:** GNU General Public License v2.0 (GPL-2.0) with Linux Syscall Note
- **License text:** https://www.kernel.org/doc/html/latest/process/license-rules.html
- **Distributed in appliance image:** Yes — system component
- **Usage:** HoneytrapAI runs as a user-space application on Linux. It does not
  incorporate, link against, or modify kernel code. The Linux Syscall Note
  explicitly permits user-space applications to invoke kernel system calls
  without incurring GPL copyleft obligations.

- **Project:** Raspberry Pi OS (Debian-based)
- **Homepage:** https://www.raspberrypi.com/software/
- **Copyright:** Copyright (c) Raspberry Pi Ltd and Debian project contributors
- **License:** Various — see individual package licenses via `dpkg-query --show`
- **Distributed in appliance image:** Yes — base OS
- **Usage:** HoneytrapAI targets Raspberry Pi OS Lite 64-bit as its primary
  supported platform. No Raspberry Pi OS source code is included in this
  repository.

---

## Python

- **Project:** Python
- **Homepage:** https://www.python.org
- **Copyright:** Copyright (c) Python Software Foundation and contributors
- **License:** Python Software Foundation License v2 (PSF-2.0)
- **License text:** https://docs.python.org/3/license.html
- **Distributed in appliance image:** Yes — system component
- **Usage:** HoneytrapAI is written in Python 3 and uses the Python standard
  library. No Python source code is included in this repository.

---

## Python Dependencies

The following packages are installed via pip at setup time and are not
included in this repository:

| Package   | Copyright | License      | Homepage                             |
|-----------|-----------|--------------|--------------------------------------|
| Flask     | Pallets   | BSD-3-Clause | https://flask.palletsprojects.com    |
| Werkzeug  | Pallets   | BSD-3-Clause | https://werkzeug.palletsprojects.com |
| Jinja2    | Pallets   | BSD-3-Clause | https://jinja.palletsprojects.com    |
| requests  | Kenneth Reitz | Apache-2.0 | https://requests.readthedocs.io    |

---

*HoneytrapAI · honeytrap.ai · Copyright (c) 2026 Anthony Watts / HoneytrapAI*