# HoneytrapAI — Distribution Policy

This document describes what you can and cannot distribute, and under
what conditions. It covers both the HoneytrapAI source code and the
pre-built appliance image.

---

## Source Code

The HoneytrapAI source code is hosted at:
https://github.com/honeytrap-ai/honeytrapai

It is licensed under the **HoneytrapAI Source Available License v1.0**
(see `LICENSE`). In summary:

| What | Permitted |
|------|-----------|
| Personal and home use | ✅ Yes |
| Self-hosting on your own hardware | ✅ Yes |
| Contributing to the official repository | ✅ Yes |
| Forking for personal, non-commercial use | ✅ Yes |
| Selling the software | ❌ No |
| Bundling into a paid product or service | ❌ No |
| Offering as a hosted or cloud service | ❌ No |
| Redistributing modified versions commercially | ❌ No |

For the full terms see `LICENSE` in this repository.

---

## Appliance Image

The pre-built HoneytrapAI appliance disk image is licensed under the
**HoneytrapAI Appliance Image License v1.0** (see `IMAGE-LICENSE`).

| What | Permitted |
|------|-----------|
| Flashing to your own device for personal use | ✅ Yes |
| Making a personal backup copy | ✅ Yes |
| Redistributing the image to third parties | ❌ No |
| Publishing or mirroring the image publicly | ❌ No |
| Bundling into another product or distribution | ❌ No |
| Commercial use of the image in any form | ❌ No |

---

## Third-Party Components

The HoneytrapAI source code and appliance image depend on or interact
with third-party software components that are licensed separately.
These components are **not covered** by the HoneytrapAI licenses.

See `NOTICE.md` for the full list of third-party components, their
copyright holders, and their license terms.

Key components:

| Component | License | Distributed in image |
|-----------|---------|----------------------|
| Maltrail | MIT | ✅ Pre-installed |
| AdGuard Home | GPL-3.0 | ❌ Downloaded at first run |
| Linux kernel / Raspberry Pi OS | GPL-2.0 + Syscall Note | ✅ System |
| Python | PSF-2.0 | ✅ System |
| Flask, Werkzeug, Jinja2 | BSD-3-Clause | ✅ Installed by setup |
| requests | Apache-2.0 | ✅ Installed by setup |

AdGuard Home is intentionally excluded from the shipped image and is
downloaded directly from AdGuard's official GitHub repository during
the first-run setup wizard, where the user accepts its GPL-3.0 license
terms before installation.

---

## Commercial Licensing

If you are interested in:

- Commercial redistribution of the software or image
- OEM or volume deployment
- White-label or embedded appliance use
- Hosted or cloud service deployment

Please contact us to discuss commercial licensing terms:

**support@honeytrap.ai**

---

## Contributing

Contributions to the HoneytrapAI repository are welcome. By submitting
a pull request or patch, you agree that your contribution is assigned
to Anthony Watts / HoneytrapAI and may be used, modified, and
relicensed under any terms the copyright holder chooses. See `LICENSE`
Section 2c for the full contributor terms.

---

*HoneytrapAI · honeytrap.ai · No cloud. No subscription. No monthly fees. Ever.*