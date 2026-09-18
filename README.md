[![English](https://img.shields.io/badge/English-555555?style=flat)](README.md) [![简体中文](https://img.shields.io/badge/简体中文-555555?style=flat)](README.zh-CN.md)

# nm-portable

Audit NetworkManager `.nmconnection` files before moving them to another machine, and optionally write copies with hardware-specific fields removed. This is useful when restoring a backup, reimaging a computer, or migrating saved network settings to replacement hardware.

![Example report](docs/images/example-output.png)

## Install

Requires Python 3.9+. Exported files can be inspected on non-Linux systems, but the supported format is NetworkManager's Linux keyfile format. There are no runtime dependencies beyond the Python standard library.

```bash
git clone https://github.com/zhuhroscar-tech/nm-portable.git
cd nm-portable
python3 -m venv .venv
source .venv/bin/activate
python -m pip install .
```

Standalone `.pyz` downloads are also available from [GitHub Releases](https://github.com/zhuhroscar-tech/nm-portable/releases). Verify against that release's `SHA256SUMS.txt` before running one.

## Usage

Use a file or a directory of exported profiles; directory scans are non-recursive:

```bash
nm-portable audit ./connections
nm-portable audit ./connections --json
nm-portable fix ./connections --out ./portable
nm-portable fix ./connections --out ./portable-auto --strip-static-ip
```

`audit` reads only. It reports MAC-address and interface-name pins, flags static IP configuration for review, and notes recognized plaintext-secret fields (Wi-Fi PSK/WEP keys, 802.1x/EAP passwords and PINs, legacy Cisco LEAP credentials, mobile-broadband SIM PIN/PUK codes, and any key under a VPN plugin's `[vpn-secrets]` section) without displaying their values.

`fix` removes supported MAC and interface-name fields, including literal cloned-MAC hardware addresses. A `cloned-mac-address` set to a non-hardware special value (`preserve`, `permanent`, `random`, `stable`, `stable-ssid` per NetworkManager's own settings spec) is left untouched, since it behaves identically on any hardware and is often a deliberate MAC-randomization privacy setting rather than a portability blocker. Static IP settings remain unless `--strip-static-ip` is supplied; that option resets manual IPv4/IPv6 sections to `auto` and removes their other settings. Review the resulting file rather than assuming every removed setting was unwanted.

Audit exits **1** for warning-level findings or unreadable profiles, otherwise **0**. Fix exits **1** if files were unreadable or refused because output would overwrite the source, otherwise **0**. An empty directory is not evidence that any profile was checked.

## Safety and deployment

Choose a separate, non-live output directory. Source paths are protected against direct overwrite, but existing output files can be replaced. Copies retain credentials, and the tool attempts to set mode `600`; check permissions yourself, especially on non-POSIX filesystems. Reading live system profiles usually needs elevated privileges.

No network requests are made. The tool never reloads or activates NetworkManager. Review credentials, addresses, routes, and removed MAC settings before manually deploying selected files with appropriate ownership and permissions. Activating changed networking can disconnect remote sessions.

## Development

```bash
python -m pip install -e '.[dev]'
python -m pytest -v
```

[Demo video](docs/demo.mp4) · [MIT license](LICENSE).
