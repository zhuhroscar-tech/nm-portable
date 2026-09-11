# nm-portable

[![CI](https://github.com/zhuhroscar-tech/nm-portable/actions/workflows/ci.yml/badge.svg)](https://github.com/zhuhroscar-tech/nm-portable/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/zhuhroscar-tech/nm-portable?include_prereleases&label=release)](https://github.com/zhuhroscar-tech/nm-portable/releases)
![Linux](https://img.shields.io/badge/platform-Linux-111111?logo=linux)

Find and fix NetworkManager `.nmconnection` profiles that are pinned to
specific hardware, so they can be safely copied to a different machine.

## Simple explanation

When you copy a saved Wi-Fi/network setup from one Linux computer to
another — reimaging a laptop, moving to new hardware, restoring from a
backup — the network connection often silently refuses to turn on,
because the saved file is locked to the old machine's unique hardware
ID. This tool scans your saved network profiles, flags anything tied
to specific hardware, and can write out a cleaned-up copy that's safe
to use on the new machine. It never touches your original files or
restarts networking itself — you copy the fixed files over yourself.

## The problem

NetworkManager keyfile connection profiles
(`/etc/NetworkManager/system-connections/*.nmconnection`) routinely embed a
hardware-specific `mac-address=` (and sometimes `cloned-mac-address=`,
`interface-name=`) pin. Copy these files verbatim to different hardware —
reimaging a Raspberry Pi, moving a laptop's config to a desktop, restoring
from a backup onto replacement hardware — and the connection silently never
activates, because NetworkManager refuses to bind a profile pinned to a MAC
address or interface name that doesn't exist on the new host.

Every fix that shows up across a decade of forum posts and Stack Exchange
answers is the same manual workaround: `sed -i 's/<old-mac>/<new-mac>/'
*.nmconnection`, or hand-editing the file and hoping nothing else host-
specific breaks too. Enterprise fleet-provisioning tools exist
(`nm-configurator`) but require pre-known per-host MAC-to-config mappings —
overkill for the common single-machine "just move my config" case, which no
existing tool addresses directly.

## What this does

```
$ nm-portable audit /etc/NetworkManager/system-connections

/etc/NetworkManager/system-connections/eth0.nmconnection
  [warn] ethernet.mac-address: Pinned to hardware MAC 11:22:33:44:55:66 --
         will never match on different hardware. Strip it to make this
         profile portable.
  [info] ipv4.method: Static IP configuration (ipv4) -- verify the
         addresses/gateway still make sense on the destination network
         before reusing this profile.

$ nm-portable fix /etc/NetworkManager/system-connections --out ./portable

/etc/NetworkManager/system-connections/eth0.nmconnection -> ./portable/eth0.nmconnection
  - removed ethernet.mac-address (was: 11:22:33:44:55:66)

1 portable copy(ies) written to ./portable. Review before copying into
/etc/NetworkManager/system-connections/ on the destination machine.
```

Two subcommands:

- **`audit`** — strictly read-only. Reports every field that pins a
  profile to specific hardware (`[warn]`: MAC address, interface name) or
  is worth double-checking before reuse (`[info]`: static IP config,
  plaintext secrets present — secret *values* are never printed).
- **`fix`** — writes portable copies with hardware pins stripped to an
  explicitly given `--out` directory. **Never overwrites the source file**,
  never writes to a live NetworkManager directory automatically, and never
  calls `nmcli`/`systemctl`/D-Bus — it does not reload, apply, or activate
  anything. Static IP configuration is left untouched unless you pass
  `--strip-static-ip`.

## Install

Requires Python 3.9+ (works anywhere, including non-Linux, for the audit
step against exported files — but is only meaningful for NetworkManager
keyfile-format connections, which is Linux-specific).

```bash
pip install nm-portable
```

Or the standalone zipapp:

```bash
curl -LO https://github.com/zhuhroscar-tech/nm-portable/releases/download/v0.1.0/nm-portable.pyz
python3 nm-portable.pyz --version
```

Verify against `SHA256SUMS.txt` in the same release before running it.

## Usage

```bash
# On the OLD machine (or against a backup of its connection files):
sudo nm-portable audit /etc/NetworkManager/system-connections

# Write portable copies (source files untouched):
sudo nm-portable fix /etc/NetworkManager/system-connections --out ~/portable-connections

# Copy ~/portable-connections/*.nmconnection to the NEW machine, then
# manually place them (this tool does not do this step for you):
sudo cp ~/portable-connections/*.nmconnection /etc/NetworkManager/system-connections/
sudo chmod 600 /etc/NetworkManager/system-connections/*.nmconnection
sudo systemctl restart NetworkManager
```

Exit codes: `audit` returns `0` if no portability blockers were found, `1`
if any warning-level blocker was found. `fix` returns `0` on success.

## Uninstall

```bash
pip uninstall nm-portable
```
No config files, no persistent state — a stateless CLI.

## Privacy & permissions

- No network access, no telemetry.
- Reads whatever `.nmconnection` file(s) you point it at (root privileges
  needed only to *read* `/etc/NetworkManager/system-connections/`, which
  NetworkManager restricts to root by default since it may contain
  plaintext Wi-Fi/VPN passwords).
- `audit` never writes anything.
- `fix` only ever writes to the directory you pass via `--out`; written
  files are `chmod 600` since they may still contain plaintext secrets
  copied through unchanged. Secret *values* are never printed to the
  terminal by either subcommand.

## Distro / architecture support

Pure Python (stdlib only, uses `configparser` to parse the GLib key-file
format NetworkManager's keyfile plugin uses). Meaningful on any Linux
distribution using NetworkManager's default keyfile connection storage
(the vast majority); architecture-independent.

## Reproducible build & test

```bash
git clone https://github.com/zhuhroscar-tech/nm-portable
cd nm-portable
python3 -m pip install -e .[dev]
python3 -m pytest -v
```

CI (`.github/workflows/ci.yml`) runs the same suite on real Ubuntu
GitHub Actions runners across Python 3.9 and 3.12, then builds and
smoke-tests both the wheel/sdist and a standalone `.pyz` against a real
sample `.nmconnection` file.

## License

MIT — see [LICENSE](LICENSE).
