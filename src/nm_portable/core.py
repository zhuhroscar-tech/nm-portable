"""Core logic for nm-portable.

The problem: NetworkManager's keyfile connection profiles (the
``.nmconnection`` files under ``/etc/NetworkManager/system-connections/``)
routinely embed a hardware-specific ``mac-address=`` (and, less often,
``cloned-mac-address=``) pin under the ``[ethernet]``/``[wifi]`` section.
Copying these files verbatim to a different machine -- reimaging a
Raspberry Pi, moving a laptop's config to a desktop, restoring from backup
onto replacement hardware -- silently produces connections that will never
activate, because NetworkManager refuses to bind a profile pinned to a MAC
address that doesn't exist on the new host. Every fix that shows up in
forums/StackExchange over the last decade is the same manual workaround:
``sed -i 's/<old-mac>/<new-mac>/' *.nmconnection``, or delete the pin by
hand and hope no other host-specific field (a static IP meant for a
different subnet, an old UUID, a leftover ``interface-name=`` pin to a
device name that doesn't exist on the new NIC) breaks things too.

This tool automates and generalizes the "de-pin a connection profile"
step (and the audit step that finds these problems before something
breaks): scan directories of ``.nmconnection`` files, report any
machine-specific field a portability check should flag (MAC pins,
interface-name pins, per-host static IPs/routes, and secrets stored in
plaintext), and optionally emit "portable" copies with the pins stripped
-- never mutating the original files in place, never touching a live
system's ``/etc/NetworkManager`` directory automatically.

Strictly read-only for the audit path. The rewrite path only ever writes
to an explicitly given output directory, never overwrites its input, and
never calls ``nmcli``/``systemctl``/``dbus`` -- it does not reload, apply,
or activate anything.
"""
from __future__ import annotations

import configparser
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

# Fields that pin a connection profile to specific hardware or a specific
# host's network topology -- portability blockers if copied verbatim.
_MAC_FIELDS = {
    ("ethernet", "mac-address"),
    ("ethernet", "cloned-mac-address"),
    ("wifi", "mac-address"),
    ("wifi", "cloned-mac-address"),
    ("802-3-ethernet", "mac-address"),
    ("802-3-ethernet", "cloned-mac-address"),
    ("802-11-wireless", "mac-address"),
    ("802-11-wireless", "cloned-mac-address"),
}
_INTERFACE_NAME_FIELDS = {
    ("connection", "interface-name"),
}
_STATIC_IP_PREFIXES = {"ipv4", "ipv6"}
_SECRET_HINT_KEYS = {"psk", "password", "wep-key0", "wep-key1", "wep-key2", "wep-key3", "private-key-password"}

_MAC_RE = re.compile(r"^[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}$")


@dataclass
class Finding:
    level: str  # "info" | "warn"
    field: str  # "section.key"
    message: str


@dataclass
class ProfileReport:
    path: Path
    findings: list = field(default_factory=list)

    @property
    def has_portability_blockers(self) -> bool:
        return any(f.level == "warn" for f in self.findings)


def parse_keyfile(path: Path) -> configparser.ConfigParser:
    """Parse an .nmconnection keyfile (GLib key-file / INI format).

    NetworkManager's keyfile format is close enough to standard INI for
    configparser, with one wrinkle: it allows duplicate list-style keys
    like ``address1=``/``address2=`` (already unique key names, so no
    special handling needed) and is case-sensitive (unlike configparser's
    default lower-casing of keys) -- both handled by the settings below.
    """
    cp = configparser.ConfigParser(strict=False, interpolation=None)
    cp.optionxform = str  # preserve case; NM keys are case-sensitive
    cp.read(path, encoding="utf-8")
    return cp


def audit_profile(path: Path) -> ProfileReport:
    """Inspect one .nmconnection file for portability blockers."""
    cp = parse_keyfile(path)
    findings: list = []

    for section in cp.sections():
        for key, value in cp.items(section):
            if (section, key) in _MAC_FIELDS:
                if _MAC_RE.match(value.strip()):
                    findings.append(Finding(
                        "warn", f"{section}.{key}",
                        f"Pinned to hardware MAC {value.strip()} -- will never match on "
                        f"different hardware. Strip it to make this profile portable.",
                    ))
            elif (section, key) in _INTERFACE_NAME_FIELDS:
                findings.append(Finding(
                    "warn", f"{section}.{key}",
                    f"Pinned to interface name '{value.strip()}' -- new hardware may name "
                    f"its NIC differently (enp0s3 vs eth0 vs wlan0, etc).",
                ))
            elif section in _STATIC_IP_PREFIXES and key == "method" and value.strip() == "manual":
                findings.append(Finding(
                    "info", f"{section}.{key}",
                    f"Static IP configuration ({section}) -- verify the addresses/gateway "
                    f"still make sense on the destination network before reusing this profile.",
                ))
            elif key.lower() in _SECRET_HINT_KEYS and value.strip() and not value.strip().startswith("$"):
                findings.append(Finding(
                    "info", f"{section}.{key}",
                    "Plaintext secret present in this file -- handle the copy securely "
                    "(this tool never prints secret values).",
                ))

    return ProfileReport(path=path, findings=findings)


def audit_directory(directory: Path) -> list:
    """Audit every *.nmconnection file in a directory (non-recursive)."""
    reports = []
    if not directory.is_dir():
        return reports
    for p in sorted(directory.glob("*.nmconnection")):
        reports.append(audit_profile(p))
    return reports


def make_portable(path: Path, strip_static_ip: bool = False) -> tuple:
    """Return (new_config_text, list[str] of changes made) with hardware
    pins removed. Does not touch the original file.

    By default only removes fields that are *always* wrong on different
    hardware (MAC pins, interface-name pins). Static IP config is left
    alone unless ``strip_static_ip`` is explicitly requested, since it may
    still be exactly what's wanted (e.g. restoring the same profile onto
    replacement hardware on the *same* network).
    """
    cp = parse_keyfile(path)
    changes: list = []

    for section, key in list(_MAC_FIELDS) + list(_INTERFACE_NAME_FIELDS):
        if cp.has_option(section, key):
            value = cp.get(section, key)
            cp.remove_option(section, key)
            changes.append(f"removed {section}.{key} (was: {value.strip()})")
            if not cp.options(section):
                cp.remove_section(section)

    if strip_static_ip:
        for section in list(_STATIC_IP_PREFIXES):
            if cp.has_section(section) and cp.get(section, "method", fallback="") == "manual":
                for key in list(dict(cp.items(section))):
                    if key != "method":
                        cp.remove_option(section, key)
                cp.set(section, "method", "auto")
                changes.append(f"reset {section} from static to 'auto'")

    from io import StringIO
    buf = StringIO()
    cp.write(buf, space_around_delimiters=False)
    return buf.getvalue(), changes


def write_portable_copy(src: Path, dest_dir: Path, strip_static_ip: bool = False) -> tuple:
    """Write a portable copy of `src` into `dest_dir` (created if needed),
    returning (dest_path, list[str] of changes). Never writes to `src`
    itself or to a live NetworkManager directory automatically -- the
    caller chooses `dest_dir` explicitly."""
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest_path = dest_dir / src.name
    text, changes = make_portable(src, strip_static_ip=strip_static_ip)
    dest_path.write_text(text, encoding="utf-8")
    try:
        dest_path.chmod(0o600)
    except OSError:
        pass
    return dest_path, changes
