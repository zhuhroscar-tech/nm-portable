from pathlib import Path

from nm_portable.core import (
    audit_directory,
    audit_profile,
    make_portable,
    parse_keyfile,
    write_portable_copy,
)


SAMPLE_WIFI = """[connection]
id=HomeWifi
uuid=be1282f3-d98b-3db6-9c1f-0cd80398f4f5
type=wifi
interface-name=wlan0

[wifi]
mode=infrastructure
ssid=HomeWifi
mac-address=AA:BB:CC:DD:EE:FF

[wifi-security]
key-mgmt=wpa-psk
psk=supersecretpassword

[ipv4]
method=auto

[ipv6]
method=auto
"""

SAMPLE_ETHERNET_STATIC = """[connection]
id=WiredStatic
uuid=11111111-2222-3333-4444-555555555555
type=ethernet

[ethernet]
mac-address=11:22:33:44:55:66
cloned-mac-address=AA:AA:AA:AA:AA:AA

[ipv4]
method=manual
address1=192.168.1.50/24,192.168.1.1
dns=8.8.8.8;

[ipv6]
method=auto
"""

SAMPLE_CLEAN = """[connection]
id=CleanProfile
uuid=99999999-8888-7777-6666-555555555555
type=ethernet

[ethernet]

[ipv4]
method=auto

[ipv6]
method=auto
"""


def _write(tmp_path: Path, name: str, content: str) -> Path:
    p = tmp_path / name
    p.write_text(content, encoding="utf-8")
    return p


def test_parse_keyfile_preserves_case(tmp_path):
    p = _write(tmp_path, "a.nmconnection", SAMPLE_WIFI)
    cp = parse_keyfile(p)
    assert cp.get("connection", "id") == "HomeWifi"
    assert cp.get("wifi", "mac-address") == "AA:BB:CC:DD:EE:FF"


def test_audit_detects_wifi_mac_pin(tmp_path):
    p = _write(tmp_path, "wifi.nmconnection", SAMPLE_WIFI)
    report = audit_profile(p)
    assert report.has_portability_blockers
    assert any("mac-address" in f.field and f.level == "warn" for f in report.findings)


def test_audit_detects_interface_name_pin(tmp_path):
    p = _write(tmp_path, "wifi.nmconnection", SAMPLE_WIFI)
    report = audit_profile(p)
    assert any(f.field == "connection.interface-name" for f in report.findings)


def test_audit_detects_both_mac_fields_on_ethernet(tmp_path):
    p = _write(tmp_path, "eth.nmconnection", SAMPLE_ETHERNET_STATIC)
    report = audit_profile(p)
    warn_fields = {f.field for f in report.findings if f.level == "warn"}
    assert "ethernet.mac-address" in warn_fields
    assert "ethernet.cloned-mac-address" in warn_fields


def test_audit_flags_static_ip_as_info_not_warn(tmp_path):
    p = _write(tmp_path, "eth.nmconnection", SAMPLE_ETHERNET_STATIC)
    report = audit_profile(p)
    static_ip_findings = [f for f in report.findings if f.field == "ipv4.method"]
    assert len(static_ip_findings) == 1
    assert static_ip_findings[0].level == "info"


def test_audit_flags_plaintext_secret(tmp_path):
    p = _write(tmp_path, "wifi.nmconnection", SAMPLE_WIFI)
    report = audit_profile(p)
    assert any(f.field == "wifi-security.psk" for f in report.findings)
    # Never print the actual secret value.
    assert not any("supersecretpassword" in f.message for f in report.findings)


def test_audit_clean_profile_has_no_blockers(tmp_path):
    p = _write(tmp_path, "clean.nmconnection", SAMPLE_CLEAN)
    report = audit_profile(p)
    assert not report.has_portability_blockers


def test_audit_directory_finds_all_files(tmp_path):
    _write(tmp_path, "a.nmconnection", SAMPLE_WIFI)
    _write(tmp_path, "b.nmconnection", SAMPLE_ETHERNET_STATIC)
    _write(tmp_path, "not-a-connection.txt", "irrelevant")
    reports = audit_directory(tmp_path)
    assert len(reports) == 2


def test_audit_directory_missing_dir_returns_empty(tmp_path):
    assert audit_directory(tmp_path / "does_not_exist") == []


def test_make_portable_removes_mac_pins(tmp_path):
    p = _write(tmp_path, "eth.nmconnection", SAMPLE_ETHERNET_STATIC)
    text, changes = make_portable(p)
    assert "mac-address" not in text
    assert any("mac-address" in c for c in changes)
    # Original file untouched.
    assert "mac-address" in p.read_text()


def test_make_portable_removes_interface_name(tmp_path):
    p = _write(tmp_path, "wifi.nmconnection", SAMPLE_WIFI)
    text, changes = make_portable(p)
    assert "interface-name" not in text
    assert any("interface-name" in c for c in changes)


def test_make_portable_keeps_static_ip_by_default(tmp_path):
    p = _write(tmp_path, "eth.nmconnection", SAMPLE_ETHERNET_STATIC)
    text, changes = make_portable(p, strip_static_ip=False)
    assert "address1" in text
    assert not any("static" in c.lower() for c in changes)


def test_make_portable_strips_static_ip_when_requested(tmp_path):
    p = _write(tmp_path, "eth.nmconnection", SAMPLE_ETHERNET_STATIC)
    text, changes = make_portable(p, strip_static_ip=True)
    assert "address1" not in text
    assert any("ipv4" in c and "static" in c.lower() for c in changes)


def test_write_portable_copy_creates_output_dir(tmp_path):
    src = _write(tmp_path, "eth.nmconnection", SAMPLE_ETHERNET_STATIC)
    out_dir = tmp_path / "out"
    dest, changes = write_portable_copy(src, out_dir)
    assert dest.exists()
    assert dest.parent == out_dir
    assert changes
    # Source file untouched.
    assert "mac-address" in src.read_text()


def test_write_portable_copy_sets_restrictive_permissions(tmp_path):
    src = _write(tmp_path, "wifi.nmconnection", SAMPLE_WIFI)
    out_dir = tmp_path / "out"
    dest, _ = write_portable_copy(src, out_dir)
    mode = dest.stat().st_mode & 0o777
    assert mode == 0o600
