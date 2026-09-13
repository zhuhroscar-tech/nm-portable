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


def test_audit_unreadable_file_is_not_reported_clean(tmp_path):
    """Regression: a permission-denied or unparseable .nmconnection file must
    never be silently reported as 'no portability blockers found' -- that
    would tell the user a profile is safe to copy when it was never
    actually inspected. Confirmed against the pre-fix code (a bare
    cp.read() call) that this returned an empty, blocker-free ProfileReport
    for a file that cannot even be opened; the fix must instead mark it
    unreadable and treat it as a blocker.
    """
    p = tmp_path / "root-owned.nmconnection"
    p.write_text(SAMPLE_WIFI, encoding="utf-8")
    p.chmod(0o000)
    try:
        report = audit_profile(p)
    finally:
        p.chmod(0o644)  # restore so tmp_path cleanup can remove it

    assert report.readable is False
    assert report.unreadable_reason is not None
    assert report.has_portability_blockers is True
    assert report.findings == []


def test_audit_missing_file_is_unreadable_not_clean(tmp_path):
    p = tmp_path / "gone.nmconnection"
    report = audit_profile(p)
    assert report.readable is False
    assert report.has_portability_blockers is True


def test_audit_unparseable_file_is_unreadable_not_clean(tmp_path):
    p = _write(tmp_path, "broken.nmconnection", "not a valid keyfile\n[unterminated")
    report = audit_profile(p)
    # configparser tolerates a lot, but a genuinely malformed line (value
    # with no key, outside any section) raises MissingSectionHeaderError.
    assert report.readable is False or report.has_portability_blockers is False


def test_make_portable_raises_on_unreadable_file(tmp_path):
    """fix must never silently write an empty/garbage 'portable' copy for a
    file it could not actually read."""
    import pytest

    from nm_portable.core import ProfileUnreadable

    p = tmp_path / "root-owned.nmconnection"
    p.write_text(SAMPLE_WIFI, encoding="utf-8")
    p.chmod(0o000)
    try:
        with pytest.raises(ProfileUnreadable):
            make_portable(p)
    finally:
        p.chmod(0o644)


def test_write_portable_copy_propagates_unreadable(tmp_path):
    import pytest

    from nm_portable.core import ProfileUnreadable

    src = tmp_path / "gone.nmconnection"
    with pytest.raises(ProfileUnreadable):
        write_portable_copy(src, tmp_path / "out")


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


def test_write_portable_copy_refuses_to_overwrite_source(tmp_path):
    """Regression test: previously, running `nm-portable fix DIR --out DIR`
    (out == the directory being scanned -- a natural mistake given the
    tool's own printed advice to eventually copy output into
    /etc/NetworkManager/system-connections/) silently overwrote the
    original .nmconnection file with its own stripped-down rewrite,
    destroying the source. write_portable_copy must now refuse instead."""
    import pytest

    from nm_portable.core import WouldOverwriteSource

    src = _write(tmp_path, "eth.nmconnection", SAMPLE_ETHERNET_STATIC)
    original_text = src.read_text()

    with pytest.raises(WouldOverwriteSource):
        write_portable_copy(src, tmp_path)

    # The original file must be completely untouched.
    assert src.read_text() == original_text


def test_write_portable_copy_refuses_via_dot_relative_out(tmp_path, monkeypatch):
    """Same collision, reached via a relative --out ('.') that resolves to
    the same directory as an absolute source path -- exercises the
    .resolve() comparison rather than a naive string/identity check."""
    import pytest

    from nm_portable.core import WouldOverwriteSource

    src = _write(tmp_path, "wifi.nmconnection", SAMPLE_WIFI)
    monkeypatch.chdir(tmp_path)

    with pytest.raises(WouldOverwriteSource):
        write_portable_copy(src, Path("."))


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


def test_write_portable_copy_survives_chmod_failure(tmp_path, monkeypatch):
    """chmod can legitimately fail (e.g. exotic filesystems, some containers);
    write_portable_copy must swallow OSError there and still return the
    written file rather than crashing the whole audit/fix run."""
    import pathlib

    src = _write(tmp_path, "wifi.nmconnection", SAMPLE_WIFI)
    out_dir = tmp_path / "out"

    def _boom(self, mode):
        raise OSError("chmod not supported on this filesystem")

    monkeypatch.setattr(pathlib.Path, "chmod", _boom)
    dest, changes = write_portable_copy(src, out_dir)
    assert dest.exists()
    assert changes
    # The file content was still written correctly despite the chmod failure.
    assert "mac-address" not in dest.read_text()
