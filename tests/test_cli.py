import json

from nm_portable.cli import main


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


def _write(tmp_path, name, content):
    p = tmp_path / name
    p.write_text(content, encoding="utf-8")
    return p


def test_audit_text_output_reports_blockers(tmp_path, capsys):
    _write(tmp_path, "a.nmconnection", SAMPLE_WIFI)
    rc = main(["audit", str(tmp_path)])
    out = capsys.readouterr().out
    assert rc == 1
    assert "mac-address" in out


def test_audit_json_output(tmp_path, capsys):
    _write(tmp_path, "a.nmconnection", SAMPLE_WIFI)
    rc = main(["audit", str(tmp_path), "--json"])
    out = capsys.readouterr().out
    assert rc == 1
    parsed = json.loads(out)
    assert len(parsed) == 1
    assert parsed[0]["has_portability_blockers"] is True


def test_audit_clean_dir_returns_zero(tmp_path, capsys):
    p = _write(tmp_path, "clean.nmconnection", "[connection]\nid=x\n\n[ipv4]\nmethod=auto\n")
    rc = main(["audit", str(tmp_path)])
    assert rc == 0


def test_audit_unreadable_file_returns_nonzero_not_clean(tmp_path, capsys):
    """CLI-level regression: an unreadable profile must exit non-zero
    (treated as a blocker) and must never print the 'ok, no portability
    blockers' headline for a file that was never actually inspected."""
    p = _write(tmp_path, "a.nmconnection", SAMPLE_WIFI)
    p.chmod(0o000)
    try:
        rc = main(["audit", str(tmp_path)])
    finally:
        p.chmod(0o644)
    out = capsys.readouterr().out
    assert rc == 1
    assert "no portability blockers found" not in out
    assert "could not inspect" in out


def test_audit_unreadable_file_json_reports_readable_false(tmp_path, capsys):
    p = _write(tmp_path, "a.nmconnection", SAMPLE_WIFI)
    p.chmod(0o000)
    try:
        rc = main(["audit", str(tmp_path), "--json"])
    finally:
        p.chmod(0o644)
    out = capsys.readouterr().out
    payload = json.loads(out)
    assert rc == 1
    assert payload[0]["readable"] is False
    assert payload[0]["has_portability_blockers"] is True


def test_fix_unreadable_file_is_skipped_not_silently_empty(tmp_path, capsys):
    """CLI-level regression for the fix path: an unreadable source file
    must be reported as skipped (and the command must exit non-zero),
    never silently produce a portable copy with no changes."""
    p = _write(tmp_path, "a.nmconnection", SAMPLE_WIFI)
    p.chmod(0o000)
    out_dir = tmp_path / "out"
    try:
        rc = main(["fix", str(tmp_path), "--out", str(out_dir)])
    finally:
        p.chmod(0o644)
    out = capsys.readouterr().out
    assert rc == 1
    assert "SKIPPED" in out
    assert not (out_dir / "a.nmconnection").exists()


def test_fix_refuses_to_overwrite_source_text_output(tmp_path, capsys):
    """CLI-level regression for the fix path's safety guard: when --out
    resolves to the same directory as the source, core.write_portable_copy
    raises WouldOverwriteSource. The CLI must report this as REFUSED (not
    SKIPPED, not silently succeed), exit non-zero, and must never write to
    the source file -- this is the guard that stops a natural mistake like
    `nm-portable fix system-connections --out system-connections` from
    clobbering a live NetworkManager profile."""
    src_dir = tmp_path / "profiles"
    src_dir.mkdir()
    p = _write(src_dir, "a.nmconnection", SAMPLE_WIFI)
    original_text = p.read_text()

    rc = main(["fix", str(src_dir), "--out", str(src_dir)])
    out = capsys.readouterr().out

    assert rc == 1
    assert "REFUSED" in out
    assert "SKIPPED" not in out
    assert p.read_text() == original_text


def test_fix_refuses_to_overwrite_source_json_output(tmp_path, capsys):
    """Same guard, JSON mode: the refusal must appear in the 'refused'
    list (not 'written', not 'unreadable'), and the command must still
    exit non-zero so scripted callers can detect it without parsing text."""
    src_dir = tmp_path / "profiles"
    src_dir.mkdir()
    _write(src_dir, "a.nmconnection", SAMPLE_WIFI)

    rc = main(["fix", str(src_dir), "--out", str(src_dir), "--json"])
    out = capsys.readouterr().out
    parsed = json.loads(out)

    assert rc == 1
    assert parsed["written"] == []
    assert parsed["unreadable"] == []
    assert len(parsed["refused"]) == 1
    assert "overwrite" in parsed["refused"][0]["error"]


def test_audit_no_files_found_message(tmp_path, capsys):
    """When --path is an empty directory, audit must say so plainly
    instead of silently printing nothing (a user could otherwise mistake
    an empty result for 'no portability blockers found')."""
    rc = main(["audit", str(tmp_path)])
    out = capsys.readouterr().out
    assert rc == 0
    assert "No .nmconnection files found" in out


def test_fix_writes_portable_copies(tmp_path, capsys):
    _write(tmp_path, "a.nmconnection", SAMPLE_WIFI)
    out_dir = tmp_path / "out"
    rc = main(["fix", str(tmp_path), "--out", str(out_dir)])
    assert rc == 0
    assert (out_dir / "a.nmconnection").exists()
    text = (out_dir / "a.nmconnection").read_text()
    assert "mac-address" not in text


def test_fix_json_output(tmp_path, capsys):
    _write(tmp_path, "a.nmconnection", SAMPLE_WIFI)
    out_dir = tmp_path / "out"
    rc = main(["fix", str(tmp_path), "--out", str(out_dir), "--json"])
    out = capsys.readouterr().out
    assert rc == 0
    parsed = json.loads(out)
    assert len(parsed["written"]) == 1
    assert parsed["written"][0]["changes"]
    assert parsed["unreadable"] == []


def test_version_exits_zero(capsys):
    import pytest

    with pytest.raises(SystemExit) as exc_info:
        main(["--version"])
    assert exc_info.value.code == 0
    assert "nm-portable" in capsys.readouterr().out


def test_audit_single_file_path_not_directory(tmp_path, capsys):
    """_collect_paths must accept a single file path, not just a directory."""
    f = _write(tmp_path, "solo.nmconnection", SAMPLE_WIFI)
    rc = main(["audit", str(f)])
    out = capsys.readouterr().out
    assert rc == 1
    assert str(f) in out
    assert "mac-address" in out


def test_audit_clean_profile_prints_ok_headline(tmp_path, capsys):
    """A profile with zero findings must hit the 'no portability blockers' branch."""
    clean = """[connection]
id=CleanProfile
uuid=be1282f3-d98b-3db6-9c1f-0cd80398f4f6
type=wifi

[wifi]
mode=infrastructure
ssid=CleanWifi

[ipv4]
method=auto

[ipv6]
method=auto
"""
    _write(tmp_path, "clean.nmconnection", clean)
    rc = main(["audit", str(tmp_path)])
    out = capsys.readouterr().out
    assert rc == 0
    assert "no portability blockers found" in out


def test_fix_empty_dir_reports_no_files_found(tmp_path, capsys):
    """fix on a directory with no .nmconnection files must hit the empty-results branch."""
    out_dir = tmp_path / "out"
    rc = main(["fix", str(tmp_path), "--out", str(out_dir)])
    out = capsys.readouterr().out
    assert rc == 0
    assert "No .nmconnection files found" in out


def test_fix_no_changes_needed_text_branch(tmp_path, capsys):
    """A profile needing zero changes must print the '(no changes needed)' line."""
    clean = """[connection]
id=CleanProfile
uuid=be1282f3-d98b-3db6-9c1f-0cd80398f4f6
type=wifi

[wifi]
mode=infrastructure
ssid=CleanWifi

[ipv4]
method=auto

[ipv6]
method=auto
"""
    _write(tmp_path, "clean.nmconnection", clean)
    out_dir = tmp_path / "out"
    rc = main(["fix", str(tmp_path), "--out", str(out_dir)])
    out = capsys.readouterr().out
    assert rc == 0
    assert "(no changes needed)" in out
