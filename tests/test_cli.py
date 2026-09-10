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
    rc = main(["audit", str(tmp_path)])
    assert rc == 0


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
    assert len(parsed) == 1
    assert parsed[0]["changes"]


def test_version_exits_zero(capsys):
    import pytest

    with pytest.raises(SystemExit) as exc_info:
        main(["--version"])
    assert exc_info.value.code == 0
    assert "nm-portable" in capsys.readouterr().out
