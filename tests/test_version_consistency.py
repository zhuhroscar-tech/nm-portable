"""Guard against pyproject.toml / __init__.py version-string drift.

This exact drift class (pyproject.toml bumped but the package's own
__version__ -- what --version actually reads -- left stale) has bitten
this fleet twice before (reboot-safety-check and usbsmart-doctor both
shipped a release where `--version` printed the old number). A plain
regex parse is used instead of tomllib so this keeps working on Python
3.9 (tomllib is 3.11+ only, and importing it broke CI once already).
"""
from __future__ import annotations

import re
from pathlib import Path

from nm_portable import __version__

_ROOT = Path(__file__).resolve().parent.parent


def _pyproject_version() -> str:
    text = (_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    m = re.search(r'^version\s*=\s*"([^"]+)"', text, re.MULTILINE)
    assert m, "could not find version = \"...\" in pyproject.toml"
    return m.group(1)


def test_init_version_matches_pyproject():
    assert __version__ == _pyproject_version()
