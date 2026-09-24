"""Regression coverage for current Python packaging metadata.

Setuptools 77+ warns on the old table-style license metadata and the
legacy MIT classifier. Keep the project metadata on the SPDX path so
sdist/wheel builds stay warning-free.
"""
from __future__ import annotations

import re
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_PYPROJECT = _ROOT / "pyproject.toml"


def _pyproject_text() -> str:
    return _PYPROJECT.read_text(encoding="utf-8")


def test_project_uses_spdx_license_string():
    text = _pyproject_text()
    assert 'license = "MIT"' in text
    assert "license = {" not in text


def test_license_file_is_declared():
    text = _pyproject_text()
    assert re.search(r'^license-files\s*=\s*\["LICENSE"\]', text, re.MULTILINE)


def test_deprecated_license_classifier_is_absent():
    assert "License :: OSI Approved :: MIT License" not in _pyproject_text()


def test_setuptools_floor_supports_spdx_license_metadata():
    text = _pyproject_text()
    assert '"setuptools>=77"' in text
