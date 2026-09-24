"""Repository-level contracts for source completeness and release hygiene."""
from __future__ import annotations

import re
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent


def _read(relative: str) -> str:
    return (_ROOT / relative).read_text(encoding="utf-8")


def _current_version() -> str:
    text = _read("pyproject.toml")
    match = re.search(r'^version\s*=\s*"([^"]+)"', text, re.MULTILINE)
    assert match, "pyproject.toml must declare project.version"
    return match.group(1)


def test_required_repository_files_exist():
    required = [
        "README.md",
        "README.zh-CN.md",
        "CHANGELOG.md",
        "LICENSE",
        "pyproject.toml",
        ".github/workflows/ci.yml",
        ".github/workflows/codeql.yml",
    ]
    missing = [path for path in required if not (_ROOT / path).is_file()]
    assert not missing


def test_readmes_link_release_history_license_and_downloads():
    for path in ["README.md", "README.zh-CN.md"]:
        text = _read(path)
        assert "CHANGELOG.md" in text
        assert "LICENSE" in text
        assert "https://github.com/zhuhroscar-tech/nm-portable/releases" in text
        assert "SHA256SUMS.txt" in text


def test_changelog_documents_current_release():
    version = _current_version()
    changelog = _read("CHANGELOG.md")
    assert f"## v{version}" in changelog
    assert "release-history documentation" in changelog


def test_ci_and_codeql_cover_mainline_quality_gates():
    ci = _read(".github/workflows/ci.yml")
    codeql = _read(".github/workflows/codeql.yml")
    assert "python -m pytest" in ci
    assert "python -m build" in ci
    assert "zipapp" in ci
    assert "SHA256SUMS.txt" in ci
    assert "github/codeql-action/analyze" in codeql


def test_release_artifact_contract_is_documented_in_ci_and_readme():
    ci = _read(".github/workflows/ci.yml")
    readme = _read("README.md")
    for artifact in ["nm-portable.pyz", "SHA256SUMS.txt"]:
        assert artifact in ci
        assert artifact in readme
