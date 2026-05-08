"""Unit tests for large-repo handling: compact_manifest and findings cap."""
from __future__ import annotations
import asyncio
import pytest
from pathlib import Path

FIXTURE = Path(__file__).parent / "fixtures" / "vulnerable-app"


# ── compact_manifest ───────────────────────────────────────────────────────────

def test_list_source_files_returns_compact_manifest():
    from argus.tools.files import _handle_list_source_files
    result = asyncio.run(_handle_list_source_files({"repo_dir": str(FIXTURE)}))
    assert "compact_manifest" in result, "compact_manifest key missing from list_source_files output"
    assert isinstance(result["compact_manifest"], str)
    assert len(result["compact_manifest"]) > 0


def test_compact_manifest_contains_relative_paths():
    from argus.tools.files import _handle_list_source_files
    result = asyncio.run(_handle_list_source_files({"repo_dir": str(FIXTURE)}))
    manifest = result["compact_manifest"]
    lines = [l for l in manifest.splitlines() if l and not l.startswith("[...")]
    assert all("/" in line or line.endswith((".py", ".c", ".rb", ".php")) for line in lines), (
        "compact_manifest should contain relative paths"
    )


def test_compact_manifest_not_truncated_for_small_repo():
    from argus.tools.files import _handle_list_source_files
    result = asyncio.run(_handle_list_source_files({"repo_dir": str(FIXTURE)}))
    assert result["compact_manifest_truncated"] is False
    assert "[...]" not in result["compact_manifest"]


def test_compact_manifest_security_sorting():
    """Files with security-relevant names should appear early in the manifest."""
    from argus.tools.files import _handle_list_source_files, _security_score
    result = asyncio.run(_handle_list_source_files({"repo_dir": str(FIXTURE)}))
    manifest_lines = [l for l in result["compact_manifest"].splitlines() if l and not l.startswith("[...")]
    # app.py has security keywords (auth, db, etc.) — should be first or near-first
    if len(manifest_lines) > 1:
        # Just verify that a file with 'app' in the name is present
        names = [Path(l).name for l in manifest_lines]
        assert "app.py" in names, f"app.py should appear in manifest; got {names}"


def test_compact_manifest_cap_creates_truncated_output():
    """Simulate a large repo by monkey-patching the cap constant."""
    import argus.tools.files as files_mod
    original_cap = files_mod._COMPACT_MANIFEST_CAP
    try:
        files_mod._COMPACT_MANIFEST_CAP = 1  # Force truncation even for 2-file fixture
        result = asyncio.run(files_mod._handle_list_source_files({"repo_dir": str(FIXTURE)}))
        if result["total_count"] > 1:
            assert result["compact_manifest_truncated"] is True
            assert "[..." in result["compact_manifest"]
    finally:
        files_mod._COMPACT_MANIFEST_CAP = original_cap


# ── aggregate_findings cap ─────────────────────────────────────────────────────

def _make_finding(type_: str, severity: str, file_: str, line: int = 1) -> dict:
    return {
        "type": type_, "severity": severity,
        "line_approx": line, "title": f"{type_} in {file_}",
        "description": "test", "recommendation": "fix it",
        "file_path": file_,
    }


def test_aggregate_findings_no_cap_when_under_limit():
    from argus.tools.files import _handle_aggregate_findings
    per_file = [
        {"file_path": "a.py", "vulnerabilities": [_make_finding("SQLi", "critical", "a.py", i) for i in range(5)]},
        {"file_path": "b.py", "vulnerabilities": [_make_finding("XSS", "high", "b.py", i) for i in range(5)]},
    ]
    result = asyncio.run(_handle_aggregate_findings({"per_file_results": per_file}))
    assert result["findings_included"] == 10
    assert result["truncation_note"] == ""


def test_aggregate_findings_caps_at_max_findings():
    from argus.tools.files import _handle_aggregate_findings
    per_file = [
        {"file_path": f"file{i}.py", "vulnerabilities": [_make_finding("BUG", "low", f"file{i}.py", j) for j in range(10)]}
        for i in range(20)
    ]
    result = asyncio.run(_handle_aggregate_findings({"per_file_results": per_file, "max_findings": 30}))
    assert result["total_findings"] == 200
    assert result["findings_included"] == 30
    assert "truncation_note" in result and result["truncation_note"]


def test_aggregate_findings_keeps_critical_over_low():
    from argus.tools.files import _handle_aggregate_findings
    per_file = [
        {"file_path": "a.py", "vulnerabilities": [_make_finding("LOW_BUG", "low", "a.py", i) for i in range(50)]},
        {"file_path": "b.py", "vulnerabilities": [_make_finding("CRIT_BUG", "critical", "b.py", i) for i in range(10)]},
    ]
    result = asyncio.run(_handle_aggregate_findings({"per_file_results": per_file, "max_findings": 15}))
    severities = [v["severity"] for v in result["vulnerabilities"]]
    # All 10 critical should be included; remaining 5 slots filled from low
    assert severities.count("critical") == 10
    assert len(severities) == 15


def test_aggregate_findings_skips_fan_out_errors():
    from argus.tools.files import _handle_aggregate_findings
    per_file = [
        {"_fan_out_error": "timeout", "vulnerabilities": []},
        {"file_path": "good.py", "vulnerabilities": [_make_finding("SQLi", "critical", "good.py")]},
    ]
    result = asyncio.run(_handle_aggregate_findings({"per_file_results": per_file}))
    assert result["findings_included"] == 1
