"""Unit tests for ISO 25010 scan profile: scanner, workflow loading, and CLI flag."""
from __future__ import annotations
import asyncio
from pathlib import Path

import pytest

WORKFLOWS_DIR = Path(__file__).parent.parent / "workflows"


# ── run_iso_scanners tool ──────────────────────────────────────────────────────

def test_run_iso_scanners_missing_dir():
    from argus.tools.scanners import _handle_run_iso_scanners
    result = asyncio.run(_handle_run_iso_scanners({"repo_dir": "/nonexistent/path"}))
    assert "error" in result


def test_run_iso_scanners_valid_dir(tmp_path):
    from argus.tools.scanners import _handle_run_iso_scanners
    (tmp_path / "sample.py").write_text("def f(): pass\n")
    result = asyncio.run(_handle_run_iso_scanners({"repo_dir": str(tmp_path)}))
    assert "complexity_scan" in result
    assert isinstance(result["complexity_scan"], str)


def test_run_iso_scanners_graceful_without_lizard(tmp_path, monkeypatch):
    import shutil as _shutil
    original_which = _shutil.which

    def patched_which(name, *args, **kwargs):
        if name == "lizard":
            return None
        return original_which(name, *args, **kwargs)

    monkeypatch.setattr(_shutil, "which", patched_which)

    # Re-import the module to pick up the patched shutil
    from argus.tools import scanners
    result = asyncio.run(scanners._handle_run_iso_scanners({"repo_dir": str(tmp_path)}))
    assert "complexity_scan" in result
    assert "not_installed" in result["complexity_scan"]


# ── iso25010-scan.yaml workflow structure ─────────────────────────────────────

def test_iso25010_workflow_file_exists():
    wf = WORKFLOWS_DIR / "iso25010-scan.yaml"
    assert wf.exists(), "iso25010-scan.yaml not found in workflows/"


def test_iso25010_workflow_loads():
    from armature.spec.loader import load_spec
    wf = WORKFLOWS_DIR / "iso25010-scan.yaml"
    spec = load_spec(wf)
    assert spec is not None


def test_iso25010_workflow_has_required_stages():
    import yaml
    wf = WORKFLOWS_DIR / "iso25010-scan.yaml"
    raw = yaml.safe_load(wf.read_text())
    stage_ids = {s["id"] for s in raw["stages"]}
    required = {
        "clone_repo", "list_source_files", "triage_files", "run_iso_scanners",
        "analyze_file", "aggregate_code_findings", "compress_iso_scanners",
        "synthesize_findings", "prioritize_tasks", "validate_findings",
        "generate_report", "cleanup",
    }
    missing = required - stage_ids
    assert not missing, f"Missing stages: {missing}"


def test_iso25010_workflow_has_iso25010_name():
    import yaml
    wf = WORKFLOWS_DIR / "iso25010-scan.yaml"
    raw = yaml.safe_load(wf.read_text())
    assert "iso25010" in raw.get("name", "").lower()


def test_iso25010_synthesize_schema_has_by_characteristic():
    """synthesize_findings output schema must include by_characteristic for ISO grouping."""
    import yaml
    wf = WORKFLOWS_DIR / "iso25010-scan.yaml"
    raw = yaml.safe_load(wf.read_text())
    synth = next(s for s in raw["stages"] if s["id"] == "synthesize_findings")
    props = synth["output_schema"]["properties"]
    assert "by_characteristic" in props, "synthesize_findings schema missing by_characteristic"
    assert "by_severity" in props, "synthesize_findings schema missing by_severity"


def test_iso25010_analyze_file_schema_has_characteristic():
    """analyze_file output schema must include characteristic and sub_characteristic."""
    import yaml
    wf = WORKFLOWS_DIR / "iso25010-scan.yaml"
    raw = yaml.safe_load(wf.read_text())
    af = next(s for s in raw["stages"] if s["id"] == "analyze_file")
    vuln_props = af["output_schema"]["properties"]["vulnerabilities"]["items"]["properties"]
    assert "characteristic" in vuln_props
    assert "sub_characteristic" in vuln_props


# ── CLI --profile flag ─────────────────────────────────────────────────────────

def test_cli_profile_selects_iso25010_workflow():
    from argus.cli import _WORKFLOWS
    assert "iso25010" in _WORKFLOWS
    assert _WORKFLOWS["iso25010"].name == "iso25010-scan.yaml"
    assert _WORKFLOWS["iso25010"].exists()


def test_cli_profile_default_is_security():
    from argus.cli import _WORKFLOWS, WORKFLOW
    assert _WORKFLOWS["security"] == WORKFLOW


def test_cli_scan_accepts_profile_option():
    from click.testing import CliRunner
    from argus.cli import scan
    runner = CliRunner()
    result = runner.invoke(scan, ["--help"])
    assert "--profile" in result.output
    assert "iso25010" in result.output
