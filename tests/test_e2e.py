from __future__ import annotations
import os
import shutil
import pytest
from pathlib import Path
from unittest.mock import patch
from armature.runtime.engine import Harness
from armature.spec.loader import load_spec

WORKFLOW = Path(__file__).parent.parent / "workflows" / "repo-scan.yaml"
FIXTURE = Path(__file__).parent / "fixtures" / "vulnerable-app"


@pytest.fixture(autouse=True)
def require_api_key():
    if not os.environ.get("ANTHROPIC_API_KEY"):
        pytest.skip("ANTHROPIC_API_KEY not set")


@pytest.fixture(autouse=True)
def require_tools():
    if not shutil.which("pip-audit"):
        pytest.skip("pip-audit not installed (pip install pip-audit)")
    if not shutil.which("gitleaks"):
        pytest.skip("gitleaks not installed (brew install gitleaks)")


async def _run_scan(repo_url: str) -> dict:
    from armature.nodes.gate import HumanGateNode

    spec = load_spec(WORKFLOW)
    harness = Harness(spec=spec)

    async def auto_approve(self, context):
        return {"approved": True, "comment": "auto-approved by test"}

    with patch.object(HumanGateNode, "execute", auto_approve):
        return await harness.run({"repo_url": repo_url})


@pytest.fixture
def repo_url():
    return str(FIXTURE.resolve())


async def test_scan_completes(repo_url):
    results = await _run_scan(repo_url)
    assert "generate_report" in results
    assert results["generate_report"].get("report_markdown")


async def test_sql_injection_found(repo_url):
    results = await _run_scan(repo_url)
    code = results.get("code_analysis", {})
    vulns = code.get("vulnerabilities", [])
    types = [v["type"].lower() for v in vulns]
    assert any("sql" in t for t in types), \
        f"Expected SQL injection finding; got types: {types}"


async def test_hardcoded_secret_found(repo_url):
    results = await _run_scan(repo_url)
    code_vulns = results.get("code_analysis", {}).get("vulnerabilities", [])
    secret_stdout = results.get("secret_scan", {}).get("stdout", "[]")

    code_types = [v["type"].lower() for v in code_vulns]
    secret_found_in_code = any("secret" in t or "key" in t or "hardcod" in t for t in code_types)
    secret_found_by_gitleaks = "sk-prod" in secret_stdout or "RuleID" in secret_stdout

    assert secret_found_in_code or secret_found_by_gitleaks, \
        "Expected hardcoded secret to be found by code analysis or gitleaks"


async def test_dependency_cves_found(repo_url):
    results = await _run_scan(repo_url)
    dep_stdout = results.get("dependency_scan", {}).get("stdout", "")
    assert "vulns" in dep_stdout or "PYSEC" in dep_stdout or "CVE" in dep_stdout, \
        f"Expected CVEs in dependency scan; got: {dep_stdout[:300]}"


async def test_report_contains_priority_list(repo_url):
    results = await _run_scan(repo_url)
    report = results["generate_report"]["report_markdown"]
    assert "Remediation" in report or "Priority" in report
    assert "SQL" in report or "injection" in report.lower()
