from __future__ import annotations
import pytest
from pathlib import Path

WORKFLOW = Path(__file__).parent.parent / "workflows" / "repo-scan.yaml"
FIXTURE = Path(__file__).parent / "fixtures" / "vulnerable-app"


async def test_scan_completes(argus_scan_results):
    results = argus_scan_results
    assert "generate_report" in results, f"results keys: {list(results.keys())}"
    assert results["generate_report"]["report_markdown"], "generate_report.report_markdown is empty"


async def test_sql_injection_found(argus_scan_results):
    results = argus_scan_results
    code = results.get("code_analysis", {})
    vulns = code.get("vulnerabilities", [])
    types = [v["type"].lower() for v in vulns]
    assert any("sql" in t for t in types), \
        f"Expected SQL injection finding; got types: {types}"


async def test_hardcoded_secret_found(argus_scan_results):
    results = argus_scan_results
    code_vulns = results.get("code_analysis", {}).get("vulnerabilities", [])
    secret_stdout = results.get("secret_scan", {}).get("stdout", "[]")

    code_types = [v["type"].lower() for v in code_vulns]
    secret_found_in_code = any("secret" in t or "key" in t or "hardcod" in t for t in code_types)
    secret_found_by_gitleaks = "sk-prod" in secret_stdout or "RuleID" in secret_stdout

    assert secret_found_in_code or secret_found_by_gitleaks, \
        f"Expected hardcoded secret; code_types={code_types}, gitleaks_excerpt={secret_stdout[:200]}"


async def test_dependency_cves_found(argus_scan_results):
    results = argus_scan_results
    dep_stdout = results.get("dependency_scan", {}).get("stdout", "")
    assert "vulns" in dep_stdout or "PYSEC" in dep_stdout or "CVE" in dep_stdout, \
        f"Expected CVEs in dependency scan; got: {dep_stdout[:300]}"


async def test_report_contains_priority_list(argus_scan_results):
    results = argus_scan_results
    report = results["generate_report"]["report_markdown"]
    assert "Remediation" in report or "Priority" in report
    assert "SQL" in report or "injection" in report.lower()
