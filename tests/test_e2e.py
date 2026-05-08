from __future__ import annotations
import pytest
from pathlib import Path

WORKFLOW = Path(__file__).parent.parent / "workflows" / "repo-scan.yaml"
FIXTURE = Path(__file__).parent / "fixtures" / "vulnerable-app"


async def test_scan_completes(argus_scan_results):
    results = argus_scan_results
    assert "generate_report" in results, f"results keys: {list(results.keys())}"
    report = results["generate_report"].get("report", "")
    assert report, (
        f"generate_report.report is empty; "
        f"keys present: {list(results['generate_report'].keys())}"
    )


async def test_sql_injection_found(argus_scan_results):
    results = argus_scan_results
    code = results.get("aggregate_code_findings", {})
    vulns = code.get("vulnerabilities", [])
    types = [v["type"].lower() for v in vulns]
    assert any("sql" in t for t in types), \
        f"Expected SQL injection finding; got types: {types}"


async def test_aggregate_code_findings_shape(argus_scan_results):
    agg = argus_scan_results.get("aggregate_code_findings", {})
    assert agg, "aggregate_code_findings stage missing or empty"
    assert "vulnerabilities" in agg, "aggregate_code_findings missing vulnerabilities key"
    assert "files_analyzed" in agg, "aggregate_code_findings missing files_analyzed key"
    assert agg["files_analyzed"] > 0, "Expected at least one file analyzed"


async def test_hardcoded_secret_found(argus_scan_results):
    results = argus_scan_results
    code_vulns = results.get("aggregate_code_findings", {}).get("vulnerabilities", [])
    # Scanner outputs live under the run_scanners stage key
    secret_raw = results.get("run_scanners", {}).get("secret_scan", "[]")

    code_types = [v["type"].lower() for v in code_vulns]
    secret_found_in_code = any(
        "secret" in t or "key" in t or "hardcod" in t for t in code_types
    )
    secret_found_by_gitleaks = "sk-prod" in secret_raw or "RuleID" in secret_raw

    assert secret_found_in_code or secret_found_by_gitleaks, (
        f"Expected hardcoded secret; code_types={code_types}, "
        f"gitleaks_excerpt={secret_raw[:200]}"
    )


async def test_dependency_cves_found(argus_scan_results):
    results = argus_scan_results
    dep_raw = results.get("run_scanners", {}).get("dependency_scan", "")
    assert "vulns" in dep_raw or "PYSEC" in dep_raw or "CVE" in dep_raw, \
        f"Expected CVEs in dependency scan; got: {dep_raw[:300]}"


async def test_compress_scanners_keys(argus_scan_results):
    compressed = argus_scan_results.get("compress_scanners", {})
    assert compressed, "compress_scanners stage missing or empty"
    for key in (
        "dependency_findings",
        "supply_chain_findings",
        "secret_findings",
        "cve_findings",
        "static_analysis_findings",
    ):
        assert key in compressed, f"compress_scanners missing key: {key}"


async def test_synthesize_findings_has_findings(argus_scan_results):
    synthesis = argus_scan_results.get("synthesize_findings", {})
    assert synthesis, "synthesize_findings stage missing or empty"
    findings = synthesis.get("findings", [])
    assert len(findings) > 0, "Expected at least one finding from synthesis"
    assert synthesis.get("total_count", 0) > 0, "Expected non-zero total_count"
    # Every finding must have required fields
    required = {"id", "source", "severity", "title", "description", "recommendation"}
    for f in findings:
        missing = required - set(f.keys())
        assert not missing, f"Finding {f.get('id')} missing fields: {missing}"


async def test_report_contains_priority_list(argus_scan_results):
    report = argus_scan_results["generate_report"]["report"]
    assert "Remediation" in report or "Priority" in report
    assert "SQL" in report or "injection" in report.lower()


async def test_report_contains_fixes(argus_scan_results):
    report = argus_scan_results["generate_report"]["report"]
    # Report should include fix/recommendation sections
    assert "Fix" in report or "fix" in report.lower() or "Recommendation" in report
    # Should contain code blocks showing vulnerable/fixed code
    assert "```" in report, "Expected code blocks in detailed findings"
