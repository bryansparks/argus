"""Argus file-system tool module.

Provides three tools that together power the fan-out/fan-in code analysis pipeline:

  list_source_files  — enumerate all source files in a repo (returns manifest)
  read_file          — read a single file's content
  aggregate_findings — merge and deduplicate per-file vulnerability lists
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from armature.permissions.permissions import PermissionLevel
from armature.registry.registry import ToolDescriptor, ToolRegistry


# Security-relevant filename keywords used to rank files for triage.
# Files whose names contain these substrings are shown first when the
# manifest is too large to pass in full to the triage LLM.
_SECURITY_KEYWORDS: frozenset[str] = frozenset({
    "auth", "login", "logout", "signup", "register", "password", "passwd",
    "token", "jwt", "oauth", "session", "cookie", "csrf", "cors",
    "api", "endpoint", "route", "handler", "controller", "middleware",
    "upload", "file", "exec", "shell", "command", "subprocess",
    "admin", "user", "role", "permission", "acl", "access",
    "sql", "query", "database", "db", "orm", "model",
    "secret", "key", "cred", "config", "setting", "env",
    "crypto", "cipher", "hash", "encrypt", "decrypt", "sign",
    "http", "request", "response", "client", "fetch", "url",
    "serial", "deserial", "pickle", "marshal", "json", "xml",
    "log", "audit", "trace",
})

_COMPACT_MANIFEST_CAP = 3000


def _security_score(relative_path: str) -> int:
    """Higher score = more likely to be security-relevant (for pre-sort before LLM triage)."""
    lower = relative_path.lower()
    return sum(1 for kw in _SECURITY_KEYWORDS if kw in lower)


_EXTENSIONS: dict[str, str] = {
    ".py": "python",
    ".js": "javascript", ".jsx": "javascript",
    ".ts": "typescript", ".tsx": "typescript",
    ".java": "java",
    ".go": "go",
    ".rs": "rust",
    ".c": "c", ".h": "c",
    ".cpp": "cpp", ".cc": "cpp", ".cxx": "cpp", ".hpp": "cpp",
    ".rb": "ruby",
    ".php": "php",
}

_SKIP_DIRS: frozenset[str] = frozenset({
    "node_modules", ".git", "target", "build", "dist",
    "vendor", ".venv", "venv", "__pycache__", ".mypy_cache",
    ".pytest_cache", "coverage", ".tox",
})


async def _handle_list_source_files(args: dict[str, Any]) -> dict[str, Any]:
    repo_dir = args.get("repo_dir", "")
    if not repo_dir or not Path(repo_dir).exists():
        return {"error": f"repo_dir not found: {repo_dir}", "files": [], "file_paths": [], "total_count": 0}

    files: list[dict[str, Any]] = []
    repo = Path(repo_dir)

    for path in sorted(repo.rglob("*")):
        if any(part in _SKIP_DIRS for part in path.parts):
            continue
        if not path.is_file():
            continue
        lang = _EXTENSIONS.get(path.suffix.lower())
        if not lang:
            continue
        try:
            size_lines = sum(1 for _ in path.open("rb"))
        except OSError:
            continue
        files.append({
            "path": str(path),
            "relative_path": str(path.relative_to(repo_dir)),
            "language": lang,
            "size_lines": size_lines,
        })

    # Build compact manifest: relative paths pre-sorted by security relevance.
    # For large repos this replaces the full files array in the triage LLM prompt,
    # keeping context usage manageable while surfacing the most relevant files first.
    sorted_files = sorted(files, key=lambda f: _security_score(f["relative_path"]), reverse=True)
    truncated = len(sorted_files) > _COMPACT_MANIFEST_CAP
    manifest_entries = sorted_files[:_COMPACT_MANIFEST_CAP]
    compact_lines = [f["relative_path"] for f in manifest_entries]
    if truncated:
        omitted = len(sorted_files) - _COMPACT_MANIFEST_CAP
        compact_lines.append(
            f"[... {omitted} additional files omitted — "
            "security-relevant files prioritized above ...]"
        )
    compact_manifest = "\n".join(compact_lines)

    # For large repos only return compact_manifest + repo_dir; omitting the full
    # objects array and flat file_paths list keeps the triage stage context well
    # under model context limits (each is ~1-5 bytes/file vs 60+ bytes for paths).
    # Small repos (≤200 files) still get file_paths for the skip-triage partition_source.
    small_repo = len(files) <= 200
    return {
        "repo_dir": repo_dir,
        "file_paths": [f["path"] for f in files] if small_repo else [],
        "total_count": len(files),
        "compact_manifest": compact_manifest,
        "compact_manifest_truncated": truncated,
    }


async def _handle_read_file(args: dict[str, Any]) -> dict[str, Any]:
    path = args.get("path", "")
    max_lines = args.get("max_lines", None)
    if not path:
        return {"error": "path is required"}
    try:
        if max_lines:
            with open(path, "rb") as f:
                lines = []
                for i, line in enumerate(f):
                    if i >= max_lines:
                        break
                    lines.append(line)
                content = b"".join(lines).decode("utf-8", errors="replace")
                truncated = i >= max_lines
        else:
            content = Path(path).read_text(errors="replace")
            truncated = False
        return {"path": path, "content": content, "size_chars": len(content), "truncated": truncated}
    except Exception as exc:
        return {"error": str(exc), "path": path, "content": ""}


_SEVERITY_RANK: dict[str, int] = {"critical": 0, "high": 1, "medium": 2, "low": 3}
_MAX_FINDINGS_DEFAULT = 120


async def _handle_aggregate_findings(args: dict[str, Any]) -> dict[str, Any]:
    per_file = args.get("per_file_results", [])
    max_findings: int = int(args.get("max_findings", _MAX_FINDINGS_DEFAULT))
    if not isinstance(per_file, list):
        return {"error": "per_file_results must be a list", "vulnerabilities": [], "files_analyzed": 0, "total_findings": 0}

    seen: set[tuple[str, str, int]] = set()
    merged: list[dict[str, Any]] = []

    for file_result in per_file:
        if not isinstance(file_result, dict):
            continue
        if file_result.get("_fan_out_error"):
            continue
        file_path = file_result.get("file_path", "")
        for v in file_result.get("vulnerabilities", []):
            if not isinstance(v, dict):
                continue
            key = (file_path, v.get("type", ""), v.get("line_approx", 0))
            if key in seen:
                continue
            seen.add(key)
            merged.append({**v, "file": file_path})

    total_before = len(merged)
    truncation_note = ""
    if total_before > max_findings:
        # Sort by severity (critical first) then keep the top max_findings
        merged.sort(key=lambda v: _SEVERITY_RANK.get(v.get("severity", "low"), 3))
        merged = merged[:max_findings]
        omitted = total_before - max_findings
        truncation_note = (
            f"{omitted} lower-severity findings omitted to keep synthesis context manageable "
            f"(total before cap: {total_before}, cap: {max_findings}). "
            "Critical and high findings are fully included."
        )

    return {
        "vulnerabilities": merged,
        "files_analyzed": len(per_file),
        "total_findings": total_before,
        "findings_included": len(merged),
        "truncation_note": truncation_note,
    }


import ast as _ast
import json as _json


def _parse_stringified(value: Any) -> Any:
    """Parse a value that may be a JSON-encoded string or Python repr string."""
    if not isinstance(value, str):
        return value
    stripped = value.strip()
    # Try JSON first
    try:
        return _json.loads(stripped)
    except (_json.JSONDecodeError, ValueError):
        pass
    # Try Python literal (handles single-quoted strings from repr())
    try:
        return _ast.literal_eval(stripped)
    except Exception:
        pass
    return value


_CHAR_KEYS = frozenset({
    "maintainability", "reliability", "performance_efficiency",
    "portability", "functional_suitability", "usability", "compatibility",
})


def _build_from_aggregate(
    agg: dict[str, Any],
    comp: dict[str, Any],
) -> tuple[list[dict[str, Any]], dict[str, int], dict[str, int]]:
    """Build a findings list from aggregate_code_findings + compress_iso_scanners."""
    agg_vulns = agg.get("vulnerabilities", []) if isinstance(agg, dict) else []
    comp_findings = comp.get("findings", []) if isinstance(comp, dict) else []

    findings: list[dict[str, Any]] = []
    seq = 1
    for f in (agg_vulns or []):
        if not isinstance(f, dict):
            continue
        findings.append({
            **f,
            "id": f"Q{seq:03d}",
            "source": "code_analysis",
        })
        seq += 1
    for f in (comp_findings or []):
        if not isinstance(f, dict):
            continue
        findings.append({
            **f,
            "id": f"Q{seq:03d}",
            "source": "complexity_scanner",
        })
        seq += 1

    by_char: dict[str, int] = {k: 0 for k in _CHAR_KEYS}
    by_sev: dict[str, int] = {"high": 0, "medium": 0, "low": 0}
    for f in findings:
        ch = str(f.get("characteristic", "")).lower()
        if ch in by_char:
            by_char[ch] += 1
        sev = str(f.get("severity", "")).lower()
        if sev in by_sev:
            by_sev[sev] += 1

    return findings, by_char, by_sev


async def _handle_normalize_synthesize_output(args: dict[str, Any]) -> dict[str, Any]:
    """Parse synthesize_findings output; fall back to aggregate sources if synthesis is empty.

    Handles two failure modes from nemotron:
    1. Nested values returned as JSON-encoded strings (e.g. "findings": "[]").
    2. Synthesize stage returns {} because the model put its JSON inside its
       thinking block and emitted only {} as the final non-thinking response.

    When synthesis is empty, directly merges aggregate_code_findings.vulnerabilities
    and compress_iso_scanners.findings into a properly formatted findings list.
    """
    synth = args.get("synthesize_findings", {})
    if not isinstance(synth, dict):
        synth = {}

    findings = _parse_stringified(synth.get("findings", []))
    if not isinstance(findings, list):
        findings = []

    total_count = synth.get("total_count", len(findings))
    if isinstance(total_count, str):
        try:
            total_count = int(total_count)
        except ValueError:
            total_count = len(findings)

    by_char = _parse_stringified(synth.get("by_characteristic", {}))
    if not isinstance(by_char, dict):
        by_char = {}

    by_sev = _parse_stringified(synth.get("by_severity", {}))
    if not isinstance(by_sev, dict):
        by_sev = {}

    # If synthesis produced no findings, fall back to source data directly.
    if not findings:
        agg = args.get("aggregate_code_findings", {})
        comp = args.get("compress_iso_scanners", {})
        if agg or comp:
            findings, by_char, by_sev = _build_from_aggregate(agg, comp)

    return {
        "findings": findings,
        "total_count": max(total_count, len(findings)),
        "by_characteristic": by_char,
        "by_severity": by_sev,
    }


import re as _re

_LIZARD_LINE = _re.compile(
    r"^(?P<file>.+?):(?P<line>\d+):\s*warning:\s*(?P<func>.+?)\s+has\s+"
    r"(?P<nloc>\d+)\s+NLOC,\s*(?P<ccn>\d+)\s+CCN,\s*\d+\s+token,\s*\d+\s+PARAM,\s*"
    r"(?P<length>\d+)\s+length"
)


def _parse_lizard_output(raw: str, repo_dir: str = "") -> list[dict[str, Any]]:
    """Parse lizard warning lines into ISO 25010 complexity findings."""
    findings: list[dict[str, Any]] = []
    for line in raw.splitlines():
        m = _LIZARD_LINE.match(line.strip())
        if not m:
            continue
        fpath = m.group("file")
        line_num = int(m.group("line"))
        func = m.group("func")
        nloc = int(m.group("nloc"))
        ccn = int(m.group("ccn"))
        length = int(m.group("length"))

        # Relative path
        rel = fpath.replace(repo_dir, "").lstrip("/") if repo_dir else fpath

        if ccn > 15:
            sev = "high"
        elif ccn > 10:
            sev = "medium"
        else:
            sev = "low"

        if ccn > 10:
            findings.append({
                "type": "complex_function",
                "characteristic": "maintainability",
                "sub_characteristic": "analyzability",
                "severity": sev,
                "line_approx": line_num,
                "title": f"High cyclomatic complexity in {func} (CCN={ccn})",
                "description": f"`{func}` has a cyclomatic complexity of {ccn} (NLOC={nloc}), exceeding the recommended threshold of 10.",
                "recommendation": "Decompose into smaller functions with single responsibilities to reduce branching.",
                "file": fpath,
            })
        if length > 50:
            findings.append({
                "type": "long_function",
                "characteristic": "maintainability",
                "sub_characteristic": "modularity",
                "severity": "medium" if length > 100 else "low",
                "line_approx": line_num,
                "title": f"{func} is too long ({length} lines)",
                "description": f"`{func}` spans {length} lines, making it hard to understand and test.",
                "recommendation": "Extract logical sub-steps into helper functions.",
                "file": fpath,
            })

    return findings


async def _handle_compress_iso_scanners(args: dict[str, Any]) -> dict[str, Any]:
    """Deterministically parse lizard complexity scanner output into structured findings."""
    rs = args.get("run_iso_scanners", {})
    if isinstance(rs, str):
        rs = _parse_stringified(rs)
    if not isinstance(rs, dict):
        rs = {}

    raw = rs.get("complexity_scan", "")
    if not isinstance(raw, str) or raw.strip() in ("", "lizard_not_installed"):
        return {"findings": [], "note": raw if raw else "no complexity scan output"}

    # Try to infer repo_dir from the first file path
    repo_dir = ""
    first_line = next((l for l in raw.splitlines() if l.strip()), "")
    m = _re.match(r"^(/tmp/argus-[a-f0-9]+)/", first_line)
    if m:
        repo_dir = m.group(1)

    findings = _parse_lizard_output(raw, repo_dir)
    return {
        "findings": findings,
        "total": len(findings),
        "note": f"Parsed {len(findings)} complexity findings from lizard output.",
    }


_SEV_EMOJI = {"high": "🟠 High", "medium": "🟡 Medium", "low": "🟢 Low"}
_SEV_ORDER = {"high": 0, "medium": 1, "low": 2}
_EFFORT_MAP = {
    "bare_except": "low", "deep_nesting": "medium", "long_function": "medium",
    "god_class": "high", "magic_values": "low", "global_mutable_state": "medium",
    "duplicate_logic": "medium", "complex_function": "medium",
    "missing_error_handling": "low", "null_dereference": "medium",
    "synchronous_blocking": "medium", "unclosed_resource": "low",
    "n_plus_one": "medium", "hardcoded_path": "low", "missing_validation": "low",
}
_CHAR_DISPLAY = {
    "maintainability": "Maintainability",
    "reliability": "Reliability",
    "performance_efficiency": "Performance Efficiency",
    "portability": "Portability",
    "functional_suitability": "Functional Suitability",
    "usability": "Usability",
    "compatibility": "Compatibility",
}
_CHAR_COVERAGE = {
    "Maintainability": (
        "(Modularity · Reusability · Analyzability · Modifiability · Testability)",
        [
            "Cyclomatic complexity (lizard, CCN > 10)", "Function length (> 50 lines)",
            "God classes (> 300 lines, mixed responsibilities)", "Deep nesting (> 4 levels)",
            "Magic values / hardcoded constants", "Global mutable state",
            "Duplicate logic blocks", "Untestable code (no injection points)",
        ],
    ),
    "Reliability": (
        "(Maturity · Fault Tolerance · Recoverability)",
        [
            "Bare except / swallowed exceptions",
            "Missing error handling on I/O and network calls",
            "Null/None dereference risks", "Missing transaction rollback",
            "No retry logic for transient failures", "Unreachable code",
        ],
    ),
    "Performance Efficiency": (
        "(Time Behavior · Resource Utilization)",
        [
            "N+1 query patterns", "Synchronous blocking in async contexts",
            "Unclosed file handles and database connections",
            "Unbounded in-memory accumulation",
            "Repeated expensive computation in loops",
        ],
    ),
    "Portability": (
        "(Adaptability)",
        [
            "Hardcoded absolute filesystem paths",
            "OS-specific API calls without guards",
            "Hardcoded timezone assumptions",
            "Hardcoded locale and encoding assumptions",
        ],
    ),
    "Functional Suitability": (
        "(Functional Correctness · Completeness)",
        [
            "Missing bounds validation on external numeric input",
            "Off-by-one index arithmetic", "Float equality comparisons",
            "Missing required field validation",
        ],
    ),
    "Usability": (
        "(Operability — API ergonomics)",
        [
            "Functions with 6+ positional parameters",
            "Inconsistent error return shapes",
            "Undocumented required parameters with non-obvious constraints",
        ],
    ),
    "Compatibility": (
        "(Co-existence)",
        ["Mutable default arguments", "Built-in name shadowing"],
    ),
}


def _effort_for(finding: dict[str, Any]) -> str:
    return _EFFORT_MAP.get(str(finding.get("type", "")).lower(), "medium")


def _short_path(file_path: str) -> str:
    """Return filename without /tmp/argus-XXXXXXXX prefix."""
    import re
    return re.sub(r"^/tmp/argus-[a-f0-9]+/", "", file_path) if file_path else ""


async def _handle_generate_markdown_report(args: dict[str, Any]) -> dict[str, Any]:
    """Generate a deterministic ISO 25010 quality assessment report from findings data."""
    run_id = args.get("run_id", "unknown")
    repo_url = args.get("repo_url", "unknown")

    # Parse normalize_synthesize
    ns = args.get("normalize_synthesize", {})
    if isinstance(ns, str):
        ns = _parse_stringified(ns)
    if not isinstance(ns, dict):
        ns = {}

    all_findings = ns.get("findings", [])
    if not isinstance(all_findings, list):
        all_findings = []

    # Parse validate_findings for false positive IDs
    vf = args.get("validate_findings", {})
    if isinstance(vf, str):
        vf = _parse_stringified(vf)
    if not isinstance(vf, dict):
        vf = {}

    fp_ids_raw = vf.get("false_positive_ids", [])
    if isinstance(fp_ids_raw, str):
        fp_ids_raw = _parse_stringified(fp_ids_raw)
    fp_ids: set[str] = set()
    if isinstance(fp_ids_raw, list):
        for item in fp_ids_raw:
            if isinstance(item, list):
                fp_ids.update(str(x) for x in item)
            elif item:
                fp_ids.add(str(item))
    confidence = vf.get("confidence", 0.9)
    try:
        confidence = float(confidence)
    except (TypeError, ValueError):
        confidence = 0.9

    # Filter false positives and findings with no file
    findings = [
        f for f in all_findings
        if isinstance(f, dict) and f.get("id", "") not in fp_ids and f.get("file", "")
    ]

    # Sort by severity then characteristic
    findings.sort(key=lambda f: (_SEV_ORDER.get(str(f.get("severity", "")).lower(), 3), str(f.get("characteristic", ""))))

    # Count by severity
    sev_counts: dict[str, int] = {"high": 0, "medium": 0, "low": 0}
    char_counts: dict[str, int] = {}
    for f in findings:
        sev = str(f.get("severity", "")).lower()
        if sev in sev_counts:
            sev_counts[sev] += 1
        ch = str(f.get("characteristic", "")).lower()
        char_counts[ch] = char_counts.get(ch, 0) + 1

    total = len(findings)
    dominant_char = max(char_counts, key=char_counts.get) if char_counts else "maintainability"
    dominant_display = _CHAR_DISPLAY.get(dominant_char, dominant_char.title())

    # Parse prior_run for delta reporting
    prior = args.get("prior_run")
    if isinstance(prior, str):
        prior = _parse_stringified(prior)
    prior_total: int | None = None
    prior_sev: dict[str, int] = {}
    if isinstance(prior, dict):
        try:
            prior_total = int(prior.get("total_count", 0))
        except (TypeError, ValueError):
            prior_total = None
        raw_sev = prior.get("by_severity", {})
        if isinstance(raw_sev, dict):
            prior_sev = {k: int(v) for k, v in raw_sev.items() if isinstance(v, (int, float))}

    lines: list[str] = []

    # Executive Summary
    lines.append("## ISO 25010 Quality Assessment Report")
    lines.append("")
    lines.append("### Executive Summary")
    if total == 0:
        lines.append(
            f"The ISO 25010 quality assessment of the `{repo_url}` repository (Run ID: {run_id}) "
            "revealed no quality findings. A total of 0 issues were identified across all quality "
            "characteristics (0 🟠 High, 0 🟡 Medium, 0 🟢 Low). "
            "Consequently, no dominant quality characteristic was affected, and no improvement tasks are prioritized."
        )
    else:
        sev_summary = ", ".join(
            f"{sev_counts[s]} {_SEV_EMOJI[s]}"
            for s in ("high", "medium", "low") if sev_counts[s] > 0
        )
        top = findings[0]
        top_title = top.get("title", "Unknown issue")
        top_file = _short_path(top.get("file", ""))
        lines.append(
            f"The ISO 25010 quality assessment of `{repo_url}` (Run ID: {run_id}) identified "
            f"**{total} quality findings**: {sev_summary}. "
            f"**{dominant_display}** is the most-affected quality characteristic "
            f"with {char_counts.get(dominant_char, 0)} finding(s). "
            f"The highest-priority issue is **{top_title}** "
            + (f"in `{top_file}`" if top_file else "") +
            f", which should be addressed first to improve {dominant_display.lower()}."
        )
        if prior_total is not None:
            delta = total - prior_total
            sign = "+" if delta > 0 else ""
            lines.append(
                f"Trend vs. prior scan: **{sign}{delta} net change** "
                f"({prior_total} findings previously, {total} now)."
            )
        if sev_counts["high"] > 0:
            high_titles = [f.get("title", "issue") for f in findings if str(f.get("severity", "")).lower() == "high"]
            lines.append("")
            lines.append(f"> [!WARNING]")
            lines.append(f"> {high_titles[0]} is the most impactful quality issue affecting this codebase.")

    lines.append("")

    # Quality Summary Table
    lines.append("### Quality Summary Table")
    lines.append("")
    lines.append("| Priority | ID | Title | Characteristic | File | Severity | Effort |")
    lines.append("|----------|----|-------|----------------|------|----------|--------|")
    if not findings:
        lines.append("|          |    |       |                |      |          |        |")
    else:
        for i, f in enumerate(findings, 1):
            fid = f.get("id", "")
            title = f.get("title", "")
            char = _CHAR_DISPLAY.get(str(f.get("characteristic", "")).lower(), str(f.get("characteristic", "")).title())
            ffile = _short_path(f.get("file", ""))
            sev = _SEV_EMOJI.get(str(f.get("severity", "")).lower(), str(f.get("severity", "")))
            effort = _effort_for(f).title()
            lines.append(f"| {i} | {fid} | {title} | {char} | `{ffile}` | {sev} | {effort} |")
    lines.append("")

    # Prioritized Improvement Tasks
    lines.append("### Prioritized Improvement Tasks")
    if not findings:
        lines.append("No improvement tasks were identified.")
    else:
        lines.append("")
        for i, f in enumerate(findings, 1):
            fid = f.get("id", "")
            title = f.get("title", "")
            sev = _SEV_EMOJI.get(str(f.get("severity", "")).lower(), "")
            effort = _effort_for(f)
            ffile = _short_path(f.get("file", ""))
            line_approx = f.get("line_approx", 0)
            char = _CHAR_DISPLAY.get(str(f.get("characteristic", "")).lower(), str(f.get("characteristic", "")).title())
            sub = str(f.get("sub_characteristic", "")).replace("_", " ").title()
            lines.append(f"{i}. **[{fid}] {title}** ({sev} · {effort} effort)")
            if ffile:
                loc = f"`{ffile}`" + (f", line ~{line_approx}" if line_approx else "")
                lines.append(f"   - File: {loc}")
            lines.append(f"   - Addresses {char} › {sub} — {f.get('recommendation', 'see detailed findings.')}")
            lines.append("")

    lines.append("")

    # Detailed Findings
    lines.append("### Detailed Findings")
    if not findings:
        lines.append("No detailed findings are available.")
    else:
        for f in findings:
            fid = f.get("id", "")
            title = f.get("title", "")
            sev_label = _SEV_EMOJI.get(str(f.get("severity", "")).lower(), str(f.get("severity", "")))
            char = _CHAR_DISPLAY.get(str(f.get("characteristic", "")).lower(), str(f.get("characteristic", "")).title())
            sub = str(f.get("sub_characteristic", "")).replace("_", " ").title()
            ffile = _short_path(f.get("file", ""))
            line_approx = f.get("line_approx", 0)
            source = f.get("source", "code_analysis")
            desc = f.get("description", "")
            rec = f.get("recommendation", "")

            lines.append(f"#### [{fid}] {title} ({sev_label})")
            lines.append("")
            lines.append(f"**Characteristic:** {char} › {sub}")
            if ffile:
                loc = f"`{ffile}`" + (f", line ~{line_approx}" if line_approx else "")
                lines.append(f"**File:** {loc}")
            lines.append(f"**Source:** {source}")
            if desc:
                lines.append(f"**Issue:** {desc}")
            if rec:
                lines.append(f"**Recommendation:** {rec}")
            lines.append("")
            lines.append("---")
            lines.append("")

    # ISO 25010 Characteristic Coverage
    lines.append("### ISO 25010 Characteristic Coverage")
    lines.append("")
    for char_name, (sub_label, checks) in _CHAR_COVERAGE.items():
        char_key = char_name.lower().replace(" ", "_")
        count = char_counts.get(char_key, 0)
        lines.append(f"**{char_name}** {sub_label}")
        lines.append(" · ".join(f"✓ {c}" for c in checks))
        lines.append(f"*{count} finding(s)*" if count > 0 else "*No findings*")
        lines.append("")

    # Scan Metadata
    lines.append("### Scan Metadata")
    lines.append(f"- Run ID: {run_id}")
    lines.append(f"- Repository: {repo_url}")
    lines.append("- Profile: ISO/IEC 25010 Software Quality")
    lines.append(
        "- Stages: clone_repo, list_source_files, triage_files, run_iso_scanners, "
        "analyze_file (fan-out), aggregate_code_findings, compress_iso_scanners, "
        "synthesize_findings, prioritize_tasks, validate_findings, generate_report"
    )
    lines.append(f"- Validator confidence: {confidence}")
    if prior_total is not None:
        prior_sev_str = ", ".join(f"{k}: {v}" for k, v in sorted(prior_sev.items()) if v > 0)
        lines.append(f"- Prior scan: {prior_total} total findings ({prior_sev_str})")

    report = "\n".join(lines)
    return {"report": report}


def register(registry: ToolRegistry) -> None:
    registry.register(ToolDescriptor(
        name="list_source_files",
        description=(
            "Enumerate all source files in a cloned repository. "
            "Returns a manifest of every file with path, language, and line count, "
            "plus a flat file_paths list and total_count. "
            "Skips node_modules, .git, build artifacts, and virtual environments."
        ),
        permission=PermissionLevel.READ_ONLY,
        handler=_handle_list_source_files,
        parameters={
            "repo_dir": {
                "type": "string",
                "description": "Absolute path to the cloned repository directory",
            }
        },
    ))

    registry.register(ToolDescriptor(
        name="read_file",
        description="Read the full text content of a single source file.",
        permission=PermissionLevel.READ_ONLY,
        handler=_handle_read_file,
        parameters={
            "path": {
                "type": "string",
                "description": "Absolute path to the file to read",
            }
        },
    ))

    registry.register(ToolDescriptor(
        name="aggregate_findings",
        description=(
            "Merge and deduplicate per-file vulnerability lists from a fan-out analysis. "
            "Takes the list of all analyze_file results, deduplicates by (file, type, line), "
            "sorts by severity, and caps output at max_findings (default 120) to prevent "
            "synthesis context overflow on large repos. Critical/high findings are kept first. "
            "Returns vulnerabilities, files_analyzed, total_findings (before cap), "
            "findings_included (after cap), and truncation_note."
        ),
        permission=PermissionLevel.READ_ONLY,
        handler=_handle_aggregate_findings,
        parameters={
            "per_file_results": {
                "type": "array",
                "description": "List of analyze_file stage outputs (one dict per file)",
            },
            "max_findings": {
                "type": "integer",
                "description": "Maximum findings to return after dedup (default 120). "
                               "Excess lower-severity findings are dropped.",
            },
        },
    ))

    registry.register(ToolDescriptor(
        name="normalize_synthesize_output",
        description=(
            "Parse stringified values in synthesize_findings output. "
            "Some models return nested JSON structures as string values "
            "(e.g. '\"findings\": \"[]\"' instead of '\"findings\": []'). "
            "This tool unwraps those strings so downstream stages receive "
            "properly typed data. Returns findings (list), total_count (int), "
            "by_characteristic (dict), and by_severity (dict)."
        ),
        permission=PermissionLevel.READ_ONLY,
        handler=_handle_normalize_synthesize_output,
        parameters={
            "synthesize_findings": {
                "type": "object",
                "description": "Raw output dict from the synthesize_findings stage",
            },
            "aggregate_code_findings": {
                "type": "object",
                "description": "Fallback: output from aggregate_code_findings (used if synthesis is empty)",
            },
            "compress_iso_scanners": {
                "type": "object",
                "description": "Fallback: output from compress_iso_scanners (used if synthesis is empty)",
            },
        },
    ))

    registry.register(ToolDescriptor(
        name="compress_iso_scanners",
        description=(
            "Parse lizard cyclomatic complexity scanner output into structured ISO 25010 findings. "
            "Extracts CCN, NLOC, and length metrics from lizard warning lines. "
            "Returns findings list with severity, file, line, title, description, recommendation."
        ),
        permission=PermissionLevel.READ_ONLY,
        handler=_handle_compress_iso_scanners,
        parameters={
            "run_iso_scanners": {
                "type": "object",
                "description": "Output from run_iso_scanners stage with complexity_scan field",
            },
        },
    ))

    registry.register(ToolDescriptor(
        name="generate_markdown_report",
        description=(
            "Generate a complete ISO 25010 quality assessment Markdown report deterministically "
            "from normalized findings data. Filters false positives, sorts by severity, and "
            "produces executive summary, quality summary table, prioritized tasks, detailed "
            "findings, characteristic coverage, and scan metadata. Returns {report: <markdown>}."
        ),
        permission=PermissionLevel.READ_ONLY,
        handler=_handle_generate_markdown_report,
        parameters={
            "run_id": {"type": "string", "description": "Scan run identifier"},
            "repo_url": {"type": "string", "description": "Repository URL being assessed"},
            "normalize_synthesize": {
                "type": "object",
                "description": "Output from normalize_synthesize stage with findings list",
            },
            "validate_findings": {
                "type": "object",
                "description": "Validator output with false_positive_ids and confidence",
            },
            "prioritize_tasks": {
                "type": "object",
                "description": "Prioritized task list (used if valid; fallback to findings order)",
                "optional": True,
            },
        },
    ))
