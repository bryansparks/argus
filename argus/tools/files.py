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

    return {
        "files": files,
        "file_paths": [f["path"] for f in files],
        "total_count": len(files),
        "compact_manifest": compact_manifest,
        "compact_manifest_truncated": truncated,
    }


async def _handle_read_file(args: dict[str, Any]) -> dict[str, Any]:
    path = args.get("path", "")
    if not path:
        return {"error": "path is required"}
    try:
        content = Path(path).read_text(errors="replace")
        return {"path": path, "content": content, "size_chars": len(content)}
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
