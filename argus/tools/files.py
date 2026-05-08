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

    return {
        "files": files,
        "file_paths": [f["path"] for f in files],
        "total_count": len(files),
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


async def _handle_aggregate_findings(args: dict[str, Any]) -> dict[str, Any]:
    per_file = args.get("per_file_results", [])
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

    return {
        "vulnerabilities": merged,
        "files_analyzed": len(per_file),
        "total_findings": len(merged),
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
            "and returns a unified vulnerabilities array compatible with synthesize_findings."
        ),
        permission=PermissionLevel.READ_ONLY,
        handler=_handle_aggregate_findings,
        parameters={
            "per_file_results": {
                "type": "array",
                "description": "List of analyze_file stage outputs (one dict per file)",
            }
        },
    ))
