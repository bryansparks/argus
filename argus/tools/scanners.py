"""Argus security scanner tool module.

Exposes one composite tool — run_all_scanners — that runs all six security
scanners concurrently against a cloned repository directory.

Register in a workflow spec:
    tools:
      - module: argus.tools.scanners
"""
from __future__ import annotations

import asyncio
import subprocess
from pathlib import Path

from armature.permissions.permissions import PermissionLevel
from armature.registry.registry import ToolDescriptor, ToolRegistry


# ── low-level subprocess helper ───────────────────────────────────────────────

def _run_sync(cmd: str, timeout: int = 120, cwd: str | None = None, max_bytes: int = 4000) -> str:
    """Run a shell command, return stdout capped at max_bytes."""
    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=timeout, cwd=cwd
        )
        out = result.stdout or ""
        return out[:max_bytes]
    except subprocess.TimeoutExpired:
        return f"TIMEOUT after {timeout}s"
    except Exception as exc:
        return f"ERROR: {exc}"


async def _run(cmd: str, timeout: int = 120, cwd: str | None = None, max_bytes: int = 4000) -> str:
    return await asyncio.to_thread(_run_sync, cmd, timeout, cwd, max_bytes)


# ── individual scanners ────────────────────────────────────────────────────────

async def _dependency_scan(repo_dir: str) -> str:
    parts = ["=== PYTHON_AUDIT ==="]
    reqs = sorted(Path(repo_dir).rglob("requirements*.txt"))[:3]
    if reqs:
        for req in reqs:
            out = await _run(f"pip-audit --format json -r {req}", cwd=repo_dir)
            parts.append(f"FILE: {req}\n{out}")
    else:
        parts.append("[]")

    parts.append("=== JS_AUDIT ===")
    repo = Path(repo_dir)
    if (repo / "pnpm-lock.yaml").exists():
        parts.append(await _run("pnpm audit --json --prod", timeout=60, cwd=repo_dir) or "{}")
    elif (repo / "package-lock.json").exists():
        parts.append(await _run("npm audit --json --production", timeout=60, cwd=repo_dir) or "{}")
    else:
        parts.append("{}")

    parts.append("=== MANIFEST_INVENTORY ===")
    manifests = await _run(
        "find . -maxdepth 3 \\( -name 'requirements*.txt' -o -name 'pyproject.toml' "
        "-o -name 'Pipfile' -o -name 'package.json' \\) ! -path '*/node_modules/*' | sort",
        cwd=repo_dir,
    )
    parts.append(manifests or "none")
    return "\n".join(parts)


async def _supply_chain_scan(repo_dir: str) -> str:
    github_cmd = (
        f"cd {repo_dir} && "
        "echo '=== GITHUB_UNPINNED_ACTIONS ===' && "
        "(grep -rn 'uses:' .github/workflows/ 2>/dev/null | grep -v '@[a-f0-9]\\{40\\}' || echo 'none') && "
        "echo '=== GITHUB_WORKFLOW_PERMISSIONS ===' && "
        "(grep -rn 'permissions:' .github/workflows/ 2>/dev/null || echo 'none') && "
        "echo '=== GITHUB_SECRETS_IN_RUN ===' && "
        "(grep -rn -i 'echo.*secrets\\.|echo.*\\$.*TOKEN\\|echo.*\\$.*PASSWORD' .github/workflows/ 2>/dev/null || echo 'none') && "
        "echo '=== GITHUB_SCRIPT_INJECTION ===' && "
        "(grep -rn 'github\\.event\\.pull_request\\|github\\.head_ref\\|github\\.event\\.issue' .github/workflows/ 2>/dev/null || echo 'none')"
    )
    gitlab_cmd = (
        f"cd {repo_dir} && "
        "echo '=== GITLAB_LATEST_IMAGES ===' && "
        "(grep -rn 'image:.*:latest' .gitlab-ci.yml 2>/dev/null || echo 'none') && "
        "echo '=== GITLAB_GLOBAL_VARS ===' && "
        "(grep -B1 -A15 '^variables:' .gitlab-ci.yml 2>/dev/null | grep -i 'PASSWORD\\|SECRET\\|TOKEN\\|API_KEY\\|PRIVATE' || echo 'none') && "
        "echo '=== GITLAB_EXTERNAL_INCLUDES ===' && "
        "(grep -n 'include:' .gitlab-ci.yml 2>/dev/null | head -8 || echo 'none')"
    )
    circleci_cmd = (
        f"cd {repo_dir} && "
        "echo '=== CIRCLECI_ORBS ===' && "
        "(grep -A25 '^orbs:' .circleci/config.yml 2>/dev/null | head -25 || echo 'none') && "
        "echo '=== CIRCLECI_VOLATILE ===' && "
        "(grep -rn '@dev:\\|@volatile\\|@edge' .circleci/ 2>/dev/null || echo 'none') && "
        "echo '=== CIRCLECI_MACHINE_LATEST ===' && "
        "(grep -n 'image:.*latest' .circleci/config.yml 2>/dev/null || echo 'none')"
    )
    azure_jenkins_cmd = (
        f"cd {repo_dir} && "
        "echo '=== AZURE_TASK_VERSIONS ===' && "
        "(find . -maxdepth 2 \\( -name 'azure-pipelines*.yml' -o -name 'azure-pipelines*.yaml' \\) | "
        "xargs grep -n 'task:' 2>/dev/null | head -15 || echo 'none') && "
        "echo '=== JENKINS_RISKS ===' && "
        "(find . -maxdepth 3 -name 'Jenkinsfile*' | "
        "xargs grep -n 'agent any\\|agent {\\|withCredentials\\|env\\.' 2>/dev/null | head -10 || echo 'none')"
    )
    deps_cmd = (
        f"cd {repo_dir} && "
        "echo '=== UNPINNED_PYTHON_DEPS ===' && "
        "(grep -rn '^[a-zA-Z]' requirements*.txt 2>/dev/null | grep -v '==' | grep -v '^#' || echo 'none') && "
        "echo '=== UNPINNED_NPM_DEPS ===' && "
        "(find . -maxdepth 2 -name 'package.json' ! -path '*/node_modules/*' | "
        "while read f; do echo \"FILE: $f\"; grep -E '\"[^\"]+\": *\"[\\^~]' \"$f\" | head -10; done 2>/dev/null || echo 'none')"
    )
    parts = await asyncio.gather(
        _run(github_cmd, max_bytes=3000),
        _run(gitlab_cmd, max_bytes=2000),
        _run(circleci_cmd, max_bytes=2000),
        _run(azure_jenkins_cmd, max_bytes=2000),
        _run(deps_cmd, max_bytes=2000),
    )
    return "\n".join(parts)


async def _secret_scan(repo_dir: str) -> str:
    leaks_file = f"{repo_dir}-leaks.json"
    await _run(
        f"gitleaks detect --source {repo_dir} --report-format json "
        f"--report-path {leaks_file} --no-git"
    )
    try:
        content = Path(leaks_file).read_text()
        return content[:3000]
    except Exception:
        return "[]"


async def _grype_scan(repo_dir: str) -> str:
    has_manifests = (await _run(
        f"find {repo_dir} "
        r"\( -name 'pom.xml' -o -name 'build.gradle' -o -name 'build.gradle.kts' "
        r"-o -name 'Cargo.toml' -o -name 'go.mod' \) "
        "! -path '*/target/*' ! -path '*/build/*' 2>/dev/null"
    )).strip()
    if not has_manifests:
        return "{}"
    grype_file = f"{repo_dir}-grype.json"
    await _run(f"grype dir:{repo_dir} -o json --file {grype_file}", timeout=120)
    try:
        content = Path(grype_file).read_text()
        return content[:3000]
    except Exception:
        return "{}"


async def _semgrep_scan(repo_dir: str) -> str:
    parts = ["=== JAVA_SEMGREP ==="]
    has_java = (await _run(
        f"find {repo_dir} -name '*.java' ! -path '*/target/*' ! -path '*/build/*' 2>/dev/null"
    )).strip()
    if has_java:
        parts.append(await _run(
            f"semgrep scan --config p/java --json --timeout 30 --quiet {repo_dir}",
            timeout=60,
        ) or "{}")
    else:
        parts.append("{}")

    parts.append("=== RUST_SEMGREP ===")
    has_rust = (await _run(
        f"find {repo_dir} -name '*.rs' ! -path '*/target/*' 2>/dev/null"
    )).strip()
    if has_rust:
        parts.append(await _run(
            f"semgrep scan --config p/rust --json --timeout 30 --quiet {repo_dir}",
            timeout=60,
        ) or "{}")
    else:
        parts.append("{}")

    return "\n".join(parts)


async def _gosec_scan(repo_dir: str) -> str:
    has_go = (await _run(
        f"find {repo_dir} -name '*.go' ! -path '*/vendor/*' 2>/dev/null"
    )).strip()
    if not has_go:
        return "{}"
    return await _run(f"gosec -fmt json -quiet {repo_dir}/...", timeout=120) or "{}"


async def _cppcheck_scan(repo_dir: str) -> str:
    has_c = (await _run(
        f"find {repo_dir} \\( -name '*.c' -o -name '*.cpp' -o -name '*.cc' -o -name '*.cxx' \\)"
        f" ! -path '*/build/*' ! -path '*/target/*' ! -path '*/.git/*' 2>/dev/null"
    )).strip()
    if not has_c:
        return "none"
    return await _run(
        f"cppcheck --enable=warning,style,performance,portability "
        f"--suppress=missingInclude --suppress=missingIncludeSystem "
        f"--template='{{file}}:{{line}}: {{severity}}: {{id}}: {{message}}' "
        f"--quiet {repo_dir} 2>&1",
        timeout=120,
    ) or "none"


# ── composite tool handler ────────────────────────────────────────────────────

async def _handle_run_all_scanners(args: dict) -> dict:
    repo_dir = args.get("repo_dir", "")
    if not repo_dir or not Path(repo_dir).exists():
        return {"error": f"repo_dir not found: {repo_dir}"}

    dep, sc, sec, grype, semgrep, gosec, cppcheck = await asyncio.gather(
        _dependency_scan(repo_dir),
        _supply_chain_scan(repo_dir),
        _secret_scan(repo_dir),
        _grype_scan(repo_dir),
        _semgrep_scan(repo_dir),
        _gosec_scan(repo_dir),
        _cppcheck_scan(repo_dir),
    )
    return {
        "dependency_scan": dep,
        "supply_chain_scan": sc,
        "secret_scan": sec,
        "grype_scan": grype,
        "semgrep_scan": semgrep,
        "gosec_scan": gosec,
        "cppcheck_scan": cppcheck,
    }


# ── registration ──────────────────────────────────────────────────────────────

def register(registry: ToolRegistry) -> None:
    registry.register(ToolDescriptor(
        name="run_all_scanners",
        description=(
            "Run all security scanners concurrently (pip-audit, npm/pnpm audit, "
            "supply chain checks, gitleaks secret detection, grype CVE scan, "
            "semgrep static analysis, gosec Go analyzer, cppcheck C/C++ analyzer) "
            "against a cloned repository. "
            "Returns a dict with keys: dependency_scan, supply_chain_scan, secret_scan, "
            "grype_scan, semgrep_scan, gosec_scan, cppcheck_scan."
        ),
        permission=PermissionLevel.READ_ONLY,
        handler=_handle_run_all_scanners,
        parameters={
            "repo_dir": {
                "type": "string",
                "description": "Absolute path to the cloned repository directory",
            }
        },
    ))
