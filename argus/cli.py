from __future__ import annotations
import asyncio
import json
import os
import re
import shutil
import subprocess
import sys
import time
import webbrowser
from pathlib import Path
import click
import yaml
from armature.runtime.engine import Harness
from armature.spec.loader import load_spec
from argus.report_html import write_html_report

_WORKFLOWS: dict[str, Path] = {
    "security": Path(__file__).parent.parent / "workflows" / "repo-scan.yaml",
    "iso25010": Path(__file__).parent.parent / "workflows" / "iso25010-scan.yaml",
}
WORKFLOW = _WORKFLOWS["security"]  # kept for model-config-test backward compat
DEFAULT_REPORT_DIR = Path.home() / "argus-reports"
CONFIG_FILE = Path.home() / ".argus" / "argus.config"


def _load_config() -> None:
    """Load env vars from .env (CWD) and ~/.argus/argus.config (key=value format).

    .env in the current working directory is checked first so project-local
    overrides take precedence over the user-global config file.
    """
    # Load .env from current working directory if present
    cwd_env = Path.cwd() / ".env"
    if cwd_env.exists():
        try:
            from dotenv import load_dotenv
            load_dotenv(cwd_env, override=False)
        except ImportError:
            _parse_env_file(cwd_env)

    if not CONFIG_FILE.exists():
        return
    _parse_env_file(CONFIG_FILE)


def _parse_env_file(path: Path) -> None:
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip()
        if key and key not in os.environ:
            os.environ[key] = value


def _repo_slug(repo_url: str) -> str:
    """Turn a GitHub URL or local path into a filesystem-safe slug."""
    # https://github.com/owner/repo  →  owner-repo
    m = re.search(r"github\.com/([^/]+)/([^/]+?)(?:\.git)?$", repo_url)
    if m:
        return f"{m.group(1)}-{m.group(2)}"
    # local path  →  directory name
    return re.sub(r"[^a-zA-Z0-9._-]", "-", Path(repo_url).name) or "repo"


def _build_clone_url(repo_url: str, token: str | None) -> str:
    """Inject a git token into an HTTPS URL for cloning private repos.

    SSH URLs and local paths are returned unchanged — tokens don't apply.
    Token is embedded as a URL credential, not a separate argument, so it
    never appears in `git` process arguments visible via ps(1).
    """
    if not token or not repo_url.startswith("https://"):
        return repo_url
    if "github.com" in repo_url:
        return repo_url.replace("https://", f"https://x-access-token:{token}@", 1)
    if "gitlab.com" in repo_url or "/gitlab." in repo_url:
        return repo_url.replace("https://", f"https://oauth2:{token}@", 1)
    if "bitbucket.org" in repo_url:
        return repo_url.replace("https://", f"https://x-token-auth:{token}@", 1)
    # Generic HTTPS git server
    return repo_url.replace("https://", f"https://{token}@", 1)


@click.group()
@click.version_option(version="0.1.0", prog_name="argus")
def cli():
    """Argus — agentic security scanner.

    Scans a GitHub repository (or local path) for security vulnerabilities
    using a multi-agent pipeline and produces a prioritized Markdown report.

    \b
    Quick start:
        argus scan https://github.com/org/repo
        argus scan https://github.com/org/repo --verbose
        argus scan https://github.com/org/repo --transcript ./transcript.md
        argus scan ./local/path --report-dir ./reports

    Run 'argus COMMAND --help' for details on each command.
    """


@cli.command()
@click.argument("repo_url")
@click.option("--report-dir", default=None,
              help=f"Directory to write the report file (default: ~/argus-reports/<repo>)")
@click.option("--verbose", "-v", is_flag=True, default=False,
              help="Print stage progress as the scan runs")
@click.option("--transcript", "transcript_path", default=None, type=click.Path(),
              help="Write agent conversation transcript to this file")
@click.option("--token", "git_token", default=None, envvar="ARGUS_GIT_TOKEN",
              help="Git credential token for private repos. Falls back to ARGUS_GIT_TOKEN env var "
                   "or GIT_TOKEN in ~/.argus/argus.config. Supports GitHub (x-access-token), "
                   "GitLab (oauth2), Bitbucket (x-token-auth), and generic HTTPS servers.")
@click.option("--profile", default="security",
              type=click.Choice(["security", "iso25010"], case_sensitive=False),
              help="Scan profile: 'security' (default) for vulnerability scanning, "
                   "'iso25010' for ISO/IEC 25010 software quality assessment.")
def scan(repo_url: str, report_dir: str | None, verbose: bool, transcript_path: str | None,
         git_token: str | None, profile: str):
    """Scan a repository for security vulnerabilities.

    REPO_URL can be a GitHub/GitLab/Bitbucket URL (https://...) or a local path.

    For private repos, provide a personal access token via --token or
    the ARGUS_GIT_TOKEN environment variable.
    """
    _load_config()
    # Also honour GIT_TOKEN from argus.config (loaded into os.environ by _load_config)
    if not git_token:
        git_token = os.environ.get("GIT_TOKEN")
    slug = _repo_slug(repo_url)
    resolved_dir = Path(report_dir) if report_dir else DEFAULT_REPORT_DIR / slug
    workflow_path = _WORKFLOWS[profile.lower()]
    asyncio.run(_run_scan(repo_url, resolved_dir, verbose, transcript_path, git_token, workflow_path))


def _on_event_verbose(event_type: str, data: dict) -> None:
    if event_type == "stage_start":
        role = f"  [{data['role']}]" if data.get("role") else ""
        click.echo(f"[argus] ▶  {data['stage']}{role}")
    elif event_type == "stage_complete":
        click.echo(f"[argus] ✓  {data['stage']}  ({data['elapsed_s']}s)")


def _format_transcript(run_id: str, repo_url: str, entries: list[dict]) -> str:
    lines = [
        "# Argus Agent Transcript",
        "",
        f"**Run ID:** {run_id}  ",
        f"**Repository:** {repo_url}",
        "",
        "---",
    ]
    for i, entry in enumerate(entries, 1):
        lines += [
            "",
            f"## [{i}] {entry['stage_id']}",
            f"**Role:** {entry['role_name']} ({entry['role_type']}) | **Model:** {entry['model']}",
            "",
            "### System Prompt",
            "",
            "```",
            entry.get("system_prompt", ""),
            "```",
            "",
            "### Response",
            "",
        ]
        response = entry.get("response", "")
        try:
            json.loads(response)
            lang = "json"
        except (json.JSONDecodeError, ValueError):
            lang = ""
        lines += [f"```{lang}", response, "```", "", "---"]
    return "\n".join(lines)


def _severity_counts_from_results(results: dict) -> dict[str, int] | None:
    """Extract per-severity finding counts from scan results, minus confirmed false positives."""
    synthesis = results.get("synthesize_findings", {})
    by_severity = synthesis.get("by_severity")
    if not isinstance(by_severity, dict):
        return None
    counts = {k: int(v) for k, v in by_severity.items() if k in ("critical", "high", "medium", "low")}
    fp_ids = set(results.get("validate_findings", {}).get("false_positive_ids") or [])
    if fp_ids:
        for finding in synthesis.get("findings", []):
            if finding.get("id") in fp_ids:
                sev = finding.get("severity", "").lower()
                if sev in counts:
                    counts[sev] = max(0, counts[sev] - 1)
    return counts


async def _run_scan(
    repo_url: str,
    report_dir: Path,
    verbose: bool,
    transcript_path: str | None,
    git_token: str | None = None,
    workflow_path: Path | None = None,
) -> None:
    wf = workflow_path or WORKFLOW
    click.echo(f"[argus] Loading workflow: {wf}")
    spec = load_spec(wf)
    harness = Harness(spec=spec, on_event=_on_event_verbose if verbose else None)

    click.echo(f"[argus] Scanning: {repo_url}")
    if git_token:
        click.echo("[argus] Using git token for private repo authentication.")

    clone_url = _build_clone_url(repo_url, git_token)

    try:
        results = await harness.run({"repo_url": repo_url, "clone_url": clone_url})
    except Exception as exc:
        click.echo(f"[argus] ERROR: {exc}", err=True)
        sys.exit(1)

    report_stage = results.get("generate_report", {})
    markdown = report_stage.get("report", "")

    if not markdown:
        click.echo(
            f"[argus] generate_report returned no content. Keys: {list(report_stage.keys())}",
            err=True,
        )
        sys.exit(1)

    # Append model-per-stage breakdown to Scan Metadata
    if harness.transcript:
        model_stages: dict[str, list[str]] = {}
        for entry in harness.transcript:
            model = entry.get("model", "")
            stage = entry.get("stage_id", "")
            if model and stage:
                model_stages.setdefault(model, []).append(stage)
        if model_stages:
            lines = ["- Models used:"]
            for model, stages in model_stages.items():
                lines.append(f"  - `{model}`: {', '.join(stages)}")
            markdown = markdown.rstrip() + "\n" + "\n".join(lines) + "\n"

    report_dir.mkdir(parents=True, exist_ok=True)
    slug = _repo_slug(repo_url)
    report_path = report_dir / f"argus-report-{slug}-{harness._run_id}.md"
    report_path.write_text(markdown, encoding="utf-8")
    click.echo(f"[argus] Report written to: {report_path}")

    html_path = write_html_report(
        report_path,
        repo=repo_url,
        run_id=harness._run_id,
        severity_counts=_severity_counts_from_results(results),
    )
    click.echo(f"[argus] HTML report:        {html_path}")

    if transcript_path:
        transcript_md = _format_transcript(
            run_id=harness._run_id,
            repo_url=repo_url,
            entries=harness.transcript,
        )
        Path(transcript_path).write_text(transcript_md, encoding="utf-8")
        click.echo(f"[argus] Transcript written to: {transcript_path}")


@cli.command("view")
@click.argument("report_file", type=click.Path(exists=True))
@click.option("--browser", is_flag=True, default=False,
              help="Open the HTML version in a browser even if glow is available")
def view(report_file: str, browser: bool):
    """View a scan report in the terminal or browser.

    REPORT_FILE can be the .md or .html report path.

    Prefers glow (terminal Markdown renderer) when installed.
    Falls back to opening the .html version in your default browser.
    Install glow:  brew install glow
    """
    path = Path(report_file)
    md_path = path.with_suffix(".md")
    html_path = path.with_suffix(".html")

    if not browser and shutil.which("glow"):
        if md_path.exists():
            subprocess.run(["glow", str(md_path)])
        else:
            click.echo("[argus] .md file not found, falling back to browser.", err=True)
            _open_html(html_path)
        return

    if not html_path.exists() and md_path.exists():
        click.echo("[argus] Generating HTML report...")
        from argus.report_html import write_html_report as _whr
        html_path = _whr(md_path)

    if html_path.exists():
        _open_html(html_path)
    elif md_path.exists():
        click.echo(md_path.read_text(encoding="utf-8"))
    else:
        click.echo(f"[argus] Report not found: {report_file}", err=True)
        sys.exit(1)


def _open_html(html_path: Path) -> None:
    url = html_path.resolve().as_uri()
    click.echo(f"[argus] Opening: {url}")
    webbrowser.open(url)


@cli.command("model-config-test")
def model_config_test():
    """Test connectivity to all configured model tiers.

    Loads model_tiers from the workflow YAML, sends a minimal probe to each
    one, and prints a result table with provider, model, latency, and status.
    """
    _load_config()
    asyncio.run(_run_model_config_test())


async def _probe_tier(name: str, cfg: dict) -> dict:
    """Send a minimal completion to one tier and return result metadata."""
    try:
        import litellm
    except ImportError:
        return {"name": name, "status": "FAIL", "latency": 0.0,
                "content": "", "error": "litellm not installed"}

    provider = cfg.get("provider", "")
    model = cfg.get("model", "")
    if provider == "ollama":
        litellm_model = f"ollama/{model}"
    elif provider == "openrouter":
        litellm_model = f"openrouter/{model}"
    else:
        litellm_model = model

    kwargs: dict = {"max_tokens": 256}
    if cfg.get("api_base"):
        kwargs["api_base"] = cfg["api_base"]
    api_key_env = cfg.get("api_key_env")
    if api_key_env:
        key = os.environ.get(api_key_env, "")
        if key:
            kwargs["api_key"] = key
    elif provider == "ollama":
        key = os.environ.get("OLLAMA_API_KEY", "")
        if key:
            kwargs["api_key"] = key

    start = time.monotonic()
    try:
        litellm.set_verbose = False
        resp = await litellm.acompletion(
            model=litellm_model,
            messages=[{"role": "user", "content": "Reply with the single word: OK"}],
            **kwargs,
        )
        latency = time.monotonic() - start
        content = (resp.choices[0].message.content or "").strip()
        notes = ""
        if not content:
            notes = "reasoning model (response consumed by thinking tokens)"
        return {"name": name, "status": "OK", "latency": latency,
                "content": content, "notes": notes, "error": ""}
    except Exception as exc:
        latency = time.monotonic() - start
        return {"name": name, "status": "FAIL", "latency": latency,
                "content": "", "notes": "", "error": str(exc)[:120]}


async def _run_model_config_test() -> None:
    raw = yaml.safe_load(WORKFLOW.read_text())
    tiers_raw: dict = raw.get("model_tiers", {})
    defaults: dict = raw.get("role_type_defaults", {})

    if not tiers_raw:
        click.echo("[argus] No model_tiers configured in workflow.", err=True)
        sys.exit(1)

    tier_order = ["tiny", "small", "medium", "large", "frontier"]
    ordered = [(k, tiers_raw[k]) for k in tier_order if k in tiers_raw]
    ordered += [(k, v) for k, v in tiers_raw.items() if k not in tier_order]

    # Map tier → which role types use it by default
    tier_roles: dict[str, list[str]] = {}
    for role_type, tier_name in defaults.items():
        tier_roles.setdefault(tier_name, []).append(role_type)

    click.echo(f"\n[argus] Testing {len(ordered)} model tier(s)...\n")

    results = []
    for name, cfg in ordered:
        click.echo(f"  probing {name} ({cfg.get('provider')}/{cfg.get('model')})...", nl=False)
        result = await _probe_tier(name, cfg)
        result["provider"] = cfg.get("provider", "")
        result["model"] = cfg.get("model", "")
        result["roles"] = ", ".join(tier_roles.get(name, [])) or "—"
        results.append(result)
        status_sym = "✓" if result["status"] == "OK" else "✗"
        click.echo(f"  {status_sym}")

    # Print table
    col_tier     = 10
    col_provider = 12
    col_model    = 46
    col_roles    = 20
    col_status   = 7
    col_latency  = 8

    header = (
        f"  {'Tier':<{col_tier}} {'Provider':<{col_provider}} {'Model':<{col_model}}"
        f" {'Role defaults':<{col_roles}} {'Status':<{col_status}} {'Latency':>{col_latency}}"
    )
    divider = "  " + "-" * (col_tier + col_provider + col_model + col_roles + col_status + col_latency + 5)

    click.echo(f"\n{header}")
    click.echo(divider)

    all_ok = True
    for r in results:
        status_display = click.style("OK", fg="green") if r["status"] == "OK" else click.style("FAIL", fg="red")
        latency_str = f"{r['latency']:.1f}s" if r["latency"] else "—"
        model_display = r["model"]
        if len(model_display) > col_model - 1:
            model_display = model_display[: col_model - 4] + "..."
        click.echo(
            f"  {r['name']:<{col_tier}} {r['provider']:<{col_provider}} {model_display:<{col_model}}"
            f" {r['roles']:<{col_roles}} {status_display:<{col_status}} {latency_str:>{col_latency}}"
        )
        if r["status"] != "OK":
            all_ok = False

    click.echo(divider)

    # Notes and errors
    notes_printed = False
    for r in results:
        if r.get("notes"):
            if not notes_printed:
                click.echo("\n  Notes:")
                notes_printed = True
            click.echo(f"    {r['name']}: {r['notes']}")
        if r.get("error"):
            if not notes_printed:
                click.echo("\n  Errors:")
                notes_printed = True
            click.echo(f"    {r['name']}: {r['error']}")

    click.echo()
    if all_ok:
        click.echo("[argus] All tiers reachable.")
    else:
        click.echo("[argus] One or more tiers failed — check ~/.argus/argus.config and model names.", err=True)
        sys.exit(1)
