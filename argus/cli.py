from __future__ import annotations
import asyncio
import sys
from pathlib import Path
import click
from armature.runtime.engine import Harness
from armature.spec.loader import load_spec

WORKFLOW = Path(__file__).parent.parent / "workflows" / "repo-scan.yaml"


@click.group()
def cli():
    """Argus — agentic security scanner."""


@cli.command()
@click.argument("repo_url")
@click.option("--report-dir", default=".", show_default=True,
              help="Directory to write the report file")
def scan(repo_url: str, report_dir: str):
    """Scan a Python repository for security vulnerabilities.

    REPO_URL can be a GitHub URL (https://github.com/org/repo)
    or a local filesystem path.
    """
    asyncio.run(_run_scan(repo_url, Path(report_dir)))


async def _run_scan(repo_url: str, report_dir: Path) -> None:
    inputs: dict = {"repo_url": repo_url}

    # For local paths, skip the clone step by injecting a pre-built clone_repo result
    if repo_url.startswith("/") or repo_url.startswith("."):
        resolved = str(Path(repo_url).resolve())
        inputs["clone_repo"] = {
            "stdout": f"CLONE_OK (local path: {resolved})",
            "stderr": "",
            "exit_code": 0,
        }
        inputs["repo_local_path"] = resolved

    click.echo(f"[argus] Loading workflow: {WORKFLOW}")
    spec = load_spec(WORKFLOW, vars=inputs)
    harness = Harness(spec=spec)

    click.echo(f"[argus] Scanning: {repo_url}")

    try:
        results = await harness.run(inputs)
    except Exception as exc:
        click.echo(f"[argus] ERROR: {exc}", err=True)
        sys.exit(1)

    report_stage = results.get("generate_report", {})
    markdown = report_stage.get("report_markdown", "")

    if not markdown:
        click.echo("[argus] WARNING: no report content in generate_report stage output", err=True)
        sys.exit(1)

    run_id = harness._run_id
    report_path = report_dir / f"argus-report-{run_id}.md"
    report_path.write_text(markdown, encoding="utf-8")
    click.echo(f"[argus] Report written to: {report_path}")
