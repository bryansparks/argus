"""Convert an Argus Markdown report to a self-contained styled HTML file."""
from __future__ import annotations
import re
from pathlib import Path

import markdown
from markdown.extensions.toc import TocExtension
from markdown.extensions.tables import TableExtension
from markdown.extensions.fenced_code import FencedCodeExtension
from markdown.extensions.codehilite import CodeHiliteExtension
from pygments.formatters import HtmlFormatter


def _pygments_css() -> str:
    return HtmlFormatter(style="monokai", cssclass="codehilite").get_style_defs(".codehilite")


_SEVERITY_BADGE_RE = re.compile(
    r"\b(Critical|High|Medium|Low)\b",
    re.IGNORECASE,
)
_SEVERITY_EMOJI = {
    "critical": "🔴",
    "high": "🟠",
    "medium": "🟡",
    "low": "🟢",
}
_SEVERITY_COLOR = {
    "critical": ("#fef2f2", "#dc2626", "#fca5a5"),
    "high":     ("#fff7ed", "#ea580c", "#fdba74"),
    "medium":   ("#fefce8", "#ca8a04", "#fde047"),
    "low":      ("#f0fdf4", "#16a34a", "#86efac"),
}

_CSS = """
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

body {
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
  font-size: 15px;
  line-height: 1.65;
  color: #1e293b;
  background: #f8fafc;
  display: flex;
  flex-direction: column;
  min-height: 100vh;
}

/* ── Top bar ── */
#topbar {
  background: linear-gradient(135deg, #0f172a 0%, #1e3a5f 100%);
  color: #e2e8f0;
  padding: 24px 40px;
  position: sticky;
  top: 0;
  z-index: 100;
  box-shadow: 0 2px 12px rgba(0,0,0,0.25);
}
#topbar h1 {
  font-size: 1.25rem;
  font-weight: 700;
  letter-spacing: -0.01em;
  color: #f1f5f9;
  display: flex;
  align-items: center;
  gap: 10px;
}
#topbar h1 .shield { font-size: 1.4rem; }
#topbar .meta {
  margin-top: 4px;
  font-size: 0.8rem;
  color: #94a3b8;
}
#topbar .meta span { margin-right: 20px; }

/* ── Layout ── */
#layout {
  display: flex;
  flex: 1;
  max-width: 1400px;
  width: 100%;
  margin: 0 auto;
  padding: 32px 24px;
  gap: 32px;
}

/* ── Sidebar TOC ── */
#toc-sidebar {
  width: 240px;
  flex-shrink: 0;
}
#toc-sticky {
  position: sticky;
  top: 96px;
  background: #fff;
  border: 1px solid #e2e8f0;
  border-radius: 10px;
  padding: 16px;
  max-height: calc(100vh - 120px);
  overflow-y: auto;
  box-shadow: 0 1px 4px rgba(0,0,0,0.06);
}
#toc-sticky h3 {
  font-size: 0.7rem;
  font-weight: 700;
  letter-spacing: 0.08em;
  text-transform: uppercase;
  color: #94a3b8;
  margin-bottom: 10px;
  padding-bottom: 8px;
  border-bottom: 1px solid #f1f5f9;
}
#toc-sticky .toc ul { list-style: none; padding-left: 0; }
#toc-sticky .toc li { list-style: none; }
#toc-sticky .toc ul ul { padding-left: 12px; border-left: 2px solid #e2e8f0; margin-left: 4px; }
#toc-sticky .toc a {
  display: block;
  font-size: 0.78rem;
  color: #475569;
  text-decoration: none;
  padding: 2px 0;
  border-radius: 3px;
  transition: color 0.15s;
}
#toc-sticky .toc a:hover { color: #0f172a; }

/* ── Main content ── */
#content {
  flex: 1;
  min-width: 0;
}

/* ── Severity summary cards ── */
#severity-cards {
  display: grid;
  grid-template-columns: repeat(4, 1fr);
  gap: 12px;
  margin-bottom: 28px;
}
.sev-card {
  background: #fff;
  border: 1px solid;
  border-radius: 10px;
  padding: 14px 16px;
  text-align: center;
}
.sev-card .sev-count { font-size: 2rem; font-weight: 800; line-height: 1; }
.sev-card .sev-label { font-size: 0.72rem; font-weight: 600; letter-spacing: 0.06em; text-transform: uppercase; margin-top: 4px; }

/* ── Headings ── */
#content h2 {
  font-size: 1.35rem;
  font-weight: 700;
  color: #0f172a;
  margin: 36px 0 14px;
  padding-bottom: 8px;
  border-bottom: 2px solid #e2e8f0;
}
#content h3 {
  font-size: 1.05rem;
  font-weight: 700;
  color: #1e293b;
  margin: 24px 0 10px;
}
#content h4 {
  font-size: 0.92rem;
  font-weight: 700;
  color: #334155;
  margin: 18px 0 8px;
  display: flex;
  align-items: center;
  gap: 8px;
}

/* ── Prose ── */
#content p { margin-bottom: 12px; color: #334155; }
#content ul, #content ol { padding-left: 22px; margin-bottom: 12px; color: #334155; }
#content li { margin-bottom: 3px; }
#content strong { color: #0f172a; }
#content a { color: #2563eb; }
#content hr {
  border: none;
  border-top: 1px solid #e2e8f0;
  margin: 28px 0;
}

/* ── Tables ── */
#content table {
  width: 100%;
  border-collapse: collapse;
  font-size: 0.85rem;
  margin-bottom: 20px;
  background: #fff;
  border: 1px solid #e2e8f0;
  border-radius: 8px;
  overflow: hidden;
  box-shadow: 0 1px 4px rgba(0,0,0,0.05);
}
#content th {
  background: #f1f5f9;
  color: #475569;
  font-weight: 700;
  font-size: 0.72rem;
  letter-spacing: 0.05em;
  text-transform: uppercase;
  padding: 10px 14px;
  text-align: left;
  border-bottom: 1px solid #e2e8f0;
}
#content td {
  padding: 9px 14px;
  border-bottom: 1px solid #f1f5f9;
  vertical-align: top;
}
#content tr:last-child td { border-bottom: none; }
#content tr:hover td { background: #f8fafc; }

/* Severity row tinting */
#content tr.sev-critical td { background: #fef2f2; }
#content tr.sev-high     td { background: #fff7ed; }
#content tr.sev-medium   td { background: #fefce8; }
#content tr.sev-low      td { background: #f0fdf4; }

/* ── Severity badges (inline) ── */
.badge {
  display: inline-block;
  font-size: 0.7rem;
  font-weight: 700;
  letter-spacing: 0.05em;
  text-transform: uppercase;
  padding: 2px 8px;
  border-radius: 999px;
  white-space: nowrap;
}
.badge-critical { background: #fca5a5; color: #7f1d1d; }
.badge-high     { background: #fdba74; color: #7c2d12; }
.badge-medium   { background: #fde047; color: #713f12; }
.badge-low      { background: #86efac; color: #14532d; }

/* ── Code blocks ── */
#content pre {
  background: #1e1e2e;
  border-radius: 8px;
  padding: 16px;
  overflow-x: auto;
  margin: 10px 0 16px;
  font-size: 0.82rem;
  line-height: 1.55;
  border: 1px solid #2d2d3f;
}
#content code {
  font-family: "SF Mono", "Fira Code", "Cascadia Code", Consolas, monospace;
}
#content p code, #content li code {
  background: #f1f5f9;
  color: #0f172a;
  padding: 1px 5px;
  border-radius: 4px;
  font-size: 0.83em;
}
.codehilite { background: #272822 !important; border-radius: 8px; padding: 14px 16px; overflow-x: auto; margin: 10px 0 16px; }
.codehilite pre { background: transparent; border: none; padding: 0; margin: 0; }
.codehilite code { color: #f8f8f2; }

/* ── GitHub-style callout blocks ── */
.admonition {
  border-left: 4px solid;
  border-radius: 6px;
  padding: 12px 16px;
  margin: 12px 0;
  font-size: 0.88rem;
}
.admonition.warning { border-color: #f59e0b; background: #fffbeb; }
.admonition.important { border-color: #8b5cf6; background: #f5f3ff; }
.admonition.caution { border-color: #ef4444; background: #fef2f2; }
.admonition.note { border-color: #3b82f6; background: #eff6ff; }
.admonition-title { font-weight: 700; font-size: 0.8rem; letter-spacing: 0.05em; text-transform: uppercase; margin-bottom: 4px; }

/* ── Finding cards ── */
.finding-card {
  background: #fff;
  border: 1px solid #e2e8f0;
  border-radius: 10px;
  padding: 20px 24px;
  margin-bottom: 20px;
  box-shadow: 0 1px 4px rgba(0,0,0,0.05);
}
.finding-card h4 { margin-top: 0; }

/* ── Footer ── */
#footer {
  text-align: center;
  font-size: 0.75rem;
  color: #94a3b8;
  padding: 20px;
  border-top: 1px solid #e2e8f0;
  background: #fff;
}

@media (max-width: 900px) {
  #toc-sidebar { display: none; }
  #severity-cards { grid-template-columns: repeat(2, 1fr); }
}
"""

_HTML_TEMPLATE = """\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Argus Security Report — {repo}</title>
<style>
{css}
{pygments_css}
</style>
</head>
<body>
<div id="topbar">
  <h1><span class="shield">🛡️</span> Argus Security Report</h1>
  <div class="meta">
    <span>📦 {repo}</span>
    <span>🔑 Run {run_id}</span>
  </div>
</div>

<div id="layout">
  <nav id="toc-sidebar">
    <div id="toc-sticky">
      <h3>Contents</h3>
      {toc}
    </div>
  </nav>

  <main id="content">
    <div id="severity-cards">
      <div class="sev-card" style="border-color:#fca5a5; color:#dc2626;">
        <div class="sev-count">{count_critical}</div>
        <div class="sev-label">🔴 Critical</div>
      </div>
      <div class="sev-card" style="border-color:#fdba74; color:#ea580c;">
        <div class="sev-count">{count_high}</div>
        <div class="sev-label">🟠 High</div>
      </div>
      <div class="sev-card" style="border-color:#fde047; color:#ca8a04;">
        <div class="sev-count">{count_medium}</div>
        <div class="sev-label">🟡 Medium</div>
      </div>
      <div class="sev-card" style="border-color:#86efac; color:#16a34a;">
        <div class="sev-count">{count_low}</div>
        <div class="sev-label">🟢 Low</div>
      </div>
    </div>
    {body}
  </main>
</div>

<div id="footer">
  Generated by <strong>Argus</strong> — agentic security scanner
</div>
</body>
</html>
"""


def _count_severity(md_text: str, level: str) -> int:
    # Count only actual finding headings: #### [F001] Title (🔴 Critical)
    # Avoids false matches in Scan Coverage, effort labels, prose, etc.
    emoji = _SEVERITY_EMOJI[level]
    pattern = re.compile(
        rf"^#{1,4}\s+\[F\d+\].*\({re.escape(emoji)}\s*{level}\)",
        re.IGNORECASE | re.MULTILINE,
    )
    return len(pattern.findall(md_text))


def _postprocess_html(html: str) -> str:
    """Replace bare severity words in table cells with styled badge spans."""
    for sev in ("critical", "high", "medium", "low"):
        emoji = _SEVERITY_EMOJI[sev]
        # Match <td> cells whose entire content is the severity word (with optional emoji prefix)
        html = re.sub(
            rf"(<td>)\s*(?:{re.escape(emoji)}\s*)?{sev}\s*(</td>)",
            rf'\1<span class="badge badge-{sev}">{emoji} {sev.capitalize()}</span>\2',
            html,
            flags=re.IGNORECASE,
        )
    return html


def _convert_callouts(md_text: str) -> str:
    """Convert GitHub-style [!TYPE] callouts to HTML admonition divs."""
    callout_re = re.compile(
        r'^> \[!(WARNING|IMPORTANT|CAUTION|NOTE)\]\n((?:^>.*\n?)*)',
        re.MULTILINE,
    )
    def _replace(m: re.Match) -> str:
        kind = m.group(1).lower()
        body_lines = re.sub(r'^> ?', '', m.group(2), flags=re.MULTILINE).strip()
        return (
            f'<div class="admonition {kind}">'
            f'<div class="admonition-title">{m.group(1)}</div>'
            f'<p>{body_lines}</p></div>\n'
        )
    return callout_re.sub(_replace, md_text)


def markdown_to_html(
    md_text: str,
    repo: str = "",
    run_id: str = "",
    severity_counts: dict[str, int] | None = None,
) -> str:
    """Render Argus Markdown report to a self-contained styled HTML string."""
    # Pre-process callout blocks before markdown parsing
    processed = _convert_callouts(md_text)

    md = markdown.Markdown(
        extensions=[
            TocExtension(toc_depth="2-4", title=""),
            TableExtension(),
            FencedCodeExtension(),
            CodeHiliteExtension(guess_lang=True, noclasses=False, css_class="codehilite"),
            "attr_list",
            "nl2br",
        ]
    )
    body_html = md.convert(processed)
    toc_html = md.toc  # type: ignore[attr-defined]

    body_html = _postprocess_html(body_html)

    # Prefer structured counts passed from the scan pipeline; fall back to
    # Markdown regex parsing (used when regenerating HTML from an existing .md).
    if severity_counts:
        count_critical = severity_counts.get("critical", 0)
        count_high     = severity_counts.get("high", 0)
        count_medium   = severity_counts.get("medium", 0)
        count_low      = severity_counts.get("low", 0)
    else:
        count_critical = _count_severity(md_text, "critical")
        count_high     = _count_severity(md_text, "high")
        count_medium   = _count_severity(md_text, "medium")
        count_low      = _count_severity(md_text, "low")

    return _HTML_TEMPLATE.format(
        repo=repo or "Unknown Repository",
        run_id=run_id or "—",
        toc=toc_html,
        body=body_html,
        css=_CSS,
        pygments_css=_pygments_css(),
        count_critical=count_critical,
        count_high=count_high,
        count_medium=count_medium,
        count_low=count_low,
    )


def write_html_report(
    md_path: Path,
    repo: str = "",
    run_id: str = "",
    severity_counts: dict[str, int] | None = None,
) -> Path:
    """Write a .html sibling of the given .md report path. Returns the html path."""
    md_text = md_path.read_text(encoding="utf-8")
    html = markdown_to_html(md_text, repo=repo, run_id=run_id, severity_counts=severity_counts)
    html_path = md_path.with_suffix(".html")
    html_path.write_text(html, encoding="utf-8")
    return html_path
