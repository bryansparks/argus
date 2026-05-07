# Argus

**Agentic security scanner for GitHub repositories and local codebases.**

Argus runs a multi-agent pipeline that clones a repository, gathers source code and configuration, runs seven security scanners concurrently, and produces a prioritized Markdown + HTML security report — all from a single command.

---

## Built on Armature

Argus is built on **[Armature](https://github.com/bryansparks/armature)**, a YAML-configured agentic workflow harness. The entire scan pipeline is declared in `workflows/repo-scan.yaml` and executed as a directed acyclic graph (DAG) of LLM agents, tool calls, and shell adapters.

Armature handles stage scheduling, parallel execution, context passing between stages, model tier routing, and output schema validation. Argus focuses entirely on the security domain logic.

---

## How it works

### Pipeline

```
clone_repo
    ├── gather_code          ┐
    ├── gather_config        │  parallel data collection
    └── run_all_scanners     ┘  (7 scanners concurrently)
              │
       compress_scanners          ← compresses raw scanner output
              │
    ┌─────────┴─────────┐
    │                   │
 code_analysis    config_analysis   ← parallel LLM workers
    │                   │
    └──────────┬─────────┘
               │
       synthesize_findings         ← deduplicates and unifies
               │
       validate_findings           ← judge: flags false positives
               │
       generate_report             ← writes Markdown report
               │
            cleanup
```

### Stage reference

| Stage | Type | Does |
|---|---|---|
| `clone_repo` | adapter | Clones the target repo (or symlinks a local path) |
| `gather_code` | adapter | Collects source files across all supported languages |
| `gather_config` | adapter | Collects Docker, CI/CD, framework, and env config files |
| `run_all_scanners` | tool call | Runs all 7 scanners concurrently; returns structured results |
| `compress_scanners` | LLM | Extracts compact findings summaries from raw scanner JSON |
| `code_analysis` | LLM worker | Reviews source code for vulnerabilities across all languages |
| `config_analysis` | LLM worker | Reviews infrastructure and configuration for misconfigurations |
| `synthesize_findings` | LLM orchestrator | Unifies all findings; assigns IDs, severity, and deduplicates |
| `validate_findings` | LLM judge | Flags false positives and severity calibration errors |
| `generate_report` | LLM worker | Writes the final prioritized Markdown security report |
| `cleanup` | adapter | Removes the cloned repository from disk |

---

## What it scans

### Source code

Supports **Python, JavaScript, TypeScript, Java, Go, Rust, C, C++**.

- SQL, command, template, and code injection (eval/exec)
- Hardcoded secrets, credentials, and API keys
- Weak cryptography (MD5/SHA1 for passwords, ECB mode, insecure randomness)
- Unsafe deserialization (pickle, yaml.load, marshal, node-serialize)
- Missing authentication/authorization, IDOR, CSRF, open redirect, SSRF
- Sensitive data in logs, path traversal, ReDoS, race conditions
- **C/C++**: buffer overflow, format string injection, integer overflow before allocation, use-after-free, double-free
- **Rust**: integer overflow in usize arithmetic feeding `Vec::with_capacity` / `reserve`; parse-and-allocate patterns with untrusted size
- **Go**: integer overflow before `make`; parse-and-allocate with untrusted user input

### Infrastructure and configuration

- Framework misconfiguration (DEBUG mode, ALLOWED_HOSTS, SECRET_KEY)
- CORS policy, missing security headers (HSTS, CSP, X-Frame-Options)
- Docker security (running as root, `COPY . .`, secrets in ENV, `latest` tag)
- CI/CD (unpinned Actions, excessive permissions, secrets echoed in run steps)
- Plaintext credentials in docker-compose, missing secret management

### Dependencies

- Known CVEs via **pip-audit** (Python requirements files)
- Known CVEs via **pnpm audit** / **npm audit** (JavaScript lock files)
- Known CVEs via **grype** (Java, Rust, Go manifests)
- Manifest inventory across requirements.txt, pyproject.toml, Pipfile, package.json

### Supply chain

- GitHub Actions not pinned to a full commit SHA
- Excessive workflow permissions (`permissions: write-all`)
- Script injection via untrusted PR event refs (`github.event.pull_request`, `github.head_ref`)
- Unpinned Python and npm dependencies (missing `==` / using `^` or `~`)

### Secrets

- API keys and tokens (AWS, GCP, GitHub, Slack, Stripe, etc.) via **gitleaks**
- Private keys (SSH, RSA, PGP)
- Database connection strings, JWT secrets, high-entropy strings

### Static analysis

- **semgrep** — Java and Rust rule packs (`p/java`, `p/rust`)
- **gosec** — Go security analyzer
- **cppcheck** — C/C++ memory safety, undefined behavior, and style issues

---

## Installation

```bash
# 1. Install Armature (required dependency)
git clone https://github.com/bryansparks/armature
pip install -e armature/

# 2. Install Argus
git clone https://github.com/bryansparks/argus
pip install -e argus/
```

### External tools

The following tools must be on your PATH:

| Tool | Purpose | Install |
|---|---|---|
| `git` | Repository cloning | system package manager |
| `gitleaks` | Secret detection | `brew install gitleaks` |
| `pip-audit` | Python CVE scanning | `pip install pip-audit` |
| `grype` | Multi-ecosystem CVE scanning | `brew install grype` |
| `semgrep` | Static analysis (Java, Rust) | `brew install semgrep` |
| `gosec` | Go security analysis | `brew install gosec` |
| `cppcheck` | C/C++ static analysis | `brew install cppcheck` |
| `pnpm` or `npm` | JavaScript CVE scanning | optional |

---

## Configuration

Argus reads `~/.argus/argus.config` on every run. Create it to set API keys:

```ini
# ~/.argus/argus.config

# LLM provider credentials — set whichever you use
ANTHROPIC_API_KEY=your-key-here
OPENROUTER_API_KEY=your-key-here
OPENROUTER_BASE_URL=https://openrouter.ai/api/v1
OLLAMA_API_KEY=your-ollama-cloud-key-here
```

Variables already in your shell environment take precedence over this file.

### Model configuration

LLM provider and model are configured in `workflows/repo-scan.yaml`:

```yaml
model_tiers:
  synthesis:
    provider: anthropic
    model: claude-haiku-4-5-20251001
    api_key_env: ANTHROPIC_API_KEY
```

To switch providers or models, edit `model_tiers`. Supported providers (via [litellm](https://docs.litellm.ai)):
`anthropic`, `openai`, `google`, `openrouter`, `ollama`

Use `argus model-config-test` to verify all configured tiers are reachable before scanning.

---

## Usage

### `argus scan`

```bash
argus scan REPO_URL [OPTIONS]
```

`REPO_URL` can be a GitHub URL or a local path:

```bash
# Scan a GitHub repository
argus scan https://github.com/org/repo

# With live stage-by-stage progress
argus scan https://github.com/org/repo -v

# Save agent transcript (system prompts + full responses)
argus scan https://github.com/org/repo --transcript ~/Desktop/transcript.md

# Custom report output directory
argus scan https://github.com/org/repo --report-dir ./security-reports

# Scan a local repo
argus scan ./my-project -v
```

**Options:**

| Option | Description |
|---|---|
| `--verbose`, `-v` | Print each stage name and elapsed time as the scan runs |
| `--report-dir PATH` | Directory to write the report (default: `~/argus-reports/<repo>/`) |
| `--transcript PATH` | Write the full agent conversation transcript to a Markdown file |

### `argus view`

```bash
argus view REPORT_FILE
```

View a previously generated report. Uses `glow` (terminal Markdown renderer) when installed, otherwise opens the HTML version in your browser.

```bash
argus view ~/argus-reports/my-repo/argus-report-my-repo-abc123.md
argus view ~/argus-reports/my-repo/argus-report-my-repo-abc123.md --browser
```

### `argus model-config-test`

```bash
argus model-config-test
```

Probes each configured model tier with a minimal completion and prints a connectivity table showing provider, model, latency, and status. Run this after editing `model_tiers` to verify everything is reachable.

---

## Output

### Security report

Written to `~/argus-reports/<repo>/argus-report-<repo>-<run-id>.md` (Markdown) and `.html` by default.

The report contains:

- **Executive Summary** — total findings by severity, top priority item
- **Risk Summary** — table of all findings with priority, severity, source, and effort
- **Prioritized Remediation Tasks** — numbered list ordered by impact and fix effort
- **Detailed Findings** — per-finding section with vulnerable code snippet, fix, and explanation
- **Scan Coverage** — complete list of every vulnerability category checked
- **Scan Metadata** — run ID, repository, validator confidence, models used per stage

The HTML report includes interactive severity badges and is suitable for sharing.

### Agent transcript (optional)

Produced with `--transcript`. A Markdown file showing each agent's system prompt and full response in execution order — useful for auditing the reasoning behind findings and reviewing false positive decisions.

---

## Project structure

```
argus/
├── argus/
│   ├── cli.py                  ← CLI entry point (click)
│   ├── report_html.py          ← Markdown → HTML report renderer
│   └── tools/
│       └── scanners.py         ← run_all_scanners tool (7 concurrent scanners)
├── workflows/
│   └── repo-scan.yaml          ← Armature workflow definition (11 stages)
├── tests/
│   ├── conftest.py             ← Session-scoped scan fixture
│   ├── test_e2e.py             ← End-to-end pipeline tests
│   └── fixtures/
│       └── vulnerable-app/     ← Intentionally vulnerable app for testing
│           ├── app.py          ← Python: SQL injection, hardcoded secrets, ...
│           └── vuln.c          ← C: buffer overflow, use-after-free, double-free, ...
├── FAN_OUT_PLAN.md             ← Architecture plan: per-file fan-out analysis
├── pyproject.toml
└── README.md
```

---

## Extending Argus

The workflow is a standard Armature spec (`workflows/repo-scan.yaml`) and can be customized:

- **Add stages** — new LLM analysis stages or shell adapters slot into the DAG via `depends_on`
- **Change models per stage** — each stage has an independent `model_tier` setting
- **Add scanners** — extend `argus/tools/scanners.py` and register new tools
- **Adjust safety rules** — the workflow blocks git write operations and destructive shell commands by default

See the [Armature repository](https://github.com/bryansparks/armature) for the full workflow spec reference.
