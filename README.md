# Argus

**Agentic security scanner for GitHub repositories and local codebases.**

Argus runs a multi-agent pipeline that clones a repository, collects source code and configuration, runs static analysis tools, and produces a prioritized Markdown security report — all from a single command.

---

## How it works

Argus is built on **[Armature](https://github.com/bryansparks/armature)**, a YAML-configured agentic workflow harness. The scan pipeline is defined in `workflows/repo-scan.yaml` and executed as a directed acyclic graph (DAG) of specialized agents and script adapters.

### Agent pipeline

```
clone_repo
    ├── gather_code          ┐
    ├── gather_config        │  parallel data collection
    ├── dependency_scan      │
    ├── supply_chain_scan    │
    └── secret_scan          ┘
              │
         code_analysis ──── config_analysis   (parallel LLM workers)
              │                    │
              └────── synthesize_findings ────┘
                             │
                       prioritize_tasks
                             │
                       validate_findings
                             │
                       generate_report
                             │
                           cleanup
```

Each LLM stage has a named **role** and **type**:

| Stage | Role | Type | Does |
|---|---|---|---|
| `code_analysis` | code_analyzer | worker | Reviews Python/JS/TS source for vulnerabilities |
| `config_analysis` | config_analyzer | worker | Reviews Docker, CI/CD, framework config |
| `synthesize_findings` | synthesizer | orchestrator | Deduplicates and unifies all findings |
| `prioritize_tasks` | prioritizer | orchestrator | Ranks findings by severity and fix effort |
| `validate_findings` | validator | judge | Flags false positives and severity errors |
| `generate_report` | reporter | worker | Writes the final Markdown report |

Script adapters (`clone_repo`, `gather_code`, `gather_config`, `dependency_scan`, `supply_chain_scan`, `secret_scan`, `cleanup`) run shell commands directly — no LLM involved.

---

## What it scans

### Source Code (Python + JavaScript/TypeScript)
- SQL injection, command injection, template injection, code injection (eval/exec)
- XXE, LDAP injection
- Hardcoded secrets and credentials, broken JWT
- Weak cryptography (MD5/SHA1 for passwords, ECB mode, insecure randomness)
- Unsafe deserialization (pickle, yaml.load, marshal, node deserialize)
- Missing authentication/authorization, IDOR, CSRF, open redirect, SSRF
- Sensitive data in logs, path traversal, ReDoS, race conditions, prototype pollution

### Infrastructure & Configuration
- Framework misconfiguration (DEBUG mode, ALLOWED_HOSTS, SECRET_KEY)
- CORS policy, missing security headers (HSTS, CSP, X-Frame-Options)
- Docker security (running as root, COPY . ., secrets in ENV, latest tag)
- CI/CD security (unpinned Actions, excessive permissions, secret leakage)
- Plaintext credentials in docker-compose, missing secret management

### Dependencies
- Known CVEs via `pip-audit` (Python requirements files only)
- Known CVEs via `pnpm audit` / `npm audit` (lock files)
- Manifest inventory across requirements.txt, pyproject.toml, package.json

### Supply Chain
- GitHub Actions not pinned to SHA
- Excessive workflow permissions
- Script injection via untrusted PR event refs (`github.event.pull_request`, `github.head_ref`)
- Secrets echoed in `run:` steps

### Secrets
- API keys and tokens (AWS, GCP, GitHub, Slack, etc.) via **gitleaks**
- Private keys (SSH, RSA, PGP)
- Database connection strings, JWT tokens, high-entropy strings

---

## Installation

```bash
# Install Armature (dependency)
pip install -e /path/to/armature

# Install Argus
cd /path/to/argus
pip install -e .
```

**External tools required** (must be on PATH):
- `git` — repository cloning
- `gitleaks` — secret detection (`brew install gitleaks`)
- `pip-audit` — Python CVE scanning (`pip install pip-audit`)
- `pnpm` or `npm` — JavaScript CVE scanning (optional)

---

## Configuration

Argus reads `~/.argus/argus.config` on every run. Create this file to set your API keys and model configuration:

```
~/.argus/
└── argus.config
```

### `~/.argus/argus.config`

```ini
# LLM provider credentials
OLLAMA_API_KEY=your-ollama-cloud-key-here
OPENROUTER_API_KEY=your-openrouter-key-here
OPENROUTER_BASE_URL=https://openrouter.ai/api/v1
```

Keys already set in your shell environment take precedence over this file.

### Model configuration

The LLM provider, model, and API base are configured in the workflow YAML:

```yaml
# workflows/repo-scan.yaml
model_tiers:
  frontier:
    provider: ollama
    model: glm-5.1:cloud
    api_base: https://api.ollama.com
```

To switch providers, edit `model_tiers` in `workflows/repo-scan.yaml`. Supported providers (via [litellm](https://docs.litellm.ai)):
- `ollama` — Ollama Cloud or local Ollama
- `openrouter` — OpenRouter (access to many models)
- `anthropic`, `openai`, `google` — direct provider APIs

---

## Usage

```
argus [OPTIONS] COMMAND [ARGS]...
```

### `argus scan`

```
argus scan [OPTIONS] REPO_URL
```

Scan a repository for security vulnerabilities.

`REPO_URL` can be a GitHub URL or a local filesystem path:

```bash
argus scan https://github.com/org/repo
argus scan ./path/to/local/repo
```

**Options:**

| Option | Description |
|---|---|
| `--verbose`, `-v` | Print each stage name and elapsed time as the scan runs |
| `--report-dir PATH` | Directory to write the report (default: `~/argus-reports/<repo>/`) |
| `--transcript PATH` | Write the full agent conversation transcript to a Markdown file |
| `--help` | Show help and exit |

**Examples:**

```bash
# Basic scan
argus scan https://github.com/org/repo

# With live progress
argus scan https://github.com/org/repo -v

# Save transcript of agent deliberations
argus scan https://github.com/org/repo --transcript ~/Desktop/transcript.md

# Custom report output directory
argus scan https://github.com/org/repo --report-dir ./security-reports

# Scan a local repo
argus scan ./my-project -v
```

### `argus --version`

```bash
argus --version
```

---

## Output

### Security report

Written to `~/argus-reports/<repo>/argus-report-<repo>-<run-id>.md` by default.

The report contains:
- **Executive Summary** — total findings by severity, top priority item
- **Risk Summary** — table of all findings with priority, severity, source, and effort
- **Prioritized Remediation Tasks** — numbered list ordered by impact and ease of fix
- **Detailed Findings** — per-finding section with vulnerable code snippet, fix, and explanation
- **Scan Coverage** — complete list of every vulnerability category checked
- **Scan Metadata** — run ID, repository, validator confidence score

### Agent transcript (optional)

Written to any path you specify with `--transcript`. The transcript is a Markdown file showing each agent's system prompt and full response in execution order — useful for auditing the reasoning behind findings and reviewing false positive decisions.

---

## Workflow configuration

The scan pipeline lives in `workflows/repo-scan.yaml`. It is a standard Armature workflow spec and can be customized:

- **Add or remove stages** — extend with new LLM analysis stages or shell adapters
- **Change models per stage** — use different `model_tier` values for cost/quality trade-offs
- **Adjust safety rules** — the workflow blocks git write operations and destructive shell commands by default
- **Tune adapter timeouts** — each script adapter has a configurable `timeout` (in seconds)

See the [Armature documentation](https://github.com/bryansparks/armature) for the full workflow spec reference.

---

## Project structure

```
argus/
├── argus/
│   └── cli.py                  ← CLI entry point (click)
├── workflows/
│   └── repo-scan.yaml          ← Armature workflow definition
├── tests/
│   ├── test_e2e.py             ← End-to-end scan tests
│   └── fixtures/
│       └── vulnerable-app/     ← Intentionally vulnerable app for testing
├── pyproject.toml
└── README.md
```
