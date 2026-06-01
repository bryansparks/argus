# Argus

**Automated security and quality scanning for code repositories, powered by agentic AI.**

Argus scans a GitHub repository or local codebase and produces a prioritized, actionable report of security vulnerabilities and software quality issues. Built on the [Armature](https://github.com/bryansparks/armature) agentic workflow harness, Argus combines industry-standard security tools with LLM-based code review to find issues that rule-based tools miss.

```bash
# Scan a GitHub repository
argus scan https://github.com/org/repo

# Scan with verbose progress output
argus scan https://github.com/org/repo --verbose

# Scan a local codebase
argus scan ./my-project
```

---

## What Argus Does

A single `argus scan` command:

1. **Clones** the target repository (supports private repos with token auth)
2. **Discovers** all source files across 10+ languages
3. **Triage-selects** the 60 most security-relevant files (for large repos)
4. **Analyzes** each file in parallel using LLM security reviewers
5. **Runs** 7 automated security scanners concurrently:
   - `gitleaks` — secret detection
   - `semgrep` — static analysis (Java, Rust, Ruby, PHP)
   - `gosec` — Go security analyzer
   - `cppcheck` — C/C++ memory safety
   - `pip-audit` — Python CVE scanning
   - `grype` — multi-ecosystem CVE scanning
   - `lizard` — complexity metrics
6. **Synthesizes** all findings into a unified, deduplicated list
7. **Validates** findings to flag false positives
8. **Generates** a prioritized Markdown + HTML security report

**Typical scan time:** 3–8 minutes depending on repo size and model availability.

---

## Built on Armature

Argus is a production implementation of [Armature](https://github.com/bryansparks/armature), a YAML-configured agentic workflow harness. The entire scan pipeline is declared in workflow specs and executed as a directed acyclic graph (DAG) of LLM agents, tool calls, and shell adapters.

### Armature Features Used

| Feature | Benefit to Argus |
|---------|------------------|
| **Fan-out / Fan-in** | Parallel per-file analysis scales to repos of any size |
| **Model tier routing** | Cost-optimized routing (small models for analysis, frontier for synthesis) |
| **Cross-run memory** | Remembers false positive patterns across scans |
| **Checkpoint/resume** | Long scans recover gracefully from crashes |
| **Strict safety mode** | Fail-closed tool governance with explicit allow rules |
| **Post-run self-analysis** | Automatic quality review suggests spec improvements |
| **Behavior registry** | Alerts on failure spikes and quality degradation |
| **Trace export** | Export high-quality traces for fine-tuning smaller models |

### Workflow Specs

Argus includes two workflow profiles:

| Workflow | Purpose | Stages | Risk Score |
|----------|---------|--------|------------|
| `workflows/repo-scan.yaml` | Security vulnerability scanning | 15 | LOW (8) |
| `workflows/iso25010-scan.yaml` | ISO/IEC 25010 quality assessment | 14 | LOW (20) |

Both workflows validate at **LOW risk** under Armature's static risk scoring system.

---

## Scan Coverage

### Source Code Languages

| Language | Security Analysis | Quality Analysis |
|----------|-------------------|------------------|
| Python | ✓ | ✓ |
| JavaScript / TypeScript | ✓ | ✓ |
| Java | ✓ | ✓ |
| Go | ✓ | ✓ |
| Rust | ✓ | ✓ |
| C / C++ | ✓ | ✓ |
| Ruby | ✓ | ✓ |
| PHP | ✓ | ✓ |
| Kotlin (Android) | ✓ | ✓ |
| Swift (iOS) | ✓ | ✓ |

### Vulnerability Categories

**Injection Attacks**
- SQL injection (all languages/ORMs)
- OS command injection (`subprocess`, `os.system`, `exec`, backticks)
- Template injection (Jinja2, Django, Handlebars, Thymeleaf)
- Code injection (`eval`, `exec`, `compile`)
- XXE (XML External Entity)

**Authentication & Cryptography**
- Hardcoded secrets, API keys, tokens
- Weak password hashing (MD5/SHA1 for passwords)
- Broken JWT (`alg:none`, weak secrets)
- Insecure randomness (`random` vs `secrets`)
- ECB mode, DES, non-constant-time comparisons

**Unsafe Deserialization**
- Python `pickle`, `marshal`, `yaml.load` (unsafe)
- Java `ObjectInputStream`, XStream, Jackson `enableDefaultTyping`
- Node.js `node-serialize`

**Access Control**
- Missing authentication/authorization
- IDOR (Insecure Direct Object References)
- Missing CSRF protection
- Open redirect, SSRF

**Data Exposure**
- Sensitive data in logs
- Stack traces returned to users
- Path traversal

**Memory Safety (C/C++, Rust)**
- Buffer overflow, use-after-free, double-free
- Integer overflow before allocation
- Format string injection
- Rust `unsafe {}` blocks, unchecked casts

### Infrastructure & Configuration

- **Docker**: running as root, `COPY . .`, secrets in ENV, `:latest` tags
- **CI/CD**: unpinned Actions, excessive permissions, script injection
- **Framework settings**: DEBUG mode, CORS misconfiguration, missing security headers
- **Spring Boot**: exposed actuators, disabled security, H2 console in production
- **Next.js/Vite**: `dangerouslyAllowSVG`, wildcard image hosts, missing CSP

### Dependency Scanning

| Tool | Ecosystems |
|------|------------|
| `pip-audit` | Python (`requirements.txt`, `pyproject.toml`) |
| `npm/pnpm audit` | JavaScript/Node.js (`package-lock.json`, `pnpm-lock.yaml`) |
| `grype` | Java, Rust, Go (Maven, Gradle, Cargo, Go modules) |

### Static Analysis Tools

| Tool | Languages |
|------|-----------|
| `semgrep` | Java, Rust, Ruby, PHP, Kotlin, Swift |
| `gosec` | Go |
| `cppcheck` | C, C++ |
| `lizard` | All (cyclomatic complexity, function length) |
| `gitleaks` | All (secrets, tokens, keys) |

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

### External Tools

The following tools must be on your PATH:

| Tool | Purpose | Install |
|------|---------|---------|
| `git` | Repository cloning | system package manager |
| `gitleaks` | Secret detection | `brew install gitleaks` |
| `pip-audit` | Python CVE scanning | `pip install pip-audit` |
| `grype` | Multi-ecosystem CVE scanning | `brew install grype` |
| `semgrep` | Static analysis (Java, Rust, Ruby, PHP) | `brew install semgrep` |
| `gosec` | Go security analysis | `brew install gosec` |
| `cppcheck` | C/C++ static analysis | `brew install cppcheck` |
| `lizard` | Complexity metrics | `pip install lizard-analyzer` |
| `pnpm` or `npm` | JavaScript CVE scanning | optional |

---

## Configuration

### LLM Provider Credentials

Argus reads credentials from `~/.argus/argus.config` or environment variables:

```ini
# ~/.argus/argus.config

# Set API key for your preferred provider
ANTHROPIC_API_KEY=sk-ant-...
OPENROUTER_API_KEY=sk-or-...
OPENAI_API_KEY=sk-...
```

### Model Configuration

Edit `model_tiers` in the workflow spec to change providers or models:

```yaml
# workflows/repo-scan.yaml
model_tiers:
  small:
    provider: anthropic
    model: claude-haiku-4-5-20251001
  frontier:
    provider: anthropic
    model: claude-sonnet-4-6
```

Test connectivity with:

```bash
argus model-config-test
```

---

## Usage

### `argus scan`

```bash
argus scan REPO_URL [OPTIONS]
```

**Examples:**

```bash
# Scan a public GitHub repository
argus scan https://github.com/OWASP/Top10

# Scan with live progress output
argus scan https://github.com/org/repo --verbose

# Save full agent transcript (system prompts + responses)
argus scan https://github.com/org/repo --transcript ~/transcript.md

# Custom report output directory
argus scan https://github.com/org/repo --report-dir ./security-reports

# Scan a local codebase
argus scan ./my-project --verbose
```

**Options:**

| Option | Description |
|--------|-------------|
| `--verbose`, `-v` | Print stage-by-stage progress |
| `--report-dir PATH` | Output directory (default: `~/argus-reports/<repo>/`) |
| `--transcript PATH` | Write agent transcript to Markdown file |
| `--workflow PROFILE` | Use `iso25010` for quality assessment instead of security |

### `argus view`

```bash
argus view REPORT_FILE
```

View a previously generated report. Uses `glow` (terminal Markdown renderer) when installed, otherwise opens the HTML version in your browser.

### `argus model-config-test`

```bash
argus model-config-test
```

Probes each configured model tier and prints a connectivity table showing provider, model, latency, and status.

---

## Output

### Security Report

Written to `~/argus-reports/<repo>/argus-report-<repo>-<run-id>.md` (Markdown) and `.html`.

**Structure:**

1. **Executive Summary** — total findings by severity, top priority item
2. **Risk Summary Table** — all findings with priority, severity, file, effort
3. **Prioritized Remediation Tasks** — ranked by severity × ease-of-fix
4. **Detailed Findings** — per-finding with vulnerable code, fix snippet, explanation
5. **Scan Coverage** — complete checklist of categories scanned
6. **Scan Metadata** — run ID, models used, validator confidence

**Severity Levels:**

| Badge | Level | Meaning |
|-------|-------|---------|
| 🔴 | Critical | Exploitable remotely with high impact (RCE, full data breach) |
| 🟠 | High | Significant risk requiring prompt remediation |
| 🟡 | Medium | Real vulnerability but limited exploitability |
| 🟢 | Low | Best practice deviation or defense-in-depth |

**Effort Estimates:**

| Effort | Time |
|--------|------|
| Low | < 1 hour |
| Medium | 1–4 hours |
| High | > 4 hours |

### Agent Transcript (Optional)

Produced with `--transcript`. Shows each agent's system prompt and full response in execution order — useful for auditing and understanding the reasoning behind findings.

---

## Project Structure

```
argus/
├── argus/
│   ├── cli.py                  # CLI entry point (Click)
│   ├── behaviors.py            # Behavior registry for trace-triggered alerts
│   ├── report_html.py          # Markdown → HTML renderer
│   └── tools/
│       ├── scanners.py         # run_all_scanners tool (7 concurrent scanners)
│       └── files.py            # list_source_files, read_file, aggregate_findings
├── workflows/
│   ├── repo-scan.yaml          # Security scanning workflow (15 stages)
│   └── iso25010-scan.yaml      # ISO 25010 quality assessment (14 stages)
├── tests/
│   ├── conftest.py             # Session-scoped scan fixture
│   ├── test_e2e.py             # End-to-end pipeline tests
│   └── fixtures/
│       └── vulnerable-app/     # Intentionally vulnerable test app
├── pyproject.toml
└── README.md
```

---

## Extending Argus

The workflows are standard Armature specs and can be customized:

### Add a New Stage

```yaml
- id: custom_review
  role:
    name: Custom Reviewer
    type: researcher
    model_tier: large
    description: "Your custom analysis task..."
  output_mode: guided_json
  depends_on: [analyze_file]
```

### Change Model per Stage

Each stage has an independent `model_tier` setting. Route expensive reasoning to `frontier` and simple tasks to `small`.

### Add Custom Tools

Create a tool module:

```python
# my_tools.py
from armature.registry import ToolDescriptor
from armature.permissions import PermissionLevel

async def my_tool(args: dict) -> dict:
    # Your logic here
    return {"result": "..."}

def register(registry: ToolRegistry) -> None:
    registry.register(ToolDescriptor(
        name="my_tool",
        description="Does something useful",
        permission=PermissionLevel.READ_ONLY,
        handler=my_tool,
        parameters={"arg": {"type": "string"}},
    ))
```

Then add to the workflow:

```yaml
tools:
  - module: my_tools
```

### Adjust Safety Rules

The default `safety_mode: strict` blocks any tool not explicitly allowed. Add allow rules for custom tools:

```yaml
safety_rules:
  - tool: my_tool
    condition:
      field: arg
      op: truthy
      value: ""
    action: allow
```

---

## Self-Improvement

Argus workflows support Armature's self-improvement system. After accumulating scan traces:

```bash
# Analyze and propose improvements
armature improve workflows/repo-scan.yaml

# Run with automatic improvement when quality drops
armature run workflows/repo-scan.yaml --input repo_url=... --auto-improve
```

The improvement system:
1. Computes the Implicit Harness Rating (IHR) from trace history
2. Diagnoses failure signatures (which stages are failing and how)
3. Calls a frontier LLM to propose targeted spec revisions
4. Applies safe changes automatically; stages structural changes for review

### Export Traces for Fine-Tuning

After 50+ scans, export high-quality traces to fine-tune a smaller model:

```bash
armature export-traces \
  --workflow repo-security-scan \
  --output training.jsonl \
  --format chat \
  --min-score 0.85
```

---

## License

MIT

---

*Argus is built on [Armature](https://github.com/bryansparks/armature), combining academic research in deliberative multi-agent systems with production-grade security scanning.*
