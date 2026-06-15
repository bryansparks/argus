# Argus Security Scanner — Feature Reference

**Audience:** Engineering management and developers  
**Purpose:** Describes what Argus detects, which languages and platforms it supports, how findings are delivered, and how Argus demonstrates Armature's capabilities for agentic teams.

Argus is open-source and intended as a reference implementation for building production-grade agentic workflows with [Armature](https://github.com/bryansparks/armature). See the section **Built on Armature** at the end of this document for a map of every Armature primitive Argus uses.

---

## What Is Argus?

Argus is an automated security scanner that reviews a code repository and produces a prioritized, actionable report of security vulnerabilities. It combines traditional scanning tools (industry-standard open-source analyzers) with LLM-based code review to find issues that rule-based tools miss. A single command produces a Markdown and HTML report with severity ratings, vulnerable code excerpts, and concrete fix recommendations — without any manual setup or rule configuration.

---

## Supported Languages

| Language | Source Code Analysis | Dependency Scanning | Static Analysis Tool |
|---|---|---|---|
| Python | ✓ | ✓ (pip-audit) | LLM + semgrep |
| JavaScript / TypeScript | ✓ | ✓ (npm/pnpm audit) | LLM |
| Java | ✓ | ✓ (grype) | LLM + semgrep p/java |
| Go | ✓ | ✓ (grype) | LLM + gosec |
| Rust | ✓ | ✓ (grype) | LLM + semgrep p/rust |
| C / C++ | ✓ | — | LLM + cppcheck |
| Ruby | ✓ | — | LLM + semgrep p/ruby |
| PHP | ✓ | — | LLM + semgrep p/php |
| Android (Java/Kotlin) | ✓ | — | mobsfscan / semgrep p/kotlin |
| iOS (Swift / Obj-C) | ✓ | — | mobsfscan / semgrep p/swift |

---

## Vulnerability Categories

### Injection Attacks
The most critical class of vulnerabilities — attacker-controlled input reaches an interpreter.

- **SQL Injection** — user input concatenated directly into database queries (all languages/ORMs)
- **OS Command Injection** — user input passed to shell execution (`subprocess`, `os.system`, backticks, `exec`, `system`)
- **Template Injection** — user-controlled strings rendered by template engines (Jinja2, Django, Handlebars, Thymeleaf)
- **Code Injection** — dynamic code execution with user input (`eval`, `exec`, `compile`, `Function()`)
- **LDAP Injection** — unsanitized input in directory service queries
- **XXE (XML External Entity)** — maliciously crafted XML triggering server-side file reads or SSRF

### Authentication & Cryptography
Weaknesses that allow unauthorized access or credential exposure.

- **Hardcoded Secrets** — API keys, passwords, tokens, connection strings embedded in source code
- **Weak Password Hashing** — use of MD5 or SHA-1 for password storage (vulnerable to rainbow table attacks); should use bcrypt, scrypt, or Argon2
- **Broken JWT** — `alg:none` acceptance, weak signing secrets, missing signature verification
- **Insecure Randomness** — use of non-cryptographic random functions for security tokens (`random` instead of `secrets`, `math/rand` instead of `crypto/rand`)
- **Non-Constant-Time Comparisons** — timing-oracle vulnerabilities in credential comparisons
- **ECB Mode / DES** — use of deprecated or fundamentally broken encryption modes

### Unsafe Deserialization
Deserializing untrusted data can lead to remote code execution.

- Python `pickle.loads`, `marshal`
- YAML `yaml.load` (unsafe; should be `yaml.safe_load`)
- Java `ObjectInputStream`, XStream, Jackson `enableDefaultTyping`
- Node.js `node-serialize`

### Access Control
Logic flaws that allow users to access data or operations they shouldn't.

- **Missing Authentication Checks** — endpoints that perform sensitive operations without verifying identity
- **Insecure Direct Object References (IDOR)** — user-supplied IDs used to access records without ownership verification
- **Missing CSRF Protection** — state-changing endpoints lacking cross-site request forgery tokens
- **Open Redirect** — attacker-controlled redirect targets that can be used in phishing
- **Server-Side Request Forgery (SSRF)** — user-supplied URLs fetched by the server, enabling internal network access

### Data Exposure
Unintended leakage of sensitive information.

- **Sensitive Data in Logs** — passwords, tokens, PII written to log statements
- **Stack Traces Returned to Users** — error handlers returning internal stack trace details
- **Path Traversal** — file path constructed from user input allowing directory escape

### Memory Safety (C, C++, Rust)
- **Buffer Overflow** — unbounded string copies (`strcpy`, `gets`, `scanf %s`) into fixed-size buffers
- **Use-After-Free** — memory accessed after it has been released
- **Double-Free** — freeing the same pointer twice, corrupting the heap allocator
- **Integer Overflow Before Allocation** — arithmetic wrap-around producing an undersized `malloc`
- **Format String Injection** — user input passed as a `printf` format argument
- Rust: `unsafe {}` blocks, `unwrap()` on externally-supplied values, unchecked `as` casts, unguarded `Vec::with_capacity`

### Language-Specific Patterns

**JavaScript / TypeScript**
- `dangerouslySetInnerHTML` with user data (React XSS)
- `innerHTML` assignment without sanitization
- Prototype pollution via unsanitized object key assignment
- `eval()` with user-controlled input

**Go**
- `database/sql` with `fmt.Sprintf` string formatting (SQL injection)
- `crypto/tls` `InsecureSkipVerify: true`
- `text/template` used where `html/template` is required (XSS)
- Goroutine race conditions on shared state
- `unsafe.Pointer` usage

**Ruby**
- ActiveRecord string interpolation in queries
- Mass assignment without strong parameter enforcement
- `Marshal.load` on untrusted data
- `YAML.load` (should be `YAML.safe_load`)
- `html_safe` / `raw` bypassing Rails auto-escaping
- `redirect_to` with user-controlled destination

**PHP**
- `mysqli`/`PDO` query string concatenation
- `include` / `require` with user-supplied file paths (remote file inclusion)
- `exec`, `system`, `passthru`, `shell_exec` with user input
- `unserialize` on user-supplied data
- `echo $_GET[...]` without `htmlspecialchars` (XSS)

**Android / iOS**
- Hardcoded API keys and credentials in source or manifest
- Insecure data storage (world-readable files, unencrypted SharedPreferences)
- Exported components without permission enforcement
- WebView JavaScript bridge exposure
- App Transport Security (ATS) disabled
- Weak `NSURLSession` TLS configuration

---

## Dependency & CVE Scanning

Argus scans package manifests for known vulnerabilities using multiple tools:

| Tool | What It Scans | Coverage |
|---|---|---|
| pip-audit | `requirements*.txt`, `pyproject.toml` | Python packages → CVE database |
| npm/pnpm audit | `package-lock.json`, `pnpm-lock.yaml` | Node.js packages → npm advisory database |
| grype | `pom.xml`, `build.gradle`, `Cargo.toml`, `go.mod`, `Cargo.lock`, `go.sum` | Java, Rust, Go → Anchore/NVD CVE database |

Findings include CVE ID, affected package version, severity, and the minimum safe version to upgrade to.

---

## CI/CD & Supply Chain Analysis

Argus reads CI/CD pipeline definitions and checks for configurations that could allow an attacker to inject malicious code into the build process or exfiltrate secrets.

### Platforms Covered

| Platform | Config File |
|---|---|
| GitHub Actions | `.github/workflows/*.yml` |
| GitLab CI | `.gitlab-ci.yml` |
| CircleCI | `.circleci/config.yml` |
| Jenkins | `Jenkinsfile` |
| Azure Pipelines | `azure-pipelines*.yml` |
| Bitbucket Pipelines | `bitbucket-pipelines.yml` |
| Travis CI | `.travis.yml` |

### What Is Checked

**GitHub Actions**
- Actions pinned to mutable version tags (`@v3`) rather than immutable commit SHAs — a compromised tag can silently replace the action code
- Excessive workflow permissions (`contents: write` when not needed)
- Secrets referenced inside `run:` steps where they may appear in build logs
- Script injection via untrusted PR event data (`github.event.pull_request.head.ref`, `github.head_ref`)

**GitLab CI**
- Base images using `:latest` tag (no reproducible version pin)
- Hardcoded credentials in the global `variables:` block
- Unverified external `include:` URLs

**CircleCI**
- Orbs using `@dev:` or `@volatile` channels (unstable, can be silently replaced)
- Machine executor images tagged `:latest`

**Jenkins**
- `agent any` broadening the execution surface
- `withCredentials` binding secrets into shell environment (verbose logging risk)
- Unsanitized `params.*` in `sh`/`bat` steps (command injection)

**Azure Pipelines**
- Tasks using `@latest` or floating major versions instead of pinned minor versions
- Variables exposed to untrusted pull request branches

**All platforms**
- Unpinned Python dependencies (no `==` version pin in `requirements.txt`)
- Unpinned npm dependencies (`^` or `~` version ranges in `package.json`)

---

## Infrastructure & Configuration Analysis

Argus reviews framework settings, Docker configurations, and environment templates for insecure defaults.

### Web Frameworks
- `DEBUG=True` in production (Python/Django/Flask — exposes interactive debugger enabling RCE)
- `ALLOWED_HOSTS=['*']` (Django — accepts requests for any hostname)
- Hardcoded `SECRET_KEY`
- Missing CSRF middleware
- `allow_origins=["*"]` CORS without credentials restriction
- Missing security response headers: HSTS, Content-Security-Policy, X-Frame-Options, X-Content-Type-Options, Referrer-Policy

### Docker
- Container running as root (no `USER` instruction)
- `COPY . .` including sensitive files (`.env`, private keys)
- Secrets in `ENV` instructions (visible in image layers)
- `FROM image:latest` (non-reproducible builds)
- Unnecessarily exposed ports

### Java / Spring Boot
- Actuator endpoints exposed without authentication (`management.endpoints.web.exposure.include=*`)
- `spring.security.enabled=false`
- Hardcoded datasource passwords in `application.properties`
- H2 console enabled in production
- Remote debug secret set (`spring.devtools.remote.secret`)
- Stack traces returned to clients (`server.error.include-stacktrace=always`)

### JavaScript Frameworks (Next.js, Vite)
- Next.js `dangerouslyAllowSVG` without content disposition
- Wildcard `remotePatterns` allowing arbitrary image hosts
- Missing `X-Frame-Options` / CSP in `headers()`
- Vite `server.cors: true` in production builds
- Secrets baked into bundle via `define`

---

## Secret Detection

Argus runs gitleaks across the entire repository history and working tree to detect:

- API keys and tokens (AWS, GCP, GitHub, Slack, Stripe, and dozens of other providers)
- SSH and RSA private keys
- PGP private keys
- Database connection strings with embedded credentials
- JWT tokens
- Generic high-entropy strings matching secret patterns

---

## How Findings Are Delivered

Each scan produces two report files:

**Markdown report** — machine-readable, renderable in GitHub, Notion, or any Markdown viewer. Contains:
- Executive summary with severity counts
- Risk summary table: priority rank, finding ID, title, file, line, severity, source, and remediation effort estimate (low / medium / high)
- Prioritized remediation task list ordered by severity × ease-of-fix
- Detailed findings with: vulnerable code excerpt, corrected code snippet, and one-sentence explanation of why the fix works

**HTML report** — self-contained, single-file, viewable in any browser. Contains the same content with visual severity badges and structured navigation.

### Severity Levels

| Level | Meaning |
|---|---|
| 🔴 Critical | Exploitable remotely with high impact (RCE, full data breach) |
| 🟠 High | Significant risk requiring prompt remediation |
| 🟡 Medium | Real vulnerability but limited exploitability or impact |
| 🟢 Low | Best practice deviation or defense-in-depth improvement |

### Effort Estimates

Each finding is assigned a remediation effort:

- **Low** — under one hour (e.g., change a boolean, switch to parameterized query)
- **Medium** — one to four hours (e.g., replace a hashing library and migrate data)
- **High** — more than four hours (e.g., redesign an authentication flow)

Priority ordering uses both dimensions: a Critical/Low finding (severe but easy to fix) ranks above a Critical/High finding (equally severe but expensive to remediate).

---

## Scanning Pipeline Overview

A scan runs a coordinated pipeline of stages:

1. **Clone** — shallow clone of the repository (supports public and private repos via token auth)
2. **File Discovery** — enumerate all source files; pre-sort by security relevance for large repos
3. **Triage** — for repos with more than 60 source files, an LLM selects the 60 most security-relevant files; skipped automatically on small repos
4. **Per-File Code Analysis** — each selected file analyzed in parallel (up to 20 concurrent) by an LLM security reviewer
5. **Config Gathering** — collect all infrastructure and CI/CD configuration files
6. **Scanner Suite** — run all automated tools concurrently (gitleaks, semgrep, gosec, cppcheck, grype, pip-audit, mobsfscan)
7. **Scanner Compression** — distill raw tool output into structured findings
8. **Config Analysis** — LLM reviews infrastructure and CI/CD configs
9. **Synthesis** — deduplicate and merge findings from all seven sources into a unified list; includes prior-scan context for trend awareness
10. **Prioritization** — rank findings by severity and remediation effort
11. **Validation** — independent LLM judge rejects false positives; consults rolling false-positive memory from prior scans
12. **Report Generation** — produce the final Markdown and HTML report with trend delta vs. prior scan
13. **Post-Run Self-Analysis** — a separate judge stage reviews the completed run transcript and suggests prompt improvements for the next scan

Typical scan time: 3–8 minutes depending on repo size and model availability.

---

## Continuous Scanning and Automation

Argus is designed to run repeatedly — not just on demand. Each scan compares against the prior one, so engineering teams see whether their security posture is improving over time.

### Scheduled and Webhook-Triggered Scans

Both workflow specs declare triggers in their YAML:

```yaml
triggers:
  - type: cron
    schedule: "0 2 * * 1"    # 2am UTC every Monday
  - type: webhook
    path: /webhook/repo-scan
```

Running `armature watch workflows/repo-scan.yaml` starts a daemon that fires the scan on schedule and on every `POST /webhook/repo-scan` call — no orchestration infrastructure required. A CI step, a GitHub Actions workflow, or a merge-queue hook can POST to that endpoint to trigger a scan on every meaningful code change.

### Trend Reporting

Every report includes a one-line trend comparison against the prior scan:

> Trend vs. prior scan: **-3 net change** (14 findings previously, 11 now).

The Scan Metadata section records prior scan severity counts, so reviewers can confirm that critical issues are being resolved rather than accumulating. On the first scan there is no baseline and the trend line is omitted; it appears automatically from the second run onward without any configuration.

### Rolling False-Positive Memory

The validation stage remembers which finding IDs were flagged as false positives in prior scans (up to the last 10 runs). This prevents the same false alarm from appearing in every report. The memory is per-repository and per-scan-type — separate from the trend tracking.

---

## Sandboxed Execution

Both workflow specs declare a Docker sandbox:

```yaml
sandbox:
  mode: docker
  allow_network: true     # scanner tools fetch vulnerability DB updates
  cpu_limit: "2.0"
  memory_limit: "2g"
  timeout_s: 600.0
  host_workspace: ./argus-workspace
```

This bounds the resource consumption of a scan to two cores and two gigabytes regardless of repository size or what the repository's code does. Multiple concurrent scans running on the same host do not starve each other. The sandbox configuration lives in the spec file, so resource limits are reviewed and version-controlled alongside the workflow definition itself.

---

## Built on Armature

Argus is a reference implementation for [Armature](https://github.com/bryansparks/armature), a YAML-first harness for multi-agent LLM workflows. The table below maps each Argus capability to the Armature primitive that implements it.

| Argus Capability | Armature Primitive | Where in the Spec |
|---|---|---|
| Parallel per-file code analysis (up to 20 files concurrently) | `fan_out:` + `partition_source:` | `analyze_file` stage |
| Automatic fan-in — merge all per-file results into one list | `fan_in: list` + `aggregate_findings` tool | `aggregate_code_findings` stage |
| Structured JSON output from every LLM stage | `output_mode: guided_json` + `output_schema:` | All analysis stages |
| Independent judge stage that rejects false positives | `role.type: judge` | `validate_findings` stage |
| Rolling false-positive memory across runs | `memory:` block with `capture:` and `max_entries:` | Top-level spec |
| Trend reporting — carry forward severity counts to the next run | `continuation:` block with `carry_forward:` keys | Top-level spec |
| Scheduled scans (weekly cron) | `triggers:` with `type: cron` | Top-level spec |
| Webhook-triggered scans from CI | `triggers:` with `type: webhook` | Top-level spec |
| Resource-bounded execution | `sandbox:` with `cpu_limit:` and `memory_limit:` | Top-level spec |
| Automatic retry on LLM output schema failure | `on_fail: loop:` with `max:` | `config_analysis`, `validate_findings` stages |
| Skip expensive triage on small repos | `skip_if:` Jinja2 condition | `triage_files` stage |
| Context isolation — each stage sees only what it needs | `signature: input:` scoping | All multi-source stages |
| Post-run self-analysis of scan quality | `post_run: true` | `self_analyst` stage |
| Fail-safe value instead of crash on triage failure | `fail_as_value: true` | `triage_files` stage |
| Resume interrupted scans from the last completed stage | `checkpoint: true` | Top-level spec |
| Declarative tool safety — fail-closed, allow-listed | `safety_mode: strict` + `safety_rules:` | Top-level spec |
| Pluggable scanner tools registered from a Python module | `tools: - module:` | `argus.tools.scanners`, `argus.tools.files` |

### What This Means for Agentic Teams

Every behavior in the table above is declared in a YAML spec file — not scattered across Python orchestration code. A security engineer can read the spec and understand exactly what the agent is allowed to do, how it handles failures, what data each stage can see, and how it learns from prior runs. A new team member can contribute a scan rule by editing the YAML without touching the harness code.

That is the central argument for Armature: complex agentic behavior should be auditable, not emergent.
