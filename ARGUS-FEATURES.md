# Argus Security Scanner — Feature Reference

**Audience:** Engineering management  
**Purpose:** Describes what Argus detects, which languages and platforms it supports, and how findings are delivered.

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
3. **Triage** — for repos with more than 60 source files, an LLM selects the 60 most security-relevant files
4. **Per-File Code Analysis** — each selected file analyzed in parallel by an LLM security reviewer
5. **Config Gathering** — collect all infrastructure and CI/CD configuration files
6. **Scanner Suite** — run all automated tools concurrently (gitleaks, semgrep, gosec, cppcheck, grype, pip-audit, mobsfscan)
7. **Scanner Compression** — distill raw tool output into structured findings
8. **Config Analysis** — LLM reviews infrastructure and CI/CD configs
9. **Synthesis** — deduplicate and merge findings from all sources into a unified list
10. **Prioritization** — rank findings by severity and remediation effort
11. **Validation** — independent LLM review to reject false positives
12. **Report Generation** — produce the final Markdown and HTML report

Typical scan time: 3–8 minutes depending on repo size and model availability.
