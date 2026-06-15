# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

As Argus is pre-1.0, only the latest minor version receives security updates.

## Reporting a Vulnerability

We take the security of Argus seriously. If you believe you have found a security vulnerability, please report it to us as described below.

**Please do NOT report security vulnerabilities through public GitHub issues.**

Instead, please report them via email to [bryan.sparks@gmail.com](mailto:bryan.sparks@gmail.com) with the subject line "Argus Security Vulnerability".

### What to Include

Please include the following information in your report:

- A clear description of the vulnerability
- Steps to reproduce the issue
- The affected version(s) of Argus
- Any potential impact
- If possible, a proof-of-concept or exploit code

### Response Timeline

You should receive a response within 48 hours acknowledging your report. After the initial reply, you will receive regular updates (at least every 7 days) on the progress of our investigation.

### Disclosure Policy

Once a vulnerability is confirmed, we will:

1. Work on a fix and test it thoroughly
2. Publish a new release with the fix
3. Notify the reporter
4. Publish a security advisory on GitHub

We request that you keep the vulnerability confidential until we have published a fix and advisory. We aim to resolve critical vulnerabilities within 30 days of disclosure.

## Security Best Practices for Users

When using Argus, follow these security best practices:

### API Keys and Credentials

- Never commit API keys or credentials to version control
- Use environment variables or a secure config file (`~/.argus/argus.config`)
- Rotate keys regularly
- Use read-only tokens where possible

### Private Repositories

- Argus clones repositories to `/tmp/argus-<run_id>/` for scanning
- The clone is deleted after each scan via the `cleanup` stage
- For highly sensitive code, consider running Argus in an isolated environment

### LLM Provider Selection

- Argus sends code to LLM providers for analysis
- Review your organization's policies on sending code to AI services
- Consider using local models (Ollama) for sensitive codebases
- The `--transcript` option logs full LLM conversations

### Tool Permissions

- Argus runs external tools (`gitleaks`, `semgrep`, `gosec`, etc.)
- Ensure tools are installed from trusted sources
- Review tool versions and update regularly

## Security Features in Argus

Argus includes several built-in security features:

### Safety Rules

The workflow specs enforce safety rules that block:
- Git write operations (push, commit, merge, rebase)
- Destructive shell commands (`rm -rf`)
- Irreversible operations (fail-closed mode with `safety_mode: strict`)

### Behavior Registry

Automatic alerts for:
- High failure rates (>30% over 20 runs)
- Quality degradation (HQS drop >0.15)
- Critically low quality scores (HQS <0.60)

### Checkpoint/Resume

Long scans can resume after crashes without re-exposing sensitive data.

## Vulnerability Disclosure History

| Date       | Version | Description                          | Severity |
| ---------- | ------- | ------------------------------------ | -------- |
| 2026-06-01 | 0.1.0   | Initial security policy established  | -        |

## Acknowledgments

We appreciate security researchers and contributors who help keep Argus safe. Thank you for responsible disclosure!

---

For general security questions, contact [bryan.sparks@gmail.com](mailto:bryan.sparks@gmail.com).
