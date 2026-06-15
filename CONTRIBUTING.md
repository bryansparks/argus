# Contributing to Argus

Thank you for your interest in contributing to Argus! This document provides guidelines and instructions for contributing.

## What is Argus?

Argus is an automated security and quality scanner for code repositories, built on the [Armature](https://github.com/bryansparks/armature) agentic workflow harness. It combines industry-standard security tools with LLM-based code review to find vulnerabilities and quality issues.

## How to Contribute

### Reporting Bugs

Before creating bug reports, please check existing issues as you might find out you don't need to create one. When creating a bug report, please include:

- **Use a clear and descriptive title**
- **Describe the exact steps to reproduce the problem**
- **Provide specific examples** (commands run, output, error messages)
- **Include your environment details**: Python version, OS, Argus version
- **If possible, include a minimal test case**

Example bug report template:

```markdown
**Description:** Brief description of the bug

**Steps to Reproduce:**
1. Run `argus scan <repo>`
2. Observe error...

**Expected behavior:** What should happen

**Actual behavior:** What actually happens

**Environment:**
- Python: 3.11.x
- OS: macOS 14.x / Ubuntu 22.04 / Windows 11
- Argus version: 0.1.0
```

### Suggesting Enhancements

Enhancement suggestions are welcome! Please include:

- **Use a clear and descriptive title**
- **Provide a detailed description** of the suggested enhancement
- **Explain why this enhancement would be useful**
- **List any similar tools or features** you've seen elsewhere
- **Consider scope**: Is this a small improvement or a major feature?

### Pull Requests

1. **Fork the repository** and create your branch from `main`
2. **If you've added code**, add tests
3. **Ensure the test suite passes**: `pytest`
4. **Make sure your code lints** (if linting is configured)
5. **Write clear commit messages**
6. **Include a description** of what your PR does

### Code Style

- Follow **PEP 8** for Python code
- Use **type hints** for function signatures
- Write **docstrings** for public functions and classes
- Keep functions **focused and small** (ideally < 50 lines)
- Use **descriptive variable names**

### Development Setup

```bash
# Clone your fork
git clone https://github.com/YOUR_USERNAME/argus
cd argus

# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install in development mode
pip install -e ".[dev]"

# Run tests
pytest
```

## Architecture Overview

Argus is built on Armature. Key components:

```
argus/
├── cli.py              # CLI entry point
├── behaviors.py        # Trace-triggered behavior rules
├── report_html.py      # HTML report renderer
└── tools/
    ├── scanners.py     # Security scanner tool
    └── files.py        # File operations (list, read, aggregate)
```

Workflow specs in `argus/workflows/` define the scan pipeline as YAML.

## Areas for Contribution

### High Priority

- **New language support** for security scanning
- **Additional static analysis** tool integrations
- **CI/CD security checks** for more platforms
- **Performance improvements** for large repositories
- **Documentation** improvements and examples

### Medium Priority

- **Custom rule engines** for organization-specific security policies
- **Integration with issue trackers** (GitHub Issues, Jira)
- **Trend analysis** across multiple scans
- **API server mode** for programmatic access

### Always Welcome

- **Bug fixes**
- **Test coverage** improvements
- **Documentation** clarifications
- **Type stub** improvements
- **Refactoring** for clarity and maintainability

## Code of Conduct

### Our Pledge

We as members, contributors, and leaders pledge to make participation in our community a harassment-free experience for everyone, regardless of age, body size, visible or invisible disability, ethnicity, sex characteristics, gender identity and expression, level of experience, education, socio-economic status, nationality, personal appearance, race, religion, or sexual identity and orientation.

### Our Standards

Examples of behavior that contributes to a positive environment:

- Using welcoming and inclusive language
- Being respectful of differing viewpoints and experiences
- Gracefully accepting constructive criticism
- Focusing on what is best for the community
- Showing empathy towards other community members

Examples of unacceptable behavior:

- The use of sexualized language or imagery and unwelcome sexual attention
- Trolling, insulting/derogatory comments, and personal or political attacks
- Public or private harassment
- Publishing others' private information without explicit permission
- Other conduct which could reasonably be considered inappropriate

### Enforcement

Instances of abusive, harassing, or otherwise unacceptable behavior may be reported by opening an issue or contacting the project maintainer. All complaints will be reviewed and investigated promptly and fairly.

## Questions?

Feel free to open an issue for any questions or discussions about contributing.

---

*Argus is licensed under the [MIT License](LICENSE).*
