# Changelog

All notable changes to Argus will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.1] - 2026-06-15

### Added
- Published to PyPI as `armature-argus` (`pip install armature-argus`)
- Live Armature workflow view on every scan — shows the workflow's stages,
  model tiers, flags, and per-stage progress, reusing Armature's own renderers
  (screen-only; never written to the report)

### Changed
- Moved workflow specs into the `argus` package (`argus/workflows/`) so they
  ship inside the installed wheel
- README now documents PyPI as the recommended install method and clarifies
  that the Armature harness is pulled in automatically as a dependency

## [Pre-1.0]

### Added
- Armature governance and self-improvement integration
  - Checkpoint/resume for crash recovery
  - `safety_mode: strict` with explicit tool allow rules
  - Memory staleness detection (14-day threshold)
  - `self_analyst` post-run stage for automatic quality review
  - Behavior registry with failure spike and quality degradation alerts
- ISO/IEC 25010 quality assessment workflow profile
- Fan-out/fan-in per-file analysis for unlimited repo sizes
- Triage stage for selecting security-relevant files in large repos
- Cross-run memory for false positive pattern tracking
- HTML report rendering alongside Markdown

### Changed
- README rewritten with comprehensive documentation
- Project licensed under MIT License
- Added standard open source files (CONTRIBUTING, CODE_OF_CONDUCT, SECURITY)

### Fixed
- Validation errors for signature inputs in strict safety mode
- Risk scores reduced to LOW (8 and 20) via strict governance

## [0.1.0] - 2026-06-01

### Added
- Initial release
- Security scanning workflow with 15 stages
- ISO 25010 quality assessment workflow with 14 stages
- Support for 10+ programming languages
- 7 concurrent security scanners (gitleaks, semgrep, gosec, cppcheck, pip-audit, grype, lizard)
- LLM-based code and config analysis
- Prioritized remediation reports with severity badges
- False positive validation stage
- Behavior registry for trace-triggered alerts
- Checkpoint/resume for long-running scans

[Unreleased]: https://github.com/bryansparks/argus/compare/v0.1.1...HEAD
[0.1.1]: https://github.com/bryansparks/argus/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/bryansparks/argus/releases/tag/v0.1.0
