# Argus Open Source Readiness Assessment

**Date:** 2026-06-01  
**Armature Version:** 0.3.2 (latest)  
**Argus Version:** 0.1.0 (proposed)

---

## Executive Summary

Argus is **85% ready** for open source release as an Armature project. The core functionality is solid and demonstrates Armature's capabilities well. However, there are several updates needed to align with recent Armature changes and best practices.

### ✅ Ready Now
- MIT License and open source files in place
- Both workflows validate at LOW risk scores (8 and 20)
- Core security scanning pipeline works
- Fan-out/fan-in architecture implemented
- Checkpoint/resume enabled
- Safety mode strict with explicit allow rules

### ⚠️ Needs Updates
- **IHR → HQS renaming** (Armature 0.3.2 breaking change)
- **Post-run stage transcript overflow** (validator warning)
- **Missing `mission:` field** for long-horizon context
- **No `loop_iteration` usage** for iterative refinement
- **No `response_stage: true`** for streaming output
- **Dependency on `armature` package** (not `armature-agents`)

---

## Required Changes

### 1. IHR → HQS Renaming (Breaking)

Armature 0.3.2 renamed `IHR` (Implicit Harness Rating) to `HQS` (Harness Quality Score) to avoid collision with the unrelated "Intelligent Harness Runtime" from NLAH research.

**Files to update:**

| File | Changes |
|------|---------|
| `argus/behaviors.py` | Rename `ihr` → `hqs`, update docstrings |
| `argus/report_html.py` | Update any IHR references |
| `README.md` | Update documentation references |
| `workflows/*.yaml` | Update any template references |

**Code changes:**
```python
# argus/behaviors.py - BEFORE
pattern=lambda traces: len(traces) >= 3 and (traces[-1].ihr or 0) < 0.60

# AFTER
pattern=lambda traces: len(traces) >= 3 and (traces[-1].hqs or 0) < 0.60
```

---

### 2. Post-Run Stage Transcript Overflow (Warning)

**Current validator warning:**
```
[POST_RUN_TRANSCRIPT_OVERFLOW_RISK] stage='self_analyst': 
Stage 'self_analyst' is a post_run stage with no signature.input filter. 
This workflow has fan_out stages, so _transcript will be very large and 
may exceed the model's context limit.
```

**Fix:** Add `signature.input` to `self_analyst` stages:

```yaml
- id: self_analyst
  post_run: true
  signature:
    input:
      _transcript: Full run transcript
      _diagnostics: Run failure signatures
      synthesize_findings.total_count: Total findings count
      validate_findings.confidence: Validator confidence
      run_scanners: Raw scanner output summary
  role:
    name: Self-Analyst
    # ... rest unchanged
```

---

### 3. Add `mission:` Field (Recommended)

Armature 0.3.0 added the `mission:` field for long-horizon context injection. This automatically injects the workflow's goal into every LLM stage's system prompt.

**Add to both workflow specs:**

```yaml
name: repo-security-scan
version: "1.0"
description: "..."
mission: |
  Produce an actionable, prioritized security report that developers can use
  to remediate vulnerabilities. Focus on findings with clear evidence and
  concrete fixes. Flag false positives. Calibrate severity accurately.

model_tiers:
  # ...
```

---

### 4. Update pyproject.toml Dependency

**Current:**
```toml
dependencies = [
    "armature>=0.1.0",
]
```

**Should be:**
```toml
dependencies = [
    "armature-agents>=0.3.2",
]
```

The PyPI package name is `armature-agents`, not `armature`.

---

### 5. Add Iterative Refinement (Optional Enhancement)

Armature 0.3.0 added first-class `loop` iteration support. The `analyze_file` fan-out stage could benefit from iterative refinement for borderline findings:

```yaml
- id: analyze_file
  fan_out: 20
  partition_source: "..."
  loop:
    max_iterations: 2
    until: "{{ len(vulnerabilities) >= 3 }}"
    carry_forward:
      - vulnerabilities
  # ...
```

This would ensure each file analysis produces at least 3 findings before moving on.

---

### 6. Add `response_stage: true` (Optional Enhancement)

For long-running scans, designate `generate_report` as a response stage for streaming output:

```yaml
- id: generate_report
  response_stage: true  # Stream tokens as they're generated
  tool_call:
    name: generate_markdown_report
    args:
      # ...
```

When running via `armature serve`, clients receive SSE events with tokens as they're generated.

---

## Feature Parity Matrix

| Armature Feature | Argus Status | Priority |
|-----------------|--------------|----------|
| Fan-out/fan-in | ✅ Implemented | — |
| Checkpoint/resume | ✅ Implemented | — |
| Memory with staleness | ✅ Implemented | — |
| Safety mode strict | ✅ Implemented | — |
| Behavior registry | ✅ Implemented | — |
| Post-run stages | ✅ Implemented (needs signature fix) | High |
| `mission:` field | ❌ Not used | Medium |
| `continuation:` | ✅ Implemented | — |
| `triggers:` (cron/webhook) | ✅ Implemented | — |
| `sandbox:` (Docker) | ✅ Implemented | — |
| HQS (vs IHR) | ❌ Uses old IHR name | High |
| `loop_iteration` | ❌ Not used | Low |
| `response_stage:` | ❌ Not used | Low |
| Causal 3-tuple attribution | ⚠️ Inherited (no changes needed) | — |
| Editable surfaces | ❌ Not configured | Medium |
| K-proposal diversity | ❌ Not configured | Low |
| Held-out regression gating | ⚠️ Inherited (no changes needed) | — |

---

## Documentation Gaps

### 1. Armature Version Requirement

README should specify:

```markdown
## Requirements

- Python 3.11+
- Armature 0.3.2+ (`pip install armature-agents`)
- External tools: git, gitleaks, semgrep, gosec, cppcheck, pip-audit, grype, lizard
```

### 2. Add "Built with Armature" Badge

```markdown
[![Built with Armature](https://img.shields.io/badge/built%20with-Armature-00A8E8)](https://github.com/bryansparks/armature)
```

### 3. Update Architecture Diagram

Current README describes the pipeline but doesn't mention:
- Continuation for cross-run state
- Triggers for scheduled scans
- Sandbox mode for isolated execution

---

## Testing Checklist

Before releasing:

- [ ] Run `armature validate` on both workflows (no errors, warnings addressed)
- [ ] Test scan against `tests/fixtures/vulnerable-app/`
- [ ] Verify HQS appears in run output (not IHR)
- [ ] Test checkpoint/resume (kill mid-scan, re-run)
- [ ] Test behavior alerts (simulate low HQS)
- [ ] Verify `armature --version` shows correct version
- [ ] Test `armature scan --help` displays correctly

---

## Release Checklist

- [ ] Update `pyproject.toml` version to `0.1.0`
- [ ] Update `CHANGELOG.md` with release date
- [ ] Create GitHub release (v0.1.0)
- [ ] Tag commit: `git tag v0.1.0 && git push --tags`
- [ ] Build package: `python -m build`
- [ ] Publish to PyPI: `twine upload dist/*`
- [ ] Announce on relevant channels (Twitter, LinkedIn, Reddit r/Python, r/Security)

---

## Post-Release Enhancements

### Phase 2 (v0.2.0)
- Add GitHub Actions CI/CD pipeline
- Add test coverage badge
- Implement `loop_iteration` for iterative refinement
- Add `response_stage: true` for streaming
- Create documentation site (mkdocs)

### Phase 3 (v0.3.0)
- Add editable surfaces configuration
- Enable K-proposal diversity for self-improvement
- Add trend analysis across multiple scans
- Integration with GitHub Issues for auto-ticket creation

---

## Conclusion

Argus is a strong candidate for open source release. It demonstrates:
- **Real-world utility** (security scanning is a universal need)
- **Armature capabilities** (fan-out, memory, safety, behaviors)
- **Production readiness** (LOW risk scores, checkpoint/resume)

The required changes are straightforward and can be completed in 1-2 hours. Once updated, Argus will serve as an excellent reference implementation for Armature-based projects.

**Recommendation:** Proceed with release after addressing High Priority items (HQS renaming, post-run signature fix, dependency update).
