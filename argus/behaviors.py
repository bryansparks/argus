"""Argus behavior registry for trace-triggered reactive logic.

Note: As of Armature 0.3.0+, behavior registries are created internally by Harness
using make_default_behavior_registry(). Custom behaviors should be registered by:

1. Accessing harness._behaviors after construction, or
2. Extending make_default_behavior_registry() in your own code

This module is kept for reference and future extension.

HQS = Harness Quality Score (renamed from IHR in Armature 0.3.2)
"""
from __future__ import annotations

from armature.hooks.lifecycle import BehaviorRule, BehaviorRegistry


def create_argus_behaviors() -> list[BehaviorRule]:
    """Return a list of Argus-specific behavior rules.

    These can be added to the harness after construction:

        harness = Harness(spec=spec)
        for rule in create_argus_behaviors():
            harness._behaviors.register(rule)
    """
    return [
        # Alert on failure spike: page when failure rate exceeds 30% over last 20 traces
        BehaviorRule(
            name="argus_failure_spike_alert",
            description="Alert when scanner failure rate exceeds 30% over last 20 traces",
            pattern=lambda traces: (
                len(traces) >= 20
                and sum(1 for t in traces[-20:] if not t.success) / 20 > 0.30
            ),
            handler=_print_failure_alert,
        ),
        # Alert on quality degradation: HQS dropped by >0.15 compared to 10 runs ago
        BehaviorRule(
            name="argus_quality_degradation_alert",
            description="Alert when HQS drops significantly compared to recent history",
            pattern=lambda traces: (
                len(traces) >= 10
                and len(traces) >= 2
                and (traces[-1].hqs or 0) < (traces[-10].hqs or 0) - 0.15
            ),
            handler=_print_degradation_alert,
        ),
        # Suggest improvement when HQS is critically low (<0.60)
        BehaviorRule(
            name="argus_critical_hqs_suggest",
            description="Suggest armature improve when HQS is critically low",
            pattern=lambda traces: len(traces) >= 3 and (traces[-1].hqs or 0) < 0.60,
            handler=_print_critical_hqs_suggestion,
        ),
    ]


def _print_failure_alert(traces: list) -> None:
    """Print alert for high failure rate."""
    recent_failures = sum(1 for t in traces[-20:] if not t.success)
    print(f"\n⚠️  ALERT: High failure rate detected — {recent_failures}/20 runs failed (30%+ threshold)")
    print("   Consider investigating scanner tool stability or spec configuration.")


def _print_degradation_alert(traces: list) -> None:
    """Print alert for HQS degradation."""
    current_hqs = traces[-1].hqs or 0
    baseline_hqs = traces[-10].hqs or 0
    drop = baseline_hqs - current_hqs
    print(f"\n⚠️  ALERT: Quality degradation detected — HQS dropped by {drop:.2f}")
    print(f"   Current HQS: {current_hqs:.2f}, Baseline (10 runs ago): {baseline_hqs:.2f}")
    print("   Consider running `armature improve` to analyze and fix quality issues.")


def _print_critical_hqs_suggestion(traces: list) -> None:
    """Print suggestion to run improve when HQS is critically low."""
    current_hqs = traces[-1].hqs or 0
    print(f"\n⚠️  CRITICAL: Very low HQS detected ({current_hqs:.2f})")
    print("   Strongly recommend running: armature improve argus/workflows/repo-scan.yaml")
    print("   to analyze failure patterns and propose spec improvements.")
