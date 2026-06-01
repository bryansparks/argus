"""Argus behavior registry for trace-triggered reactive logic.

Provides built-in behavior rules that fire after a scan run completes,
based on patterns in the recent trace history.

Usage:
    from argus.behaviors import create_default_registry
    registry = create_default_registry()
    harness = Harness.from_spec("workflows/repo-scan.yaml", behavior_registry=registry)
"""
from __future__ import annotations

from armature.hooks.lifecycle import BehaviorRule, BehaviorRegistry


def create_default_registry() -> BehaviorRegistry:
    """Create a BehaviorRegistry with Argus default behaviors."""
    registry = BehaviorRegistry()

    # Built-in ihr_feedback fires automatically when harness initializes
    # This is registered by Armature core, so we don't duplicate it here.

    # Alert on failure spike: page when failure rate exceeds 30% over last 20 traces
    registry.register(BehaviorRule(
        name="argus_failure_spike_alert",
        description="Alert when scanner failure rate exceeds 30% over last 20 traces",
        pattern=lambda traces: (
            len(traces) >= 20
            and sum(1 for t in traces[-20:] if not t.success) / 20 > 0.30
        ),
        handler=lambda traces: _print_failure_alert(traces),
    ))

    # Alert on quality degradation: IHR dropped by >0.15 compared to 10 runs ago
    registry.register(BehaviorRule(
        name="argus_quality_degradation_alert",
        description="Alert when IHR drops significantly compared to recent history",
        pattern=lambda traces: (
            len(traces) >= 10
            and len(traces) >= 2
            and (traces[-1].ihr or 0) < (traces[-10].ihr or 0) - 0.15
        ),
        handler=lambda traces: _print_degradation_alert(traces),
    ))

    # Suggest improvement when IHR is critically low (<0.60)
    registry.register(BehaviorRule(
        name="argus_critical_ihr_suggest",
        description="Suggest armature improve when IHR is critically low",
        pattern=lambda traces: len(traces) >= 3 and (traces[-1].ihr or 0) < 0.60,
        handler=lambda traces: _print_critical_ihr_suggestion(traces),
    ))

    return registry


def _print_failure_alert(traces: list) -> None:
    """Print alert for high failure rate."""
    recent_failures = sum(1 for t in traces[-20:] if not t.success)
    print(f"\n⚠️  ALERT: High failure rate detected — {recent_failures}/20 runs failed (30%+ threshold)")
    print("   Consider investigating scanner tool stability or spec configuration.")


def _print_degradation_alert(traces: list) -> None:
    """Print alert for IHR degradation."""
    current_ihr = traces[-1].ihr or 0
    baseline_ihr = traces[-10].ihr or 0
    drop = baseline_ihr - current_ihr
    print(f"\n⚠️  ALERT: Quality degradation detected — IHR dropped by {drop:.2f}")
    print(f"   Current IHR: {current_ihr:.2f}, Baseline (10 runs ago): {baseline_ihr:.2f}")
    print("   Consider running `armature improve` to analyze and fix quality issues.")


def _print_critical_ihr_suggestion(traces: list) -> None:
    """Print suggestion to run improve when IHR is critically low."""
    current_ihr = traces[-1].ihr or 0
    print(f"\n⚠️  CRITICAL: Very low IHR detected ({current_ihr:.2f})")
    print("   Strongly recommend running: armature improve workflows/repo-scan.yaml")
    print("   to analyze failure patterns and propose spec improvements.")
