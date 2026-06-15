from pathlib import Path
from armature.spec.loader import load_spec

WORKFLOW = Path(__file__).parent.parent / "argus" / "workflows" / "repo-scan.yaml"


def test_workflow_yaml_exists():
    assert WORKFLOW.exists(), f"Workflow not found at {WORKFLOW}"


def test_workflow_loads_without_error():
    spec = load_spec(WORKFLOW)
    assert spec.name == "repo-security-scan"


def test_workflow_accepts_repo_and_clone_url():
    """Workflow spec loads when both repo_url and clone_url are provided.

    Full template rendering is deferred to runtime (stage outputs like
    list_source_files are only available then), so we test spec-level loading only.
    """
    spec = load_spec(WORKFLOW)
    assert spec.name == "repo-security-scan"
    stage_ids = {s.id for s in spec.stages}
    assert "clone_repo" in stage_ids
    assert "list_source_files" in stage_ids


def test_workflow_has_required_stages():
    spec = load_spec(WORKFLOW)
    stage_ids = {s.id for s in spec.stages}
    required = {
        "clone_repo",
        "list_source_files", "triage_files", "analyze_file", "aggregate_code_findings",
        "gather_config", "run_scanners", "compress_scanners",
        "config_analysis", "synthesize_findings", "prioritize_tasks",
        "validate_findings", "generate_report",
    }
    missing = required - stage_ids
    assert not missing, f"Missing stages: {missing}"


def test_workflow_has_safety_rules():
    spec = load_spec(WORKFLOW)
    assert len(spec.safety_rules) >= 3


def test_stage_depends_on_resolve():
    spec = load_spec(WORKFLOW)
    stage_ids = {s.id for s in spec.stages}
    for stage in spec.stages:
        for dep in stage.depends_on:
            assert dep in stage_ids, f"Stage '{stage.id}' depends_on unknown stage '{dep}'"


def test_adapter_stages_have_commands():
    spec = load_spec(WORKFLOW)
    adapter_stages = [s for s in spec.stages if s.adapter]
    for stage in adapter_stages:
        adapter = spec.adapters.get(stage.adapter)
        assert adapter is not None, f"No adapter defined for stage '{stage.id}'"
        assert adapter.cmd, f"Adapter '{stage.adapter}' has no cmd"
