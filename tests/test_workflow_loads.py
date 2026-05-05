from pathlib import Path
from armature.spec.loader import load_spec

WORKFLOW = Path(__file__).parent.parent / "workflows" / "repo-scan.yaml"


def test_workflow_yaml_exists():
    assert WORKFLOW.exists(), f"Workflow not found at {WORKFLOW}"


def test_workflow_loads_without_error():
    spec = load_spec(WORKFLOW)
    assert spec.name == "repo-security-scan"


def test_workflow_has_required_stages():
    spec = load_spec(WORKFLOW)
    stage_ids = {s.id for s in spec.stages}
    required = {
        "clone_repo", "gather_code", "dependency_scan", "secret_scan",
        "code_analysis", "synthesize_findings", "prioritize_tasks",
        "validate_findings", "human_approval", "generate_report",
    }
    missing = required - stage_ids
    assert not missing, f"Missing stages: {missing}"


def test_workflow_has_safety_rules():
    spec = load_spec(WORKFLOW)
    assert len(spec.safety_rules) >= 2


def test_adapter_stages_have_commands():
    spec = load_spec(WORKFLOW)
    adapter_stages = [s for s in spec.stages if s.adapter]
    for stage in adapter_stages:
        adapter = spec.adapters.get(stage.adapter)
        assert adapter is not None, f"No adapter defined for stage '{stage.id}'"
        assert adapter.cmd, f"Adapter '{stage.adapter}' has no cmd"
