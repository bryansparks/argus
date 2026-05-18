import os
import sys
import shutil
import pytest
from pathlib import Path

# Ensure the project root is on sys.path so tests run without package installation
_project_root = Path(__file__).parent.parent
if str(_project_root) not in sys.path:
    sys.path.insert(0, str(_project_root))

pytest_plugins = ("anyio",)

FIXTURE = Path(__file__).parent / "fixtures" / "vulnerable-app"
WORKFLOW = Path(__file__).parent.parent / "workflows" / "repo-scan.yaml"


@pytest.fixture(scope="session")
def anyio_backend():
    return "asyncio"


@pytest.fixture(scope="session")
async def argus_scan_results():
    """Run Argus scan once against the vulnerable-app fixture; shared across all e2e tests."""
    if not os.environ.get("ANTHROPIC_API_KEY"):
        pytest.skip("ANTHROPIC_API_KEY not set")
    if not shutil.which("pip-audit"):
        pytest.skip("pip-audit not installed")
    if not shutil.which("gitleaks"):
        pytest.skip("gitleaks not installed")

    from unittest.mock import patch
    from armature.runtime.engine import Harness
    from armature.spec.loader import load_spec
    from armature.nodes.gate import HumanGateNode

    spec = load_spec(WORKFLOW)
    harness = Harness(spec=spec)

    async def auto_approve(self, context):
        return {"approved": True, "feedback": "auto-approved by test"}

    fixture_path = str(FIXTURE.resolve())
    with patch.object(HumanGateNode, "execute", auto_approve):
        return await harness.run({"repo_url": fixture_path, "clone_url": fixture_path})
