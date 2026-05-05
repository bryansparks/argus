import os
import shutil
import pytest
from pathlib import Path

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

    with patch.object(HumanGateNode, "execute", auto_approve):
        return await harness.run({"repo_url": str(FIXTURE.resolve())})
