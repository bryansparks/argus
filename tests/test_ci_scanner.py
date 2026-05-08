"""Unit tests for non-GitHub CI supply chain scanning and config gathering."""
from __future__ import annotations
import asyncio
import shutil
import pytest
from pathlib import Path

FIXTURE = Path(__file__).parent / "fixtures" / "vulnerable-app"


# ── supply chain scanner ───────────────────────────────────────────────────────

@pytest.mark.skipif(not shutil.which("grep"), reason="grep not available")
def test_supply_chain_scan_returns_all_sections():
    """_supply_chain_scan output must contain section headers for every CI system."""
    from argus.tools.scanners import _supply_chain_scan
    result = asyncio.run(_supply_chain_scan(str(FIXTURE)))
    for section in (
        "GITHUB_UNPINNED_ACTIONS",
        "GITLAB_LATEST_IMAGES",
        "CIRCLECI_ORBS",
        "CIRCLECI_VOLATILE",
        "AZURE_TASK_VERSIONS",
        "JENKINS_RISKS",
        "UNPINNED_PYTHON_DEPS",
    ):
        assert section in result, f"Missing section {section!r} in supply chain output"


@pytest.mark.skipif(not shutil.which("grep"), reason="grep not available")
def test_supply_chain_scan_finds_gitlab_latest_image():
    from argus.tools.scanners import _supply_chain_scan
    result = asyncio.run(_supply_chain_scan(str(FIXTURE)))
    assert "python:latest" in result, (
        "Expected to find 'python:latest' in GitLab CI scan output; "
        f"got: {result[:500]}"
    )


@pytest.mark.skipif(not shutil.which("grep"), reason="grep not available")
def test_supply_chain_scan_finds_circleci_volatile_orb():
    from argus.tools.scanners import _supply_chain_scan
    result = asyncio.run(_supply_chain_scan(str(FIXTURE)))
    assert "@dev:" in result or "volatile" in result.lower(), (
        "Expected to find CircleCI dev/volatile orb in scan output; "
        f"got: {result[:500]}"
    )


# ── gather_config sections ─────────────────────────────────────────────────────

def test_gitlab_ci_fixture_exists():
    assert (FIXTURE / ".gitlab-ci.yml").exists(), ".gitlab-ci.yml fixture missing"


def test_circleci_config_fixture_exists():
    assert (FIXTURE / ".circleci" / "config.yml").exists(), ".circleci/config.yml fixture missing"


def test_gitlab_ci_fixture_has_latest_image():
    content = (FIXTURE / ".gitlab-ci.yml").read_text()
    assert "python:latest" in content, "Fixture should have a :latest image for scanner to catch"


def test_circleci_fixture_has_dev_orb():
    content = (FIXTURE / ".circleci" / "config.yml").read_text()
    assert "@dev:" in content, "Fixture should have a @dev: orb for scanner to catch"
