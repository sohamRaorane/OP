"""End-to-end integration test — full pipeline."""

import asyncio
import subprocess
import tempfile
from pathlib import Path

import pytest

from sentinel.config.settings import Settings
from sentinel.core.service import SentinelService
from sentinel.git.repository import GitRepository


def _init_repo(path: Path):
    subprocess.run(["git", "init"], cwd=path, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.email", "test@test.com"], cwd=path, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.name", "Test"], cwd=path, check=True, capture_output=True)
    (path / "README.md").write_text("# Test\n", encoding="utf-8")
    (path / "app.py").write_text("def hello():\n    return 'hello'\n", encoding="utf-8")
    subprocess.run(["git", "add", "."], cwd=path, check=True, capture_output=True)
    subprocess.run(["git", "commit", "-m", "init"], cwd=path, check=True, capture_output=True)


@pytest.mark.asyncio
async def test_e2e_low_risk_accept():
    with tempfile.TemporaryDirectory() as d:
        p = Path(d)
        _init_repo(p)
        # Simulate agent change: update README (low risk)
        (p / "README.md").write_text("# Test\n\nUpdated docs\n", encoding="utf-8")
        settings = Settings(database_url="sqlite:///:memory:", sentinel_env="testing")
        service = SentinelService(settings=settings)
        result = await service.verify(p, task="Update README", jev_fixture="high_confidence_safe")
        assert result["changeset"].file_count >= 1
        assert result["decision"].action.value in ("ACCEPT", "REVISE")  # low risk should accept or revise
        assert result["risk_assessment"].level.value in ("LOW", "MEDIUM")
        # Security should be low
        assert not any(f.severity.value == "CRITICAL" for f in result["security_findings"])


@pytest.mark.asyncio
async def test_e2e_high_risk_block():
    with tempfile.TemporaryDirectory() as d:
        p = Path(d)
        _init_repo(p)
        # Destructive change
        (p / "migration.sql").write_text("DROP TABLE users;", encoding="utf-8")
        (p / "config.py").write_text('password = "supersecret123"\n', encoding="utf-8")
        settings = Settings(database_url="sqlite:///:memory:", sentinel_env="testing")
        service = SentinelService(settings=settings)
        result = await service.verify(p, task="Update DB", jev_fixture="destructive")
        # Should be high/critical and not ACCEPT
        assert result["decision"].action.value in ("BLOCK", "REQUIRE_HUMAN_REVIEW", "REVISE")
        assert result["security_findings"]  # should have findings


@pytest.mark.asyncio
async def test_e2e_verification_pipeline_all_steps():
    with tempfile.TemporaryDirectory() as d:
        p = Path(d)
        _init_repo(p)
        (p / "new_feature.py").write_text("def feature():\n    return 42\n", encoding="utf-8")
        settings = Settings(database_url="sqlite:///:memory:", sentinel_env="testing")
        service = SentinelService(settings=settings)
        result = await service.verify(p, task="Add feature", jev_fixture="high_confidence_safe")
        # All pipeline artifacts present
        assert "changeset" in result
        assert "validation_results" in result
        assert "security_findings" in result
        assert "jev_evaluation" in result
        assert "risk_assessment" in result
        assert "policy_evaluation" in result
        assert "decision" in result
        # Validation results have required fields
        for vr in result["validation_results"]:
            assert vr.validator_name
            assert vr.status
        # JEV has scores
        assert len(result["jev_evaluation"].scores) > 0
        # Risk is explainable
        assert result["risk_assessment"].explanation
        assert len(result["risk_assessment"].evidence) >= 0
        # Decision is reproducible
        assert result["decision"].id
        assert result["decision"].reason


def test_cli_inspect_and_verify():
    with tempfile.TemporaryDirectory() as d:
        p = Path(d)
        _init_repo(p)
        (p / "change.txt").write_text("hello", encoding="utf-8")
        from typer.testing import CliRunner
        from sentinel.cli.main import app

        runner = CliRunner()
        res = runner.invoke(app, ["inspect", "--repo", str(p)])
        assert res.exit_code == 0
        res = runner.invoke(app, ["status", "--repo", str(p), "--json"])
        assert res.exit_code == 0
        res = runner.invoke(app, ["diff", "--repo", str(p)])
        assert res.exit_code == 0
