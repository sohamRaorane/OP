"""Validation engine tests — Phase 2."""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from sentinel.config.settings import Settings
from sentinel.core.models.validation import ValidationStatus
from sentinel.validation.engine import ValidationRunner


@pytest.fixture
def runner():
    s = Settings(database_url="sqlite:///:memory:", sentinel_env="testing")
    return ValidationRunner(settings=s)


def test_discover_python_project(runner):
    with tempfile.TemporaryDirectory() as d:
        p = Path(d)
        (p / "test_example.py").write_text("def test_x(): assert 1==1\n")
        validators = runner.discover(p)
        names = [v.name for v in validators]
        assert "pytest" in names or "ruff" in names


def test_detect_project_type(runner):
    with tempfile.TemporaryDirectory() as d:
        p = Path(d)
        (p / "pyproject.toml").write_text("[tool.pytest]\n")
        assert runner.detect_project_type(p) == "python"
        # Node
        with tempfile.TemporaryDirectory() as d2:
            p2 = Path(d2)
            (p2 / "package.json").write_text("{}")
            assert runner.detect_project_type(p2) == "node"


def test_allowlist_blocks_arbitrary_command():
    from sentinel.validation.engine import ValidationRunner, DEFAULT_ALLOWLIST
    from sentinel.validation.validators import CommandValidator

    s = Settings(database_url="sqlite:///:memory:", sentinel_env="testing")
    runner = ValidationRunner(settings=s, allowlist={"pytest"})  # only pytest allowed
    with tempfile.TemporaryDirectory() as d:
        p = Path(d)
        (p / "something.py").write_text("x=1\n")
        # Try to run ruff which is not in allowlist
        from sentinel.validation.validators import RuffValidator

        v = RuffValidator()
        results = runner.run(p, validators=[v])
        assert results[0].status == ValidationStatus.SKIPPED
        assert "allowlist" in results[0].stderr.lower()


def test_validation_run_records_metadata(runner):
    with tempfile.TemporaryDirectory() as d:
        p = Path(d)
        (p / "test_ok.py").write_text("def test_ok(): assert True\n")
        results = runner.run(p)
        for r in results:
            assert r.validator_name
            assert r.command
            assert r.started_at
            assert r.finished_at
            assert r.status in list(ValidationStatus)
            assert r.timeout_seconds > 0


def test_timeout_handling():
    from sentinel.validation.validators import Validator
    from pathlib import Path as _P

    class SleepValidator(Validator):
        name = "sleep"

        def is_applicable(self, repo_path: _P) -> bool:
            return True

        def get_command(self, repo_path: _P) -> list[str]:
            return ["python", "-c", "import time; time.sleep(5)"]

    s = Settings(database_url="sqlite:///:memory:", sentinel_env="testing")
    runner = ValidationRunner(settings=s, allowlist={"python"})
    with tempfile.TemporaryDirectory() as d:
        p = Path(d)
        v = SleepValidator()
        results = runner.run(p, validators=[v], timeout=1)
        assert results[0].status == ValidationStatus.TIMEOUT


def test_output_limits():
    from sentinel.validation.validators import Validator

    class BigOutputValidator(Validator):
        name = "big"

        def is_applicable(self, repo_path: Path) -> bool:
            return True

        def get_command(self, repo_path: Path) -> list[str]:
            return ["python", "-c", "print('x'*2000000)"]

    s = Settings(database_url="sqlite:///:memory:", sentinel_env="testing", max_output_size=1000)
    runner = ValidationRunner(settings=s, allowlist={"python"})
    with tempfile.TemporaryDirectory() as d:
        p = Path(d)
        v = BigOutputValidator()
        results = runner.run(p, validators=[v], timeout=5)
        # Should truncate
        assert len(results[0].stdout.encode("utf-8")) <= 1000 + 10
        assert results[0].stdout_truncated is True or len(results[0].stdout) <= 1000 + 10
