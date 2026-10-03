"""Sandbox tests — Phase 3."""

import subprocess
import tempfile
from pathlib import Path
from typing import Any

import pytest

from sentinel.config.settings import Settings
from sentinel.sandbox.executor import DockerSandboxExecutor, SubprocessFallbackExecutor


def test_subprocess_fallback_success() -> None:
    s = Settings(database_url="sqlite:///:memory:", sentinel_env="development", sandbox_fallback_enabled=True)
    executor = SubprocessFallbackExecutor(settings=s)
    with tempfile.TemporaryDirectory() as d:
        p = Path(d)
        result = executor.execute(["python", "-c", "print('hello')"], workdir=p, timeout=5)
        assert result.exit_code == 0
        assert "hello" in result.stdout
        assert result.timed_out is False


def test_subprocess_fallback_timeout() -> None:
    s = Settings(database_url="sqlite:///:memory:", sentinel_env="development", sandbox_fallback_enabled=True)
    executor = SubprocessFallbackExecutor(settings=s)
    with tempfile.TemporaryDirectory() as d:
        p = Path(d)
        result = executor.execute(["python", "-c", "import time; time.sleep(5)"], workdir=p, timeout=1)
        assert result.timed_out is True


def test_subprocess_fallback_denies_dangerous_command() -> None:
    s = Settings(database_url="sqlite:///:memory:", sentinel_env="development", sandbox_fallback_enabled=True)
    executor = SubprocessFallbackExecutor(settings=s)
    with tempfile.TemporaryDirectory() as d:
        p = Path(d)
        with pytest.raises(Exception):
            executor.execute(["rm", "-rf", "/"], workdir=p)


def test_subprocess_fallback_disabled_in_production() -> None:
    s = Settings(database_url="sqlite:///:memory:", sentinel_env="production", sandbox_fallback_enabled=False)
    executor = SubprocessFallbackExecutor(settings=s)
    assert executor.is_available() is False
    with tempfile.TemporaryDirectory() as d:
        p = Path(d)
        with pytest.raises(Exception):
            executor.execute(["python", "-c", "print(1)"], workdir=p)


def test_docker_unavailable_handling() -> None:
    s = Settings(database_url="sqlite:///:memory:", sentinel_env="testing")
    executor = DockerSandboxExecutor(settings=s)
    # If docker not running, is_available should be False or execute should raise SandboxError
    available = executor.is_available()
    if not available:
        with pytest.raises(Exception):
            with tempfile.TemporaryDirectory() as d:
                p = Path(d)
                executor.execute(["echo", "hello"], workdir=p, timeout=5)
    else:
        # If available, test basic execution (may be skipped)
        pytest.skip("Docker available — skipping unavailable test")


def test_sensitive_mount_denied() -> None:
    s = Settings(database_url="sqlite:///:memory:", sentinel_env="development", sandbox_fallback_enabled=True)
    executor = SubprocessFallbackExecutor(settings=s)
    # Try to execute in sensitive path (home .ssh)
    sensitive = Path.home() / ".ssh"
    if sensitive.exists():
        with pytest.raises(Exception):
            executor.execute(["python", "-c", "print(1)"], workdir=sensitive, timeout=5)


def test_fallback_env_never_has_empty_path(monkeypatch: pytest.MonkeyPatch) -> None:
    """Regression: caller env=None used to produce PATH='' which broke every command on Linux."""
    captured: dict[str, dict[str, str] | None] = {}
    real_run = subprocess.run

    def spy(*args: Any, **kwargs: Any) -> Any:
        captured["env"] = kwargs.get("env")
        return real_run(*args, **kwargs)

    monkeypatch.setattr("sentinel.sandbox.executor.subprocess.run", spy)

    s = Settings(database_url="sqlite:///:memory:", sentinel_env="development", sandbox_fallback_enabled=True)
    executor = SubprocessFallbackExecutor(settings=s)
    with tempfile.TemporaryDirectory() as d:
        executor.execute(["python", "-c", "print('x')"], workdir=Path(d), timeout=10)

    env = captured.get("env")
    assert env is not None, "fallback must pass an explicit env"
    assert env.get("PATH"), "PATH must never be empty — child cannot resolve executables"
    assert env.get("HOME"), "HOME must be set"


def test_fallback_empty_caller_path_falls_back_to_system(monkeypatch: pytest.MonkeyPatch) -> None:
    """Caller explicitly passing PATH='' must still fall back to the host PATH."""
    captured: dict[str, dict[str, str] | None] = {}
    real_run = subprocess.run

    def spy(*args: Any, **kwargs: Any) -> Any:
        captured["env"] = kwargs.get("env")
        return real_run(*args, **kwargs)

    monkeypatch.setattr("sentinel.sandbox.executor.subprocess.run", spy)

    s = Settings(database_url="sqlite:///:memory:", sentinel_env="development", sandbox_fallback_enabled=True)
    executor = SubprocessFallbackExecutor(settings=s)
    with tempfile.TemporaryDirectory() as d:
        executor.execute(["python", "-c", "print('x')"], workdir=Path(d), timeout=10, env={"PATH": ""})

    env = captured.get("env")
    assert env is not None
    assert env.get("PATH"), "explicitly empty caller PATH must fall back to os.environ PATH"
