"""Sandbox tests — Phase 3."""

import pytest
from pathlib import Path
import tempfile

from sentinel.config.settings import Settings
from sentinel.sandbox.executor import SubprocessFallbackExecutor, DockerSandboxExecutor


def test_subprocess_fallback_success():
    s = Settings(database_url="sqlite:///:memory:", sentinel_env="development", sandbox_fallback_enabled=True)
    executor = SubprocessFallbackExecutor(settings=s)
    with tempfile.TemporaryDirectory() as d:
        p = Path(d)
        result = executor.execute(["python", "-c", "print('hello')"], workdir=p, timeout=5)
        assert result.exit_code == 0
        assert "hello" in result.stdout
        assert result.timed_out is False


def test_subprocess_fallback_timeout():
    s = Settings(database_url="sqlite:///:memory:", sentinel_env="development", sandbox_fallback_enabled=True)
    executor = SubprocessFallbackExecutor(settings=s)
    with tempfile.TemporaryDirectory() as d:
        p = Path(d)
        result = executor.execute(["python", "-c", "import time; time.sleep(5)"], workdir=p, timeout=1)
        assert result.timed_out is True


def test_subprocess_fallback_denies_dangerous_command():
    s = Settings(database_url="sqlite:///:memory:", sentinel_env="development", sandbox_fallback_enabled=True)
    executor = SubprocessFallbackExecutor(settings=s)
    with tempfile.TemporaryDirectory() as d:
        p = Path(d)
        with pytest.raises(Exception):
            executor.execute(["rm", "-rf", "/"], workdir=p)


def test_subprocess_fallback_disabled_in_production():
    s = Settings(database_url="sqlite:///:memory:", sentinel_env="production", sandbox_fallback_enabled=False)
    executor = SubprocessFallbackExecutor(settings=s)
    assert executor.is_available() is False
    with tempfile.TemporaryDirectory() as d:
        p = Path(d)
        with pytest.raises(Exception):
            executor.execute(["python", "-c", "print(1)"], workdir=p)


def test_docker_unavailable_handling():
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


def test_sensitive_mount_denied():
    s = Settings(database_url="sqlite:///:memory:", sentinel_env="development", sandbox_fallback_enabled=True)
    executor = SubprocessFallbackExecutor(settings=s)
    # Try to execute in sensitive path (home .ssh)
    sensitive = Path.home() / ".ssh"
    if sensitive.exists():
        with pytest.raises(Exception):
            executor.execute(["python", "-c", "print(1)"], workdir=sensitive, timeout=5)
