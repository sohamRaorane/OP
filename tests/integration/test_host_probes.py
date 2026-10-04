"""Phase 1 gates — no repo code may execute on the host.

Probes (from the security review):
1. A tracked conftest.py that writes a marker must never create that marker on the host.
2. A gitignored conftest.py must never execute at all (it never reaches the sandbox).
3. With Docker unavailable, verify must fail closed to REQUIRE_HUMAN_REVIEW.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

from sentinel.config.settings import Settings
from sentinel.core.service import SentinelService
from sentinel.git.repository import GitRepository
from sentinel.sandbox.executor import DockerSandboxExecutor

MARKER_NAME = "PWNED_MARKER"
GIT_ENV = {
    "PATH": os.environ.get("PATH", ""),
    "HOME": os.environ.get("HOME", ""),
    "GIT_CONFIG_GLOBAL": "NUL" if os.name == "nt" else "/dev/null",
    "GIT_CONFIG_SYSTEM": "NUL" if os.name == "nt" else "/dev/null",
}


def _git(repo: Path, *args: str) -> None:
    subprocess.run(
        ["git", *args],
        cwd=str(repo),
        check=True,
        capture_output=True,
        shell=False,
        env=GIT_ENV,
    )


def _make_repo(tmp_path: Path, *, gitignore_conftest: bool) -> Path:
    """Minimal repo whose conftest.py tries to write a marker in its cwd."""
    repo = tmp_path / ("repo_ignored" if gitignore_conftest else "repo_tracked")
    repo.mkdir()
    _git(repo, "init", "-b", "main")
    (repo / "pyproject.toml").write_text("[project]\nname='probe'\nversion='0'\n", encoding="utf-8")
    (repo / "conftest.py").write_text(
        f"from pathlib import Path\nPath({MARKER_NAME!r}).write_text('pwned', encoding='utf-8')\n",
        encoding="utf-8",
    )
    if gitignore_conftest:
        (repo / ".gitignore").write_text("conftest.py\n", encoding="utf-8")
    _git(repo, "add", "-A")
    _git(
        repo,
        "-c", "user.name=Probe", "-c", "user.email=probe@local",
        "commit", "-m", "probe",
    )
    assert not (repo / MARKER_NAME).exists()
    return repo


def _service(**overrides: object) -> SentinelService:
    kwargs: dict = {
        "database_url": "sqlite:///:memory:",
        "sentinel_env": "testing",
        "jev_enabled": False,
        "docker_enabled": True,
    }
    kwargs.update(overrides)
    return SentinelService(settings=Settings(**kwargs))  # type: ignore[arg-type]


DOCKER_AVAILABLE = DockerSandboxExecutor(settings=Settings(database_url="sqlite:///:memory:")).is_available()


@pytest.mark.skipif(not DOCKER_AVAILABLE, reason="Docker required for sandbox execution probe")
async def test_tracked_malicious_conftest_never_writes_marker_on_host(tmp_path: Path) -> None:
    repo = _make_repo(tmp_path, gitignore_conftest=False)
    service = _service()
    result = await service.verify(repo, task="probe")
    assert not (repo / MARKER_NAME).exists(), "untrusted code executed on the host"
    assert result["decision"].action.value != "ACCEPT"


@pytest.mark.skipif(not DOCKER_AVAILABLE, reason="Docker required for sandbox execution probe")
async def test_gitignored_conftest_never_reaches_execution(tmp_path: Path) -> None:
    repo = _make_repo(tmp_path, gitignore_conftest=True)
    # The file exists on disk but is gitignored — snapshot must exclude it
    listing = GitRepository().snapshot_file_list(repo)
    assert "conftest.py" not in listing, "gitignored file leaked into the snapshot"
    assert ".gitignore" in listing

    service = _service()
    result = await service.verify(repo, task="probe")
    assert not (repo / MARKER_NAME).exists(), "gitignored conftest executed somewhere"
    assert result["decision"].action.value != "ACCEPT"


def test_no_docker_fails_closed_to_human_review(tmp_path: Path) -> None:
    repo = _make_repo(tmp_path, gitignore_conftest=False)
    service = _service(docker_enabled=False)
    result = service.verify_sync(repo, task="probe")
    decision = result["decision"]
    assert decision.action.value == "REQUIRE_HUMAN_REVIEW"
    assert "validation not executed" in decision.reason
    assert not (repo / MARKER_NAME).exists()


def test_docker_unavailable_flag_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """DOCKER_ENABLED=true but daemon down → same fail-closed outcome."""
    repo = _make_repo(tmp_path, gitignore_conftest=False)
    service = _service(docker_enabled=True)
    monkeypatch.setattr(DockerSandboxExecutor, "is_available", lambda self: False)
    results, executed, reason = service._run_validation_sandboxed(repo)  # noqa: SLF001 -- direct unit probe
    assert executed is False
    assert results == []
    assert "Docker unavailable" in reason


def test_export_snapshot_skips_symlinks_and_includes_untracked(tmp_path: Path) -> None:
    repo = _make_repo(tmp_path, gitignore_conftest=False)
    (repo / "untracked_new.py").write_text("x = 1\n", encoding="utf-8")  # untracked, not ignored
    (repo / "ignored.log").write_text("log\n", encoding="utf-8")
    (repo / ".gitignore").write_text("*.log\n", encoding="utf-8")
    if os.name != "nt":
        (repo / "evil_link").symlink_to("/etc/passwd")

    dest = tmp_path / "snap"
    copied = GitRepository().export_snapshot(repo, dest)

    assert "untracked_new.py" in copied
    assert "ignored.log" not in copied
    assert "conftest.py" in copied
    assert not (dest / "ignored.log").exists()
    assert not (dest / ".git").exists()
    if os.name != "nt":
        assert "evil_link" not in copied
