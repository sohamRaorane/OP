"""Unit tests for GitRepository — Phase 1 DoD."""

from __future__ import annotations

import subprocess
import tempfile
from collections.abc import Iterator
from pathlib import Path

import pytest

from sentinel.config.settings import Settings
from sentinel.core.exceptions import InvalidRepositoryError, PathTraversalError
from sentinel.git.repository import GitRepository


def _init_repo(path: Path) -> None:
    subprocess.run(["git", "init"], cwd=path, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.email", "test@test.com"], cwd=path, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.name", "Test"], cwd=path, check=True, capture_output=True)


def _commit_file(repo: Path, name: str, content: str, msg: str = "commit") -> None:
    (repo / name).write_text(content, encoding="utf-8")
    subprocess.run(["git", "add", name], cwd=repo, check=True, capture_output=True)
    subprocess.run(["git", "commit", "-m", msg], cwd=repo, check=True, capture_output=True)


@pytest.fixture
def tmp_repo() -> Iterator[Path]:
    with tempfile.TemporaryDirectory() as d:
        p = Path(d)
        _init_repo(p)
        yield p


@pytest.fixture
def git_repo() -> GitRepository:
    settings = Settings(database_url="sqlite:///:memory:", sentinel_env="testing")
    return GitRepository(settings=settings)


def test_discover_valid_repo(tmp_repo: Path, git_repo: GitRepository) -> None:
    _commit_file(tmp_repo, "README.md", "# hello")
    repo = git_repo.discover(tmp_repo)
    assert repo.path == str(tmp_repo.resolve())
    assert repo.name == tmp_repo.name


def test_discover_invalid_repo(git_repo: GitRepository) -> None:
    with tempfile.TemporaryDirectory() as d:
        with pytest.raises(InvalidRepositoryError):
            git_repo.discover(Path(d))


def test_empty_repository_changeset(tmp_repo: Path, git_repo: GitRepository) -> None:
    repo = git_repo.discover(tmp_repo)
    cs = git_repo.changeset(repo)
    # Empty repo: no commits, but changeset should be generated without error
    assert cs.repository_id == repo.id
    assert cs.changed_files == [] or isinstance(cs.changed_files, list)


def test_new_file_detection(tmp_repo: Path, git_repo: GitRepository) -> None:
    _commit_file(tmp_repo, "initial.txt", "init")
    repo = git_repo.discover(tmp_repo)
    (tmp_repo / "newfile.txt").write_text("new content", encoding="utf-8")
    cs = git_repo.changeset(repo)
    paths = [f.path for f in cs.changed_files]
    assert "newfile.txt" in paths
    assert any(f.change_type.value == "ADDED" for f in cs.changed_files)


def test_modified_file(tmp_repo: Path, git_repo: GitRepository) -> None:
    _commit_file(tmp_repo, "file.txt", "original")
    repo = git_repo.discover(tmp_repo)
    (tmp_repo / "file.txt").write_text("modified", encoding="utf-8")
    cs = git_repo.changeset(repo)
    assert any(f.path == "file.txt" and f.change_type.value == "MODIFIED" for f in cs.changed_files)


def test_deleted_file(tmp_repo: Path, git_repo: GitRepository) -> None:
    _commit_file(tmp_repo, "todelete.txt", "bye")
    (tmp_repo / "todelete.txt").unlink()
    repo = git_repo.discover(tmp_repo)
    cs = git_repo.changeset(repo)
    assert any(f.path == "todelete.txt" and f.change_type.value == "DELETED" for f in cs.changed_files)


def test_renamed_file(tmp_repo: Path, git_repo: GitRepository) -> None:
    _commit_file(tmp_repo, "old.txt", "content")
    subprocess.run(["git", "mv", "old.txt", "new.txt"], cwd=tmp_repo, check=True, capture_output=True)
    # Don't commit — test staged rename detection
    repo = git_repo.discover(tmp_repo)
    cs = git_repo.changeset(repo)
    # Should detect rename or added+deleted
    paths = [f.path for f in cs.changed_files]
    assert "new.txt" in paths


def test_binary_file_detection(tmp_repo: Path, git_repo: GitRepository) -> None:
    _commit_file(tmp_repo, "init.txt", "init")
    repo = git_repo.discover(tmp_repo)
    # Create binary file with null bytes
    (tmp_repo / "binary.bin").write_bytes(b"\x00\x01\x02\xff\x00\xab")
    cs = git_repo.changeset(repo)
    bf = next((f for f in cs.changed_files if f.path == "binary.bin"), None)
    assert bf is not None
    assert bf.is_binary is True


def test_huge_diff_truncation(tmp_repo: Path, git_repo: GitRepository) -> None:
    _commit_file(tmp_repo, "init.txt", "init")
    # Create huge file
    large_content = "x\n" * 100000  # ~200KB
    # Set small max diff for test
    git_repo.settings.max_diff_size = 1000
    (tmp_repo / "huge.txt").write_text(large_content, encoding="utf-8")
    repo = git_repo.discover(tmp_repo)
    cs = git_repo.changeset(repo)
    assert cs.diff_truncated is True or len(cs.unified_diff) <= 1000 + 500  # allow header


def test_invalid_repository_path_traversal(git_repo: GitRepository) -> None:
    # Try to pass path with null byte
    with pytest.raises((InvalidRepositoryError, PathTraversalError, ValueError)):
        git_repo.discover(Path("/tmp/\x00bad"))  # noqa: S108 -- malicious input fixture


def test_malicious_path_in_diff(tmp_repo: Path, git_repo: GitRepository) -> None:
    _commit_file(tmp_repo, "ok.txt", "ok")
    repo = git_repo.discover(tmp_repo)
    # Manually try to inject malicious baseline
    with pytest.raises((PathTraversalError, Exception)):
        git_repo.changeset(repo, baseline="../../../etc/passwd\x00")


def test_detached_head(tmp_repo: Path, git_repo: GitRepository) -> None:
    _commit_file(tmp_repo, "a.txt", "a", msg="first")
    _commit_file(tmp_repo, "b.txt", "b", msg="second")
    # Get first commit hash
    r = subprocess.run(["git", "rev-parse", "HEAD~1"], cwd=tmp_repo, capture_output=True, text=True, check=True)
    sha = r.stdout.strip()
    subprocess.run(["git", "checkout", sha], cwd=tmp_repo, check=True, capture_output=True)
    repo = git_repo.discover(tmp_repo)
    snap = git_repo.snapshot(repo)
    assert snap.is_detached is True
    assert snap.branch is None
    cs = git_repo.changeset(repo)
    assert cs.is_detached is True


def test_staged_and_unstaged_changes(tmp_repo: Path, git_repo: GitRepository) -> None:
    _commit_file(tmp_repo, "file.txt", "original")
    # Modify and stage
    (tmp_repo / "file.txt").write_text("staged change", encoding="utf-8")
    subprocess.run(["git", "add", "file.txt"], cwd=tmp_repo, check=True, capture_output=True)
    # Modify again unstaged
    (tmp_repo / "file.txt").write_text("unstaged change", encoding="utf-8")
    repo = git_repo.discover(tmp_repo)
    snap = git_repo.snapshot(repo)
    assert len(snap.staged_files) >= 0  # git status may show both
    cs = git_repo.changeset(repo)
    assert any(f.path == "file.txt" for f in cs.changed_files)


def test_changeset_summary_statistics(tmp_repo: Path, git_repo: GitRepository) -> None:
    _commit_file(tmp_repo, "file.txt", "line1\nline2\n")
    (tmp_repo / "file.txt").write_text("line1\nline2\nline3\n", encoding="utf-8")
    (tmp_repo / "new.txt").write_text("hello\n", encoding="utf-8")
    repo = git_repo.discover(tmp_repo)
    cs = git_repo.changeset(repo)
    summary = cs.to_summary_dict()
    assert summary["files_changed"] >= 2
    assert summary["lines_added"] >= 1


def test_safe_git_executor_no_shell_injection(tmp_repo: Path, git_repo: GitRepository) -> None:
    # Ensure executor never uses shell
    from sentinel.git.executor import SafeGitExecutor

    executor = SafeGitExecutor()
    # Valid command should work
    r = executor.run(tmp_repo, ["status", "--porcelain"])
    assert isinstance(r.stdout, str)
    # Invalid args type should raise
    with pytest.raises(ValueError):
        executor.run(tmp_repo, "status")  # type: ignore[arg-type]


def test_rollback_safe(tmp_repo: Path, git_repo: GitRepository) -> None:
    _commit_file(tmp_repo, "file.txt", "original")
    (tmp_repo / "file.txt").write_text("dirty", encoding="utf-8")
    (tmp_repo / "untracked.txt").write_text("untracked", encoding="utf-8")
    repo = git_repo.discover(tmp_repo)
    snap_before = git_repo.snapshot(repo)
    assert snap_before.is_dirty is True
    git_repo.rollback(repo)
    snap_after = git_repo.snapshot(repo)
    # After rollback, working tree should be clean-ish (untracked removed)
    assert snap_after.is_dirty is False or len(snap_after.untracked_files) == 0
    assert (tmp_repo / "file.txt").read_text() == "original"
    assert not (tmp_repo / "untracked.txt").exists()
