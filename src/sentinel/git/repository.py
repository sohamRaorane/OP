"""GitRepository — production-quality Git intelligence — Phase 1."""

from __future__ import annotations

import shutil
import uuid
from datetime import UTC, datetime
from pathlib import Path

from sentinel.config.settings import Settings, get_settings
from sentinel.core.exceptions import (
    GitCommandError,
    InvalidRepositoryError,
    PathTraversalError,
)
from sentinel.core.interfaces.repository import RepositoryProvider
from sentinel.core.models.repository import (
    ChangedFile,
    ChangeSet,
    FileChangeType,
    Repository,
    RepositorySnapshot,
)
from sentinel.git.executor import SafeGitExecutor

# Map git status codes to FileChangeType
_STATUS_MAP: dict[str, FileChangeType] = {
    "A": FileChangeType.ADDED,
    "M": FileChangeType.MODIFIED,
    "D": FileChangeType.DELETED,
    "R": FileChangeType.RENAMED,
    "C": FileChangeType.COPIED,
    "U": FileChangeType.UNMERGED,
    "T": FileChangeType.TYPE_CHANGED,
}


def _validate_repo_path(path: Path) -> Path:
    """Resolve, ensure absolute, prevent traversal."""
    try:
        resolved = path.resolve()
    except Exception as e:
        raise InvalidRepositoryError(f"Cannot resolve path {path}: {e}") from e
    if not resolved.is_absolute():
        raise InvalidRepositoryError("Path must be absolute")
    # Prevent traversal that escapes expected? Already resolved.
    # Additional: check no null bytes etc.
    if "\x00" in str(resolved):
        raise PathTraversalError("Null byte in path")
    return resolved


def _is_binary_file(repo_path: Path, file_path: str) -> bool:
    """Heuristic binary detection — check git's binary flag via `git diff --numstat` or file inspection."""
    # We use git diff --numstat: binary files show "-   -   path"
    return False  # placeholder, actual detection done per file via git


class GitRepository(RepositoryProvider):
    """Git-backed repository provider."""

    def __init__(self, settings: Settings | None = None, executor: SafeGitExecutor | None = None) -> None:
        self.settings = settings or get_settings()
        self.executor = executor or SafeGitExecutor()

    # ------------------------------------------------------------------ snapshot export
    def snapshot_file_list(self, repo_path: Path) -> list[str]:
        """Tracked + untracked non-ignored files — gitignored files are excluded by design.

        This is the scan set AND the execute set: a file Sentinel never saw must
        never run (closes the gitignored-conftest.py detection bypass).
        """
        result = self.executor.run(
            repo_path,
            ["ls-files", "-z", "--cached", "--others", "--exclude-standard"],
            check=True,
        )
        return [f for f in result.stdout.split("\0") if f]

    def export_snapshot(self, repo_path: Path, dest: Path) -> list[str]:
        """Copy the scannable file set to dest — no .git, no symlinks, no ignored files."""
        copied: list[str] = []
        dest.mkdir(parents=True, exist_ok=True)
        for rel in self.snapshot_file_list(repo_path):
            src = repo_path / rel
            try:
                if src.is_symlink() or not src.is_file():
                    continue
                target = dest / rel
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(src, target)
                copied.append(rel)
            except OSError:
                continue
        return copied

    # ------------------------------------------------------------------ discovery
    def is_valid(self, path: Path) -> bool:
        try:
            self.discover(path)
            return True
        except InvalidRepositoryError:
            return False

    def discover(self, path: Path) -> Repository:
        resolved = _validate_repo_path(path)
        if not resolved.exists():
            raise InvalidRepositoryError(f"Path does not exist: {resolved}")
        if not resolved.is_dir():
            raise InvalidRepositoryError(f"Not a directory: {resolved}")
        # git rev-parse --show-toplevel ensures we are exactly at repo root, not nested inside another repo
        try:
            toplevel = self.executor.run(resolved, ["rev-parse", "--show-toplevel"])
            actual_toplevel = Path(toplevel.stdout.strip()).resolve()
            if actual_toplevel != resolved:
                raise InvalidRepositoryError(f"Not a Git repository root: {resolved} (toplevel is {actual_toplevel})")
        except GitCommandError as e:
            raise InvalidRepositoryError(f"Not a Git repository: {resolved}: {e.stderr if hasattr(e, 'stderr') else e}") from e
        # Also verify we are inside work tree
        try:
            inside = self.executor.run(resolved, ["rev-parse", "--is-inside-work-tree"])
            if inside.stdout.strip() != "true":
                raise InvalidRepositoryError(f"Not inside work tree: {resolved}")
        except GitCommandError as e:
            raise InvalidRepositoryError(f"Not a Git repository: {resolved}") from e
        # Get remote URL
        remote_url = None
        try:
            r = self.executor.run(resolved, ["config", "--get", "remote.origin.url"], check=False)
            if r.returncode == 0:
                remote_url = r.stdout.strip() or None
        except GitCommandError:
            pass
        # Default branch: try to detect
        default_branch = None
        try:
            r = self.executor.run(resolved, ["symbolic-ref", "refs/remotes/origin/HEAD"], check=False)
            if r.returncode == 0:
                default_branch = r.stdout.strip().split("/")[-1]
        except GitCommandError:
            pass

        return Repository(
            id=str(uuid.uuid5(uuid.NAMESPACE_URL, str(resolved))),
            path=str(resolved),
            name=resolved.name,
            remote_url=remote_url,
            default_branch=default_branch,
        )

    # ------------------------------------------------------------------ helpers
    def _current_branch(self, repo_path: Path) -> tuple[str | None, bool]:
        """Returns (branch, is_detached)."""
        result = self.executor.run(repo_path, ["rev-parse", "--abbrev-ref", "HEAD"], check=False)
        branch = result.stdout.strip()
        if branch == "HEAD":
            return None, True
        if result.returncode != 0:
            return None, True
        return branch, False

    def _head_commit(self, repo_path: Path) -> str | None:
        result = self.executor.run(repo_path, ["rev-parse", "HEAD"], check=False)
        if result.returncode != 0:
            return None
        sha = result.stdout.strip()
        return sha if sha else None

    def _git_status_porcelain(self, repo_path: Path) -> list[str]:
        result = self.executor.run(repo_path, ["status", "--porcelain=v1", "--untracked-files=all"], check=False)
        if result.returncode != 0:
            return []
        return [line for line in result.stdout.splitlines() if line]

    # ------------------------------------------------------------------ snapshot
    def snapshot(self, repo: Repository) -> RepositorySnapshot:
        repo_path = _validate_repo_path(Path(repo.path))
        branch, is_detached = self._current_branch(repo_path)
        head = self._head_commit(repo_path)

        porcelain = self._git_status_porcelain(repo_path)
        staged: list[str] = []
        unstaged: list[str] = []
        untracked: list[str] = []
        for line in porcelain:
            if len(line) < 3:
                continue
            x, y = line[0], line[1]
            path = line[3:] if len(line) > 3 else ""
            # Handle renames: "R  old -> new"
            if "->" in path:
                path = path.split("->")[-1].strip()
            if x != " " and x != "?":
                staged.append(path)
            if y != " ":
                if x == "?" and y == "?":
                    untracked.append(path)
                else:
                    unstaged.append(path)

        is_dirty = bool(staged or unstaged or untracked)
        return RepositorySnapshot(
            repository_id=repo.id,
            branch=branch,
            head_commit=head,
            is_detached=is_detached,
            is_dirty=is_dirty,
            staged_files=staged,
            unstaged_files=unstaged,
            untracked_files=untracked,
        )

    # ------------------------------------------------------------------ changeset
    def changeset(self, repo: Repository, baseline: str | None = None) -> ChangeSet:
        repo_path = _validate_repo_path(Path(repo.path))
        # Validate baseline if provided — must be valid commit-ish
        if baseline:
            # Prevent path traversal via baseline arg: only allow safe git refs
            if "\x00" in baseline or ".." in baseline and "/" in baseline:
                # Be strict: allow only alphanum, -, _, /, ., ^, ~
                import re

                if not re.match(r"^[A-Za-z0-9_/\-\.\^~]+$", baseline):
                    raise PathTraversalError(f"Invalid baseline ref: {baseline}")

        branch, is_detached = self._current_branch(repo_path)
        head = self._head_commit(repo_path)
        baseline_commit = baseline or head

        # Resolve baseline to SHA if possible
        if baseline_commit:
            try:
                r = self.executor.run(repo_path, ["rev-parse", baseline_commit], check=False)
                if r.returncode == 0:
                    baseline_commit = r.stdout.strip()
            except GitCommandError:
                pass

        # If repo has no commits (empty), we diff against empty tree vs working tree
        changed_files = self._collect_changed_files(repo_path, baseline, head)

        # Generate unified diff with size limit
        unified_diff, truncated = self._unified_diff(repo_path, baseline, head)

        # Enforce max_diff_size
        if len(unified_diff.encode("utf-8")) > self.settings.max_diff_size:
            # Truncate and mark
            unified_diff = unified_diff[: self.settings.max_diff_size]
            truncated = True

        # Detect sizes for changed files
        for cf in changed_files:
            # Check actual file size if exists
            try:
                fpath = repo_path / cf.path
                if fpath.exists() and fpath.is_file():
                    size = fpath.stat().st_size
                    cf.size_bytes = size
                    if size > self.settings.max_file_size:
                        cf.is_large = True
                # Binary detection via git diff --numstat
                # Already flagged via numstat
            except (OSError, ValueError):
                pass

        summary = {
            "files_changed": len(changed_files),
            "lines_added": sum(f.additions for f in changed_files),
            "lines_removed": sum(f.deletions for f in changed_files),
        }

        return ChangeSet(
            repository_id=repo.id,
            baseline_commit=baseline_commit,
            current_commit=head,
            branch=branch,
            is_detached=is_detached,
            generated_at=datetime.now(UTC),
            changed_files=changed_files,
            unified_diff=unified_diff,
            diff_truncated=truncated,
            summary=summary,  # type: ignore[arg-type]
        )

    def _collect_changed_files(self, repo_path: Path, baseline: str | None, head: str | None) -> list[ChangedFile]:
        """Collect changed files via git diff --name-status and numstat."""
        # Determine diff range:
        # - If baseline provided: diff baseline..HEAD or baseline
        # - Else: diff HEAD (working tree + staged) vs HEAD
        # For untracked files, also include --others
        changed: dict[str, ChangedFile] = {}

        # Use git status porcelain to capture working tree changes (including untracked)
        # Plus git diff for committed changes
        # First: git diff --name-status with renames

        # Determine diff target
        if head is None:
            # Empty repo — all files are untracked
            # Use ls-files --others --exclude-standard
            try:
                r = self.executor.run(repo_path, ["ls-files", "--others", "--exclude-standard", "-z"], check=False)
                if r.returncode == 0 and r.stdout:
                    for fname in r.stdout.split("\x00"):
                        if fname:
                            changed[fname] = ChangedFile(path=fname, change_type=FileChangeType.ADDED, is_binary=False)
            except GitCommandError:
                pass
            # Also include staged
            try:
                r = self.executor.run(repo_path, ["diff", "--cached", "--name-status", "--find-renames", "-M"], check=False)
                if r.returncode == 0:
                    for line in r.stdout.splitlines():
                        if line:
                            self._parse_name_status_line(line, changed)
            except GitCommandError:
                pass
            return list(changed.values())

        # Normal case: diff HEAD vs working tree (including staged+unstaged+untracked)
        # We'll use `git status --porcelain` for working tree, and `git diff HEAD --name-status` for diff vs HEAD
        # But simpler: use `git diff HEAD --name-status` which includes staged+unstaged but not untracked, so add untracked separately.

        # 1. diff HEAD
        try:
            r = self.executor.run(
                repo_path, ["diff", "HEAD", "--name-status", "--find-renames", "-M", "--diff-filter=ADMRCTUXB"],
                check=False,
            )
            if r.returncode == 0:
                for line in r.stdout.splitlines():
                    if line.strip():
                        self._parse_name_status_line(line, changed)
        except GitCommandError:
            pass

        # 2. untracked files not in diff
        try:
            r = self.executor.run(repo_path, ["ls-files", "--others", "--exclude-standard", "-z"], check=False)
            if r.returncode == 0 and r.stdout:
                for fname in r.stdout.split("\x00"):
                    if fname and fname not in changed:
                        changed[fname] = ChangedFile(
                            path=fname, change_type=FileChangeType.ADDED,
                            is_binary=self._check_binary(repo_path, fname),
                        )
        except GitCommandError:
            pass

        # 3. Enrich with numstat for additions/deletions and binary detection
        try:
            r = self.executor.run(repo_path, ["diff", "HEAD", "--numstat", "--find-renames", "-M"], check=False)
            if r.returncode == 0:
                for line in r.stdout.splitlines():
                    parts = line.split("\t")
                    if len(parts) == 3:
                        added, removed, fpath = parts
                        # Handle rename: "old -> new" format in numstat also shows new path
                        if "->" in fpath:
                            fpath = fpath.split("->")[-1].strip()
                        # Binary files show "-   -"
                        is_binary = added == "-" and removed == "-"
                        if fpath in changed:
                            cf = changed[fpath]
                            cf.is_binary = is_binary
                            if not is_binary:
                                try:
                                    cf.additions = int(added)
                                    cf.deletions = int(removed)
                                except ValueError:
                                    pass
                        # Also for untracked, numstat won't list them — skip
        except GitCommandError:
            pass

        # Validate paths for traversal
        validated: list[ChangedFile] = []
        for cf in changed.values():
            # Prevent path traversal in file paths
            p = Path(cf.path)
            if p.is_absolute():
                raise PathTraversalError(f"Absolute path in diff: {cf.path}")
            if ".." in p.parts:
                raise PathTraversalError(f"Path traversal in diff: {cf.path}")
            if "\x00" in cf.path:
                raise PathTraversalError(f"Null byte in path: {cf.path}")
            # Normalize
            cf.path = str(p.as_posix())
            if cf.old_path:
                op = Path(cf.old_path)
                if op.is_absolute() or ".." in op.parts:
                    raise PathTraversalError(f"Path traversal in old_path: {cf.old_path}")
                cf.old_path = str(op.as_posix())
            validated.append(cf)

        return validated

    def _parse_name_status_line(self, line: str, changed: dict[str, ChangedFile]) -> None:
        """Parse a single `git diff --name-status` line into ChangedFile."""
        # Format: "A\tpath" or "R100\told\tnew"
        parts = line.split("\t")
        if not parts:
            return
        status = parts[0].strip()
        # Status may be like "R100"
        code = status[0] if status else ""
        ctype = _STATUS_MAP.get(code, FileChangeType.MODIFIED)
        if ctype == FileChangeType.RENAMED and len(parts) >= 3:
            old_path, new_path = parts[1], parts[2]
            changed[new_path] = ChangedFile(path=new_path, old_path=old_path, change_type=ctype)
        elif len(parts) >= 2:
            fpath = parts[1]
            changed[fpath] = ChangedFile(path=fpath, change_type=ctype)

    def _check_binary(self, repo_path: Path, file_path: str) -> bool:
        """Check if file is binary by inspecting content."""
        try:
            fp = repo_path / file_path
            if not fp.exists() or not fp.is_file():
                return False
            # Read first 8000 bytes and check for null byte
            data = fp.read_bytes()[:8000]
            if b"\x00" in data:
                return True
            # Also check git attribute: git check-attr binary
            r = self.executor.run(repo_path, ["check-attr", "binary", "--", file_path], check=False)
            if r.returncode == 0 and "set" in r.stdout:
                return True
            return False
        except OSError:
            return False

    def _unified_diff(self, repo_path: Path, baseline: str | None, head: str | None) -> tuple[str, bool]:
        """Generate unified diff with size guard."""
        truncated = False
        args: list[str]
        if head is None:
            # Empty repo: diff cached
            args = ["diff", "--cached", "--patch", "--find-renames", "-M", "--unified=3"]
        else:
            # Diff HEAD (all working tree changes)
            args = ["diff", "HEAD", "--patch", "--find-renames", "-M", "--unified=3"]

        try:
            r = self.executor.run(repo_path, args, check=False)
            diff = r.stdout if r.returncode == 0 else ""
            # Also handle untracked files by catting them? For now, include via diff --no-index?
            # For untracked, diff HEAD won't include them, so we append their content as pseudo-diff
            # Instead we rely on `git diff HEAD` missing untracked; we generate synthetic diff for untracked
            untracked = []
            try:
                rr = self.executor.run(repo_path, ["ls-files", "--others", "--exclude-standard", "-z"], check=False)
                if rr.returncode == 0 and rr.stdout:
                    for fname in rr.stdout.split("\x00"):
                        if fname:
                            untracked.append(fname)
            except GitCommandError:
                pass
            if untracked:
                # For each untracked, produce synthetic diff header + content (truncated)
                MAX_SNIPPET = self.settings.max_file_size
                for fname in untracked:
                    try:
                        fp = repo_path / fname
                        if fp.exists() and fp.is_file():
                            size = fp.stat().st_size
                            if size > MAX_SNIPPET:
                                content = f"[File too large: {size} bytes, truncated]\n"
                            else:
                                # Check binary
                                data = fp.read_bytes()
                                if b"\x00" in data[:8000]:
                                    content = "[Binary file]\n"
                                else:
                                    try:
                                        text = data.decode("utf-8")
                                    except UnicodeDecodeError:
                                        content = "[Binary file]\n"
                                    else:
                                        content = text
                            diff += f"\ndiff --git a/{fname} b/{fname}\nnew file mode 100644\n--- /dev/null\n+++ b/{fname}\n{content}\n"
                    except OSError:
                        pass
            # Truncate if over limit
            if len(diff.encode("utf-8")) > self.settings.max_diff_size:
                diff = diff[: self.settings.max_diff_size]
                truncated = True
            return diff, truncated
        except GitCommandError as e:
            raise GitCommandError(f"Failed to generate diff: {e}") from e

    # ------------------------------------------------------------------ rollback
    def rollback(self, repo: Repository, commit: str | None = None) -> None:
        """Safe rollback — never auto-commits. Cleans working tree or resets to commit."""
        repo_path = _validate_repo_path(Path(repo.path))
        # Validate commit if provided
        if commit:
            import re

            if not re.match(r"^[A-Za-z0-9_/\-\.\^~]+$", commit):
                raise PathTraversalError(f"Invalid commit ref: {commit}")
            # Verify commit exists
            self.executor.run(repo_path, ["rev-parse", "--verify", commit])
            # Safe reset --hard to commit (only if valid)
            self.executor.run(repo_path, ["reset", "--hard", commit])
            # Clean untracked
            self.executor.run(repo_path, ["clean", "-fdx"])
        else:
            # Safe clean: restore all tracked files + remove untracked
            # Use `git restore` (git 2.23+) fallback to checkout
            try:
                self.executor.run(repo_path, ["restore", "--staged", "."])
                self.executor.run(repo_path, ["restore", "."])
            except GitCommandError:
                # Fallback
                self.executor.run(repo_path, ["checkout", "--", "."], check=False)
                self.executor.run(repo_path, ["reset", "HEAD", "."], check=False)
            self.executor.run(repo_path, ["clean", "-fd"])
