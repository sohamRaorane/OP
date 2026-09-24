"""Repository domain models — Phase 1."""

from __future__ import annotations

import hashlib
import uuid
from datetime import UTC, datetime
from enum import Enum
from pathlib import Path

from pydantic import BaseModel, Field, field_validator


class FileChangeType(str, Enum):
    ADDED = "ADDED"
    MODIFIED = "MODIFIED"
    DELETED = "DELETED"
    RENAMED = "RENAMED"
    COPIED = "COPIED"
    UNMERGED = "UNMERGED"
    TYPE_CHANGED = "TYPE_CHANGED"


class Repository(BaseModel):
    """A tracked Git repository."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    path: str = Field(description="Absolute path to repository root")
    name: str = Field(description="Repository name (directory basename)")
    remote_url: str | None = Field(default=None)
    default_branch: str | None = Field(default=None)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    @field_validator("path")
    @classmethod
    def validate_path(cls, v: str) -> str:
        p = Path(v)
        if not p.is_absolute():
            raise ValueError("Repository path must be absolute")
        return str(p.resolve())


class RepositorySnapshot(BaseModel):
    """Point-in-time view of repository Git state."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    repository_id: str
    branch: str | None = Field(description="Current branch, None if detached HEAD")
    head_commit: str | None = Field(description="HEAD commit SHA, None for empty repo")
    is_detached: bool = Field(default=False)
    is_dirty: bool = Field(description="Whether working tree has changes")
    staged_files: list[str] = Field(default_factory=list)
    unstaged_files: list[str] = Field(default_factory=list)
    untracked_files: list[str] = Field(default_factory=list)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))


class ChangedFile(BaseModel):
    """A single file within a ChangeSet."""

    path: str = Field(description="Current path (or new path for renames)")
    old_path: str | None = Field(default=None, description="Old path for renames")
    change_type: FileChangeType
    additions: int = Field(default=0, ge=0)
    deletions: int = Field(default=0, ge=0)
    is_binary: bool = Field(default=False)
    is_large: bool = Field(default=False, description="Exceeds max_file_size")
    size_bytes: int | None = Field(default=None)
    # Optional per-file diff snippet (truncated if huge)
    diff_snippet: str | None = Field(default=None)


class ChangeSet(BaseModel):
    """Structured description of what changed in a repository."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    repository_id: str
    baseline_commit: str | None = Field(description="Baseline SHA (None for empty repo)")
    current_commit: str | None = Field(description="Current SHA (None if dirty)")
    branch: str | None = Field(default=None)
    is_detached: bool = Field(default=False)
    generated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    changed_files: list[ChangedFile] = Field(default_factory=list)
    unified_diff: str = Field(default="", description="Full unified diff (size-limited)")
    diff_truncated: bool = Field(default=False)
    summary: dict[str, int | bool] = Field(default_factory=dict)

    @property
    def diff_hash(self) -> str:
        return hashlib.sha256(self.unified_diff.encode("utf-8")).hexdigest()

    @property
    def file_count(self) -> int:
        return len(self.changed_files)

    @property
    def lines_added(self) -> int:
        return sum(f.additions for f in self.changed_files)

    @property
    def lines_removed(self) -> int:
        return sum(f.deletions for f in self.changed_files)

    def to_summary_dict(self) -> dict[str, int | bool]:
        return {
            "files_changed": self.file_count,
            "lines_added": self.lines_added,
            "lines_removed": self.lines_removed,
            "has_binary": any(f.is_binary for f in self.changed_files),
            "has_large": any(f.is_large for f in self.changed_files),
            "has_renames": any(f.change_type == FileChangeType.RENAMED for f in self.changed_files),
            "has_deletions": any(f.change_type == FileChangeType.DELETED for f in self.changed_files),
            "has_additions": any(f.change_type == FileChangeType.ADDED for f in self.changed_files),
            "diff_truncated": self.diff_truncated,
        }
