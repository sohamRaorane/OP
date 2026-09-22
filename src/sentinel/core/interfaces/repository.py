"""RepositoryProvider interface — Phase 1."""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path

from sentinel.core.models.repository import ChangeSet, Repository, RepositorySnapshot


class RepositoryProvider(ABC):
    """Abstract repository provider."""

    @abstractmethod
    def discover(self, path: Path) -> Repository:
        """Discover and validate a repository at path."""

    @abstractmethod
    def snapshot(self, repo: Repository) -> RepositorySnapshot:
        """Capture current Git state."""

    @abstractmethod
    def changeset(self, repo: Repository, baseline: str | None = None) -> ChangeSet:
        """Generate ChangeSet against baseline (default: HEAD)."""

    @abstractmethod
    def rollback(self, repo: Repository, commit: str | None = None) -> None:
        """Safe rollback to commit or clean working tree."""

    @abstractmethod
    def is_valid(self, path: Path) -> bool:
        """Check if path is a valid repository."""
