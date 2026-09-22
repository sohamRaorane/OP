"""Sentinel exception hierarchy."""

from __future__ import annotations


class SentinelError(Exception):
    """Base for all sentinel errors."""


class RepositoryError(SentinelError):
    """Repository / Git related error."""


class GitCommandError(RepositoryError):
    """Git command failed."""

    def __init__(self, message: str, command: list[str] | None = None, exit_code: int | None = None, stderr: str | None = None) -> None:
        super().__init__(message)
        self.command = command
        self.exit_code = exit_code
        self.stderr = stderr


class InvalidRepositoryError(RepositoryError):
    """Path is not a valid Git repository."""


class PathTraversalError(RepositoryError):
    """Path traversal attempt detected."""


class DiffTooLargeError(RepositoryError):
    """Diff exceeds maximum allowed size."""


class FileTooLargeError(RepositoryError):
    """File exceeds maximum allowed size."""


class BinaryFileError(RepositoryError):
    """Binary file handling error."""


class ValidationError(SentinelError):
    """Validation engine error."""


class SandboxError(SentinelError):
    """Sandbox execution error."""


class SecurityError(SentinelError):
    """Security analysis error."""


class JevError(SentinelError):
    """JEV provider error."""


class JevTimeoutError(JevError):
    """JEV request timed out."""


class JevUnavailableError(JevError):
    """JEV provider unavailable."""


class JevMalformedResponseError(JevError):
    """JEV returned malformed response."""


class RiskError(SentinelError):
    """Risk engine error."""


class PolicyError(SentinelError):
    """Policy engine error."""


class DecisionError(SentinelError):
    """Decision engine error."""


class ApprovalError(SentinelError):
    """Approval workflow error."""


class AuditError(SentinelError):
    """Audit system error."""
