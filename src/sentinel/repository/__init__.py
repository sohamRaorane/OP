"""Repository package — re-exports GitRepository as default provider."""

from sentinel.git.repository import GitRepository

__all__ = ["GitRepository"]
