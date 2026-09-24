"""Validation domain models — Phase 2."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from enum import Enum

from pydantic import BaseModel, Field


class ValidationStatus(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    TIMEOUT = "TIMEOUT"
    ERROR = "ERROR"
    SKIPPED = "SKIPPED"


class ValidationResult(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    changeset_id: str | None = Field(default=None)
    validator_name: str = Field(description="e.g. pytest, ruff, mypy")
    command: list[str] = Field(description="Executed command as arg list")
    started_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    finished_at: datetime | None = Field(default=None)
    duration_ms: int | None = Field(default=None)
    exit_code: int | None = Field(default=None)
    stdout: str = Field(default="")
    stderr: str = Field(default="")
    stdout_truncated: bool = Field(default=False)
    stderr_truncated: bool = Field(default=False)
    timeout_seconds: int = Field(default=120)
    status: ValidationStatus
    # Parsed findings
    failures: list[str] = Field(default_factory=list, description="Extracted failure summaries")
    summary: str | None = Field(default=None)

    def compute_duration(self) -> None:
        if self.started_at and self.finished_at:
            delta = self.finished_at - self.started_at
            self.duration_ms = int(delta.total_seconds() * 1000)
