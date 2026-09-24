"""JEV domain models — Phase 5."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from enum import Enum

from pydantic import BaseModel, Field


class JevDimension(str, Enum):
    TASK_ALIGNMENT = "task_alignment"
    UNRELATED_CHANGES = "unrelated_changes"
    SECURITY_RISK = "security_risk"
    INTERFACE_COMPATIBILITY = "interface_compatibility"
    DESTRUCTIVE_BEHAVIOR = "destructive_behavior"
    UNNECESSARY_SCOPE = "unnecessary_scope"
    REGRESSION_RISK = "regression_risk"


class JevScore(BaseModel):
    dimension: JevDimension
    score: float = Field(ge=0.0, le=1.0, description="0=safe, 1=risky")
    confidence: float = Field(ge=0.0, le=1.0)
    reasoning: str | None = Field(default=None)


class JevEvaluation(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    changeset_id: str | None = Field(default=None)
    provider: str = Field(default="mock")
    model: str | None = Field(default=None)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    latency_ms: int | None = Field(default=None)
    scores: list[JevScore] = Field(default_factory=list)
    overall_risk: float = Field(ge=0.0, le=1.0, default=0.0)
    summary: str | None = Field(default=None)
    raw_response: dict | None = Field(default=None)
    is_mock: bool = Field(default=True)
    timed_out: bool = Field(default=False)
    is_malformed: bool = Field(default=False)


class JevContext(BaseModel):
    """Minimized context sent to JEV."""

    task: str | None = Field(default=None)
    change_summary: dict | None = Field(default=None)
    changed_files: list[str] = Field(default_factory=list)
    relevant_diff: str | None = Field(default=None)
    diff_truncated: bool = Field(default=False)
    validation_summary: list[dict] | None = Field(default=None)
    security_summary: list[dict] | None = Field(default=None)
    repository_metadata: dict | None = Field(default=None)
    policy_context: dict | None = Field(default=None)
