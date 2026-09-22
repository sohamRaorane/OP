"""Decision domain models — Phase 8."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum

from pydantic import BaseModel, Field


class DecisionAction(str, Enum):
    ACCEPT = "ACCEPT"
    REVISE = "REVISE"
    REJECT = "REJECT"
    REQUIRE_HUMAN_REVIEW = "REQUIRE_HUMAN_REVIEW"
    BLOCK = "BLOCK"


class Decision(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    changeset_id: str | None = Field(default=None)
    action: DecisionAction
    reason: str
    risk_level: str | None = Field(default=None)
    # Evidence references
    validation_ids: list[str] = Field(default_factory=list)
    security_finding_ids: list[str] = Field(default_factory=list)
    jev_evaluation_id: str | None = Field(default=None)
    risk_assessment_id: str | None = Field(default=None)
    policy_evaluation_id: str | None = Field(default=None)
    triggered_policies: list[str] = Field(default_factory=list)
    # Versioning for reproducibility
    engine_version: str = Field(default="1.0.0")
    policy_version: str = Field(default="1.0.0")
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    # Extra trace
    trace: list[str] = Field(default_factory=list)
