"""Policy domain models — Phase 7."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum

from pydantic import BaseModel, Field


class PolicyAction(str, Enum):
    ACCEPT = "ACCEPT"
    REVISE = "REVISE"
    REJECT = "REJECT"
    REQUIRE_HUMAN_REVIEW = "REQUIRE_HUMAN_REVIEW"
    BLOCK = "BLOCK"


class PolicyCondition(BaseModel):
    security_severity: str | None = Field(default=None)
    validation_status: str | None = Field(default=None)
    validator: str | None = Field(default=None)
    file_pattern: str | None = Field(default=None)
    file_count_gt: int | None = Field(default=None)
    file_count_lt: int | None = Field(default=None)
    risk_level: str | None = Field(default=None)
    jev_risk_gt: float | None = Field(default=None)
    migration_detected: bool | None = Field(default=None)
    branch: str | None = Field(default=None)
    repository: str | None = Field(default=None)


class PolicyRule(BaseModel):
    name: str
    when: PolicyCondition = Field(default_factory=PolicyCondition)
    action: PolicyAction
    description: str | None = Field(default=None)
    precedence: int = Field(default=0)


class PolicyResult(BaseModel):
    rule_name: str
    action: PolicyAction
    matched: bool
    reason: str | None = Field(default=None)


class PolicyEvaluation(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    changeset_id: str | None = Field(default=None)
    triggered: list[PolicyResult] = Field(default_factory=list)
    final_action: PolicyAction | None = Field(default=None)
    trace: list[str] = Field(default_factory=list)
    policy_version: str = Field(default="1.0.0")
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
