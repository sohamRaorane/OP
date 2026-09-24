"""Risk domain models — Phase 6."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from enum import Enum

from pydantic import BaseModel, Field


class RiskLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class RiskSignal(BaseModel):
    name: str
    value: float | str | bool | None = Field(default=None)
    weight: float = Field(default=1.0)
    is_deterministic: bool = Field(description="True if from deterministic signal")
    evidence: str | None = Field(default=None)
    increased_risk: bool = Field(default=True)


class RiskFactor(BaseModel):
    category: str
    signals: list[RiskSignal] = Field(default_factory=list)
    score_contribution: float = Field(default=0.0)


class RiskAssessment(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    changeset_id: str | None = Field(default=None)
    level: RiskLevel
    score: float = Field(ge=0.0, le=100.0)
    factors: list[RiskFactor] = Field(default_factory=list)
    increasing_signals: list[RiskSignal] = Field(default_factory=list)
    decreasing_signals: list[RiskSignal] = Field(default_factory=list)
    deterministic_signals: list[RiskSignal] = Field(default_factory=list)
    probabilistic_signals: list[RiskSignal] = Field(default_factory=list)
    triggered_policies: list[str] = Field(default_factory=list)
    evidence: list[str] = Field(default_factory=list)
    explanation: str | None = Field(default=None)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    engine_version: str = Field(default="1.0.0")
