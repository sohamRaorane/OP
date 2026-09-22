"""Audit domain models — Phase 11."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum

from pydantic import BaseModel, Field


class AuditEventType(str, Enum):
    SESSION_CREATED = "session_created"
    REPOSITORY_INSPECTED = "repository_inspected"
    AGENT_STARTED = "agent_started"
    CHANGE_GENERATED = "change_generated"
    VALIDATION_STARTED = "validation_started"
    VALIDATION_COMPLETED = "validation_completed"
    SECURITY_FINDING_CREATED = "security_finding_created"
    JEV_REQUEST = "jev_request"
    JEV_RESPONSE = "jev_response"
    RISK_ASSESSMENT = "risk_assessment"
    POLICY_EVALUATION = "policy_evaluation"
    DECISION_CREATED = "decision_created"
    APPROVAL_REQUESTED = "approval_requested"
    APPROVAL_GRANTED = "approval_granted"
    APPROVAL_REJECTED = "approval_rejected"
    ROLLBACK = "rollback"
    AGENT_RETRY = "agent_retry"
    ERROR = "error"


class AuditEvent(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    actor: str = Field(default="system")
    session_id: str | None = Field(default=None)
    repository_id: str | None = Field(default=None)
    changeset_id: str | None = Field(default=None)
    decision_id: str | None = Field(default=None)
    event_type: AuditEventType
    payload: dict = Field(default_factory=dict)
    correlation_id: str | None = Field(default=None)
