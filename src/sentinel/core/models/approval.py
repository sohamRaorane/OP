"""Approval domain models — Phase 10."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from enum import Enum

from pydantic import BaseModel, Field


class ApprovalStatus(str, Enum):
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    EXPIRED = "EXPIRED"


class ApprovalDecision(str, Enum):
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"


class ApprovalRequest(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    decision_id: str
    changeset_id: str | None = Field(default=None)
    repository_id: str | None = Field(default=None)
    reason: str
    requested_by: str | None = Field(default=None)
    status: ApprovalStatus = Field(default=ApprovalStatus.PENDING)
    approver: str | None = Field(default=None)
    decided_at: datetime | None = Field(default=None)
    expires_at: datetime | None = Field(default=None)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    # For audit trail: history of status changes
    history: list[dict] = Field(default_factory=list)

    def is_expired(self) -> bool:
        if self.expires_at and datetime.now(UTC) > self.expires_at:
            return True
        return False
