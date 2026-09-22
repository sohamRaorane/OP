"""Human approval workflow — Phase 10."""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session

from sentinel.core.exceptions import ApprovalError
from sentinel.core.models.approval import ApprovalRequest, ApprovalStatus


# In-memory store for V1 (persisted to DB in production)
# For now, simple dict + DB mirror
class ApprovalService:
    """Manages approval lifecycle."""

    def __init__(self, expiration_hours: int = 24) -> None:
        self.expiration_hours = expiration_hours
        self._store: dict[str, ApprovalRequest] = {}

    def create_request(
        self,
        decision_id: str,
        changeset_id: str | None = None,
        repository_id: str | None = None,
        reason: str = "Human review required",
        requested_by: str | None = None,
    ) -> ApprovalRequest:
        now = datetime.now(timezone.utc)
        req = ApprovalRequest(
            id=str(uuid.uuid4()),
            decision_id=decision_id,
            changeset_id=changeset_id,
            repository_id=repository_id,
            reason=reason,
            requested_by=requested_by,
            status=ApprovalStatus.PENDING,
            created_at=now,
            expires_at=now + timedelta(hours=self.expiration_hours),
            history=[{"status": ApprovalStatus.PENDING.value, "at": now.isoformat(), "actor": requested_by or "system"}],
        )
        self._store[req.id] = req
        # Also check expiration immediately?
        return req

    def get(self, approval_id: str) -> ApprovalRequest:
        req = self._store.get(approval_id)
        if not req:
            raise ApprovalError(f"Approval {approval_id} not found")
        # Check expiration
        if req.status == ApprovalStatus.PENDING and req.is_expired():
            req.status = ApprovalStatus.EXPIRED
            req.history.append({"status": "EXPIRED", "at": datetime.now(timezone.utc).isoformat(), "actor": "system"})
        return req

    def approve(self, approval_id: str, approver: str) -> ApprovalRequest:
        req = self.get(approval_id)
        if req.status != ApprovalStatus.PENDING:
            raise ApprovalError(f"Cannot approve {approval_id}: status is {req.status.value}, not PENDING")
        if req.is_expired():
            req.status = ApprovalStatus.EXPIRED
            raise ApprovalError(f"Approval {approval_id} expired")
        req.status = ApprovalStatus.APPROVED
        req.approver = approver
        req.decided_at = datetime.now(timezone.utc)
        req.history.append({"status": "APPROVED", "at": req.decided_at.isoformat(), "actor": approver})
        # Immutable: never overwrite history, only append
        return req

    def reject(self, approval_id: str, approver: str, reason: str | None = None) -> ApprovalRequest:
        req = self.get(approval_id)
        if req.status != ApprovalStatus.PENDING:
            raise ApprovalError(f"Cannot reject {approval_id}: status is {req.status.value}")
        if req.is_expired():
            req.status = ApprovalStatus.EXPIRED
            raise ApprovalError(f"Approval {approval_id} expired")
        req.status = ApprovalStatus.REJECTED
        req.approver = approver
        req.decided_at = datetime.now(timezone.utc)
        req.history.append({"status": "REJECTED", "at": req.decided_at.isoformat(), "actor": approver, "reason": reason})
        return req

    def list_pending(self) -> list[ApprovalRequest]:
        return [r for r in self._store.values() if r.status == ApprovalStatus.PENDING and not r.is_expired()]

    def is_approved(self, decision_id: str) -> bool:
        for r in self._store.values():
            if r.decision_id == decision_id and r.status == ApprovalStatus.APPROVED:
                return True
        return False
