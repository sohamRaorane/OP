"""Immutable audit service — Phase 11."""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime

from sqlalchemy.orm import Session

from sentinel.core.models.audit import AuditEvent, AuditEventType
from sentinel.repository.orm import AuditEventORM


class AuditService:
    """Append-only audit store."""

    def __init__(self, db: Session | None = None) -> None:
        self.db = db

    def log(
        self,
        event_type: AuditEventType,
        payload: dict | None = None,
        actor: str = "system",
        session_id: str | None = None,
        repository_id: str | None = None,
        changeset_id: str | None = None,
        decision_id: str | None = None,
        correlation_id: str | None = None,
    ) -> AuditEvent:
        event = AuditEvent(
            id=str(uuid.uuid4()),
            timestamp=datetime.now(UTC),
            actor=actor,
            session_id=session_id,
            repository_id=repository_id,
            changeset_id=changeset_id,
            decision_id=decision_id,
            event_type=event_type,
            payload=payload or {},
            correlation_id=correlation_id,
        )
        if self.db is not None:
            orm = AuditEventORM(
                id=event.id,
                timestamp=event.timestamp,
                actor=event.actor,
                session_id=event.session_id,
                repository_id=event.repository_id,
                changeset_id=event.changeset_id,
                decision_id=event.decision_id,
                event_type=event.event_type.value,
                payload_json=json.dumps(event.payload),
                correlation_id=event.correlation_id,
            )
            self.db.add(orm)
            self.db.commit()
        return event

    def query(
        self,
        db: Session,
        repository_id: str | None = None,
        changeset_id: str | None = None,
        event_type: AuditEventType | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[AuditEvent]:
        q = db.query(AuditEventORM).order_by(AuditEventORM.timestamp.desc())
        if repository_id:
            q = q.filter(AuditEventORM.repository_id == repository_id)
        if changeset_id:
            q = q.filter(AuditEventORM.changeset_id == changeset_id)
        if event_type:
            q = q.filter(AuditEventORM.event_type == event_type.value)
        rows = q.offset(offset).limit(limit).all()
        return [
            AuditEvent(
                id=r.id,
                timestamp=r.timestamp,
                actor=r.actor,
                session_id=r.session_id,
                repository_id=r.repository_id,
                changeset_id=r.changeset_id,
                decision_id=r.decision_id,
                event_type=AuditEventType(r.event_type),
                payload=json.loads(r.payload_json) if r.payload_json else {},
                correlation_id=r.correlation_id,
            )
            for r in rows
        ]
