"""Audit routes — Phase 11."""

from fastapi import APIRouter, Query

router = APIRouter()

# For V1, audit is in-memory if DB not configured
_audit_events: list[dict] = []


@router.get("/audit")
async def list_audit(
    repository_id: str | None = Query(default=None),
    changeset_id: str | None = Query(default=None),
    event_type: str | None = Query(default=None),
    limit: int = Query(default=50, le=200),
    offset: int = Query(default=0),
) -> list[dict]:
    # Try DB first
    try:
        from sentinel.audit.service import AuditService
        from sentinel.core.db import get_session_factory
        from sentinel.core.models.audit import AuditEventType

        Session = get_session_factory()
        evt_type = AuditEventType(event_type) if event_type else None
        with Session() as db:
            svc = AuditService()
            events = svc.query(db, repository_id=repository_id, changeset_id=changeset_id, event_type=evt_type, limit=limit, offset=offset)
            return [e.model_dump(mode="json") for e in events]
    except Exception:
        # Fallback to in-memory
        filtered = _audit_events
        if repository_id:
            filtered = [e for e in filtered if e.get("repository_id") == repository_id]
        if changeset_id:
            filtered = [e for e in filtered if e.get("changeset_id") == changeset_id]
        if event_type:
            filtered = [e for e in filtered if e.get("event_type") == event_type]
        return filtered[offset : offset + limit]


@router.get("/audit/{event_id}")
async def get_audit(event_id: str) -> dict:
    try:
        from sentinel.core.db import get_session_factory
        from sentinel.repository.orm import AuditEventORM

        Session = get_session_factory()
        with Session() as db:
            row = db.query(AuditEventORM).filter(AuditEventORM.id == event_id).first()
            if not row:
                from fastapi import HTTPException

                raise HTTPException(status_code=404, detail="Event not found")
            import json

            return {
                "id": row.id,
                "timestamp": row.timestamp.isoformat(),
                "actor": row.actor,
                "event_type": row.event_type,
                "payload": json.loads(row.payload_json) if row.payload_json else {},
            }
    except Exception as e:
        from fastapi import HTTPException

        raise HTTPException(status_code=404, detail=str(e)) from e
