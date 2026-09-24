"""Decisions routes."""

from fastapi import APIRouter, HTTPException

router = APIRouter()

# In-memory decision store mirrors service decisions for V1 API retrieval
_decisions: dict[str, dict] = {}


@router.get("/decisions/{decision_id}")
async def get_decision(decision_id: str) -> dict:
    d = _decisions.get(decision_id)
    if not d:
        raise HTTPException(status_code=404, detail="Decision not found")
    return d


@router.post("/decisions/{decision_id}/approve")
async def approve_decision(decision_id: str, body: dict | None = None) -> dict:
    # Delegates to approval service — for now mark approved
    d = _decisions.get(decision_id)
    if not d:
        raise HTTPException(status_code=404, detail="Decision not found")
    d["approval_status"] = "APPROVED"
    return {"decision_id": decision_id, "status": "APPROVED"}


@router.post("/decisions/{decision_id}/reject")
async def reject_decision(decision_id: str, body: dict | None = None) -> dict:
    d = _decisions.get(decision_id)
    if not d:
        raise HTTPException(status_code=404, detail="Decision not found")
    d["approval_status"] = "REJECTED"
    return {"decision_id": decision_id, "status": "REJECTED"}


@router.post("/decisions/{decision_id}/retry")
async def retry_decision(decision_id: str) -> dict:
    d = _decisions.get(decision_id)
    if not d:
        raise HTTPException(status_code=404, detail="Decision not found")
    d["retry_count"] = d.get("retry_count", 0) + 1
    return {"decision_id": decision_id, "retry_count": d["retry_count"]}
