"""Approvals routes — Phase 10."""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from sentinel.approval.service import ApprovalService

router = APIRouter()

# Singleton for V1
_approval_service = ApprovalService()


class ApprovalRequestBody(BaseModel):
    decision_id: str
    changeset_id: str | None = None
    repository_id: str | None = None
    reason: str = "Human review required"


class ApprovalDecisionBody(BaseModel):
    approver: str
    reason: str | None = None


@router.post("/approvals")
async def create_approval(body: ApprovalRequestBody):
    req = _approval_service.create_request(body.decision_id, body.changeset_id, body.repository_id, body.reason)
    return req.model_dump(mode="json")


@router.get("/approvals/{approval_id}")
async def get_approval(approval_id: str):
    try:
        req = _approval_service.get(approval_id)
        return req.model_dump(mode="json")
    except Exception as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.post("/approvals/{approval_id}/approve")
async def approve(approval_id: str, body: ApprovalDecisionBody):
    try:
        req = _approval_service.approve(approval_id, body.approver)
        return req.model_dump(mode="json")
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/approvals/{approval_id}/reject")
async def reject(approval_id: str, body: ApprovalDecisionBody):
    try:
        req = _approval_service.reject(approval_id, body.approver, body.reason)
        return req.model_dump(mode="json")
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/approvals")
async def list_approvals():
    return [_approval_service.get(k).model_dump(mode="json") for k in list(_approval_service._store.keys())]
