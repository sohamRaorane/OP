"""Changes routes — Phase 12."""

from pathlib import Path
from typing import Any

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel

from sentinel.core.service import SentinelService
from sentinel.git.repository import GitRepository

router = APIRouter()


class AnalyzeRequest(BaseModel):
    repository_path: str
    baseline: str | None = None


class VerifyRequest(BaseModel):
    repository_path: str
    task: str | None = None
    jev_fixture: str = "high_confidence_safe"
    baseline: str | None = None


@router.post("/changes/analyze")
async def analyze_changes(body: AnalyzeRequest):
    git = GitRepository()
    try:
        repo = git.discover(Path(body.repository_path))
        changeset = git.changeset(repo, baseline=body.baseline)
        return {
            "changeset": changeset.model_dump(mode="json"),
            "summary": changeset.to_summary_dict(),
            "diff_hash": changeset.diff_hash,
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/changes/verify")
async def verify_changes(body: VerifyRequest):
    service = SentinelService()
    try:
        result = await service.verify(body.repository_path, task=body.task, jev_fixture=body.jev_fixture)
        # Serialize
        return {
            "changeset": result["changeset"].model_dump(mode="json"),
            "validation_results": [r.model_dump(mode="json") for r in result["validation_results"]],
            "security_findings": [f.model_dump(mode="json") for f in result["security_findings"]],
            "jev_evaluation": result["jev_evaluation"].model_dump(mode="json"),
            "risk_assessment": result["risk_assessment"].model_dump(mode="json"),
            "policy_evaluation": result["policy_evaluation"].model_dump(mode="json"),
            "decision": result["decision"].model_dump(mode="json"),
            "approval": result["approval"].model_dump(mode="json") if result["approval"] else None,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/changes")
async def list_changes(repository_path: str = Query(...)):
    # For V1, just return current changeset
    git = GitRepository()
    try:
        repo = git.discover(Path(repository_path))
        cs = git.changeset(repo)
        return {"changeset": cs.model_dump(mode="json")}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
