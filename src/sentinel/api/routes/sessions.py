"""Sessions routes — Phase 9."""

import uuid
from datetime import datetime, timezone

from fastapi import APIRouter
from pydantic import BaseModel

router = APIRouter()

# In-memory session store for V1
_sessions: dict[str, dict] = {}


class CreateSessionRequest(BaseModel):
    repository_path: str
    task: str
    agent: str = "generic"


class SessionResponse(BaseModel):
    id: str
    repository_path: str
    task: str
    agent: str
    created_at: str
    status: str


@router.post("/sessions", response_model=SessionResponse)
async def create_session(body: CreateSessionRequest):
    sid = str(uuid.uuid4())
    session = {
        "id": sid,
        "repository_path": body.repository_path,
        "task": body.task,
        "agent": body.agent,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "status": "active",
    }
    _sessions[sid] = session
    return SessionResponse(**session)


@router.get("/sessions/{session_id}", response_model=SessionResponse)
async def get_session(session_id: str):
    s = _sessions.get(session_id)
    if not s:
        from fastapi import HTTPException

        raise HTTPException(status_code=404, detail="Session not found")
    return SessionResponse(**s)


@router.get("/sessions", response_model=list[SessionResponse])
async def list_sessions(limit: int = 20, offset: int = 0):
    items = list(_sessions.values())[offset : offset + limit]
    return [SessionResponse(**s) for s in items]
