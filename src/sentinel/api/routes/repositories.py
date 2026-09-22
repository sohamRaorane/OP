"""Repositories routes."""

from pathlib import Path

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from sentinel.git.repository import GitRepository

router = APIRouter()


class RepoInspectRequest(BaseModel):
    path: str


class RepoInspectResponse(BaseModel):
    id: str
    path: str
    name: str
    remote_url: str | None = None
    default_branch: str | None = None
    branch: str | None = None
    head_commit: str | None = None
    is_detached: bool = False
    is_dirty: bool = False


@router.post("/repositories/inspect", response_model=RepoInspectResponse)
async def inspect_repo(body: RepoInspectRequest):
    git = GitRepository()
    try:
        repo = git.discover(Path(body.path))
        snap = git.snapshot(repo)
        return RepoInspectResponse(
            id=repo.id,
            path=repo.path,
            name=repo.name,
            remote_url=repo.remote_url,
            default_branch=repo.default_branch,
            branch=snap.branch,
            head_commit=snap.head_commit,
            is_detached=snap.is_detached,
            is_dirty=snap.is_dirty,
        )
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
