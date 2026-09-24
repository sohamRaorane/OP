"""Health routes."""

from fastapi import APIRouter
from pydantic import BaseModel

router = APIRouter()


class HealthResponse(BaseModel):
    status: str
    version: str = "0.1.0"
    mode: str = "gated"


@router.get("/health")
async def health() -> HealthResponse:
    return HealthResponse(status="ok", mode="gated")


@router.get("/readiness")
async def readiness() -> dict:
    # Check DB connectivity
    try:
        from sentinel.core.db import get_engine

        engine = get_engine()
        with engine.connect() as conn:
            conn.execute(__import__("sqlalchemy").text("SELECT 1"))
        return {"status": "ready", "database": "ok"}
    except Exception as e:
        return {"status": "not_ready", "database": str(e)}
