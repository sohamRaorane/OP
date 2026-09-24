"""API dependencies."""

from __future__ import annotations

from fastapi import Header, HTTPException

from sentinel.config.settings import get_settings


async def get_request_id(x_request_id: str | None = Header(default=None)) -> str:
    import uuid

    return x_request_id or str(uuid.uuid4())


# Simple auth abstraction for V1 (local)
async def require_auth(authorization: str | None = Header(default=None)) -> dict:
    settings = get_settings()
    # In development, allow unauthenticated
    if settings.sentinel_env in ("development", "testing"):
        return {"user": "dev"}
    if not authorization:
        raise HTTPException(status_code=401, detail="Missing Authorization")
    # In production, validate token — placeholder
    return {"user": "authenticated"}
