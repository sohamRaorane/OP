"""FastAPI main — Phase 12."""

from __future__ import annotations

import time
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from sentinel.api.routes import approvals, audit, changes, decisions, health, repositories, sessions
from sentinel.config.settings import get_settings

settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    # Startup: init DB if needed
    try:
        from sentinel.core.db import init_db

        init_db()
    except Exception:  # noqa: S110 -- DB table creation is best-effort at startup
        pass
    yield


app = FastAPI(
    title="JEV Sentinel API",
    version="0.1.0",
    description="AI Coding Agent Guardian — verification and governance layer",
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
    lifespan=lifespan,
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Request ID middleware
@app.middleware("http")
async def add_request_id(request: Request, call_next: Callable[[Request], Awaitable[Response]]) -> Response:
    request_id = request.headers.get("X-Request-ID", str(uuid.uuid4()))
    start = time.time()
    response = await call_next(request)
    response.headers["X-Request-ID"] = request_id
    response.headers["X-Response-Time"] = f"{(time.time() - start)*1000:.1f}ms"
    return response


# Include routers
app.include_router(health.router, prefix="/api/v1", tags=["health"])
app.include_router(repositories.router, prefix="/api/v1", tags=["repositories"])
app.include_router(sessions.router, prefix="/api/v1", tags=["sessions"])
app.include_router(changes.router, prefix="/api/v1", tags=["changes"])
app.include_router(decisions.router, prefix="/api/v1", tags=["decisions"])
app.include_router(approvals.router, prefix="/api/v1", tags=["approvals"])
app.include_router(audit.router, prefix="/api/v1", tags=["audit"])


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    return JSONResponse(
        status_code=500,
        content={"error": "internal_error", "message": str(exc), "request_id": request.headers.get("X-Request-ID", "")},
    )


@app.get("/", include_in_schema=False)
async def root() -> dict:
    return {"service": "jev-sentinel", "version": "0.1.0", "docs": "/docs"}


# For local dev: uvicorn sentinel.api.main:app --reload
