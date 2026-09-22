"""Security domain models — Phase 4."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum

from pydantic import BaseModel, Field


class SecuritySeverity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class SecurityCategory(str, Enum):
    SECRETS = "secrets"
    DANGEROUS_EXECUTION = "dangerous_execution"
    FILESYSTEM = "filesystem"
    NETWORK = "network"
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    DATABASE = "database"
    DEPENDENCIES = "dependencies"
    PROMPT_INJECTION = "prompt_injection"
    OTHER = "other"


class SecurityFinding(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    changeset_id: str | None = Field(default=None)
    severity: SecuritySeverity
    category: SecurityCategory
    file: str | None = Field(default=None)
    line: int | None = Field(default=None)
    evidence: str = Field(description="Snippet that triggered finding")
    explanation: str
    remediation: str | None = Field(default=None)
    confidence: float = Field(ge=0.0, le=1.0, default=0.8)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
