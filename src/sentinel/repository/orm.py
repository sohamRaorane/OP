"""ORM for repository / changeset — Phase 1."""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import DateTime, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from sentinel.core.db import Base


class RepositoryORM(Base):
    __tablename__ = "repositories"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    path: Mapped[str] = mapped_column(String, nullable=False)
    name: Mapped[str] = mapped_column(String, nullable=False)
    remote_url: Mapped[str | None] = mapped_column(String, nullable=True)
    default_branch: Mapped[str | None] = mapped_column(String, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC))


class ChangeSetORM(Base):
    __tablename__ = "changesets"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    repository_id: Mapped[str] = mapped_column(String, nullable=False, index=True)
    baseline_commit: Mapped[str | None] = mapped_column(String, nullable=True)
    current_commit: Mapped[str | None] = mapped_column(String, nullable=True)
    branch: Mapped[str | None] = mapped_column(String, nullable=True)
    is_detached: Mapped[bool] = mapped_column(default=False)
    generated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    unified_diff: Mapped[str] = mapped_column(Text, default="")
    diff_truncated: Mapped[bool] = mapped_column(default=False)
    summary_json: Mapped[str] = mapped_column(Text, default="{}")
    changed_files_json: Mapped[str] = mapped_column(Text, default="[]")
    diff_hash: Mapped[str | None] = mapped_column(String, nullable=True)


class ValidationRunORM(Base):
    __tablename__ = "validation_runs"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    changeset_id: Mapped[str | None] = mapped_column(String, nullable=True, index=True)
    validator_name: Mapped[str] = mapped_column(String, nullable=False)
    command_json: Mapped[str] = mapped_column(Text, default="[]")
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    duration_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
    exit_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    stdout: Mapped[str] = mapped_column(Text, default="")
    stderr: Mapped[str] = mapped_column(Text, default="")
    status: Mapped[str] = mapped_column(String, nullable=False)
    timeout_seconds: Mapped[int] = mapped_column(Integer, default=120)


class SecurityFindingORM(Base):
    __tablename__ = "security_findings"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    changeset_id: Mapped[str | None] = mapped_column(String, nullable=True, index=True)
    severity: Mapped[str] = mapped_column(String, nullable=False)
    category: Mapped[str] = mapped_column(String, nullable=False)
    file: Mapped[str | None] = mapped_column(String, nullable=True)
    line: Mapped[int | None] = mapped_column(Integer, nullable=True)
    evidence: Mapped[str] = mapped_column(Text, default="")
    explanation: Mapped[str] = mapped_column(Text, default="")
    remediation: Mapped[str | None] = mapped_column(Text, nullable=True)
    confidence: Mapped[float] = mapped_column(default=0.8)


class AuditEventORM(Base):
    __tablename__ = "audit_events"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    actor: Mapped[str] = mapped_column(String, default="system")
    session_id: Mapped[str | None] = mapped_column(String, nullable=True)
    repository_id: Mapped[str | None] = mapped_column(String, nullable=True)
    changeset_id: Mapped[str | None] = mapped_column(String, nullable=True)
    decision_id: Mapped[str | None] = mapped_column(String, nullable=True)
    event_type: Mapped[str] = mapped_column(String, nullable=False)
    payload_json: Mapped[str] = mapped_column(Text, default="{}")
    correlation_id: Mapped[str | None] = mapped_column(String, nullable=True)
