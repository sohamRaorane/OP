"""AgentAdapter abstraction — Phase 9."""

from __future__ import annotations

from abc import ABC, abstractmethod
from enum import Enum

from pydantic import BaseModel, Field


class AgentAction(str, Enum):
    START = "START"
    SUBMIT_TASK = "SUBMIT_TASK"
    PROPOSE_CHANGES = "PROPOSE_CHANGES"
    REQUEST_REVISE = "REQUEST_REVISE"
    RETRY = "RETRY"
    STOP = "STOP"


class AgentRequest(BaseModel):
    task: str
    repository_path: str
    session_id: str | None = Field(default=None)


class AgentResponse(BaseModel):
    session_id: str
    changeset_id: str | None = Field(default=None)
    status: str
    message: str | None = Field(default=None)


class AgentFeedback(BaseModel):
    decision: str
    reasons: list[str] = Field(default_factory=list)
    required_changes: list[str] = Field(default_factory=list)
    raw: str | None = Field(default=None)

    def to_text(self) -> str:
        lines = [self.decision, ""]
        if self.reasons:
            lines.append("Reasons:")
            for r in self.reasons:
                lines.append(f"- {r}")
            lines.append("")
        if self.required_changes:
            lines.append("Required changes:")
            for i, c in enumerate(self.required_changes, 1):
                lines.append(f"{i}. {c}")
        return "\n".join(lines)


class Agent(BaseModel):
    id: str
    name: str
    type: str = Field(default="generic")


class AgentSession(BaseModel):
    id: str
    agent_id: str
    task: str
    repository_path: str
    retry_count: int = Field(default=0)
    max_retries: int = Field(default=3)
    status: str = Field(default="active")
    last_changeset_id: str | None = Field(default=None)
    last_diff_hash: str | None = Field(default=None)


class AgentAdapter(ABC):
    @abstractmethod
    def start_session(self, task: str, repository_path: str) -> AgentSession:
        ...

    @abstractmethod
    def get_changes(self, session: AgentSession):
        ...

    @abstractmethod
    def send_feedback(self, session: AgentSession, feedback: AgentFeedback) -> None:
        ...

    @abstractmethod
    def continue_execution(self, session: AgentSession) -> bool:
        ...

    @abstractmethod
    def stop_session(self, session: AgentSession) -> None:
        ...

    @abstractmethod
    def get_status(self, session: AgentSession) -> str:
        ...
