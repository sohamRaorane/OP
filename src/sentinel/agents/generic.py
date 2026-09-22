"""Generic/OpenCode adapter — Phase 9."""

from __future__ import annotations

import time
import uuid
from pathlib import Path

from sentinel.agents.base import AgentAdapter, AgentFeedback, AgentSession
from sentinel.core.exceptions import SentinelError
from sentinel.git.repository import GitRepository


class GenericAgentAdapter(AgentAdapter):
    """Generic adapter — works with any agent that modifies files on disk."""

    def __init__(self, max_retries: int = 3) -> None:
        self.max_retries = max_retries
        self.sessions: dict[str, AgentSession] = {}
        self.git = GitRepository()

    def start_session(self, task: str, repository_path: str) -> AgentSession:
        session = AgentSession(
            id=str(uuid.uuid4()),
            agent_id="generic",
            task=task,
            repository_path=repository_path,
            max_retries=self.max_retries,
        )
        self.sessions[session.id] = session
        return session

    def get_changes(self, session: AgentSession):
        # Delegate to GitRepository to get ChangeSet
        from sentinel.core.models.repository import Repository

        repo = self.git.discover(Path(session.repository_path))
        changeset = self.git.changeset(repo)
        session.last_changeset_id = changeset.id
        session.last_diff_hash = changeset.diff_hash
        return changeset

    def send_feedback(self, session: AgentSession, feedback: AgentFeedback) -> None:
        # In generic mode, feedback is logged / stored. Real agents would receive via API.
        # We store it in session for inspection.
        # For now, just store as attribute
        session.status = f"feedback:{feedback.decision}"

    def continue_execution(self, session: AgentSession) -> bool:
        # Check retry limits
        if session.retry_count >= session.max_retries:
            session.status = "requires_human_review"
            return False
        # Check unchanged patch detection
        # If diff hash unchanged after retry, escalate
        if session.last_diff_hash:
            # Re-get changeset and compare
            new_changeset = self.get_changes(session)
            if new_changeset.diff_hash == session.last_diff_hash and session.retry_count > 0:
                session.status = "unchanged_patch"
                return False
        return True

    def stop_session(self, session: AgentSession) -> None:
        session.status = "stopped"
        self.sessions.pop(session.id, None)

    def get_status(self, session: AgentSession) -> str:
        return session.status

    def record_retry(self, session: AgentSession, backoff: bool = True) -> None:
        session.retry_count += 1
        if backoff:
            # Exponential backoff: 1s, 2s, 4s
            delay = min(2 ** (session.retry_count - 1), 8)
            time.sleep(delay * 0.1)  # scaled down for tests

    def should_escalate(self, session: AgentSession) -> bool:
        return session.retry_count >= session.max_retries
