"""JEV client interface — Phase 5."""

from __future__ import annotations

from abc import ABC, abstractmethod

from sentinel.core.models.jev import JevContext, JevEvaluation
from sentinel.core.models.repository import ChangeSet


class JevClient(ABC):
    """Abstract JEV provider — strict interface, no invented endpoints."""

    @abstractmethod
    async def evaluate(self, context: JevContext) -> JevEvaluation:
        """Evaluate context and return structured JevEvaluation."""

    @abstractmethod
    def is_available(self) -> bool:
        """Whether provider is reachable."""


class JevContextBuilder:
    """Builds minimized JEV context from ChangeSet + validation + security."""

    MAX_DIFF_CHARS = 8000

    def build(
        self,
        task: str | None,
        changeset: ChangeSet,
        validation_results: list | None = None,
        security_findings: list | None = None,
        repository_metadata: dict | None = None,
        policy_context: dict | None = None,
    ) -> JevContext:
        from sentinel.core.models.jev import JevContext

        # Changed files
        changed_files = [cf.path for cf in changeset.changed_files] if changeset else []
        # Relevant diff — truncated
        diff = changeset.unified_diff if changeset else ""
        truncated = False
        if diff and len(diff) > self.MAX_DIFF_CHARS:
            diff = diff[: self.MAX_DIFF_CHARS] + "\n[TRUNCATED]"
            truncated = True
        # Validation summary
        val_summary = None
        if validation_results:
            val_summary = [
                {"validator": r.validator_name, "status": r.status.value, "exit_code": r.exit_code, "failures": r.failures[:3]}
                for r in validation_results
            ]
        # Security summary
        sec_summary = None
        if security_findings:
            sec_summary = [
                {"severity": f.severity.value, "category": f.category.value, "file": f.file, "confidence": f.confidence}
                for f in security_findings[:10]
            ]

        change_summary = changeset.to_summary_dict() if changeset and hasattr(changeset, "to_summary_dict") else {}

        return JevContext(
            task=task,
            change_summary=change_summary,
            changed_files=changed_files,
            relevant_diff=diff,
            diff_truncated=truncated,
            validation_summary=val_summary,
            security_summary=sec_summary,
            repository_metadata=repository_metadata,
            policy_context=policy_context,
        )
