"""Sentinel orchestrator — full verification pipeline."""

from __future__ import annotations

import asyncio
import shutil
import tempfile
from pathlib import Path

import structlog

from sentinel.agents.base import AgentFeedback
from sentinel.approval.service import ApprovalService
from sentinel.audit.service import AuditService
from sentinel.config.settings import Settings, get_settings
from sentinel.core.models.audit import AuditEventType
from sentinel.core.models.decision import Decision, DecisionAction
from sentinel.core.models.security import SecurityFinding, SecuritySeverity
from sentinel.core.models.validation import ValidationResult, ValidationStatus
from sentinel.decision.engine import DecisionEngine
from sentinel.git.repository import GitRepository
from sentinel.jev.client import JevClient, JevContextBuilder
from sentinel.jev.mock import MockJevClient
from sentinel.jev.openrouter import OpenRouterJevClient
from sentinel.jev.service import JevDecisionService
from sentinel.policy.engine import PolicyEngine
from sentinel.risk.engine import RiskEngine
from sentinel.sandbox.executor import DockerSandboxExecutor
from sentinel.security.engine import SecurityAnalyzer
from sentinel.validation.engine import ValidationRunner

logger = structlog.get_logger(__name__)


class SentinelService:
    """End-to-end verification: ChangeSet → Validation → Security → JEV → Risk → Policy → Decision."""

    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or get_settings()
        self.git = GitRepository(settings=self.settings)
        self.validation = ValidationRunner(settings=self.settings)
        self.security = SecurityAnalyzer()
        self.jev_client = self._build_jev_client()
        self.jev_service = JevDecisionService(client=self.jev_client, timeout=self.settings.jev_timeout)
        self.risk = RiskEngine()
        self.policy = PolicyEngine()
        self.decision = DecisionEngine()
        self.approval = ApprovalService()
        self.audit = AuditService()

    def _build_jev_client(self) -> JevClient:
        """Real Jev when JEV_ENABLED + key present; mock otherwise (tests/dev stay offline)."""
        s = self.settings
        if s.jev_enabled and s.jev_api_key:
            logger.info("jev_client_selected", provider="openrouter", model=s.jev_model)
            return OpenRouterJevClient(
                api_key=s.jev_api_key,
                api_url=s.jev_api_url,
                model=s.jev_model,
                timeout=float(s.jev_timeout),
            )
        if s.jev_enabled and not s.jev_api_key:
            logger.warning("jev_enabled_without_key", fallback="mock")
        return MockJevClient()

    def _run_validation_sandboxed(self, repo_path: Path) -> tuple[list[ValidationResult], bool, str]:
        """Run validators ONLY inside Docker on a throwaway snapshot of the scannable set.

        Never falls back to host execution. Returns (results, executed, skip_reason).
        """
        s = self.settings
        if not s.docker_enabled:
            return [], False, "validation not executed: DOCKER_ENABLED=false"
        sandbox = DockerSandboxExecutor(settings=s)
        if not sandbox.is_available():
            return [], False, "validation not executed: Docker unavailable"
        snapshot_base = Path(s.snapshot_dir) if s.snapshot_dir else Path(tempfile.gettempdir())
        snapshot: Path | None = None
        try:
            snapshot_base.mkdir(parents=True, exist_ok=True)
            snapshot = Path(tempfile.mkdtemp(prefix="jev-snapshot-", dir=snapshot_base))
            self.git.export_snapshot(repo_path, snapshot)
            results = self.validation.run(snapshot, use_sandbox=True, sandbox_executor=sandbox)
            return results, True, ""
        except Exception as e:
            return [], False, f"validation not executed: {e}"
        finally:
            if snapshot is not None:
                shutil.rmtree(snapshot, ignore_errors=True)

    @staticmethod
    def _skipped_result(name: str, reason: str) -> ValidationResult:
        return ValidationResult(
            validator_name=name,
            command=[],
            status=ValidationStatus.SKIPPED,
            stderr=reason,
        )

    def _apply_safety_guards(
        self,
        decision: Decision,
        *,
        validation_executed: bool,
        validation_skip_reason: str,
        critical_count: int,
        changeset_id: str,
    ) -> Decision:
        """No incomplete verification ever ends in ACCEPT (fail-closed)."""
        if critical_count and decision.action != DecisionAction.BLOCK:
            decision = decision.model_copy(
                update={
                    "action": DecisionAction.BLOCK,
                    "reason": f"Critical security findings ({critical_count}) — execution skipped, blocked",
                }
            )
            self.audit.log(
                AuditEventType.DECISION_OVERRIDDEN,
                {"action": decision.action.value, "reason": decision.reason, "guard": "critical_security"},
                changeset_id=changeset_id, decision_id=decision.id,
            )
            return decision
        if not validation_executed and decision.action in (
            DecisionAction.ACCEPT, DecisionAction.REVISE, DecisionAction.REJECT,
        ):
            decision = decision.model_copy(
                update={
                    "action": DecisionAction.REQUIRE_HUMAN_REVIEW,
                    "reason": validation_skip_reason or "validation not executed",
                }
            )
            self.audit.log(
                AuditEventType.DECISION_OVERRIDDEN,
                {"action": decision.action.value, "reason": decision.reason, "guard": "validation_not_executed"},
                changeset_id=changeset_id, decision_id=decision.id,
            )
        return decision

    async def verify(
        self,
        repo_path: Path | str,
        task: str | None = None,
        jev_fixture: str = "high_confidence_safe",
    ) -> dict:
        """Full verification pipeline — scan → gate → execute → decide.

        Ordering is a security property: nothing from the repo executes unless
        the security scan already ran and did not find CRITICAL, and execution
        only ever happens inside the Docker sandbox on a throwaway snapshot.
        """
        repo_path = Path(repo_path).resolve()
        if isinstance(self.jev_client, MockJevClient):
            self.jev_client.set_fixture(jev_fixture)

        # Discover
        repo = self.git.discover(repo_path)
        self.audit.log(AuditEventType.REPOSITORY_INSPECTED, {"path": str(repo_path)}, repository_id=repo.id)

        changeset = self.git.changeset(repo)
        self.audit.log(
            AuditEventType.CHANGE_GENERATED, {"files": len(changeset.changed_files)},
            repository_id=repo.id, changeset_id=changeset.id,
        )

        # 1) SCAN — security runs before anything executes
        security_findings = self.security.analyze(changeset)
        for f in security_findings:
            self.audit.log(
                AuditEventType.SECURITY_FINDING_CREATED,
                {"severity": f.severity.value, "category": f.category.value},
                changeset_id=changeset.id,
            )
        critical_findings = [f for f in security_findings if f.severity == SecuritySeverity.CRITICAL]

        # 2) GATE + 3) EXECUTE — sandbox-only, snapshot-only
        self.audit.log(AuditEventType.VALIDATION_STARTED, {}, changeset_id=changeset.id)
        if critical_findings:
            validation_results = [
                self._skipped_result(
                    "security_gate",
                    f"validation skipped: {len(critical_findings)} CRITICAL security finding(s)",
                )
            ]
            validation_executed = False
            validation_skip_reason = "validation not executed: blocked by CRITICAL security findings"
        else:
            validation_results, validation_executed, validation_skip_reason = await asyncio.to_thread(
                self._run_validation_sandboxed, repo_path
            )
        self.audit.log(
            AuditEventType.VALIDATION_COMPLETED,
            {"count": len(validation_results), "executed": validation_executed},
            changeset_id=changeset.id,
        )

        # JEV
        context_builder = JevContextBuilder()
        jev_context = context_builder.build(
            task=task,
            changeset=changeset,
            validation_results=validation_results,
            security_findings=security_findings,
            repository_metadata={"path": repo.path, "branch": changeset.branch},
        )
        self.audit.log(AuditEventType.JEV_REQUEST, {"fixture": jev_fixture}, changeset_id=changeset.id)
        jev_evaluation = await self.jev_service.evaluate_with_retry(jev_context)
        self.audit.log(AuditEventType.JEV_RESPONSE, {"overall_risk": jev_evaluation.overall_risk}, changeset_id=changeset.id)

        # Risk
        risk_assessment = self.risk.assess(changeset, validation_results, security_findings, jev_evaluation)
        self.audit.log(
            AuditEventType.RISK_ASSESSMENT,
            {"level": risk_assessment.level.value, "score": risk_assessment.score},
            changeset_id=changeset.id,
        )

        # Policy
        policy_evaluation = self.policy.evaluate(changeset, validation_results, security_findings, risk_assessment, jev_evaluation)
        self.audit.log(
            AuditEventType.POLICY_EVALUATION,
            {"action": policy_evaluation.final_action.value if policy_evaluation.final_action else None},
            changeset_id=changeset.id,
        )

        # Decision
        decision = self.decision.decide(
            changeset,
            risk=risk_assessment,
            policy_evaluation=policy_evaluation,
            validation_ids=[r.id for r in validation_results],
            security_finding_ids=[f.id for f in security_findings],
            jev_evaluation_id=jev_evaluation.id,
            risk_assessment_id=risk_assessment.id,
        )
        self.audit.log(
            AuditEventType.DECISION_CREATED, {"action": decision.action.value, "reason": decision.reason},
            changeset_id=changeset.id, decision_id=decision.id,
        )

        # Safety guards — incomplete verification can never ACCEPT
        decision = self._apply_safety_guards(
            decision,
            validation_executed=validation_executed,
            validation_skip_reason=validation_skip_reason,
            critical_count=len(critical_findings),
            changeset_id=changeset.id,
        )

        # Approval if needed
        approval = None
        if decision.action.value == "REQUIRE_HUMAN_REVIEW":
            approval = self.approval.create_request(decision.id, changeset.id, repo.id, reason=decision.reason)
            self.audit.log(
                AuditEventType.APPROVAL_REQUESTED, {"approval_id": approval.id},
                changeset_id=changeset.id, decision_id=decision.id,
            )

        return {
            "repository": repo,
            "changeset": changeset,
            "validation_results": validation_results,
            "security_findings": security_findings,
            "jev_evaluation": jev_evaluation,
            "risk_assessment": risk_assessment,
            "policy_evaluation": policy_evaluation,
            "decision": decision,
            "approval": approval,
        }

    def verify_sync(self, repo_path: Path | str, task: str | None = None, jev_fixture: str = "high_confidence_safe") -> dict:
        return asyncio.run(self.verify(repo_path, task, jev_fixture))

    def generate_feedback(
        self, decision: Decision,
        validation_results: list[ValidationResult],
        security_findings: list[SecurityFinding],
    ) -> AgentFeedback:
        reasons: list[str] = []
        required: list[str] = []

        for vr in validation_results:
            if vr.status.value in ("FAIL", "TIMEOUT", "ERROR"):
                reasons.append(f"{vr.validator_name} {vr.status.value}: {vr.failures[:1] if vr.failures else vr.stderr[:100]}")
                if vr.validator_name == "pytest":
                    required.append("Fix failing tests")
                elif vr.validator_name == "ruff":
                    required.append("Fix lint errors")
                elif vr.validator_name == "mypy":
                    required.append("Fix type errors")

        for f in security_findings:
            if f.severity.value in ("HIGH", "CRITICAL"):
                reasons.append(f"{f.category.value} {f.severity.value} in {f.file}: {f.explanation[:80]}")
                if f.remediation:
                    required.append(f.remediation[:100])

        if decision.action.value in ("REVISE", "REJECT", "BLOCK"):
            if not reasons:
                reasons.append(decision.reason)
            if not required:
                required.append("Review policy violations and retry")

        return AgentFeedback(
            decision=decision.action.value,
            reasons=reasons,
            required_changes=required,
            raw=decision.reason,
        )
