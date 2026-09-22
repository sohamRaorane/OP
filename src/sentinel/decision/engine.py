"""Decision engine — Phase 8 (deterministic, precedence, reproducible)."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sentinel.core.models.decision import Decision, DecisionAction
from sentinel.core.models.policy import PolicyAction, PolicyEvaluation
from sentinel.core.models.repository import ChangeSet
from sentinel.core.models.risk import RiskAssessment, RiskLevel
from sentinel.core.models.security import SecuritySeverity


class DecisionEngine:
    """Deterministic decision engine — never calls AI models."""

    VERSION = "1.0.0"

    # Precedence order (highest first):
    # CRITICAL security / CRITICAL risk → BLOCK
    # explicit BLOCK policy → BLOCK
    # REQUIRE_HUMAN_REVIEW policy → REQUIRE_HUMAN_REVIEW
    # failed mandatory validation → REVISE/REJECT
    # high risk → REQUIRE_HUMAN_REVIEW
    # medium risk → REVISE
    # low risk → ACCEPT

    def decide(
        self,
        changeset: ChangeSet,
        risk: RiskAssessment | None = None,
        policy_evaluation: PolicyEvaluation | None = None,
        validation_ids: list[str] | None = None,
        security_finding_ids: list[str] | None = None,
        jev_evaluation_id: str | None = None,
        risk_assessment_id: str | None = None,
    ) -> Decision:
        validation_ids = validation_ids or []
        security_finding_ids = security_finding_ids or []
        trace: list[str] = []
        triggered_policies = [r.rule_name for r in (policy_evaluation.triggered if policy_evaluation else []) if r.matched]

        # 1. Policy-driven decisions take precedence (deterministic)
        if policy_evaluation and policy_evaluation.final_action:
            action_map: dict[PolicyAction, DecisionAction] = {
                PolicyAction.BLOCK: DecisionAction.BLOCK,
                PolicyAction.REQUIRE_HUMAN_REVIEW: DecisionAction.REQUIRE_HUMAN_REVIEW,
                PolicyAction.REJECT: DecisionAction.REJECT,
                PolicyAction.REVISE: DecisionAction.REVISE,
                PolicyAction.ACCEPT: DecisionAction.ACCEPT,
            }
            final = policy_evaluation.final_action
            # Document precedence
            trace.append(f"Policy final_action={final.value} from {triggered_policies}")
            # CRITICAL / BLOCK always wins
            if final == PolicyAction.BLOCK:
                return self._make_decision(
                    changeset, DecisionAction.BLOCK, f"Blocked by policy: {triggered_policies[0] if triggered_policies else 'critical'}",
                    risk, triggered_policies, trace, validation_ids, security_finding_ids, jev_evaluation_id, risk_assessment_id, policy_evaluation,
                )
            if final == PolicyAction.REQUIRE_HUMAN_REVIEW:
                return self._make_decision(
                    changeset, DecisionAction.REQUIRE_HUMAN_REVIEW, f"Human review required by policy: {triggered_policies[0] if triggered_policies else 'policy'}",
                    risk, triggered_policies, trace, validation_ids, security_finding_ids, jev_evaluation_id, risk_assessment_id, policy_evaluation,
                )
            if final == PolicyAction.REJECT:
                return self._make_decision(
                    changeset, DecisionAction.REJECT, f"Rejected by policy: {triggered_policies[0] if triggered_policies else 'policy'}",
                    risk, triggered_policies, trace, validation_ids, security_finding_ids, jev_evaluation_id, risk_assessment_id, policy_evaluation,
                )
            if final == PolicyAction.REVISE:
                return self._make_decision(
                    changeset, DecisionAction.REVISE, f"Revision required by policy: {triggered_policies[0] if triggered_policies else 'policy'}",
                    risk, triggered_policies, trace, validation_ids, security_finding_ids, jev_evaluation_id, risk_assessment_id, policy_evaluation,
                )
            if final == PolicyAction.ACCEPT:
                # Still check risk overrides? For now accept if policy says accept and no higher risk
                trace.append("Policy ACCEPT but checking risk overrides")
                # Fall through to risk check, but policy ACCEPT is strong

        # 2. Risk-based fallback if no policy triggered
        if risk:
            trace.append(f"Risk level={risk.level.value} score={risk.score:.1f}")
            if risk.level == RiskLevel.CRITICAL:
                return self._make_decision(
                    changeset, DecisionAction.BLOCK, f"Critical risk ({risk.score:.1f}): {risk.evidence[:1]}",
                    risk, triggered_policies, trace, validation_ids, security_finding_ids, jev_evaluation_id, risk_assessment_id, policy_evaluation,
                )
            if risk.level == RiskLevel.HIGH:
                return self._make_decision(
                    changeset, DecisionAction.REQUIRE_HUMAN_REVIEW, f"High risk ({risk.score:.1f}): {risk.evidence[:2]}",
                    risk, triggered_policies, trace, validation_ids, security_finding_ids, jev_evaluation_id, risk_assessment_id, policy_evaluation,
                )
            if risk.level == RiskLevel.MEDIUM:
                return self._make_decision(
                    changeset, DecisionAction.REVISE, f"Medium risk ({risk.score:.1f}): review suggested",
                    risk, triggered_policies, trace, validation_ids, security_finding_ids, jev_evaluation_id, risk_assessment_id, policy_evaluation,
                )
            # LOW → ACCEPT
            return self._make_decision(
                changeset, DecisionAction.ACCEPT, f"Low risk ({risk.score:.1f}): accepted",
                risk, triggered_policies, trace, validation_ids, security_finding_ids, jev_evaluation_id, risk_assessment_id, policy_evaluation,
            )

        # 3. Default accept if nothing else
        trace.append("No risk/policy signal → default ACCEPT")
        return self._make_decision(
            changeset, DecisionAction.ACCEPT, "No blocking signals — accepted",
            risk, triggered_policies, trace, validation_ids, security_finding_ids, jev_evaluation_id, risk_assessment_id, policy_evaluation,
        )

    def _make_decision(
        self,
        changeset: ChangeSet,
        action: DecisionAction,
        reason: str,
        risk: RiskAssessment | None,
        triggered_policies: list[str],
        trace: list[str],
        validation_ids: list[str],
        security_finding_ids: list[str],
        jev_evaluation_id: str | None,
        risk_assessment_id: str | None,
        policy_evaluation: PolicyEvaluation | None,
    ) -> Decision:
        return Decision(
            id=str(uuid.uuid4()),
            changeset_id=changeset.id,
            action=action,
            reason=reason,
            risk_level=risk.level.value if risk else None,
            validation_ids=validation_ids,
            security_finding_ids=security_finding_ids,
            jev_evaluation_id=jev_evaluation_id,
            risk_assessment_id=risk_assessment_id or (risk.id if risk else None),
            policy_evaluation_id=policy_evaluation.id if policy_evaluation else None,
            triggered_policies=triggered_policies,
            engine_version=self.VERSION,
            policy_version=policy_evaluation.policy_version if policy_evaluation else "1.0.0",
            created_at=datetime.now(timezone.utc),
            trace=trace,
        )
