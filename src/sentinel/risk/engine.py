"""Risk assessment engine — Phase 6 (explainable, configurable)."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sentinel.core.models.jev import JevEvaluation
from sentinel.core.models.repository import ChangeSet
from sentinel.core.models.risk import RiskAssessment, RiskFactor, RiskLevel, RiskSignal
from sentinel.core.models.security import SecurityFinding, SecuritySeverity
from sentinel.core.models.validation import ValidationResult, ValidationStatus


class RiskEngine:
    """Combines deterministic + probabilistic signals into explainable RiskAssessment."""

    VERSION = "1.0.0"

    # Configurable weights — can be overridden via settings/policy
    DEFAULT_WEIGHTS: dict[str, float] = {
        "validation_failure": 30,
        "security_critical": 50,
        "security_high": 30,
        "security_medium": 10,
        "jev_high": 20,
        "large_scope": 15,
        "sensitive_files": 20,
        "new_dependencies": 10,
        "binary_files": 5,
        "huge_diff": 10,
    }

    SENSITIVE_PATTERNS = ["auth", "payment", "migration", "infra", ".env", "secret", "credential", "docker", "ci", "config"]

    def __init__(self, weights: dict[str, float] | None = None) -> None:
        self.weights = {**self.DEFAULT_WEIGHTS, **(weights or {})}

    def assess(
        self,
        changeset: ChangeSet,
        validation_results: list[ValidationResult] | None = None,
        security_findings: list[SecurityFinding] | None = None,
        jev_evaluation: JevEvaluation | None = None,
        triggered_policies: list[str] | None = None,
    ) -> RiskAssessment:
        validation_results = validation_results or []
        security_findings = security_findings or []
        triggered_policies = triggered_policies or []

        factors: list[RiskFactor] = []
        increasing: list[RiskSignal] = []
        decreasing: list[RiskSignal] = []
        deterministic: list[RiskSignal] = []
        probabilistic: list[RiskSignal] = []
        evidence: list[str] = []
        score = 0.0

        # 1. Deterministic: validation failures
        failed_validators = [r for r in validation_results if r.status in (ValidationStatus.FAIL, ValidationStatus.TIMEOUT, ValidationStatus.ERROR)]
        if failed_validators:
            for r in failed_validators:
                w = self.weights["validation_failure"]
                score += w
                sig = RiskSignal(
                    name=f"validation_{r.validator_name}_{r.status.value}",
                    value=r.status.value,
                    weight=w,
                    is_deterministic=True,
                    evidence=f"{r.validator_name} {r.status.value}: {r.failures[:1]}",
                    increased_risk=True,
                )
                increasing.append(sig)
                deterministic.append(sig)
                evidence.append(f"Validation {r.validator_name} {r.status.value}")
            factors.append(RiskFactor(category="validation", signals=[s for s in increasing if "validation" in s.name], score_contribution=w * len(failed_validators)))
        else:
            if validation_results:
                sig = RiskSignal(name="all_validations_passed", value=True, weight=5, is_deterministic=True, evidence="All validations passed", increased_risk=False)
                decreasing.append(sig)
                deterministic.append(sig)
                evidence.append("All validations passed")
                score -= 5  # reduce risk slightly

        # 2. Deterministic: security findings
        sec_score = 0
        sec_signals: list[RiskSignal] = []
        for f in security_findings:
            if f.severity == SecuritySeverity.CRITICAL:
                w = self.weights["security_critical"]
                sec_score += w
                sig = RiskSignal(name=f"security_{f.category.value}_CRITICAL", value=f.evidence[:100], weight=w, is_deterministic=True, evidence=f.explanation, increased_risk=True)
                increasing.append(sig)
                deterministic.append(sig)
                sec_signals.append(sig)
                evidence.append(f"CRITICAL security: {f.category.value} in {f.file}")
            elif f.severity == SecuritySeverity.HIGH:
                w = self.weights["security_high"]
                sec_score += w
                sig = RiskSignal(name=f"security_{f.category.value}_HIGH", value=f.evidence[:100], weight=w, is_deterministic=True, evidence=f.explanation, increased_risk=True)
                increasing.append(sig)
                deterministic.append(sig)
                sec_signals.append(sig)
                evidence.append(f"HIGH security: {f.category.value}")
            elif f.severity == SecuritySeverity.MEDIUM:
                w = self.weights["security_medium"]
                sec_score += w
                sig = RiskSignal(name=f"security_{f.category.value}_MEDIUM", value=True, weight=w, is_deterministic=True, evidence=f.explanation, increased_risk=True)
                increasing.append(sig)
                deterministic.append(sig)
                sec_signals.append(sig)
        if sec_signals:
            factors.append(RiskFactor(category="security", signals=sec_signals, score_contribution=sec_score))
            score += sec_score
        else:
            sig = RiskSignal(name="no_security_findings", value=True, weight=3, is_deterministic=True, evidence="No security findings", increased_risk=False)
            decreasing.append(sig)
            deterministic.append(sig)

        # 3. Probabilistic: JEV evaluation
        jev_signals: list[RiskSignal] = []
        if jev_evaluation and jev_evaluation.scores:
            for s in jev_evaluation.scores:
                # Only high-risk dimensions increase score
                if s.score >= 0.7:
                    w = self.weights["jev_high"] * s.score
                    score += w * 0.5  # scaled
                    sig = RiskSignal(name=f"jev_{s.dimension.value}", value=s.score, weight=w, is_deterministic=False, evidence=s.reasoning, increased_risk=True)
                    increasing.append(sig)
                    probabilistic.append(sig)
                    jev_signals.append(sig)
                    evidence.append(f"JEV {s.dimension.value} high ({s.score:.2f})")
                elif s.score <= 0.3:
                    sig = RiskSignal(name=f"jev_{s.dimension.value}_low", value=s.score, weight=2, is_deterministic=False, evidence=s.reasoning, increased_risk=False)
                    decreasing.append(sig)
                    probabilistic.append(sig)
            if jev_signals:
                factors.append(RiskFactor(category="jev", signals=jev_signals, score_contribution=sum(s.weight * 0.5 for s in jev_signals)))
            else:
                # No high JEV signals → slight decrease
                pass
        elif jev_evaluation and jev_evaluation.timed_out:
            sig = RiskSignal(name="jev_timeout", value=True, weight=10, is_deterministic=False, evidence="JEV timed out", increased_risk=True)
            increasing.append(sig)
            probabilistic.append(sig)
            score += 10
            evidence.append("JEV timeout → conservative risk increase")

        # 4. Change scope
        scope_signals: list[RiskSignal] = []
        file_count = len(changeset.changed_files)
        if file_count > 20:
            w = self.weights["large_scope"]
            score += w
            sig = RiskSignal(name="large_scope_file_count", value=file_count, weight=w, is_deterministic=True, evidence=f"{file_count} files changed", increased_risk=True)
            increasing.append(sig)
            deterministic.append(sig)
            scope_signals.append(sig)
            evidence.append(f"Large scope: {file_count} files")
        elif file_count <= 3:
            sig = RiskSignal(name="small_scope", value=file_count, weight=2, is_deterministic=True, evidence=f"{file_count} files", increased_risk=False)
            decreasing.append(sig)
            deterministic.append(sig)

        # Sensitive files
        sensitive_hits = []
        for cf in changeset.changed_files:
            for pat in self.SENSITIVE_PATTERNS:
                if pat.lower() in cf.path.lower():
                    sensitive_hits.append(cf.path)
                    break
        if sensitive_hits:
            w = self.weights["sensitive_files"]
            score += w
            sig = RiskSignal(name="sensitive_files", value=",".join(sensitive_hits[:5]), weight=w, is_deterministic=True, evidence=f"Sensitive files: {sensitive_hits[:3]}", increased_risk=True)
            increasing.append(sig)
            deterministic.append(sig)
            scope_signals.append(sig)
            evidence.append(f"Sensitive files: {sensitive_hits[:3]}")

        # Huge diff
        if changeset.diff_truncated or changeset.summary.get("lines_added", 0) > 500:  # type: ignore[operator]
            w = self.weights["huge_diff"]
            score += w
            sig = RiskSignal(name="huge_diff", value=True, weight=w, is_deterministic=True, evidence="Diff truncated or large", increased_risk=True)
            increasing.append(sig)
            deterministic.append(sig)
            scope_signals.append(sig)

        if scope_signals:
            factors.append(RiskFactor(category="scope", signals=scope_signals, score_contribution=sum(s.weight for s in scope_signals)))

        # Clamp score 0-100
        score = max(0.0, min(100.0, score))

        # Map score to level
        if score >= 70 or any(f.severity == SecuritySeverity.CRITICAL for f in security_findings):
            level = RiskLevel.CRITICAL
        elif score >= 40 or any(f.severity == SecuritySeverity.HIGH for f in security_findings):
            level = RiskLevel.HIGH
        elif score >= 15:
            level = RiskLevel.MEDIUM
        else:
            level = RiskLevel.LOW

        # Explanation
        explanation = f"Score {score:.1f} → {level.value}. Increasing: {len(increasing)}, Decreasing: {len(decreasing)}. Deterministic: {len(deterministic)}, Probabilistic: {len(probabilistic)}."

        return RiskAssessment(
            id=str(uuid.uuid4()),
            changeset_id=changeset.id,
            level=level,
            score=score,
            factors=factors,
            increasing_signals=increasing,
            decreasing_signals=decreasing,
            deterministic_signals=deterministic,
            probabilistic_signals=probabilistic,
            triggered_policies=triggered_policies,
            evidence=evidence,
            explanation=explanation,
            created_at=datetime.now(timezone.utc),
            engine_version=self.VERSION,
        )
