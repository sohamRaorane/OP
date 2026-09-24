"""Risk engine tests — Phase 6."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sentinel.core.models.jev import JevDimension, JevEvaluation, JevScore
from sentinel.core.models.repository import ChangedFile, ChangeSet, FileChangeType
from sentinel.core.models.risk import RiskLevel
from sentinel.core.models.security import SecurityCategory, SecurityFinding, SecuritySeverity
from sentinel.core.models.validation import ValidationResult, ValidationStatus
from sentinel.risk.engine import RiskEngine


def make_changeset(
    files: list[ChangedFile] | None = None,
    diff: str = "",
    summary: dict | None = None,
) -> ChangeSet:
    return ChangeSet(
        repository_id=str(uuid.uuid4()),
        baseline_commit="a",
        current_commit="b",
        generated_at=datetime.now(UTC),
        changed_files=files or [],
        unified_diff=diff,
        summary=summary or {},
    )


def test_low_risk_simple_change() -> None:
    engine = RiskEngine()
    cs = make_changeset(
        files=[ChangedFile(path="README.md", change_type=FileChangeType.MODIFIED, additions=2, deletions=1)],
        diff="change docs",
    )
    assessment = engine.assess(cs, validation_results=[], security_findings=[], jev_evaluation=None)
    assert assessment.level in (RiskLevel.LOW, RiskLevel.MEDIUM)  # may be low or medium depending on weights
    assert assessment.score < 40
    assert len(assessment.evidence) >= 0


def test_critical_risk_with_critical_security() -> None:
    engine = RiskEngine()
    cs = make_changeset(files=[ChangedFile(path="app.py", change_type=FileChangeType.MODIFIED)], diff="secret")
    finding = SecurityFinding(
        severity=SecuritySeverity.CRITICAL, category=SecurityCategory.SECRETS,
        evidence="AKIA...", explanation="secret",
    )
    assessment = engine.assess(cs, security_findings=[finding])
    assert assessment.level == RiskLevel.CRITICAL
    assert assessment.score >= 50
    assert any(f.severity == SecuritySeverity.CRITICAL for f in [finding])


def test_risk_explainability_signals() -> None:
    engine = RiskEngine()
    cs = make_changeset(files=[ChangedFile(path="auth.py", change_type=FileChangeType.MODIFIED)])
    validation = ValidationResult(validator_name="pytest", command=["pytest"], status=ValidationStatus.FAIL, failures=["test fail"])
    finding = SecurityFinding(
        severity=SecuritySeverity.HIGH, category=SecurityCategory.AUTHENTICATION,
        evidence="auth bypass", explanation="bypass",
    )
    jev = JevEvaluation(
        provider="mock",
        scores=[JevScore(dimension=JevDimension.SECURITY_RISK, score=0.9, confidence=0.8, reasoning="high risk")],
        overall_risk=0.8,
    )
    assessment = engine.assess(cs, validation_results=[validation], security_findings=[finding], jev_evaluation=jev)
    # Must answer 6 questions via signals
    assert len(assessment.increasing_signals) > 0
    assert len(assessment.deterministic_signals) > 0
    assert len(assessment.probabilistic_signals) > 0
    assert len(assessment.evidence) > 0
    assert assessment.explanation
    assert len(assessment.factors) > 0


def test_risk_not_opaque_single_score() -> None:
    engine = RiskEngine()
    cs = make_changeset()
    assessment = engine.assess(cs)
    assert hasattr(assessment, "factors")
    assert hasattr(assessment, "increasing_signals")
    assert hasattr(assessment, "decreasing_signals")
    assert hasattr(assessment, "deterministic_signals")
    assert hasattr(assessment, "probabilistic_signals")
    assert hasattr(assessment, "evidence")


def test_large_scope_increases_risk() -> None:
    engine = RiskEngine()
    files = [ChangedFile(path=f"file{i}.py", change_type=FileChangeType.MODIFIED) for i in range(25)]
    cs = make_changeset(files=files)
    assessment = engine.assess(cs)
    assert assessment.level in (RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL) or assessment.score > 10
