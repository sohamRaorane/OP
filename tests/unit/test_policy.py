"""Policy engine tests — Phase 7."""

import tempfile
import uuid
from datetime import UTC, datetime
from pathlib import Path

from sentinel.core.models.policy import PolicyAction, PolicyCondition, PolicyRule
from sentinel.core.models.repository import ChangedFile, ChangeSet, FileChangeType
from sentinel.core.models.security import SecurityCategory, SecurityFinding, SecuritySeverity
from sentinel.core.models.validation import ValidationResult, ValidationStatus
from sentinel.policy.engine import PolicyEngine


def make_changeset(files: list[ChangedFile] | None = None) -> ChangeSet:
    return ChangeSet(
        repository_id=str(uuid.uuid4()),
        baseline_commit="a",
        current_commit="b",
        branch="main",
        generated_at=datetime.now(UTC),
        changed_files=files or [],
        unified_diff="",
    )


def test_critical_security_blocks() -> None:
    engine = PolicyEngine(policies=[
        PolicyRule(name="critical_security", when=PolicyCondition(security_severity="CRITICAL"), action=PolicyAction.BLOCK, precedence=100),
        PolicyRule(name="allow", when=PolicyCondition(security_severity="LOW"), action=PolicyAction.ACCEPT, precedence=10),
    ])
    cs = make_changeset()
    findings = [SecurityFinding(severity=SecuritySeverity.CRITICAL, category=SecurityCategory.SECRETS, evidence="x", explanation="y")]
    eval = engine.evaluate(cs, security_findings=findings)
    assert eval.final_action == PolicyAction.BLOCK
    assert any(r.rule_name == "critical_security" for r in eval.triggered if r.matched)


def test_failed_tests_revise() -> None:
    engine = PolicyEngine(policies=[
        PolicyRule(
            name="failed_tests", when=PolicyCondition(validation_status="FAIL", validator="pytest"),
            action=PolicyAction.REVISE, precedence=100,
        ),
    ])
    cs = make_changeset()
    validations = [ValidationResult(validator_name="pytest", command=["pytest"], status=ValidationStatus.FAIL)]
    eval = engine.evaluate(cs, validation_results=validations)
    assert eval.final_action == PolicyAction.REVISE


def test_file_pattern_policy() -> None:
    engine = PolicyEngine(policies=[
        PolicyRule(name="auth", when=PolicyCondition(file_pattern="**/auth*"), action=PolicyAction.REQUIRE_HUMAN_REVIEW, precedence=100),
    ])
    cs = make_changeset(files=[ChangedFile(path="src/auth.py", change_type=FileChangeType.MODIFIED)])
    eval = engine.evaluate(cs)
    assert eval.final_action == PolicyAction.REQUIRE_HUMAN_REVIEW


def test_file_count_policy() -> None:
    engine = PolicyEngine(policies=[
        PolicyRule(name="huge", when=PolicyCondition(file_count_gt=20), action=PolicyAction.REQUIRE_HUMAN_REVIEW, precedence=100),
    ])
    files = [ChangedFile(path=f"f{i}.py", change_type=FileChangeType.MODIFIED) for i in range(25)]
    cs = make_changeset(files=files)
    eval = engine.evaluate(cs)
    assert eval.final_action == PolicyAction.REQUIRE_HUMAN_REVIEW


def test_yaml_loading() -> None:
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
        f.write("""
policies:
  my_rule:
    when:
      security_severity: CRITICAL
    action: BLOCK
  other_rule:
    when:
      file_count_gt: 10
    action: REQUIRE_HUMAN_REVIEW
""")
        fname = f.name
    engine = PolicyEngine(policy_file=Path(fname))
    assert len(engine.rules) >= 2
    assert any(r.name == "my_rule" for r in engine.rules)


def test_policy_trace() -> None:
    engine = PolicyEngine(policies=[
        PolicyRule(name="r1", when=PolicyCondition(security_severity="CRITICAL"), action=PolicyAction.BLOCK, precedence=100),
    ])
    cs = make_changeset()
    eval = engine.evaluate(cs, security_findings=[])
    # Should have trace entries
    assert len(eval.trace) > 0
    assert any("SKIPPED" in t or "TRIGGERED" in t for t in eval.trace)


def test_externalized_config_not_hardcoded() -> None:
    # Ensure engine can load different configs and behave differently
    e1 = PolicyEngine(policies=[
        PolicyRule(name="a", when=PolicyCondition(security_severity="HIGH"), action=PolicyAction.BLOCK, precedence=100),
    ])
    e2 = PolicyEngine(policies=[
        PolicyRule(name="a", when=PolicyCondition(security_severity="HIGH"), action=PolicyAction.REVISE, precedence=100),
    ])
    cs = make_changeset()
    findings = [SecurityFinding(severity=SecuritySeverity.HIGH, category=SecurityCategory.SECRETS, evidence="x", explanation="y")]
    assert e1.evaluate(cs, security_findings=findings).final_action == PolicyAction.BLOCK
    assert e2.evaluate(cs, security_findings=findings).final_action == PolicyAction.REVISE
