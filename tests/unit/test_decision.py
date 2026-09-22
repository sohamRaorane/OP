"""Decision engine tests — Phase 8."""

import uuid
from datetime import datetime, timezone

import pytest

from sentinel.core.models.decision import DecisionAction
from sentinel.core.models.policy import PolicyAction, PolicyEvaluation, PolicyResult
from sentinel.core.models.repository import ChangeSet, ChangedFile, FileChangeType
from sentinel.core.models.risk import RiskAssessment, RiskLevel
from sentinel.decision.engine import DecisionEngine


def make_cs():
    return ChangeSet(
        repository_id=str(uuid.uuid4()),
        baseline_commit="a",
        current_commit="b",
        generated_at=datetime.now(timezone.utc),
        changed_files=[ChangedFile(path="a.py", change_type=FileChangeType.MODIFIED)],
        unified_diff="",
    )


def make_risk(level):
    return RiskAssessment(level=level, score=50 if level == RiskLevel.HIGH else 10, factors=[], increasing_signals=[], decreasing_signals=[], deterministic_signals=[], probabilistic_signals=[], evidence=[])


def make_policy(action, name="rule"):
    return PolicyEvaluation(triggered=[PolicyResult(rule_name=name, action=action, matched=True)], final_action=action, trace=[])


def test_critical_security_policy_blocks():
    engine = DecisionEngine()
    cs = make_cs()
    risk = make_risk(RiskLevel.CRITICAL)
    policy = make_policy(PolicyAction.BLOCK, "critical_security")
    decision = engine.decide(cs, risk=risk, policy_evaluation=policy)
    assert decision.action == DecisionAction.BLOCK
    assert "critical_security" in decision.triggered_policies


def test_human_review_policy():
    engine = DecisionEngine()
    cs = make_cs()
    risk = make_risk(RiskLevel.HIGH)
    policy = make_policy(PolicyAction.REQUIRE_HUMAN_REVIEW, "high_risk")
    decision = engine.decide(cs, risk=risk, policy_evaluation=policy)
    assert decision.action == DecisionAction.REQUIRE_HUMAN_REVIEW


def test_failed_validation_revise_via_policy():
    engine = DecisionEngine()
    cs = make_cs()
    policy = make_policy(PolicyAction.REVISE, "failed_tests")
    decision = engine.decide(cs, risk=make_risk(RiskLevel.MEDIUM), policy_evaluation=policy)
    assert decision.action == DecisionAction.REVISE


def test_high_risk_requires_review_without_policy():
    engine = DecisionEngine()
    cs = make_cs()
    risk = make_risk(RiskLevel.HIGH)
    decision = engine.decide(cs, risk=risk, policy_evaluation=None)
    assert decision.action == DecisionAction.REQUIRE_HUMAN_REVIEW


def test_low_risk_accept():
    engine = DecisionEngine()
    cs = make_cs()
    risk = make_risk(RiskLevel.LOW)
    decision = engine.decide(cs, risk=risk)
    assert decision.action == DecisionAction.ACCEPT


def test_decision_contains_evidence_refs():
    engine = DecisionEngine()
    cs = make_cs()
    risk = make_risk(RiskLevel.LOW)
    decision = engine.decide(cs, risk=risk, validation_ids=["v1"], security_finding_ids=["s1"], jev_evaluation_id="j1", risk_assessment_id="r1")
    assert decision.validation_ids == ["v1"]
    assert decision.security_finding_ids == ["s1"]
    assert decision.jev_evaluation_id == "j1"
    assert decision.risk_assessment_id == "r1"
    assert decision.engine_version
    assert decision.policy_version
    assert decision.created_at
    assert decision.id


def test_reproducibility_same_evidence_same_decision():
    engine = DecisionEngine()
    cs = make_cs()
    risk = make_risk(RiskLevel.MEDIUM)
    policy = make_policy(PolicyAction.REVISE, "test")
    d1 = engine.decide(cs, risk=risk, policy_evaluation=policy, validation_ids=["v1"])
    d2 = engine.decide(cs, risk=risk, policy_evaluation=policy, validation_ids=["v1"])
    assert d1.action == d2.action
    assert d1.reason == d2.reason
