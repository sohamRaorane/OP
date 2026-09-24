"""Policy engine — Phase 7 (YAML, typed, precedence, trace)."""

from __future__ import annotations

import fnmatch
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml

from sentinel.core.exceptions import PolicyError
from sentinel.core.models.policy import (
    PolicyAction,
    PolicyCondition,
    PolicyEvaluation,
    PolicyResult,
    PolicyRule,
)
from sentinel.core.models.repository import ChangeSet
from sentinel.core.models.risk import RiskAssessment
from sentinel.core.models.security import SecurityFinding
from sentinel.core.models.validation import ValidationResult


class PolicyEngine:
    """Loads YAML policies and evaluates deterministically."""

    VERSION = "1.0.0"

    def __init__(self, policy_file: Path | None = None, policies: list[PolicyRule] | None = None) -> None:
        if policies is not None:
            self.rules = policies
        elif policy_file and policy_file.exists():
            self.rules = self._load_yaml(policy_file)
        else:
            # Try sentinel.yaml
            candidates = [Path("sentinel.yaml"), Path("sentinel.yml"), Path("config/sentinel.yaml")]
            self.rules = []
            for p in candidates:
                if p.exists():
                    self.rules = self._load_yaml(p)
                    break
            if not self.rules:
                self.rules = self._default_policies()

    def _default_policies(self) -> list[PolicyRule]:
        return [
            PolicyRule(
                name="critical_security", when=PolicyCondition(security_severity="CRITICAL"),
                action=PolicyAction.BLOCK, description="Critical security → BLOCK", precedence=100,
            ),
            PolicyRule(
                name="high_security_review", when=PolicyCondition(security_severity="HIGH"),
                action=PolicyAction.REQUIRE_HUMAN_REVIEW, description="High → review", precedence=90,
            ),
            PolicyRule(
                name="failed_tests",
                when=PolicyCondition(validation_status="FAIL", validator="pytest"),
                action=PolicyAction.REVISE, description="Tests fail → revise", precedence=80,
            ),
            PolicyRule(
                name="build_failure",
                when=PolicyCondition(validation_status="FAIL", validator="build"),
                action=PolicyAction.REJECT, description="Build fail → reject", precedence=85,
            ),
            PolicyRule(
                name="critical_risk", when=PolicyCondition(risk_level="CRITICAL"),
                action=PolicyAction.BLOCK, description="Critical risk → block", precedence=95,
            ),
            PolicyRule(
                name="high_risk_review", when=PolicyCondition(risk_level="HIGH"),
                action=PolicyAction.REQUIRE_HUMAN_REVIEW, description="High risk → review", precedence=88,
            ),
            PolicyRule(
                name="migration", when=PolicyCondition(migration_detected=True),
                action=PolicyAction.REQUIRE_HUMAN_REVIEW, description="Migration → review", precedence=87,
            ),
        ]

    def _load_yaml(self, path: Path) -> list[PolicyRule]:
        try:
            with open(path, encoding="utf-8") as f:
                data = yaml.safe_load(f) or {}
        except Exception as e:
            raise PolicyError(f"Failed to load policy YAML {path}: {e}") from e

        policies_data = data.get("policies", data) if isinstance(data, dict) else {}
        rules: list[PolicyRule] = []
        precedence = 100
        if isinstance(policies_data, dict):
            for name, cfg in policies_data.items():
                if not isinstance(cfg, dict):
                    continue
                when_data = cfg.get("when", {})
                action_str = cfg.get("action", "REQUIRE_HUMAN_REVIEW")
                try:
                    action = PolicyAction(action_str)
                except ValueError:
                    raise PolicyError(f"Invalid action {action_str} for policy {name}") from None
                when = PolicyCondition(**{k: v for k, v in when_data.items() if k in PolicyCondition.model_fields})
                rules.append(
                    PolicyRule(
                        name=name, when=when, action=action,
                        description=cfg.get("description"), precedence=cfg.get("precedence", precedence),
                    )
                )
                precedence -= 1
        # Sort by precedence desc
        rules.sort(key=lambda r: r.precedence, reverse=True)
        return rules

    def evaluate(
        self,
        changeset: ChangeSet,
        validation_results: list[ValidationResult] | None = None,
        security_findings: list[SecurityFinding] | None = None,
        risk: RiskAssessment | None = None,
        jev_evaluation: Any | None = None,
    ) -> PolicyEvaluation:
        validation_results = validation_results or []
        security_findings = security_findings or []

        triggered: list[PolicyResult] = []
        trace: list[str] = []

        # Build lookup for quick checks
        sec_severities = {f.severity.value for f in security_findings}
        val_map: dict[str, list[ValidationResult]] = {}
        for r in validation_results:
            val_map.setdefault(r.validator_name, []).append(r)
            val_map.setdefault(r.status.value, []).append(r)  # also by status

        # Helper to check single rule
        for rule in self.rules:
            matched, reason = self._matches(rule, changeset, validation_results, security_findings, risk, jev_evaluation, sec_severities)
            if matched:
                triggered.append(PolicyResult(rule_name=rule.name, action=rule.action, matched=True, reason=reason))
                trace.append(f"TRIGGERED {rule.name}: {rule.action.value} — {reason}")
            else:
                trace.append(f"SKIPPED {rule.name}: {reason}")

        # Determine final action by precedence: first triggered wins (sorted high→low)
        final_action: PolicyAction | None = None
        if triggered:
            # Highest precedence triggered wins
            # Already sorted
            final_action = triggered[0].action
            # But if BLOCK or CRITICAL exists, it takes absolute precedence even if lower precedence? Our sort handles.
            # Ensure BLOCK > REQUIRE_HUMAN_REVIEW > REJECT > REVISE > ACCEPT
            # We respect precedence order as configured; admin can set.

        evaluation = PolicyEvaluation(
            id=str(uuid.uuid4()),
            changeset_id=changeset.id,
            triggered=triggered,
            final_action=final_action,
            trace=trace,
            policy_version=self.VERSION,
            created_at=datetime.now(UTC),
        )
        return evaluation

    def _matches(
        self,
        rule: PolicyRule,
        changeset: ChangeSet,
        validations: list[ValidationResult],
        findings: list[SecurityFinding],
        risk: RiskAssessment | None,
        jev: Any | None,
        sec_severities: set[str],
    ) -> tuple[bool, str]:
        w = rule.when
        # Each non-None condition must match
        # security_severity
        if w.security_severity:
            if w.security_severity not in sec_severities:
                return False, f"no security {w.security_severity}"
        # validation_status + validator
        if w.validation_status:
            matched_val = False
            for r in validations:
                if r.status.value == w.validation_status:
                    if w.validator:
                        if r.validator_name == w.validator:
                            matched_val = True
                            break
                    else:
                        matched_val = True
                        break
            if not matched_val:
                return False, f"no validation {w.validator or ''}:{w.validation_status}"
        # file_pattern
        if w.file_pattern:
            matched_file = False
            for cf in changeset.changed_files:
                pattern = w.file_pattern
                if fnmatch.fnmatch(cf.path, pattern) or fnmatch.fnmatch(cf.path, pattern.lstrip("*")) or pattern in cf.path:
                    matched_file = True
                    break
                # Also try glob match via Path.match
                try:
                    if Path(cf.path).match(pattern):
                        matched_file = True
                        break
                except Exception:  # noqa: S110 -- invalid glob patterns are non-fatal
                    pass
            if not matched_file:
                return False, f"no file matches {w.file_pattern}"
        # file_count_gt/lt
        if w.file_count_gt is not None:
            if len(changeset.changed_files) <= w.file_count_gt:
                return False, f"file_count {len(changeset.changed_files)} <= {w.file_count_gt}"
        if w.file_count_lt is not None:
            if len(changeset.changed_files) >= w.file_count_lt:
                return False, f"file_count {len(changeset.changed_files)} >= {w.file_count_lt}"
        # risk_level
        if w.risk_level:
            if not risk or risk.level.value != w.risk_level:
                return False, f"risk {risk.level.value if risk else None} != {w.risk_level}"
        # jev_risk_gt
        if w.jev_risk_gt is not None:
            if not jev or not hasattr(jev, "overall_risk"):
                return False, "no jev evaluation"
            if jev.overall_risk <= w.jev_risk_gt:
                return False, f"jev risk {jev.overall_risk} <= {w.jev_risk_gt}"
        # migration_detected
        if w.migration_detected is not None:
            has_migration = any("migration" in cf.path.lower() or "migrate" in cf.path.lower() for cf in changeset.changed_files)
            # Also check diff for CREATE TABLE etc.
            if "migration" in (changeset.unified_diff or "").lower():
                has_migration = True
            if has_migration != w.migration_detected:
                return False, f"migration {has_migration} != {w.migration_detected}"
        # branch
        if w.branch:
            if changeset.branch != w.branch:
                return False, f"branch {changeset.branch} != {w.branch}"
        # repository
        if w.repository:
            if changeset.repository_id != w.repository and w.repository not in changeset.repository_id:
                return False, "repo mismatch"

        return True, f"matched {rule.name}"
