"""MockJevClient — deterministic fixtures for testing — Phase 5."""

from __future__ import annotations

import asyncio
import uuid
from datetime import UTC, datetime

from sentinel.core.exceptions import JevMalformedResponseError, JevTimeoutError, JevUnavailableError
from sentinel.core.models.jev import JevContext, JevDimension, JevEvaluation, JevScore
from sentinel.jev.client import JevClient


class MockJevClient(JevClient):
    """Deterministic mock — supports fixtures for predictable testing."""

    # Fixture presets
    FIXTURES: dict[str, dict[JevDimension, float]] = {
        "high_confidence_safe": {
            JevDimension.TASK_ALIGNMENT: 0.05,
            JevDimension.UNRELATED_CHANGES: 0.05,
            JevDimension.SECURITY_RISK: 0.05,
            JevDimension.INTERFACE_COMPATIBILITY: 0.05,
            JevDimension.DESTRUCTIVE_BEHAVIOR: 0.02,
            JevDimension.UNNECESSARY_SCOPE: 0.05,
            JevDimension.REGRESSION_RISK: 0.05,
        },
        "suspicious_change": {
            JevDimension.TASK_ALIGNMENT: 0.6,
            JevDimension.UNRELATED_CHANGES: 0.7,
            JevDimension.SECURITY_RISK: 0.5,
            JevDimension.INTERFACE_COMPATIBILITY: 0.6,
            JevDimension.DESTRUCTIVE_BEHAVIOR: 0.4,
            JevDimension.UNNECESSARY_SCOPE: 0.7,
            JevDimension.REGRESSION_RISK: 0.6,
        },
        "unrelated_change": {
            JevDimension.TASK_ALIGNMENT: 0.8,
            JevDimension.UNRELATED_CHANGES: 0.9,
            JevDimension.SECURITY_RISK: 0.3,
            JevDimension.INTERFACE_COMPATIBILITY: 0.5,
            JevDimension.DESTRUCTIVE_BEHAVIOR: 0.2,
            JevDimension.UNNECESSARY_SCOPE: 0.85,
            JevDimension.REGRESSION_RISK: 0.5,
        },
        "security_concern": {
            JevDimension.TASK_ALIGNMENT: 0.4,
            JevDimension.UNRELATED_CHANGES: 0.5,
            JevDimension.SECURITY_RISK: 0.9,
            JevDimension.INTERFACE_COMPATIBILITY: 0.4,
            JevDimension.DESTRUCTIVE_BEHAVIOR: 0.7,
            JevDimension.UNNECESSARY_SCOPE: 0.5,
            JevDimension.REGRESSION_RISK: 0.6,
        },
        "ambiguous_result": {
            JevDimension.TASK_ALIGNMENT: 0.5,
            JevDimension.UNRELATED_CHANGES: 0.5,
            JevDimension.SECURITY_RISK: 0.5,
            JevDimension.INTERFACE_COMPATIBILITY: 0.5,
            JevDimension.DESTRUCTIVE_BEHAVIOR: 0.5,
            JevDimension.UNNECESSARY_SCOPE: 0.5,
            JevDimension.REGRESSION_RISK: 0.5,
        },
        "destructive": {
            JevDimension.TASK_ALIGNMENT: 0.3,
            JevDimension.UNRELATED_CHANGES: 0.6,
            JevDimension.SECURITY_RISK: 0.8,
            JevDimension.INTERFACE_COMPATIBILITY: 0.7,
            JevDimension.DESTRUCTIVE_BEHAVIOR: 0.95,
            JevDimension.UNNECESSARY_SCOPE: 0.6,
            JevDimension.REGRESSION_RISK: 0.8,
        },
    }

    def __init__(
        self,
        fixture: str = "high_confidence_safe",
        latency_ms: int = 50,
        should_timeout: bool = False,
        should_malform: bool = False,
        should_unavailable: bool = False,
        is_mock: bool = True,
    ) -> None:
        self.fixture = fixture
        self.latency_ms = latency_ms
        self.should_timeout = should_timeout
        self.should_malform = should_malform
        self.should_unavailable = should_unavailable
        self.is_mock = is_mock
        self.call_count = 0
        self.last_context: JevContext | None = None

    def is_available(self) -> bool:
        return not self.should_unavailable

    async def evaluate(self, context: JevContext) -> JevEvaluation:
        self.call_count += 1
        self.last_context = context

        if self.should_unavailable:
            raise JevUnavailableError("JEV provider unavailable (mock)")

        if self.should_timeout:
            # Simulate timeout by sleeping longer than caller's timeout? For now raise
            raise JevTimeoutError("JEV request timed out (mock)")

        if self.should_malform:
            raise JevMalformedResponseError("JEV malformed response (mock)")

        # Simulate latency
        if self.latency_ms > 0:
            await asyncio.sleep(self.latency_ms / 1000.0)

        # Choose fixture scores
        scores_map = self.FIXTURES.get(self.fixture, self.FIXTURES["high_confidence_safe"])
        # Heuristic override: if diff contains DROP TABLE, elevate destructive/security
        diff = (context.relevant_diff or "").lower()
        if "drop table" in diff or "rm -rf" in diff:
            scores_map = dict(scores_map)
            scores_map[JevDimension.DESTRUCTIVE_BEHAVIOR] = 0.95
            scores_map[JevDimension.SECURITY_RISK] = 0.9

        # If security findings indicate critical, elevate
        if context.security_summary:
            for f in context.security_summary:
                if f.get("severity") == "CRITICAL":
                    scores_map = dict(scores_map)
                    scores_map[JevDimension.SECURITY_RISK] = max(scores_map.get(JevDimension.SECURITY_RISK, 0), 0.85)

        scores: list[JevScore] = []
        for dim, score in scores_map.items():
            # Add small jitter for realism unless fixture is deterministic?
            # Keep deterministic for tests: no jitter
            scores.append(
                JevScore(
                    dimension=dim,
                    score=score,
                    confidence=0.85 if score < 0.5 else 0.75,
                    reasoning=f"Mock evaluation for {dim.value}: {score:.2f}",
                )
            )

        overall = sum(s.score for s in scores) / len(scores) if scores else 0.0

        evaluation = JevEvaluation(
            id=str(uuid.uuid4()),
            provider="mock",
            model="mock-1.0",
            created_at=datetime.now(UTC),
            latency_ms=self.latency_ms,
            scores=scores,
            overall_risk=overall,
            summary=f"Mock {self.fixture}: overall {overall:.2f}",
            raw_response={"fixture": self.fixture, "scores": {s.dimension.value: s.score for s in scores}},
            is_mock=True,
            timed_out=False,
            is_malformed=False,
        )
        return evaluation

    def set_fixture(self, fixture: str) -> None:
        if fixture not in self.FIXTURES:
            raise ValueError(f"Unknown fixture: {fixture}")
        self.fixture = fixture
