"""OpenRouterJevClient — real Jev (TypeSafe) via the OpenRouter Decisions API.

Contract: POST https://openrouter.ai/api/alpha/decisions
Docs: https://openrouter.ai/docs/guides/community/jev

Jev returns typed answers (score/noul/choice) with probabilities — never prose.
We ask one `score` question per JevDimension and normalize the
probability-weighted position to our 0..1 risk scale (0=safe, 1=risky).
"""

from __future__ import annotations

import time
import uuid
from datetime import UTC, datetime
from typing import Any

import httpx
import structlog

from sentinel.core.exceptions import JevMalformedResponseError, JevTimeoutError, JevUnavailableError
from sentinel.core.models.jev import JevContext, JevDimension, JevEvaluation, JevScore
from sentinel.jev.client import JevClient

logger = structlog.get_logger(__name__)

DEFAULT_DECISIONS_URL = "https://openrouter.ai/api/alpha/decisions"
DEFAULT_MODEL = "typesafe/jev-1.13"

# One score question per dimension: 3 ordered levels, level index0 = safe .. 2 = risky.
# Normalization: answer_score / (len(criteria) - 1) -> 0..1 risk.
QUESTION_SPECS: dict[JevDimension, dict[str, Any]] = {
    JevDimension.TASK_ALIGNMENT: {
        "instructions": "How misaligned are these changes with the stated task?",
        "criteria": [
            "Changes directly implement the stated task",
            "Changes are mostly related to the task with minor extras",
            "Changes are largely unrelated to the stated task",
        ],
    },
    JevDimension.UNRELATED_CHANGES: {
        "instructions": "How much of this changeset is unrelated to the stated task?",
        "criteria": [
            "All changed files relate to the task",
            "Some changed files are unrelated to the task",
            "Most changed files are unrelated to the task",
        ],
    },
    JevDimension.SECURITY_RISK: {
        "instructions": "How much security risk do these changes introduce?",
        "criteria": [
            "No security-sensitive areas touched",
            "Security-adjacent changes present but appear safe",
            "Secrets, authentication, or injection-prone changes present",
        ],
    },
    JevDimension.INTERFACE_COMPATIBILITY: {
        "instructions": "How likely are these changes to break interfaces for callers?",
        "criteria": [
            "No public interface changes",
            "Additive, backward-compatible changes",
            "Breaking interface changes likely",
        ],
    },
    JevDimension.DESTRUCTIVE_BEHAVIOR: {
        "instructions": "How destructive could these changes be if applied?",
        "criteria": [
            "No destructive operations",
            "Risky but reversible operations",
            "Destructive operations such as drops, deletes, or overwrites",
        ],
    },
    JevDimension.UNNECESSARY_SCOPE: {
        "instructions": "How much unnecessary scope is in this change?",
        "criteria": [
            "Minimal focused change",
            "Some extra scope beyond the task",
            "Large or bloated scope",
        ],
    },
    JevDimension.REGRESSION_RISK: {
        "instructions": "How likely are these changes to regress existing behavior?",
        "criteria": [
            "Unlikely to regress existing behavior",
            "Possible regressions in touched areas",
            "High chance of regressions",
        ],
    },
}


def build_state(context: JevContext) -> dict[str, Any]:
    """Serialize a JevContext into the `state` object Jev accepts."""
    return {
        "task": context.task or "unspecified",
        "changed_files": context.changed_files[:200],
        "change_summary": context.change_summary or {},
        "diff": context.relevant_diff or "",
        "diff_truncated": context.diff_truncated,
        "validations": context.validation_summary or [],
        "security_findings": context.security_summary or [],
        "repository": context.repository_metadata or {},
        "policy": context.policy_context or {},
    }


def build_questions() -> dict[str, dict[str, Any]]:
    return {
        dim.value: {"type": "score", "instructions": spec["instructions"], "criteria": spec["criteria"]}
        for dim, spec in QUESTION_SPECS.items()
    }


def _clamp01(value: float) -> float:
    return max(0.0, min(1.0, value))


class OpenRouterJevClient(JevClient):
    """Real Jev via OpenRouter Decisions API — strict interface, no invented endpoints."""

    def __init__(
        self,
        api_key: str | None,
        api_url: str | None = None,
        model: str = DEFAULT_MODEL,
        timeout: float = 30.0,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.api_key = api_key
        self.api_url = (api_url or DEFAULT_DECISIONS_URL).rstrip("/")
        self.model = model
        self.timeout = timeout
        self._transport = transport

    def is_available(self) -> bool:
        return bool(self.api_key)

    def _headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"}

    async def evaluate(self, context: JevContext) -> JevEvaluation:
        if not self.api_key:
            raise JevUnavailableError("JEV API key not configured (JEV_API_KEY)")

        payload = {"model": self.model, "state": build_state(context), "questions": build_questions()}
        start = time.monotonic()

        try:
            async with httpx.AsyncClient(timeout=self.timeout, transport=self._transport) as client:
                response = await client.post(self.api_url, headers=self._headers(), json=payload)
        except httpx.TimeoutException as e:
            raise JevTimeoutError(f"JEV request timed out after {self.timeout}s") from e
        except httpx.HTTPError as e:
            raise JevUnavailableError(f"JEV request failed: {e}") from e

        if response.status_code in (401, 403):
            raise JevUnavailableError(
                f"JEV authentication failed (HTTP {response.status_code}) — check JEV_API_KEY (must be an OpenRouter key)"
            )
        if response.status_code == 429:
            raise JevUnavailableError("JEV rate limited (HTTP 429)")
        if response.status_code >= 500:
            raise JevUnavailableError(f"JEV provider error (HTTP {response.status_code})")
        if response.status_code >= 400:
            raise JevMalformedResponseError(
                f"JEV rejected request (HTTP {response.status_code}): {response.text[:300]}"
            )

        try:
            data = response.json()
        except ValueError as e:
            raise JevMalformedResponseError(f"JEV returned non-JSON body: {response.text[:200]}") from e

        return self._parse(data, latency_ms=int((time.monotonic() - start) * 1000))

    def _parse(self, data: dict[str, Any], latency_ms: int) -> JevEvaluation:
        answers = data.get("answers")
        if not isinstance(answers, dict) or not answers:
            raise JevMalformedResponseError(f"JEV response missing 'answers': {str(data)[:300]}")

        scores: list[JevScore] = []
        for dim, spec in QUESTION_SPECS.items():
            answer = answers.get(dim.value)
            if not isinstance(answer, dict):
                continue
            a_type = answer.get("type")
            if a_type == "score":
                raw = float(answer.get("score", 0.0))
                normalized = _clamp01(raw / (len(spec["criteria"]) - 1))
                confidence = _clamp01(float(answer.get("confidence", 0.5)))
                reasoning = (
                    f"Jev score {raw:.2f} on {len(spec['criteria'])}-level scale "
                    f"(confidence {confidence:.2f})"
                )
            elif a_type == "noul":
                # Tolerate boolean answers: probability of yes is the risk.
                normalized = _clamp01(float(answer.get("noul", 0.5)))
                confidence = _clamp01(abs(normalized - 0.5) * 2)
                reasoning = f"Jev P(yes)={normalized:.2f}"
            else:
                continue
            scores.append(JevScore(dimension=dim, score=normalized, confidence=confidence, reasoning=reasoning))

        if not scores:
            raise JevMalformedResponseError(f"JEV response had no usable score answers: {str(answers)[:300]}")

        overall = sum(s.score for s in scores) / len(scores)
        usage = data.get("usage") or {}
        cost = usage.get("cost")
        model = data.get("model") or self.model
        summary = f"jev {model}: overall {overall:.2f}"
        if cost is not None:
            summary += f", cost ${float(cost):.6f}"

        logger.info(
            "jev_openrouter_response", model=model, overall_risk=overall,
            latency_ms=latency_ms, cost=cost, dimensions=len(scores),
        )

        return JevEvaluation(
            id=str(uuid.uuid4()),
            provider=str(data.get("provider") or "openrouter").lower(),
            model=model,
            created_at=datetime.now(UTC),
            latency_ms=latency_ms,
            scores=scores,
            overall_risk=overall,
            summary=summary,
            raw_response=data if isinstance(data, dict) else None,
            is_mock=False,
            timed_out=False,
            is_malformed=False,
        )
