"""OpenRouterJevClient tests — contract mapping, error handling (offline via MockTransport)."""

from __future__ import annotations

from collections.abc import Callable

import httpx
import pytest

from sentinel.core.exceptions import JevMalformedResponseError, JevUnavailableError
from sentinel.core.models.jev import JevContext, JevDimension
from sentinel.jev.openrouter import (
    DEFAULT_DECISIONS_URL,
    OpenRouterJevClient,
    build_questions,
    build_state,
)

SAMPLE_RESPONSE = {
    "id": "gen-dec-test",
    "model": "typesafe/jev-1.13-20260917",
    "provider": "TypeSafe",
    "answers": {
        "task_alignment": {"type": "score", "score": 0.1, "confidence": 0.9, "probabilities": {"0": 1}},
        "unrelated_changes": {"type": "score", "score": 0.0, "confidence": 0.9, "probabilities": {"0": 1}},
        "security_risk": {"type": "score", "score": 1.9, "confidence": 0.8, "probabilities": {"2": 1}},
        "interface_compatibility": {"type": "score", "score": 0.0, "confidence": 0.9, "probabilities": {"0": 1}},
        "destructive_behavior": {"type": "score", "score": 0.4, "confidence": 0.7, "probabilities": {"0": 0.8, "1": 0.2}},
        "unnecessary_scope": {"type": "score", "score": 0.0, "confidence": 0.9, "probabilities": {"0": 1}},
        "regression_risk": {"type": "noul", "noul": 0.25},
    },
    "usage": {"input_tokens": 400, "output_tokens": 70, "cost": 0.00002},
}


def make_client(handler: Callable[[httpx.Request], httpx.Response]) -> OpenRouterJevClient:
    transport = httpx.MockTransport(handler)
    return OpenRouterJevClient(api_key="sk-or-test", transport=transport)


def test_build_state_includes_diff_and_summaries() -> None:
    ctx = JevContext(
        task="fix login",
        changed_files=["a.py"],
        relevant_diff="diff --git a/a.py",
        validation_summary=[{"validator": "pytest", "status": "PASS"}],
        security_summary=[{"severity": "HIGH"}],
    )
    state = build_state(ctx)
    assert state["task"] == "fix login"
    assert state["diff"].startswith("diff --git")
    assert state["validations"][0]["status"] == "PASS"
    assert state["security_findings"][0]["severity"] == "HIGH"


def test_build_questions_covers_all_dimensions() -> None:
    questions = build_questions()
    assert set(questions) == {d.value for d in JevDimension}
    assert all(q["type"] == "score" and len(q["criteria"]) == 3 for q in questions.values())


async def test_evaluate_maps_answers_to_scores() -> None:
    seen: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["auth"] = request.headers.get("Authorization")
        seen["url"] = str(request.url)
        return httpx.Response(200, json=SAMPLE_RESPONSE)

    client = make_client(handler)
    evaluation = await client.evaluate(JevContext(task="t", changed_files=["a.py"]))

    # Request contract
    assert seen["auth"] == "Bearer sk-or-test"
    assert seen["url"] == DEFAULT_DECISIONS_URL

    # Response mapping
    assert evaluation.is_mock is False
    assert evaluation.provider == "typesafe"
    assert evaluation.model == "typesafe/jev-1.13-20260917"
    by_dim = {s.dimension: s for s in evaluation.scores}
    assert len(evaluation.scores) == 7
    # score 1.9 on 3-level scale -> 1.9/2 = 0.95
    assert by_dim[JevDimension.SECURITY_RISK].score == pytest.approx(0.95)
    assert by_dim[JevDimension.TASK_ALIGNMENT].score == pytest.approx(0.05)
    # noul 0.25 -> risk 0.25, confidence |0.25-0.5|*2 = 0.5
    assert by_dim[JevDimension.REGRESSION_RISK].score == pytest.approx(0.25)
    assert by_dim[JevDimension.REGRESSION_RISK].confidence == pytest.approx(0.5)
    assert 0.0 <= evaluation.overall_risk <= 1.0
    assert "cost" in (evaluation.summary or "")
    assert evaluation.raw_response is not None
    assert evaluation.raw_response["usage"]["cost"] == 0.00002


async def test_auth_failure_raises_unavailable() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, json={"error": {"message": "Missing Authentication header", "code": 401}})

    client = make_client(handler)
    with pytest.raises(JevUnavailableError, match="authentication failed"):
        await client.evaluate(JevContext(task="t"))


async def test_server_error_raises_unavailable() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(503, text="upstream down")

    client = make_client(handler)
    with pytest.raises(JevUnavailableError, match="provider error"):
        await client.evaluate(JevContext(task="t"))


async def test_missing_answers_raises_malformed() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"id": "x"})

    client = make_client(handler)
    with pytest.raises(JevMalformedResponseError, match="answers"):
        await client.evaluate(JevContext(task="t"))


async def test_missing_key_raises_unavailable() -> None:
    client = OpenRouterJevClient(api_key=None)
    assert client.is_available() is False
    with pytest.raises(JevUnavailableError, match="API key"):
        await client.evaluate(JevContext(task="t"))


def test_is_available_with_key() -> None:
    assert OpenRouterJevClient(api_key="sk-or-x").is_available() is True
