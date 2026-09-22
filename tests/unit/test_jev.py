"""JEV mock tests — Phase 5."""

from __future__ import annotations

import pytest

from sentinel.core.models.jev import JevContext
from sentinel.jev.mock import MockJevClient
from sentinel.jev.service import JevDecisionService


@pytest.mark.asyncio
async def test_mock_jev_high_confidence_safe():
    client = MockJevClient(fixture="high_confidence_safe")
    ctx = JevContext(task="test", changed_files=["a.py"], relevant_diff="hello")
    eval = await client.evaluate(ctx)
    assert eval.overall_risk < 0.3
    assert eval.is_mock is True
    assert len(eval.scores) == 7


@pytest.mark.asyncio
async def test_mock_jev_security_concern():
    client = MockJevClient(fixture="security_concern")
    ctx = JevContext(task="test", relevant_diff="normal diff")
    eval = await client.evaluate(ctx)
    # Security risk should be high
    sec = next(s for s in eval.scores if s.dimension.value == "security_risk")
    assert sec.score >= 0.8


@pytest.mark.asyncio
async def test_mock_jev_timeout_simulation():
    client = MockJevClient(should_timeout=True)
    service = JevDecisionService(client=client, timeout=1, max_retries=1)
    ctx = JevContext(task="test")
    eval = await service.evaluate_with_retry(ctx)
    # Should return fallback conservative evaluation
    assert eval.timed_out is True or eval.overall_risk >= 0.5


@pytest.mark.asyncio
async def test_mock_jev_unavailable_fallback():
    client = MockJevClient(should_unavailable=True)
    service = JevDecisionService(client=client, timeout=1, max_retries=1)
    ctx = JevContext(task="test")
    eval = await service.evaluate_with_retry(ctx)
    assert eval.overall_risk >= 0.5


@pytest.mark.asyncio
async def test_mock_jev_malformed_handling():
    client = MockJevClient(should_malform=True)
    service = JevDecisionService(client=client, timeout=1, max_retries=1)
    ctx = JevContext(task="test")
    with pytest.raises(Exception):
        await service.evaluate_with_retry(ctx)


@pytest.mark.asyncio
async def test_jev_context_minimization():
    from sentinel.jev.client import JevContextBuilder
    from sentinel.core.models.repository import ChangeSet, ChangedFile, FileChangeType
    import uuid
    from datetime import datetime, timezone

    builder = JevContextBuilder()
    cs = ChangeSet(
        repository_id=str(uuid.uuid4()),
        baseline_commit="a",
        current_commit="b",
        generated_at=datetime.now(timezone.utc),
        changed_files=[ChangedFile(path="a.py", change_type=FileChangeType.MODIFIED)],
        unified_diff="x" * 20000,  # huge diff
    )
    ctx = builder.build(task="do thing", changeset=cs, validation_results=[], security_findings=[])
    assert len(ctx.relevant_diff or "") <= 9000  # truncated
    assert ctx.diff_truncated is True
    assert ctx.task == "do thing"


@pytest.mark.asyncio
async def test_jev_not_directly_deciding_accept():
    # Ensure JEV result is not directly used to produce ACCEPT/REJECT
    # It must be consumed by risk/decision layers — we test service returns evaluation, not decision
    client = MockJevClient(fixture="high_confidence_safe")
    ctx = JevContext(task="test")
    eval = await client.evaluate(ctx)
    # Evaluation should not contain decision action
    assert not hasattr(eval, "action")
    assert hasattr(eval, "overall_risk")
