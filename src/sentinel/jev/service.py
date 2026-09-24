"""JevDecisionService — handles timeout, retry, malformed — Phase 5."""

from __future__ import annotations

import asyncio
import time
import uuid
from datetime import UTC, datetime

import structlog

from sentinel.core.exceptions import JevMalformedResponseError, JevTimeoutError, JevUnavailableError
from sentinel.core.models.jev import JevContext, JevEvaluation
from sentinel.jev.client import JevClient
from sentinel.jev.mock import MockJevClient

logger = structlog.get_logger(__name__)


class JevDecisionService:
    """Wraps JevClient with timeout, retry, fallback."""

    def __init__(
        self,
        client: JevClient | None = None,
        timeout: int = 30,
        max_retries: int = 2,
        fallback_to_mock: bool = True,
    ) -> None:
        self.client = client or MockJevClient()
        self.timeout = timeout
        self.max_retries = max_retries
        self.fallback_to_mock = fallback_to_mock

    async def evaluate_with_retry(self, context: JevContext) -> JevEvaluation:
        """Evaluate with timeout and retries, structured logging."""
        start = time.monotonic()
        last_error: Exception | None = None
        for attempt in range(1, self.max_retries + 2):  # initial + retries
            try:
                logger.info("jev_request", attempt=attempt, fixture=getattr(self.client, "fixture", "unknown"))
                # Timeout handling
                try:
                    evaluation: JevEvaluation = await asyncio.wait_for(self.client.evaluate(context), timeout=self.timeout)
                except TimeoutError as e:
                    raise JevTimeoutError(f"JEV timeout after {self.timeout}s") from e

                # Validate response
                if not evaluation.scores:
                    raise JevMalformedResponseError("Empty scores in JEV response")

                logger.info(
                    "jev_response", evaluation_id=evaluation.id,
                    overall_risk=evaluation.overall_risk, latency_ms=evaluation.latency_ms,
                )
                evaluation.latency_ms = int((time.monotonic() - start) * 1000)
                return evaluation

            except (JevTimeoutError, JevUnavailableError, JevMalformedResponseError) as e:
                last_error = e
                logger.warning("jev_error", attempt=attempt, error=str(e), error_type=type(e).__name__)
                if attempt <= self.max_retries:
                    # Exponential backoff: 0.5s, 1s
                    await asyncio.sleep(0.5 * attempt)
                    continue
                # Exhausted retries
                break
            except Exception as e:
                last_error = e
                logger.error("jev_unexpected_error", error=str(e))
                break

        # Fallback or propagate
        if self.fallback_to_mock and not isinstance(self.client, MockJevClient):
            logger.warning("jev_fallback_to_mock", reason=str(last_error))
            mock = MockJevClient(fixture="ambiguous_result")
            try:
                return await mock.evaluate(context)
            except Exception:  # noqa: S110 -- mock fallback failure falls through to conservative result
                pass

        # If all fails, return a conservative evaluation (high risk) rather than failing open
        # But mark as malformed/unavailable
        logger.error("jev_all_retries_failed", error=str(last_error))
        if isinstance(last_error, JevTimeoutError):
            return JevEvaluation(
                id=str(uuid.uuid4()),
                provider="mock-fallback",
                created_at=datetime.now(UTC),
                latency_ms=int((time.monotonic() - start) * 1000),
                scores=[],
                overall_risk=0.7,
                summary="JEV timeout — conservative fallback",
                is_mock=True,
                timed_out=True,
            )
        if isinstance(last_error, JevUnavailableError):
            return JevEvaluation(
                id=str(uuid.uuid4()),
                provider="mock-fallback",
                created_at=datetime.now(UTC),
                latency_ms=int((time.monotonic() - start) * 1000),
                scores=[],
                overall_risk=0.6,
                summary="JEV unavailable — conservative fallback",
                is_mock=True,
            )
        # Malformed or other
        raise last_error or JevMalformedResponseError("JEV evaluation failed")
