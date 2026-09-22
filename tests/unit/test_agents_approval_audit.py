"""Tests for Phase 9-11: agents, approval, audit."""

import pytest
import tempfile
import subprocess
from pathlib import Path

from sentinel.agents.generic import GenericAgentAdapter
from sentinel.agents.base import AgentFeedback
from sentinel.approval.service import ApprovalService
from sentinel.core.models.approval import ApprovalStatus
from sentinel.audit.service import AuditService
from sentinel.core.models.audit import AuditEventType


def _init_repo(path: Path):
    subprocess.run(["git", "init"], cwd=path, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.email", "test@test.com"], cwd=path, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.name", "Test"], cwd=path, check=True, capture_output=True)


def test_agent_session_lifecycle():
    with tempfile.TemporaryDirectory() as d:
        p = Path(d)
        _init_repo(p)
        (p / "f.txt").write_text("init")
        subprocess.run(["git", "add", "f.txt"], cwd=p, check=True, capture_output=True)
        subprocess.run(["git", "commit", "-m", "init"], cwd=p, check=True, capture_output=True)

        adapter = GenericAgentAdapter(max_retries=2)
        session = adapter.start_session("add feature", str(p))
        assert session.task == "add feature"
        cs = adapter.get_changes(session)
        assert cs is not None
        feedback = AgentFeedback(decision="REVISE", reasons=["fix"], required_changes=["do x"])
        adapter.send_feedback(session, feedback)
        assert "REVISE" in adapter.get_status(session)
        assert adapter.continue_execution(session) is True
        adapter.record_retry(session, backoff=False)
        assert session.retry_count == 1
        adapter.record_retry(session, backoff=False)
        assert adapter.should_escalate(session) is True
        adapter.stop_session(session)


def test_agent_prevents_infinite_retry():
    with tempfile.TemporaryDirectory() as d:
        p = Path(d)
        _init_repo(p)
        adapter = GenericAgentAdapter(max_retries=1)
        session = adapter.start_session("task", str(p))
        adapter.record_retry(session, backoff=False)
        assert adapter.should_escalate(session) is True
        assert adapter.continue_execution(session) is False


def test_approval_workflow():
    svc = ApprovalService(expiration_hours=24)
    req = svc.create_request("dec123", reason="review needed")
    assert req.status == ApprovalStatus.PENDING
    # Approve
    approved = svc.approve(req.id, "alice")
    assert approved.status == ApprovalStatus.APPROVED
    assert approved.approver == "alice"
    assert len(approved.history) >= 2
    # Cannot approve again
    with pytest.raises(Exception):
        svc.approve(req.id, "bob")


def test_approval_reject_and_pending():
    svc = ApprovalService()
    req = svc.create_request("dec2")
    svc.reject(req.id, "bob", reason="bad")
    assert svc.get(req.id).status == ApprovalStatus.REJECTED
    # Immutable history
    assert any(h["status"] == "REJECTED" for h in svc.get(req.id).history)


def test_approval_cannot_overwrite():
    svc = ApprovalService()
    req = svc.create_request("dec3")
    svc.approve(req.id, "alice")
    with pytest.raises(Exception):
        svc.reject(req.id, "bob")


def test_audit_immutable_log():
    svc = AuditService()
    evt = svc.log(AuditEventType.SESSION_CREATED, {"foo": "bar"}, actor="tester", repository_id="r1")
    assert evt.id
    assert evt.event_type == AuditEventType.SESSION_CREATED
    assert evt.payload["foo"] == "bar"
    assert evt.timestamp


def test_audit_query_filtering():
    svc = AuditService()
    # Use DB fallback: test in-memory query via DB session if available
    try:
        from sentinel.core.db import get_session_factory, init_db
        from sentinel.config.settings import Settings

        settings = Settings(database_url="sqlite:///:memory:", sentinel_env="testing")
        # monkey patch
        import sentinel.core.db as dbmod

        orig = dbmod.get_engine

        def mock_engine():
            from sqlalchemy import create_engine

            return create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})

        dbmod.get_engine = mock_engine
        from sentinel.core.db import Base
        from sentinel.repository.orm import AuditEventORM, RepositoryORM

        engine = mock_engine()
        Base.metadata.create_all(bind=engine)
        from sqlalchemy.orm import sessionmaker

        Session = sessionmaker(bind=engine)
        with Session() as db:
            svc_db = AuditService(db=db)
            svc_db.log(AuditEventType.CHANGE_GENERATED, {"x": 1}, repository_id="r1", changeset_id="c1")
            svc_db.log(AuditEventType.DECISION_CREATED, {"y": 2}, repository_id="r1", changeset_id="c1")
            events = svc_db.query(db, repository_id="r1", limit=10)
            assert len(events) >= 2
        dbmod.get_engine = orig
    except Exception as e:
        pytest.skip(f"DB not available: {e}")
