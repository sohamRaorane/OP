"""Database setup — SQLAlchemy 2, PostgreSQL / SQLite."""

from __future__ import annotations

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker

from sentinel.config.settings import get_settings


class Base(DeclarativeBase):
    pass


def get_engine():
    settings = get_settings()
    url = settings.database_url
    # For SQLite, need check_same_thread
    connect_args = {}
    if url.startswith("sqlite"):
        connect_args = {"check_same_thread": False}
    engine = create_engine(url, connect_args=connect_args, echo=False, future=True)
    return engine


def get_session_factory():
    engine = get_engine()
    return sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)


def init_db() -> None:
    """Create all tables — for dev/testing. Production uses Alembic."""
    from sentinel.core import models  # noqa: F401 ensure models imported
    # Import ORM models to register
    import sentinel.audit.orm  # noqa: F401
    import sentinel.repository.orm  # noqa: F401

    engine = get_engine()
    Base.metadata.create_all(bind=engine)
