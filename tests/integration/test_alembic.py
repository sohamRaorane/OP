"""Migrations must reproduce the ORM schema — regression test for drift.

If you add/change an ORM table, this fails until you generate a new revision:
alembic revision --autogenerate -m "your change"
"""

from __future__ import annotations

from pathlib import Path

from sqlalchemy import create_engine, inspect

from alembic import command
from alembic.config import Config
from sentinel.core.db import Base
from sentinel.repository.orm import AuditEventORM, ChangeSetORM, RepositoryORM  # noqa: F401

REPO_ROOT = Path(__file__).resolve().parents[2]


def make_config(db_url: str) -> Config:
    cfg = Config(str(REPO_ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(REPO_ROOT / "alembic"))
    # env.py honors this attribute over settings (programmatic override)
    cfg.attributes["sqlalchemy.url"] = db_url
    return cfg


def test_upgrade_head_reproduces_orm_schema(tmp_path: Path) -> None:
    db_path = tmp_path / "migrate.db"
    cfg = make_config(f"sqlite:///{db_path}")
    command.upgrade(cfg, "head")

    engine = create_engine(f"sqlite:///{db_path}")
    inspector = inspect(engine)
    migrated = {
        t: sorted(c["name"] for c in inspector.get_columns(t))
        for t in inspector.get_table_names()
        if t != "alembic_version"
    }
    expected = {t: sorted(c.name for c in tbl.columns) for t, tbl in Base.metadata.tables.items()}

    assert migrated == expected, (
        f"schema drift: migration={sorted(migrated)} orm={sorted(expected)}; "
        "run: alembic revision --autogenerate -m 'describe change'"
    )
    assert inspector.has_table("alembic_version"), "alembic_version missing after upgrade"
