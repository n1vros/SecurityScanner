"""Recheck selection honours the persisted takeover retry timestamp."""

from datetime import datetime, timedelta
from pathlib import Path

import pytest

from app.core.config import Settings
from app.core.scheduler import Scheduler, retry_due_clause
from app.db.db_models import Subdomain
from app.takeover.subdomain_hunter.retry_policy import retry_is_due


class FakeResult:
    def scalars(self):
        return self

    def all(self):
        return []


class CapturingSession:
    def __init__(self):
        self.statements = []

    async def execute(self, stmt):
        self.statements.append(stmt)
        return FakeResult()


def compiled(stmt) -> str:
    return str(stmt.compile(compile_kwargs={"literal_binds": True}))


@pytest.mark.asyncio
async def test_potential_recheck_skips_future_retry_timestamps():
    session = CapturingSession()

    await Scheduler.get_potential_subdomains_needing_recheck(session, limit=5)

    sql = compiled(session.statements[0])
    assert "takeover_retry_at" in sql


@pytest.mark.asyncio
async def test_potential_long_recheck_skips_future_retry_timestamps():
    session = CapturingSession()

    await Scheduler.get_potential_long_subdomains_needing_recheck(session, limit=5)

    sql = compiled(session.statements[0])
    assert "takeover_retry_at" in sql


@pytest.mark.asyncio
async def test_dangling_retry_query_selects_only_due_recorded_outcomes():
    session = CapturingSession()

    await Scheduler.get_dangling_subdomains_needing_retry(session, limit=5)

    sql = compiled(session.statements[0])
    assert "takeover_retry_at IS NOT NULL" in sql
    assert "subdomains.state" in sql
    assert "last_scanned_at" in sql


def test_retry_due_clause_treats_null_as_due():
    clause = retry_due_clause(datetime.utcnow())

    sql = str(clause.compile(compile_kwargs={"literal_binds": True}))
    assert "takeover_retry_at IS NULL" in sql
    assert "takeover_retry_at <=" in sql


def test_new_takeover_settings_have_sensible_defaults():
    fields = Settings.model_fields

    assert fields["TAKEOVER_AUTO_ENABLED"].default is True
    assert fields["TAKEOVER_RETRY_HOURS"].default == 24
    assert fields["TAKEOVER_RETRY_DAYS"].default == 7
    assert fields["TAKEOVER_CLAIM_VALIDATE_TIMEOUT"].default == 15.0
    assert fields["TAKEOVER_CLAIM_VALIDATE_ATTEMPTS"].default == 3
    assert fields["TAKEOVER_CLAIM_MARKER"].default == "STO by Rizin"


def test_subdomain_retry_columns_and_migrations_exist():
    columns = Subdomain.__table__.columns
    assert "takeover_retry_at" in columns
    assert "takeover_last_status" in columns
    assert columns["takeover_retry_at"].nullable is True
    assert columns["takeover_last_status"].nullable is True

    migrations = Path("app/db/session.py").read_text(encoding="utf-8")
    assert "ADD COLUMN IF NOT EXISTS takeover_retry_at" in migrations
    assert "ADD COLUMN IF NOT EXISTS takeover_last_status" in migrations
    assert "ix_subdomains_takeover_retry_at" in migrations


def test_http_probe_columns_are_declared():
    # The HTTP prober assigns these attributes and the notification/web layers
    # read them; without real columns a fresh query raises AttributeError.
    columns = Subdomain.__table__.columns
    for name in (
        "http_status",
        "http_title",
        "http_body_hash",
        "http_content_length",
        "http_probed_at",
    ):
        assert name in columns


@pytest.mark.asyncio
async def test_retry_schedule_supports_manual_outcomes_becoming_due():
    now = datetime.utcnow()
    future = now + timedelta(days=7)
    past = now - timedelta(seconds=1)

    assert not retry_is_due(future, now)
    assert retry_is_due(past, now)

    # The SQL predicate uses the same boundary, so a pending manual retry is
    # picked up automatically once its timestamp elapses.
    clause_sql = str(
        retry_due_clause(now).compile(compile_kwargs={"literal_binds": True})
    )
    assert "takeover_retry_at <=" in clause_sql


def test_env_example_documents_new_settings():
    text = Path(".env.example").read_text(encoding="utf-8")
    for name in (
        "TAKEOVER_AUTO_ENABLED",
        "TAKEOVER_RETRY_HOURS",
        "TAKEOVER_RETRY_DAYS",
        "TAKEOVER_CLAIM_MARKER",
        "TAKEOVER_CLAIM_VALIDATE_TIMEOUT",
        "TAKEOVER_CLAIM_VALIDATE_ATTEMPTS",
    ):
        assert name in text

    assert "TAKEOVER_SIGNATURES_PATH=files/signatures.yaml" in text
