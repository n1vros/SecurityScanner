"""Settings, due-time logic and schema coverage for automatic platform sync."""

from datetime import datetime, timedelta
from pathlib import Path

from app.core.config import Settings, settings
from app.db.db_models import PlatformSyncState
from app.programs.sync import (
    credentials_configured,
    is_due,
    platform_interval_days,
    select_due_platforms,
    sync_platform,
)

SYNC_SETTINGS = [
    "PLATFORM_SYNC_ENABLED",
    "PLATFORM_SYNC_POLL_SECONDS",
    "HACKERONE_SYNC_INTERVAL_DAYS",
    "YESWEHACK_SYNC_INTERVAL_DAYS",
    "INTIGRITI_SYNC_INTERVAL_DAYS",
    "BUGCROWD_SYNC_INTERVAL_DAYS",
]


def test_platform_sync_setting_defaults():
    fields = Settings.model_fields
    assert fields["PLATFORM_SYNC_ENABLED"].default is True
    assert fields["PLATFORM_SYNC_POLL_SECONDS"].default == 60
    for name in SYNC_SETTINGS[2:]:
        assert fields[name].default == 7.0


def test_env_example_documents_platform_sync_settings():
    text = Path(".env.example").read_text(encoding="utf-8")
    for name in SYNC_SETTINGS:
        assert name in text


def test_platform_sync_state_schema():
    assert PlatformSyncState.__tablename__ == "platform_sync_state"
    columns = set(PlatformSyncState.__table__.columns.keys())
    assert {
        "id",
        "platform",
        "last_synced_at",
        "last_status",
        "last_error",
        "updated_at",
    } <= columns
    assert PlatformSyncState.__table__.columns["platform"].unique is True

    session_source = Path("app/db/session.py").read_text(encoding="utf-8")
    assert "CREATE TABLE IF NOT EXISTS platform_sync_state" in session_source


def test_is_due_respects_per_platform_interval():
    now = datetime(2026, 1, 10)
    assert is_due(now, None, 7) is True
    assert is_due(now, now - timedelta(days=7), 7) is True
    assert is_due(now, now - timedelta(days=6, hours=23), 7) is False
    assert is_due(now, now - timedelta(days=3), 1) is True


def test_select_due_platforms_preserves_spec_order():
    now = datetime(2026, 1, 10)
    states = {
        "hackerone": now - timedelta(days=8),
        "yeswehack": now - timedelta(days=6),
        "intigriti": None,
        "bugcrowd": now,
    }
    intervals = {
        "hackerone": 7,
        "yeswehack": 7,
        "intigriti": 7,
        "bugcrowd": 7,
    }
    assert select_due_platforms(states, now, intervals) == [
        "hackerone",
        "intigriti",
    ]


def test_credentials_configured_requires_every_credential(monkeypatch):
    monkeypatch.setattr(settings, "H1_USERNAME", None)
    monkeypatch.setattr(settings, "H1_API_TOKEN", "token")
    assert credentials_configured("hackerone") is False

    monkeypatch.setattr(settings, "H1_USERNAME", "researcher")
    assert credentials_configured("hackerone") is True

    monkeypatch.setattr(settings, "BC_SESSION", None)
    assert credentials_configured("bugcrowd") is False
    monkeypatch.setattr(settings, "BC_SESSION", "cookie")
    assert credentials_configured("bugcrowd") is True

    monkeypatch.setattr(settings, "YWH_TOKEN", None)
    monkeypatch.setattr(settings, "INTI_TOKEN", None)
    assert credentials_configured("yeswehack") is False
    assert credentials_configured("intigriti") is False


def test_platform_interval_days_reads_the_setting(monkeypatch):
    monkeypatch.setattr(settings, "HACKERONE_SYNC_INTERVAL_DAYS", 2.5)
    assert platform_interval_days("hackerone") == 2.5


async def test_sync_platform_never_loads_an_adapter_without_credentials(monkeypatch):
    monkeypatch.setattr(settings, "H1_USERNAME", None)
    monkeypatch.setattr(settings, "H1_API_TOKEN", None)

    def _should_not_load_adapter():
        raise AssertionError("adapter loaded without credentials")

    monkeypatch.setattr("app.programs.sync.get_loader", _should_not_load_adapter)

    result = await sync_platform("hackerone")

    assert result.status == "skipped"
    assert result.programs == 0
    assert "credentials not configured" in (result.skipped_reason or "")
