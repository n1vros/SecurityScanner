"""Route-level tests for the web UI and daemon API, without a database."""

from datetime import datetime
from pathlib import Path

import httpx
import pytest
from fastapi import FastAPI

from app.web import api as api_module
from app.web import web as web_module

TEMPLATES_DIR = Path(__file__).resolve().parents[1] / "app" / "web" / "templates"


class FakeScalars:
    def all(self):
        return []


class FakeResult:
    def scalar(self):
        return 0

    def scalar_one_or_none(self):
        return None

    def scalars(self):
        return FakeScalars()

    def all(self):
        return []


class FakeSession:
    async def execute(self, *args, **kwargs):
        return FakeResult()


async def fake_db():
    yield FakeSession()


@pytest.fixture
async def web_client():
    app = FastAPI()
    app.include_router(web_module.router, prefix="/web")
    app.dependency_overrides[web_module.get_db] = fake_db
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        yield client


@pytest.mark.parametrize(
    "path",
    [
        "/web/",
        "/web/dashboard",
        "/web/findings",
        "/web/programs",
        "/web/subdomains",
    ],
)
async def test_pages_render_with_empty_database(web_client, path):
    response = await web_client.get(path)

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/html")
    assert "STOscanner" in response.text
    assert str(datetime.utcnow().year) in response.text


@pytest.mark.parametrize(
    "path",
    ["/web/program/1", "/web/subdomain/1", "/web/unknown"],
)
async def test_missing_pages_render_html_404(web_client, path):
    response = await web_client.get(path)

    assert response.status_code == 404
    assert "Page Not Found" in response.text


def test_api_routes_are_registered():
    paths = {route.path for route in api_module.app.routes}

    assert {
        "/api/latest-findings",
        "/api/daemon/status",
        "/api/daemon/start",
        "/api/daemon/stop",
        "/api/daemon/restart",
    } <= paths


def test_web_routes_are_registered():
    paths = {route.path for route in web_module.router.routes}

    assert {
        "/",
        "/dashboard",
        "/findings",
        "/programs",
        "/subdomains",
        "/program/{program_id}",
        "/subdomain/{subdomain_id}",
        "/{path:path}",
    } <= paths


async def test_latest_findings_returns_findings_list():
    payload = await api_module.get_latest_findings(
        db=FakeSession(), min_confidence=70, hours=24, limit=10
    )

    assert payload == {"findings": []}


async def test_daemon_status_payload_has_expected_keys(monkeypatch):
    class FakeManager:
        async def get_status(self):
            return {
                "running": False,
                "status": "stopped",
                "message": "Daemon is stopped",
                "pid": None,
                "started_at": None,
                "uptime_seconds": None,
                "log_file": "/tmp/stoscanner-daemon.log",
                "settings": {
                    "daemon_sleep_seconds": 60,
                    "active_discovery_enabled": False,
                    "daemon_max_iterations": None,
                },
            }

    monkeypatch.setattr(api_module, "daemon_manager", FakeManager())
    transport = httpx.ASGITransport(app=api_module.app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/api/daemon/status")

    assert response.status_code == 200
    payload = response.json()
    assert {
        "running",
        "status",
        "message",
        "pid",
        "started_at",
        "uptime_seconds",
        "log_file",
        "settings",
    } <= payload.keys()
    assert {
        "daemon_sleep_seconds",
        "active_discovery_enabled",
        "daemon_max_iterations",
    } <= payload["settings"].keys()


def test_dashboard_polls_a_registered_endpoint():
    dashboard = (TEMPLATES_DIR / "dashboard.html").read_text(encoding="utf-8")
    api_paths = {route.path for route in api_module.app.routes}

    assert "/api/latest-findings" in dashboard
    assert "/api/latest-findings" in api_paths
