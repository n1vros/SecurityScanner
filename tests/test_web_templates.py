"""Jinja template tests that do not need a database or a running web server."""

from pathlib import Path

import pytest
from jinja2 import Environment, FileSystemLoader, select_autoescape

TEMPLATES_DIR = Path(__file__).resolve().parents[1] / "app" / "web" / "templates"
STAMP = {"current_year": 2031, "current_time": "07:08:09"}


def _environment() -> Environment:
    return Environment(
        loader=FileSystemLoader(str(TEMPLATES_DIR)),
        autoescape=select_autoescape(["html", "xml"]),
    )


def test_all_templates_compile():
    env = _environment()

    names = env.list_templates()

    assert "base.html" in names
    assert "subdomain_detail.html" in names
    for name in names:
        env.get_template(name)


def test_base_renders_timestamp_context():
    html = _environment().get_template("base.html").render(**STAMP)

    assert "2031" in html
    assert "07:08:09" in html


def test_no_legacy_now_tag_remains():
    for path in TEMPLATES_DIR.glob("*.html"):
        text = path.read_text(encoding="utf-8")
        assert "{% now" not in text, f"{path.name} still uses a Jinja now tag"


PAGE_CONTEXTS = {
    "dashboard.html": {
        "program_count": 0,
        "scope_count": 0,
        "subdomain_count": 0,
        "high_confidence_count": 0,
        "recent_findings": 0,
        "latest_scan": None,
        "latest_findings": [],
        "programs_needing_scan": [],
    },
    "findings.html": {
        "findings": [],
        "total_count": 0,
        "page": 1,
        "per_page": 50,
        "total_pages": 1,
        "min_confidence": 70,
        "hours": 24,
    },
    "programs.html": {
        "programs": [],
        "total_count": 0,
        "page": 1,
        "per_page": 20,
        "total_pages": 1,
    },
    "program_detail.html": {
        "program": {
            "id": 1,
            "name": "Example Program",
            "platform": "manual",
            "url": None,
            "created_at": None,
            "updated_at": None,
            "last_scan_at": None,
            "is_active": True,
        },
        "scopes": [],
        "subdomain_counts": {},
        "total_subdomains": 0,
        "recent_findings": [],
    },
    "subdomains.html": {
        "subdomains": [],
        "total_count": 0,
        "page": 1,
        "per_page": 50,
        "total_pages": 1,
        "state": None,
        "min_confidence": None,
        "max_confidence": None,
        "scope_id": None,
        "program_id": None,
        "order_by": "confidence",
        "states": ["discovered", "alive", "dead", "dangling", "claimed"],
        "programs": [],
        "scopes": [],
    },
    "subdomain_detail.html": {
        "subdomain": {
            "id": 1,
            "scope_id": 1,
            "scope_domain": "example.com",
            "program_name": "Example Program",
            "name": "www.example.com",
            "state": "dangling",
            "confidence": 90,
            "discovered_at": None,
            "last_scanned_at": None,
            "last_state_change_at": None,
            "cname_target": "example.s3.amazonaws.com",
            "dns_resolver": None,
            "dns_resolved_at": None,
            "http_status": None,
            "http_title": None,
            "http_body_hash": None,
            "http_content_length": None,
            "http_probed_at": None,
            "takeover_provider": "aws_s3",
            "takeover_evidence": None,
        },
    },
    "404.html": {"message": "Page not found"},
}


@pytest.mark.parametrize("template_name", sorted(PAGE_CONTEXTS))
def test_page_renders_with_minimal_context(template_name: str):
    html = _environment().get_template(template_name).render(
        **STAMP, **PAGE_CONTEXTS[template_name]
    )

    assert "STOscanner" in html
    assert "2031" in html
