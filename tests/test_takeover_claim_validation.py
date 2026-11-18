"""Claim-validation parser and retry loop (no network)."""

import pytest

from app.takeover.subdomain_hunter.claim_validator import ClaimValidator

MARKER = "STO by Rizin"


def make_fetch(responses, calls):
    """Build a fetch callable from a {url_scheme: response_or_exception} map."""

    async def fetch(url: str):
        calls.append(url)
        scheme = url.split("://", 1)[0]
        response = responses.get(scheme, (404, "not found", url))
        if isinstance(response, Exception):
            raise response
        status, body = response[0], response[1]
        return status, body, url

    return fetch


@pytest.mark.asyncio
async def test_marker_present_verifies_on_first_https_fetch():
    calls = []
    validator = ClaimValidator(
        marker=MARKER,
        attempts=3,
        delay=0,
        fetch=make_fetch({"https": (200, f"<html><!-- {MARKER} --></html>")}, calls),
    )

    outcome = await validator.validate("app.example.com")

    assert outcome.verified is True
    assert outcome.attempts == 1
    assert outcome.status_code == 200
    assert outcome.marker == MARKER
    assert calls == ["https://app.example.com"]


@pytest.mark.asyncio
async def test_marker_absent_is_unverified_after_all_attempts():
    calls = []
    validator = ClaimValidator(
        marker=MARKER,
        attempts=3,
        delay=0,
        fetch=make_fetch({"https": (200, "live service page")}, calls),
    )

    outcome = await validator.validate("app.example.com")

    assert outcome.verified is False
    assert outcome.attempts == 3
    # HTTPS then HTTP for each attempt.
    assert len(calls) == 6
    assert calls[0] == "https://app.example.com"
    assert calls[1] == "http://app.example.com"
    assert "marker not present" in outcome.error


@pytest.mark.asyncio
async def test_https_failure_falls_back_to_http_marker():
    calls = []
    validator = ClaimValidator(
        marker=MARKER,
        attempts=1,
        delay=0,
        fetch=make_fetch(
            {
                "https": ConnectionError("tls not ready"),
                "http": (200, f"<body>{MARKER}</body>"),
            },
            calls,
        ),
    )

    outcome = await validator.validate("app.example.com")

    assert outcome.verified is True
    assert outcome.url == "http://app.example.com"
    assert outcome.attempts == 1


@pytest.mark.asyncio
async def test_retry_after_transient_exception():
    calls = []
    failures = 2  # both schemes of the first attempt fail

    async def fetch(url: str):
        nonlocal failures
        calls.append(url)
        if failures:
            failures -= 1
            raise TimeoutError("slow")
        return 200, MARKER, url

    validator = ClaimValidator(marker=MARKER, attempts=2, delay=0, fetch=fetch)

    outcome = await validator.validate("app.example.com")

    assert outcome.verified is True
    assert outcome.attempts == 2


@pytest.mark.asyncio
async def test_provider_specific_success_predicate_can_verify():
    async def fetch(url: str):
        return 204, "", url

    validator = ClaimValidator(
        marker=MARKER,
        attempts=1,
        delay=0,
        fetch=fetch,
        success_predicate=lambda status, body: status == 204,
    )

    outcome = await validator.validate("app.example.com")

    assert outcome.verified is True


@pytest.mark.asyncio
async def test_empty_marker_refuses_to_validate():
    calls = []
    validator = ClaimValidator(
        marker="",
        attempts=1,
        delay=0,
        fetch=make_fetch({"https": (200, MARKER)}, calls),
    )

    outcome = await validator.validate("app.example.com")

    assert outcome.verified is False
    assert "TAKEOVER_CLAIM_MARKER is empty" in outcome.error
    assert calls == []


@pytest.mark.asyncio
async def test_empty_hostname_is_rejected():
    outcome = await ClaimValidator(marker=MARKER, attempts=1, delay=0).validate(" ")

    assert outcome.verified is False
    assert outcome.error == "empty hostname"


@pytest.mark.asyncio
async def test_body_snippet_is_bounded():
    async def fetch(url: str):
        return 200, MARKER + ("x" * 1000), url

    outcome = await ClaimValidator(
        marker=MARKER, attempts=1, delay=0, fetch=fetch
    ).validate("app.example.com")

    assert outcome.verified is True
    assert outcome.body_snippet is not None
    assert len(outcome.body_snippet) == 200
