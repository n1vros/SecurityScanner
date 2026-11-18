"""TakeoverEvaluator decision-tree regressions (no network)."""

import re
from types import SimpleNamespace

import pytest

from app.db.db_models import SubdomainState
from app.probing.confidence import ConfidenceScorer
from app.takeover.subdomain_hunter.evaluator import TakeoverEvaluator
from app.takeover.subdomain_hunter.takeover_loader import SignatureData


class FakeSession:
    def __init__(self):
        self.added = []

    def add(self, obj):
        self.added.append(obj)


class RecordingProvidersEvaluator:
    def __init__(self):
        self.calls = []

    async def verify(self, session, subdomain, provider, cname, overall, dns_data, http_data):
        self.calls.append(
            {
                "provider": provider,
                "cname": cname,
                "overall": overall,
            }
        )
        return overall, None, {}, {}, None


def make_subdomain(name="app.example.com", state=SubdomainState.DISCOVERED, confidence=0):
    return SimpleNamespace(
        id=1,
        name=name,
        state=state,
        confidence=confidence,
        takeover_provider=None,
        takeover_evidence=None,
        takeover_last_status=None,
        takeover_retry_at=None,
        last_state_change_at=None,
        scope_id=1,
        scope=SimpleNamespace(domain="example.com"),
    )


def make_evaluator():
    evaluator = TakeoverEvaluator()
    recorder = RecordingProvidersEvaluator()
    evaluator._providers_evaluator = recorder
    return evaluator, recorder


@pytest.mark.asyncio
async def test_nxdomain_claimable_cname_reaches_provider_verification():
    evaluator, recorder = make_evaluator()
    session = FakeSession()
    subdomain = make_subdomain()

    outcome = await evaluator.evaluate(
        session,
        subdomain,
        dns_data={"cname": "app.herokuapp.com", "nxdomain": True, "ips": []},
        http_data=None,
    )

    assert outcome["provider"] == "heroku"
    assert outcome["confidence"] >= 60
    assert recorder.calls == [
        {"provider": "heroku", "cname": "app.herokuapp.com", "overall": 65}
    ]
    assert subdomain.state == SubdomainState.DANGLING


@pytest.mark.asyncio
async def test_nxdomain_non_claimable_cname_is_suppressed(monkeypatch):
    fake = SignatureData(
        cname_patterns={"cloudfront": [(re.compile(r"\.cloudfront\.net$"), 35)]},
        claimable={"cloudfront": False},
        nxdomain_required={},
    )
    monkeypatch.setattr(ConfidenceScorer, "_sig", staticmethod(lambda: fake))

    evaluator, recorder = make_evaluator()
    session = FakeSession()
    subdomain = make_subdomain()

    outcome = await evaluator.evaluate(
        session,
        subdomain,
        dns_data={"cname": "d111.cloudfront.net", "nxdomain": True, "ips": []},
        http_data=None,
    )

    assert outcome["confidence"] == 0
    assert outcome["provider"] is None
    assert recorder.calls and recorder.calls[0]["provider"] is None
    assert subdomain.state == SubdomainState.ALIVE


@pytest.mark.asyncio
async def test_http_fingerprint_for_a_different_provider_gates_the_finding():
    # google_app_engine has no HTTP fingerprints of its own, so the old gate
    # never fired and a Vercel page scored 72 for an App Engine CNAME.
    evaluator, recorder = make_evaluator()
    session = FakeSession()
    subdomain = make_subdomain()

    outcome = await evaluator.evaluate(
        session,
        subdomain,
        dns_data={"cname": "app.appspot.com", "nxdomain": False, "ips": ["1.2.3.4"]},
        http_data={
            "status_code": 404,
            "body": "The deployment could not be found",
            "headers": {},
            "url": "https://app.appspot.com",
        },
    )

    assert outcome["confidence"] == 0
    assert outcome["provider"] is None
    assert recorder.calls[0]["provider"] is None
    assert subdomain.state == SubdomainState.ALIVE


@pytest.mark.asyncio
async def test_nxdomain_with_a_different_provider_fingerprint_is_suppressed():
    evaluator, recorder = make_evaluator()
    session = FakeSession()
    subdomain = make_subdomain()

    outcome = await evaluator.evaluate(
        session,
        subdomain,
        dns_data={"cname": "app.github.io", "nxdomain": True, "ips": []},
        http_data={"status_code": 404, "body": "No such app", "headers": {}},
    )

    assert outcome["confidence"] == 0
    assert outcome["provider"] is None
    assert recorder.calls[0]["provider"] is None
    assert subdomain.state == SubdomainState.ALIVE


@pytest.mark.asyncio
async def test_matching_http_fingerprint_keeps_the_provider():
    evaluator, recorder = make_evaluator()
    session = FakeSession()
    subdomain = make_subdomain()

    outcome = await evaluator.evaluate(
        session,
        subdomain,
        dns_data={"cname": "app.herokuapp.com", "nxdomain": False, "ips": []},
        http_data={"status_code": 404, "body": "No such app", "headers": {}},
    )

    assert outcome["provider"] == "heroku"
    assert outcome["confidence"] == 70
    assert recorder.calls[0]["provider"] == "heroku"


@pytest.mark.asyncio
async def test_http_timeout_does_not_suppress_a_cname_match():
    evaluator, recorder = make_evaluator()
    session = FakeSession()
    subdomain = make_subdomain()

    outcome = await evaluator.evaluate(
        session,
        subdomain,
        dns_data={"cname": "app.herokuapp.com", "nxdomain": False, "ips": []},
        http_data={"status_code": None, "body": None, "headers": {}},
    )

    assert outcome["provider"] == "heroku"
    assert outcome["confidence"] == 40
    assert subdomain.state == SubdomainState.POTENTIAL
    assert recorder.calls[0]["provider"] == "heroku"


@pytest.mark.asyncio
async def test_alive_claimable_cname_is_potential_capped_at_59_and_not_attempted():
    evaluator, recorder = make_evaluator()
    session = FakeSession()
    subdomain = make_subdomain()

    outcome = await evaluator.evaluate(
        session,
        subdomain,
        dns_data={"cname": "app.herokuapp.com", "nxdomain": False, "ips": ["1.2.3.4"]},
        http_data={"status_code": 200, "body": "hello", "headers": {}},
    )

    assert outcome["is_potential"] is True
    assert outcome["confidence"] == 59
    assert subdomain.state == SubdomainState.POTENTIAL
    assert subdomain.confidence == 59
    assert recorder.calls == []


@pytest.mark.asyncio
async def test_potential_long_survives_a_recheck_that_scores_59():
    evaluator, _ = make_evaluator()
    session = FakeSession()
    subdomain = make_subdomain(state=SubdomainState.POTENTIAL_LONG, confidence=30)

    await evaluator.evaluate(
        session,
        subdomain,
        dns_data={"cname": "app.herokuapp.com", "nxdomain": False, "ips": ["1.2.3.4"]},
        http_data={"status_code": 200, "body": "hello", "headers": {}},
    )

    assert subdomain.state == SubdomainState.POTENTIAL_LONG
    assert subdomain.confidence == 59


@pytest.mark.asyncio
async def test_probe_empty_preserves_potential_long_confidence():
    evaluator, recorder = make_evaluator()
    session = FakeSession()
    subdomain = make_subdomain(state=SubdomainState.POTENTIAL_LONG, confidence=30)

    outcome = await evaluator.evaluate(
        session,
        subdomain,
        dns_data={"cname": None, "nxdomain": False, "ips": []},
        http_data=None,
    )

    assert outcome["skipped"] == "probe_empty"
    assert outcome["confidence"] == 30
    assert subdomain.state == SubdomainState.POTENTIAL_LONG
    assert recorder.calls == []


@pytest.mark.asyncio
async def test_claimed_is_terminal_and_not_re_evaluated():
    evaluator, recorder = make_evaluator()
    session = FakeSession()
    subdomain = make_subdomain(state=SubdomainState.CLAIMED, confidence=90)

    outcome = await evaluator.evaluate(
        session,
        subdomain,
        dns_data={"cname": "app.herokuapp.com", "nxdomain": True, "ips": []},
        http_data=None,
    )

    assert outcome["skipped"] == "claimed_terminal"
    assert outcome["confidence"] == 90
    assert subdomain.state == SubdomainState.CLAIMED
    assert recorder.calls == []
