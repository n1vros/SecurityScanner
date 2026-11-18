"""ProvidersEvaluator outcome handling, guards and claim validation (no network)."""

from datetime import datetime, timedelta
from types import SimpleNamespace

import pytest

from app.core.config import settings
from app.db.db_models import StateTransition, SubdomainState
from app.takeover.subdomain_hunter import providers_evaluator
from app.takeover.subdomain_hunter.claim_validator import ClaimValidationResult
from app.takeover.subdomain_hunter.providers.aws_s3 import (
    AWSS3TakeoverChecker,
    extract_bucket_and_region,
)
from app.takeover.subdomain_hunter.providers.azure import (
    AzureTakeoverChecker,
    extract_resource_name,
)
from app.takeover.subdomain_hunter.providers.base import TakeoverResult, TakeoverStatus
from app.takeover.subdomain_hunter.providers.heroku import HerokuTakeoverChecker
from app.takeover.subdomain_hunter.providers.netlify import NetlifyTakeoverChecker
from app.takeover.subdomain_hunter.providers.vercel import (
    VercelVerifyResult,
    VercelVerifyStatus,
)
from app.takeover.subdomain_hunter.providers_evaluator import ProvidersEvaluator
from app.takeover.subdomain_hunter.takeover_loader import SignatureLoader


@pytest.fixture(autouse=True)
def _fast_provider_bucket(monkeypatch):
    monkeypatch.setattr(providers_evaluator, "_provider_bucket", None)
    monkeypatch.setattr(settings, "TAKEOVER_CHECK_RATE_LIMIT", 1000.0)


class FakeSession:
    def __init__(self):
        self.added = []

    def add(self, obj):
        self.added.append(obj)

    async def refresh(self, obj, attribute_names=None):
        return None


class FakeChecker:
    def __init__(self, result=None, error=None):
        self.result = result
        self.error = error
        self.calls = []

    async def attempt(self, name, cname):
        self.calls.append((name, cname))
        if self.error:
            raise self.error
        return self.result

    async def verify(self, name):
        self.calls.append((name, None))
        if self.error:
            raise self.error
        return self.result


class FakeValidator:
    def __init__(self, result):
        self.result = result
        self.calls = []

    async def validate(self, hostname):
        self.calls.append(hostname)
        return self.result


def verified_result() -> ClaimValidationResult:
    return ClaimValidationResult(True, attempts=1, url="https://app.example.com", status_code=200)


def failed_validation() -> ClaimValidationResult:
    return ClaimValidationResult(False, attempts=3, error="claim marker not present")


def make_subdomain(
    name="app.example.com",
    state=SubdomainState.DANGLING,
    confidence=70,
    provider="heroku",
    scope_domain="example.com",
    retry_at=None,
    last_status=None,
    last_scanned_at=None,
):
    return SimpleNamespace(
        id=1,
        name=name,
        state=state,
        confidence=confidence,
        takeover_provider=provider,
        takeover_evidence=None,
        takeover_last_status=last_status,
        takeover_retry_at=retry_at,
        last_state_change_at=None,
        last_scanned_at=last_scanned_at,
        scope_id=1,
        scope=SimpleNamespace(domain=scope_domain),
    )


def make_evaluator(validator_result=None):
    validator = FakeValidator(validator_result or failed_validation())
    return ProvidersEvaluator(validator=validator), validator


def transitions(session):
    return [obj for obj in session.added if isinstance(obj, StateTransition)]


def assert_retry_in(retry_at, *, hours=None, days=None):
    assert retry_at is not None
    expected = timedelta(hours=hours) if hours is not None else timedelta(days=days)
    now = datetime.utcnow()
    assert now + expected - timedelta(minutes=2) <= retry_at <= now + expected + timedelta(minutes=2)


@pytest.mark.asyncio
async def test_validated_success_becomes_terminal_claimed():
    evaluator, validator = make_evaluator(verified_result())
    checker = FakeChecker(
        TakeoverResult(
            status=TakeoverStatus.SUCCESS,
            provider="heroku",
            subdomain="app.example.com",
            confidence_delta=10,
            evidence={"app_created": True},
            claim_url="https://app.example.com",
        )
    )
    evaluator._heroku = checker
    session = FakeSession()
    subdomain = make_subdomain()

    overall, filtered, _, extras, result = await evaluator.verify(
        session, subdomain, "heroku", "app.herokuapp.com", 70, {}, None
    )

    assert overall >= 90
    assert filtered == "heroku_claim_validated"
    assert result.status == TakeoverStatus.SUCCESS
    assert result.claim_validated is True
    assert extras["takeover_status"] == "success"
    assert validator.calls == ["app.example.com"]
    assert subdomain.state == SubdomainState.CLAIMED
    assert subdomain.confidence == 90
    assert subdomain.takeover_last_status == "claimed"
    assert subdomain.takeover_retry_at is None
    assert [t.to_state for t in transitions(session)][-1] == SubdomainState.CLAIMED
    import json

    evidence = json.loads(subdomain.takeover_evidence)
    assert evidence["takeover"]["status"] == "success"
    assert evidence["takeover"]["evidence"]["claim_validation"]["verified"] is True


@pytest.mark.asyncio
async def test_reported_success_without_marker_is_downgraded_and_retried():
    evaluator, validator = make_evaluator(failed_validation())
    evaluator._heroku = FakeChecker(
        TakeoverResult(
            status=TakeoverStatus.SUCCESS,
            provider="heroku",
            subdomain="app.example.com",
            confidence_delta=10,
            claim_url="https://app.example.com",
        )
    )
    session = FakeSession()
    subdomain = make_subdomain()

    overall, filtered, _, extras, result = await evaluator.verify(
        session, subdomain, "heroku", "app.herokuapp.com", 70, {}, None
    )

    assert filtered is None
    assert result.status == TakeoverStatus.FAIL
    assert result.claim_validated is False
    assert "claim validation failed" in result.error
    assert extras["takeover_status"] == "fail"
    assert validator.calls == ["app.example.com"]
    assert subdomain.state == SubdomainState.DANGLING
    assert subdomain.takeover_last_status == "validation_failed"
    assert_retry_in(subdomain.takeover_retry_at, hours=settings.TAKEOVER_RETRY_HOURS)


@pytest.mark.asyncio
async def test_not_vuln_returns_zero_and_never_retries():
    evaluator, _ = make_evaluator()
    evaluator._heroku = FakeChecker(
        TakeoverResult(
            status=TakeoverStatus.NOT_VULN,
            provider="heroku",
            subdomain="app.example.com",
            confidence_delta=-30,
            error="App name exists in another Heroku account",
        )
    )
    session = FakeSession()
    subdomain = make_subdomain()

    overall, filtered, _, extras, result = await evaluator.verify(
        session, subdomain, "heroku", "app.herokuapp.com", 70, {}, None
    )

    assert overall == 0
    assert filtered == "heroku_app_taken"
    assert result.status == TakeoverStatus.NOT_VULN
    assert extras["takeover_status"] == "not_vuln"
    assert subdomain.state == SubdomainState.ALIVE
    assert subdomain.confidence == 0
    assert subdomain.takeover_last_status == "not_vuln"
    assert subdomain.takeover_retry_at is None


@pytest.mark.asyncio
async def test_needs_txt_stays_potential_long_and_retries_in_days():
    evaluator, _ = make_evaluator()
    evaluator._heroku = FakeChecker(
        TakeoverResult(
            status=TakeoverStatus.NEEDS_TXT,
            provider="heroku",
            subdomain="app.example.com",
            evidence={"reason": "heroku_name_reserved"},
        )
    )
    session = FakeSession()
    subdomain = make_subdomain()

    overall, filtered, _, _, result = await evaluator.verify(
        session, subdomain, "heroku", "app.herokuapp.com", 70, {}, None
    )

    assert overall == 30
    assert filtered == "heroku_name_reserved"
    assert result.status == TakeoverStatus.NEEDS_TXT
    assert subdomain.state == SubdomainState.POTENTIAL_LONG
    assert subdomain.confidence == 30
    assert subdomain.takeover_last_status == "needs_txt"
    assert_retry_in(subdomain.takeover_retry_at, days=settings.TAKEOVER_RETRY_DAYS)


@pytest.mark.asyncio
async def test_netlify_domain_claimed_elsewhere_preserves_potential_long():
    evaluator, _ = make_evaluator()
    evaluator._netlify = FakeChecker(
        TakeoverResult(
            status=TakeoverStatus.FAIL,
            provider="netlify",
            subdomain="app.example.com",
            evidence={"domain_claimed_elsewhere": True},
        )
    )
    session = FakeSession()
    subdomain = make_subdomain(provider="netlify")

    overall, filtered, _, _, result = await evaluator.verify(
        session, subdomain, "netlify", "app.netlify.app", 70, {}, None
    )

    assert overall == 30
    assert filtered == "netlify_domain_claimed_elsewhere"
    assert subdomain.state == SubdomainState.POTENTIAL_LONG
    assert subdomain.confidence == 30
    assert subdomain.takeover_last_status == "manual"
    assert_retry_in(subdomain.takeover_retry_at, days=settings.TAKEOVER_RETRY_DAYS)


@pytest.mark.asyncio
async def test_not_vuln_clears_a_stale_potential_long_state():
    evaluator, _ = make_evaluator()
    evaluator._heroku = FakeChecker(
        TakeoverResult(
            status=TakeoverStatus.NOT_VULN,
            provider="heroku",
            subdomain="app.example.com",
            error="App name exists in another Heroku account",
        )
    )
    session = FakeSession()
    subdomain = make_subdomain(state=SubdomainState.POTENTIAL_LONG, confidence=30)

    overall, filtered, _, _, result = await evaluator.verify(
        session, subdomain, "heroku", "app.herokuapp.com", 70, {}, None
    )

    assert overall == 0
    assert filtered == "heroku_app_taken"
    assert result.status == TakeoverStatus.NOT_VULN
    assert subdomain.state == SubdomainState.ALIVE
    assert subdomain.takeover_last_status == "not_vuln"
    assert subdomain.takeover_retry_at is None


@pytest.mark.asyncio
async def test_unavailable_retries_in_hours_and_is_not_terminal():
    evaluator, _ = make_evaluator()
    evaluator._heroku = FakeChecker(
        TakeoverResult(
            status=TakeoverStatus.UNAVAILABLE,
            provider="heroku",
            subdomain="app.example.com",
            error="HEROKU_API_KEY not configured",
        )
    )
    session = FakeSession()
    subdomain = make_subdomain()

    overall, _, _, _, result = await evaluator.verify(
        session, subdomain, "heroku", "app.herokuapp.com", 70, {}, None
    )

    assert overall == 70
    assert result.status == TakeoverStatus.UNAVAILABLE
    assert subdomain.state == SubdomainState.DANGLING
    assert subdomain.takeover_last_status == "unavailable"
    assert_retry_in(subdomain.takeover_retry_at, hours=settings.TAKEOVER_RETRY_HOURS)


@pytest.mark.asyncio
async def test_not_impl_manual_provider_retries_in_days_without_network():
    evaluator, _ = make_evaluator()
    session = FakeSession()
    subdomain = make_subdomain(provider="fastly")

    overall, _, _, _, result = await evaluator.verify(
        session, subdomain, "fastly", "app.fastly.net", 65, {}, None
    )

    assert overall <= 72
    assert result.status == TakeoverStatus.NOT_IMPL
    assert subdomain.takeover_last_status == "manual"
    assert_retry_in(subdomain.takeover_retry_at, days=settings.TAKEOVER_RETRY_DAYS)


@pytest.mark.asyncio
async def test_auto_takeover_switch_prevents_attempts(monkeypatch):
    monkeypatch.setattr(settings, "TAKEOVER_AUTO_ENABLED", False)
    evaluator, _ = make_evaluator()
    checker = FakeChecker(
        TakeoverResult(status=TakeoverStatus.SUCCESS, provider="heroku", subdomain="app.example.com")
    )
    evaluator._heroku = checker
    session = FakeSession()
    subdomain = make_subdomain()

    overall, _, _, _, result = await evaluator.verify(
        session, subdomain, "heroku", "app.herokuapp.com", 70, {}, None
    )

    assert checker.calls == []
    assert result.status == TakeoverStatus.UNAVAILABLE
    assert overall <= 72
    assert subdomain.takeover_last_status == "unavailable"
    assert_retry_in(subdomain.takeover_retry_at, hours=settings.TAKEOVER_RETRY_HOURS)


@pytest.mark.asyncio
async def test_future_retry_timestamp_defers_the_attempt():
    evaluator, _ = make_evaluator()
    checker = FakeChecker(
        TakeoverResult(status=TakeoverStatus.SUCCESS, provider="heroku", subdomain="app.example.com")
    )
    evaluator._heroku = checker
    session = FakeSession()
    subdomain = make_subdomain(retry_at=datetime.utcnow() + timedelta(hours=1), last_status="failed")

    _, filtered, _, _, result = await evaluator.verify(
        session, subdomain, "heroku", "app.herokuapp.com", 70, {}, None
    )

    assert filtered == "heroku_retry_scheduled"
    assert result is None
    assert checker.calls == []


@pytest.mark.asyncio
async def test_failed_attempt_defers_a_second_concurrent_cycle():
    evaluator, validator = make_evaluator(verified_result())
    checker = FakeChecker(
        TakeoverResult(
            status=TakeoverStatus.FAIL,
            provider="heroku",
            subdomain="app.example.com",
            error="API quota exceeded",
        )
    )
    evaluator._heroku = checker
    session = FakeSession()
    subdomain = make_subdomain()

    await evaluator.verify(
        session, subdomain, "heroku", "app.herokuapp.com", 70, {}, None
    )
    assert subdomain.takeover_last_status == "failed"
    assert subdomain.takeover_retry_at is not None

    # A second cycle before retry_at is due must not touch the provider again.
    _, filtered, _, _, second_result = await evaluator.verify(
        session, subdomain, "heroku", "app.herokuapp.com", 70, {}, None
    )

    assert filtered == "heroku_retry_scheduled"
    assert second_result is None
    assert len(checker.calls) == 1
    assert validator.calls == []


@pytest.mark.asyncio
async def test_aws_apigateway_manual_finding_stays_potential_long():
    evaluator, _ = make_evaluator()
    evaluator._aws_apigateway = FakeChecker(
        TakeoverResult(
            status=TakeoverStatus.NOT_IMPL,
            provider="aws_apigateway",
            subdomain="app.example.com",
            evidence={"reason": "execute_api_account_bound"},
        )
    )
    session = FakeSession()
    subdomain = make_subdomain(provider="aws_apigateway", confidence=95)

    overall, filtered, _, _, result = await evaluator.verify(
        session, subdomain, "aws_apigateway", "abc.execute-api.us-east-1.amazonaws.com",
        95, {}, None,
    )

    assert overall <= 72
    assert filtered == "aws_apigateway_manual"
    assert result.status == TakeoverStatus.NOT_IMPL
    assert subdomain.state == SubdomainState.POTENTIAL_LONG
    assert subdomain.confidence <= 72
    assert_retry_in(subdomain.takeover_retry_at, days=settings.TAKEOVER_RETRY_DAYS)


@pytest.mark.asyncio
async def test_claimed_subdomain_is_never_attempted_again():
    evaluator, _ = make_evaluator()
    checker = FakeChecker(
        TakeoverResult(status=TakeoverStatus.SUCCESS, provider="heroku", subdomain="app.example.com")
    )
    evaluator._heroku = checker
    session = FakeSession()
    subdomain = make_subdomain(state=SubdomainState.CLAIMED, confidence=90)

    _, filtered, _, _, result = await evaluator.verify(
        session, subdomain, "heroku", "app.herokuapp.com", 90, {}, None
    )

    assert filtered == "heroku_already_claimed"
    assert result is None
    assert checker.calls == []


@pytest.mark.asyncio
async def test_scope_root_is_never_auto_claimed():
    evaluator, _ = make_evaluator()
    checker = FakeChecker(
        TakeoverResult(status=TakeoverStatus.SUCCESS, provider="heroku", subdomain="example.com")
    )
    evaluator._heroku = checker
    session = FakeSession()
    subdomain = make_subdomain(name="example.com", provider="heroku")

    overall, filtered, _, _, result = await evaluator.verify(
        session, subdomain, "heroku", "app.herokuapp.com", 70, {}, None
    )

    assert overall == 70  # heuristic finding is preserved/alerts, just not claimed
    assert filtered is None
    assert result is None
    assert checker.calls == []


@pytest.mark.asyncio
async def test_apex_is_never_auto_claimed_even_outside_the_scope_root():
    evaluator, _ = make_evaluator()
    checker = FakeChecker(
        TakeoverResult(status=TakeoverStatus.SUCCESS, provider="heroku", subdomain="example.com")
    )
    evaluator._heroku = checker
    session = FakeSession()
    subdomain = make_subdomain(name="example.com", provider="heroku", scope_domain="api.example.com")

    _, _, _, _, result = await evaluator.verify(
        session, subdomain, "heroku", "app.herokuapp.com", 70, {}, None
    )

    assert result is None
    assert checker.calls == []


@pytest.mark.asyncio
async def test_attempts_are_gated_at_the_dangling_threshold():
    evaluator, _ = make_evaluator()
    checker = FakeChecker(
        TakeoverResult(status=TakeoverStatus.SUCCESS, provider="heroku", subdomain="app.example.com")
    )
    evaluator._heroku = checker
    session = FakeSession()
    subdomain = make_subdomain(state=SubdomainState.POTENTIAL, confidence=40)

    overall, _, _, _, result = await evaluator.verify(
        session, subdomain, "heroku", "app.herokuapp.com", 40, {}, None
    )

    assert overall == 40
    assert result is None
    assert checker.calls == []


@pytest.mark.asyncio
async def test_non_claimable_provider_is_suppressed(monkeypatch):
    monkeypatch.setitem(SignatureLoader.instance().claimable, "heroku", False)
    evaluator, _ = make_evaluator()
    checker = FakeChecker(
        TakeoverResult(status=TakeoverStatus.SUCCESS, provider="heroku", subdomain="app.example.com")
    )
    evaluator._heroku = checker
    session = FakeSession()
    subdomain = make_subdomain()

    overall, filtered, _, _, result = await evaluator.verify(
        session, subdomain, "heroku", "app.herokuapp.com", 70, {}, None
    )

    assert overall == 0
    assert filtered == "heroku_not_claimable"
    assert result is None
    assert subdomain.state == SubdomainState.ALIVE
    assert checker.calls == []


@pytest.mark.asyncio
async def test_provider_exception_is_contained_and_scheduled_for_retry():
    evaluator, _ = make_evaluator()
    evaluator._heroku = FakeChecker(error=RuntimeError("boom"))
    session = FakeSession()
    subdomain = make_subdomain()

    overall, _, _, extras, result = await evaluator.verify(
        session, subdomain, "heroku", "app.herokuapp.com", 70, {}, None
    )

    assert overall == 70
    assert result.status == TakeoverStatus.FAIL
    assert "boom" in result.error
    assert extras["takeover_status"] == "fail"
    assert subdomain.takeover_last_status == "failed"
    assert_retry_in(subdomain.takeover_retry_at, hours=settings.TAKEOVER_RETRY_HOURS)


@pytest.mark.asyncio
async def test_provider_verify_cooldown_skips_the_checker():
    evaluator, _ = make_evaluator()
    checker = FakeChecker(
        TakeoverResult(status=TakeoverStatus.NOT_VULN, provider="heroku", subdomain="app.example.com")
    )
    evaluator._heroku = checker
    session = FakeSession()
    subdomain = make_subdomain(last_scanned_at=datetime.utcnow())

    _, filtered, _, _, result = await evaluator.verify(
        session, subdomain, "heroku", "app.herokuapp.com", 70, {}, None
    )

    assert filtered == "heroku_verify_cooldown"
    assert result is None
    assert checker.calls == []


@pytest.mark.asyncio
async def test_scan_cooldown_does_not_block_a_new_dangling_promotion():
    evaluator, _ = make_evaluator()
    checker = FakeChecker(
        TakeoverResult(
            status=TakeoverStatus.UNAVAILABLE,
            provider="heroku",
            subdomain="app.example.com",
            error="HEROKU_API_KEY not configured",
        )
    )
    evaluator._heroku = checker
    session = FakeSession()
    subdomain = make_subdomain(
        state=SubdomainState.POTENTIAL,
        confidence=59,
        last_scanned_at=datetime.utcnow(),
    )

    await evaluator.verify(
        session, subdomain, "heroku", "app.herokuapp.com", 70, {}, None
    )

    assert len(checker.calls) == 1


@pytest.mark.asyncio
async def test_due_retry_is_not_blocked_by_the_scan_cooldown():
    evaluator, validator = make_evaluator(verified_result())
    checker = FakeChecker(
        TakeoverResult(
            status=TakeoverStatus.FAIL,
            provider="heroku",
            subdomain="app.example.com",
            error="temporary API error",
        )
    )
    evaluator._heroku = checker
    session = FakeSession()
    # The probe just stamped last_scanned_at, and retry_at has now elapsed.
    subdomain = make_subdomain(
        retry_at=datetime.utcnow() - timedelta(seconds=1),
        last_status="failed",
        last_scanned_at=datetime.utcnow(),
    )

    _, filtered, _, _, _ = await evaluator.verify(
        session, subdomain, "heroku", "app.herokuapp.com", 70, {}, None
    )

    assert filtered is None
    assert len(checker.calls) == 1


@pytest.mark.asyncio
async def test_vercel_verified_result_is_mapped_to_success_and_claimed():
    evaluator, validator = make_evaluator(verified_result())
    vercel_result = VercelVerifyResult(
        status=VercelVerifyStatus.VERIFIED,
        subdomain="app.example.com",
        confidence_delta=10,
        evidence={"http_status": 200, "claim_url": "https://app.example.com"},
    )
    evaluator._vercel = FakeChecker(vercel_result)
    session = FakeSession()
    subdomain = make_subdomain(provider="vercel")

    overall, filtered, _, extras, result = await evaluator.verify(
        session, subdomain, "vercel", "app.vercel.app", 70, {}, None
    )

    assert isinstance(result, TakeoverResult)
    assert result.status == TakeoverStatus.SUCCESS
    assert result.claim_url == "https://app.example.com"
    assert extras["takeover_status"] == "success"
    assert filtered == "vercel_claim_validated"
    assert subdomain.state == SubdomainState.CLAIMED
    assert subdomain.takeover_last_status == "claimed"


# ── Provider-level regressions ────────────────────────────────────────────────


def test_s3_extracts_bucket_and_region_variants():
    assert extract_bucket_and_region("my-bucket.s3.amazonaws.com") == ("my-bucket", "us-east-1")
    assert extract_bucket_and_region("my-bucket.s3-website-eu-west-1.amazonaws.com") == (
        "my-bucket",
        "eu-west-1",
    )
    assert extract_bucket_and_region("my-bucket.s3.eu-central-1.amazonaws.com") == (
        "my-bucket",
        "eu-central-1",
    )
    assert extract_bucket_and_region("not-an-s3-host.example.com") == (None, "us-east-1")


@pytest.mark.asyncio
async def test_s3_never_falls_back_to_the_subdomain_as_bucket_name():
    checker = AWSS3TakeoverChecker()
    checker._ready = False

    result = await checker.attempt("app.example.com", "app.example.com")

    assert result.status == TakeoverStatus.UNAVAILABLE
    assert "Cannot extract bucket" in result.error


@pytest.mark.asyncio
async def test_heroku_resumes_our_own_partial_claim(monkeypatch):
    checker = HerokuTakeoverChecker()
    checker._key = "fake-key"

    async def app_exists(http, app_name):
        return "taken", None

    async def add_domain(http, app_name, domain):
        return True, None

    async def deploy(http, app_name, domain):
        return f"https://{domain}"

    monkeypatch.setattr(checker, "_check_app_available", app_exists)
    monkeypatch.setattr(checker, "_add_domain", add_domain)
    monkeypatch.setattr(checker, "_deploy", deploy)

    result = await checker._run(object(), "app.example.com", "app")

    assert result.status == TakeoverStatus.SUCCESS
    assert result.evidence["app_reused"] is True
    assert result.claim_url == "https://app.example.com"


@pytest.mark.asyncio
async def test_heroku_resumes_when_the_domain_is_already_bound(monkeypatch):
    checker = HerokuTakeoverChecker()
    checker._key = "fake-key"

    async def app_exists(http, app_name):
        return "taken", None

    async def add_domain(http, app_name, domain):
        return False, 'HTTP 422: {"message":"Domain already exists"}'

    async def deploy(http, app_name, domain):
        return f"https://{domain}"

    monkeypatch.setattr(checker, "_check_app_available", app_exists)
    monkeypatch.setattr(checker, "_add_domain", add_domain)
    monkeypatch.setattr(checker, "_deploy", deploy)

    result = await checker._run(object(), "app.example.com", "app")

    assert result.status == TakeoverStatus.SUCCESS
    assert result.evidence["app_reused"] is True


@pytest.mark.asyncio
async def test_heroku_foreign_app_is_not_vulnerable(monkeypatch):
    checker = HerokuTakeoverChecker()
    checker._key = "fake-key"

    async def app_exists(http, app_name):
        return "taken", None

    async def add_domain(http, app_name, domain):
        return False, "HTTP 403: app not owned by this account"

    monkeypatch.setattr(checker, "_check_app_available", app_exists)
    monkeypatch.setattr(checker, "_add_domain", add_domain)

    result = await checker._run(object(), "app.example.com", "app")

    assert result.status == TakeoverStatus.NOT_VULN


@pytest.mark.asyncio
async def test_missing_credentials_are_unavailable_not_not_impl():
    heroku = HerokuTakeoverChecker()
    heroku._key = None
    netlify = NetlifyTakeoverChecker()
    netlify._token = None
    s3 = AWSS3TakeoverChecker()
    s3._ready = False

    heroku_result = await heroku.attempt("app.example.com", "app.herokuapp.com")
    netlify_result = await netlify.attempt("app.example.com", "app.netlify.app")
    s3_result = await s3.attempt("app.example.com", "app.s3.amazonaws.com")

    assert heroku_result.status == TakeoverStatus.UNAVAILABLE
    assert netlify_result.status == TakeoverStatus.UNAVAILABLE
    assert s3_result.status == TakeoverStatus.UNAVAILABLE


def test_azure_generic_provider_hint_still_detects_the_service():
    # signatures.yaml only knows the generic "azure" provider; passing it as a
    # per-service hint used to skip every pattern and return UNAVAILABLE.
    assert extract_resource_name("app.azurewebsites.net", "azure") == (
        "azure_websites",
        "app",
    )
    assert extract_resource_name("app.azurefd.net", None) == ("azure_frontdoor", "app")
    assert extract_resource_name("app.azurewebsites.net", "azure_websites") == (
        "azure_websites",
        "app",
    )


@pytest.mark.asyncio
async def test_azure_websites_missing_service_principal_is_unavailable():
    checker = AzureTakeoverChecker()
    checker._creds_ready = False

    result = await checker._takeover_websites(
        object(), "app.example.com", "app", {"azure_resource": "app"}
    )

    assert result.status == TakeoverStatus.UNAVAILABLE
    assert result.evidence["reason"] == "azure_sp_creds_not_configured"


@pytest.mark.asyncio
async def test_azure_missing_subscription_is_unavailable_not_manual(monkeypatch):
    checker = AzureTakeoverChecker()

    async def unavailable_check(http, provider, resource_name):
        return None, "AZURE_SUBSCRIPTION_ID not configured — cannot call checkNameAvailability"

    monkeypatch.setattr(checker, "_check_name_available", unavailable_check)

    result = await checker._dispatch(
        object(), "app.example.com", "azure_websites", "app", "app.azurewebsites.net"
    )

    assert result.status == TakeoverStatus.UNAVAILABLE
    assert result.evidence["reason"] == "azure_credentials_not_configured"


def test_parent_domain_detection():
    assert providers_evaluator.is_parent_domain("example.com")
    assert providers_evaluator.is_parent_domain("example.com", "example.com")
    assert providers_evaluator.is_parent_domain("example.co.uk", "example.co.uk")
    assert not providers_evaluator.is_parent_domain("app.example.com", "example.com")


def test_default_validator_uses_configured_marker():
    validator = ProvidersEvaluator()._validator

    assert validator._marker == settings.TAKEOVER_CLAIM_MARKER
    assert validator._attempts == settings.TAKEOVER_CLAIM_VALIDATE_ATTEMPTS

