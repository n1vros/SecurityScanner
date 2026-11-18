"""Per-outcome retry policy matrix for automatic subdomain takeover."""

from datetime import datetime, timedelta

import pytest

from app.takeover.subdomain_hunter.providers.base import TakeoverResult, TakeoverStatus
from app.takeover.subdomain_hunter.retry_policy import (
    OutcomePolicy,
    RetryDelay,
    TakeoverOutcome,
    classify_outcome,
    compute_retry_at,
    retry_is_due,
)

NOW = datetime(2026, 1, 1, 12, 0, 0)


def result(status: TakeoverStatus, **kwargs) -> TakeoverResult:
    kwargs.setdefault("provider", "heroku")
    kwargs.setdefault("subdomain", "app.example.com")
    return TakeoverResult(status=status, **kwargs)


def test_validated_success_is_terminal_claimed():
    policy = classify_outcome(result(TakeoverStatus.SUCCESS, claim_validated=True))

    assert policy == OutcomePolicy(TakeoverOutcome.CLAIMED, RetryDelay.NONE)
    assert policy.terminal
    assert compute_retry_at(policy, now=NOW) is None


def test_success_without_validation_is_a_failed_attempt():
    for claim_validated in (None, False):
        policy = classify_outcome(
            result(TakeoverStatus.SUCCESS, claim_validated=claim_validated)
        )
        assert policy.outcome is TakeoverOutcome.VALIDATION_FAILED
        assert policy.retry is RetryDelay.HOURS
        assert not policy.terminal


def test_not_vuln_never_retries():
    policy = classify_outcome(result(TakeoverStatus.NOT_VULN))

    assert policy.outcome is TakeoverOutcome.NOT_VULN
    assert policy.terminal
    assert compute_retry_at(policy, now=NOW) is None


def test_needs_txt_retries_in_days():
    policy = classify_outcome(result(TakeoverStatus.NEEDS_TXT))

    assert policy.outcome is TakeoverOutcome.NEEDS_TXT
    assert compute_retry_at(policy, now=NOW, retry_days=7) == NOW + timedelta(days=7)


def test_not_impl_is_manual_retry_in_days():
    policy = classify_outcome(result(TakeoverStatus.NOT_IMPL))

    assert policy.outcome is TakeoverOutcome.MANUAL
    assert compute_retry_at(policy, now=NOW, retry_days=3) == NOW + timedelta(days=3)


def test_unavailable_retries_in_hours_and_is_not_terminal():
    policy = classify_outcome(result(TakeoverStatus.UNAVAILABLE))

    assert policy.outcome is TakeoverOutcome.UNAVAILABLE
    assert not policy.terminal
    assert compute_retry_at(policy, now=NOW, retry_hours=6) == NOW + timedelta(hours=6)


def test_fail_retries_in_hours():
    policy = classify_outcome(result(TakeoverStatus.FAIL))

    assert policy.outcome is TakeoverOutcome.FAILED
    assert compute_retry_at(policy, now=NOW, retry_hours=24) == NOW + timedelta(hours=24)


def test_fail_with_domain_claimed_elsewhere_is_manual():
    policy = classify_outcome(
        result(TakeoverStatus.FAIL, evidence={"domain_claimed_elsewhere": True})
    )

    assert policy.outcome is TakeoverOutcome.MANUAL
    assert compute_retry_at(policy, now=NOW, retry_days=7) == NOW + timedelta(days=7)


def test_no_result_has_no_policy():
    assert classify_outcome(None) is None
    assert compute_retry_at(None, now=NOW) is None


def test_retry_is_due_semantics():
    assert retry_is_due(None, now=NOW)
    assert retry_is_due(NOW - timedelta(seconds=1), now=NOW)
    assert retry_is_due(NOW, now=NOW)
    assert not retry_is_due(NOW + timedelta(seconds=1), now=NOW)


@pytest.mark.parametrize("hours,days", [(0, 0), (-5, -1)])
def test_negative_intervals_clamp_to_immediate(hours, days):
    hours_policy = classify_outcome(result(TakeoverStatus.FAIL))
    days_policy = classify_outcome(result(TakeoverStatus.NEEDS_TXT))

    assert compute_retry_at(hours_policy, now=NOW, retry_hours=hours) == NOW
    assert compute_retry_at(days_policy, now=NOW, retry_days=days) == NOW
