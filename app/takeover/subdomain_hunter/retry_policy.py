"""
Per-outcome retry policy for automatic subdomain-takeover attempts.

Every provider result maps to one durable outcome. The outcome decides whether
a finding may ever be retried automatically, and what is persisted in
``Subdomain.takeover_last_status`` / ``Subdomain.takeover_retry_at``:

  claimed            validated takeover -> CLAIMED, never attempted again
  not_vuln           resource still owned (or TAKEN) -> no automatic retry;
                     the caller negates the finding (confidence 0 / ALIVE)
  failed             attempt errored -> retry after TAKEOVER_RETRY_HOURS
  validation_failed  attempt reported success but did not serve our claim
                     marker -> retry after TAKEOVER_RETRY_HOURS
  unavailable        credentials/API missing -> retry after
                     TAKEOVER_RETRY_HOURS; never terminal, so enabling the
                     provider later picks the finding up again
  needs_txt          ownership transfer required (Vercel/Heroku) ->
                     retry after TAKEOVER_RETRY_DAYS, keeping POTENTIAL_LONG
  manual             NOT_IMPL or domain owned by another provider account ->
                     retry after TAKEOVER_RETRY_DAYS

``takeover_retry_at`` is authoritative: a NULL value means "no schedule
recorded" and is treated as due. Recheck queries skip rows whose timestamp is
still in the future and pick them up automatically once it elapses.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum
from typing import Optional

from app.takeover.subdomain_hunter.providers.base import TakeoverResult, TakeoverStatus


class TakeoverOutcome(str, Enum):
    """Durable classification of a provider attempt."""

    CLAIMED = "claimed"
    NOT_VULN = "not_vuln"
    FAILED = "failed"
    VALIDATION_FAILED = "validation_failed"
    UNAVAILABLE = "unavailable"
    NEEDS_TXT = "needs_txt"
    MANUAL = "manual"


class RetryDelay(str, Enum):
    """Which retry interval applies to an outcome."""

    NONE = "none"
    HOURS = "hours"
    DAYS = "days"


@dataclass(frozen=True)
class OutcomePolicy:
    """Outcome plus its scheduling rule."""

    outcome: TakeoverOutcome
    retry: RetryDelay

    @property
    def status(self) -> str:
        """Value persisted in ``Subdomain.takeover_last_status``."""
        return self.outcome.value

    @property
    def terminal(self) -> bool:
        """True when no automatic attempt may ever run again."""
        return self.retry is RetryDelay.NONE

    @property
    def retryable(self) -> bool:
        return self.retry is not RetryDelay.NONE


def classify_outcome(result: Optional[TakeoverResult]) -> Optional[OutcomePolicy]:
    """
    Map a provider result to an :class:`OutcomePolicy`.

    ``SUCCESS`` only counts as claimed when the result carries
    ``claim_validated=True``; an unvalidated success is a failed attempt, not a
    takeover. Returns ``None`` when there is no attempt to classify.
    """
    if result is None:
        return None

    status = result.status

    if status == TakeoverStatus.SUCCESS:
        if result.claim_validated is True:
            return OutcomePolicy(TakeoverOutcome.CLAIMED, RetryDelay.NONE)
        return OutcomePolicy(TakeoverOutcome.VALIDATION_FAILED, RetryDelay.HOURS)

    if status == TakeoverStatus.NOT_VULN:
        return OutcomePolicy(TakeoverOutcome.NOT_VULN, RetryDelay.NONE)

    if status == TakeoverStatus.NEEDS_TXT:
        return OutcomePolicy(TakeoverOutcome.NEEDS_TXT, RetryDelay.DAYS)

    if status == TakeoverStatus.NOT_IMPL:
        return OutcomePolicy(TakeoverOutcome.MANUAL, RetryDelay.DAYS)

    if status == TakeoverStatus.UNAVAILABLE:
        return OutcomePolicy(TakeoverOutcome.UNAVAILABLE, RetryDelay.HOURS)

    # FAIL: a custom domain owned by another provider account behaves like a
    # manual ownership block, not a transient error.
    if result.evidence.get("domain_claimed_elsewhere"):
        return OutcomePolicy(TakeoverOutcome.MANUAL, RetryDelay.DAYS)

    if result.evidence.get("validation_failed"):
        return OutcomePolicy(TakeoverOutcome.VALIDATION_FAILED, RetryDelay.HOURS)

    return OutcomePolicy(TakeoverOutcome.FAILED, RetryDelay.HOURS)


def compute_retry_at(
    policy: Optional[OutcomePolicy],
    *,
    now: Optional[datetime] = None,
    retry_hours: int = 24,
    retry_days: int = 7,
) -> Optional[datetime]:
    """Return the next automatic attempt time for *policy*, or ``None``."""
    if policy is None or policy.retry is RetryDelay.NONE:
        return None

    now = now or datetime.utcnow()
    if policy.retry is RetryDelay.HOURS:
        delta = timedelta(hours=max(0, int(retry_hours)))
    else:
        delta = timedelta(days=max(0, int(retry_days)))
    return now + delta


def retry_is_due(retry_at: Optional[datetime], now: Optional[datetime] = None) -> bool:
    """True when a finding may be attempted again (NULL means due now)."""
    if retry_at is None:
        return True
    return retry_at <= (now or datetime.utcnow())
