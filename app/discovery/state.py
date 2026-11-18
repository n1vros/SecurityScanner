"""
app/discovery/state.py

Subdomain state machine and the confidence ladder.

This module is the only place that decides how a numeric confidence maps to a
``SubdomainState``. The thresholds are load-bearing — Discord alerts and the
recheck cadence depend on them:

    0            .. 29   ALIVE        nothing to report
    30           .. 59   POTENTIAL    structurally at risk, monitored, no alert
    60           .. 100  DANGLING     alert-worthy, queued for a report

``POTENTIAL_LONG`` (ownership-blocked) and the terminal states DEAD,
FALSE_POSITIVE and CLAIMED are never produced by the confidence ladder; they
are set explicitly with :meth:`StateManager.transition`. A generic confidence
update must not silently demote them (for example, a POTENTIAL_LONG finding
must stay POTENTIAL_LONG when a recheck merely recomputes a low score).
"""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.logging import logger
from app.db.db_models import StateTransition, Subdomain, SubdomainState


class StateManager:
    """Confidence-driven state transitions with an audit trail."""

    # Confidence thresholds — referenced by the evaluator and provider handlers.
    DANGLING_THRESHOLD: int = 60
    POTENTIAL_THRESHOLD: int = 30
    POTENTIAL_LONG_THRESHOLD: int = 30

    # States that the generic ladder must not overwrite.
    _TERMINAL_STATES = {
        SubdomainState.DEAD,
        SubdomainState.FALSE_POSITIVE,
        SubdomainState.CLAIMED,
    }

    @classmethod
    def state_for_confidence(cls, confidence: int) -> SubdomainState:
        """Return the state implied by a 0–100 confidence score."""
        if confidence >= cls.DANGLING_THRESHOLD:
            return SubdomainState.DANGLING
        if confidence >= cls.POTENTIAL_THRESHOLD:
            return SubdomainState.POTENTIAL
        return SubdomainState.ALIVE

    @classmethod
    async def update_confidence(
        cls,
        session: AsyncSession,
        subdomain: Subdomain,
        confidence: int,
        takeover_provider: Optional[str] = None,
        takeover_evidence: Optional[str] = None,
    ) -> SubdomainState:
        """
        Persist a new confidence, provider and evidence, and move the subdomain
        along the ladder when the band changes.

        * POTENTIAL_LONG is preserved unless the new score reaches DANGLING.
        * DEAD / FALSE_POSITIVE / CLAIMED are preserved.
        * Returns the resulting state.
        """
        try:
            score = int(confidence)
        except (TypeError, ValueError):
            score = 0
        score = max(0, min(100, score))

        subdomain.confidence = score
        subdomain.takeover_provider = takeover_provider
        if takeover_evidence is not None:
            subdomain.takeover_evidence = takeover_evidence

        target = cls.state_for_confidence(score)

        if subdomain.state == SubdomainState.POTENTIAL_LONG:
            if target != SubdomainState.DANGLING:
                target = SubdomainState.POTENTIAL_LONG
        elif subdomain.state in cls._TERMINAL_STATES:
            target = subdomain.state

        await cls.transition(session, subdomain, target, reason=f"confidence={score}")
        session.add(subdomain)
        return subdomain.state

    @classmethod
    async def transition(
        cls,
        session: AsyncSession,
        subdomain: Subdomain,
        state: SubdomainState,
        reason: Optional[str] = None,
    ) -> None:
        """
        Move a subdomain to an explicit state and record a ``StateTransition``.

        A no-op when the state is unchanged, so callers can invoke it freely.
        """
        if subdomain.state == state:
            return

        previous = subdomain.state
        now = datetime.utcnow()

        subdomain.state = state
        subdomain.last_state_change_at = now
        session.add(subdomain)
        session.add(
            StateTransition(
                subdomain_id=subdomain.id,
                from_state=previous,
                to_state=state,
                reason=(reason or "")[:512] or None,
            )
        )
        logger.info(
            "state: %s %s -> %s (%s)",
            subdomain.name,
            previous.value if previous else "none",
            state.value,
            reason or "no reason",
        )
