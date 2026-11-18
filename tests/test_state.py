"""State ladder tests — the severity of every finding depends on these rules."""

from types import SimpleNamespace

import pytest

from app.db.db_models import SubdomainState, StateTransition
from app.discovery.state import StateManager


class FakeSession:
    def __init__(self):
        self.added = []

    def add(self, obj):
        self.added.append(obj)


def make_subdomain(state=SubdomainState.DISCOVERED, confidence=0):
    return SimpleNamespace(
        id=1,
        name="api.example.com",
        state=state,
        confidence=confidence,
        takeover_provider=None,
        takeover_evidence=None,
        last_state_change_at=None,
    )


@pytest.mark.asyncio
async def test_confidence_ladder():
    subdomain = make_subdomain()
    session = FakeSession()

    await StateManager.update_confidence(session, subdomain, 10)
    assert subdomain.state == SubdomainState.ALIVE
    assert subdomain.confidence == 10

    await StateManager.update_confidence(session, subdomain, 45)
    assert subdomain.state == SubdomainState.POTENTIAL

    await StateManager.update_confidence(session, subdomain, 60)
    assert subdomain.state == SubdomainState.DANGLING

    transitions = [obj for obj in session.added if isinstance(obj, StateTransition)]
    assert [t.to_state for t in transitions] == [
        SubdomainState.ALIVE,
        SubdomainState.POTENTIAL,
        SubdomainState.DANGLING,
    ]
    assert subdomain.last_state_change_at is not None


@pytest.mark.asyncio
async def test_potential_long_is_not_demoted_by_a_recheck():
    subdomain = make_subdomain(state=SubdomainState.POTENTIAL_LONG, confidence=30)
    session = FakeSession()

    await StateManager.update_confidence(session, subdomain, 20)

    assert subdomain.state == SubdomainState.POTENTIAL_LONG
    assert subdomain.confidence == 20


@pytest.mark.asyncio
async def test_potential_long_can_be_promoted_to_dangling():
    subdomain = make_subdomain(state=SubdomainState.POTENTIAL_LONG, confidence=30)
    session = FakeSession()

    await StateManager.update_confidence(session, subdomain, 75)

    assert subdomain.state == SubdomainState.DANGLING


@pytest.mark.asyncio
async def test_terminal_states_survive_generic_updates():
    for terminal in (
        SubdomainState.DEAD,
        SubdomainState.FALSE_POSITIVE,
        SubdomainState.CLAIMED,
    ):
        subdomain = make_subdomain(state=terminal, confidence=0)
        session = FakeSession()

        await StateManager.update_confidence(session, subdomain, 90)

        assert subdomain.state == terminal


@pytest.mark.asyncio
async def test_explicit_transition_records_reason_and_is_idempotent():
    subdomain = make_subdomain(state=SubdomainState.DANGLING, confidence=80)
    session = FakeSession()

    await StateManager.transition(
        session, subdomain, SubdomainState.POTENTIAL_LONG, reason="needs TXT transfer"
    )
    assert subdomain.state == SubdomainState.POTENTIAL_LONG

    records = [obj for obj in session.added if isinstance(obj, StateTransition)]
    assert len(records) == 1
    assert records[0].reason == "needs TXT transfer"

    await StateManager.transition(session, subdomain, SubdomainState.POTENTIAL_LONG)
    assert len([obj for obj in session.added if isinstance(obj, StateTransition)]) == 1


@pytest.mark.asyncio
async def test_confidence_is_clamped():
    subdomain = make_subdomain()
    session = FakeSession()

    await StateManager.update_confidence(session, subdomain, 250)
    assert subdomain.confidence == 100
    assert subdomain.state == SubdomainState.DANGLING

    await StateManager.update_confidence(session, subdomain, -50)
    assert subdomain.confidence == 0
