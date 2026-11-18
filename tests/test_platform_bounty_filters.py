"""Bounty-only program filters for the four main platform adapters."""

from app.programs.bounty_utils import money_amount, positive_money
from app.programs.platforms.bugcrowd import (
    program_offers_bounty as bugcrowd_offers_bounty,
)
from app.programs.platforms.hackerone import (
    program_offers_bounty as hackerone_offers_bounty,
    scope_is_bounty_eligible as hackerone_scope_eligible,
)
from app.programs.platforms.intigriti import (
    program_offers_bounty as intigriti_offers_bounty,
)
from app.programs.platforms.yeswehack import (
    program_offers_bounty as yeswehack_offers_bounty,
)


def test_money_parsing_accepts_currency_strings_and_rejects_points():
    assert money_amount("$2,500") == 2500.0
    assert money_amount("Up to €1.000") == 1.0
    assert money_amount(3000) == 3000.0
    assert money_amount("Points") is None
    assert positive_money("$200") is True
    assert positive_money("$0") is False
    assert positive_money("Points") is False


def test_hackerone_program_bounty_signal():
    assert hackerone_offers_bounty({"offers_bounties": True}, []) is True
    assert hackerone_offers_bounty({"offers_bounties": False}, []) is False
    # Missing program flag: a structured scope flagged for bounty is the
    # fallback positive signal.
    assert hackerone_offers_bounty(
        {"handle": "example"},
        [{"attributes": {"eligible_for_bounty": True}}],
    ) is True
    assert hackerone_offers_bounty({"handle": "example"}, []) is False


def test_hackerone_scope_bounty_fallback_is_conservative():
    assert hackerone_scope_eligible({"eligible_for_bounty": True}, False) is True
    assert hackerone_scope_eligible({"eligible_for_bounty": False}, True) is False
    assert hackerone_scope_eligible(
        {"eligible_for_bounty": True, "eligible_for_submission": False}, True
    ) is False
    # Missing flag: only bounty-eligible programs with submissions not disabled.
    assert hackerone_scope_eligible({}, True) is True
    assert hackerone_scope_eligible({}, False) is False
    assert hackerone_scope_eligible(
        {"eligible_for_submission": False}, True
    ) is False


def test_yeswehack_program_bounty_signal():
    assert yeswehack_offers_bounty({"bounty": True}) is True
    assert yeswehack_offers_bounty({"bounty": False}) is False
    assert yeswehack_offers_bounty({"bounty_reward_max": 500}) is True
    assert yeswehack_offers_bounty({"bounty_reward_min": 100}) is True
    assert yeswehack_offers_bounty({"rewards": {"high": 1000}}) is True
    assert yeswehack_offers_bounty({"rewards": "1000"}) is True
    assert yeswehack_offers_bounty({}) is False


def test_intigriti_program_bounty_signal():
    assert intigriti_offers_bounty(
        {"maxBounty": {"value": 100.0}, "type": {"id": 1}}
    ) is True
    assert intigriti_offers_bounty(
        {"maxBounty": {"value": 0}, "type": {"id": 1}}
    ) is False
    assert intigriti_offers_bounty(
        {"bounty": False, "maxBounty": {"value": 100}, "type": {"id": 1}}
    ) is False
    assert intigriti_offers_bounty(
        {"bounty": True, "type": {"id": 1}}
    ) is True
    # No money fields at all: the platform's Bug Bounty type is the fallback.
    assert intigriti_offers_bounty({"type": {"id": 1}}) is True
    assert intigriti_offers_bounty({}) is False


def test_bugcrowd_program_bounty_signal():
    assert bugcrowd_offers_bounty({
        "rewardSummary": {"minReward": "$200", "maxReward": "$3,000"}
    }) is True
    assert bugcrowd_offers_bounty({
        "rewardSummary": {"minReward": "Points", "maxReward": "Points"}
    }) is False
    # Null summary marks a VDP even though the engagement label may say bounty.
    assert bugcrowd_offers_bounty({"rewardSummary": None}) is False
    assert bugcrowd_offers_bounty({
        "productEngagementType": {"label": "Bug Bounty"}
    }) is True
    assert bugcrowd_offers_bounty({
        "productEngagementType": {"label": "Vulnerability Disclosure"}
    }) is False
