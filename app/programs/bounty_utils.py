"""
Shared bounty-signal helpers for platform adapters.

Platform APIs disagree on how they express "this program pays": booleans,
max-reward objects, currency strings, or a reward summary that only exists for
paid programs. Each adapter extracts an explicit tri-state signal and passes it
here so the fallback rule is identical everywhere:

    explicit True / False wins;
    a missing signal keeps the program only when another positive signal exists.
"""

import re
from typing import Iterable, Optional

from app.core.logging import logger

_TRUE_STRINGS = frozenset({"true", "1", "yes", "y", "bounty", "paid"})
_FALSE_STRINGS = frozenset({"false", "0", "no", "n", "none", "null", "", "vdp"})
_AMOUNT_RE = re.compile(r"\d[\d,.]*")


def as_optional_bool(value: object) -> Optional[bool]:
    """Normalise a JSON boolean-like value to True/False, or None if absent."""
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in _TRUE_STRINGS:
            return True
        if normalized in _FALSE_STRINGS:
            return False
    return None


def money_amount(value: object) -> Optional[float]:
    """Extract a numeric amount from an API money field.

    Handles numbers and display strings such as "$2,500", "€1000", "Up to
    $5,000". Non-monetary labels ("Points", "N/A") return None rather than 0 so
    callers can tell "no signal" from "explicitly zero".
    """
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    if not isinstance(value, str):
        return None
    match = _AMOUNT_RE.search(value)
    if not match:
        return None
    try:
        return float(match.group(0).replace(",", ""))
    except ValueError:
        return None


def positive_money(value: object) -> bool:
    """True only when *value* parses to a strictly positive amount."""
    amount = money_amount(value)
    return amount is not None and amount > 0


def bounty_decision(
    *,
    platform: str,
    program: str,
    explicit: Optional[bool],
    signals: Iterable[bool],
) -> bool:
    """Apply the conservative program-level bounty rule.

    When the platform omits its primary bounty flag, the payload shape has
    changed or is a partial response. We log that at WARNING and keep the
    program only if another positive bounty signal is present; otherwise the
    program is skipped rather than scanned as a free/unknown engagement.
    """
    if explicit is not None:
        return explicit

    positive = any(bool(signal) for signal in signals)
    logger.warning(
        "%s [%s]: bounty signal missing from payload — %s",
        platform,
        program or "<unknown>",
        "keeping (another positive signal is present)" if positive else "skipping",
    )
    return positive
