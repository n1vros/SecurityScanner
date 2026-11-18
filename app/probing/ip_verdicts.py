"""
app/probing/ip_verdicts.py

Shared per-IP ownership verdicts used by the DNS sweep, the IP liveness check
and the IP hunter.

A verdict answers one question for a single IPv4/IPv6 address:

    FREE          the address looks unallocated and may be claimable
    TAKEN         something is clearly running on it (open/refused ports,
                  foreign TLS certificate, provider allocation markers)
    INCONCLUSIVE  only filtered/errored probes; ambiguous

The verdict object is serialized to ``Subdomain.ip_verdicts`` as a JSON object
keyed by IP so later scan cycles and the hunter can reuse it without re-probing.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, Iterable, List, Optional


class IPVerdictStatus(str, Enum):
    FREE = "free"
    TAKEN = "taken"
    INCONCLUSIVE = "inconclusive"


@dataclass
class IPVerdict:
    """Ownership verdict for one IP address."""

    ip: str
    status: IPVerdictStatus = IPVerdictStatus.INCONCLUSIVE
    source: str = "unknown"
    checked_at: datetime = field(default_factory=datetime.utcnow)
    reason: Optional[str] = None
    confidence: int = 0
    provider: Optional[str] = None
    region: Optional[str] = None
    open_ports: List[int] = field(default_factory=list)

    @property
    def ip_free(self) -> Optional[bool]:
        """True = free, False = taken, None = inconclusive."""
        if self.status == IPVerdictStatus.FREE:
            return True
        if self.status == IPVerdictStatus.TAKEN:
            return False
        return None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "status": self.status.value,
            "source": self.source,
            "checked_at": self.checked_at.isoformat(),
            "reason": self.reason,
            "confidence": self.confidence,
            "provider": self.provider,
            "region": self.region,
            "open_ports": list(self.open_ports),
        }

    @classmethod
    def from_dict(cls, ip: str, payload: Dict[str, Any]) -> "IPVerdict":
        checked_at = payload.get("checked_at")
        try:
            parsed_checked_at = datetime.fromisoformat(checked_at) if checked_at else datetime.utcnow()
        except (TypeError, ValueError):
            parsed_checked_at = datetime.utcnow()
        try:
            status = IPVerdictStatus(str(payload.get("status", "inconclusive")).lower())
        except ValueError:
            status = IPVerdictStatus.INCONCLUSIVE
        return cls(
            ip=ip,
            status=status,
            source=str(payload.get("source") or "unknown"),
            checked_at=parsed_checked_at,
            reason=payload.get("reason"),
            confidence=int(payload.get("confidence") or 0),
            provider=payload.get("provider"),
            region=payload.get("region"),
            open_ports=[int(p) for p in payload.get("open_ports") or []],
        )


def verdict_from_finding(finding: Any) -> IPVerdict:
    """
    Convert a ``DanglingIPFinding`` (duck-typed to avoid a circular import)
    into a per-IP verdict.

    A foreign TLS certificate means somebody else already owns the address, so
    it is TAKEN even if other signals looked like a free IP.
    """
    foreign_cert = bool(getattr(finding, "foreign_tls_cert", False))
    confirmed_free = bool(getattr(finding, "confirmed_free", False)) or bool(
        getattr(finding, "cloud_claim_confirmed", False)
    )

    if foreign_cert:
        status = IPVerdictStatus.TAKEN
        reason = "foreign TLS certificate — address is live and owned by another party"
    elif confirmed_free:
        status = IPVerdictStatus.FREE
        reason = "dangling-IP analysis confirmed the address is unallocated"
    else:
        status = IPVerdictStatus.INCONCLUSIVE
        reason = "dangling-IP analysis stayed inconclusive"

    return IPVerdict(
        ip=str(getattr(finding, "ip", "")),
        status=status,
        source=str(getattr(finding, "finding_type", "dangling")),
        checked_at=datetime.utcnow(),
        reason=reason,
        confidence=int(getattr(finding, "confidence", 0) or 0),
        provider=getattr(finding, "provider_key", None) or None,
        region=getattr(finding, "region", None) or None,
        open_ports=[int(p) for p in getattr(finding, "open_ports", []) or []],
    )


def serialize_ip_verdicts(verdicts: Iterable[Optional[IPVerdict]]) -> str:
    """
    Serialize verdicts to the JSON object stored on ``Subdomain.ip_verdicts``.

    Accepts lists, generators or ``dict.values()``; ``None`` entries are
    skipped. Always returns a JSON object (``{}`` when there is nothing).
    """
    payload: Dict[str, Any] = {}
    for verdict in verdicts or ():
        if not isinstance(verdict, IPVerdict) or not verdict.ip:
            continue
        payload[verdict.ip] = verdict.to_dict()
    return json.dumps(payload, sort_keys=True)


def deserialize_ip_verdicts(raw: Optional[str]) -> Dict[str, IPVerdict]:
    """Parse the JSON stored on ``Subdomain.ip_verdicts``; tolerate junk."""
    if not raw:
        return {}
    try:
        payload = json.loads(raw)
    except (TypeError, ValueError):
        return {}
    if not isinstance(payload, dict):
        return {}
    result: Dict[str, IPVerdict] = {}
    for ip, entry in payload.items():
        if isinstance(entry, dict):
            result[str(ip)] = IPVerdict.from_dict(str(ip), entry)
    return result


def load_ip_verdicts(raw: Any) -> Dict[str, IPVerdict]:
    """
    Load verdicts from the JSON stored on ``Subdomain.ip_verdicts``.

    Accepts a JSON string (DB value), an already-parsed mapping, or ``None``.
    """
    if not raw:
        return {}
    if isinstance(raw, dict):
        return {
            str(ip): IPVerdict.from_dict(str(ip), payload)
            for ip, payload in raw.items()
            if isinstance(payload, dict)
        }
    return deserialize_ip_verdicts(raw)


def filter_current_ip_verdicts(
    ips: Iterable[str],
    verdicts: Optional[Dict[str, IPVerdict]],
) -> Dict[str, IPVerdict]:
    """
    Keep only verdicts for the addresses the subdomain currently resolves to.

    Stale verdicts from removed A records must not influence hunting decisions.
    """
    if not verdicts:
        return {}
    current = {str(ip) for ip in ips or ()}
    return {ip: verdict for ip, verdict in verdicts.items() if ip in current}


def aggregate_subdomain_ip_free(verdicts: Iterable[Optional[IPVerdict]]) -> Optional[bool]:
    """
    Aggregate per-IP verdicts into the subdomain-level ``ip_free`` flag.

    * any TAKEN          -> False (at least one address clearly responded)
    * otherwise any FREE -> True
    * no usable verdicts -> None (ambiguous, never treated as free)

    Returning False/None instead of True keeps the hunter conservative: only
    evidence of a free address enables claiming.
    """
    saw_free = False
    saw_any = False
    for verdict in verdicts or ():
        if not isinstance(verdict, IPVerdict):
            continue
        saw_any = True
        if verdict.status == IPVerdictStatus.TAKEN:
            return False
        if verdict.status == IPVerdictStatus.FREE:
            saw_free = True
    if not saw_any:
        return None
    return True if saw_free else None
