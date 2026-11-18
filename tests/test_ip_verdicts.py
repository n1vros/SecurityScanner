"""Per-IP verdict serialization, aggregation and filtering."""

import json
from datetime import datetime

from app.probing.ip_verdicts import (
    IPVerdict,
    IPVerdictStatus,
    aggregate_subdomain_ip_free,
    deserialize_ip_verdicts,
    filter_current_ip_verdicts,
    load_ip_verdicts,
    serialize_ip_verdicts,
    verdict_from_finding,
)


def verdict(ip, status):
    return IPVerdict(ip=ip, status=status, source="test", checked_at=datetime.utcnow())


def test_round_trip_serialization():
    verdicts = [
        verdict("1.2.3.4", IPVerdictStatus.FREE),
        verdict("5.6.7.8", IPVerdictStatus.TAKEN),
        verdict("9.9.9.9", IPVerdictStatus.INCONCLUSIVE),
    ]
    raw = serialize_ip_verdicts(verdicts)
    payload = json.loads(raw)

    assert set(payload) == {"1.2.3.4", "5.6.7.8", "9.9.9.9"}
    assert payload["1.2.3.4"]["status"] == "free"
    assert payload["5.6.7.8"]["status"] == "taken"

    restored = deserialize_ip_verdicts(raw)
    assert restored["1.2.3.4"].status == IPVerdictStatus.FREE
    assert restored["9.9.9.9"].ip_free is None


def test_serialization_tolerates_junk():
    assert json.loads(serialize_ip_verdicts([])) == {}
    assert deserialize_ip_verdicts("not json") == {}
    assert deserialize_ip_verdicts(None) == {}


def test_aggregate_rules():
    free = verdict("1.1.1.1", IPVerdictStatus.FREE)
    taken = verdict("2.2.2.2", IPVerdictStatus.TAKEN)
    unknown = verdict("3.3.3.3", IPVerdictStatus.INCONCLUSIVE)

    assert aggregate_subdomain_ip_free([free]) is True
    assert aggregate_subdomain_ip_free([free, unknown]) is True
    assert aggregate_subdomain_ip_free([free, taken]) is False
    assert aggregate_subdomain_ip_free([taken, unknown]) is False
    assert aggregate_subdomain_ip_free([unknown]) is None
    assert aggregate_subdomain_ip_free([]) is None


def test_filter_drops_stale_ips():
    verdicts = {
        "1.1.1.1": verdict("1.1.1.1", IPVerdictStatus.FREE),
        "2.2.2.2": verdict("2.2.2.2", IPVerdictStatus.TAKEN),
    }

    filtered = filter_current_ip_verdicts(["1.1.1.1"], verdicts)

    assert list(filtered) == ["1.1.1.1"]


def test_load_accepts_json_and_mapping():
    raw = serialize_ip_verdicts([verdict("1.1.1.1", IPVerdictStatus.FREE)])
    assert load_ip_verdicts(raw)["1.1.1.1"].status == IPVerdictStatus.FREE
    assert load_ip_verdicts(json.loads(raw))["1.1.1.1"].status == IPVerdictStatus.FREE


def test_verdict_from_finding():
    base = dict(
        ip="10.0.0.1",
        finding_type="dangling",
        confidence=80,
        provider_key="aws",
        region="us-east-1",
        open_ports=[80],
        confirmed_free=True,
        foreign_tls_cert=False,
        cloud_claim_confirmed=False,
    )

    from types import SimpleNamespace

    free = verdict_from_finding(SimpleNamespace(**base))
    assert free.status == IPVerdictStatus.FREE
    assert free.ip_free is True

    foreign = verdict_from_finding(
        SimpleNamespace(**{**base, "foreign_tls_cert": True, "confirmed_free": False})
    )
    assert foreign.status == IPVerdictStatus.TAKEN
    assert foreign.ip_free is False

    unknown = verdict_from_finding(
        SimpleNamespace(
            **{
                **base,
                "foreign_tls_cert": False,
                "confirmed_free": False,
                "cloud_claim_confirmed": False,
            }
        )
    )
    assert unknown.status == IPVerdictStatus.INCONCLUSIVE
