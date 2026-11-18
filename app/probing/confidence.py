"""
app/probing/confidence.py

DNS/HTTP confidence scoring for the subdomain takeover evaluator.

Weights come from ``files/signatures.yaml`` (loaded once by
:class:`~app.takeover.subdomain_hunter.takeover_loader.SignatureLoader`):

* CNAME match                  → 40 for claimable providers, 35 otherwise
* NXDOMAIN on a matched CNAME  → +25 (the classic dangling-CNAME signal)
* HTTP body/header fingerprints→ their configured weight (can be negative;
  e.g. S3's ``AccessDenied`` is −100 and must suppress the finding)

The resulting 0–100 score feeds :class:`StateManager` (30 = POTENTIAL,
60 = DANGLING). A dangling CNAME to a claimable provider therefore scores at
least 65 and alerts, while a recognised provider whose page proves the resource
still exists is pushed back to 0.
"""

from __future__ import annotations

from typing import Any, Dict, Optional, Tuple

from app.takeover.subdomain_hunter.takeover_loader import SignatureData, SignatureLoader

# Added when the CNAME target does not exist (dangling pointer).
NXDOMAIN_BONUS: int = 25

# HTTP fingerprints corroborate a DNS signal, they do not replace it.
HTTP_CONTRIBUTION: float = 0.5


class ConfidenceScorer:
    """Combine DNS and HTTP takeover signals into one confidence score."""

    @staticmethod
    def _sig() -> SignatureData:
        return SignatureLoader.instance().data

    @staticmethod
    def score_dns(
        cname: Optional[str],
        nxdomain: bool,
        subdomain_name: Optional[str] = None,
    ) -> Tuple[int, Optional[str]]:
        """
        Score a CNAME against the provider signatures.

        Returns ``(score, provider)``. On the NXDOMAIN path ``provider`` is
        deliberately ``None``: the evaluator re-runs the match without
        NXDOMAIN to identify which provider to verify, and keeps the score.
        """
        if not cname:
            return 0, None

        target = str(cname).lower().rstrip(".")
        best_provider: Optional[str] = None
        best_weight = 0

        for provider, patterns in ConfidenceScorer._sig().cname_patterns.items():
            for regex, weight in patterns:
                if regex.search(target) and weight > best_weight:
                    best_provider, best_weight = provider, weight

        if best_provider is None:
            return 0, None

        score = best_weight + (NXDOMAIN_BONUS if nxdomain else 0)
        score = max(0, min(100, score))
        return score, (None if nxdomain else best_provider)

    @staticmethod
    def score_http(
        status_code: Optional[int],
        body: Optional[str],
        headers: Optional[Dict[str, Any]],
    ) -> Tuple[int, Optional[str]]:
        """
        Score an HTTP response against body/header fingerprints.

        Returns ``(score, provider)`` for the provider with the strongest
        aggregate match. Negative weights (AccessDenied, NoSuchWebsite …) can
        make the score negative, which the evaluator uses to suppress findings.
        """
        scores: Dict[str, int] = {}
        data = ConfidenceScorer._sig()

        if body:
            for provider, patterns in data.http_fingerprints.items():
                for regex, weight in patterns:
                    if regex.search(body):
                        scores[provider] = scores.get(provider, 0) + weight

        if headers:
            lowered = {str(k).lower(): str(v) for k, v in headers.items()}
            for header_name, regex, provider, weight in data.header_fingerprints:
                value = lowered.get(header_name.lower())
                if value is not None and regex.search(value):
                    scores[provider] = scores.get(provider, 0) + weight

        if not scores:
            return 0, None

        provider = max(scores, key=lambda key: scores[key])
        return max(-100, min(100, scores[provider])), provider

    @staticmethod
    def compute_overall(
        dns_score: int,
        http_score: int,
        nxdomain: bool,
        subdomain_name: Optional[str] = None,
    ) -> int:
        """
        Combine DNS and HTTP scores into the 0–100 confidence persisted on the
        subdomain. HTTP only corroborates (half weight); a negative HTTP score
        subtracts in full so explicit "still owned" pages suppress the finding.
        """
        if dns_score <= 0 and http_score <= 0:
            return 0

        http_component = http_score * HTTP_CONTRIBUTION if http_score > 0 else http_score
        overall = int(round(dns_score + http_component))

        # A dangling CNAME is meaningful on its own, but a page that proves the
        # resource still exists (negative HTTP score) must be able to suppress it.
        if nxdomain and dns_score > 0 and http_score >= 0:
            overall = max(overall, dns_score)

        return max(0, min(100, overall))
