"""
app/takeover/potential.py

Potential takeover detection.

A subdomain is POTENTIAL when:
  - Its CNAME points to a claimable provider  (structural risk)
  - AND the site is currently responding with 2xx  (still live)

The provider account could be deleted at any time, making the subdomain
immediately takeable. We flag it now so the recheck cycle catches the
moment it goes dangling.

NOT POTENTIAL:
  - NXDOMAIN with no CNAME   → record doesn't exist → ALIVE
  - NXDOMAIN with CNAME      → already dangling → evaluator.py scores it
  - 2xx with CNAME to non-claimable provider (e.g. CloudFront) → ALIVE
  - No CNAME at all          → ALIVE

Confidence scoring:
  All POTENTIAL subdomains score exactly 60, then get capped to 59 before
  persisting. This keeps them in POTENTIAL state (30–59) without any
  severity guesswork. Only provider verification (DANGLING path) can push
  a subdomain to ≥ 60 and trigger a Discord alert.
"""

from typing import Optional, Dict, Any

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.logging import logger
from app.db.db_models import Subdomain
from app.discovery.state import StateManager
from app.takeover.subdomain_hunter.takeover_loader import SignatureLoader


class PotentialTakeoverDetector:
    """
    Detect subdomains that are alive (2xx) but whose CNAME points to a
    claimable provider — future takeover candidates.
    """

    def __init__(self):
        sig = SignatureLoader.instance()
        self._cname_patterns      = sig.cname_patterns   # {provider: [(regex, weight), ...]}
        self._claimable_providers = sig.claimable        # {provider: bool}

    # ──────────────────────────────────────────────────────────────────────────
    # Public API
    # ──────────────────────────────────────────────────────────────────────────

    async def evaluate_potential(
            self,
            session: AsyncSession,
            subdomain: Subdomain,
            dns_data: Optional[Dict[str, Any]],
            http_data: Optional[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """
        Evaluate whether a subdomain is a POTENTIAL takeover candidate.

        Returns a dict with:
          is_potential: bool
          confidence:   int  (always 60 if potential, capped to 59 on persist)
          provider:     str | None
          reason:       str
        """
        _not_potential = {"is_potential": False, "confidence": 0, "provider": None}

        status_code = http_data.get("status_code") if http_data else None
        body = http_data.get("body") if http_data else None
        headers = http_data.get("headers", {}) if http_data else {}
        cname = dns_data.get("cname") if dns_data else None
        nxdomain = dns_data.get("nxdomain", False) if dns_data else False

        # NXDOMAIN = service already gone → DANGLING path in evaluator.py
        if nxdomain:
            return {**_not_potential, "reason": "nxdomain — belongs to dangling path"}

        # Must have a CNAME
        if not cname:
            return {**_not_potential, "reason": "no_cname"}

        # Must be alive (2xx) — dead service is DANGLING, not POTENTIAL
        if not status_code or not (200 <= status_code < 300):
            return {**_not_potential, "reason": "not_2xx"}

        # CNAME must point to a claimable provider
        provider = self._match_cname_provider(cname)
        if not provider:
            return {**_not_potential, "reason": "cname_not_claimable"}

        # ── Soft-404 / disguised-dangling guard ──────────────────────────────
        # Some providers (GitHub Pages, Heroku, Shopify, Wix, Pantheon, Tumblr)
        # serve their "this domain is unclaimed" error page as HTTP 200.
        # If the body fingerprints the provider's error page, the subdomain is
        # dangling despite the 200 — bail out and let the evaluator's DNS+HTTP
        # scoring path handle it as DANGLING.
        #
        # We check against the matched CNAME provider specifically, not all
        # providers, to avoid cross-provider false positives.
        if body:
            sig = SignatureLoader.instance()
            provider_http_patterns = sig.http_fingerprints.get(provider, [])
            for pattern, _ in provider_http_patterns:
                if pattern.search(body):
                    logger.debug(
                        "potential: %s returned 200 but body matches %s error fingerprint "
                        "— routing to dangling path",
                        subdomain.name, provider,
                    )
                    return {
                        **_not_potential,
                        "reason": f"200 with {provider} error fingerprint — dangling disguised as 200",
                    }

        # Confirmed alive with no error fingerprint in body — this is genuinely
        # a live service at a claimable provider. Mark POTENTIAL for monitoring.
        return {
            "is_potential": True,
            "confidence": 60,  # capped to 59 by update_potential_state
            "provider": provider,
            "reason": f"Alive 2xx + CNAME → claimable provider {provider}, no error fingerprint",
        }

    async def update_potential_state(
        self,
        session: AsyncSession,
        subdomain: Subdomain,
        evaluation_result: Dict[str, Any],
    ) -> int:
        """
        Persist POTENTIAL state and return the capped confidence.

        Hard cap at DANGLING_THRESHOLD - 1 (59). A live 2xx subdomain is
        POTENTIAL, never DANGLING. Provider verification hasn't run yet —
        nothing is confirmed. Only the DANGLING path (NXDOMAIN + provider
        check) can trigger a Discord alert.
        """
        if not evaluation_result["is_potential"]:
            return 0

        # Cap strictly below DANGLING so this never triggers a Discord alert.
        capped = min(evaluation_result["confidence"], StateManager.DANGLING_THRESHOLD - 1)

        await StateManager.update_confidence(
            session,
            subdomain,
            capped,
            takeover_provider=evaluation_result["provider"],
        )

        logger.info(
            "Marked %s as POTENTIAL (confidence: %d%%, provider: %s)",
            subdomain.name,
            capped,
            evaluation_result["provider"],
        )
        return capped

    # ──────────────────────────────────────────────────────────────────────────
    # Internal helpers
    # ──────────────────────────────────────────────────────────────────────────

    def _match_cname_provider(self, cname: str) -> Optional[str]:
        """Match CNAME against claimable provider patterns only."""
        cname = cname.lower().rstrip(".")

        for provider, patterns in self._cname_patterns.items():
            if not self._claimable_providers.get(provider, False):
                continue
            for regex, weight in patterns:
                if regex.search(cname):
                    return provider

        return None