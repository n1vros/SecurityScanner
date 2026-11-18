"""
app/takeover/evaluator.py

Takeover evaluation combining DNS and HTTP signals.
Nuclei removed from pipeline.

Decision tree
─────────────
  0. No data at all                     → confidence 0, no state update
  0a. Probe empty (no cname, no nxdomain, no ips, no http) AND subdomain is
      already POTENTIAL/DANGLING        → skip update (treat as timeout,
                                          preserve existing state)
  1. Internal CNAME (same registered domain) → confidence 0, ALIVE
  2. Alive (2xx) + CNAME → claimable provider → POTENTIAL  (potential.py)
  3. NXDOMAIN + CNAME → score via DNS+HTTP → DANGLING / POTENTIAL
     3a. NXDOMAIN + CNAME + no provider match → confidence 0, ALIVE
         (CNAME target unknown — cannot confirm claimability, suppress FP)
  4. NXDOMAIN + no CNAME               → confidence 0, ALIVE
     (record simply doesn't exist — not a subdomain takeover scenario)
  5. CNAME + no NXDOMAIN + dns_provider matched + claimable → score → state
  6. No CNAME / no matching provider   → confidence 0, ALIVE
  7. A live HTTP fingerprint for a DIFFERENT provider than the CNAME suppresses
     the finding to 0; timeouts do not.
  8. CLAIMED is terminal: a validated claim is never re-evaluated or overwritten.
"""

from typing import Optional, Dict, Any

from sqlalchemy.ext.asyncio import AsyncSession

from app.probing.confidence import ConfidenceScorer
from app.discovery.state import StateManager
from app.db.db_models import Subdomain, SubdomainState
from app.takeover.subdomain_hunter.potential import PotentialTakeoverDetector
from app.takeover.subdomain_hunter.providers_evaluator import ProvidersEvaluator, _build_evidence


def _registered_domain(hostname: str) -> str:
    """
    Return the registered domain (eTLD+1) of *hostname*.

    Examples
    --------
    >>> _registered_domain("redirects.yelp.com")
    'yelp.com'
    >>> _registered_domain("foo.bar.netlify.app")
    'netlify.app'
    """
    hostname = hostname.rstrip(".").lower()
    parts = hostname.split(".")

    TWO_PART_TLDS = {
        "co.uk", "co.jp", "co.nz", "co.za", "co.in", "co.kr",
        "com.au", "com.br", "com.cn", "com.mx", "com.ar",
        "net.au", "org.au", "gov.au", "edu.au",
        "ac.uk", "gov.uk", "org.uk", "me.uk",
        "ne.jp", "or.jp", "ac.jp",
    }

    if len(parts) >= 3 and ".".join(parts[-2:]) in TWO_PART_TLDS:
        return ".".join(parts[-3:])

    return ".".join(parts[-2:]) if len(parts) >= 2 else hostname


# States that should not be silently downgraded to ALIVE on a probe timeout.
# POTENTIAL_LONG is ownership-blocked and keeps its cadence; CLAIMED is handled
# by an early terminal return below.
_SENSITIVE_STATES = {
    SubdomainState.POTENTIAL,
    SubdomainState.POTENTIAL_LONG,
    SubdomainState.DANGLING,
}


class TakeoverEvaluator:
    """Evaluate takeover potential based on DNS and HTTP data."""

    def __init__(self):
        self._potential_detector  = PotentialTakeoverDetector()
        self._providers_evaluator = ProvidersEvaluator()

    def _is_internal_cname(self, subdomain_name: str, cname: Optional[str]) -> bool:
        """Return True if the CNAME points back to the same registered domain."""
        if not cname:
            return False
        return _registered_domain(subdomain_name) == _registered_domain(cname)

    async def evaluate(
        self,
        session:   AsyncSession,
        subdomain: Subdomain,
        dns_data:  Optional[Dict[str, Any]],
        http_data: Optional[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """
        Main evaluation entry point.  Combines DNS + HTTP signals into a
        confidence score, persists state, and triggers provider verification.
        """

        # ------------------------------------------------------------------
        # 0. Terminal / no-data guards
        # ------------------------------------------------------------------
        # A validated claim is terminal: never re-verify it and never let a
        # later probe overwrite the CLAIMED state.
        if subdomain.state == SubdomainState.CLAIMED:
            return {
                "confidence": subdomain.confidence or 0,
                "provider":   subdomain.takeover_provider,
                "skipped":    "claimed_terminal",
            }

        if not dns_data and not http_data:
            return {"confidence": 0, "provider": None, "skipped": "no_data"}

        cname    = dns_data.get("cname")    if dns_data else None
        nxdomain = dns_data.get("nxdomain", False) if dns_data else False
        ips      = dns_data.get("ips", [])  if dns_data else []

        # ------------------------------------------------------------------
        # 0a. Probe-empty guard
        #
        # A probe that returned {cname: null, nxdomain: false, ips: []}
        # with no HTTP data looks identical to a DNS timeout.  If the
        # subdomain is already in a sensitive state (POTENTIAL/POTENTIAL_LONG/
        # DANGLING), do NOT downgrade it to ALIVE based on what could be a
        # transient failure.  Log and skip — the next recheck will resolve it.
        # ------------------------------------------------------------------
        is_probe_empty = (
            not cname
            and not nxdomain
            and not ips
            and not http_data
        )
        if is_probe_empty and subdomain.state in _SENSITIVE_STATES:
            logger.info(
                "Probe returned empty for %s (state=%s) — treating as timeout, "
                "preserving state",
                subdomain.name,
                subdomain.state.value,
            )
            return {
                "confidence": subdomain.confidence or 0,
                "provider":   subdomain.takeover_provider,
                "skipped":    "probe_empty",
            }

        # ------------------------------------------------------------------
        # 1. Internal-CNAME filter
        # ------------------------------------------------------------------
        if self._is_internal_cname(subdomain.name, cname):
            await StateManager.update_confidence(session, subdomain, 0)
            session.add(subdomain)
            return {"confidence": 0, "provider": None, "filtered": "internal_cname"}

        # ------------------------------------------------------------------
        # 2. Potential takeover check (alive 2xx + CNAME → claimable provider)
        #
        # This path handles subdomains that are LIVE but structurally at risk.
        # If the service is already dead (NXDOMAIN / non-2xx), evaluate_potential
        # returns is_potential=False and we fall through to the scoring path.
        # ------------------------------------------------------------------
        potential_result = await self._potential_detector.evaluate_potential(
            session, subdomain, dns_data, http_data
        )

        if potential_result["is_potential"]:
            potential_confidence = await self._potential_detector.update_potential_state(
                session, subdomain, potential_result
            )
            session.add(subdomain)
            return {
                "confidence":   potential_confidence,
                "provider":     potential_result["provider"],
                "dns_score":    0,
                "http_score":   0,
                "is_potential": True,
            }

        # ------------------------------------------------------------------
        # 3. DNS + HTTP scoring (NXDOMAIN / non-live subdomains)
        # ------------------------------------------------------------------
        dns_score, dns_provider = ConfidenceScorer.score_dns(
            cname, nxdomain, subdomain.name
        )
        http_score, http_provider = ConfidenceScorer.score_http(
            status_code=http_data.get("status_code") if http_data else None,
            body=http_data.get("body") if http_data else None,
            headers=http_data.get("headers", {}) if http_data else {},
        )

        # ------------------------------------------------------------------
        # Provider + overall resolution
        #
        # NXDOMAIN path:
        #   - NXDOMAIN + no CNAME → score 0, ALIVE.
        #     The subdomain record doesn't exist at all.  There is no dangling
        #     CNAME to exploit.  This is NOT a subdomain takeover scenario.
        #     (score_dns already returns 0 in this case after the confidence.py
        # , but we guard here too for defense-in-depth.)
        #
        #   - NXDOMAIN + CNAME + provider identified → score normally.
        #     A dangling CNAME whose target is NXDOMAIN is the classic takeover
        #     signal.  Provider-specific verification can run.
        #
        #   - NXDOMAIN + CNAME + NO provider match → score 0, ALIVE.
        #     The CNAME target is gone but points to an unknown/unrecognised
        #     provider.  We have no way to confirm the resource is claimable,
        #     so we cannot assert a takeover is possible.  Suppressing here
        #     eliminates ~100% false-positive rate for unrecognised CNAMEs
        #     (e.g. whecloud.com, cloudsmith.io, unknown ELB variants).
        #     If the provider should be tracked, add it to signatures.yaml.
        #
        # CNAME path:
        #   - No CNAME                 → 0, ALIVE
        #   - CNAME, no provider match → 0, ALIVE
        #   - Non-claimable provider   → 0, ALIVE (e.g. CloudFront)
        #   - Claimable provider       → score; HTTP gate only fires when HTTP
        #     actually returned a fingerprint for a DIFFERENT provider.
        #     Timeouts / no-body don't zero out a valid CNAME match.
        # ------------------------------------------------------------------

        if nxdomain:
            # Defense-in-depth: enforce no-CNAME → 0 even if score_dns somehow
            # returned a non-zero score.
            if not cname:
                overall  = 0
                provider = None
            else:
                # Try to identify provider from CNAME for verification step.
                # score_dns() always returns provider=None on the nxdomain path,
                # so we do a second pass with nxdomain=False to get a CNAME match.
                provider = dns_provider  # always None from score_dns nxdomain path
                if provider is None:
                    _, cname_provider = ConfidenceScorer.score_dns(
                        cname, nxdomain=False, subdomain_name=None
                    )
                    provider = cname_provider

                if provider is None:
                    overall = 0
                elif not ConfidenceScorer._sig().claimable.get(provider, True):
                    # NXDOMAIN does not make a non-claimable provider takeable.
                    overall  = 0
                    provider = None
                elif http_provider is not None and http_provider != provider:
                    # A live page served by a different provider contradicts
                    # the dangling CNAME; do not verify the wrong service.
                    overall  = 0
                    provider = None
                else:
                    overall = ConfidenceScorer.compute_overall(
                        dns_score, http_score, False, subdomain.name
                    )

        elif not cname:
            overall  = 0
            provider = None

        elif dns_provider is None:
            overall  = 0
            provider = None

        else:
            sig = ConfidenceScorer._sig()

            if not sig.claimable.get(dns_provider, True):
                # Non-claimable provider (e.g. CloudFront) — always suppress.
                overall  = 0
                provider = None
            elif http_provider is not None and http_provider != dns_provider:
                # The live page fingerprints a different service than the
                # CNAME. That is contradictory evidence, so suppress regardless
                # of whether the CNAME provider has its own HTTP fingerprints.
                # A timeout (http_provider is None) never suppresses.
                overall  = 0
                provider = None
            else:
                overall = ConfidenceScorer.compute_overall(
                    dns_score, http_score, False, subdomain.name
                )
                provider = dns_provider

        # ------------------------------------------------------------------
        # 4. Provider-specific verification + auto-takeover
        # ------------------------------------------------------------------
        overall, filtered, evidence, result_extras, takeover_result = (
            await self._providers_evaluator.verify(
                session, subdomain, provider, cname, overall, dns_data, http_data
            )
        )

        # ------------------------------------------------------------------
        # 5. Persist state
        #
        # Skip update_confidence when providers_evaluator already handled
        # state persistence internally (signalled by filtered being set, e.g.
        # "vercel_needs_txt", "vercel_domain_taken", "github_account_exists",
        # "heroku_app_taken", "heroku_name_reserved", "netlify_site_taken",
        # "aws_s3_bucket_taken", "azure_*_resource_exists",
        # "wix_parent_domain_active", nxdomain_required early-returns).
        #
        # Without this guard, evaluator.py step 5 calls update_confidence(30)
        # AFTER providers_evaluator has already called update_confidence(30)
        # AND transition(POTENTIAL_LONG), causing update_confidence to fire
        # again and overwrite POTENTIAL_LONG → POTENTIAL via the state ladder
        # in StateManager.update_confidence(). This produces triple-transition
        # log spam and leaves the subdomain in POTENTIAL instead of
        # POTENTIAL_LONG, causing it to be rechecked every POTENTIAL_RECHECK_HOURS
        # instead of the slower POTENTIAL_LONG_RECHECK_HOURS cadence.
        # ------------------------------------------------------------------
        if not filtered:
            await StateManager.update_confidence(
                session,
                subdomain,
                overall,
                takeover_provider=provider,
                takeover_evidence=_build_evidence(dns_data, http_data, **evidence),
            )
            session.add(subdomain)

        return {
            "confidence": overall,
            "provider":   provider,
            "dns_score":  dns_score,
            "http_score": http_score,
            "is_potential": False,
            "takeover_result": takeover_result,
            **result_extras,
        }


# ---------------------------------------------------------------------------
# Module-level logger (imported at top in real file — keeping here for clarity)
# ---------------------------------------------------------------------------
from app.core.logging import logger  # noqa: E402