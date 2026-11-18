"""
app/takeover/providers_evaluator.py

Provider-specific verification + auto-takeover orchestration.

Flow per subdomain
------------------
  1. DNS+HTTP scoring sets provider + confidence (TakeoverEvaluator)
  2. ProvidersEvaluator.verify() is called with those results
  3. For each matched provider:
       a. Run account/resource existence check (fast, no side-effects)
       b. If genuinely vulnerable AND confidence >= DANGLING threshold:
            → attempt auto-takeover (gated by TAKEOVER_AUTO_ENABLED)
       c. A reported SUCCESS is only accepted when the claimed hostname
          serves TAKEOVER_CLAIM_MARKER (ClaimValidator); otherwise it is
          downgraded to FAIL and retried.
       d. Return TakeoverResult with SUCCESS / FAIL / NOT_IMPL / NOT_VULN /
          NEEDS_TXT / UNAVAILABLE
  4. Caller (TakeoverEvaluator) persists state and fires Discord notification
     with the appropriate Takeover: <label>

Attempt guardrails
------------------
  * Parent domains (scope root or registrable apex) are never claimed.
  * Providers that are not claimable in signatures.yaml are never verified.
  * Resource-creating providers only run at/above the DANGLING threshold, so a
    live CNAME that stayed POTENTIAL cannot be claimed accidentally.
  * One in-flight attempt per (subdomain, provider) in this process, plus a
    persisted takeover_retry_at that defers the next cycle.
  * A validated claim transitions to CLAIMED (terminal). NOT_VULN outcomes
    record no retry; transient failures use TAKEOVER_RETRY_HOURS and
    ownership/manual blocks use TAKEOVER_RETRY_DAYS (retry_policy.py).

Automatable providers (attempt takeover)
-----------------------------------------
  vercel    — create project + add domain + deploy
  github    — account existence check only; NOT_IMPL (manual signup required)
  heroku    — existence pre-check + create app + add domain + deploy
  netlify   — existence pre-check + create site + deploy zip
  aws_s3    — create bucket + configure website + upload HTML
  azure     — resource existence check via Azure REST API; CDN/FrontDoor/
              Websites auto-takeover where supported

NOT_IMPL providers (detected, manual required)
-----------------------------------------------
  aws_apigateway — execute-api hostnames are account-bound; HTTP probe +
                   optional SDK check confirm fingerprint; → POTENTIAL_LONG
  azure_blob, azure_cloudapp, azure_trafficmgr (detected but not auto-claimed),
  fastly, ghost_io, surge_sh, readme_io, helpscout, zendesk, bitbucket,
  wordpress, smugmug, strikingly, ucraft, cargo, tilda, webflow

NOT_IMPL confidence cap
-----------------------
  cap=72, DANGLING threshold=60 (see state.py).
  NOT_IMPL findings sit at 60–72, which is:
    - ABOVE the DANGLING threshold → Discord alert fires
    - BELOW verified SUCCESS findings (82+) → visually distinct in Discord
    - Clearly labelled "⚠️ Auto-takeover: N/A" in the embed

NOT_VULN / TAKEN return rule
-----------------------------
  Every code path that confirms a subdomain is NOT vulnerable MUST return 0
  as the overall confidence. evaluator.py persists that value as ALIVE; a
  non-zero return would overwrite the suppression and fire a false DANGLING
  alert.

Azure provider naming
---------------------
  signatures.yaml uses a single "azure" provider entry whose CNAME patterns
  cover all Azure service variants. _AZURE_PROVIDERS therefore includes
  "azure" alongside the per-service names, so those findings route through
  AzureTakeoverChecker instead of falling through to NOT_IMPL.

RATE LIMITING
-------------
  All provider checks that make real external API/HTTP calls are gated behind
  a global 1 req/s token bucket (_provider_check_bucket). This prevents
  bursts of 20+ concurrent potential-recheck tasks from hammering Vercel,
  GitHub, Heroku etc. simultaneously.

  Providers that return immediately without network I/O (NOT_IMPL stubs,
  NXDOMAIN pre-filter) skip the bucket entirely — no point throttling a
  pure in-memory decision.

  Rate is configurable via TAKEOVER_CHECK_RATE_LIMIT (default 1.0 req/s).

POTENTIAL_LONG transitions
--------------------------
  POTENTIAL_LONG is NOT set by StateManager.update_confidence() — it is set
  only here, explicitly, for provider-recheck cases:
    - Vercel NEEDS_TXT:              domain is in another Vercel account;
                                     TXT ownership transfer required.
    - Netlify domain_claimed_elsewhere: custom domain owned by another Netlify
                                     account; provider must release it first.
    - Heroku name_reserved:          app name held by Heroku post-deletion;
                                     may become claimable once hold expires.
    - aws_apigateway NOT_IMPL:       execute-api hostnames are account-bound;
                                     external takeover architecturally impossible;
                                     manual verification / report required.
  These outcomes schedule TAKEOVER_RETRY_DAYS (default 7). All other cases use
  the generic confidence ladder (POTENTIAL / DANGLING).

CLAIMED
-------
  Only a provider SUCCESS whose claim was validated against the live hostname
  transitions the subdomain to CLAIMED. StateManager treats CLAIMED as
  terminal, so no further automatic attempt runs for it.
"""

import asyncio
import json
import time
from datetime import datetime, timedelta
from typing import Any, Dict, Optional, Tuple

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.logging import logger
from app.db.db_models import Subdomain, SubdomainState
from app.takeover.subdomain_hunter.claim_validator import ClaimValidationResult, ClaimValidator
from app.takeover.subdomain_hunter.providers.base import TakeoverResult, TakeoverStatus
from app.takeover.subdomain_hunter.providers.vercel import VercelTakeoverChecker
from app.takeover.subdomain_hunter.providers.github import GitHubTakeoverChecker
from app.takeover.subdomain_hunter.providers.heroku import HerokuTakeoverChecker
from app.takeover.subdomain_hunter.providers.netlify import NetlifyTakeoverChecker
from app.takeover.subdomain_hunter.providers.aws_s3 import AWSS3TakeoverChecker
from app.takeover.ns_hunter.providers.aws_apigateway import AWSAPIGatewayTakeoverChecker
from app.takeover.subdomain_hunter.providers.azure import AzureTakeoverChecker
from app.takeover.subdomain_hunter.providers.stubs import not_impl_result
from app.takeover.subdomain_hunter.retry_policy import (
    TakeoverOutcome,
    classify_outcome,
    compute_retry_at,
)
from app.discovery.state import StateManager
from app.takeover.subdomain_hunter.takeover_loader import SignatureLoader


# NOT_IMPL cap: keeps unverified findings at 60–72.
# Above DANGLING threshold (60) → Discord fires.
# Below verified SUCCESS findings (82+) → visually distinct in embed.
_NOT_IMPL_CONFIDENCE_CAP: int = 72


# ---------------------------------------------------------------------------
# Global provider-check rate limiter — 1 req/s across ALL providers
# ---------------------------------------------------------------------------
# Prevents bursts of concurrent potential-recheck tasks from hammering
# Vercel, GitHub, Heroku, Netlify etc. when many subdomains are rechecked
# in the same daemon iteration.
#
# Uses a simple token bucket: capacity=1, rate=TAKEOVER_CHECK_RATE_LIMIT.
# Only acquired by providers that make real external network calls.
# NOT_IMPL stubs and the NXDOMAIN pre-filter skip it entirely.
# ---------------------------------------------------------------------------

class _ProviderTokenBucket:
    """Simple coroutine-safe token bucket for provider API rate limiting."""

    def __init__(self, rate: float) -> None:
        self._rate        = rate          # tokens per second
        self._tokens      = 1.0           # start full
        self._last_refill = time.monotonic()
        self._lock        = asyncio.Lock()

    async def acquire(self) -> None:
        while True:
            async with self._lock:
                now     = time.monotonic()
                elapsed = now - self._last_refill
                self._tokens = min(1.0, self._tokens + elapsed * self._rate)
                self._last_refill = now
                if self._tokens >= 1.0:
                    self._tokens -= 1.0
                    return
                wait = (1.0 - self._tokens) / self._rate
            await asyncio.sleep(wait)


# Module-level singleton — lazily initialised so it's always created inside
# a running event loop (same pattern as puredns/subfinder semaphores).
_provider_bucket: Optional[_ProviderTokenBucket] = None


def _get_provider_bucket() -> _ProviderTokenBucket:
    global _provider_bucket
    if _provider_bucket is None:
        rate = float(getattr(settings, "TAKEOVER_CHECK_RATE_LIMIT", 1.0))
        _provider_bucket = _ProviderTokenBucket(rate)
        logger.debug(
            "provider rate limiter: initialised at %.1f req/s", rate
        )
    return _provider_bucket


def _provider_verify_cooldown_active(
    subdomain: Subdomain, provider: str, overall: int
) -> bool:
    """
    Skip expensive external provider verification when this exact provider was
    already checked for the same subdomain recently.

    A recorded outcome owns the schedule: when ``takeover_retry_at`` is due the
    caller is running the scheduled retry, so ``last_scanned_at`` (which the
    probe has just advanced) must not suppress it. A finding that has just
    crossed into DANGLING must also reach the provider — otherwise a stale
    cooldown stamp would delay the first real attempt by a whole rescan cycle.
    """
    cooldown_hours = int(getattr(settings, "TAKEOVER_PROVIDER_VERIFY_COOLDOWN_HOURS", 24))
    if cooldown_hours <= 0:
        return False

    if subdomain.takeover_provider != provider:
        return False

    if overall >= StateManager.DANGLING_THRESHOLD and subdomain.state != SubdomainState.DANGLING:
        return False

    retry_at = getattr(subdomain, "takeover_retry_at", None)
    if retry_at is not None:
        # The explicit retry schedule decides (and is re-read under the attempt
        # lock); a scan-cooldown stamp must not mask a due retry.
        return False

    last_scanned_at = getattr(subdomain, "last_scanned_at", None)
    if last_scanned_at is None:
        return False

    return last_scanned_at >= datetime.utcnow() - timedelta(hours=cooldown_hours)


# ---------------------------------------------------------------------------
# Provider sets
# ---------------------------------------------------------------------------

_CNAME_PROVIDERS = {
    "github", "heroku", "netlify", "aws_s3", "aws_apigateway",
    "azure", "azure_frontdoor", "azure_websites", "azure_cdn",
    "azure_blob", "azure_cloudapp", "azure_trafficmgr",
    "fastly", "ghost_io", "surge_sh", "readme_io", "helpscout",
    "zendesk", "bitbucket", "wordpress", "smugmug", "strikingly",
    "ucraft", "cargo", "tilda", "webflow",
    "wix",
}

# Providers handled by NOT_IMPL stubs — no external calls, skip rate limit
_NOT_IMPL_PROVIDERS = {
    "fastly", "ghost_io", "surge_sh", "readme_io", "helpscout",
    "zendesk", "bitbucket", "wordpress", "smugmug", "strikingly",
    "ucraft", "cargo", "tilda", "webflow",
}

# includes "azure" so it routes to AzureTakeoverChecker instead of
# falling through to the NOT_IMPL else-branch.
_AZURE_PROVIDERS = {
    "azure", "azure_frontdoor", "azure_websites",
    "azure_cdn", "azure_blob", "azure_cloudapp", "azure_trafficmgr",
}

# Providers whose check may create/claim a resource. Read-only checks (GitHub
# account lookup, most Azure name availability checks, API Gateway probe, Wix
# parent-domain probe) are intentionally not listed: they stay useful below the
# DANGLING threshold because they cannot mutate anything. Azure is listed
# because the generic "azure" provider may resolve to a Web App that the
# checker creates.
_ATTEMPT_PROVIDERS = {
    "vercel", "heroku", "netlify", "aws_s3",
    "azure", "azure_websites",
}

# Verified claims score above every heuristic path so a claimed finding is
# visibly distinct in notifications (82+ per the confidence ladder).
_CLAIMED_CONFIDENCE: int = 90

# Provider attempts for the same subdomain can be reached from the scope scan,
# a POTENTIAL recheck and a certstream probe concurrently. The lock keeps a
# single in-flight attempt per (subdomain, provider) in this process; the
# persisted takeover_retry_at covers sequential cycles and other processes.
_ATTEMPT_LOCKS: Dict[Tuple[str, str], asyncio.Lock] = {}
_MAX_ATTEMPT_LOCKS = 4096


def _get_attempt_lock(subdomain_name: str, provider: str) -> asyncio.Lock:
    key = (subdomain_name, provider)
    lock = _ATTEMPT_LOCKS.get(key)
    if lock is not None:
        return lock

    if len(_ATTEMPT_LOCKS) >= _MAX_ATTEMPT_LOCKS:
        for old_key, old_lock in list(_ATTEMPT_LOCKS.items()):
            if not old_lock.locked():
                _ATTEMPT_LOCKS.pop(old_key, None)
    lock = asyncio.Lock()
    _ATTEMPT_LOCKS[key] = lock
    return lock


def is_parent_domain(subdomain_name: str, scope_domain: Optional[str] = None) -> bool:
    """
    True when *subdomain_name* is a scope root or the apex of its registrable
    domain. Parent domains are never auto-claimed: the CNAME/HTTP evidence at
    an apex is not sufficient proof that the whole domain is abandonable.
    """
    name = (subdomain_name or "").strip().lower().rstrip(".")
    if not name:
        return True

    if scope_domain:
        parent = scope_domain.strip().lower().rstrip(".")
        if parent and name == parent:
            return True

    # Local import: evaluator.py imports this module, so a top-level import
    # would create a cycle.
    from app.takeover.subdomain_hunter.evaluator import _registered_domain

    return name == _registered_domain(name)


_VERCEL_STATUS_MAP = {
    "verified":     TakeoverStatus.SUCCESS,
    "taken":        TakeoverStatus.NOT_VULN,
    "needs_txt":    TakeoverStatus.NEEDS_TXT,
    "misconfigured": TakeoverStatus.FAIL,
    "unavailable":  TakeoverStatus.UNAVAILABLE,
}


def _vercel_to_takeover_result(result: Any, subdomain_name: str) -> TakeoverResult:
    """Adapt VercelVerifyResult to the unified TakeoverResult contract."""
    evidence = dict(result.evidence or {})
    return TakeoverResult(
        status=_VERCEL_STATUS_MAP.get(result.status.value, TakeoverStatus.UNAVAILABLE),
        provider="vercel",
        subdomain=subdomain_name,
        confidence_delta=result.confidence_delta,
        evidence=evidence,
        claim_url=evidence.get("claim_url"),
        error=result.error,
    )


# ---------------------------------------------------------------------------
# Evidence builder — shared with evaluator.py
# ---------------------------------------------------------------------------

def _build_evidence(
    dns_data:       Optional[Dict[str, Any]],
    http_data:      Optional[Dict[str, Any]],
    takeover:       Optional[Dict[str, Any]] = None,
    **extra,
) -> str:
    evidence: Dict[str, Any] = {
        "dns": {
            "cname":    dns_data.get("cname")    if dns_data else None,
            "nxdomain": dns_data.get("nxdomain") if dns_data else None,
            "ips":      dns_data.get("ips")      if dns_data else None,
        } if dns_data else None,
        "http": {
            "status_code":    http_data.get("status_code")    if http_data else None,
            "content_length": http_data.get("content_length") if http_data else None,
            "url":            http_data.get("url")            if http_data else None,
        } if http_data else None,
    }
    if takeover:
        evidence["takeover"] = takeover
    evidence.update(extra)
    return json.dumps(evidence)


# ---------------------------------------------------------------------------
# ProvidersEvaluator
# ---------------------------------------------------------------------------

class ProvidersEvaluator:
    """
    Runs provider-specific verification and auto-takeover for a matched subdomain.

    Returns (overall, filtered_reason, evidence, result_extras, takeover_result)
    where takeover_result is a TakeoverResult (or None if provider unknown).

    IMPORTANT: Any path that confirms NOT_VULN or TAKEN must return 0 as the
    first element. evaluator.py step 5 calls update_confidence(overall) — if
    overall is non-zero here, it overwrites the update_confidence(0) already
    called inside the provider handler, causing false-positive DANGLING alerts.
    """

    def __init__(self, validator: Optional[ClaimValidator] = None):
        self._vercel  = VercelTakeoverChecker()
        self._github  = GitHubTakeoverChecker()
        self._heroku  = HerokuTakeoverChecker()
        self._netlify = NetlifyTakeoverChecker()
        self._aws_s3          = AWSS3TakeoverChecker()
        self._aws_apigateway  = AWSAPIGatewayTakeoverChecker()
        self._azure           = AzureTakeoverChecker()
        self._validator       = validator or ClaimValidator()

    async def verify(
        self,
        session:   AsyncSession,
        subdomain: Subdomain,
        provider:  Optional[str],
        cname:     Optional[str],
        overall:   int,
        dns_data:  Optional[Dict[str, Any]],
        http_data: Optional[Dict[str, Any]],
    ) -> Tuple[int, Optional[str], Dict[str, Any], Dict[str, Any], Optional[TakeoverResult]]:
        """
        Returns: (overall, filtered_reason, evidence, result_extras, takeover_result)

        ``filtered_reason`` tells the evaluator that state/evidence persistence
        already happened here, so its generic ``update_confidence`` must not run
        and overwrite an explicit POTENTIAL_LONG/CLAIMED transition.
        """
        evidence:        Dict[str, Any]           = {}
        result_extras:   Dict[str, Any]           = {}
        filtered:        Optional[str]            = None
        takeover_result: Optional[TakeoverResult] = None

        if not provider:
            return overall, filtered, evidence, result_extras, None

        loader = SignatureLoader.instance()

        # ── Generic NXDOMAIN pre-filter ────────────────────────────────────────
        # Pure in-memory check — no network call, skip rate limiter.
        #
        # If nxdomain_required=true in signatures.yaml but the CNAME still
        # resolves (nxdomain=false), the resource exists — not vulnerable.
        # Return 0 so evaluator.py step 5 writes 0 → ALIVE. No Discord alert.
        if loader.nxdomain_required.get(provider):
            nxdomain = dns_data.get("nxdomain", False) if dns_data else False
            if not nxdomain:
                logger.info(
                    "nxdomain_required: %s provider=%s CNAME resolves — not vulnerable",
                    subdomain.name, provider,
                )
                not_vuln = TakeoverResult(
                    status=TakeoverStatus.NOT_VULN,
                    provider=provider,
                    subdomain=subdomain.name,
                    confidence_delta=-30,
                    evidence={"reason": "cname_target_resolves_nxdomain_required"},
                    error=f"{provider}: CNAME target resolves — resource still exists, not vulnerable",
                )
                await StateManager.update_confidence(
                    session, subdomain, 0, takeover_provider=None,
                    takeover_evidence=_build_evidence(dns_data, http_data, takeover=not_vuln.to_dict()),
                )
                session.add(subdomain)
                await self._record_outcome(session, subdomain, not_vuln)
                # Return 0 — not overall. evaluator.py step 5 must write 0, not
                # the pre-computed score, otherwise it overwrites this suppression.
                return 0, f"{provider}_cname_resolves", {"takeover": not_vuln.to_dict()}, {"takeover_status": not_vuln.status.value}, not_vuln

        # ── Non-claimable providers ────────────────────────────────────────────
        # A recognised provider whose resource name is not claimable (CDN-style
        # mappings) can never be taken over, so it must not be verified or
        # alerted even when the CNAME is dangling.
        if not loader.claimable.get(provider, True):
            logger.info(
                "non-claimable provider %s for %s — suppressing", provider, subdomain.name,
            )
            await StateManager.update_confidence(
                session, subdomain, 0, takeover_provider=None,
                takeover_evidence=_build_evidence(dns_data, http_data),
            )
            session.add(subdomain)
            return 0, f"{provider}_not_claimable", evidence, result_extras, None

        # ── NOT_IMPL providers — no external calls, skip rate limiter ──────────
        if provider in _NOT_IMPL_PROVIDERS:
            takeover_result = not_impl_result(provider, subdomain.name, cname or "")
            evidence["takeover"] = takeover_result.to_dict()
            result_extras["takeover_status"] = takeover_result.status.value
            overall = min(overall, _NOT_IMPL_CONFIDENCE_CAP)
            await self._record_outcome(session, subdomain, takeover_result)
            return overall, filtered, evidence, result_extras, takeover_result

        if _provider_verify_cooldown_active(subdomain, provider, overall):
            logger.info(
                "provider verify cooldown: skipping %s (%s) for %dh",
                subdomain.name,
                provider,
                int(getattr(settings, "TAKEOVER_PROVIDER_VERIFY_COOLDOWN_HOURS", 24)),
            )
            return overall, f"{provider}_verify_cooldown", evidence, result_extras, None

        # ── Rate limit — all remaining providers make real external API calls ──
        # Throttle to TAKEOVER_CHECK_RATE_LIMIT req/s (default 1/s) so 20+
        # concurrent potential-recheck tasks don't burst-hammer provider APIs.
        await _get_provider_bucket().acquire()
        logger.debug(
            "provider rate limit: acquired token for %s (%s)",
            subdomain.name, provider,
        )

        async with _get_attempt_lock(subdomain.name, provider):
            # Re-read the persisted outcome: a concurrent task (scope scan,
            # certstream probe) may have just scheduled the next attempt.
            await self._refresh_outcome(session, subdomain)

            if subdomain.state == SubdomainState.CLAIMED:
                logger.debug(
                    "provider verify: %s is CLAIMED (terminal) — skipping %s",
                    subdomain.name, provider,
                )
                return overall, f"{provider}_already_claimed", evidence, result_extras, None

            retry_at = getattr(subdomain, "takeover_retry_at", None)
            if retry_at is not None and retry_at > datetime.utcnow():
                logger.info(
                    "provider verify: %s (%s) retry scheduled at %s — skipping",
                    subdomain.name, provider, retry_at,
                )
                return overall, f"{provider}_retry_scheduled", evidence, result_extras, None

            if await self._is_parent_domain(session, subdomain):
                logger.info(
                    "provider verify: %s is a scope/apex parent domain — no automatic takeover",
                    subdomain.name,
                )
                return overall, None, evidence, result_extras, None

            # ── Global automatic-takeover switch ───────────────────────────────
            if (
                provider in _ATTEMPT_PROVIDERS
                and not getattr(settings, "TAKEOVER_AUTO_ENABLED", True)
            ):
                takeover_result = TakeoverResult(
                    status=TakeoverStatus.UNAVAILABLE,
                    provider=provider,
                    subdomain=subdomain.name,
                    evidence={"reason": "takeover_auto_disabled"},
                    error=(
                        "TAKEOVER_AUTO_ENABLED is false — automatic takeover "
                        "disabled; verify and claim manually"
                    ),
                )
                evidence["takeover"] = takeover_result.to_dict()
                result_extras["takeover_status"] = takeover_result.status.value
                overall = min(overall, _NOT_IMPL_CONFIDENCE_CAP)
                await self._record_outcome(session, subdomain, takeover_result)
                return overall, None, evidence, result_extras, takeover_result

            # ── Attempt gate ──────────────────────────────────────────────────
            # Only a finding that reached the DANGLING threshold may create a
            # resource. A CNAME-only match (or an inconclusive probe) stays
            # POTENTIAL and is rechecked instead of claiming a live service.
            if provider in _ATTEMPT_PROVIDERS and overall < StateManager.DANGLING_THRESHOLD:
                logger.info(
                    "provider takeover: %s (%s) score %d < %d — not attempting",
                    subdomain.name, provider, overall, StateManager.DANGLING_THRESHOLD,
                )
                return overall, None, evidence, result_extras, None

            try:
                takeover_result, overall, filtered, evidence, result_extras = await self._dispatch(
                    session, subdomain, provider, cname, overall, dns_data, http_data,
                )
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                logger.error(
                    "provider verification crashed for %s (%s): %s",
                    subdomain.name, provider, exc, exc_info=True,
                )
                takeover_result = TakeoverResult(
                    status=TakeoverStatus.FAIL,
                    provider=provider,
                    subdomain=subdomain.name,
                    error=f"provider verification error: {exc}",
                )
                evidence["takeover"] = takeover_result.to_dict()
                result_extras["takeover_status"] = takeover_result.status.value
                filtered = None

            if takeover_result is not None and takeover_result.status == TakeoverStatus.SUCCESS:
                overall, filtered = await self._accept_or_reject_claim(
                    session, subdomain, provider, takeover_result, overall,
                    dns_data, http_data, evidence, result_extras,
                )

            if takeover_result is not None and takeover_result.status == TakeoverStatus.NOT_IMPL:
                overall = min(overall, _NOT_IMPL_CONFIDENCE_CAP)

            await self._record_outcome(session, subdomain, takeover_result)
            return overall, filtered, evidence, result_extras, takeover_result

    async def _dispatch(
        self,
        session:   AsyncSession,
        subdomain: Subdomain,
        provider:  str,
        cname:     Optional[str],
        overall:   int,
        dns_data:  Optional[Dict[str, Any]],
        http_data: Optional[Dict[str, Any]],
    ) -> Tuple[Optional[TakeoverResult], int, Optional[str], Dict[str, Any], Dict[str, Any]]:
        """Route a matched provider to its checker."""
        evidence:      Dict[str, Any] = {}
        result_extras: Dict[str, Any] = {}
        filtered:      Optional[str]  = None
        takeover_result: Optional[TakeoverResult] = None

        # ── Azure providers (all variants routed through AzureTakeoverChecker)
        if provider in _AZURE_PROVIDERS:
            overall, filtered, evidence, result_extras, takeover_result = \
                await self._do_azure(
                    session, subdomain, provider, cname or subdomain.name,
                    overall, dns_data, http_data,
                )

        # ── Automatable providers
        elif provider == "vercel":
            overall, filtered, evidence, result_extras, takeover_result = \
                await self._do_vercel(session, subdomain, overall, dns_data, http_data)

        elif provider == "github" and cname:
            overall, filtered, evidence, result_extras, takeover_result = \
                await self._do_github(session, subdomain, cname, overall, dns_data, http_data)

        elif provider == "heroku" and cname:
            overall, filtered, evidence, result_extras, takeover_result = \
                await self._do_heroku(session, subdomain, cname, overall, dns_data, http_data)

        elif provider == "netlify" and cname:
            overall, filtered, evidence, result_extras, takeover_result = \
                await self._do_netlify(session, subdomain, cname, overall, dns_data, http_data)

        elif provider == "aws_s3":
            overall, filtered, evidence, result_extras, takeover_result = \
                await self._do_aws_s3(
                    session, subdomain, cname or subdomain.name,
                    overall, dns_data, http_data,
                )

        elif provider == "aws_apigateway" and cname:
            overall, filtered, evidence, result_extras, takeover_result = \
                await self._do_aws_apigateway(
                    session, subdomain, cname,
                    overall, dns_data, http_data,
                )

        elif provider == "wix" and cname:
            overall, filtered, evidence, result_extras, takeover_result = \
                await self._do_wix(session, subdomain, cname, overall, dns_data, http_data)

        else:
            # Provider matched by DNS scoring but no checker — treat as NOT_IMPL
            takeover_result = not_impl_result(provider, subdomain.name, cname or "")
            evidence["takeover"] = takeover_result.to_dict()
            result_extras["takeover_status"] = takeover_result.status.value
            overall = min(overall, _NOT_IMPL_CONFIDENCE_CAP)

        return takeover_result, overall, filtered, evidence, result_extras

    async def _accept_or_reject_claim(
        self,
        session:   AsyncSession,
        subdomain: Subdomain,
        provider:  str,
        result:    TakeoverResult,
        overall:   int,
        dns_data:  Optional[Dict[str, Any]],
        http_data: Optional[Dict[str, Any]],
        evidence:  Dict[str, Any],
        result_extras: Dict[str, Any],
    ) -> Tuple[int, Optional[str]]:
        """
        Validate a SUCCESS claim against the hostname's live response.

        A provider API accepting the domain is not proof that our content is
        served. Only a marker match promotes the finding to CLAIMED; otherwise
        the attempt is downgraded to FAIL so it is retried later and never
        reported as a takeover.
        """
        validation = await self._validate_claim(subdomain.name)
        result.evidence["claim_validation"] = validation.to_dict()

        if validation.verified:
            result.claim_validated = True
            result.claim_url = result.claim_url or f"https://{subdomain.name}"
            overall = max(overall, _CLAIMED_CONFIDENCE)
            await StateManager.update_confidence(
                session, subdomain, overall, takeover_provider=provider,
                takeover_evidence=_build_evidence(
                    dns_data, http_data, takeover=result.to_dict()
                ),
            )
            await StateManager.transition(
                session, subdomain, SubdomainState.CLAIMED,
                reason=f"{provider}: claim validated — hostname serves the claim marker",
            )
            session.add(subdomain)
            evidence["takeover"] = result.to_dict()
            result_extras["takeover_status"] = result.status.value
            logger.info(
                "provider takeover VALIDATED: %s via %s (confidence=%d)",
                subdomain.name, provider, overall,
            )
            return overall, f"{provider}_claim_validated"

        result.status = TakeoverStatus.FAIL
        result.claim_validated = False
        result.evidence["validation_failed"] = True
        result.error = f"claim validation failed: {validation.error or 'marker not served'}"
        evidence["takeover"] = result.to_dict()
        result_extras["takeover_status"] = result.status.value
        logger.warning(
            "provider takeover UNVERIFIED: %s via %s — %s",
            subdomain.name, provider, result.error,
        )
        return overall, None

    async def _validate_claim(self, hostname: str) -> ClaimValidationResult:
        try:
            return await self._validator.validate(hostname)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            logger.error("claim validator error for %s: %s", hostname, exc)
            return ClaimValidationResult(False, error=f"validator error: {exc}")

    async def _record_outcome(
        self,
        session:   AsyncSession,
        subdomain: Subdomain,
        result:    Optional[TakeoverResult],
    ) -> None:
        """Persist the outcome classification and the next retry timestamp."""
        policy = classify_outcome(result)
        if policy is None:
            return
        subdomain.takeover_last_status = policy.status
        subdomain.takeover_retry_at = compute_retry_at(
            policy,
            now=datetime.utcnow(),
            retry_hours=int(getattr(settings, "TAKEOVER_RETRY_HOURS", 24)),
            retry_days=int(getattr(settings, "TAKEOVER_RETRY_DAYS", 7)),
        )
        # A provider that now confirms the resource is owned negates the
        # finding. The generic confidence ladder deliberately preserves
        # POTENTIAL_LONG on rechecks, so clearing it needs this explicit
        # transition; otherwise the row would keep a stale ownership block.
        if (
            policy.outcome is TakeoverOutcome.NOT_VULN
            and subdomain.state == SubdomainState.POTENTIAL_LONG
        ):
            await StateManager.transition(
                session, subdomain, SubdomainState.ALIVE,
                reason="provider confirmed the resource is owned — clearing POTENTIAL_LONG",
            )
        session.add(subdomain)
        logger.debug(
            "takeover outcome: %s -> %s (retry_at=%s)",
            subdomain.name, policy.status, subdomain.takeover_retry_at,
        )

    async def _refresh_outcome(self, session: AsyncSession, subdomain: Subdomain) -> None:
        """Reload attempt bookkeeping so concurrent in-flight work is visible."""
        refresh = getattr(session, "refresh", None)
        if refresh is None:
            return
        try:
            await refresh(
                subdomain,
                attribute_names=["state", "takeover_last_status", "takeover_retry_at"],
            )
        except Exception as exc:
            logger.debug("takeover outcome refresh skipped for %s: %s", subdomain.name, exc)

    async def _is_parent_domain(self, session: AsyncSession, subdomain: Subdomain) -> bool:
        scope_domain: Optional[str] = None
        try:
            scope = subdomain.scope
        except Exception:
            scope = None
        if scope is not None:
            scope_domain = getattr(scope, "domain", None)

        if scope_domain is None:
            scope_id = getattr(subdomain, "scope_id", None)
            getter = getattr(session, "get", None)
            if scope_id is not None and getter is not None:
                try:
                    from app.db.db_models import Scope
                    scope = await getter(Scope, scope_id)
                    scope_domain = getattr(scope, "domain", None) if scope else None
                except Exception:
                    scope_domain = None

        return is_parent_domain(subdomain.name, scope_domain)

    # ── Azure ─────────────────────────────────────────────────────────────────

    async def _do_azure(
        self,
        session:   AsyncSession,
        subdomain: Subdomain,
        provider:  str,
        cname:     str,
        overall:   int,
        dns_data:  Optional[Dict[str, Any]],
        http_data: Optional[Dict[str, Any]],
    ) -> Tuple[int, Optional[str], Dict[str, Any], Dict[str, Any], TakeoverResult]:

        result  = await self._azure.attempt(subdomain.name, cname, provider)
        overall = max(0, min(100, overall + result.confidence_delta))
        ev      = {"takeover": result.to_dict()}
        extras  = {"takeover_status": result.status.value}

        if result.status == TakeoverStatus.NOT_VULN:
            await StateManager.update_confidence(
                session, subdomain, 0, takeover_provider=None,
                takeover_evidence=_build_evidence(dns_data, http_data, takeover=result.to_dict()),
            )
            session.add(subdomain)
            # Return 0 — resource exists, not vulnerable. Returning overall here
            # would let evaluator.py step 5 overwrite the 0 we just persisted.
            return 0, f"azure_{provider}_resource_exists", ev, extras, result

        if result.status == TakeoverStatus.NOT_IMPL:
            overall = min(overall, _NOT_IMPL_CONFIDENCE_CAP)

        return overall, None, ev, extras, result

    # ── Vercel ────────────────────────────────────────────────────────────────

    async def _do_vercel(
        self,
        session:   AsyncSession,
        subdomain: Subdomain,
        overall:   int,
        dns_data:  Optional[Dict[str, Any]],
        http_data: Optional[Dict[str, Any]],
    ) -> Tuple[int, Optional[str], Dict[str, Any], Dict[str, Any], TakeoverResult]:

        vercel_result = await self._vercel.verify(subdomain.name)
        result  = _vercel_to_takeover_result(vercel_result, subdomain.name)
        overall = max(0, min(100, overall + result.confidence_delta))
        ev      = {"takeover": result.to_dict()}
        extras  = {"takeover_status": result.status.value}

        if result.status == TakeoverStatus.NOT_VULN:
            await StateManager.update_confidence(
                session, subdomain, 0, takeover_provider=None,
                takeover_evidence=_build_evidence(dns_data, http_data, takeover=result.to_dict()),
            )
            session.add(subdomain)
            # Return 0 — domain legitimately owned. Returning overall would
            # overwrite the suppression in evaluator.py step 5.
            return 0, "vercel_domain_taken", ev, extras, result

        if result.status == TakeoverStatus.NEEDS_TXT:
            # Domain is in another Vercel account — TXT record transfer required.
            # Persist as POTENTIAL_LONG so it is rechecked on the slower cadence
            # instead of every scan cycle.
            #
            # Do NOT call update_confidence() here — it internally calls
            # transition(POTENTIAL) since confidence=30 >= POTENTIAL_LONG_THRESHOLD.
            # That spurious POTENTIAL transition double-stamps last_state_change_at
            # on every recheck, corrupting the scheduler's recheck timing.
            # Set fields directly, then call transition() exactly once.
            potential_long_confidence = min(overall, StateManager.POTENTIAL_LONG_THRESHOLD)
            subdomain.confidence        = potential_long_confidence
            subdomain.takeover_provider = "vercel"
            subdomain.takeover_evidence = _build_evidence(dns_data, http_data, takeover=result.to_dict())
            await StateManager.transition(
                session, subdomain, SubdomainState.POTENTIAL_LONG,
                reason="Vercel TXT ownership transfer required — provider recheck needed",
            )
            session.add(subdomain)
            logger.info(
                "Vercel verify: %s needs TXT transfer — persisted as POTENTIAL_LONG, "
                "retry in %d days",
                subdomain.name, int(getattr(settings, "TAKEOVER_RETRY_DAYS", 7)),
            )
            return potential_long_confidence, "vercel_needs_txt", ev, extras, result

        return overall, None, ev, extras, result

    # ── GitHub ────────────────────────────────────────────────────────────────

    async def _do_github(
        self,
        session:   AsyncSession,
        subdomain: Subdomain,
        cname:     str,
        overall:   int,
        dns_data:  Optional[Dict[str, Any]],
        http_data: Optional[Dict[str, Any]],
    ) -> Tuple[int, Optional[str], Dict[str, Any], Dict[str, Any], TakeoverResult]:

        result  = await self._github.attempt(subdomain.name, cname)
        overall = max(0, min(100, overall + result.confidence_delta))
        ev      = {"takeover": result.to_dict()}
        extras  = {"takeover_status": result.status.value}

        if result.status == TakeoverStatus.NOT_VULN:
            await StateManager.update_confidence(
                session, subdomain, 0, takeover_provider=None,
                takeover_evidence=_build_evidence(dns_data, http_data, takeover=result.to_dict()),
            )
            session.add(subdomain)
            return 0, "github_account_exists", ev, extras, result

        return overall, None, ev, extras, result

    # ── Heroku ────────────────────────────────────────────────────────────────

    async def _do_heroku(
        self,
        session:   AsyncSession,
        subdomain: Subdomain,
        cname:     str,
        overall:   int,
        dns_data:  Optional[Dict[str, Any]],
        http_data: Optional[Dict[str, Any]],
    ) -> Tuple[int, Optional[str], Dict[str, Any], Dict[str, Any], TakeoverResult]:

        result  = await self._heroku.attempt(subdomain.name, cname)
        overall = max(0, min(100, overall + result.confidence_delta))
        ev      = {"takeover": result.to_dict()}
        extras  = {"takeover_status": result.status.value}

        if result.status == TakeoverStatus.NOT_VULN:
            await StateManager.update_confidence(
                session, subdomain, 0, takeover_provider=None,
                takeover_evidence=_build_evidence(dns_data, http_data, takeover=result.to_dict()),
            )
            session.add(subdomain)
            return 0, "heroku_app_taken", ev, extras, result

        if result.status == TakeoverStatus.NEEDS_TXT:
            # App name is reserved by Heroku (post-deletion hold).
            # Do NOT call update_confidence() here — see Vercel POTENTIAL_LONG
            # comment above for the full explanation. Set fields directly, then
            # call transition() exactly once to avoid double-stamping last_state_change_at.
            potential_long_confidence = min(overall, StateManager.POTENTIAL_LONG_THRESHOLD)
            subdomain.confidence        = potential_long_confidence
            subdomain.takeover_provider = "heroku"
            subdomain.takeover_evidence = _build_evidence(dns_data, http_data, takeover=result.to_dict())
            await StateManager.transition(
                session, subdomain, SubdomainState.POTENTIAL_LONG,
                reason="Heroku app name reserved (post-deletion hold) — recheck when hold expires",
            )
            session.add(subdomain)
            logger.info(
                "heroku: %s app name reserved — POTENTIAL_LONG, retry in %d days",
                subdomain.name, int(getattr(settings, "TAKEOVER_RETRY_DAYS", 7)),
            )
            return potential_long_confidence, "heroku_name_reserved", ev, extras, result

        return overall, None, ev, extras, result

    # ── Netlify ───────────────────────────────────────────────────────────────

    async def _do_netlify(
        self,
        session:   AsyncSession,
        subdomain: Subdomain,
        cname:     str,
        overall:   int,
        dns_data:  Optional[Dict[str, Any]],
        http_data: Optional[Dict[str, Any]],
    ) -> Tuple[int, Optional[str], Dict[str, Any], Dict[str, Any], TakeoverResult]:

        result  = await self._netlify.attempt(subdomain.name, cname)
        overall = max(0, min(100, overall + result.confidence_delta))
        ev      = {"takeover": result.to_dict()}
        extras  = {"takeover_status": result.status.value}

        if result.status == TakeoverStatus.NOT_VULN:
            await StateManager.update_confidence(
                session, subdomain, 0, takeover_provider=None,
                takeover_evidence=_build_evidence(dns_data, http_data, takeover=result.to_dict()),
            )
            session.add(subdomain)
            return 0, "netlify_site_taken", ev, extras, result

        # Custom domain already claimed by another Netlify account.
        # → POTENTIAL_LONG: slower provider retry, no Discord spam.
        if (
            result.status == TakeoverStatus.FAIL
            and result.evidence.get("domain_claimed_elsewhere")
        ):
            # Do NOT call update_confidence() here — see Vercel POTENTIAL_LONG
            # comment above for the full explanation. Set fields directly, then
            # call transition() exactly once to avoid double-stamping last_state_change_at.
            potential_long_confidence = min(overall, StateManager.POTENTIAL_LONG_THRESHOLD)
            subdomain.confidence        = potential_long_confidence
            subdomain.takeover_provider = "netlify"
            subdomain.takeover_evidence = _build_evidence(dns_data, http_data, takeover=result.to_dict())
            # Explicit POTENTIAL_LONG — this is a provider-recheck case only.
            await StateManager.transition(
                session, subdomain, SubdomainState.POTENTIAL_LONG,
                reason="Netlify domain claimed by another account — provider recheck needed",
            )
            session.add(subdomain)
            extras["domain_claimed_elsewhere"] = True
            logger.info(
                "netlify: %s custom domain owned elsewhere — POTENTIAL_LONG, "
                "retry in %d days",
                subdomain.name, int(getattr(settings, "TAKEOVER_RETRY_DAYS", 7)),
            )
            return potential_long_confidence, "netlify_domain_claimed_elsewhere", ev, extras, result

        return overall, None, ev, extras, result

    # ── AWS S3 ────────────────────────────────────────────────────────────────

    async def _do_aws_s3(
        self,
        session:   AsyncSession,
        subdomain: Subdomain,
        cname:     str,
        overall:   int,
        dns_data:  Optional[Dict[str, Any]],
        http_data: Optional[Dict[str, Any]],
    ) -> Tuple[int, Optional[str], Dict[str, Any], Dict[str, Any], TakeoverResult]:

        result  = await self._aws_s3.attempt(subdomain.name, cname)
        overall = max(0, min(100, overall + result.confidence_delta))
        ev      = {"takeover": result.to_dict()}
        extras  = {"takeover_status": result.status.value}

        if result.status == TakeoverStatus.NOT_VULN:
            await StateManager.update_confidence(
                session, subdomain, 0, takeover_provider=None,
                takeover_evidence=_build_evidence(dns_data, http_data, takeover=result.to_dict()),
            )
            session.add(subdomain)
            return 0, "aws_s3_bucket_taken", ev, extras, result

        return overall, None, ev, extras, result

    # ── AWS API Gateway ───────────────────────────────────────────────────────

    async def _do_aws_apigateway(
        self,
        session:   AsyncSession,
        subdomain: Subdomain,
        cname:     str,
        overall:   int,
        dns_data:  Optional[Dict[str, Any]],
        http_data: Optional[Dict[str, Any]],
    ) -> Tuple[int, Optional[str], Dict[str, Any], Dict[str, Any], TakeoverResult]:
        """
        AWS API Gateway handler.

        Auto-takeover is architecturally impossible for execute-api custom-domain
        hostnames: they are account-bound and cannot be re-claimed from an external
        AWS account (unlike S3 bucket names which exist in a global namespace).

        Strategy:
          1. Run the checker (HTTP probe + optional SDK check).
          2. NOT_VULN (domain already in our account) → return 0 / suppress alert.
          3. All other outcomes (NOT_IMPL / FAIL / inconclusive) → cap confidence
             at _NOT_IMPL_CONFIDENCE_CAP and transition to POTENTIAL_LONG so the
             finding is tracked as a persistent manual-verification item.

        POTENTIAL_LONG rationale:
          The 403 Forbidden fingerprint on an execute-api endpoint is a high-signal
          indicator that the API Gateway custom domain mapping has been removed while
          the CNAME remains.  The subdomain is genuinely at-risk but exploitation
          requires either:
            a) Access to the original AWS account to add a new API mapping, or
            b) Social engineering / account takeover of the original owner.
          Re-checking daily is wasteful; POTENTIAL_LONG schedules the slower
          TAKEOVER_RETRY_DAYS cadence and keeps the finding visible.
        """
        result = await self._aws_apigateway.attempt(subdomain.name, cname)
        ev     = {"takeover": result.to_dict()}
        extras = {"takeover_status": result.status.value}

        # ── NOT_VULN: domain already in our account — suppress alert ──────────
        if result.status == TakeoverStatus.NOT_VULN:
            await StateManager.update_confidence(
                session, subdomain, 0, takeover_provider=None,
                takeover_evidence=_build_evidence(dns_data, http_data, takeover=result.to_dict()),
            )
            session.add(subdomain)
            logger.info(
                "aws_apigateway: %s — custom domain in our account → NOT_VULN, score=0",
                subdomain.name,
            )
            return 0, "aws_apigateway_domain_owned_by_us", ev, extras, result

        # ── NOT_IMPL / FAIL / any other status → POTENTIAL_LONG ──────────────
        #
        # Set the fields directly and call transition() exactly once so a
        # later confidence update cannot promote the manual finding past its cap.
        potential_long_confidence = min(overall, _NOT_IMPL_CONFIDENCE_CAP)
        subdomain.confidence = potential_long_confidence

        await StateManager.transition(
            session, subdomain, SubdomainState.POTENTIAL_LONG,
            reason=(
                "AWS API Gateway: execute-api custom-domain endpoint returns "
                "403 Forbidden — API mapping removed but CNAME remains. "
                "External takeover not possible; manual verification required."
            ),
        )
        session.add(subdomain)

        logger.info(
            "aws_apigateway: %s — POTENTIAL_LONG (confidence=%d, "
            "execute-api unclaimed but not externally reclaimable; "
            "retry in %d days)",
            subdomain.name,
            potential_long_confidence,
            int(getattr(settings, "TAKEOVER_RETRY_DAYS", 7)),
        )

        # filtered tells the evaluator this transition is final for the cycle;
        # otherwise its generic update_confidence(>=60) would promote the
        # manual API Gateway finding back to DANGLING.
        return potential_long_confidence, "aws_apigateway_manual", ev, extras, result

    # ── Wix ───────────────────────────────────────────────────────────────────

    async def _do_wix(
        self,
        session:   AsyncSession,
        subdomain: Subdomain,
        cname:     str,
        overall:   int,
        dns_data:  Optional[Dict[str, Any]],
        http_data: Optional[Dict[str, Any]],
    ) -> Tuple[int, Optional[str], Dict[str, Any], Dict[str, Any], TakeoverResult]:
        """
        Wix-specific verification.

        Wix only allows subdomain takeover when the parent (registered) domain
        is NOT already connected to an active Wix site.  If the parent domain
        returns a 2xx response it is actively in use — the subdomain cannot be
        claimed regardless of the dangling CNAME.

        Decision:
          - Parent domain live (2xx)  → NOT_VULN, score=0, state=DEAD.
            Marked DEAD (not just ALIVE) so the daemon never rescans it:
            as long as the parent stays active the vulnerability cannot appear.
          - Parent domain not live    → NOT_IMPL (manual takeover required),
            score capped at NOT_IMPL ceiling.
        """
        parent_live = await self._check_wix_parent_domain(subdomain.name)

        if parent_live:
            # ── Parent domain is active — takeover impossible ─────────────────
            not_vuln = TakeoverResult(
                status=TakeoverStatus.NOT_VULN,
                provider="wix",
                subdomain=subdomain.name,
                confidence_delta=-30,
                evidence={"reason": "wix_parent_domain_active"},
                error="wix: parent domain is connected to an active site — takeover not possible",
            )
            ev     = {"takeover": not_vuln.to_dict()}
            extras = {
                "takeover_status": not_vuln.status.value,
                "wix_parent_live": True,
            }

            await StateManager.update_confidence(
                session, subdomain, 0, takeover_provider=None,
                takeover_evidence=_build_evidence(
                    dns_data, http_data, takeover=not_vuln.to_dict()
                ),
            )
            # Transition to DEAD: as long as the parent domain is live this
            # subdomain can never be taken over via Wix.  Mark it DEAD so the
            # daemon skips it on future scan cycles entirely.
            await StateManager.transition(
                session, subdomain, SubdomainState.DEAD,
                reason="wix: parent domain is active — subdomain takeover not possible, suppressing re-scan",
            )
            session.add(subdomain)
            logger.info(
                "wix: %s — parent domain is live, NOT_VULN → DEAD (will not re-scan)",
                subdomain.name,
            )
            # Return 0 — evaluator.py step 5 must not overwrite the DEAD state
            # transition with a non-zero confidence score.
            return 0, "wix_parent_domain_active", ev, extras, not_vuln

        # ── Parent domain is not live — potential takeover, manual required ───
        result  = not_impl_result("wix", subdomain.name, cname)
        overall = min(overall, _NOT_IMPL_CONFIDENCE_CAP)
        ev      = {"takeover": result.to_dict(), "wix_parent_live": False}
        extras  = {
            "takeover_status": result.status.value,
            "wix_parent_live": False,
        }
        logger.info(
            "wix: %s — parent domain is NOT live, potential takeover (NOT_IMPL, manual required)",
            subdomain.name,
        )
        return overall, None, ev, extras, result

    async def _check_wix_parent_domain(self, subdomain_name: str) -> bool:
        """
        Probe the registered (parent) domain of *subdomain_name* over HTTPS
        then HTTP.  Returns True if any attempt yields a 2xx response,
        indicating the domain is actively connected to a live site.

        The check uses a short 8-second timeout and follows redirects so that
        domains behind a www-redirect (e.g. example.com → www.example.com)
        are correctly identified as live.

        A local import of _registered_domain avoids a circular import:
          evaluator.py  → providers_evaluator.py (normal)
          providers_evaluator.py → evaluator._registered_domain (local, lazy)
        """
        import aiohttp
        # Local import to prevent circular: evaluator imports providers_evaluator
        from app.takeover.subdomain_hunter.evaluator import _registered_domain

        parent = _registered_domain(subdomain_name)

        # Edge case: subdomain IS the apex — nothing meaningful to check.
        if parent == subdomain_name:
            logger.debug(
                "wix parent check: %s is already the apex domain — skipping",
                subdomain_name,
            )
            return False

        for scheme in ("https", "http"):
            url = f"{scheme}://{parent}"
            try:
                async with aiohttp.ClientSession(
                    timeout=aiohttp.ClientTimeout(total=8),
                    connector=aiohttp.TCPConnector(ssl=False),
                ) as client:
                    async with client.get(
                        url,
                        allow_redirects=True,
                        headers={"User-Agent": "Mozilla/5.0 (compatible; STOscanner/1.0)"},
                    ) as resp:
                        if 200 <= resp.status < 300:
                            logger.debug(
                                "wix parent check: %s → %s returned %d (live)",
                                subdomain_name, url, resp.status,
                            )
                            return True
                        logger.debug(
                            "wix parent check: %s → %s returned %d (not 2xx)",
                            subdomain_name, url, resp.status,
                        )
            except Exception as exc:
                logger.debug(
                    "wix parent check: %s → %s failed (%s)",
                    subdomain_name, url, exc,
                )

        return False
