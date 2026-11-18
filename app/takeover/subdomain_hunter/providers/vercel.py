"""
Vercel takeover verification module.

When the evaluator detects a dangling CNAME pointing at cname.vercel-dns.com,
this module attempts to register the subdomain on a single persistent Vercel
project via the API.  A successful add_domain call both confirms the subdomain
is genuinely claimable AND completes the takeover in one step — Vercel routes
by Host header, so the subdomain immediately serves the project's claim page.

Flow
----
evaluator detects provider=vercel, confidence >= threshold
    └─> VercelTakeoverChecker.verify(subdomain_name)
            ├─> POST /v10/projects/{VERCEL_PROJECT_ID}/domains
            ├─> interpret response code + error body
            └─> return VercelVerifyResult

One persistent project handles all takeovers:
  - project:    pre-created manually, claim page deployed once
  - per-check:  single API call to add the domain — no project creation,
                no re-deployment, no dashboard clutter

Required .env keys
------------------
  VERCEL_TOKEN      — API token with domain:write access on the project
  VERCEL_PROJECT_ID — ID of the persistent takeover project
"""

import asyncio
import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, Dict, Any

import aiohttp

from app.core.config import settings
from app.core.logging import logger


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

VERCEL_API_BASE = "https://api.vercel.com"

_ERR_TAKEN        = "domain_already_in_use"
_ERR_FORBIDDEN    = "forbidden"
_ERR_INVALID      = "invalid_domain"
_ERR_NEEDS_VERIFY = "domain_not_verified"

_REQUEST_TIMEOUT = 15  # seconds


# ---------------------------------------------------------------------------
# Result dataclass
# ---------------------------------------------------------------------------

class VercelVerifyStatus(str, Enum):
    VERIFIED      = "verified"       # domain claimed, takeover active
    TAKEN         = "taken"          # legitimately owned by target — suppress finding
    NEEDS_TXT     = "needs_txt"      # in another Vercel acct — claimable via TXT record
    MISCONFIGURED = "misconfigured"  # Vercel rejected domain
    UNAVAILABLE   = "unavailable"    # API unreachable / not configured


@dataclass
class VercelVerifyResult:
    status: VercelVerifyStatus
    subdomain: str
    # Applied on top of the existing heuristic confidence score.
    # Positive = finding strengthened; negative = finding weakened / suppressed.
    confidence_delta: int = 0
    evidence: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None

    @property
    def is_verified(self) -> bool:
        return self.status == VercelVerifyStatus.VERIFIED

    def to_dict(self) -> Dict[str, Any]:
        return {
            "vercel_verify_status": self.status.value,
            "subdomain": self.subdomain,
            "confidence_delta": self.confidence_delta,
            "evidence": self.evidence,
            "error": self.error,
        }


# ---------------------------------------------------------------------------
# Checker
# ---------------------------------------------------------------------------

class VercelTakeoverChecker:
    """
    Verify whether a Vercel-hosted subdomain is takeable via the Vercel API.

    Uses a single persistent project (VERCEL_PROJECT_ID) that already has the
    claim page deployed.  Each check is a single POST to add the domain — if
    Vercel accepts it the subdomain is immediately live and serving the claim
    page via the existing deployment.

    Instantiated once inside TakeoverEvaluator; no per-check state.
    """

    def __init__(self) -> None:
        self._token:      Optional[str] = settings.VERCEL_TOKEN
        self._project_id: Optional[str] = settings.VERCEL_PROJECT_ID
        self._configured: bool          = bool(self._token and self._project_id)

        if not self._token:
            logger.warning(
                "VercelTakeoverChecker: VERCEL_TOKEN not set in .env — "
                "API verification disabled, heuristic score used as-is",
            )
        elif not self._project_id:
            logger.warning(
                "VercelTakeoverChecker: VERCEL_PROJECT_ID not set in .env — "
                "API verification disabled, heuristic score used as-is",
            )

    # ── Public API ────────────────────────────────────────────────────────────

    async def verify(self, subdomain_name: str) -> VercelVerifyResult:
        """
        Attempt to claim *subdomain_name* on the persistent takeover project.

        Single API call: POST /v10/projects/{VERCEL_PROJECT_ID}/domains
        If Vercel accepts the domain it is immediately live — no separate
        deployment step needed since the project already has the claim page.

        Always returns a VercelVerifyResult — never raises.
        """
        if not self._configured:
            return VercelVerifyResult(
                status=VercelVerifyStatus.UNAVAILABLE,
                subdomain=subdomain_name,
                error="VERCEL_TOKEN or VERCEL_PROJECT_ID not set in .env",
            )

        logger.info("Vercel verify: probing %s", subdomain_name)

        try:
            async with aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=_REQUEST_TIMEOUT),
                headers={
                    "Authorization": f"Bearer {self._token}",
                    "Content-Type":  "application/json",
                },
            ) as session:
                return await self._add_domain(session, subdomain_name)

        except asyncio.TimeoutError:
            logger.warning("Vercel verify: timeout probing %s", subdomain_name)
            return VercelVerifyResult(
                status=VercelVerifyStatus.UNAVAILABLE,
                subdomain=subdomain_name,
                error="Request timed out",
            )
        except aiohttp.ClientError as exc:
            logger.warning("Vercel verify: network error probing %s: %s", subdomain_name, exc)
            return VercelVerifyResult(
                status=VercelVerifyStatus.UNAVAILABLE,
                subdomain=subdomain_name,
                error=f"Network error: {exc}",
            )

    # ── Internal helpers ──────────────────────────────────────────────────────

    async def _add_domain(
        self,
        session: aiohttp.ClientSession,
        subdomain_name: str,
    ) -> VercelVerifyResult:
        """
        POST the subdomain to the persistent project's domain list.

        If Vercel accepts it (200/201) the takeover is immediately active —
        the CNAME already points at cname.vercel-dns.com, Vercel matches the
        Host header to our project, and the pre-deployed claim page is served.
        """
        add_url = f"{VERCEL_API_BASE}/v10/projects/{self._project_id}/domains"

        async with session.post(add_url, json={"name": subdomain_name}) as resp:
            raw_body  = await resp.text()
            http_code = resp.status

        logger.debug(
            "Vercel verify: POST %s → HTTP %d  body=%s",
            add_url, http_code, raw_body[:400],
        )

        try:
            body = json.loads(raw_body)
        except json.JSONDecodeError:
            body = {}

        result = self._interpret(subdomain_name, http_code, body)
        result.evidence["vercel_project_id"] = self._project_id

        if result.status == VercelVerifyStatus.NEEDS_TXT:
            # Domain was added to our project in a pending/unverified state.
            # Remove it now to keep the project clean — it cannot be used until
            # the domain owner completes the TXT transfer, which may never happen.
            await self._remove_domain(session, subdomain_name)
            logger.info(
                "Vercel verify: %s requires TXT transfer — removed from project, "
                "marking POTENTIAL_LONG",
                subdomain_name,
            )

        if result.is_verified:
            result.evidence["claim_url"] = f"https://{subdomain_name}"
            logger.info("Vercel verify: takeover active — %s", subdomain_name)

        return result

    async def _remove_domain(
        self,
        session: aiohttp.ClientSession,
        subdomain_name: str,
    ) -> None:
        """Remove a domain from the persistent project (cleanup after NEEDS_TXT)."""
        remove_url = (
            f"{VERCEL_API_BASE}/v10/projects/{self._project_id}"
            f"/domains/{subdomain_name}"
        )
        try:
            async with session.delete(remove_url) as resp:
                if resp.status not in (200, 204):
                    body = await resp.text()
                    logger.warning(
                        "Vercel verify: failed to remove domain %s from project "
                        "(HTTP %d): %s",
                        subdomain_name, resp.status, body[:200],
                    )
                else:
                    logger.debug(
                        "Vercel verify: removed pending domain %s from project",
                        subdomain_name,
                    )
        except Exception as exc:
            logger.warning(
                "Vercel verify: error removing domain %s: %s", subdomain_name, exc
            )

    def _interpret(
        self,
        subdomain_name: str,
        http_code: int,
        body: Dict[str, Any],
    ) -> VercelVerifyResult:
        """
        Translate a Vercel add-domain response into a VercelVerifyResult.

        Vercel v10 POST /projects/{id}/domains response matrix:

          200/201  name == subdomain   verified=true                VERIFIED      (+10)
          200/201  name == subdomain   verified=false, no verif[]   VERIFIED      (+10)  DNS pending only
          200/201  name == subdomain   verified=false, verif[]      NEEDS_TXT     ( 0)   disputed domain
          409      domain_already_in_use  WITH verification[]       NEEDS_TXT     ( 0)   in another account
          409      domain_already_in_use  WITHOUT verification[]    TAKEN         (-40)  legitimately owned
          400      invalid_domain                                    MISCONFIGURED (-20)
          400      domain_not_verified                               MISCONFIGURED (-20)
          403      forbidden                                         UNAVAILABLE   (  0)
          429      rate-limit                                        UNAVAILABLE   (  0)
          other                                                      UNAVAILABLE   (  0)
        """
        evidence = {"http_status": http_code, "response_body": body}

        error_obj  = body.get("error", {})
        error_code = (
            error_obj.get("code", "") if isinstance(error_obj, dict) else str(error_obj)
        )

        if http_code in (200, 201) and body.get("name") == subdomain_name:
            is_dns_verified = body.get("verified", False)
            verification    = body.get("verification") or []

            # verified=false WITH a verification array means Vercel accepted
            # the domain into our project but it is disputed — another Vercel project
            # already owns it. Vercel will NOT route traffic until TXT ownership is
            # proven. This is identical to the 409 NEEDS_TXT case, just surfaced on
            # a 200 response, so it must not be treated as verified.
            if not is_dns_verified and verification:
                txt_records = [
                    {"type": v.get("type"), "domain": v.get("domain"), "value": v.get("value")}
                    for v in verification
                    if isinstance(v, dict)
                ]
                evidence["vercel_txt_required"] = txt_records
                evidence["vercel_dns_verified"]  = False
                evidence["vercel_note"] = (
                    "Domain accepted by Vercel (HTTP 200) but verified=false with a "
                    "verification array — domain is disputed between Vercel projects. "
                    "Vercel will NOT route traffic until TXT ownership is proven. "
                    "Add the TXT record in vercel_txt_required to claim it. "
                    "Manual DNS step required — this is NOT a live takeover yet."
                )
                logger.info(
                    "Vercel verify: %s accepted (200) but needs TXT transfer "
                    "(verified=false + verification array) — NOT a live takeover",
                    subdomain_name,
                )
                return VercelVerifyResult(
                    status=VercelVerifyStatus.NEEDS_TXT,
                    subdomain=subdomain_name,
                    confidence_delta=0,  # keep existing confidence — finding is still valid
                    evidence=evidence,
                )

            # verified=false WITHOUT verification array = Vercel's internal DNS
            # propagation check is still pending. The CNAME already resolves to
            # cname.vercel-dns.com and Vercel IS routing by Host header — takeover
            # is live. This is the normal post-add state before Vercel confirms DNS.
            evidence["vercel_dns_verified"] = is_dns_verified
            if not is_dns_verified:
                evidence["vercel_note"] = (
                    "Domain accepted by Vercel project. verified=false means Vercel's "
                    "internal DNS check is pending — takeover is still active via CNAME routing."
                )
            logger.info(
                "Vercel verify: CONFIRMED claimable — %s accepted by Vercel API (dns_verified=%s)",
                subdomain_name, is_dns_verified,
            )
            return VercelVerifyResult(
                status=VercelVerifyStatus.VERIFIED,
                subdomain=subdomain_name,
                confidence_delta=+10,
                evidence=evidence,
            )

        if http_code == 409 or error_code == _ERR_TAKEN:
            # Vercel returns 409 in two distinct cases:
            #
            # Case A — domain_already_in_use WITH verification array:
            #   The domain is in ANOTHER Vercel account but the CNAME still dangles.
            #   Vercel requires a TXT record (_vercel.<apex>) to transfer ownership.
            #   This is still a valid takeover — it just needs manual DNS verification.
            #   Confidence kept high, labelled NEEDS_TXT so Discord alert fires.
            #
            # Case B — domain_already_in_use WITHOUT verification array:
            #   Domain is legitimately owned and actively used. Suppress.
            #
            verification = body.get("verification") or []
            if verification:
                # Extract the TXT record details Vercel requires
                txt_records = [
                    {"type": v.get("type"), "domain": v.get("domain"), "value": v.get("value")}
                    for v in verification
                    if isinstance(v, dict)
                ]
                evidence["vercel_txt_required"] = txt_records
                evidence["vercel_note"] = (
                    "Domain is in another Vercel account. "
                    "Add the TXT record shown in vercel_txt_required to claim it. "
                    "Manual DNS step required — automated takeover blocked by Vercel."
                )
                logger.info(
                    "Vercel verify: %s needs TXT ownership transfer — still claimable manually",
                    subdomain_name,
                )
                return VercelVerifyResult(
                    status=VercelVerifyStatus.NEEDS_TXT,
                    subdomain=subdomain_name,
                    confidence_delta=0,   # keep existing confidence — finding is still valid
                    evidence=evidence,
                )
            else:
                logger.info("Vercel verify: %s already in use (legitimately) — suppressing", subdomain_name)
                return VercelVerifyResult(
                    status=VercelVerifyStatus.TAKEN,
                    subdomain=subdomain_name,
                    confidence_delta=-40,
                    evidence=evidence,
                )

        if error_code in (_ERR_INVALID, _ERR_NEEDS_VERIFY):
            logger.info("Vercel verify: %s rejected (%s)", subdomain_name, error_code)
            return VercelVerifyResult(
                status=VercelVerifyStatus.MISCONFIGURED,
                subdomain=subdomain_name,
                confidence_delta=-20,
                evidence=evidence,
                error=error_code,
            )

        if http_code == 403 or error_code == _ERR_FORBIDDEN:
            logger.warning(
                "Vercel verify: 403 for %s — check VERCEL_TOKEN has domain:write scope "
                "on project %s",
                subdomain_name, self._project_id,
            )
            return VercelVerifyResult(
                status=VercelVerifyStatus.UNAVAILABLE,
                subdomain=subdomain_name,
                error="403 Forbidden — token may lack domain:write scope on the project",
                evidence=evidence,
            )

        if http_code == 429:
            logger.warning("Vercel verify: rate-limited probing %s", subdomain_name)
            return VercelVerifyResult(
                status=VercelVerifyStatus.UNAVAILABLE,
                subdomain=subdomain_name,
                error="Rate-limited by Vercel API (HTTP 429)",
                evidence=evidence,
            )

        logger.warning(
            "Vercel verify: unexpected HTTP %d for %s — treating as UNAVAILABLE",
            http_code, subdomain_name,
        )
        return VercelVerifyResult(
            status=VercelVerifyStatus.UNAVAILABLE,
            subdomain=subdomain_name,
            error=f"Unexpected HTTP {http_code}",
            evidence=evidence,
        )