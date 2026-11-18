"""
Post-attempt validation for auto-claimed subdomains.

A provider reporting ``SUCCESS`` only means its control-plane API accepted the
request; it does not prove the hostname now serves our PoC. DNS propagation,
custom-domain mapping and deployments can all lag or fail. This module fetches
the claimed hostname over HTTPS then HTTP, following redirects conservatively,
and looks for the configured claim marker (``TAKEOVER_CLAIM_MARKER``) in the
body. Only then may the finding be reported as a validated takeover.

The fetch callable is injectable so tests can exercise the parser and retry
loop without touching the network.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Awaitable, Callable, Optional, Tuple

import aiohttp

from app.core.config import settings
from app.core.logging import logger

# Bounded body read: claim pages are tiny, and a claimed host could otherwise
# stream an arbitrarily large response.
_MAX_BODY_BYTES = 256 * 1024

# Redirect chains longer than this are not followed; a claim page is expected
# to serve directly (or from the provider's canonical hostname).
_MAX_REDIRECTS = 3

_USER_AGENT = "Mozilla/5.0 (compatible; STOscanner/1.0)"

# A fetch returns (http_status, body, final_url).
FetchResult = Tuple[int, str, str]
FetchFn = Callable[[str], Awaitable[FetchResult]]
SuccessPredicate = Callable[[int, str], bool]


@dataclass(frozen=True)
class ClaimValidationResult:
    """Outcome of the post-attempt fetch/verify step."""

    verified: bool
    attempts: int = 0
    url: Optional[str] = None
    status_code: Optional[int] = None
    marker: Optional[str] = None
    error: Optional[str] = None
    body_snippet: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "verified": self.verified,
            "attempts": self.attempts,
            "url": self.url,
            "status_code": self.status_code,
            "marker": self.marker,
            "error": self.error,
            "body_snippet": self.body_snippet,
        }


class ClaimValidator:
    """
    Verify that a claimed hostname actually serves our content.

    Each attempt tries HTTPS first and falls back to HTTP. TLS verification is
    disabled on purpose: a freshly-mapped custom domain often has a
    not-yet-provisioned certificate, and the claim marker in the body is the
    signal that matters. Any HTTP status is accepted when the marker is
    present; a negative/404 page that merely echoes the hostname does not
    contain the marker.
    """

    def __init__(
        self,
        marker: Optional[str] = None,
        timeout: Optional[float] = None,
        attempts: Optional[int] = None,
        delay: float = 2.0,
        fetch: Optional[FetchFn] = None,
        success_predicate: Optional[SuccessPredicate] = None,
    ) -> None:
        resolved_marker = settings.TAKEOVER_CLAIM_MARKER if marker is None else marker
        self._marker = (resolved_marker or "").strip()
        self._timeout = float(
            settings.TAKEOVER_CLAIM_VALIDATE_TIMEOUT if timeout is None else timeout
        )
        self._attempts = max(
            1, int(settings.TAKEOVER_CLAIM_VALIDATE_ATTEMPTS if attempts is None else attempts)
        )
        self._delay = max(0.0, float(delay))
        self._fetch = fetch or self._aiohttp_fetch
        self._success_predicate = success_predicate

    async def validate(self, hostname: str) -> ClaimValidationResult:
        """Fetch *hostname* and return whether our claim marker is served."""
        hostname = (hostname or "").strip().rstrip(".").lower()
        if not hostname:
            return ClaimValidationResult(False, error="empty hostname")
        if not self._marker:
            return ClaimValidationResult(
                False,
                error="TAKEOVER_CLAIM_MARKER is empty — cannot validate a claim",
            )

        last_error: Optional[str] = None
        last_url: Optional[str] = None
        last_status: Optional[int] = None
        last_body: Optional[str] = None
        attempts = 0

        for attempt in range(1, self._attempts + 1):
            attempts = attempt
            for scheme in ("https", "http"):
                url = f"{scheme}://{hostname}"
                try:
                    status, body, final_url = await self._fetch(url)
                except asyncio.CancelledError:
                    raise
                except Exception as exc:  # fetch failures are retried, not fatal
                    last_error = f"{url}: {exc}"
                    continue

                last_url = final_url or url
                last_status = status
                last_body = body
                if self._matches(status, body):
                    logger.info(
                        "claim validator: %s serves the claim marker (HTTP %d)",
                        hostname, status,
                    )
                    return ClaimValidationResult(
                        verified=True,
                        attempts=attempt,
                        url=last_url,
                        status_code=status,
                        marker=self._marker,
                        body_snippet=(body or "")[:200],
                    )
                last_error = f"{url}: claim marker not present (HTTP {status})"

            if attempt < self._attempts and self._delay > 0:
                await asyncio.sleep(self._delay)

        logger.warning(
            "claim validator: %s did not serve the claim marker after %d attempt(s): %s",
            hostname, attempts, last_error,
        )
        return ClaimValidationResult(
            verified=False,
            attempts=attempts,
            url=last_url,
            status_code=last_status,
            marker=self._marker,
            error=last_error or "claim marker not found",
            body_snippet=(last_body or "")[:200],
        )

    # ── Internals ─────────────────────────────────────────────────────────────

    def _matches(self, status: int, body: Optional[str]) -> bool:
        if body and self._marker in body:
            return True
        if self._success_predicate is not None:
            try:
                return bool(self._success_predicate(status, body or ""))
            except Exception:
                return False
        return False

    async def _aiohttp_fetch(self, url: str) -> FetchResult:
        connector = aiohttp.TCPConnector(ssl=False)
        async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=self._timeout),
            connector=connector,
            max_redirects=_MAX_REDIRECTS,
        ) as client:
            async with client.get(
                url,
                allow_redirects=True,
                headers={"User-Agent": _USER_AGENT},
            ) as resp:
                raw = await resp.content.read(_MAX_BODY_BYTES)
                body = raw.decode("utf-8", errors="replace")
                return resp.status, body, str(resp.url)
