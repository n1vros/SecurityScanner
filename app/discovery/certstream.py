"""
app/discovery/certstream.py

Real-time Certificate Transparency log monitoring via certstream.

Connects to wss://certstream.calidog.io (or configurable URL) and receives
a live stream of newly issued TLS certificates. For each cert, extracts all
SANs (Subject Alternative Names) and checks if any match a scope we're
tracking. Matches are fed immediately into the expedited takeover probe pipeline.

Why this matters for subdomain takeover:
  - Cert issuance = operator is actively configuring a service RIGHT NOW.
    The configuration window is often minutes. Acting immediately beats them.
  - SAN lists often contain legacy/staging names that no longer resolve.
  - "payments-legacy", "old-api", "deprecated-" prefixes = high takeover signal.
  - Zero scan cost: purely passive, we just receive a WebSocket feed.

Three cert-triggered takeover attack windows (handled by _certstream_takeover_probe):

  1. CNAME Race — new cert on `dev-api.target.com` → check CNAME immediately.
     If it points to an unclaimed provider resource (Heroku/Netlify/Vercel/GitHub
     Pages, etc.) that was just set up but not yet claimed, you can beat the
     operator to the "Claim Domain" button. Provider checkers run immediately via
     TakeoverEvaluator rather than waiting for the next scan cycle.

  2. Shadow DNS / Dangling Cloud IP — cert on `legacy-api.target.com` while the
     company migrates infra may expose an old static IP (on-prem or cloud) they
     no longer own. The NS sweep + CIDR index + port scan runs immediately via
     SubdomainNSSweeper rather than waiting for the weekly sweep.

  3. SaaS Verification Race — the company issues a cert but hasn't finished the
     "Add Custom Domain → Verify Ownership" step in the SaaS provider dashboard.
     If the HTTP probe fingerprints an unclaimed provider state (e.g. Vercel
     returns verified=false with a TXT requirement), you can add the domain to a
     trial account first. TakeoverEvaluator catches this via its provider checkers.

Architecture:
  - Runs as a persistent background task alongside the main daemon loop.
  - Maintains an in-memory cache of known scope domains for O(1) matching.
  - Scope cache refreshes every CERTSTREAM_SCOPE_REFRESH_SECS seconds.
  - New subdomains are upserted via ActiveDiscovery.upsert_subdomains then
    immediately dispatched to the expedited takeover probe pipeline via callback.
  - The callback receives both the new subdomain names AND cert metadata so the
    daemon can log cert-triggered checks distinctly from regular scan cycle ones.

Config (all optional):
  CERTSTREAM_ENABLED                bool  default True
  CERTSTREAM_URL                    str   default "wss://certstream.calidog.io"
  CERTSTREAM_SCOPE_REFRESH_SECS     int   default 300  (refresh scope cache)
  CERTSTREAM_RECONNECT_SECS         int   default 5    (reconnect delay on disconnect)
  CERTSTREAM_SKIP_WILDCARDS         bool  default True  (skip *.example.com SANs)
  CERTSTREAM_TAKEOVER_CHECK_ENABLED bool  default True
                                          False = only discover, no expedited takeover probe
                                          True  = full pipeline (DNS+HTTP+TakeoverEvaluator+
                                                  NS sweep) fires immediately on cert hit

PROXY NOTE: certstream intentionally does NOT use HTTP_PROXY.
  Certstream is a purely passive public CT log feed — no scan target ever
  sees your IP from this connection. Routing WebSocket through SOCKS5 causes
  persistent "Server disconnected" errors with most proxy setups.
  Direct connection from home IP is safe and correct here.
"""

import asyncio
import json
import time
from typing import Callable, Dict, List, Optional, Set

import aiohttp
from sqlalchemy import select

from app.core.config import settings
from app.core.logging import logger
from app.db.db_models import Scope
from app.db.session import get_session
from app.discovery.active import ActiveDiscovery


# ---------------------------------------------------------------------------
# DiscoverySource value for CT log finds
# ---------------------------------------------------------------------------
_CT_SOURCE = "certstream"


class CertstreamMonitor:
    """
    Persistent WebSocket client for the certstream CT log feed.

    Intended to be started once in Daemon.run() as a background task.
    Runs forever until cancelled (Ctrl+C / SIGTERM).

    When a cert is issued for a domain in our scope, the probe_callback is
    invoked with:
        probe_callback(
            subdomain_names: list[str],   # newly discovered subdomains
            scope_domain:    str,         # scope root they belong to
            cert_all_domains: list[str],  # ALL SANs on the cert (context)
            is_cert_triggered: bool,      # always True from this class
        )

    The daemon's _certstream_takeover_probe uses is_cert_triggered=True to
    run the expedited pipeline (DNS+HTTP+TakeoverEvaluator+NS sweep) instead
    of the normal queued scan.
    """

    def __init__(self, probe_callback: Optional[Callable] = None) -> None:
        """
        Args:
            probe_callback: async callable(
                                subdomain_names:  list[str],
                                scope_domain:     str,
                                cert_all_domains: list[str],
                                is_cert_triggered: bool,
                            )
                            Called after new subdomains are upserted.  Passing
                            cert_all_domains lets the daemon log all SANs on the
                            certificate for context when investigating a hit.
                            If None, subdomains are upserted but not immediately
                            probed (picked up by the next normal scan cycle).
        """
        self._url             = getattr(settings, "CERTSTREAM_URL", "wss://certstream.calidog.io")
        self._scope_refresh   = getattr(settings, "CERTSTREAM_SCOPE_REFRESH_SECS", 300)
        self._reconnect_delay = getattr(settings, "CERTSTREAM_RECONNECT_SECS", 5)
        self._skip_wildcards  = getattr(settings, "CERTSTREAM_SKIP_WILDCARDS", True)
        self._takeover_check  = getattr(settings, "CERTSTREAM_TAKEOVER_CHECK_ENABLED", True)
        self._probe_callback  = probe_callback

        # normalized_key -> original_scope_domain, refreshed periodically.
        # Keys are stripped of wildcard prefixes so "*.example.com" and
        # "example.com" both match as "example.com".
        self._scope_cache: Dict[str, str] = {}
        self._cache_loaded_at: float = 0.0

    # ── Public API ─────────────────────────────────────────────────────────

    async def run(self) -> None:
        """Main loop — connect, consume, reconnect on error. Runs until cancelled."""
        if not getattr(settings, "CERTSTREAM_ENABLED", True):
            logger.info("certstream: disabled via CERTSTREAM_ENABLED=false")
            return

        takeover_mode = (
            "takeover-probe" if self._takeover_check else "discovery-only"
        )
        logger.info(
            "certstream: starting monitor on %s (mode=%s)",
            self._url, takeover_mode,
        )

        while True:
            try:
                await self._connect_and_consume()
            except asyncio.CancelledError:
                logger.info("certstream: monitor cancelled")
                return
            except Exception as e:
                logger.warning(
                    "certstream: connection error (%s), reconnecting in %ds",
                    e, self._reconnect_delay,
                )
                try:
                    await asyncio.sleep(self._reconnect_delay)
                except asyncio.CancelledError:
                    return

    # ── WebSocket consumer ─────────────────────────────────────────────────

    async def _connect_and_consume(self) -> None:
        """Open WebSocket and process messages until disconnected.

        NO PROXY — certstream is a passive public CT log feed. No scan target
        ever sees the home IP from this connection. Routing WebSocket through
        SOCKS5 causes persistent "Server disconnected" errors.
        """
        timeout = aiohttp.ClientTimeout(total=None, sock_connect=15, sock_read=30)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.ws_connect(
                self._url,
                heartbeat=20,
                max_msg_size=0,
                # proxy intentionally omitted — direct connection only
            ) as ws:
                logger.info("certstream: connected to %s", self._url)
                async for msg in ws:
                    if msg.type == aiohttp.WSMsgType.TEXT:
                        await self._handle_message(msg.data)
                    elif msg.type == aiohttp.WSMsgType.ERROR:
                        raise ConnectionError(f"WebSocket error: {ws.exception()}")
                    elif msg.type == aiohttp.WSMsgType.CLOSED:
                        raise ConnectionError("WebSocket closed by server")

    async def _handle_message(self, raw: str) -> None:
        """Parse one certstream message and process any matching SANs."""
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            return

        if data.get("message_type") != "certificate_update":
            return

        leaf = data.get("data", {}).get("leaf_cert", {})
        all_domains: list = leaf.get("all_domains", [])
        if not all_domains:
            return

        await self._process_domains(all_domains)

    # ── Domain processing ──────────────────────────────────────────────────

    async def _process_domains(self, domains: list[str]) -> None:
        """
        Check each SAN against known scopes, upsert matches, and invoke the
        probe callback with full cert context.

        cert_all_domains is passed to the callback so the daemon can log all
        SANs on the triggering certificate — useful when investigating a hit to
        understand what else the operator was configuring at the same time.
        """
        await self._maybe_refresh_scope_cache()

        if not self._scope_cache:
            return

        matches: Dict[str, list[str]] = {}

        for raw in domains:
            domain = raw.strip().lower()

            if not domain:
                continue

            if domain.startswith("*."):
                if self._skip_wildcards:
                    continue
                domain = domain[2:]

            scope_domain = self._find_scope(domain)
            if not scope_domain:
                continue

            matches.setdefault(scope_domain, []).append(domain)

        if not matches:
            return

        # Clean domain list for cert context (deduplicated, wildcards stripped)
        cert_domains_clean = list({
            d[2:] if d.startswith("*.") else d
            for d in domains
            if d.strip()
        })

        for scope_domain, hostnames in matches.items():
            try:
                async with get_session() as session:
                    new_names = await ActiveDiscovery.upsert_subdomains(
                        session, scope_domain, hostnames, source=_CT_SOURCE
                    )

                if new_names:
                    logger.info(
                        "certstream: %d new subdomain(s) for %s: %s  "
                        "[cert also covers: %s]",
                        len(new_names),
                        scope_domain,
                        new_names,
                        ", ".join(cert_domains_clean[:10])
                        + (" ..." if len(cert_domains_clean) > 10 else ""),
                    )
                    if self._probe_callback:
                        await self._probe_callback(
                            new_names,
                            scope_domain,
                            cert_domains_clean,   # full cert SAN context
                            True,                 # is_cert_triggered
                        )

            except asyncio.CancelledError:
                raise
            except Exception as e:
                logger.debug("certstream: upsert error for %s: %s", scope_domain, e)

    def _find_scope(self, domain: str) -> Optional[str]:
        """
        Return the original scope domain string that owns this subdomain, or None.

        The cache is keyed by normalized (wildcard-stripped) domain names, so
        both "example.com" and "*.example.com" stored in the DB resolve to the
        same lookup key "example.com".  We return the original DB value so that
        upsert_subdomains can locate the correct Scope row.
        """
        if domain in self._scope_cache:
            return self._scope_cache[domain]

        parts = domain.split(".")
        for i in range(1, len(parts)):
            candidate = ".".join(parts[i:])
            if candidate in self._scope_cache:
                return self._scope_cache[candidate]

        return None

    # ── Scope cache ────────────────────────────────────────────────────────

    async def _maybe_refresh_scope_cache(self) -> None:
        """Reload scope domains from DB if cache is stale."""
        now = time.monotonic()
        if now - self._cache_loaded_at < self._scope_refresh:
            return

        try:
            async with get_session() as session:
                result = await session.execute(
                    select(Scope.domain, Scope.id).where(Scope.is_active == True)  # noqa: E712
                )
                new_cache: Dict[str, str] = {}
                for row in result:
                    original = row.domain
                    # Strip wildcard prefix for lookup key: "*.example.com" -> "example.com"
                    # This lets certstream SANs match scopes stored as either form.
                    is_wildcard = original.startswith("*.")
                    normalized = original[2:] if is_wildcard else original
                    if not normalized:
                        continue
                    # Prefer the non-wildcard version when both exist for the same root,
                    # so upsert_subdomains gets a domain it can find in the Scope table.
                    if normalized not in new_cache or not new_cache[normalized].startswith("*."):
                        new_cache[normalized] = original
                self._scope_cache = new_cache
                self._cache_loaded_at = now
                logger.debug(
                    "certstream: scope cache refreshed — %d domains",
                    len(self._scope_cache),
                )
        except asyncio.CancelledError:
            raise
        except Exception as e:
            logger.warning("certstream: scope cache refresh failed: %s", e)