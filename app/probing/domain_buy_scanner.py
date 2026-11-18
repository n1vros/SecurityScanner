"""
Domain availability / buy scanner.

Two-phase design
────────────────
Phase 1 — Registration (called on new domain discovery):
    When a new scope domain is encountered for the first time, call
    `register_domain(session, domain)`.  This runs a single WHOIS lookup and
    stores the expiry date in `domain_availability`.  No polling, no interval.

Phase 2 — Expiry check (called each daemon iteration via `run()`):
    Query the DB for rows where `expires_at <= now`.  For each hit, do a
    lightweight DNS-based availability check (not a full WHOIS re-query) to
    confirm the domain is actually free.  Send a Discord notification if it is.

    If DNS still resolves (domain was renewed / not yet dropped), re-run WHOIS
    to refresh the expiry date so the domain leaves the expired bucket.

This means:
  • WHOIS is only ever run once per domain at discovery time.
  • On expiry, a single DNS check decides: available → notify, resolves →
    re-WHOIS to capture the new expiry so we stop checking it every iteration.
  • Notification de-duplication is handled via `last_notified_at` and
    `DOMAIN_BUY_RENOTIFY_HOURS`.
"""

from __future__ import annotations

import asyncio
import shutil
import socket
import subprocess
import time
from datetime import datetime, timedelta
from typing import Optional, Sequence, Tuple

import whois as pywhois
from sqlalchemy import select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.config import settings
from app.core.logging import logger
from app.db.db_models import DomainAvailability, DomainAvailabilityState, Scope
from app.notify.discord import DiscordNotifier
from whois.exceptions import WhoisDomainNotFoundError
from whois.parser import WhoisEntry

_WHOIS_TLD_LOCKS: dict[str, asyncio.Lock] = {}
_WHOIS_TLD_NEXT_ALLOWED_AT: dict[str, float] = {}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _extract_root_domain(domain: str) -> str:
    """
    Return the registrable root domain from any subdomain or wildcard.

    Examples:
      '*.sub.example.co.uk' -> 'example.co.uk'
      'sub.example.com'     -> 'example.com'
      'example.com'         -> 'example.com'
    """
    domain = domain.lstrip("*").lstrip(".").lower()
    parts  = domain.split(".")
    # Two-part TLD heuristic (.co.uk, .com.br, .org.au ...)
    if len(parts) >= 3 and len(parts[-2]) <= 3:
        return ".".join(parts[-3:])
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return domain


def _run_whois(domain: str) -> Tuple[Optional[datetime], Optional[str], bool, bool, bool]:
    """
    Synchronous WHOIS lookup — run in a thread executor.

    Returns (expiry_date, registrar, is_available, lookup_ok, transient_failure).

    - expiry_date: naive UTC datetime, or None if unknown/privacy proxy.
    - registrar:   registrar string (truncated to 512 chars), or None.
    - is_available: True ONLY when WHOIS positively confirms the domain is
      free — i.e. the WHOIS server explicitly says "available" in the status
      field.  Empty/unparseable responses are treated as lookup failures
      (return False for is_available) — NOT as "domain is free".
    - lookup_ok: True when WHOIS transport+parsing succeeded and the response
      indicates either a registered or an available domain.
    - transient_failure: True when transport succeeded but the registry/server
      temporarily refused the query (e.g. rate limit) or the client timed out.

    Transport uses the native `whois` binary first. This avoids the broken
    python-whois socket client path that relies on resolver behavior which is
    not reliable in this runtime. python-whois is still reused for parsing.

    Expiry date is always returned as a naive UTC datetime (tzinfo stripped)
    so it can be stored in a TIMESTAMP WITHOUT TIME ZONE column.
    """
    def _extract_from_entry(entry: WhoisEntry) -> Tuple[Optional[datetime], Optional[str], bool, bool, bool]:
        # WHOIS server explicitly says the domain is available — the only
        # reliable positive signal.  Empty data / missing fields are NOT
        # treated as available; they mean the lookup failed or the server
        # returned a privacy proxy / minimal response.
        #
        # IMPORTANT: "NOT AVAILABLE" (DNS Belgium .be) and "UNAVAILABLE"
        # both contain the substring "available" — a naive `in` check fires
        # on those and produces false positives.  Explicitly exclude negations.
        import re as _re

        status = entry.status or ""
        if isinstance(status, list):
            status = " ".join(str(s) for s in status)
        status_lower = status.lower().strip()
        is_explicitly_available = (
            _re.search(r"\bavailable\b", status_lower) is not None
            and "not available" not in status_lower
            and "unavailable" not in status_lower
        )
        if is_explicitly_available:
            return None, None, True, True, False

        whois_text = getattr(entry, "text", "") or ""
        exp = entry.expiration_date
        if isinstance(exp, list):
            exp = exp[0]
        if not isinstance(exp, datetime):
            exp = None

        if exp is not None and exp.tzinfo is not None:
            exp = exp.replace(tzinfo=None)

        registrar = str(entry.registrar)[:512] if entry.registrar else None

        has_any_data = any([
            registrar,
            entry.creation_date,
            exp,
            entry.name_servers,
            status.strip(),
            len(whois_text.strip()) > 50,
        ])
        if not has_any_data:
            return None, None, False, False, False

        return exp, registrar, False, True, False

    try:
        whois_binary = shutil.which("whois")
        if whois_binary:
            completed = subprocess.run(
                [whois_binary, domain],
                capture_output=True,
                text=True,
                timeout=15,
            )
            text = completed.stdout or completed.stderr or ""
            text_lower = text.lower().strip()
            if any(
                marker in text_lower
                for marker in (
                    "ratelimit exceeded",
                    "rate limit exceeded",
                    "too many requests",
                    "try again later",
                    "query rate limit exceeded",
                )
            ):
                logger.debug("WHOIS temporary refusal for %s: %s", domain, text.strip())
                return None, None, False, False, True
            try:
                entry = WhoisEntry.load(domain, text)
            except WhoisDomainNotFoundError:
                return None, None, True, True, False
            return _extract_from_entry(entry)

        w = pywhois.whois(
            domain,
            quiet=True,
            ignore_socket_errors=False,
            timeout=10,
        )
        return _extract_from_entry(w)
    except WhoisDomainNotFoundError:
        return None, None, True, True, False
    except subprocess.TimeoutExpired:
        logger.debug("WHOIS command timed out for %s", domain)
        return None, None, False, False, True
    
    except Exception as exc:
        logger.debug("WHOIS lookup failed for %s: %s", domain, exc)
        return None, None, False, False, True


def _whois_refresh_deadline(now: datetime) -> datetime:
    """Fallback recheck time for registries that do not expose expiry dates."""
    return now + timedelta(hours=settings.DOMAIN_BUY_RENOTIFY_HOURS)


async def _run_whois_limited(domain: str) -> Tuple[Optional[datetime], Optional[str], bool, bool, bool]:
    """
    Pace WHOIS lookups per TLD to avoid registry-side throttling.
    """
    tld = domain.rsplit(".", 1)[-1].lower() if "." in domain else domain.lower()
    lock = _WHOIS_TLD_LOCKS.setdefault(tld, asyncio.Lock())
    min_interval = float(getattr(settings, "DOMAIN_BUY_WHOIS_MIN_INTERVAL_SECONDS", 2.0))
    backoff = float(getattr(settings, "DOMAIN_BUY_WHOIS_RATE_LIMIT_BACKOFF_SECONDS", 15.0))

    async with lock:
        wait = _WHOIS_TLD_NEXT_ALLOWED_AT.get(tld, 0.0) - time.monotonic()
        if wait > 0:
            await asyncio.sleep(wait)

        loop = asyncio.get_running_loop()
        result = await loop.run_in_executor(None, _run_whois, domain)
        transient_failure = result[4]
        _WHOIS_TLD_NEXT_ALLOWED_AT[tld] = time.monotonic() + (backoff if transient_failure else min_interval)
        return result


def _is_domain_available(domain: str) -> bool:
    """
    Lightweight availability check: attempt DNS resolution via multiple
    resolvers to avoid false positives when system DNS is broken/proxied.

    Tries 1.1.1.1 (Cloudflare) and 8.8.8.8 (Google) directly via socket
    before falling back to the system resolver.  If ANY resolver says the
    domain resolves, it is treated as still registered.

    PROXY NOTE: socket.getaddrinfo() uses the system resolver which may
    misbehave when a SOCKS5 proxy is active.  Querying public resolvers
    directly bypasses this — if both direct resolvers agree the domain
    does NOT exist, it's a much stronger signal than system-resolver-only.
    """
    import struct

    def _dns_query(nameserver: str, domain: str, timeout: float = 3.0):
        """
        Send a raw DNS A-record query to nameserver:53.

        Returns:
          True  — domain has A records (definitely registered)
          False — NXDOMAIN (domain does not exist)
          None  — timeout / network error / inconclusive

        IMPORTANT: NOERROR with zero answers (ancount=0) means the domain
        EXISTS in DNS but has no A record — it has NS/SOA/MX/etc records.
        This is NOT NXDOMAIN.  Treat it as registered (return True), because
        the domain is clearly in use and buying it is not possible.
        Example: gighouse.app returns NOERROR + SOA, no A record.
        """
        # Build minimal DNS query for A record
        qname = b"".join(
            len(part).to_bytes(1, "big") + part.encode()
            for part in domain.rstrip(".").split(".")
        ) + b"\x00"
        header = struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
        question = qname + struct.pack(">HH", 1, 1)  # QTYPE=A, QCLASS=IN
        query = header + question

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(timeout)
                s.sendto(query, (nameserver, 53))
                data, _ = s.recvfrom(512)
            if len(data) < 12:
                return None
            rcode   = data[3] & 0x0F
            ancount = struct.unpack(">H", data[6:8])[0]
            if rcode == 3:
                return False    # NXDOMAIN — domain genuinely does not exist
            if rcode == 0:
                # NOERROR: domain exists regardless of whether there are A records.
                # ancount=0 + NOERROR = SOA/NS/MX only → domain IS registered.
                return True
            return None         # other rcode (SERVFAIL etc) — inconclusive
        except Exception:
            return None

    # Try public resolvers first — more reliable than system DNS under proxy
    for ns in ("1.1.1.1", "8.8.8.8"):
        result = _dns_query(ns, domain)
        if result is True:
            return False    # resolver confirms domain exists → registered
        if result is False:
            pass            # NXDOMAIN on this resolver — continue to verify
        # None = timeout/error on this resolver, try next

    # Fall back to system resolver as a last check
    try:
        socket.getaddrinfo(domain, None)
        return False        # system resolver says it exists → registered
    except socket.gaierror:
        pass

    # All resolvers agree NXDOMAIN — domain is likely available
    return True


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------

class DomainBuyScanner:
    """
    Coordinates WHOIS registration (phase 1) and expiry-triggered availability
    checking (phase 2).
    """

    def __init__(self) -> None:
        test_webhook = getattr(settings, "DISCORD_WEBHOOK_URL_TEST", None)
        self.notifier = DiscordNotifier(webhook_url=test_webhook or settings.DISCORD_WEBHOOK_URL)

    # ------------------------------------------------------------------
    # Internal: look up program name + platform for a root domain
    # ------------------------------------------------------------------

    async def _lookup_program_info(
        self,
        session: AsyncSession,
        domain: str,
    ) -> Tuple[str, str]:
        """
        Return (program_name, platform) for the given root domain by joining
        Scope → Program.  A single domain may belong to multiple programs
        (e.g. *.example.com and example.com in different programs) — we take
        the first active match.  Falls back to ("unknown", "unknown") if no
        match is found.
        """
        try:
            result = await session.execute(
                select(Scope)
                .options(selectinload(Scope.program))
                .where(
                    Scope.domain.like(f"%{domain}%"),
                    Scope.is_active.is_(True),
                )
                .limit(1)
            )
            scope = result.scalar_one_or_none()
            if scope and scope.program:
                return scope.program.name, scope.program.platform.value
        except Exception as exc:
            logger.debug("domain_buy: program lookup failed for %s: %s", domain, exc)
        return "unknown", "unknown"

    async def _notify_confirmed_buyable(
        self,
        session: AsyncSession,
        record: DomainAvailability,
        now: datetime,
        expires_at: Optional[datetime],
        registrar: Optional[str],
    ) -> None:
        if not self._should_notify(record, now):
            return
        program_name, platform = await self._lookup_program_info(session, record.domain)
        await self.notifier.notify_domain_buyable(
            domain=record.domain,
            expires_at=expires_at,
            registrar=registrar,
            program_name=program_name,
            platform=platform,
        )
        await session.execute(
            update(DomainAvailability)
            .where(DomainAvailability.id == record.id)
            .values(last_notified_at=now)
        )
        await session.commit()

    # ------------------------------------------------------------------
    # Phase 1 — called by passive/active discovery on new scope domain
    # ------------------------------------------------------------------

    async def register_domain(
        self,
        session: AsyncSession,
        raw_domain: str,
    ) -> None:
        """
        Upsert a domain into `domain_availability` and run WHOIS to capture
        the expiry date.  Safe to call multiple times — re-runs WHOIS only if
        the row has no expiry date yet (e.g. first insert or previous failure).

        Call this whenever a new Scope domain is created.
        """
        if not settings.DOMAIN_BUY_SCANNER_ENABLED:
            return

        domain = _extract_root_domain(raw_domain)
        if not domain:
            return

        # Upsert — create row if missing, leave existing rows alone
        insert_stmt = (
            pg_insert(DomainAvailability)
            .values(domain=domain)
            .on_conflict_do_nothing(index_elements=["domain"])
        )
        await session.execute(insert_stmt)
        await session.flush()

        # Fetch the (possibly just-inserted) row
        result = await session.execute(
            select(DomainAvailability).where(DomainAvailability.domain == domain)
        )
        record = result.scalar_one_or_none()
        if record is None:
            return

        # Skip if an expiry date already exists (WHOIS already succeeded).
        if record.expires_at is not None:
            logger.debug(
                "domain_buy: %s already has expiry %s, skipping WHOIS",
                domain,
                record.expires_at.date(),
            )
            return

        # Skip if WHOIS already failed and we're within the retry cooldown.
        # This prevents re-running WHOIS on every startup for UNKNOWN domains.
        # _retry_unknown_domains() handles the scheduled retry with the same gate.
        if record.whois_give_up:
            logger.debug("domain_buy: %s — WHOIS permanently given up, skipping", domain)
            return

        if record.last_checked_at is not None:
            retry_cutoff = datetime.utcnow() - timedelta(hours=settings.DOMAIN_BUY_RENOTIFY_HOURS)
            if record.last_checked_at >= retry_cutoff:
                logger.debug(
                    "domain_buy: %s — WHOIS checked recently (attempt %d/%d), skipping until %s",
                    domain,
                    record.whois_retry_count,
                    settings.DOMAIN_BUY_WHOIS_RETRY_LIMIT,
                    (record.last_checked_at + timedelta(hours=settings.DOMAIN_BUY_RENOTIFY_HOURS))
                    .strftime("%Y-%m-%d %H:%M"),
                )
                return

        logger.info("domain_buy: running WHOIS for newly registered domain %s", domain)
        now = datetime.utcnow()
        expiry, registrar, is_available, lookup_ok, transient_failure = await _run_whois_limited(domain)

        if is_available:
            loop = asyncio.get_event_loop()
            dns_available = await loop.run_in_executor(None, _is_domain_available, domain)
            if dns_available:
                await session.execute(
                    update(DomainAvailability)
                    .where(DomainAvailability.id == record.id)
                    .values(
                        state=DomainAvailabilityState.AVAILABLE,
                        last_checked_at=now,
                        whois_retry_count=0,
                        whois_give_up=False,
                    )
                )
                await session.commit()
                logger.info("domain_buy: %s — confirmed buyable at discovery", domain)
                await self._notify_confirmed_buyable(session, record, now, None, None)
            else:
                await session.execute(
                    update(DomainAvailability)
                    .where(DomainAvailability.id == record.id)
                    .values(
                        state=DomainAvailabilityState.UNKNOWN,
                        last_checked_at=now,
                        whois_retry_count=0,
                        whois_give_up=False,
                    )
                )
                await session.commit()
                logger.warning(
                    "domain_buy: %s — WHOIS says available at discovery but DNS does not; "
                    "suppressing notification",
                    domain,
                )

        elif lookup_ok:
            # Successful WHOIS lookup for a registered domain. Some registries
            # do not expose an expiry date, so fall back to a scheduled refresh.
            expires_at = expiry or _whois_refresh_deadline(now)
            await session.execute(
                update(DomainAvailability)
                .where(DomainAvailability.id == record.id)
                .values(
                    expires_at=expires_at,
                    registrar=registrar,
                    state=DomainAvailabilityState.REGISTERED,
                    last_checked_at=now,
                    whois_retry_count=0,
                    whois_give_up=False,
                )
            )
            await session.commit()
            logger.info(
                "domain_buy: %s registered — expires=%s registrar=%s",
                domain,
                expires_at.date(),
                registrar or "unknown",
            )
        elif transient_failure:
            logger.warning(
                "domain_buy: temporary WHOIS failure for %s; keeping it pending for retry",
                domain,
            )
            await session.execute(
                update(DomainAvailability)
                .where(DomainAvailability.id == record.id)
                .values(
                    state=DomainAvailabilityState.UNKNOWN,
                    last_checked_at=now,
                    whois_give_up=False,
                )
            )
            await session.commit()
        else:
            # Failure — increment retry counter, give up if limit reached
            new_count = record.whois_retry_count + 1
            give_up   = new_count >= settings.DOMAIN_BUY_WHOIS_RETRY_LIMIT
            if give_up:
                logger.info(
                    "domain_buy: giving up on %s after %d failed WHOIS attempts",
                    domain, new_count,
                )
            else:
                logger.warning(
                    "domain_buy: WHOIS failed for %s (attempt %d/%d), will retry in %dh",
                    domain, new_count, settings.DOMAIN_BUY_WHOIS_RETRY_LIMIT,
                    settings.DOMAIN_BUY_RENOTIFY_HOURS,
                )
            await session.execute(
                update(DomainAvailability)
                .where(DomainAvailability.id == record.id)
                .values(
                    state=DomainAvailabilityState.UNKNOWN,
                    last_checked_at=now,
                    whois_retry_count=new_count,
                    whois_give_up=give_up,
                )
            )
            await session.commit()

    # ------------------------------------------------------------------
    # Phase 2 — called each daemon iteration
    # ------------------------------------------------------------------

    async def run(self, session: AsyncSession) -> None:
        """
        Two sub-tasks per iteration:

        1. Retry WHOIS for UNKNOWN domains (expires_at IS NULL) — port 43
           may have been blocked at backfill time. Retried every
           DOMAIN_BUY_RENOTIFY_HOURS so we don't hammer on every iteration.

        2. DNS availability check for domains whose stored expires_at has
           passed — these are the actual buy candidates.
        """
        if not settings.DOMAIN_BUY_SCANNER_ENABLED:
            logger.debug("domain_buy: scanner disabled")
            return

        await self._retry_unknown_domains(session)

        expired = await self._get_expired_domains(session)
        if not expired:
            logger.debug("domain_buy: no domains past expiry date")
            return

        logger.info(
            "domain_buy: %d domain(s) past expiry — checking availability",
            len(expired),
        )
        for record in expired:
            await self._check_and_notify(session, record)

    async def _retry_unknown_domains(self, session: AsyncSession) -> None:
        """
        Re-run WHOIS for domains where expires_at is NULL (WHOIS failed or
        timed out).  Only retried after DOMAIN_BUY_RENOTIFY_HOURS
        to avoid hammering blocked WHOIS servers every iteration.

        After DOMAIN_BUY_WHOIS_RETRY_LIMIT consecutive failures, whois_give_up
        is set to True and the domain is permanently skipped.  If a retry ever
        succeeds, whois_retry_count resets to 0 and whois_give_up to False.
        """
        now          = datetime.utcnow()
        retry_cutoff = now - timedelta(hours=settings.DOMAIN_BUY_RENOTIFY_HOURS)

        stmt = (
            select(DomainAvailability)
            .where(
                DomainAvailability.expires_at.is_(None),
                DomainAvailability.whois_give_up.is_(False),
                DomainAvailability.state == DomainAvailabilityState.UNKNOWN,
                (DomainAvailability.last_checked_at.is_(None) |
                 (DomainAvailability.last_checked_at < retry_cutoff)),
            )
        )
        result  = await session.execute(stmt)
        unknown = result.scalars().all()

        if not unknown:
            logger.debug("domain_buy: no UNKNOWN domains to retry")
            return

        logger.info("domain_buy: retrying WHOIS for %d UNKNOWN domain(s)", len(unknown))

        for record in unknown:
            domain = record.domain
            expiry, registrar, is_available, lookup_ok, transient_failure = await _run_whois_limited(domain)

            if is_available:
                loop = asyncio.get_event_loop()
                dns_available = await loop.run_in_executor(None, _is_domain_available, domain)
                if dns_available:
                    await session.execute(
                        update(DomainAvailability)
                        .where(DomainAvailability.id == record.id)
                        .values(
                            state=DomainAvailabilityState.AVAILABLE,
                            last_checked_at=now,
                            whois_retry_count=0,
                            whois_give_up=False,
                        )
                    )
                    await session.commit()
                    logger.info("domain_buy: %s — WHOIS retry confirmed buyable", domain)
                    await self._notify_confirmed_buyable(session, record, now, None, None)
                else:
                    await session.execute(
                        update(DomainAvailability)
                        .where(DomainAvailability.id == record.id)
                        .values(
                            state=DomainAvailabilityState.UNKNOWN,
                            last_checked_at=now,
                            whois_retry_count=0,
                            whois_give_up=False,
                        )
                    )
                    await session.commit()
                    logger.warning(
                        "domain_buy: %s — WHOIS retry says available but DNS does not; "
                        "suppressing notification",
                        domain,
                    )

            elif lookup_ok:
                # Successful WHOIS lookup for a registered domain. Some
                # registries do not expose an expiry date.
                expires_at = expiry or _whois_refresh_deadline(now)
                logger.info(
                    "domain_buy: WHOIS retry succeeded for %s — expires=%s (was %d failure(s))",
                    record.domain, expires_at.date(), record.whois_retry_count,
                )
                await session.execute(
                    update(DomainAvailability)
                    .where(DomainAvailability.id == record.id)
                    .values(
                        expires_at=expires_at,
                        registrar=registrar,
                        state=DomainAvailabilityState.REGISTERED,
                        last_checked_at=now,
                        whois_retry_count=0,
                        whois_give_up=False,
                    )
                )
            elif transient_failure:
                logger.warning(
                    "domain_buy: temporary WHOIS failure for %s; leaving UNKNOWN for retry",
                    record.domain,
                )
                await session.execute(
                    update(DomainAvailability)
                    .where(DomainAvailability.id == record.id)
                    .values(
                        last_checked_at=now,
                        whois_give_up=False,
                    )
                )
            else:
                # Failure — increment counter, give up if limit reached
                new_count = record.whois_retry_count + 1
                give_up   = new_count >= settings.DOMAIN_BUY_WHOIS_RETRY_LIMIT
                if give_up:
                    logger.info(
                        "domain_buy: giving up on %s after %d failed WHOIS attempts",
                        record.domain, new_count,
                    )
                else:
                    logger.debug(
                        "domain_buy: WHOIS still unknown for %s (attempt %d/%d)",
                        record.domain, new_count, settings.DOMAIN_BUY_WHOIS_RETRY_LIMIT,
                    )
                await session.execute(
                    update(DomainAvailability)
                    .where(DomainAvailability.id == record.id)
                    .values(
                        last_checked_at=now,
                        whois_retry_count=new_count,
                        whois_give_up=give_up,
                    )
                )

            await session.commit()

    async def _get_expired_domains(
        self,
        session: AsyncSession,
    ) -> Sequence[DomainAvailability]:
        """Return domains whose expires_at is in the past and not yet confirmed available."""
        now  = datetime.utcnow()
        stmt = (
            select(DomainAvailability)
            .where(
                DomainAvailability.expires_at <= now,
                DomainAvailability.state != DomainAvailabilityState.AVAILABLE,
            )
            .order_by(DomainAvailability.expires_at.asc())
        )
        result = await session.execute(stmt)
        return result.scalars().all()

    async def _check_and_notify(
        self,
        session: AsyncSession,
        record: DomainAvailability,
    ) -> None:
        """
        DNS-check one expired domain and act on the result:

        - Available (NXDOMAIN):
            Mark AVAILABLE, notify via Discord.

        - Still resolves (renewed / not yet dropped):
            Re-run WHOIS to refresh the expiry date.
        """
        domain = record.domain
        now    = datetime.utcnow()

        loop      = asyncio.get_event_loop()
        available = await loop.run_in_executor(None, _is_domain_available, domain)

        if available:
            # DNS says NXDOMAIN — but always confirm with WHOIS before notifying.
            # A SOCKS5 proxy or broken system DNS can cause false-positive NXDOMAIN
            # for perfectly live domains.  WHOIS runs on port 43 directly (not proxied)
            # and is the authoritative check.  If WHOIS fails or says the domain is
            # still registered, we skip the notification entirely.
            logger.info(
                "domain_buy: %s — DNS NXDOMAIN, confirming with WHOIS before notifying",
                domain,
            )
            (
                whois_expiry,
                whois_registrar,
                whois_available,
                whois_lookup_ok,
                _whois_transient_failure,
            ) = await _run_whois_limited(domain)

            if not whois_available and whois_lookup_ok:
                # WHOIS says still registered — DNS is lying (proxy artifact).
                # Refresh expiry if we got one, mark as REGISTERED, do not notify.
                expires_at = whois_expiry or record.expires_at or _whois_refresh_deadline(now)
                logger.warning(
                    "domain_buy: %s — DNS said NXDOMAIN but WHOIS says registered "
                    "(proxy DNS false-positive). Skipping notification.",
                    domain,
                )
                await session.execute(
                    update(DomainAvailability)
                    .where(DomainAvailability.id == record.id)
                    .values(
                        state=DomainAvailabilityState.REGISTERED,
                        expires_at=expires_at,
                        registrar=whois_registrar or record.registrar,
                        last_checked_at=now,
                    )
                )
                await session.commit()
                return

            if not whois_available and not whois_lookup_ok:
                # WHOIS completely failed (port 43 blocked, timeout, etc.) — cannot
                # confirm availability.  Do NOT notify.  Mark UNKNOWN for retry later.
                logger.warning(
                    "domain_buy: %s — DNS NXDOMAIN but WHOIS failed (proxy blocking "
                    "port 43?). Marking UNKNOWN — will retry later.",
                    domain,
                )
                await session.execute(
                    update(DomainAvailability)
                    .where(DomainAvailability.id == record.id)
                    .values(
                        state=DomainAvailabilityState.UNKNOWN,
                        last_checked_at=now,
                    )
                )
                await session.commit()
                return

            # Both DNS (NXDOMAIN) and WHOIS (available) agree — domain is free.
            logger.info("domain_buy: %s — confirmed available by DNS + WHOIS", domain)
            await session.execute(
                update(DomainAvailability)
                .where(DomainAvailability.id == record.id)
                .values(
                    state=DomainAvailabilityState.AVAILABLE,
                    last_checked_at=now,
                )
            )
            await session.commit()
            await self._notify_confirmed_buyable(
                session, record, now, record.expires_at, record.registrar,
            )

        else:
            # Domain still resolves — re-WHOIS to refresh the expiry date
            logger.info(
                "domain_buy: %s still resolves — re-running WHOIS to refresh expiry",
                domain,
            )
            expiry, registrar, is_available, lookup_ok, _transient_failure = await _run_whois_limited(domain)

            if is_available:
                # WHOIS says available but DNS still resolves. This is not a
                # reliable buyable signal, so keep it UNKNOWN for later retry.
                await session.execute(
                    update(DomainAvailability)
                    .where(DomainAvailability.id == record.id)
                    .values(
                        state=DomainAvailabilityState.UNKNOWN,
                        expires_at=None,
                        last_checked_at=now,
                    )
                )
                await session.commit()
                logger.warning(
                    "domain_buy: %s — WHOIS says available but DNS still resolves; "
                    "suppressing notify until both checks agree",
                    domain,
                )

            elif lookup_ok and expiry is not None and expiry > now:
                # Domain was renewed — update expiry so it leaves the expired bucket
                logger.info(
                    "domain_buy: %s renewed — new expiry=%s", domain, expiry.date()
                )
                await session.execute(
                    update(DomainAvailability)
                    .where(DomainAvailability.id == record.id)
                    .values(
                        expires_at=expiry,
                        registrar=registrar,
                        state=DomainAvailabilityState.REGISTERED,
                        last_checked_at=now,
                    )
                )
                await session.commit()

            elif lookup_ok and expiry is not None:
                # WHOIS returned an expiry still in the past — domain in redemption /
                # pending-delete. Bump expires_at forward by DOMAIN_BUY_RENOTIFY_HOURS
                # so the domain leaves _get_expired_domains() until the next check window.
                # Without this, every daemon iteration re-runs DNS + WHOIS on every
                # redemption domain indefinitely, hammering WHOIS servers.
                next_check = now + timedelta(hours=settings.DOMAIN_BUY_RENOTIFY_HOURS)
                logger.info(
                    "domain_buy: %s — in redemption/pending-delete, WHOIS expiry=%s "
                    "— deferring next check to %s",
                    domain, expiry.date(), next_check.strftime("%Y-%m-%d %H:%M"),
                )
                await session.execute(
                    update(DomainAvailability)
                    .where(DomainAvailability.id == record.id)
                    .values(
                        state=DomainAvailabilityState.REGISTERED,
                        expires_at=next_check,
                        last_checked_at=now,
                    )
                )
                await session.commit()

            elif lookup_ok:
                # WHOIS confirms the domain is registered, but this registry does
                # not expose an expiry date. Defer re-check on the normal cadence.
                next_check = _whois_refresh_deadline(now)
                logger.info(
                    "domain_buy: %s — WHOIS confirms registered without expiry, "
                    "deferring next check to %s",
                    domain, next_check.strftime("%Y-%m-%d %H:%M"),
                )
                await session.execute(
                    update(DomainAvailability)
                    .where(DomainAvailability.id == record.id)
                    .values(
                        state=DomainAvailabilityState.REGISTERED,
                        expires_at=next_check,
                        registrar=registrar or record.registrar,
                        last_checked_at=now,
                    )
                )
                await session.commit()

            else:
                # WHOIS failed — mark UNKNOWN so _retry_unknown_domains handles
                # it on a schedule (every DOMAIN_BUY_RENOTIFY_HOURS) rather than
                # re-running full WHOIS on every daemon iteration via this path.
                logger.warning(
                    "domain_buy: %s — WHOIS re-check failed, marking UNKNOWN for scheduled retry",
                    domain,
                )
                await session.execute(
                    update(DomainAvailability)
                    .where(DomainAvailability.id == record.id)
                    .values(
                        state=DomainAvailabilityState.UNKNOWN,
                        expires_at=None,   # clear stale expiry so retry path picks it up
                        last_checked_at=now,
                    )
                )
                await session.commit()

    def _should_notify(self, record: DomainAvailability, now: datetime) -> bool:
        """Notify on first discovery; re-notify after DOMAIN_BUY_RENOTIFY_HOURS."""
        if record.last_notified_at is None:
            return True
        renotify_cutoff = now - timedelta(hours=settings.DOMAIN_BUY_RENOTIFY_HOURS)
        return record.last_notified_at < renotify_cutoff
