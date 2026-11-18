"""
app/probing/dns_scanner/ns_confirmation.py

Cross-confirmation of NS takeover findings using the trusted resolver pool.

After the bulk random-resolver pool raises a finding, these functions re-run
the same probes against ONLY the trusted confirmation pool (well-known public
resolvers extremely unlikely to give false answers). A configurable minimum
number of confirmation resolvers must agree before an alert fires.

Rate limiting
─────────────
All outgoing queries to the trusted confirmation pool are serialised through
a module-level token bucket that enforces a minimum 0.1 s gap between
consecutive queries.  With NS_SWEEP_CONCURRENCY=100 and only ~16 trusted
resolvers, without this gate all 100 concurrent sweep coroutines would fire
confirmation queries simultaneously, triggering rate-limiting on 1.1.1.1,
8.8.8.8 etc. — causing them to drop packets and making every confirmation
fail with 0/N agreed after a few minutes of runtime.

  10 queries/sec  ×  NS_CONFIRMATION_MIN_AGREE queries per finding
  = safe sustained throughput regardless of sweep concurrency.

Config keys:
  NS_CONFIRMATION_ENABLED    bool   default True
  NS_CONFIRMATION_TIMEOUT    float  default 5.0
  NS_CONFIRMATION_MIN_AGREE  int    default 2
  NS_CONFIRMATION_RESOLVERS  str    comma-separated
"""

import asyncio
import re
import time
from typing import List, Optional, Set

import dns.flags
import dns.message
import dns.name
import dns.query
import dns.rcode
import dns.rdatatype

from app.core.config import settings
from app.core.logging import logger
from app.probing.dns_scanner.resolvers import get_confirmation_pool


# ─────────────────────────────────────────────────────────────────────────────
# Trusted-resolver query rate limiter
# ─────────────────────────────────────────────────────────────────────────────
#
# All confirmation DNS queries go through _throttle_confirmation_query().
# A module-level asyncio.Lock + monotonic timer enforces at most one query
# per _CONFIRMATION_QUERY_INTERVAL seconds (default 0.1 s = 10 queries/sec).
#
# Why this matters:
#   The trusted pool is only ~16 well-known IPs (1.1.1.1, 8.8.8.8, …).
#   With NS_SWEEP_CONCURRENCY=100 all 100 coroutines hammer these same IPs
#   simultaneously.  After a few minutes of runtime the resolvers start
#   dropping packets → confirmations score 0/N → real findings get suppressed.
#   The rate limit serialises outgoing confirmation traffic so the resolvers
#   never see a burst regardless of sweep concurrency.

_CONFIRMATION_QUERY_INTERVAL: float = 0.1   # seconds between queries (10/s max)
_confirmation_lock: Optional[asyncio.Lock] = None
_last_confirmation_query: float = 0.0


def _get_confirmation_lock() -> asyncio.Lock:
    """Lazily initialise the lock inside the running event loop."""
    global _confirmation_lock
    if _confirmation_lock is None:
        _confirmation_lock = asyncio.Lock()
    return _confirmation_lock


async def _throttle_confirmation_query() -> None:
    """
    Acquire the rate-limit token before sending any query to a trusted resolver.

    Ensures at most 1 / _CONFIRMATION_QUERY_INTERVAL queries per second leave
    this process towards the trusted confirmation pool.  Lock is held only for
    the brief sleep period — not for the duration of the DNS I/O — so other
    coroutines queue up rather than pile up.
    """
    global _last_confirmation_query
    lock = _get_confirmation_lock()
    async with lock:
        now  = asyncio.get_event_loop().time()
        wait = _CONFIRMATION_QUERY_INTERVAL - (now - _last_confirmation_query)
        if wait > 0:
            await asyncio.sleep(wait)
        _last_confirmation_query = asyncio.get_event_loop().time()


# ─────────────────────────────────────────────────────────────────────────────
# Async NS hostname resolution (replaces run_in_executor path)
# ─────────────────────────────────────────────────────────────────────────────

async def _resolve_ns_hostname(
    ns: str,
    pool: List[str],
    timeout: float,
) -> List[str]:
    try:
        import dns.asyncresolver
        resolver = dns.asyncresolver.Resolver()
        resolver.nameservers = list(pool)
        resolver.timeout     = timeout
        resolver.lifetime    = timeout * 2
        try:
            answer = await asyncio.wait_for(
                resolver.resolve(ns, "A"),
                timeout=timeout + 2,
            )
            ips = [str(rdata) for rdata in answer]
            if ips:
                logger.debug("confirm: resolved %s → %s (asyncresolver)", ns, ips)
                return ips
        except Exception:
            pass
    except ImportError:
        pass

    # Fallback: iterate pool manually with asyncio-wrapped udp query
    loop = asyncio.get_running_loop()
    for resolver_ip in pool:
        try:
            await _throttle_confirmation_query()
            req  = dns.message.make_query(ns, dns.rdatatype.A)
            resp = await asyncio.wait_for(
                loop.run_in_executor(
                    None, lambda r=resolver_ip, q=req: dns.query.udp(q, r, timeout=timeout)
                ),
                timeout=timeout + 1,
            )
            if resp.rcode() == dns.rcode.NOERROR:
                ips = [
                    str(rd)
                    for rrset in resp.answer
                    if rrset.rdtype == dns.rdatatype.A
                    for rd in rrset
                ]
                if ips:
                    return ips
        except Exception:
            pass

    return []


async def _recursive_soa_confirm(
    domain: str,
    pool: List[str],
    timeout: float,
    expected_rcodes: tuple,
    need: int,
) -> int:
    """
    When the NS hostname cannot be resolved, confirm by
    asking each trusted recursive resolver for the domain SOA with RD=1.

    If the zone doesn't exist at the provider the recursive resolvers will
    return NXDOMAIN or SERVFAIL regardless of which NS serves it.  This path
    is independent of NS IP resolution and handles Azure DNS correctly.

    Returns the number of resolvers that agreed on a vulnerable rcode.
    """
    loop   = asyncio.get_running_loop()
    agreed = 0

    for resolver_ip in pool:
        if agreed >= need:
            break
        try:
            qname   = dns.name.from_text(domain)
            request = dns.message.make_query(qname, dns.rdatatype.SOA)
            # RD=1 — ask the recursive resolver to resolve for us
            request.flags |= dns.flags.RD
            await _throttle_confirmation_query()
            resp = await asyncio.wait_for(
                loop.run_in_executor(
                    None,
                    lambda ip=resolver_ip, q=request: dns.query.udp(q, ip, timeout=timeout),
                ),
                timeout=timeout + 1,
            )
            rcode_str = dns.rcode.to_text(resp.rcode())
            if rcode_str in expected_rcodes:
                agreed += 1
                logger.debug(
                    "confirm: recursive fallback — %s SOA via %s → %s ✓",
                    domain, resolver_ip, rcode_str,
                )
            else:
                logger.debug(
                    "confirm: recursive fallback — %s SOA via %s → %s",
                    domain, resolver_ip, rcode_str,
                )
        except Exception:
            pass

    return agreed


# ─────────────────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────────────────

async def confirm_ns_rcode(
    domain: str,
    ns: str,
    expected_rcodes: tuple = ("SERVFAIL", "REFUSED", "NXDOMAIN"),
    confirmation_pool: Optional[List[str]] = None,
    timeout: Optional[float] = None,
    min_agree: Optional[int] = None,
) -> bool:
    """
    Re-verify a standard rcode-based NS takeover finding against trusted resolvers.

    Returns True  → finding confirmed (≥ min_agree probes returned a vulnerable rcode)
    Returns False → finding NOT confirmed (suppress as likely false positive)

    Two-path confirmation:
      Primary   — resolve NS hostname → query NS directly (RD=0, authoritative)
      Fallback  — ask confirmation pool resolvers recursively (RD=1) when NS
                  hostname is unresolvable (covers Azure DNS under sweep load)
    """
    if not getattr(settings, "NS_CONFIRMATION_ENABLED", True):
        logger.debug("confirm: NS confirmation disabled — treating as confirmed")
        return True

    pool   = confirmation_pool or get_confirmation_pool()
    t      = timeout   if timeout   is not None else float(getattr(settings, "NS_CONFIRMATION_TIMEOUT", 5.0))
    need   = min_agree if min_agree is not None else int(getattr(settings, "NS_CONFIRMATION_MIN_AGREE", 2))
    loop   = asyncio.get_running_loop()

    # ── Step 1: resolve NS hostname → IPs (async) ───────────────────────────
    ns_ips = await _resolve_ns_hostname(ns, pool, t)

    if not ns_ips:
        # NS hostname unresolvable — do NOT silently suppress.
        # Fall back to recursive SOA confirmation via the trusted pool.
        # This correctly handles Azure DNS (ns*.azure-dns.*) and any other
        # provider whose NS hostnames are slow to resolve under sweep load.
        logger.debug(
            "confirm: could not resolve %s — falling back to recursive SOA confirmation for %s",
            ns, domain,
        )
        agreed = await _recursive_soa_confirm(domain, pool, t, expected_rcodes, need)
        if agreed >= need:
            logger.info(
                "confirm: NS takeover CONFIRMED for %s (recursive fallback, %d/%d probes) — "
                "NS hostname %s was unresolvable but domain returned vulnerable rcode",
                domain, agreed, len(pool), ns,
            )
            return True
        logger.info(
            "confirm: NS takeover NOT confirmed for %s via %s — "
            "NS hostname unresolvable AND recursive check gave %d/%d agreement",
            domain, ns, agreed, need,
        )
        return False

    # ── Step 2: direct SOA query to NS (RD=0, authoritative check) ───────────
    # rotate across all resolved NS IPs instead of pinning to [0].
    qname   = dns.name.from_text(domain)
    agreed  = 0
    attempts = max(need, 3)

    for i in range(attempts):
        ns_ip = ns_ips[i % len(ns_ips)]   # rotate across resolved NS IPs
        try:
            request = dns.message.make_query(qname, dns.rdatatype.SOA)
            request.flags &= ~dns.flags.RD
            await _throttle_confirmation_query()
            resp = await asyncio.wait_for(
                loop.run_in_executor(
                    None,
                    lambda ip=ns_ip, q=request: dns.query.udp(q, ip, timeout=t),
                ),
                timeout=t + 1,
            )
            rcode_str = dns.rcode.to_text(resp.rcode())
            if rcode_str in expected_rcodes:
                agreed += 1
                logger.debug("confirm: probe %d/%d — %s SOA via %s → %s ✓",
                             i + 1, attempts, domain, ns_ip, rcode_str)
                if agreed >= need:
                    logger.info("confirm: NS takeover CONFIRMED for %s via %s (%d/%d probes)",
                                domain, ns, agreed, attempts)
                    return True
            else:
                logger.debug("confirm: probe %d/%d — %s SOA via %s → %s (not vuln)",
                             i + 1, attempts, domain, ns_ip, rcode_str)
        except asyncio.TimeoutError:
            pass
        except Exception:
            pass

    logger.info("confirm: NS takeover NOT confirmed for %s via %s (%d/%d need %d)",
                domain, ns, agreed, attempts, need)
    return False


async def confirm_aws_ns_mismatch(
    domain: str,
    ns: str,
    recursive_ns_set: List[str],
    confirmation_pool: Optional[List[str]] = None,
    timeout: Optional[float] = None,
    min_agree: Optional[int] = None,
) -> bool:
    """
    Re-verify an AWS Route 53 NS-mismatch finding against trusted resolvers.

    Returns True  → mismatch confirmed by ≥ min_agree trusted resolvers
    Returns False → finding NOT confirmed (false positive)
    """
    if not getattr(settings, "NS_CONFIRMATION_ENABLED", True):
        return True

    pool    = confirmation_pool or get_confirmation_pool()
    t       = timeout   if timeout   is not None else float(getattr(settings, "NS_CONFIRMATION_TIMEOUT", 5.0))
    need    = min_agree if min_agree is not None else int(getattr(settings, "NS_CONFIRMATION_MIN_AGREE", 2))
    loop    = asyncio.get_running_loop()
    _awspat = re.compile(r"awsdns", re.IGNORECASE)
    agreed  = 0

    for resolver_ip in pool:
        if agreed >= need:
            break

        # use async resolution for NS hostname
        ns_ips = await _resolve_ns_hostname(ns, [resolver_ip], t)
        if not ns_ips:
            continue
        ns_ip = ns_ips[0]

        try:
            qname   = dns.name.from_text(domain)
            request = dns.message.make_query(qname, dns.rdatatype.NS)
            request.flags &= ~dns.flags.RD
            await _throttle_confirmation_query()
            auth_resp = await asyncio.wait_for(
                loop.run_in_executor(
                    None,
                    lambda ip=ns_ip, q=request: dns.query.udp(q, ip, timeout=t),
                ),
                timeout=t + 1,
            )
        except Exception:
            continue

        if auth_resp.rcode() != dns.rcode.NOERROR:
            continue

        auth_ns_set: Set[str] = set()
        for rrset in auth_resp.answer + auth_resp.authority:
            if rrset.rdtype == dns.rdatatype.NS:
                auth_ns_set.update(str(rd.target).rstrip(".").lower() for rd in rrset)

        if not auth_ns_set:
            continue

        recursive_set        = {n.lower() for n in recursive_ns_set}
        auth_only            = auth_ns_set - recursive_set
        auth_only_awsdns     = {n for n in auth_only if _awspat.search(n)}
        auth_only_non_awsdns = auth_only - auth_only_awsdns

        if auth_only_awsdns and not auth_only_non_awsdns:
            agreed += 1
            logger.debug("confirm_aws: mismatch confirmed via %s for %s", resolver_ip, domain)

    if agreed >= need:
        logger.info("confirm_aws: AWS NS mismatch CONFIRMED for %s via %s (%d/%d)",
                    domain, ns, agreed, len(pool))
        return True

    logger.info("confirm_aws: AWS NS mismatch NOT confirmed for %s (%d/%d need %d)",
                domain, agreed, len(pool), need)
    return False