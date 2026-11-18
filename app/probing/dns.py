"""
DNS probing for subdomains.

Resolver strategy
-----------------
Picks a FRESH random resolver from the full pool for EVERY individual query.
Uses raw UDP via dns.query.udp_with_fallback() so queries go directly from
this machine and never touch proxychains (proxychains only hooks TCP connect).
The event loop thread-pool (run_in_executor) is used to keep the blocking
dns.query.udp call off the async event loop.
"""
import asyncio
import json
import random
from datetime import datetime
from typing import Optional, Dict, Any, List

import dns.exception
import dns.flags
import dns.message
import dns.name
import dns.query
import dns.rcode
import dns.rdatatype
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.logging import logger
from app.discovery.resolvers import get_resolver_list
from app.db.db_models import Subdomain


MAX_CNAME_HOPS = 5
_QUERY_TIMEOUT = getattr(settings, "DNS_PROBE_TIMEOUT", 5)
# How many resolvers to try before giving up on a single query
_MAX_ATTEMPTS = 3


def _get_resolver_list() -> List[str]:
    return get_resolver_list()


def _pick_resolver(pool: List[str]) -> str:
    """Pick a random resolver from the pool each time."""
    return random.choice(pool)


def _udp_query(resolver_ip: str, name: str, rdtype: int, timeout: float) -> dns.message.Message:
    """
    Blocking UDP DNS query — runs in executor so it doesn't block the event loop.
    Raises on timeout or error.
    """
    request = dns.message.make_query(name, rdtype)
    return dns.query.udp(request, resolver_ip, timeout=timeout)


async def _query_with_retry(
    pool: List[str],
    name: str,
    rdtype: int,
    timeout: float = _QUERY_TIMEOUT,
    attempts: int = _MAX_ATTEMPTS,
) -> Optional[dns.message.Message]:
    """
    Fire a UDP DNS query, retrying with a different random resolver on failure.
    Returns the response Message, or None if all attempts fail.
    """
    loop = asyncio.get_running_loop()
    tried: set = set()

    for _ in range(attempts):
        # Pick a resolver we haven't tried yet this round
        resolver = _pick_resolver(pool)
        for _ in range(10):  # avoid infinite loop on tiny pools
            if resolver not in tried or len(tried) >= len(pool):
                break
            resolver = _pick_resolver(pool)
        tried.add(resolver)

        try:
            response = await asyncio.wait_for(
                loop.run_in_executor(
                    None,
                    lambda r=resolver: _udp_query(r, name, rdtype, timeout),
                ),
                timeout=timeout + 1,
            )
            logger.debug("DNS %s %s via %s → %s",
                         dns.rdatatype.to_text(rdtype), name, resolver,
                         dns.rcode.to_text(response.rcode()))
            return response
        except asyncio.TimeoutError:
            logger.debug("DNS timeout for %s via %s", name, resolver)
        except Exception as e:
            logger.debug("DNS error for %s via %s: %s", name, resolver, e)

    return None


def _extract_rrset(response: dns.message.Message, rdtype: int, name: str) -> List:
    """Extract rdata records of given type from answer section."""
    qname = dns.name.from_text(name)
    results = []
    for rrset in response.answer:
        if rrset.rdtype == rdtype and rrset.name == qname:
            results.extend(list(rrset))
    return results


class DNSProber:
    """
    DNS resolution and CNAME chain following.

    Uses raw UDP queries with a fresh random resolver from the full pool
    on every single query. Completely bypasses proxychains.
    """

    def __init__(self):
        self._pool = _get_resolver_list()
        if not self._pool:
            raise RuntimeError("DNS resolver pool is empty — check DNS_RESOLVERS config")
        logger.debug("DNSProber initialized with pool of %d resolvers", len(self._pool))

    async def probe(
        self,
        session: AsyncSession,
        subdomain: Subdomain,
    ) -> Optional[Dict[str, Any]]:
        """Perform DNS resolution on a subdomain."""
        logger.debug("DNS probing: %s", subdomain.name)

        try:
            # ── A + AAAA records (concurrent) ─────────────────────────────────
            resolved = False
            ips: List[str] = []       # IPv4
            ipv6s: List[str] = []     # IPv6
            nxdomain = False

            a_response, aaaa_response = await asyncio.gather(
                _query_with_retry(self._pool, subdomain.name, dns.rdatatype.A),
                _query_with_retry(self._pool, subdomain.name, dns.rdatatype.AAAA),
            )

            # ── A record ──────────────────────────────────────────────────────
            if a_response is None:
                logger.debug("DNS A query failed for %s (all attempts exhausted)", subdomain.name)
                return None

            rcode = a_response.rcode()
            if rcode == dns.rcode.NXDOMAIN:
                nxdomain = True
            elif rcode == dns.rcode.NOERROR:
                a_records = _extract_rrset(a_response, dns.rdatatype.A, subdomain.name)
                if a_records:
                    resolved = True
                    ips = [str(r) for r in a_records]

            # ── AAAA record ───────────────────────────────────────────────────
            if aaaa_response is not None and aaaa_response.rcode() == dns.rcode.NOERROR:
                aaaa_records = _extract_rrset(aaaa_response, dns.rdatatype.AAAA, subdomain.name)
                if aaaa_records:
                    resolved = True
                    ipv6s = [str(r) for r in aaaa_records]
                    logger.debug("AAAA records for %s: %s", subdomain.name, ipv6s)

            # ── CNAME chain ───────────────────────────────────────────────────
            cname_chain: List[str] = []
            cname_target = await self._resolve_cname_chain(subdomain.name, cname_chain)

            if cname_chain:
                logger.debug(
                    "CNAME chain for %s: %s",
                    subdomain.name,
                    " -> ".join(cname_chain),
                )

            subdomain.cname_target = cname_target
            subdomain.dns_resolved_at = datetime.utcnow()
            subdomain.dns_resolver = None  # no single resolver — rotated per query
            subdomain.ip_addresses = json.dumps(ips) if ips else None
            subdomain.ipv6_addresses = json.dumps(ipv6s) if ipv6s else None

            return {
                "resolved": resolved,
                "ips": ips,
                "ipv6s": ipv6s,
                "cname": cname_target,
                "cname_chain": cname_chain,
                "nxdomain": nxdomain,
            }

        except Exception as e:
            logger.error("DNS probe error for %s: %s", subdomain.name, e)
            return None

    async def _resolve_cname_chain(
        self,
        name: str,
        chain: List[str],
    ) -> Optional[str]:
        """
        Follow CNAME records starting from `name` until a terminal node is reached
        or MAX_CNAME_HOPS is hit. Fresh random resolver used for each hop.
        Mutates `chain` in-place. Returns terminal target or None.
        """
        current = name
        seen: set = {name.lower().rstrip(".")}

        for hop in range(MAX_CNAME_HOPS):
            response = await _query_with_retry(self._pool, current, dns.rdatatype.CNAME)
            if response is None:
                break

            if response.rcode() != dns.rcode.NOERROR:
                break

            cname_records = _extract_rrset(response, dns.rdatatype.CNAME, current)
            if not cname_records:
                break

            target = str(cname_records[0].target).rstrip(".")
            chain.append(target)

            target_lower = target.lower()
            if target_lower in seen:
                logger.warning(
                    "CNAME loop detected for %s at hop %d: %s -> %s (already seen)",
                    name, hop, current, target,
                )
                break

            seen.add(target_lower)
            current = target

        return chain[-1] if chain else None