"""
app/probing/dns_scanner/resolvers.py

UDP DNS query helpers and resolver pool management.

Uses raw UDP via dns.query.udp — never touches proxychains (TCP only).
Picks a fresh random resolver from the full pool on every query.
"""

import asyncio
import random
from typing import List, Optional, Set

import dns.message
import dns.query
import dns.rdatatype

from app.core.config import settings
from app.core.logging import logger
from app.discovery.resolvers import get_resolver_list

_DNS_TIMEOUT  = float(getattr(settings, "DNS_TAKEOVER_TIMEOUT", 3.0))
_MAX_ATTEMPTS = 2


def get_pool() -> List[str]:
    """Return the full resolver pool (random UDP per query)."""
    try:
        return get_resolver_list()
    except Exception:
        return ["1.1.1.1", "8.8.8.8", "9.9.9.9"]


def get_confirmation_pool() -> List[str]:
    """Return the trusted confirmation resolver pool."""
    raw = getattr(settings, "NS_CONFIRMATION_RESOLVERS", "")
    if raw:
        parsed = [r.strip() for r in raw.split(",") if r.strip()]
        if parsed:
            return parsed
    return [
        "1.1.1.1", "1.0.0.1",
        "8.8.8.8", "8.8.4.4",
        "9.9.9.9", "149.112.112.112",
        "208.67.222.222", "208.67.220.220",
        "64.6.64.6", "64.6.65.6",
        "185.228.168.9", "185.228.169.9",
        "94.140.14.14", "94.140.15.15",
        "76.76.19.19", "76.223.122.150",
    ]


async def udp_query(
    pool: List[str],
    name: str,
    rdtype: int,
    timeout: float = _DNS_TIMEOUT,
    attempts: int = _MAX_ATTEMPTS,
) -> Optional[dns.message.Message]:
    """
    Fire a UDP DNS query, retrying with a fresh random resolver each attempt.
    Returns the response Message or None if all attempts fail.
    """
    loop = asyncio.get_running_loop()
    tried: Set[str] = set()

    for _ in range(attempts):
        resolver = random.choice(pool)
        for _ in range(10):
            if resolver not in tried or len(tried) >= len(pool):
                break
            resolver = random.choice(pool)
        tried.add(resolver)

        try:
            request  = dns.message.make_query(name, rdtype)
            response = await asyncio.wait_for(
                loop.run_in_executor(
                    None,
                    lambda r=resolver: dns.query.udp(request, r, timeout=timeout),
                ),
                timeout=timeout + 1,
            )
            return response
        except asyncio.TimeoutError:
            logger.debug("dns_scanner: UDP timeout for %s via %s", name, resolver)
        except Exception as exc:
            logger.debug("dns_scanner: UDP error for %s via %s: %s", name, resolver, exc)

    return None


async def resolve_to_ips(pool: List[str], hostname: str, timeout: float = _DNS_TIMEOUT) -> List[str]:
    """Resolve a hostname to its A record IP addresses."""
    try:
        response = await udp_query(pool, hostname, dns.rdatatype.A, timeout)
        if response is None or response.rcode() != 0:   # NOERROR = 0
            return []
        results = []
        for rrset in response.answer:
            if rrset.rdtype == dns.rdatatype.A:
                for rdata in rrset:
                    results.append(str(rdata))
        return results
    except Exception:
        return []