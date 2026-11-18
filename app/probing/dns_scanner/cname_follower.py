"""
app/probing/dns_scanner/cname_follower.py

CNAME chain follower for dangling IP detection.

When a subdomain resolves via a CNAME chain, the terminal IPs are not directly
delegated to this subdomain — so they cannot represent a standard "IP takeover"
of this subdomain specifically.

HOWEVER: if the CNAME target itself is dangling (the service it points to has
been decommissioned but DNS was not cleaned up), the terminal IPs may still
be worth checking. Two scenarios:

  Scenario A — CNAME target is a vulnerable provider endpoint
    e.g. sub.example.com CNAME → bucket.s3.amazonaws.com
    This is the classic subdomain takeover via CNAME — handled by the existing
    TakeoverEvaluator, NOT here.

  Scenario B — CNAME chain terminates at a cloud IP (A or AAAA record)
    e.g. sub.example.com CNAME → old-lb.partner.com → 1.2.3.4 (AWS EIP)
    The partner shut down their LB, the IP was released, but the DNS chain
    still exists. If 1.2.3.4 is a dangling AWS EIP, claiming it allows
    serving content for sub.example.com.

    This module detects Scenario B. The finding type is "cname_dangling" and
    the confidence reflects the extra hop in the chain.

  Scenario C — CNAME chain terminates in NXDOMAIN
    e.g. sub.example.com CNAME → deleted-service.azure.com (NXDOMAIN)
    The terminal target no longer exists. ns_checker._check_cname_nxdomain_target
    takes over to probe whether the IP that used to live there is now free.

Config:
  DANGLING_IP_CNAME_FOLLOW   bool   default True
  MAX_CNAME_HOPS             int    (hardcoded 5, matches dns.py)
"""

import asyncio
from typing import List, Optional, Tuple

import dns.name
import dns.rdatatype
import dns.rcode

from app.core.logging import logger
from app.probing.dns_scanner.resolvers import get_pool, udp_query

MAX_CNAME_HOPS = 5


async def follow_cname_chain(
    subdomain_name: str,
    initial_response,         # dns.message.Message with CNAME in answer
    pool: Optional[List[str]] = None,
    timeout: float = 3.0,
) -> Tuple[List[str], List[str], List[str], bool]:
    """
    Follow a CNAME chain from an initial DNS response that contains a CNAME.

    Returns:
      (cname_chain, terminal_ips, terminal_ipv6s, is_nxdomain)
        cname_chain     — list of CNAME targets in order, e.g. ["a.cdn.com", "b.cdn.com"]
        terminal_ips    — final A record IPs at end of chain (IPv4, may be empty)
        terminal_ipv6s  — final AAAA record IPs at end of chain (IPv6, may be empty)
        is_nxdomain     — True if the chain terminated with NXDOMAIN

    Does NOT check whether these IPs are dangling — that is done by ip_analyzer.

    Each hop resolves both A and AAAA records so IPv6 terminal addresses are
    returned alongside IPv4. The CNAME labels themselves do not depend on the
    terminal record type.
    """
    if pool is None:
        pool = get_pool()

    chain: List[str] = []
    seen  = {subdomain_name.lower().rstrip(".")}

    # Extract first CNAME from initial response
    current: Optional[str] = None
    for rrset in initial_response.answer:
        if rrset.rdtype == dns.rdatatype.CNAME:
            for rdata in rrset:
                current = str(rdata.target).rstrip(".").lower()
                chain.append(current)
                break
        if current:
            break

    if not current:
        return [], [], [], False

    # Follow the chain
    for hop in range(MAX_CNAME_HOPS - 1):
        if current in seen:
            logger.debug("cname_follower: loop detected at %s (hop %d)", current, hop)
            break
        seen.add(current)

        # Resolve both A and AAAA at each hop in parallel.
        a_resp, aaaa_resp = await asyncio.gather(
            udp_query(pool, current, dns.rdatatype.A, timeout),
            udp_query(pool, current, dns.rdatatype.AAAA, timeout),
        )

        # Detect an NXDOMAIN terminal. A double timeout (both
        # udp_query() calls return None) is not NXDOMAIN: require an explicit
        # NXDOMAIN rcode so _check_cname_nxdomain_target does not run on
        # transient network failures.
        # probe traffic for domains that still exist.
        # require at least one explicit NXDOMAIN rcode.  If both queries
        # time out we cannot determine the domain status — fall through and let
        # the chain terminate normally with no IPs (is_nxdomain=False).
        a_rcode    = a_resp.rcode()    if a_resp    is not None else None
        aaaa_rcode = aaaa_resp.rcode() if aaaa_resp is not None else None

        a_is_nxdomain    = (a_rcode    == dns.rcode.NXDOMAIN)
        aaaa_is_nxdomain = (aaaa_rcode == dns.rcode.NXDOMAIN)
        a_is_gone        = (a_is_nxdomain    or a_rcode    is None)
        aaaa_is_gone     = (aaaa_is_nxdomain or aaaa_rcode is None)

        if a_is_gone and aaaa_is_gone and (a_is_nxdomain or aaaa_is_nxdomain):
            # At least one explicit NXDOMAIN — domain is genuinely deleted
            logger.debug(
                "cname_follower: %s → NXDOMAIN at hop %d (%s) — chain=%s",
                subdomain_name, hop, current, chain,
            )
            return chain, [], [], True

        if a_is_gone and aaaa_is_gone:
            # Both timed out — cannot confirm deletion, terminate without NXDOMAIN
            logger.debug(
                "cname_follower: %s → double timeout at hop %d (%s) — "
                "treating as unresolvable, not NXDOMAIN",
                subdomain_name, hop, current,
            )
            break

        next_cname:    Optional[str] = None
        terminal_ips:  List[str]     = []
        terminal_ipv6s: List[str]    = []

        # Extract A records and next CNAME from A response
        if a_resp is not None and a_rcode == dns.rcode.NOERROR:
            for rrset in a_resp.answer:
                if rrset.rdtype == dns.rdatatype.CNAME:
                    for rdata in rrset:
                        next_cname = str(rdata.target).rstrip(".").lower()
                elif rrset.rdtype == dns.rdatatype.A:
                    for rdata in rrset:
                        terminal_ips.append(str(rdata))

        # Extract AAAA records from the AAAA response
        if aaaa_resp is not None and aaaa_rcode == dns.rcode.NOERROR:
            for rrset in aaaa_resp.answer:
                if rrset.rdtype == dns.rdatatype.AAAA:
                    for rdata in rrset:
                        terminal_ipv6s.append(str(rdata))

        if terminal_ips or terminal_ipv6s:
            # Reached terminal IP records — chain ends here
            logger.debug(
                "cname_follower: %s → chain=%s → IPs=%s IPv6s=%s",
                subdomain_name, chain, terminal_ips, terminal_ipv6s,
            )
            return chain, terminal_ips, terminal_ipv6s, False

        if next_cname:
            chain.append(next_cname)
            current = next_cname
        else:
            break

    return chain, [], [], False