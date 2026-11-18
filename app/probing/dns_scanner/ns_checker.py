"""
app/probing/dns_scanner/ns_checker.py

DNSScanner — core NS takeover detection + subdomain scan orchestration.

Performs:
  1. NS record resolution via parent-zone query (RD=0, no CNAME chasing)
  2. NS takeover detection:
       a) AWS Route 53 NS-set mismatch (custom path, awsdns NS only)
       b) Standard rcode-based (SERVFAIL/REFUSED/NXDOMAIN) for all other providers
       c) Unresolvable NS host detection (dead nameserver — takeover signal)
  3. A + AAAA record resolution for each subdomain
  4. CNAME chain following (via cname_follower.py) for terminal IPv4+IPv6 analysis
  5. MX record resolution + dangling IP analysis on MX targets
  6. DanglingIPAnalyzer call for each direct A / AAAA record IP
  7. CNAME NXDOMAIN target resolution — checks if dangling CNAME target resolves
     to a claimable cloud IP via authoritative NS query

AWS Route 53 mismatch detection
────────────────────────────────
Standard SERVFAIL/NXDOMAIN detection does NOT work for AWS. A claimed zone
always returns NOERROR from Route 53 regardless of who owns it.
The real signal is NS SET MISMATCH: the recursive NS answer differs from what
Route 53 authoritatively serves, because a new zone gets DIFFERENT NS records.
Confirmed real case: fireblocks.io (Bugcrowd PoC, March 2026).
"""

import asyncio
import random
import re
from typing import Dict, List, Optional, Set, Tuple

import dns.flags
import dns.message
import dns.name
import dns.query
import dns.rcode
import dns.rdatatype

from app.core.config import settings
from app.core.logging import logger
from app.probing.dns_scanner.models import NSFinding, ScanResult, DanglingIPFinding
from app.probing.dns_scanner.resolvers import get_confirmation_pool, udp_query, resolve_to_ips
from app.discovery.resolvers import get_resolver_list as get_pool
from app.probing.dns_scanner.ns_providers import VULNERABLE_NS_PROVIDERS
from app.probing.dns_scanner.ns_confirmation import confirm_ns_rcode, confirm_aws_ns_mismatch
from app.probing.dns_scanner.ip_analyzer import DanglingIPAnalyzer
from app.probing.dns_scanner.cname_follower import follow_cname_chain
from app.probing.ip_verdicts import (
    IPVerdict,
    aggregate_subdomain_ip_free,
    verdict_from_finding,
)

try:
    from app.takeover.ip_hunter.cidr_index import CIDRIndex
    from app.probing.ip_check import check_ip_verdict
except ImportError:
    CIDRIndex = None


_DNS_TIMEOUT = float(getattr(settings, "DNS_TAKEOVER_TIMEOUT", 3.0))
_AWSDNS_PAT  = re.compile(r"awsdns", re.IGNORECASE)


class DNSScanner:
    """
    Unified DNS security scanner.

    Public API:
      check_scope(domain)          — scope-root NS takeover check (daemon sweep)
      scan_subdomain(subdomain, …) — full subdomain scan (NS + dangling IP + CNAME)
    """

    def __init__(self, cidr_index: Optional[CIDRIndex] = None) -> None:
        self._timeout           = _DNS_TIMEOUT
        self._pool              = get_pool()
        self._confirmation_pool = get_confirmation_pool()
        # cache stores (ips, expiry_monotonic) tuples so stale
        # entries are refreshed rather than held for the entire daemon lifetime.
        # 300 s TTL keeps the hot path fast while surviving NS IP rotation.
        self._parent_ns_cache:  Dict[str, tuple] = {}   # key → (List[str], float)
        self._parent_ns_cache_ttl: float = 300.0
        # STAMPEDE: per-key locks prevent 100 concurrent coroutines scanning
        # subdomains of the same parent zone (e.g. all *.example.com subdomains)
        # from each sending their own parent-zone NS query.  Without this, the
        # first 100 coroutines all miss the cold cache simultaneously and each
        # independently send the same UDP query, multiplying ns_check= traffic
        # by the concurrency factor.  With the lock, only ONE query is sent and
        # all others wait, then get a cache hit on the re-check inside the lock.
        self._parent_ns_locks:  Dict[str, asyncio.Lock] = {}
        self._cidr_index        = cidr_index
        self._ip_analyzer       = DanglingIPAnalyzer(cidr_index=cidr_index)
        self._cname_follow      = bool(getattr(settings, "DANGLING_IP_CNAME_FOLLOW", True))
        self._mx_check          = bool(getattr(settings, "DANGLING_IP_MX_CHECK", True))

        logger.debug(
            "DNSScanner: %d resolvers / %d confirmation resolvers / cidr_index=%s",
            len(self._pool), len(self._confirmation_pool),
            "yes" if cidr_index else "no",
        )

    def set_cidr_index(self, cidr_index) -> None:
        self._cidr_index = cidr_index
        self._ip_analyzer.set_cidr_index(cidr_index)

    # ── Resolver pool warm-up ────────────────────────────────────────────────

    async def warm_pool(self) -> None:
        """
        Pre-filter dead resolvers from self._pool before a sweep.

        Samples up to NS_SWEEP_WARM_POOL_SAMPLE (default 200) resolvers,
        probes each with a single A query for "google.com" using a short
        timeout (NS_SWEEP_WARM_POOL_TIMEOUT, default 1.0 s, up to
        NS_SWEEP_WARM_POOL_ATTEMPTS default 2 tries per resolver).
        Resolvers that fail every attempt are removed from self._pool.

        Config (.env):
          NS_SWEEP_WARM_POOL_SAMPLE    int    default 200
          NS_SWEEP_WARM_POOL_TIMEOUT   float  default 1.0  (seconds per attempt)
          NS_SWEEP_WARM_POOL_ATTEMPTS  int    default 2    (tries per resolver)
          NS_SWEEP_WARM_POOL_MIN       int    default 8    (minimum pool size)

        Expected effect: removes 30-50% of dead entries, cutting dns= and
        ns_check= latency by ~50% because the sweep stops burning time on
        timeout retries against resolvers that never respond.

        Safe to call repeatedly - always keeps at least NS_SWEEP_WARM_POOL_MIN
        resolvers so accidental mass-pruning never breaks the scanner.
        """
        sample_size = int(getattr(settings, "NS_SWEEP_WARM_POOL_SAMPLE",   200))
        timeout     = float(getattr(settings, "NS_SWEEP_WARM_POOL_TIMEOUT", 1.0))
        attempts    = int(getattr(settings, "NS_SWEEP_WARM_POOL_ATTEMPTS",  2))
        min_pool    = int(getattr(settings, "NS_SWEEP_WARM_POOL_MIN",       8))

        if len(self._pool) <= min_pool:
            logger.debug("warm_pool: pool already at minimum size (%d) - skipping", len(self._pool))
            return

        pool_snapshot = list(self._pool)
        # Sample from the front - stable ordering means the same resolvers are
        # tested on each sweep so dead entries are evicted quickly and the
        # unsampled tail (assumed alive) stays untouched.
        sample = pool_snapshot[:sample_size]

        loop = asyncio.get_running_loop()

        async def _probe(resolver_ip: str) -> bool:
            """True if resolver answers a basic A query within timeout."""
            for _ in range(attempts):
                try:
                    req  = dns.message.make_query("google.com", dns.rdatatype.A)
                    resp = await asyncio.wait_for(
                        loop.run_in_executor(
                            None,
                            lambda r=resolver_ip, q=req: dns.query.udp(q, r, timeout=timeout),
                        ),
                        timeout=timeout + 0.5,
                    )
                    if resp is not None:
                        return True
                except Exception:
                    pass
            return False

        results = await asyncio.gather(*[_probe(r) for r in sample], return_exceptions=True)

        dead: set = set()
        for resolver, ok in zip(sample, results):
            if ok is not True:
                dead.add(resolver)

        if not dead:
            logger.debug("warm_pool: all %d sampled resolvers alive", len(sample))
            return

        new_pool = [r for r in self._pool if r not in dead]

        # Safety: never shrink below min_pool
        if len(new_pool) < min_pool:
            logger.warning(
                "warm_pool: too many dead resolvers (%d/%d dead) - "
                "pool would shrink below minimum (%d), keeping full pool",
                len(dead), len(sample), min_pool,
            )
            return

        removed = len(self._pool) - len(new_pool)
        logger.info(
            "warm_pool: removed %d dead resolver(s) "
            "(%d/%d sampled dead, pool: %d -> %d)",
            removed, len(dead), len(sample), len(self._pool), len(new_pool),
        )
        self._pool = new_pool

    # ── Scope-root NS takeover check ────────────────────────────────────────

    async def check_scope(self, domain: str) -> Optional[NSFinding]:
        """
        Check a scope-root domain for NS takeover vulnerability.

        The wildcard CNAME check runs unconditionally before the nameserver
        guard: _check_wildcard_cname() queries the parent zone's NS directly and
        does not depend on whether the domain's own NS records resolve. An empty
        NS resolution (transient timeout, UDP loss) must not skip it.

        When a wildcard CNAME finding and confirmed NS findings coexist, the
        wildcard CNAME is the primary result (higher severity) and the NS
        findings are logged rather than discarded.
        """
        if not getattr(settings, "DNS_TAKEOVER_ENABLED", True):
            return None

        # run wildcard CNAME check first, independently of NS resolution.
        wildcard_cname = await self._check_wildcard_cname(
            domain=domain,
            scope_domain=domain,
            program_name="",
            platform="",
        )

        nameservers = await self._get_nameservers(domain)
        findings: List[NSFinding] = []
        if nameservers:
            findings = await self._check_all_ns(
                domain=domain,
                nameservers=nameservers,
                scope_domain=domain,
                program_name="",
                platform="",
            )

        if wildcard_cname:
            # log any concurrent NS findings instead of silently
            # discarding them when wildcard CNAME wins.
            if findings:
                logger.warning(
                    "dns_scanner: check_scope %s — wildcard CNAME AND %d NS finding(s) "
                    "detected simultaneously; returning wildcard CNAME (more severe). "
                    "Suppressed NS findings: %s",
                    domain,
                    len(findings),
                    [(f.nameserver, f.rcode) for f in findings],
                )
            # Wildcard CNAME is more severe than a single-subdomain finding:
            # every subdomain under this scope is simultaneously vulnerable.
            return wildcard_cname

        return findings[0] if findings else None

    # ── Full subdomain scan ─────────────────────────────────────────────────

    async def scan_subdomain(
        self,
        subdomain,
        scope_domain: str = "",
        program_name: str = "",
        platform:     str = "",
    ) -> ScanResult:
        """
        Full scan for a single subdomain ORM object.

        Steps:
          1. Resolve A + AAAA records
          2. Follow CNAME chain (IPv4 + IPv6 terminals)
          3. NS takeover check (all NS hosts, dead NS detection)
          4a. Dangling IP — direct A records (full analysis even when CNAME present)
          4b. Dangling IP — direct AAAA records
          4c. Dangling IP — CNAME terminal IPv4 IPs
          4d. Dangling IP — MX record targets
          4e. Dangling IP — CNAME terminal IPv6 IPs
          4f. CNAME NXDOMAIN target cloud IP check
          4g. CNAME intermediate hop domain availability
        """
        result = ScanResult(subdomain_name=subdomain.name)

        # ── Step 1: A + AAAA resolution ─────────────────────────────────────
        a_resp, aaaa_resp = await asyncio.gather(
            udp_query(self._pool, subdomain.name, dns.rdatatype.A),
            udp_query(self._pool, subdomain.name, dns.rdatatype.AAAA),
        )

        has_cname   = False
        direct_ips: List[str] = []
        ipv6s:      List[str] = []

        if a_resp is not None and a_resp.rcode() == dns.rcode.NOERROR:
            for rrset in a_resp.answer:
                if rrset.rdtype == dns.rdatatype.CNAME:
                    has_cname = True
                if rrset.rdtype == dns.rdatatype.A:
                    direct_ips.extend(str(r) for r in rrset)

        if aaaa_resp is not None and aaaa_resp.rcode() == dns.rcode.NOERROR:
            for rrset in aaaa_resp.answer:
                if rrset.rdtype == dns.rdatatype.AAAA:
                    ipv6s.extend(str(r) for r in rrset)

        result.ips       = sorted(set(direct_ips))
        result.ipv6s     = sorted(set(ipv6s))
        result.has_cname = has_cname

        # ── Step 2: CNAME chain follow (IPv4 + IPv6) ─────────────────────────
        cname_chain:      List[str] = []
        cname_ips:        List[str] = []
        cname_ipv6s:      List[str] = []
        cname_terminal:   Optional[str] = None
        cname_is_nxdomain: bool = False

        if has_cname and a_resp is not None and self._cname_follow:
            cname_chain, cname_ips, cname_ipv6s, cname_is_nxdomain = await follow_cname_chain(
                subdomain_name=subdomain.name,
                initial_response=a_resp,
                pool=self._pool,
                timeout=self._timeout,
            )
            if cname_chain:
                result.cname_chain = cname_chain
                cname_terminal     = cname_chain[-1] if cname_chain else None

        # ── Step 3: NS takeover check (all NS hosts) ─────────────────────────
        # 9: collect all NS findings, not just the first
        nameservers = await self._get_nameservers(subdomain.name)
        if nameservers:
            ns_findings = await self._check_all_ns(
                domain=subdomain.name,
                nameservers=nameservers,
                scope_domain=scope_domain,
                program_name=program_name,
                platform=platform,
            )
            if ns_findings:
                result.ns_finding = ns_findings[0]  # primary; extras logged

        # ── Step 4a: Dangling IP — direct A records (IPv4) ───────────────────
        # CNAME presence does not skip full dangling analysis.
        # IPs in direct_ips when has_cname=True are unusual (resolver flattening)
        # but still worth analyzing. finding_type is "cname_dangling" for those.
        ip_verdicts: Dict[str, IPVerdict] = {}

        for ip in result.ips:
            # Determine finding type: if this IP co-exists with a CNAME in the
            # answer section, it arrived via resolver flattening — treat as
            # cname_dangling to reflect the indirect path.
            ft = "cname_dangling" if has_cname else "dangling"
            finding = await self._ip_analyzer.analyze(
                ip=ip, subdomain_name=subdomain.name,
                scope_domain=scope_domain, program_name=program_name, platform=platform,
                finding_type=ft,
                cname_chain=cname_chain if has_cname else None,
                cname_terminal=cname_terminal if has_cname else None,
            )
            if finding is not None:
                result.dangling_ip_findings.append(finding)
                ip_verdicts[ip] = verdict_from_finding(finding)
            else:
                ip_verdicts[ip] = await check_ip_verdict(ip)

        # ── Step 4b: Dangling IP — AAAA records (IPv6) ───────────────────────

        if result.ipv6s:
            for ip6 in result.ipv6s:
                finding = await self._ip_analyzer.analyze(
                    ip=ip6, subdomain_name=subdomain.name,
                    scope_domain=scope_domain, program_name=program_name, platform=platform,
                    finding_type="ipv6_dangling",
                )
                if finding is not None:
                    result.dangling_ip_findings.append(finding)
                    if finding.confirmed_free or finding.foreign_tls_cert:
                        logger.info(
                            "dangling_ip: IPv6 finding for %s — ip=%s type=%s confidence=%d",
                            subdomain.name, ip6, finding.finding_type, finding.confidence,
                        )

        # ── Step 4c: Dangling IP — CNAME terminal IPv4 IPs ───────────────────
        if cname_ips:
            if not self._cidr_index:
                logger.warning(
                    "ns_sweep: cidr_index is None — skipping CNAME terminal IP analysis "
                    "for %s (chain=%s). Rebuild CIDR index to enable.",
                    subdomain.name, cname_chain,
                )
            else:
                for ip in cname_ips:
                    finding = await self._ip_analyzer.analyze(
                        ip=ip, subdomain_name=subdomain.name,
                        scope_domain=scope_domain, program_name=program_name, platform=platform,
                        finding_type="cname_dangling",
                        cname_chain=cname_chain, cname_terminal=cname_terminal,
                    )
                    if finding is not None:
                        finding.confidence = max(0, finding.confidence - 15)
                        finding.indicators.append(
                            f"IP reached via CNAME chain: {' → '.join(cname_chain)}"
                        )
                        if finding.confirmed_free or finding.foreign_tls_cert:
                            result.dangling_ip_findings.append(finding)

        # ── Step 4d: Dangling IP — MX record targets ─────────────────────────
        if self._mx_check:
            mx_findings = await self._analyze_mx_records(
                subdomain_name=subdomain.name,
                scope_domain=scope_domain,
                program_name=program_name,
                platform=platform,
            )
            result.dangling_ip_findings.extend(mx_findings)

        # ── Step 4e: Dangling IP — CNAME terminal IPv6 IPs ───────────────────
        if cname_ipv6s:
            if not self._cidr_index:
                logger.warning(
                    "ns_sweep: cidr_index is None — skipping CNAME terminal IPv6 analysis "
                    "for %s", subdomain.name,
                )
            else:
                for ip6 in cname_ipv6s:
                    finding = await self._ip_analyzer.analyze(
                        ip=ip6, subdomain_name=subdomain.name,
                        scope_domain=scope_domain, program_name=program_name, platform=platform,
                        finding_type="cname_dangling",
                        cname_chain=cname_chain, cname_terminal=cname_terminal,
                    )
                    if finding is not None:
                        finding.confidence = max(0, finding.confidence - 15)
                        finding.indicators.append(
                            f"IPv6 reached via CNAME chain: {' → '.join(cname_chain)}"
                        )
                        if finding.confirmed_free or finding.foreign_tls_cert:
                            result.dangling_ip_findings.append(finding)

        # ── Step 4f: CNAME NXDOMAIN target — resolve via authoritative NS ─────
        if cname_is_nxdomain and cname_terminal and self._cidr_index:
            nxd_findings = await self._check_cname_nxdomain_target(
                subdomain_name=subdomain.name,
                cname_terminal=cname_terminal,
                cname_chain=cname_chain,
                scope_domain=scope_domain,
                program_name=program_name,
                platform=platform,
            )
            result.dangling_ip_findings.extend(nxd_findings)

        # ── Step 4g: CNAME intermediate hop domain availability ───────────────
        if cname_chain and len(cname_chain) > 1:
            hop_findings = await self._check_cname_intermediate_hops(
                subdomain_name=subdomain.name,
                cname_chain=cname_chain,
                scope_domain=scope_domain,
                program_name=program_name,
                platform=platform,
            )
            for hf in hop_findings:
                if result.ns_finding is None:
                    result.ns_finding = hf   # primary slot
                else:
                    logger.info(
                        "ns_sweep: cname hop available for %s (hop=%s) "
                        "but ns_finding already set (%s) — logging only",
                        subdomain.name, hf.nameserver, result.ns_finding.rcode,
                    )

        # ── Aggregate ip_free (IPv4 only) ────────────────────────────────────
        result.ip_verdicts = ip_verdicts
        result.ip_free = aggregate_subdomain_ip_free(ip_verdicts.values())

        return result

    async def scan_subdomain_cached(
        self,
        subdomain,
        scope_domain: str = "",
        program_name: str = "",
        platform:     str = "",
        ip_cache=None,
    ) -> ScanResult:
        """
        Like scan_subdomain() but routes dangling IP analysis through ip_cache.

        When ip_cache is None, delegates to scan_subdomain() directly.
        """
        if ip_cache is None:
            return await self.scan_subdomain(
                subdomain=subdomain,
                scope_domain=scope_domain,
                program_name=program_name,
                platform=platform,
            )

        result = ScanResult(subdomain_name=subdomain.name)

        # ── Step 1: A + AAAA resolution ─────────────────────────────────────
        a_resp, aaaa_resp = await asyncio.gather(
            udp_query(self._pool, subdomain.name, dns.rdatatype.A),
            udp_query(self._pool, subdomain.name, dns.rdatatype.AAAA),
        )

        has_cname   = False
        direct_ips: List[str] = []
        ipv6s:      List[str] = []

        if a_resp is not None and a_resp.rcode() == dns.rcode.NOERROR:
            for rrset in a_resp.answer:
                if rrset.rdtype == dns.rdatatype.CNAME:
                    has_cname = True
                if rrset.rdtype == dns.rdatatype.A:
                    direct_ips.extend(str(r) for r in rrset)

        if aaaa_resp is not None and aaaa_resp.rcode() == dns.rcode.NOERROR:
            for rrset in aaaa_resp.answer:
                if rrset.rdtype == dns.rdatatype.AAAA:
                    ipv6s.extend(str(r) for r in rrset)

        result.ips       = sorted(set(direct_ips))
        result.ipv6s     = sorted(set(ipv6s))
        result.has_cname = has_cname

        # ── Step 2: CNAME chain follow (IPv4 + IPv6) ─────────────────────────
        cname_chain:       List[str] = []
        cname_ips:         List[str] = []
        cname_ipv6s:       List[str] = []
        cname_terminal:    Optional[str] = None
        cname_is_nxdomain: bool = False

        if has_cname and a_resp is not None and self._cname_follow:
            cname_chain, cname_ips, cname_ipv6s, cname_is_nxdomain = await follow_cname_chain(
                subdomain_name=subdomain.name,
                initial_response=a_resp,
                pool=self._pool,
                timeout=self._timeout,
            )
            if cname_chain:
                result.cname_chain = cname_chain
                cname_terminal     = cname_chain[-1] if cname_chain else None

        # ── Step 3: NS takeover check (all NS hosts) ─────────────────────────
        # 9
        nameservers = await self._get_nameservers(subdomain.name)
        if nameservers:
            ns_findings = await self._check_all_ns(
                domain=subdomain.name,
                nameservers=nameservers,
                scope_domain=scope_domain,
                program_name=program_name,
                platform=platform,
            )
            if ns_findings:
                result.ns_finding = ns_findings[0]

        # ── Step 4a: Dangling IP — direct A (IPv4) via cache ─────────────────
        ip_verdicts: Dict[str, IPVerdict] = {}

        for ip in result.ips:
            ft = "cname_dangling" if has_cname else "dangling"
            finding = await ip_cache.get_or_analyze(
                ip=ip,
                analyze_fn=self._ip_analyzer.analyze,
                subdomain_name=subdomain.name,
                scope_domain=scope_domain,
                program_name=program_name,
                platform=platform,
                finding_type=ft,
                cname_chain=cname_chain if has_cname else None,
                cname_terminal=cname_terminal if has_cname else None,
            )
            if finding is not None:
                result.dangling_ip_findings.append(finding)
                ip_verdicts[ip] = verdict_from_finding(finding)
            else:
                ip_verdicts[ip] = await check_ip_verdict(ip)

        # ── Step 4b: Dangling IP — AAAA (IPv6) via cache ─────────────────────
        if result.ipv6s:
            for ip6 in result.ipv6s:
                finding = await ip_cache.get_or_analyze(
                    ip=ip6,
                    analyze_fn=self._ip_analyzer.analyze,
                    subdomain_name=subdomain.name,
                    scope_domain=scope_domain,
                    program_name=program_name,
                    platform=platform,
                    finding_type="ipv6_dangling",
                )
                if finding is not None:
                    result.dangling_ip_findings.append(finding)
                    if finding.confirmed_free or finding.foreign_tls_cert:
                        logger.info(
                            "dangling_ip: IPv6 finding for %s — ip=%s type=%s confidence=%d",
                            subdomain.name, ip6, finding.finding_type, finding.confidence,
                        )

        # ── Step 4c: Dangling IP — CNAME terminal IPv4 via cache ─────────────
        if cname_ips:
            if not self._cidr_index:
                logger.warning(
                    "ns_sweep: cidr_index is None — skipping CNAME terminal IP analysis "
                    "for %s (chain=%s). Rebuild CIDR index to enable.",
                    subdomain.name, cname_chain,
                )
            else:
                for ip in cname_ips:
                    finding = await ip_cache.get_or_analyze(
                        ip=ip,
                        analyze_fn=self._ip_analyzer.analyze,
                        subdomain_name=subdomain.name,
                        scope_domain=scope_domain,
                        program_name=program_name,
                        platform=platform,
                        finding_type="cname_dangling",
                        cname_chain=cname_chain,
                        cname_terminal=cname_terminal,
                    )
                    if finding is not None:
                        finding.confidence = max(0, finding.confidence - 15)
                        if finding.confirmed_free or finding.foreign_tls_cert:
                            finding.indicators.append(
                                f"IP reached via CNAME chain: {' → '.join(cname_chain)}"
                            )
                            result.dangling_ip_findings.append(finding)

        # ── Step 4d: Dangling IP — MX record targets ─────────────────────────
        if self._mx_check:
            mx_findings = await self._analyze_mx_records(
                subdomain_name=subdomain.name,
                scope_domain=scope_domain,
                program_name=program_name,
                platform=platform,
            )
            result.dangling_ip_findings.extend(mx_findings)

        # ── Step 4e: Dangling IP — CNAME terminal IPv6 via cache ─────────────
        if cname_ipv6s:
            if not self._cidr_index:
                logger.warning(
                    "ns_sweep: cidr_index is None — skipping CNAME terminal IPv6 analysis "
                    "for %s", subdomain.name,
                )
            else:
                for ip6 in cname_ipv6s:
                    finding = await ip_cache.get_or_analyze(
                        ip=ip6,
                        analyze_fn=self._ip_analyzer.analyze,
                        subdomain_name=subdomain.name,
                        scope_domain=scope_domain,
                        program_name=program_name,
                        platform=platform,
                        finding_type="cname_dangling",
                        cname_chain=cname_chain,
                        cname_terminal=cname_terminal,
                    )
                    if finding is not None:
                        finding.confidence = max(0, finding.confidence - 15)
                        finding.indicators.append(
                            f"IPv6 reached via CNAME chain: {' → '.join(cname_chain)}"
                        )
                        if finding.confirmed_free or finding.foreign_tls_cert:
                            result.dangling_ip_findings.append(finding)

        # ── Step 4f: CNAME NXDOMAIN target cloud IP check ────────────────────
        if cname_is_nxdomain and cname_terminal and self._cidr_index:
            nxd_findings = await self._check_cname_nxdomain_target(
                subdomain_name=subdomain.name,
                cname_terminal=cname_terminal,
                cname_chain=cname_chain,
                scope_domain=scope_domain,
                program_name=program_name,
                platform=platform,
            )
            result.dangling_ip_findings.extend(nxd_findings)

        # ── Step 4g: CNAME intermediate hop domain availability ───────────────
        if cname_chain and len(cname_chain) > 1:
            hop_findings = await self._check_cname_intermediate_hops(
                subdomain_name=subdomain.name,
                cname_chain=cname_chain,
                scope_domain=scope_domain,
                program_name=program_name,
                platform=platform,
            )
            for hf in hop_findings:
                if result.ns_finding is None:
                    result.ns_finding = hf
                else:
                    logger.info(
                        "ns_sweep: cname hop available for %s (hop=%s) "
                        "but ns_finding already set (%s) — logging only",
                        subdomain.name, hf.nameserver, result.ns_finding.rcode,
                    )

        # ── Aggregate ip_free (IPv4 only) ────────────────────────────────────
        result.ip_verdicts = ip_verdicts
        result.ip_free = aggregate_subdomain_ip_free(ip_verdicts.values())

        return result

    # ── NS check logic ──────────────────────────────────────────────────────

    async def _check_all_ns(
        self,
        domain:       str,
        nameservers:  List[str],
        scope_domain: str,
        program_name: str,
        platform:     str,
    ) -> List[NSFinding]:
        """
        Check every nameserver for takeover, not just the first one.

        Returns deduplicated list of NSFindings sorted by severity (NS_UNRESOLVABLE
        last, confirmed mismatches first). The caller stores findings[0] as the
        primary result for the subdomain.
        """
        findings: List[NSFinding] = []
        seen_providers: Set[str] = set()

        for ns in nameservers:
            finding = await self._check_ns(
                domain=domain, ns=ns, all_nameservers=nameservers,
                scope_domain=scope_domain, program_name=program_name, platform=platform,
            )
            if finding is None:
                continue
            # Deduplicate by provider name to avoid double-alerting on identical
            # providers sharing NS (e.g. two Hurricane Electric nameservers)
            key = f"{finding.provider}:{finding.rcode}"
            if key in seen_providers:
                logger.debug(
                    "dns_scanner: dedup — skipping duplicate finding for %s "
                    "(provider=%s rcode=%s already found)",
                    domain, finding.provider, finding.rcode,
                )
                continue
            seen_providers.add(key)
            findings.append(finding)
            logger.info(
                "dns_scanner: NS finding #%d for %s — ns=%s provider=%s rcode=%s",
                len(findings), domain, ns, finding.provider, finding.rcode,
            )

        # Sort: NS_UNRESOLVABLE findings last (informational only)
        findings.sort(key=lambda f: (1 if f.rcode == "NS_UNRESOLVABLE" else 0))
        return findings

    async def _check_ns(
        self,
        domain:          str,
        ns:              str,
        all_nameservers: List[str],
        scope_domain:    str,
        program_name:    str,
        platform:        str,
    ) -> Optional[NSFinding]:
        """Check a single NS for takeover. Returns NSFinding or None."""

        # AWS Route 53 — NS mismatch path ONLY for awsdns NS
        if _AWSDNS_PAT.search(ns):
            mismatch = await self._check_aws_ns_mismatch(domain, ns, all_nameservers)
            if mismatch:
                confirmed = await confirm_aws_ns_mismatch(
                    domain, ns, all_nameservers,
                    confirmation_pool=self._confirmation_pool,
                    timeout=float(getattr(settings, "NS_CONFIRMATION_TIMEOUT", 5.0)),
                )
                if not confirmed:
                    logger.info("dns_scanner: AWS NS mismatch for %s → %s suppressed", domain, ns)
                    return None
                logger.info("dns_scanner: VULNERABLE (AWS NS mismatch) — %s → %s", domain, ns)
                aws_prov = next(
                    (p for p in VULNERABLE_NS_PROVIDERS if p.custom_detection and p.pattern.fullmatch(ns)),
                    None,
                )
                return NSFinding(
                    subdomain_name=domain, nameserver=ns,
                    provider=aws_prov.name if aws_prov else "AWS Route 53 (NS mismatch)",
                    provider_notes=aws_prov.notes if aws_prov else "",
                    rcode="NS_MISMATCH",
                    fp_risk=aws_prov.fp_risk if aws_prov else True,
                    scope_domain=scope_domain, program_name=program_name, platform=platform,
                    all_nameservers=all_nameservers,
                )
            return None   # awsdns but no mismatch — skip rcode path

        ns_ips_for_check = await resolve_to_ips(self._pool, ns, self._timeout)

        if not ns_ips_for_check:
            # Bulk pool failed — retry with confirmation pool before giving up.
            confirm_timeout = float(getattr(settings, "NS_CONFIRMATION_TIMEOUT", 5.0))
            for resolver_ip in self._confirmation_pool:
                ips = await resolve_to_ips([resolver_ip], ns, confirm_timeout)
                if ips:
                    ns_ips_for_check = ips
                    logger.debug(
                        "dns_scanner: NS %s resolved via confirmation pool (%s) "
                        "after bulk pool failure — transient timeout suppressed",
                        ns, resolver_ip,
                    )
                    break

        if not ns_ips_for_check:
            # Both pools failed — NS hostname is genuinely unresolvable.
            matched_dead = [
                p for p in VULNERABLE_NS_PROVIDERS
                if not p.custom_detection and p.pattern.fullmatch(ns)
            ]
            if matched_dead:
                # Use _query_direct as the final gate. It returns "UNKNOWN" when
                # it cannot resolve the NS hostname, which confirm_ns_rcode will
                # also verify before we fire.
                rcode = await self._query_direct(domain, ns)
                if rcode == "UNKNOWN":
                    confirmed = await confirm_ns_rcode(
                        domain, ns,
                        expected_rcodes=("SERVFAIL", "REFUSED", "NXDOMAIN", "UNKNOWN"),
                        confirmation_pool=self._confirmation_pool,
                        timeout=float(getattr(settings, "NS_CONFIRMATION_TIMEOUT", 5.0)),
                    )
                    if confirmed:
                        provider = matched_dead[0]
                        logger.info(
                            "dns_scanner: DEAD NS (unresolvable, confirmed) — "
                            "%s → %s (%s) — strong takeover signal",
                            domain, ns, provider.name,
                        )
                        return NSFinding(
                            subdomain_name=domain, nameserver=ns,
                            provider=provider.name, provider_notes=provider.notes,
                            rcode="NS_UNRESOLVABLE",
                            fp_risk=provider.fp_risk,
                            scope_domain=scope_domain, program_name=program_name,
                            platform=platform, all_nameservers=all_nameservers,
                        )
                logger.debug(
                    "dns_scanner: NS %s for %s unresolvable on both pools "
                    "but rcode=%s — suppressed (not confirmed dead)",
                    ns, domain, rcode if "rcode" in dir() else "N/A",
                )
                return None
            else:
                # Unresolvable NS that doesn't match a known provider — skip
                logger.debug(
                    "dns_scanner: NS %s for %s is unresolvable but no provider match — skipping",
                    ns, domain,
                )
                return None

        # Standard rcode path — ns_ips_for_check is populated
        matched = [
            p for p in VULNERABLE_NS_PROVIDERS
            if not p.custom_detection and p.pattern.fullmatch(ns)
        ]

        if not matched:
            # ── LAME DELEGATION CHECK ─────────────────────────────────────────
            # NS resolves (has IPs) but doesn't match any known vulnerable provider.
            # This covers in-house / decommissioned NS (e.g. ns1.oldcompany.com)
            # that was removed from the provider but the registrar delegation
            # still points to it.  The NS responds but returns REFUSED or SERVFAIL
            # because it's no longer authoritative for the zone.
            #
            # Distinct from NS takeover (where you can claim the provider zone).
            # Here the NS software is still running but the zone file was deleted.
            # The registrar delegation is intact — to exploit: gain control of the
            # NS host itself (server takeover) or wait for the NS host to expire.
            # Still HIGH severity — zone is unresolvable from these NS.
            lame_rcode = await self._query_direct(domain, ns)
            if lame_rcode in ("REFUSED", "SERVFAIL"):
                confirmed = await confirm_ns_rcode(
                    domain, ns,
                    expected_rcodes=("REFUSED", "SERVFAIL"),
                    confirmation_pool=self._confirmation_pool,
                    timeout=float(getattr(settings, "NS_CONFIRMATION_TIMEOUT", 5.0)),
                )
                if confirmed:
                    logger.warning(
                        "dns_scanner: LAME DELEGATION — %s → %s returned %s "
                        "(NS exists+resolves but is no longer authoritative for zone). "
                        "Zone was likely deleted from this provider.",
                        domain, ns, lame_rcode,
                    )
                    return NSFinding(
                        subdomain_name=domain,
                        nameserver=ns,
                        provider="Lame Delegation",
                        provider_notes=(
                            f"Nameserver `{ns}` resolves but returned `{lame_rcode}` "
                            f"when queried for `{domain}`.\n\n"
                            f"This indicates the NS records exist and the nameserver "
                            f"software is running, but the zone file for `{domain}` "
                            f"has been deleted from the provider.\n\n"
                            f"**Attack surface**: The registrar delegation is intact. "
                            f"Anyone who gains control of this nameserver host can serve "
                            f"authoritative DNS responses for `{domain}` — including A, "
                            f"MX, TXT, and any subdomains.\n\n"
                            f"**Recommended action**: Remove the NS delegation from the "
                            f"registrar OR restore the zone at the nameserver provider. "
                            f"If the NS host is decommissioned, update the registrar to "
                            f"point to the current authoritative servers."
                        ),
                        rcode=lame_rcode,
                        fp_risk=True,   # Some providers legitimately REFUSE non-zone queries
                        scope_domain=scope_domain,
                        program_name=program_name,
                        platform=platform,
                        all_nameservers=all_nameservers,
                    )
                else:
                    logger.debug(
                        "dns_scanner: %s → %s returned %s but NOT confirmed by "
                        "trusted resolvers — lame delegation suppressed (likely FP)",
                        domain, ns, lame_rcode,
                    )
            return None
            # ── END LAME DELEGATION CHECK ─────────────────────────────────────

        provider = matched[0]
        rcode    = await self._query_direct(domain, ns)

        if rcode in ("SERVFAIL", "REFUSED", "NXDOMAIN"):
            confirmed = await confirm_ns_rcode(
                domain, ns,
                expected_rcodes=("SERVFAIL", "REFUSED", "NXDOMAIN"),
                confirmation_pool=self._confirmation_pool,
                timeout=float(getattr(settings, "NS_CONFIRMATION_TIMEOUT", 5.0)),
            )
            if not confirmed:
                logger.info(
                    "dns_scanner: %s → %s (%s) returned %s but NOT confirmed — suppressed",
                    domain, ns, provider.name, rcode,
                )
                return None
            logger.info(
                "dns_scanner: VULNERABLE (confirmed) — %s → %s (%s) %s%s",
                domain, ns, provider.name, rcode,
                " [fp_risk]" if provider.fp_risk else "",
            )
            return NSFinding(
                subdomain_name=domain, nameserver=ns,
                provider=provider.name, provider_notes=provider.notes,
                rcode=rcode, fp_risk=provider.fp_risk,
                scope_domain=scope_domain, program_name=program_name, platform=platform,
                all_nameservers=all_nameservers,
            )

        return None

    # ── MX record dangling check ─────────────────────────────────────────────

    async def _analyze_mx_records(
        self,
        subdomain_name: str,
        scope_domain:   str,
        program_name:   str,
        platform:       str,
    ) -> List[DanglingIPFinding]:
        """
        Resolve MX records for the subdomain and analyze each MX target IP for
        cloud dangling. MX-sourced findings use finding_type="mx_dangling".

        Only analyzes MX targets that resolve to cloud provider IPs. Ignores
        shared MX providers (Google, Outlook, etc.) via PTR/header signals.
        """
        findings: List[DanglingIPFinding] = []

        mx_resp = await udp_query(self._pool, subdomain_name, dns.rdatatype.MX, self._timeout)
        if mx_resp is None or mx_resp.rcode() != dns.rcode.NOERROR:
            return findings

        mx_hosts: List[str] = []
        for rrset in mx_resp.answer:
            if rrset.rdtype == dns.rdatatype.MX:
                for rdata in rrset:
                    host = str(rdata.exchange).rstrip(".").lower()
                    if host and host != ".":
                        mx_hosts.append(host)

        if not mx_hosts:
            return findings

        for mx_host in mx_hosts:
            # Resolve MX host to IPs
            a_resp, aaaa_resp = await asyncio.gather(
                udp_query(self._pool, mx_host, dns.rdatatype.A, self._timeout),
                udp_query(self._pool, mx_host, dns.rdatatype.AAAA, self._timeout),
            )

            mx_ips: List[Tuple[str, str]] = []  # (ip, rdtype_hint)
            if a_resp is not None and a_resp.rcode() == dns.rcode.NOERROR:
                for rrset in a_resp.answer:
                    if rrset.rdtype == dns.rdatatype.A:
                        for rdata in rrset:
                            mx_ips.append((str(rdata), "ipv4"))
            if aaaa_resp is not None and aaaa_resp.rcode() == dns.rcode.NOERROR:
                for rrset in aaaa_resp.answer:
                    if rrset.rdtype == dns.rdatatype.AAAA:
                        for rdata in rrset:
                            mx_ips.append((str(rdata), "ipv6"))

            for ip, family in mx_ips:
                ft = "mx_dangling"
                finding = await self._ip_analyzer.analyze(
                    ip=ip, subdomain_name=subdomain_name,
                    scope_domain=scope_domain, program_name=program_name, platform=platform,
                    finding_type=ft,
                )
                if finding is not None and (finding.confirmed_free or finding.foreign_tls_cert):
                    finding.indicators.append(
                        f"IP reached via MX record: {subdomain_name} MX → {mx_host} → {ip}"
                    )
                    logger.info(
                        "dangling_ip: MX finding for %s — mx_host=%s ip=%s type=%s confidence=%d",
                        subdomain_name, mx_host, ip, finding.finding_type, finding.confidence,
                    )
                    findings.append(finding)

        return findings

    # ── CNAME NXDOMAIN target cloud IP check ─────────────────────────────────

    async def _check_cname_nxdomain_target(
        self,
        subdomain_name: str,
        cname_terminal: str,
        cname_chain:    List[str],
        scope_domain:   str,
        program_name:   str,
        platform:       str,
    ) -> List[DanglingIPFinding]:
        findings: List[DanglingIPFinding] = []

        if not cname_terminal:
            return findings

        try:
            qname = dns.name.from_text(cname_terminal)
        except Exception:
            return findings

        # Find authoritative NS for the terminal target
        try:
            parent = qname.parent()
        except dns.name.NoParent:
            return findings

        parent_str = str(parent).rstrip(".")
        ns_resp = await udp_query(self._pool, parent_str, dns.rdatatype.NS, self._timeout)
        if ns_resp is None or ns_resp.rcode() != dns.rcode.NOERROR:
            return findings

        auth_ns_hosts = [
            str(rd.target).rstrip(".")
            for rrset in ns_resp.answer
            if rrset.rdtype == dns.rdatatype.NS
            for rd in rrset
        ]
        if not auth_ns_hosts:
            return findings

        # Resolve one authoritative NS to an IP
        auth_ns_ip: Optional[str] = None
        for ns_host in auth_ns_hosts:
            ips = await resolve_to_ips(self._pool, ns_host, self._timeout)
            if ips:
                auth_ns_ip = ips[0]
                break

        if not auth_ns_ip:
            return findings

        # Query the terminal CNAME target directly from its authoritative NS
        loop = asyncio.get_running_loop()
        for rdtype, family in [(dns.rdatatype.A, "ipv4"), (dns.rdatatype.AAAA, "ipv6")]:
            try:
                request = dns.message.make_query(qname, rdtype)
                request.flags &= ~dns.flags.RD
                resp = await asyncio.wait_for(
                    loop.run_in_executor(
                        None,
                        lambda ip=auth_ns_ip: dns.query.udp(request, ip, timeout=self._timeout),
                    ),
                    timeout=self._timeout + 1,
                )
            except Exception:
                continue

            if resp.rcode() not in (dns.rcode.NOERROR,):
                continue

            for rrset in resp.answer:
                if rrset.rdtype == rdtype:
                    for rdata in rrset:
                        ip = str(rdata)
                        ft = "cname_dangling"
                        finding = await self._ip_analyzer.analyze(
                            ip=ip, subdomain_name=subdomain_name,
                            scope_domain=scope_domain, program_name=program_name,
                            platform=platform, finding_type=ft,
                            cname_chain=cname_chain, cname_terminal=cname_terminal,
                        )
                        if finding is not None:
                            should_include = finding.confirmed_free or finding.foreign_tls_cert
                            finding.confidence = max(0, finding.confidence - 20)
                            finding.indicators.append(
                                f"IP resolved from NXDOMAIN CNAME target {cname_terminal} "
                                f"via authoritative NS {auth_ns_ip} — stale DNS"
                            )
                            if should_include:
                                logger.info(
                                    "dangling_ip: CNAME-NXDOMAIN cloud IP for %s — "
                                    "terminal=%s ip=%s confidence=%d",
                                    subdomain_name, cname_terminal, ip, finding.confidence,
                                )
                                findings.append(finding)

        return findings

    # ── Wildcard CNAME detection ─────────────────────────────────────────────

    async def _check_wildcard_cname(
        self,
        domain:       str,
        scope_domain: str,
        program_name: str,
        platform:     str,
    ) -> Optional[NSFinding]:
        """
        Check if *.domain has a CNAME record pointing to a claimable provider.

        Attack: *.target.com CNAME → claimable-service.io
        Impact: EVERY subdomain under target.com is simultaneously vulnerable.
        Registering claimable-service.io (or claiming the provider resource)
        gives control over all subdomains at once.

        Detection: query the parent zone authoritative NS for the *.domain
        CNAME record using RD=0 (no recursion — must ask parent NS directly
        to see wildcard owner name records).
        """
        try:
            # Build wildcard name
            qname = dns.name.from_text(f"*.{domain}")

            # Resolve parent NS
            parent_ns_list = await self._get_nameservers(domain)
            # _get_nameservers returns the domain's own NS, not what we want.
            # We need the PARENT zone's NS to query for the wildcard owner name.
            # Use the existing _get_nameservers logic against parent of domain.
            import dns.name as _dnsname
            parent = _dnsname.from_text(domain).parent()
            if parent == _dnsname.root:
                return None
            parent_str = str(parent).rstrip(".")

            ns_resp = await udp_query(self._pool, parent_str, dns.rdatatype.NS, self._timeout)
            if ns_resp is None or ns_resp.rcode() != dns.rcode.NOERROR:
                return None

            parent_ns_hosts = [
                str(rd.target).rstrip(".")
                for rrset in ns_resp.answer
                if rrset.rdtype == dns.rdatatype.NS
                for rd in rrset
            ]
            ns_ips: list = []
            for host in parent_ns_hosts:
                ips = await resolve_to_ips(self._pool, host, self._timeout)
                ns_ips.extend(ips)
                if ns_ips:
                    break

            if not ns_ips:
                return None

            # Query parent NS for *.domain CNAME (non-recursive)
            request = dns.message.make_query(qname, dns.rdatatype.CNAME)
            request.flags &= ~dns.flags.RD

            loop = asyncio.get_running_loop()
            try:
                response = await asyncio.wait_for(
                    loop.run_in_executor(
                        None,
                        lambda: dns.query.udp(request, random.choice(ns_ips), timeout=self._timeout),
                    ),
                    timeout=self._timeout + 1,
                )
            except (asyncio.TimeoutError, Exception):
                return None

            if response.rcode() != dns.rcode.NOERROR:
                return None

            cname_target: Optional[str] = None
            for rrset in response.answer:
                if rrset.rdtype == dns.rdatatype.CNAME:
                    for rd in rrset:
                        cname_target = str(rd.target).rstrip(".").lower()
                        break
                if cname_target:
                    break

            if not cname_target:
                return None

            # Check if the CNAME target matches a known claimable provider
            from app.probing.confidence import ConfidenceScorer
            dns_score, provider = ConfidenceScorer.score_dns(
                cname=cname_target,
                nxdomain=False,
                subdomain_name=f"*.{domain}",
            )

            if not provider or dns_score == 0:
                # Not a known claimable provider — log but don't alert
                logger.debug(
                    "dns_scanner: wildcard CNAME *.%s → %s — provider not recognised, skipping",
                    domain, cname_target,
                )
                return None

            logger.warning(
                "dns_scanner: WILDCARD CNAME VULNERABLE — *.%s CNAME → %s (provider=%s) "
                "— ALL subdomains simultaneously at risk",
                domain, cname_target, provider,
            )

            # Return an NSFinding re-using existing model; rcode="WILDCARD_CNAME"
            # so the Discord embed shows the right context.
            return NSFinding(
                subdomain_name=f"*.{domain}",
                nameserver=cname_target,
                provider=provider,
                provider_notes=(
                    f"Wildcard CNAME: *.{domain} → {cname_target}\n"
                    f"Claiming this provider resource grants control over EVERY subdomain "
                    f"under {domain} simultaneously.\n"
                    f"Provider: {provider} — follow normal claim procedure for this provider."
                ),
                rcode="WILDCARD_CNAME",
                fp_risk=True,  # Verify manually — wildcard NS lookups can be tricky
                scope_domain=scope_domain,
                program_name=program_name,
                platform=platform,
                all_nameservers=[cname_target],
            )

        except asyncio.CancelledError:
            raise
        except Exception as exc:
            logger.debug("dns_scanner: wildcard CNAME check error for %s: %s", domain, exc)
            return None

    # ── Wildcard A dangling IP detection ─────────────────────────────────────

    async def check_wildcard_a_findings(
        self,
        domain:       str,
        scope_domain: str = "",
        program_name: str = "",
        platform:     str = "",
    ) -> List[DanglingIPFinding]:
        """
        Public entry point — called from daemon._dns_takeover_scope_sweep alongside
        check_scope() to detect wildcard A records pointing to dangling cloud IPs.

        Returns a (possibly empty) list of DanglingIPFinding with
        finding_type="wildcard_a_dangling".
        """
        return await self._check_wildcard_a(
            domain=domain,
            scope_domain=scope_domain or domain,
            program_name=program_name,
            platform=platform,
        )

    async def _check_wildcard_a(
        self,
        domain:       str,
        scope_domain: str,
        program_name: str,
        platform:     str,
    ) -> List[DanglingIPFinding]:
        findings: List[DanglingIPFinding] = []
        if not self._cidr_index:
            return findings

        try:
            import dns.name as _dnsname

            qname = _dnsname.from_text(f"*.{domain}")

            parent = _dnsname.from_text(domain).parent()
            if parent == _dnsname.root:
                return findings
            parent_str = str(parent).rstrip(".")

            ns_resp = await udp_query(self._pool, parent_str, dns.rdatatype.NS, self._timeout)
            if ns_resp is None or ns_resp.rcode() != dns.rcode.NOERROR:
                return findings

            parent_ns_hosts = [
                str(rd.target).rstrip(".")
                for rrset in ns_resp.answer
                if rrset.rdtype == dns.rdatatype.NS
                for rd in rrset
            ]
            ns_ips: List[str] = []
            for host in parent_ns_hosts:
                ips = await resolve_to_ips(self._pool, host, self._timeout)
                ns_ips.extend(ips)
                if ns_ips:
                    break

            if not ns_ips:
                return findings

            # Query parent NS for *.domain A records (non-recursive)
            request = dns.message.make_query(qname, dns.rdatatype.A)
            request.flags &= ~dns.flags.RD

            loop = asyncio.get_running_loop()
            try:
                response = await asyncio.wait_for(
                    loop.run_in_executor(
                        None,
                        lambda: dns.query.udp(
                            request, random.choice(ns_ips), timeout=self._timeout
                        ),
                    ),
                    timeout=self._timeout + 1,
                )
            except (asyncio.TimeoutError, Exception):
                return findings

            if response.rcode() != dns.rcode.NOERROR:
                return findings

            wildcard_ips: List[str] = []
            for rrset in response.answer:
                if rrset.rdtype == dns.rdatatype.A:
                    for rd in rrset:
                        wildcard_ips.append(str(rd))

            if not wildcard_ips:
                return findings

            logger.info(
                "dns_scanner: wildcard A record *.%s → %s — running dangling IP analysis",
                domain, wildcard_ips,
            )

            for ip in wildcard_ips:
                finding = await self._ip_analyzer.analyze(
                    ip=ip,
                    subdomain_name=f"*.{domain}",
                    scope_domain=scope_domain,
                    program_name=program_name,
                    platform=platform,
                    finding_type="wildcard_a_dangling",
                )
                if finding is not None:
                    finding.indicators.insert(
                        0,
                        f"⚡ WILDCARD A RECORD: *.{domain} → {ip} "
                        f"— ALL subdomains simultaneously affected",
                    )
                    if finding.confirmed_free or finding.cloud_claim_confirmed:
                        logger.warning(
                            "dns_scanner: WILDCARD A DANGLING — *.%s A %s "
                            "confirmed free (confidence=%d) — ALL subdomains at risk",
                            domain, ip, finding.confidence,
                        )
                        findings.append(finding)

        except asyncio.CancelledError:
            raise
        except Exception as exc:
            logger.debug("dns_scanner: wildcard A check error for %s: %s", domain, exc)

        return findings

    # ── CNAME intermediate hop availability ───────────────────────────────────

    async def _check_cname_intermediate_hops(
        self,
        subdomain_name: str,
        cname_chain:    List[str],
        scope_domain:   str,
        program_name:   str,
        platform:       str,
    ) -> List[NSFinding]:
        findings: List[NSFinding] = []
        seen_roots: set = set()

        for hop in cname_chain[:-1]:
            root = _cname_hop_registrable_root(hop)
            if not root or root in seen_roots:
                continue
            seen_roots.add(root)

            is_nxdomain = await _hop_domain_is_nxdomain(root)
            if not is_nxdomain:
                continue

            chain_display = " → ".join(cname_chain)
            logger.warning(
                "dns_scanner: CNAME hop available for %s — hop=%s (root=%s) "
                "chain=%s — register the hop domain to control the full chain",
                subdomain_name, hop, root, chain_display,
            )

            findings.append(NSFinding(
                subdomain_name=subdomain_name,
                nameserver=root,
                provider="domain_registrar",
                provider_notes=(
                    f"Intermediate CNAME hop `{root}` (from `{hop}`) is "
                    f"available to register.\n\n"
                    f"Full chain: {chain_display}\n\n"
                    f"Registering `{root}` gives full control over all downstream "
                    f"hops in this chain, including the terminal IP, without needing "
                    f"to claim the cloud IP itself."
                ),
                rcode="CNAME_HOP_AVAILABLE",
                fp_risk=False,
                scope_domain=scope_domain,
                program_name=program_name,
                platform=platform,
                all_nameservers=[root],
            ))
            # Stop at first (most upstream) hit — downstream findings are subsumed
            break

        return findings

    # ── DNS helpers ─────────────────────────────────────────────────────────

    async def _get_nameservers(self, domain: str) -> List[str]:
        try:
            qname = dns.name.from_text(domain)
            try:
                parent = qname.parent()
            except dns.name.NoParent:
                return []
            if parent == dns.name.root:
                return []

            parent_str = str(parent).rstrip(".")
            cache_key  = parent_str

            import time as _time
            now = _time.monotonic()

            # ── Fast path: valid cache hit (no lock needed for reads) ──────────
            ns_addr: Optional[str] = None
            cached_entry = self._parent_ns_cache.get(cache_key)
            if cached_entry is not None:
                cached_ips, expiry = cached_entry
                if now < expiry:
                    if not cached_ips:
                        return []
                    ns_addr = random.choice(cached_ips)
                # else: expired — fall through to locked refresh

            if ns_addr is None:
                if cache_key not in self._parent_ns_locks:
                    self._parent_ns_locks[cache_key] = asyncio.Lock()
                async with self._parent_ns_locks[cache_key]:
                    # Re-check inside lock — may have been populated while waiting
                    cached_entry = self._parent_ns_cache.get(cache_key)
                    if cached_entry is not None:
                        cached_ips, expiry = cached_entry
                        if now < expiry:
                            if not cached_ips:
                                return []
                            ns_addr = random.choice(cached_ips)

                    if ns_addr is None:
                        # We are the winner — send exactly one parent-zone NS query
                        ns_resp = await udp_query(self._pool, parent_str, dns.rdatatype.NS, self._timeout)
                        if ns_resp is None or ns_resp.rcode() != dns.rcode.NOERROR:
                            self._parent_ns_cache[cache_key] = ([], now + self._parent_ns_cache_ttl)
                            return []

                        parent_ns_hosts = [
                            str(rd.target).rstrip(".")
                            for rrset in ns_resp.answer
                            if rrset.rdtype == dns.rdatatype.NS
                            for rd in rrset
                        ]
                        if not parent_ns_hosts:
                            self._parent_ns_cache[cache_key] = ([], now + self._parent_ns_cache_ttl)
                            return []

                        all_ips: List[str] = []
                        for host in parent_ns_hosts:
                            ips = await resolve_to_ips(self._pool, host, self._timeout)
                            all_ips.extend(ips)
                            if all_ips:
                                break

                        self._parent_ns_cache[cache_key] = (all_ips, now + self._parent_ns_cache_ttl)
                        if not all_ips:
                            return []
                        ns_addr = random.choice(all_ips)

            request        = dns.message.make_query(qname, dns.rdatatype.NS)
            request.flags &= ~dns.flags.RD

            loop = asyncio.get_running_loop()
            try:
                response = await asyncio.wait_for(
                    loop.run_in_executor(
                        None, lambda: dns.query.udp(request, ns_addr, timeout=self._timeout)
                    ),
                    timeout=self._timeout + 1,
                )
            except (asyncio.TimeoutError, Exception):
                return []

            if response.rcode() == dns.rcode.NXDOMAIN:
                wildcard_results = await self._get_nameservers_wildcard(
                    domain=domain,
                    parent_str=parent_str,
                    ns_addr=ns_addr,
                )
                return wildcard_results

            # CNAME in answer = this is an alias, not a zone cut
            for rrset in response.answer:
                if rrset.rdtype == dns.rdatatype.CNAME and rrset.name == qname:
                    return []

            results: List[str] = [
                str(rd.target).rstrip(".").lower()
                for rrset in response.answer
                if rrset.rdtype == dns.rdatatype.NS and rrset.name == qname
                for rd in rrset
            ]
            if not results:
                results = [
                    str(rd.target).rstrip(".").lower()
                    for rrset in response.authority
                    if rrset.rdtype == dns.rdatatype.NS and rrset.name == qname
                    for rd in rrset
                ]
            return results

        except Exception as exc:
            logger.debug("dns_scanner: _get_nameservers error for %s: %s", domain, exc)
            return []

    async def _get_nameservers_wildcard(
        self,
        domain:     str,
        parent_str: str,
        ns_addr:    str,
    ) -> List[str]:
        try:
            wildcard_name = dns.name.from_text(f"*.{parent_str}")
            request       = dns.message.make_query(wildcard_name, dns.rdatatype.NS)
            request.flags &= ~dns.flags.RD

            loop = asyncio.get_running_loop()
            response = await asyncio.wait_for(
                loop.run_in_executor(
                    None, lambda: dns.query.udp(request, ns_addr, timeout=self._timeout)
                ),
                timeout=self._timeout + 1,
            )
        except Exception:
            return []

        if response.rcode() != dns.rcode.NOERROR:
            return []

        results = [
            str(rd.target).rstrip(".").lower()
            for rrset in response.answer
            if rrset.rdtype == dns.rdatatype.NS
            for rd in rrset
        ]
        if results:
            logger.info(
                "dns_scanner: wildcard delegation detected for %s — "
                "*.%s NS %s",
                domain, parent_str, results,
            )
        return results

    async def _query_direct(self, domain: str, nameserver: str) -> str:
        """Query domain SOA directly against nameserver (RD=0). Returns rcode string."""
        try:
            ns_ips = await resolve_to_ips(self._pool, nameserver, self._timeout)
            if not ns_ips:
                return "UNKNOWN"

            qname   = dns.name.from_text(domain)
            request = dns.message.make_query(qname, dns.rdatatype.SOA)
            request.flags &= ~dns.flags.RD

            loop = asyncio.get_running_loop()
            try:
                resp = await asyncio.wait_for(
                    loop.run_in_executor(
                        None,
                        lambda: dns.query.udp(request, random.choice(ns_ips), timeout=self._timeout),
                    ),
                    timeout=self._timeout + 1,
                )
            except asyncio.TimeoutError:
                return "TIMEOUT"

            rcode = resp.rcode()
            if rcode == dns.rcode.NOERROR:  return "NOERROR"
            if rcode == dns.rcode.NXDOMAIN: return "NXDOMAIN"
            if rcode == dns.rcode.SERVFAIL: return "SERVFAIL"
            if rcode == dns.rcode.REFUSED:  return "REFUSED"
            return dns.rcode.to_text(rcode)

        except asyncio.CancelledError:
            raise
        except Exception as exc:
            logger.debug("dns_scanner: direct query error %s@%s: %s", domain, nameserver, exc)
            return "UNKNOWN"

    async def _check_aws_ns_mismatch(
        self,
        domain:           str,
        ns:               str,
        recursive_ns_set: List[str],
    ) -> bool:
        """Detect AWS Route 53 DNS takeover via NS set mismatch."""
        try:
            ns_ips = await resolve_to_ips(self._pool, ns, self._timeout)
            if not ns_ips:
                return False

            qname   = dns.name.from_text(domain)
            request = dns.message.make_query(qname, dns.rdatatype.NS)
            request.flags &= ~dns.flags.RD

            loop = asyncio.get_running_loop()
            try:
                resp = await asyncio.wait_for(
                    loop.run_in_executor(
                        None,
                        lambda: dns.query.udp(request, random.choice(ns_ips), timeout=self._timeout),
                    ),
                    timeout=self._timeout + 1,
                )
            except asyncio.TimeoutError:
                return False

            if resp.rcode() != dns.rcode.NOERROR:
                return False

            auth_ns_set: Set[str] = set()
            for rrset in resp.answer + resp.authority:
                if rrset.rdtype == dns.rdatatype.NS:
                    auth_ns_set.update(str(rd.target).rstrip(".").lower() for rd in rrset)

            if not auth_ns_set:
                return False

            recursive_set = {n.lower() for n in recursive_ns_set}

            _MIN_NS = 4
            if len(recursive_set) < _MIN_NS or len(auth_ns_set) < _MIN_NS:
                return False

            auth_only            = auth_ns_set - recursive_set
            auth_only_awsdns     = {n for n in auth_only if _AWSDNS_PAT.search(n)}
            auth_only_non_awsdns = auth_only - auth_only_awsdns

            if not auth_only_awsdns:
                return False
            if auth_only_non_awsdns:
                return False

            # SOA verification: any SERVFAIL/NXDOMAIN = zone was deleted
            recursive_awsdns = [n for n in recursive_set if _AWSDNS_PAT.search(n)]
            if recursive_awsdns:
                soa_results = await asyncio.gather(
                    *[self._query_direct(domain, rns) for rns in recursive_awsdns],
                    return_exceptions=True,
                )
                non_err = sum(1 for r in soa_results if not isinstance(r, Exception))
                all_noerror = non_err > 0 and all(
                    r == "NOERROR"
                    for r in soa_results
                    if not isinstance(r, Exception)
                )
                if all_noerror:
                    return False

            logger.info(
                "dns_scanner: AWS NS mismatch for %s — recursive=%s auth_only=%s",
                domain, sorted(recursive_set), sorted(auth_only_awsdns),
            )
            return True

        except asyncio.CancelledError:
            raise
        except Exception as exc:
            logger.debug("dns_scanner: AWS mismatch error for %s: %s", domain, exc)
            return False

# ─────────────────────────────────────────────────────────────────────────────
# Module-level helpers for CNAME intermediate-hop availability
# ─────────────────────────────────────────────────────────────────────────────

import socket as _socket
import struct as _struct


def _cname_hop_registrable_root(domain: str) -> str:
    """
    Extract the registrable root domain from a CNAME hop hostname.

    Examples:
      old-lb.dead-partner.com  →  dead-partner.com
      cdn.example.co.uk        →  example.co.uk
      dead-partner.com         →  dead-partner.com
      a.b.c.example.com        →  example.com
    """
    domain = domain.lstrip("*").lstrip(".").lower().rstrip(".")
    if not domain or "." not in domain:
        return ""
    parts = domain.split(".")
    # Two-part TLD heuristic (.co.uk, .com.br, .org.au …)
    if len(parts) >= 3 and len(parts[-2]) <= 3 and parts[-2].isalpha():
        return ".".join(parts[-3:])
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return domain


async def _hop_domain_is_nxdomain(domain: str) -> bool:
    """
    Fast async NXDOMAIN check for a CNAME hop domain.

    Queries 1.1.1.1 and 8.8.8.8 directly via raw UDP (bypasses proxy).
    Returns True ONLY when BOTH resolvers return NXDOMAIN — prevents false
    positives from single-resolver timeouts or SERVFAIL responses.

    Does NOT run WHOIS — too slow for the hot scan path. The domain_buy_scanner
    pipeline handles the WHOIS confirmation separately.
    """
    loop = asyncio.get_running_loop()

    def _raw_nxdomain(nameserver: str) -> Optional[bool]:
        """
        Returns:
          True  — NXDOMAIN (domain does not exist)
          False — NOERROR (domain exists, even with zero A records)
          None  — timeout / network error / SERVFAIL
        """
        try:
            qname = b"".join(
                len(part).to_bytes(1, "big") + part.encode()
                for part in domain.rstrip(".").split(".")
            ) + b"\x00"
            header   = _struct.pack(">HHHHHH", 0xABCD, 0x0100, 1, 0, 0, 0)
            question = qname + _struct.pack(">HH", 1, 1)  # QTYPE=A, QCLASS=IN
            query    = header + question

            with _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM) as s:
                s.settimeout(3.0)
                s.sendto(query, (nameserver, 53))
                data, _ = s.recvfrom(512)

            if len(data) < 12:
                return None
            rcode = data[3] & 0x0F
            if rcode == 3:
                return True   # NXDOMAIN
            if rcode == 0:
                return False  # NOERROR — domain exists
            return None       # SERVFAIL or other
        except Exception:
            return None

    try:
        r1, r2 = await asyncio.gather(
            loop.run_in_executor(None, _raw_nxdomain, "1.1.1.1"),
            loop.run_in_executor(None, _raw_nxdomain, "8.8.8.8"),
        )
    except Exception:
        return False

    # Both must confirm NXDOMAIN — single-resolver timeout (None) doesn't count
    return r1 is True and r2 is True
