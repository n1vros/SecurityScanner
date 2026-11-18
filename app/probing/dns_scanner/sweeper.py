"""
app/probing/dns_scanner/sweeper.py

SubdomainNSSweeper — batch orchestrator for the NS sweep.

Drives DNSScanner.scan_subdomain() across a batch of subdomain ORM objects,
collects results, fires callbacks, and persists DB changes in bulk.

Called exclusively from daemon._ns_sweep_loop().

Timing instrumentation
──────────────────────
Every run_sweep() call is one "loop".  The scan phase is broken into nine
per-step timers that are AGGREGATED (summed) across all concurrently running
_check_one() coroutines in the batch.  Because subdomains scan in parallel
the sum can exceed t_scan wall-clock; that is expected and shows total I/O
time spent per step across the entire batch.

Scan steps (aggregated across all subdomains):
  dns_resolve    — Step 1 : A + AAAA UDP queries (parallel per subdomain)
  cname_follow   — Step 2 : CNAME chain following
  ns_check       — Step 3 : NS record resolution + vulnerability check
  ip4_analyze    — Step 4a: direct-A IPv4 dangling IP probe / liveness check
  ip6_analyze    — Step 4b: AAAA IPv6 dangling IP analysis
  cname_ip4      — Step 4c: CNAME terminal IPv4 dangling IP analysis
  mx_analyze     — Step 4d: MX target resolution + dangling IP analysis
  cname_ip6      — Step 4e: CNAME terminal IPv6 dangling IP analysis
  nxdomain_check — Step 4f: CNAME-NXDOMAIN cloud IP check via auth NS
  hop_check      — Step 4g: CNAME intermediate hop domain availability

Outer phases (wall-clock for the run_sweep() call as a whole):
  t_scan     — asyncio.gather wall-clock (the concurrent _check_one calls)
  t_process  — result iteration + callback dispatch
  t_persist  — total DB write time, broken into four sub-actions:
    stamp    — UPDATE last_ns_sweep_at (bulk IN)
    ip4      — executemany UPDATE ip_addresses
    ip6      — executemany UPDATE ipv6_addresses
    ipfree   — executemany UPDATE ip_free / ip_free_checked_at
  t_loop     — full wall-clock for the entire run_sweep() call

After every loop two INFO lines are emitted:
  [loop N timing]      — all times and counts for this call only
  [cumulative N loops] — running totals since the sweeper instance was created

IP address update policy
────────────────────────
ip_addresses and ipv6_addresses are written for every scanned subdomain,
including empty results, so the DB always reflects the latest DNS state:

  scan.ips non-empty  → write JSON array of current IPs
  scan.ips empty      → write NULL (clears stale IPs)

The same rule applies to ipv6_addresses.

NOTE: _timed_scan_with_cache replicates the step sequence of
      DNSScanner.scan_subdomain_cached() in ns_checker.py.  If that method
      gains new steps or changes ordering, update _timed_scan_with_cache too.
"""

import asyncio
import json
import time
from dataclasses import dataclass
from datetime import datetime
from typing import Callable, Dict, List, Optional, Set, Tuple

import dns.rdatatype

from app.core.config import settings
from app.core.logging import logger
from app.probing.dns_scanner.cname_follower import follow_cname_chain
from app.probing.dns_scanner.models import DanglingIPFinding, NSFinding, ScanResult
from app.probing.dns_scanner.ns_checker import DNSScanner
from app.probing.dns_scanner.resolvers import udp_query
from app.probing.ip_check import check_ip_verdict
from app.probing.ip_verdicts import (
    IPVerdict,
    aggregate_subdomain_ip_free,
    serialize_ip_verdicts,
    verdict_from_finding,
)


# ─────────────────────────────────────────────────────────────────────────────
# MX shared-provider skip-list
# ─────────────────────────────────────────────────────────────────────────────
# MX hostnames that resolve to high-availability shared mail infrastructure.
# Scanning their IPs for "dangling" status is pointless — they are never free
# — and causes the majority of the mx_analyze time cost because every subdomain
# that uses Google Workspace / Office 365 / SendGrid would trigger a full port
# scan + TLS check on the same handful of IPs, repeated for every subdomain.
#
# Matching is suffix-based (endswith) so subdomains are also caught:
#   alt1.aspmx.l.google.com  →  matches "aspmx.l.google.com"
#   mail1.smtp.sendgrid.net  →  matches "smtp.sendgrid.net"
#
# Add entries here when you see a shared provider eating mx_analyze time.
_MX_SKIP_SUFFIXES: tuple = (
    # Google Workspace / Gmail
    "aspmx.l.google.com",
    "googlemail.com",
    "smtp.google.com",
    # Microsoft / Office 365
    "mail.protection.outlook.com",
    "olc.protection.outlook.com",
    # Amazon SES
    "inbound-smtp.us-east-1.amazonaws.com",
    "inbound-smtp.us-west-2.amazonaws.com",
    "inbound-smtp.eu-west-1.amazonaws.com",
    "amazonses.com",
    # SendGrid
    "smtp.sendgrid.net",
    "sendgrid.net",
    # Mailgun
    "mxa.mailgun.org",
    "mxb.mailgun.org",
    "mailgun.org",
    # Proofpoint
    "pphosted.com",
    # Mimecast
    "mimecast.com",
    # Postmark
    "mtasv.net",
    # Mailchimp / Mandrill
    "mcsv.net",
    "mandrillapp.com",
    # Zoho
    "zoho.com",
    "zohomail.com",
    # Yahoo
    "yahoodns.net",
    # SpamExperts / Plesk
    "antispamcloud.com",
)


def _mx_host_is_shared(mx_host: str) -> bool:
    """Return True if this MX hostname belongs to known shared mail infrastructure."""
    h = mx_host.lower().rstrip(".")
    return any(h == s or h.endswith("." + s) for s in _MX_SKIP_SUFFIXES)


# ─────────────────────────────────────────────────────────────────────────────
# Per-sweep IP analysis cache
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class _CachedIPResult:
    finding:  Optional[DanglingIPFinding]
    analyzed: bool = True


class SweepIPCache:
    """
    Per-sweep cache: IP string → Optional[DanglingIPFinding].

    Prevents running port scans / HTTP probes / TLS checks on the same IP
    multiple times within a single sweep batch.  Thread-safe via asyncio Lock.
    """

    def __init__(self, sem: Optional[asyncio.Semaphore] = None) -> None:
        self._cache:      Dict[str, Optional[DanglingIPFinding]] = {}
        self._in_flight:  Dict[str, asyncio.Future]              = {}
        self._lock        = asyncio.Lock()
        self._reuse_count: int = 0
        self._sem: Optional[asyncio.Semaphore] = sem

    async def get_or_analyze(
        self,
        ip: str,
        analyze_fn,
        **kwargs,
    ) -> Optional[DanglingIPFinding]:
        async with self._lock:
            if ip in self._cache:
                self._reuse_count += 1
                return self._cache[ip]
            if ip in self._in_flight:
                fut = self._in_flight[ip]
            else:
                loop = asyncio.get_running_loop()
                fut  = loop.create_future()
                self._in_flight[ip] = fut
                fut = None

        if fut is not None:
            if self._sem is not None:
                self._sem.release()
            try:
                await asyncio.shield(fut)
            except Exception:
                pass
            finally:
                if self._sem is not None:
                    await self._sem.acquire()
            async with self._lock:
                return self._cache.get(ip)

        try:
            finding = await analyze_fn(ip=ip, **kwargs)
        except Exception as exc:
            logger.debug("sweep_cache: analysis error for %s: %s", ip, exc)
            finding = None

        async with self._lock:
            self._cache[ip] = finding
            if ip in self._in_flight:
                try:
                    self._in_flight[ip].set_result(finding)
                except asyncio.InvalidStateError:
                    pass
                del self._in_flight[ip]

        return finding

    @property
    def unique_count(self) -> int:
        return len(self._cache)

    @property
    def reuse_count(self) -> int:
        return self._reuse_count

    @property
    def hit_count(self) -> int:
        return len(self._cache)

    def already_seen(self, ip: str) -> bool:
        return ip in self._cache


# ─────────────────────────────────────────────────────────────────────────────
# _ScanStepTimings
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class _ScanStepTimings:
    """
    Aggregated (summed) wall-clock time for each of the nine scan steps across
    every subdomain processed in one run_sweep() call.

    Because subdomains run concurrently, the sum per field can exceed the
    outer t_scan wall-clock — that is intentional and shows total I/O time.
    """
    dns_resolve:    float = 0.0
    cname_follow:   float = 0.0
    ns_check:       float = 0.0
    ip4_analyze:    float = 0.0
    ip6_analyze:    float = 0.0
    cname_ip4:      float = 0.0
    mx_analyze:     float = 0.0
    cname_ip6:      float = 0.0
    nxdomain_check: float = 0.0
    hop_check:      float = 0.0

    def __iadd__(self, other: "_ScanStepTimings") -> "_ScanStepTimings":
        self.dns_resolve    += other.dns_resolve
        self.cname_follow   += other.cname_follow
        self.ns_check       += other.ns_check
        self.ip4_analyze    += other.ip4_analyze
        self.ip6_analyze    += other.ip6_analyze
        self.cname_ip4      += other.cname_ip4
        self.mx_analyze     += other.mx_analyze
        self.cname_ip6      += other.cname_ip6
        self.nxdomain_check += other.nxdomain_check
        self.hop_check      += other.hop_check
        return self

    def format(self) -> str:
        return (
            f"dns={self.dns_resolve:.2f}s "
            f"cname_follow={self.cname_follow:.2f}s "
            f"ns_check={self.ns_check:.2f}s "
            f"ip4={self.ip4_analyze:.2f}s "
            f"ip6={self.ip6_analyze:.2f}s "
            f"cname_ip4={self.cname_ip4:.2f}s "
            f"mx={self.mx_analyze:.2f}s "
            f"cname_ip6={self.cname_ip6:.2f}s "
            f"nxdomain={self.nxdomain_check:.2f}s "
            f"hops={self.hop_check:.2f}s"
        )


# ─────────────────────────────────────────────────────────────────────────────
# _PersistTimings
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class _PersistTimings:
    stamp:  float = 0.0
    ip4:    float = 0.0
    ip6:    float = 0.0
    ipfree: float = 0.0

    @property
    def total(self) -> float:
        return self.stamp + self.ip4 + self.ip6 + self.ipfree


# ─────────────────────────────────────────────────────────────────────────────
# SubdomainNSSweeper
# ─────────────────────────────────────────────────────────────────────────────

class SubdomainNSSweeper:
    """
    Batch NS sweep + dangling IP scanner.

    Usage (daemon.py):
        sweeper = SubdomainNSSweeper(scanner, concurrency=10)
        ns_count, dangling_count = await sweeper.run_sweep(
            batch,
            ns_finding_callback=self._handle_subdomain_ns_finding,
            dangling_ip_callback=self._handle_dangling_ip,
        )
    """

    def __init__(self, scanner: DNSScanner, concurrency: int = 10) -> None:
        self._scanner     = scanner
        self._concurrency = concurrency

        # Cumulative accumulators — reset only by creating a new instance.
        self._total_loops               = 0
        self._total_subdomains          = 0
        self._total_ns_findings         = 0
        self._total_dangling_findings   = 0
        self._total_t_scan              = 0.0
        self._total_t_process           = 0.0
        self._total_t_persist_stamp     = 0.0
        self._total_t_persist_ip4       = 0.0
        self._total_t_persist_ip6       = 0.0
        self._total_t_persist_ipfree    = 0.0
        self._total_t_persist           = 0.0
        self._total_t_loop              = 0.0
        self._total_scan_steps          = _ScanStepTimings()

    # ──────────────────────────────────────────────────────────────────────────
    # Public API
    # ──────────────────────────────────────────────────────────────────────────

    async def run_sweep(
        self,
        subdomains: list,
        recheck_hours:        Optional[int]      = None,
        ns_finding_callback:  Optional[Callable] = None,
        dangling_ip_callback: Optional[Callable] = None,
    ) -> Tuple[int, int]:
        """
        Sweep a batch of subdomain ORM objects.

        Returns (ns_findings_count, dangling_ip_findings_count).

        Timing summary is logged at the end of every call (per-loop + cumulative).
        """
        if recheck_hours is None:
            recheck_hours = int(getattr(settings, "NS_SWEEP_INTERVAL_HOURS", 168))

        t_loop_start = time.monotonic()
        self._total_loops += 1
        loop_num = self._total_loops

        sem      = asyncio.Semaphore(self._concurrency)
        ip_cache = SweepIPCache(sem=sem)

        # Shared accumulator for per-step scan timings — one per run_sweep call,
        # locked because every concurrent _check_one will write to it.
        loop_scan_steps = _ScanStepTimings()
        steps_lock      = asyncio.Lock()

        logger.info(
            "ns_sweep [loop %d]: %d subdomains to check",
            loop_num, len(subdomains),
        )

        # ──────────────────────────────────────────────────────────────────
        # ACTION 1 — SCAN
        # ──────────────────────────────────────────────────────────────────
        t_scan_start = time.monotonic()

        scan_results = await asyncio.gather(
            *[
                self._check_one(s, sem, ip_cache, loop_scan_steps, steps_lock)
                for s in subdomains
            ],
            return_exceptions=True,
        )

        t_scan = time.monotonic() - t_scan_start

        # ──────────────────────────────────────────────────────────────────
        # ACTION 2 — PROCESS RESULTS
        # ──────────────────────────────────────────────────────────────────
        t_process_start = time.monotonic()

        ns_count       = 0
        dangling_count = 0
        alerted_ips:     Set[str]            = set()
        checked_ids:     List[int]           = []

        # Always record the ip_addresses and ipv6_addresses for every
        # scanned subdomain, even when the result is empty (no A/AAAA records).
        #
        # Values:
        #   non-empty list → JSON string of current IPs (replaces old value)
        #   empty list     → None (NULL in DB — clears stale IPs)
        #
        # Using Optional[str] where None means "write NULL" and a string means
        # "write this JSON value".  Every scanned subdomain gets an entry.
        ip_updates:      Dict[int, Optional[str]] = {}
        ipv6_updates:    Dict[int, Optional[str]] = {}
        ip_verdict_updates: Dict[int, Optional[str]] = {}
        ip_free_updates: Dict[int, Optional[bool]] = {}

        for subdomain, result in zip(subdomains, scan_results):
            if isinstance(result, Exception):
                logger.debug("ns_sweep: error for %s: %s", subdomain.name, result)
                checked_ids.append(subdomain.id)
                continue

            scan: ScanResult = result

            # Always record ip_addresses — write NULL when empty so that
            # stale IPs from previous scans are cleared from the DB.
            ip_updates[subdomain.id] = (
                json.dumps(sorted(set(scan.ips))) if scan.ips else None
            )
            # Same logic for IPv6.
            ipv6_updates[subdomain.id] = (
                json.dumps(sorted(set(scan.ipv6s))) if scan.ipv6s else None
            )
            ip_verdict_updates[subdomain.id] = serialize_ip_verdicts(scan.ip_verdicts.values())
            ip_free_updates[subdomain.id] = scan.ip_free

            if scan.ns_finding:
                ns_count += 1
                await self._handle_ns_finding_hooks(scan.ns_finding, subdomain)
                if ns_finding_callback:
                    try:
                        await ns_finding_callback(scan.ns_finding)
                    except asyncio.CancelledError:
                        raise
                    except Exception as cb_exc:
                        logger.warning("ns_sweep: ns_finding_callback error: %s", cb_exc)

            for dip in scan.dangling_ip_findings:
                if not self._is_actionable(dip):
                    continue
                if dip.ip in alerted_ips:
                    logger.debug(
                        "ns_sweep: dedup — %s already alerted for ip=%s this sweep",
                        subdomain.name, dip.ip,
                    )
                    continue
                alerted_ips.add(dip.ip)
                dangling_count += 1
                if dangling_ip_callback:
                    try:
                        await dangling_ip_callback(dip)
                    except asyncio.CancelledError:
                        raise
                    except Exception as cb_exc:
                        logger.warning("ns_sweep: dangling_ip_callback error: %s", cb_exc)

            checked_ids.append(subdomain.id)

        t_process = time.monotonic() - t_process_start

        logger.info(
            "ns_sweep [loop %d]: ip_cache unique_ips_analyzed=%d cache_reuses=%d",
            loop_num, ip_cache.unique_count, ip_cache.reuse_count,
        )

        # ──────────────────────────────────────────────────────────────────
        # ACTION 3 — PERSIST
        # ──────────────────────────────────────────────────────────────────
        t_persist_start = time.monotonic()

        persist_timings = await self._persist(
            checked_ids=checked_ids,
            ip_updates=ip_updates,
            ipv6_updates=ipv6_updates,
            ip_verdict_updates=ip_verdict_updates,
            ip_free_updates=ip_free_updates,
        )

        t_persist = time.monotonic() - t_persist_start

        # ── Update cumulative accumulators ─────────────────────────────────
        t_loop = time.monotonic() - t_loop_start

        self._total_subdomains        += len(subdomains)
        self._total_ns_findings       += ns_count
        self._total_dangling_findings += dangling_count
        self._total_t_scan            += t_scan
        self._total_t_process         += t_process
        self._total_t_persist_stamp   += persist_timings.stamp
        self._total_t_persist_ip4     += persist_timings.ip4
        self._total_t_persist_ip6     += persist_timings.ip6
        self._total_t_persist_ipfree  += persist_timings.ipfree
        self._total_t_persist         += t_persist
        self._total_t_loop            += t_loop
        self._total_scan_steps        += loop_scan_steps

        # ── Per-loop timing summary ────────────────────────────────────────
        logger.info(
            "ns_sweep [loop %d timing]  "
            "scan_wall=%.2fs  scan_steps=[%s]  "
            "process=%.2fs  "
            "persist=%.2fs (stamp=%.2fs ip4=%.2fs ip6=%.2fs ipfree=%.2fs)  "
            "total_wall=%.2fs  |  "
            "subdomains=%d ns_findings=%d dangling_findings=%d",
            loop_num,
            t_scan, loop_scan_steps.format(),
            t_process,
            t_persist,
            persist_timings.stamp, persist_timings.ip4,
            persist_timings.ip6, persist_timings.ipfree,
            t_loop,
            len(subdomains), ns_count, dangling_count,
        )

        # ── Cumulative timing summary ──────────────────────────────────────
        logger.info(
            "ns_sweep [cumulative %d loop(s)]  "
            "scan_wall=%.2fs  scan_steps=[%s]  "
            "process=%.2fs  "
            "persist=%.2fs (stamp=%.2fs ip4=%.2fs ip6=%.2fs ipfree=%.2fs)  "
            "total_wall=%.2fs  |  "
            "subdomains=%d ns_findings=%d dangling_findings=%d",
            loop_num,
            self._total_t_scan, self._total_scan_steps.format(),
            self._total_t_process,
            self._total_t_persist,
            self._total_t_persist_stamp, self._total_t_persist_ip4,
            self._total_t_persist_ip6, self._total_t_persist_ipfree,
            self._total_t_loop,
            self._total_subdomains,
            self._total_ns_findings,
            self._total_dangling_findings,
        )

        return ns_count, dangling_count

    # ──────────────────────────────────────────────────────────────────────────
    # _check_one — scans one subdomain, accumulates step timings
    # ──────────────────────────────────────────────────────────────────────────

    @staticmethod
    def _is_actionable(dip: DanglingIPFinding) -> bool:
        return (
            dip.confirmed_free
            or dip.foreign_tls_cert
            or dip.cloud_claim_confirmed
        )

    async def _check_one(
        self,
        subdomain,
        sem:             asyncio.Semaphore,
        ip_cache:        SweepIPCache,
        loop_scan_steps: _ScanStepTimings,
        steps_lock:      asyncio.Lock,
    ) -> ScanResult:
        """
        Scan one subdomain under the global concurrency semaphore.
        """
        async with sem:
            scope_domain = subdomain.scope.domain if subdomain.scope else ""
            program_name = (
                subdomain.scope.program.name
                if subdomain.scope and subdomain.scope.program else "unknown"
            )
            platform = (
                subdomain.scope.program.platform.value
                if subdomain.scope and subdomain.scope.program else "unknown"
            )
            try:
                result, step_timings = await self._timed_scan_with_cache(
                    subdomain=subdomain,
                    scope_domain=scope_domain,
                    program_name=program_name,
                    platform=platform,
                    ip_cache=ip_cache,
                )
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                logger.debug("ns_sweep: scan error for %s: %s", subdomain.name, exc)
                return ScanResult(subdomain_name=subdomain.name)

        async with steps_lock:
            loop_scan_steps += step_timings

        return result

    # ──────────────────────────────────────────────────────────────────────────
    # _timed_scan_with_cache — replicates scan_subdomain_cached step-by-step
    # ──────────────────────────────────────────────────────────────────────────

    async def _timed_scan_with_cache(
        self,
        subdomain,
        scope_domain: str,
        program_name: str,
        platform:     str,
        ip_cache:     SweepIPCache,
    ) -> Tuple[ScanResult, _ScanStepTimings]:
        """
        Performs the same nine-step sequence as DNSScanner.scan_subdomain_cached()
        but wraps each step in time.monotonic() calls so per-step elapsed time
        is captured for every subdomain.

        Returns (ScanResult, _ScanStepTimings).
        """
        st      = _ScanStepTimings()
        scanner = self._scanner
        result  = ScanResult(subdomain_name=subdomain.name)

        # ── Step 1: A + AAAA resolution ───────────────────────────────────
        _t = time.monotonic()

        a_resp, aaaa_resp = await asyncio.gather(
            udp_query(scanner._pool, subdomain.name, dns.rdatatype.A),
            udp_query(scanner._pool, subdomain.name, dns.rdatatype.AAAA),
        )

        st.dns_resolve = time.monotonic() - _t

        has_cname   = False
        direct_ips: List[str] = []
        ipv6s:      List[str] = []

        if a_resp is not None and a_resp.rcode() == 0:
            for rrset in a_resp.answer:
                if rrset.rdtype == dns.rdatatype.CNAME:
                    has_cname = True
                if rrset.rdtype == dns.rdatatype.A:
                    direct_ips.extend(str(r) for r in rrset)

        if aaaa_resp is not None and aaaa_resp.rcode() == 0:
            for rrset in aaaa_resp.answer:
                if rrset.rdtype == dns.rdatatype.AAAA:
                    ipv6s.extend(str(r) for r in rrset)

        result.ips       = sorted(set(direct_ips))
        result.ipv6s     = sorted(set(ipv6s))
        result.has_cname = has_cname

        # ── Step 2: CNAME chain following ────────────────────────────────
        _t = time.monotonic()

        cname_chain:       List[str] = []
        cname_ips:         List[str] = []
        cname_ipv6s:       List[str] = []
        cname_terminal:    Optional[str] = None
        cname_is_nxdomain: bool = False

        if has_cname and a_resp is not None and scanner._cname_follow:
            cname_chain, cname_ips, cname_ipv6s, cname_is_nxdomain = \
                await follow_cname_chain(
                    subdomain_name=subdomain.name,
                    initial_response=a_resp,
                    pool=scanner._pool,
                    timeout=scanner._timeout,
                )
            if cname_chain:
                result.cname_chain = cname_chain
                cname_terminal     = cname_chain[-1]

        st.cname_follow = time.monotonic() - _t

        # ── Step 3: NS takeover check ─────────────────────────────────────
        _t = time.monotonic()

        nameservers = await scanner._get_nameservers(subdomain.name)
        if nameservers:
            ns_findings = await scanner._check_all_ns(
                domain=subdomain.name,
                nameservers=nameservers,
                scope_domain=scope_domain,
                program_name=program_name,
                platform=platform,
            )
            if ns_findings:
                result.ns_finding = ns_findings[0]

        st.ns_check = time.monotonic() - _t

        # ── Step 4a: Dangling IP — direct A records (IPv4) ────────────────
        _t = time.monotonic()

        ip_verdicts: Dict[str, IPVerdict] = {}

        for ip in result.ips:
            ft      = "cname_dangling" if has_cname else "dangling"
            finding = await ip_cache.get_or_analyze(
                ip=ip,
                analyze_fn=scanner._ip_analyzer.analyze,
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

        st.ip4_analyze = time.monotonic() - _t

        # ── Step 4b: Dangling IP — AAAA records (IPv6) ───────────────────
        _t = time.monotonic()

        if result.ipv6s:
            for ip6 in result.ipv6s:
                finding = await ip_cache.get_or_analyze(
                    ip=ip6,
                    analyze_fn=scanner._ip_analyzer.analyze,
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

        st.ip6_analyze = time.monotonic() - _t

        # ── Step 4c: Dangling IP — CNAME terminal IPv4 ───────────────────
        _t = time.monotonic()

        if cname_ips:
            if not scanner._cidr_index:
                logger.warning(
                    "ns_sweep: cidr_index is None — skipping CNAME terminal IP "
                    "analysis for %s (chain=%s). Rebuild CIDR index to enable.",
                    subdomain.name, cname_chain,
                )
            else:
                for ip in cname_ips:
                    finding = await ip_cache.get_or_analyze(
                        ip=ip,
                        analyze_fn=scanner._ip_analyzer.analyze,
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

        st.cname_ip4 = time.monotonic() - _t

        # ── Step 4d: Dangling IP — MX record targets ──────────────────────
        #
        # shared-provider skip:
        #   MX hosts belonging to Google, Microsoft, SendGrid, etc. are shared
        #   infrastructure that is never unallocated.
        #
        # SweepIPCache routing:
        #   All MX IPs now go through ip_cache.get_or_analyze() so an IP is
        #   only probed once per sweep regardless of how many subdomains share
        #   the same mail server.
        _t = time.monotonic()

        if scanner._mx_check:
            mx_resp = await udp_query(
                scanner._pool, subdomain.name, dns.rdatatype.MX, scanner._timeout
            )
            if mx_resp is not None and mx_resp.rcode() == 0:
                mx_hosts: List[str] = []
                for rrset in mx_resp.answer:
                    if rrset.rdtype == dns.rdatatype.MX:
                        for rdata in rrset:
                            host = str(rdata.exchange).rstrip(".").lower()
                            if host and host != ".":
                                mx_hosts.append(host)

                for mx_host in mx_hosts:
                    if _mx_host_is_shared(mx_host):
                        logger.debug(
                            "ns_sweep: skipping shared MX host %s for %s",
                            mx_host, subdomain.name,
                        )
                        continue

                    a_mx, aaaa_mx = await asyncio.gather(
                        udp_query(scanner._pool, mx_host, dns.rdatatype.A,    scanner._timeout),
                        udp_query(scanner._pool, mx_host, dns.rdatatype.AAAA, scanner._timeout),
                    )

                    mx_ips: List[str] = []
                    if a_mx is not None and a_mx.rcode() == 0:
                        for rrset in a_mx.answer:
                            if rrset.rdtype == dns.rdatatype.A:
                                mx_ips.extend(str(r) for r in rrset)
                    if aaaa_mx is not None and aaaa_mx.rcode() == 0:
                        for rrset in aaaa_mx.answer:
                            if rrset.rdtype == dns.rdatatype.AAAA:
                                mx_ips.extend(str(r) for r in rrset)

                    for ip in mx_ips:
                        finding = await ip_cache.get_or_analyze(
                            ip=ip,
                            analyze_fn=scanner._ip_analyzer.analyze,
                            subdomain_name=subdomain.name,
                            scope_domain=scope_domain,
                            program_name=program_name,
                            platform=platform,
                            finding_type="mx_dangling",
                        )
                        if finding is not None and (
                            finding.confirmed_free or finding.foreign_tls_cert
                        ):
                            finding.indicators.append(
                                f"IP reached via MX record: {subdomain.name} MX → {mx_host} → {ip}"
                            )
                            result.dangling_ip_findings.append(finding)

        st.mx_analyze = time.monotonic() - _t

        # ── Step 4e: Dangling IP — CNAME terminal IPv6 ───────────────────
        _t = time.monotonic()

        if cname_ipv6s:
            if not scanner._cidr_index:
                logger.warning(
                    "ns_sweep: cidr_index is None — skipping CNAME terminal "
                    "IPv6 analysis for %s", subdomain.name,
                )
            else:
                for ip6 in cname_ipv6s:
                    finding = await ip_cache.get_or_analyze(
                        ip=ip6,
                        analyze_fn=scanner._ip_analyzer.analyze,
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

        st.cname_ip6 = time.monotonic() - _t

        # ── Step 4f: CNAME NXDOMAIN target — resolve via authoritative NS ─
        _t = time.monotonic()

        if cname_is_nxdomain and cname_terminal and scanner._cidr_index:
            nxd_findings = await scanner._check_cname_nxdomain_target(
                subdomain_name=subdomain.name,
                cname_terminal=cname_terminal,
                cname_chain=cname_chain,
                scope_domain=scope_domain,
                program_name=program_name,
                platform=platform,
            )
            result.dangling_ip_findings.extend(nxd_findings)

        st.nxdomain_check = time.monotonic() - _t

        # ── Step 4g: CNAME intermediate hop domain availability ───────────
        _t = time.monotonic()

        if cname_chain and len(cname_chain) > 1:
            hop_findings = await scanner._check_cname_intermediate_hops(
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

        st.hop_check = time.monotonic() - _t

        # ── Aggregate ip_free (IPv4 only) ─────────────────────────────────
        result.ip_verdicts = ip_verdicts
        result.ip_free = aggregate_subdomain_ip_free(ip_verdicts.values())

        return result, st

    # ──────────────────────────────────────────────────────────────────────────
    # NS finding hooks
    # ──────────────────────────────────────────────────────────────────────────

    async def _handle_ns_finding_hooks(
        self, finding: NSFinding, subdomain
    ) -> None:
        """
        Enqueue provider-specific NS takeover attempts.
        """
        ns           = finding.nameserver
        program_name = finding.program_name
        platform     = finding.platform
        scope_id     = getattr(subdomain, "scope_id", 0)

        # ── AWS Route 53 NS lottery ───────────────────────────────────────────
        if "awsdns" in ns.lower():
            try:
                from app.takeover.subdomain_hunter.providers.aws_route53 import Route53TakeoverQueue
                await Route53TakeoverQueue.enqueue(
                    subdomain_id=subdomain.id,
                    subdomain_name=finding.subdomain_name,
                    nameservers=finding.all_nameservers,
                    program_name=program_name,
                    platform=platform,
                    scope_id=scope_id,
                    is_parent=False,
                )
            except Exception as exc:
                logger.error(
                    "ns_sweep: Route53TakeoverQueue.enqueue failed for %s: %s",
                    finding.subdomain_name, exc, exc_info=True,
                )

        # ── Azure DNS NS lottery ──────────────────────────────────────────────
        if "azure-dns" in ns.lower():
            try:
                import re as _re
                from app.takeover.ns_hunter.providers.azure_dns_takeover import AzureDNSTakeoverQueue
                _m = _re.search(r"ns\d+-(\d+)\.azure-dns", ns, _re.IGNORECASE)
                target_shard = _m.group(1) if _m else ns.split(".")[0]
                AzureDNSTakeoverQueue.enqueue(
                    subdomain=subdomain,
                    target_shard=target_shard,
                    program_name=program_name,
                    platform=platform,
                )
            except Exception as exc:
                logger.error(
                    "ns_sweep: AzureDNSTakeoverQueue.enqueue failed for %s: %s",
                    finding.subdomain_name, exc, exc_info=True,
                )

        # ── GCP Cloud DNS NS lottery ──────────────────────────────────────────
        if "googledomains.com" in ns.lower():
            try:
                from app.takeover.ns_hunter.providers.gcp_dns_takeover import GCPDNSTakeoverQueue
                GCPDNSTakeoverQueue.enqueue(
                    subdomain=subdomain,
                    target_ns_set=finding.all_nameservers,
                    program_name=program_name,
                    platform=platform,
                )
            except Exception as exc:
                logger.error(
                    "ns_sweep: GCPDNSTakeoverQueue.enqueue failed for %s: %s",
                    finding.subdomain_name, exc, exc_info=True,
                )

    # ──────────────────────────────────────────────────────────────────────────
    # Persistence — four sub-actions, individually timed
    # ──────────────────────────────────────────────────────────────────────────

    async def _persist(
        self,
        checked_ids:     List[int],
        ip_updates:      Dict[int, Optional[str]],
        ipv6_updates:    Dict[int, Optional[str]],
        ip_verdict_updates: Dict[int, Optional[str]],
        ip_free_updates: Dict[int, Optional[bool]],
    ) -> _PersistTimings:
        """
        Write all collected data to the database in five separately timed steps.

        ip_updates and ipv6_updates now use Optional[str] where:
          - A non-None string is written as-is (JSON array of IPs)
          - None is written as SQL NULL (clears stale IPs)

        This ensures stale IP addresses are removed when a subdomain no longer
        has A/AAAA records, rather than persisting indefinitely.

        Returns _PersistTimings so run_sweep() can include the breakdown in logs.
        """
        from sqlalchemy import update, bindparam, text as _text
        from app.db.db_models import Subdomain
        from app.db.session import get_session

        timings = _PersistTimings()
        now     = datetime.utcnow()

        _t = time.monotonic()
        if checked_ids:
            try:
                async with get_session() as session:
                    await session.execute(
                        update(Subdomain)
                        .where(Subdomain.id.in_(checked_ids))
                        .values(last_ns_sweep_at=now),
                        execution_options={"synchronize_session": False},
                    )
                    await session.commit()
                logger.debug(
                    "ns_sweep: stamped last_ns_sweep_at for %d subdomains",
                    len(checked_ids),
                )
            except Exception as exc:
                logger.warning("ns_sweep: failed to stamp last_ns_sweep_at: %s", exc)
        timings.stamp = time.monotonic() - _t
        _t = time.monotonic()
        if ip_updates:
            try:
                non_null_rows = [
                    {"_id": sid, "_ips": ips}
                    for sid, ips in ip_updates.items()
                    if ips is not None
                ]
                null_ids = [
                    sid for sid, ips in ip_updates.items()
                    if ips is None
                ]

                async with get_session() as session:
                    conn = await session.connection()
                    if non_null_rows:
                        await conn.execute(
                            update(Subdomain)
                            .where(Subdomain.id == bindparam("_id"))
                            .values(ip_addresses=bindparam("_ips")),
                            non_null_rows,
                        )
                    if null_ids:
                        await conn.execute(
                            update(Subdomain)
                            .where(Subdomain.id.in_(null_ids))
                            .values(ip_addresses=None),
                            execution_options={"synchronize_session": False},
                        )
                    await session.commit()

                logger.debug(
                    "ns_sweep: updated ip_addresses for %d subdomains "
                    "(%d with IPs, %d cleared to NULL)",
                    len(ip_updates),
                    len(non_null_rows),
                    len(null_ids),
                )
            except Exception as exc:
                logger.warning("ns_sweep: failed to persist ip_addresses: %s", exc)
        timings.ip4 = time.monotonic() - _t

        _t = time.monotonic()
        if ipv6_updates:
            try:
                non_null_rows6 = [
                    {"_id": sid, "_ips6": ips6}
                    for sid, ips6 in ipv6_updates.items()
                    if ips6 is not None
                ]
                null_ids6 = [
                    sid for sid, ips6 in ipv6_updates.items()
                    if ips6 is None
                ]

                async with get_session() as session:
                    conn = await session.connection()
                    if non_null_rows6:
                        await conn.execute(
                            update(Subdomain)
                            .where(Subdomain.id == bindparam("_id"))
                            .values(ipv6_addresses=bindparam("_ips6")),
                            non_null_rows6,
                        )
                    if null_ids6:
                        await conn.execute(
                            update(Subdomain)
                            .where(Subdomain.id.in_(null_ids6))
                            .values(ipv6_addresses=None),
                            execution_options={"synchronize_session": False},
                        )
                    await session.commit()

                logger.debug(
                    "ns_sweep: updated ipv6_addresses for %d subdomains "
                    "(%d with IPs, %d cleared to NULL)",
                    len(ipv6_updates),
                    len(non_null_rows6),
                    len(null_ids6),
                )
            except Exception as exc:
                logger.warning("ns_sweep: failed to persist ipv6_addresses: %s", exc)
        timings.ip6 = time.monotonic() - _t

        _t = time.monotonic()
        if ip_verdict_updates:
            try:
                non_null_rows = [
                    {"_id": sid, "_verdicts": verdicts}
                    for sid, verdicts in ip_verdict_updates.items()
                    if verdicts is not None
                ]
                null_ids = [
                    sid for sid, verdicts in ip_verdict_updates.items()
                    if verdicts is None
                ]

                async with get_session() as session:
                    conn = await session.connection()
                    if non_null_rows:
                        await conn.execute(
                            update(Subdomain)
                            .where(Subdomain.id == bindparam("_id"))
                            .values(ip_verdicts=bindparam("_verdicts")),
                            non_null_rows,
                        )
                    if null_ids:
                        await conn.execute(
                            update(Subdomain)
                            .where(Subdomain.id.in_(null_ids))
                            .values(ip_verdicts=None),
                            execution_options={"synchronize_session": False},
                        )
                    await session.commit()

                logger.debug(
                    "ns_sweep: updated ip_verdicts for %d subdomains "
                    "(%d with verdicts, %d cleared to NULL)",
                    len(ip_verdict_updates),
                    len(non_null_rows),
                    len(null_ids),
                )
            except Exception as exc:
                logger.warning("ns_sweep: failed to persist ip_verdicts: %s", exc)

        _t = time.monotonic()
        if ip_free_updates:
            rows = [
                {"_id": sid, "_free": val, "_checked_at": now}
                for sid, val in ip_free_updates.items()
            ]
            if rows:
                try:
                    async with get_session() as session:
                        conn = await session.connection()
                        await conn.execute(
                            update(Subdomain)
                            .where(Subdomain.id == bindparam("_id"))
                            .values(
                                ip_free=bindparam("_free"),
                                ip_free_checked_at=bindparam("_checked_at"),
                            ),
                            rows,
                        )
                        await session.commit()
                    logger.debug(
                        "ns_sweep: updated ip_free for %d subdomains "
                        "(free=%d taken=%d inconclusive=%d) (bulk)",
                        len(rows),
                        sum(1 for r in rows if r["_free"] is True),
                        sum(1 for r in rows if r["_free"] is False),
                        sum(1 for r in rows if r["_free"] is None),
                    )
                except Exception as exc:
                    logger.warning("ns_sweep: failed to persist ip_free: %s", exc)
        timings.ipfree = time.monotonic() - _t

        return timings
