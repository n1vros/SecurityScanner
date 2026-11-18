"""
app/takeover/ip_hunter/hunter.py

IP takeover hunter — active allocation orchestrator (TAKEOVER mode only).

Architecture — independent per-provider loops
──────────────────────────────────────────────
Each provider (AWS / GCP / Azure / DO) runs as a completely independent
asyncio coroutine with its own sleep cycle. A separate verifier loop refreshes
the per-IP free verdicts before and during hunting. When run() is called it
first verifies the currently-tracked free IPv4 set, then launches the verifier
plus all four provider loops concurrently via asyncio.gather and never returns
(until cancelled). Each provider:

  1. Loads ALL target IPs fresh from DB each cycle.
  2. Refreshes its confirmed-free IPv4 candidates from DB verdict storage.
  3. Refreshes CIDR index if stale.
  4. Rolls only regions containing confirmed-free IPv4 targets.
  5. Notifies on any hit.
  6. Sleeps IP_HUNTER_INTERVAL_HOURS before repeating.

Provider loops are completely isolated — one provider being slow or erroring
has zero effect on the others.

Per-provider kill switches (.env):
  AWS_EIP_ENABLED      bool    default True
  GCP_EIP_ENABLED      bool    default True
  AZURE_PIP_ENABLED    bool    default True
  DO_EIP_ENABLED       bool    default True

Config keys (.env):
  IP_HUNTER_MODE               str     default "off"   (off|takeover)
  IP_HUNTER_ENABLED            bool    default False    (legacy → mode=takeover)
  IP_HUNTER_INTERVAL_HOURS     float   default 0.5     per-provider sleep between cycles
  IP_HUNTER_ATTEMPTS_PER_BLOCK int     default 50      attempts per region (AWS/DO/Azure)

Stale IP handling
─────────────────
When a DNS recheck confirms that a subdomain no longer resolves to an IP we
just claimed:

  1. Perform a live DNS A-record lookup for each affected subdomain.
  2. Write the current IP set back to ip_addresses (replacing the old value).
     If the subdomain no longer resolves at all, ip_addresses is set to NULL.
  3. Clear stale per-IP verdicts so the verifier rebuilds them from live DNS.
  4. Log the before/after for observability.

This keeps the DB in sync with the latest DNS state instead of accumulating
stale entries or missing new IPs.

Daemon integration:
  The daemon's _ip_hunter_loop simply awaits run() — it loops forever
  internally, so no outer while-loop or sleep is needed in the daemon.
"""

import asyncio
import ipaddress
import json
import socket
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional, Set

from app.core.config import settings
from app.core.logging import logger
from app.probing.dns_scanner.ip_analyzer import DanglingIPAnalyzer
from app.probing.dns_scanner.resolvers import get_pool as get_dns_pool, resolve_to_ips
from app.probing.ip_check import check_ip_verdict
from app.probing.ip_verdicts import (
    IPVerdict,
    IPVerdictStatus,
    aggregate_subdomain_ip_free,
    filter_current_ip_verdicts,
    load_ip_verdicts,
    serialize_ip_verdicts,
    verdict_from_finding,
)
from app.takeover.ip_hunter.cidr_index import CIDRIndex, get_index


# ──────────────────────────────────────────────────────────────────────────────
# Mode enum
# ──────────────────────────────────────────────────────────────────────────────

class IPHunterMode(str, Enum):
    OFF      = "off"
    TAKEOVER = "takeover"


# ──────────────────────────────────────────────────────────────────────────────
# Result dataclass
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class ProviderHuntResult:
    provider:          str
    region:            str
    hit:               bool
    hit_ip:            Optional[str]  = None
    hit_subdomain_ids: List[int]      = field(default_factory=list)
    attempts:          int            = 0
    error:             Optional[str]  = None
    program_name:      str            = "unknown"
    platform:          str            = "unknown"
    scope_url:         str            = ""


@dataclass
class FreeIPTarget:
    ip:               str
    provider:         str
    regions:          Set[str]        = field(default_factory=set)
    subdomain_ids:    Set[int]        = field(default_factory=set)
    subdomain_names:  Set[str]        = field(default_factory=set)


@dataclass
class VerificationTarget:
    subdomain_id:     int
    subdomain_name:   str
    stored_ips:       List[str]                 = field(default_factory=list)
    stored_verdicts:  Dict[str, IPVerdict]      = field(default_factory=dict)
    scope_domain:     str                       = ""
    program_name:     str                       = "unknown"
    platform:         str                       = "unknown"
    aggregate_ip_free: Optional[bool]           = None


# ──────────────────────────────────────────────────────────────────────────────
# IPHunter
# ──────────────────────────────────────────────────────────────────────────────

class IPHunter:

    def __init__(self) -> None:
        mode_raw = getattr(settings, "IP_HUNTER_MODE", "off")
        legacy   = getattr(settings, "IP_HUNTER_ENABLED", False)
        if legacy and mode_raw == "off":
            mode_raw = "takeover"
        try:
            self._mode = IPHunterMode(mode_raw.lower())
        except ValueError:
            logger.warning("ip_hunter: unknown IP_HUNTER_MODE=%r — defaulting to off", mode_raw)
            self._mode = IPHunterMode.OFF

        self._attempts    = int(getattr(settings, "IP_HUNTER_ATTEMPTS_PER_BLOCK", 50))
        self._cidr_index: Optional[CIDRIndex] = None
        self._ip_analyzer = DanglingIPAnalyzer(cidr_index=None)
        self._all_targets: Set[str] = set()
        self._free_ip_targets: Dict[str, Dict[str, FreeIPTarget]] = {
            "aws": {},
            "do": {},
            "azure": {},
            "gcp": {},
        }

    # ── Public entry point ────────────────────────────────────────────────────

    async def run(self) -> None:
        """
        Start all provider loops as concurrent independent infinite tasks.
        Never returns (runs until cancelled).
        """
        if self._mode == IPHunterMode.OFF:
            logger.info("ip_hunter: disabled (IP_HUNTER_MODE=off)")
            return

        await self._ensure_cidr_index()
        await self._verify_free_ip_targets_once()

        logger.info(
            "ip_hunter: starting independent per-provider loops "
            "(interval=%.1fh each)",
            float(getattr(settings, "IP_HUNTER_INTERVAL_HOURS", 0.5)),
        )

        await asyncio.gather(
            self._free_ip_verifier_loop(),
            self._provider_loop("aws"),
            self._provider_loop("do"),
            self._provider_loop("azure"),
            self._provider_loop("gcp"),
            return_exceptions=True,
        )

    async def _free_ip_verifier_loop(self) -> None:
        """
        Independent loop that re-validates tracked free IPv4 verdicts against
        live DNS and stamps the latest per-IP state back into the DB.
        """
        interval_hours = float(getattr(settings, "IP_HUNTER_INTERVAL_HOURS", 0.5))
        interval_secs = interval_hours * 3600

        logger.info(
            "ip_hunter: free-ip verifier loop started (interval=%.1fh)",
            interval_hours,
        )

        while True:
            try:
                await self._verify_free_ip_targets_once()
            except asyncio.CancelledError:
                logger.info("ip_hunter: free-ip verifier loop cancelled")
                raise
            except Exception as exc:
                logger.error(
                    "ip_hunter: free-ip verifier loop error: %s",
                    exc,
                    exc_info=True,
                )

            await asyncio.sleep(interval_secs)

    # ── Per-provider independent loop ─────────────────────────────────────────

    async def _provider_loop(self, provider: str) -> None:
        """
        Independent infinite loop for one provider.
        """
        interval_hours = float(getattr(settings, "IP_HUNTER_INTERVAL_HOURS", 0.5))
        interval_secs  = interval_hours * 3600

        logger.info("ip_hunter: [%s] independent loop started (interval=%.1fh)", provider, interval_hours)

        while True:
            try:
                # ── Refresh CIDR index (shared, best-effort) ──────────────────
                await self._ensure_cidr_index(provider)

                # ── Load fresh target IPs and free-IP candidates ─────────────
                targets = await self._load_all_ips()
                await self._refresh_free_ip_targets(provider)

                if not targets:
                    logger.info(
                        "ip_hunter: [%s] no IPs in DB — skipping this cycle",
                        provider,
                    )
                else:
                    self._all_targets = targets
                    free_targets = self._free_ip_targets[provider]
                    if not free_targets:
                        logger.info(
                            "ip_hunter: [%s] no confirmed-free IPv4 targets — "
                            "skipping hunt loop to avoid cost abuse",
                            provider,
                        )
                        await self._recheck_free_ip_targets(provider)
                        logger.info(
                            "ip_hunter: [%s] sleeping %.1fh before next cycle",
                            provider, interval_hours,
                        )
                        await asyncio.sleep(interval_secs)
                        continue
                    logger.info(
                        "ip_hunter: [%s] cycle starting — %d target IPs, %d free-IP candidates",
                        provider, len(targets), len(free_targets),
                    )

                    # ── Run provider hunt ─────────────────────────────────────
                    results: List[ProviderHuntResult] = []
                    try:
                        if provider == "aws":
                            results = await self._run_aws()
                        elif provider == "do":
                            results = await self._run_do()
                        elif provider == "azure":
                            results = await self._run_azure()
                        elif provider == "gcp":
                            results = await self._run_gcp()
                    except asyncio.CancelledError:
                        raise
                    except Exception as exc:
                        logger.error(
                            "ip_hunter: [%s] hunt error: %s",
                            provider, exc, exc_info=True,
                        )

                    # ── Process results ───────────────────────────────────────
                    hits = 0
                    for r in results:
                        if not r.hit:
                            await self._persist_result(r)
                            continue

                        # ── DNS recheck before celebrating ────────────────────
                        sub_names = await self._subdomain_names_for_ids(r.hit_subdomain_ids)
                        still_live = await self._dns_recheck(r.hit_ip, sub_names)

                        if still_live:
                            hits += 1
                            self._free_ip_targets[provider].pop(r.hit_ip or "", None)
                            await self._persist_result(r)
                            await self._notify_hit(r)
                            logger.info(
                                "ip_hunter: HIT [%s/%s] ip=%s — DNS confirmed live",
                                r.provider, r.region, r.hit_ip,
                            )
                        else:
                            logger.info(
                                "ip_hunter: HIT [%s/%s] ip=%s — DNS recheck: "
                                "IP no longer in A records, refreshing DB with current IPs",
                                r.provider, r.region, r.hit_ip,
                            )
                            self._free_ip_targets[provider].pop(r.hit_ip or "", None)
                            # refresh with current live IPs instead of only removing the stale one
                            await self._refresh_ips_from_dns(r.hit_ip, r.hit_subdomain_ids, sub_names)

                    await self._recheck_free_ip_targets(provider)
                    logger.info(
                        "ip_hunter: [%s] cycle complete — %d hit(s) across %d result(s)",
                        provider, hits, len(results),
                    )

            except asyncio.CancelledError:
                logger.info("ip_hunter: [%s] loop cancelled", provider)
                raise
            except Exception as exc:
                logger.error(
                    "ip_hunter: [%s] unexpected loop error: %s",
                    provider, exc, exc_info=True,
                )

            logger.info(
                "ip_hunter: [%s] sleeping %.1fh before next cycle",
                provider, interval_hours,
            )
            await asyncio.sleep(interval_secs)

    # ── IP loading ────────────────────────────────────────────────────────────

    async def _load_all_ips(self) -> Set[str]:
        """
        Return every unique IPv4 address currently in the DB.
        """
        from sqlalchemy import select
        from app.db.db_models import Subdomain
        from app.db.session import get_session

        targets: Set[str] = set()
        async with get_session() as session:
            result = await session.execute(
                select(Subdomain.ip_addresses)
                .where(Subdomain.ip_addresses.isnot(None))
            )
            rows = result.scalars().all()

        for ip_json in rows:
            try:
                if isinstance(ip_json, list):
                    ips = ip_json
                elif isinstance(ip_json, str):
                    ips = json.loads(ip_json)
                else:
                    continue
            except (json.JSONDecodeError, TypeError):
                continue
            for ip in ips:
                try:
                    ipaddress.IPv4Address(ip)
                    targets.add(ip)
                except ValueError:
                    continue

        return targets

    async def _load_free_ip_targets(self, provider: str) -> Dict[str, FreeIPTarget]:
        """
        Return currently tracked FREE IPv4 verdicts for the requested provider.

        This is intentionally per-IP, not per-subdomain aggregate state. A
        multi-A subdomain can contain one free IP and one taken IP; the hunter
        should still pursue the free address without that host-level mix
        contaminating the candidate set.
        """
        from sqlalchemy import select
        from app.db.db_models import Subdomain
        from app.db.session import get_session

        candidates: Dict[str, FreeIPTarget] = {}
        async with get_session() as session:
            result = await session.execute(
                select(Subdomain.id, Subdomain.name, Subdomain.ip_addresses, Subdomain.ip_verdicts)
                .where(Subdomain.ip_addresses.isnot(None))
                .where(Subdomain.ip_verdicts.isnot(None))
            )
            rows = result.all()

        for subdomain_id, subdomain_name, ip_json, verdict_json in rows:
            ips = self._parse_ipv4_json(ip_json)
            if not ips:
                continue
            verdicts = filter_current_ip_verdicts(ips, load_ip_verdicts(verdict_json))
            if not verdicts:
                continue

            for ip in ips:
                verdict = verdicts.get(ip)
                if verdict is None or verdict.status != IPVerdictStatus.FREE:
                    continue

                if not self._cidr_index:
                    continue
                match = self._cidr_index.lookup(ip)
                if not match or not self._provider_matches(provider, match.provider):
                    continue

                target = candidates.setdefault(
                    ip,
                    FreeIPTarget(ip=ip, provider=provider),
                )
                if match.region:
                    target.regions.add(match.region)
                target.subdomain_ids.add(int(subdomain_id))
                if subdomain_name:
                    target.subdomain_names.add(subdomain_name)

        return candidates

    async def _load_subdomains_needing_ip_verification(self) -> List[VerificationTarget]:
        """
        Return subdomains that still have tracked free-IP state requiring
        periodic verification.
        """
        from sqlalchemy import select
        from app.db.db_models import Program, Scope, Subdomain
        from app.db.session import get_session

        async with get_session() as session:
            result = await session.execute(
                select(
                    Subdomain.id,
                    Subdomain.name,
                    Subdomain.ip_addresses,
                    Subdomain.ip_verdicts,
                    Subdomain.ip_free,
                    Scope.domain,
                    Program.name,
                    Program.platform,
                )
                .join(Subdomain.scope)
                .join(Scope.program)
                .where(
                    (Subdomain.ip_free.is_(True)) |
                    (Subdomain.ip_verdicts.isnot(None))
                )
            )
            rows = result.all()

        parsed: List[VerificationTarget] = []
        for subdomain_id, subdomain_name, ip_json, verdict_json, ip_free, scope_domain, program_name, platform in rows:
            ips = self._parse_ipv4_json(ip_json)
            verdicts = filter_current_ip_verdicts(ips, load_ip_verdicts(verdict_json))
            has_tracked_free_ip = any(v.status == IPVerdictStatus.FREE for v in verdicts.values())
            if not has_tracked_free_ip and ip_free is not True:
                continue
            parsed.append(
                VerificationTarget(
                    subdomain_id=int(subdomain_id),
                    subdomain_name=subdomain_name,
                    stored_ips=ips,
                    stored_verdicts=verdicts,
                    scope_domain=(scope_domain or "").lstrip("*."),
                    program_name=program_name or "unknown",
                    platform=platform.value if platform else "unknown",
                    aggregate_ip_free=ip_free,
                )
            )

        return parsed

    async def _verify_free_ip_targets_once(self) -> None:
        """
        Re-check tracked free-IP verdicts against current DNS and rebuild the
        stored per-IP verdict set from live IPv4s.
        """
        from sqlalchemy import text
        from app.db.session import get_session

        await self._ensure_cidr_index("verifier")
        candidates = await self._load_subdomains_needing_ip_verification()
        if not candidates:
            logger.debug("ip_hunter: no tracked free-IP subdomains to verify")
            return

        now = datetime.utcnow()
        logger.info(
            "ip_hunter: verifying %d tracked free-IP subdomain(s) before hunting",
            len(candidates),
        )

        for candidate in candidates:
            live_ips = await self._resolve_current_ips(candidate.subdomain_name)
            current_verdicts: Dict[str, IPVerdict] = {}
            if live_ips:
                current_verdicts = await self._evaluate_live_ip_verdicts(candidate, live_ips)
            result: Optional[bool] = True if not live_ips else aggregate_subdomain_ip_free(current_verdicts.values())

            try:
                async with get_session() as session:
                    await session.execute(
                        text(
                            "UPDATE subdomains "
                            "SET ip_free = :ip_free, ip_addresses = :ip_addresses, ip_verdicts = :ip_verdicts, ip_free_checked_at = :checked_at "
                            "WHERE id = :sid"
                        ),
                        {
                            "ip_free": result,
                            "ip_addresses": json.dumps(live_ips) if live_ips else None,
                            "ip_verdicts": serialize_ip_verdicts(current_verdicts.values()),
                            "checked_at": now,
                            "sid": candidate.subdomain_id,
                        },
                    )
                    await session.commit()
            except Exception as exc:
                logger.error(
                    "ip_hunter: failed to update ip_free for %s (id=%d): %s",
                    candidate.subdomain_name, candidate.subdomain_id, exc,
                )
                continue

            logger.info(
                "ip_hunter: verified %s (id=%d) → ip_free=%s "
                "(stored_ips=%s live_ips=%s verdicts=%s)",
                candidate.subdomain_name,
                candidate.subdomain_id,
                result,
                candidate.stored_ips,
                live_ips,
                {ip: verdict.status.value for ip, verdict in current_verdicts.items()},
            )

    async def _refresh_free_ip_targets(self, provider: str) -> None:
        candidates = await self._load_free_ip_targets(provider)
        self._free_ip_targets[provider] = candidates
        if candidates:
            logger.info(
                "ip_hunter: [%s] tracking %d free-IP candidate(s): %s",
                provider, len(candidates), sorted(candidates.keys()),
            )

    async def _recheck_free_ip_targets(self, provider: str) -> None:
        refreshed = await self._load_free_ip_targets(provider)
        active: Dict[str, FreeIPTarget] = {}

        for ip, candidate in refreshed.items():
            names = sorted(candidate.subdomain_names)
            if names and not await self._dns_recheck(ip, names):
                logger.info(
                    "ip_hunter: [%s] free-IP candidate expired after cycle — %s "
                    "(DNS no longer points to it)",
                    provider, ip,
                )
                continue
            active[ip] = candidate

        dropped = sorted(set(self._free_ip_targets[provider]) - set(active))
        if dropped:
            logger.info(
                "ip_hunter: [%s] stopped tracking %d free-IP candidate(s): %s",
                provider, len(dropped), dropped,
            )

        kept = sorted(active)
        if kept:
            logger.info(
                "ip_hunter: [%s] free-IP candidates still available; retrying after interval: %s",
                provider, kept,
            )

        self._free_ip_targets[provider] = active

    def _candidate_regions(self, provider: str, regions: List[str]) -> List[str]:
        """
        Return only regions that currently have confirmed-free IPv4 candidates.
        """
        allowed_regions = set(regions)
        candidate_regions: List[str] = []
        seen: Set[str] = set()

        for candidate in self._free_ip_targets[provider].values():
            for region in sorted(candidate.regions):
                if region and region in allowed_regions and region not in seen:
                    candidate_regions.append(region)
                    seen.add(region)

        return candidate_regions

    # ── Subdomain lookup by IP ────────────────────────────────────────────────

    async def _subdomain_ids_for_ip(self, ip: str) -> List[int]:
        """Return IDs of all subdomains whose ip_addresses JSON array contains ip."""
        from sqlalchemy import text
        from app.db.session import get_session

        try:
            async with get_session() as session:
                result = await session.execute(
                    text("""
                        SELECT id FROM subdomains
                        WHERE ip_addresses IS NOT NULL
                        AND EXISTS (
                            SELECT 1
                            FROM json_array_elements(ip_addresses::json) AS elem
                            WHERE elem #>> '{}' = :ip
                        )
                    """),
                    {"ip": ip}
                )
                return [row[0] for row in result.all()]
        except Exception as exc:
            logger.error("ip_hunter: _subdomain_ids_for_ip failed for IP %s: %s", ip, exc)
            return []

    async def _subdomain_names_for_ids(self, subdomain_ids: List[int]) -> List[str]:
        """Return the subdomain names for the given IDs (used for DNS recheck)."""
        if not subdomain_ids:
            return []
        from sqlalchemy import text
        from app.db.session import get_session

        try:
            async with get_session() as session:
                result = await session.execute(
                    text("SELECT name FROM subdomains WHERE id = ANY(:ids)"),
                    {"ids": list(subdomain_ids)},
                )
                return [row[0] for row in result.all()]
        except Exception as exc:
            logger.error("ip_hunter: _subdomain_names_for_ids failed: %s", exc)
            return []

    # ── DNS recheck ───────────────────────────────────────────────────────────

    async def _dns_recheck(self, ip: str, subdomain_names: List[str]) -> bool:
        """
        Return True if at least one subdomain in subdomain_names still resolves
        to ip via an A record (live DNS query, not the DB cache).
        """
        loop = asyncio.get_running_loop()

        for name in subdomain_names:
            try:
                resolved = set(await self._resolve_current_ips(name))
                if ip in resolved:
                    logger.info(
                        "ip_hunter: DNS recheck OK — %s still resolves to %s",
                        name, ip,
                    )
                    return True
                logger.debug(
                    "ip_hunter: DNS recheck — %s resolves to %s (not %s)",
                    name, resolved, ip,
                )
            except OSError as exc:
                logger.debug("ip_hunter: DNS recheck error for %s: %s", name, exc)

        logger.info(
            "ip_hunter: DNS recheck — %s is no longer an A record for any "
            "target subdomain (%s checked)",
            ip, subdomain_names,
        )
        return False

    async def _ensure_cidr_index(self, context: str = "shared") -> None:
        if self._cidr_index is not None and not self._cidr_index.is_stale():
            return
        try:
            self._cidr_index = await get_index()
            self._ip_analyzer.set_cidr_index(self._cidr_index)
            logger.info("ip_hunter: [%s] CIDR index refreshed", context)
        except Exception as exc:
            logger.warning(
                "ip_hunter: [%s] CIDR index refresh failed: %s — using stale/none",
                context,
                exc,
            )

    @staticmethod
    def _provider_matches(loop_provider: str, cidr_provider: str) -> bool:
        aliases = {
            "aws": {"aws"},
            "azure": {"azure"},
            "gcp": {"gcp"},
            "do": {"do", "digitalocean"},
        }
        return cidr_provider in aliases.get(loop_provider, {loop_provider})

    @staticmethod
    def _parse_ipv4_json(raw: object) -> List[str]:
        try:
            if isinstance(raw, list):
                ips = raw
            elif isinstance(raw, str):
                ips = json.loads(raw)
            else:
                ips = []
        except (json.JSONDecodeError, TypeError):
            ips = []

        parsed: List[str] = []
        for ip in ips:
            try:
                ipaddress.IPv4Address(ip)
                parsed.append(ip)
            except ValueError:
                continue
        return parsed

    async def _evaluate_live_ip_verdicts(
        self,
        candidate: VerificationTarget,
        live_ips: List[str],
    ) -> Dict[str, IPVerdict]:
        verdicts: Dict[str, IPVerdict] = {}

        for ip in live_ips:
            finding = None
            if self._cidr_index is not None:
                try:
                    finding = await self._ip_analyzer.analyze(
                        ip=ip,
                        subdomain_name=candidate.subdomain_name,
                        scope_domain=candidate.scope_domain,
                        program_name=candidate.program_name,
                        platform=candidate.platform,
                        finding_type="dangling",
                    )
                except Exception as exc:
                    logger.debug(
                        "ip_hunter: analyzer error for %s (%s): %s",
                        candidate.subdomain_name,
                        ip,
                        exc,
                    )
            if finding is not None:
                verdicts[ip] = verdict_from_finding(finding)
            else:
                verdicts[ip] = await check_ip_verdict(ip)

        return filter_current_ip_verdicts(live_ips, verdicts)

    # ── Live DNS resolution helper ────────────────────────────────────────────

    async def _resolve_current_ips(self, subdomain_name: str) -> List[str]:
        """
        Resolve the current A records for subdomain_name using the shared UDP
        resolver pool first, then fall back to the system resolver.

        Returns a list of IPv4 address strings, or an empty list if the subdomain
        does not resolve (NXDOMAIN, timeout, etc.).
        """
        loop = asyncio.get_running_loop()
        try:
            pool = get_dns_pool()
            if pool:
                ips = sorted(set(await resolve_to_ips(pool, subdomain_name)))
                if ips:
                    logger.debug("ip_hunter: live DNS via UDP for %s → %s", subdomain_name, ips)
                    return ips
        except Exception as exc:
            logger.debug("ip_hunter: UDP DNS for %s failed: %s", subdomain_name, exc)

        try:
            infos = await loop.run_in_executor(
                None,
                lambda: socket.getaddrinfo(subdomain_name, None, socket.AF_INET),
            )
            ips = sorted({info[4][0] for info in infos})
            logger.debug(
                "ip_hunter: live DNS for %s → %s", subdomain_name, ips
            )
            return ips
        except OSError:
            # NXDOMAIN, timeout, network error — subdomain no longer resolves
            logger.debug(
                "ip_hunter: live DNS for %s → (no result)", subdomain_name
            )
            return []

    # ── Stale IP refresh ─────────────────────────────────────────────────────

    async def _refresh_ips_from_dns(
        self,
        stale_ip: str,
        subdomain_ids: List[int],
        subdomain_names: List[str],
    ) -> None:
        """
        Refresh ip_addresses for the given subdomains using live DNS lookups.

        For each subdomain:
          - Query current A records from DNS (no proxy — direct system resolver).
          - Write the result back to ip_addresses:
              non-empty → JSON array of current IPs  (replaces old value)
              empty     → NULL                        (subdomain no longer resolves)
          - Clear stale per-IP verdicts and aggregate ip_free so the verifier
            rebuilds state from the fresh DNS answer.
          - Log the before/after for observability.

        This replaces the old _clear_stale_ip_from_db() which only removed the
        one stale IP without checking whether new IPs have appeared.  The new
        approach is correct in all cases:

          A) Subdomain re-pointed to new IPs → DB updated with new IPs.
          B) Subdomain record removed (NXDOMAIN) → ip_addresses set to NULL.
          C) DNS query error → conservative: leave ip_addresses unchanged.
        """
        if not subdomain_ids:
            return

        from sqlalchemy import text
        from app.db.session import get_session

        # Build a mapping of subdomain_id → subdomain_name for targeted lookups.
        id_to_name: Dict[int, str] = {}
        for sid, name in zip(subdomain_ids, subdomain_names):
            id_to_name[sid] = name

        for sid in subdomain_ids:
            name = id_to_name.get(sid)
            if not name:
                logger.warning(
                    "ip_hunter: no name found for subdomain id=%d — skipping refresh",
                    sid,
                )
                continue

            current_ips = await self._resolve_current_ips(name)

            if current_ips:
                new_value: Optional[str] = json.dumps(current_ips)
                log_suffix = f"updated to {current_ips}"
            else:
                new_value = None
                log_suffix = "set to NULL (no A records)"

            logger.info(
                "ip_hunter: refreshing ip_addresses for %s (id=%d) — "
                "stale_ip=%s %s",
                name, sid, stale_ip, log_suffix,
            )

            try:
                async with get_session() as session:
                    await session.execute(
                        text(
                            "UPDATE subdomains "
                            "SET ip_addresses = :new_val, ip_verdicts = NULL, ip_free = NULL "
                            "WHERE id = :sid"
                        ),
                        {"new_val": new_value, "sid": sid},
                    )
                    await session.commit()
            except Exception as exc:
                logger.error(
                    "ip_hunter: failed to refresh ip_addresses for %s (id=%d): %s",
                    name, sid, exc,
                )

    # ── Per-provider hunt methods ─────────────────────────────────────────────

    async def _run_aws(self) -> List[ProviderHuntResult]:
        if not getattr(settings, "AWS_EIP_ENABLED", True):
            logger.info("ip_hunter: [aws] disabled (AWS_EIP_ENABLED=false)")
            return []

        from app.takeover.ip_hunter.providers.aws_eip import AWSEIPHunter
        try:
            hunter = AWSEIPHunter(target_ips=self._all_targets, cidr_index=self._cidr_index)
        except RuntimeError as exc:
            return [ProviderHuntResult(provider="aws", region="—", hit=False, error=str(exc))]

        regions  = self._candidate_regions("aws", hunter.target_regions())
        results: List[ProviderHuntResult] = []
        if not regions:
            logger.info("ip_hunter: [aws] no confirmed-free candidate regions — skipping")
            return results

        logger.info("ip_hunter: [aws] rolling %d region(s): %s", len(regions), regions)

        for region in regions:
            try:
                raw = await hunter.hunt(region=region)
            except Exception as exc:
                results.append(ProviderHuntResult(
                    provider="aws", region=region, hit=False, error=str(exc)
                ))
                continue

            hit = next((r for r in raw if r.hit), None)
            if hit:
                sub_ids = await self._subdomain_ids_for_ip(hit.ip_allocated)
                results.append(ProviderHuntResult(
                    provider="aws", region=region, hit=True,
                    hit_ip=hit.ip_allocated, hit_subdomain_ids=sub_ids,
                    attempts=len(raw),
                ))
                continue
            results.append(ProviderHuntResult(
                provider="aws", region=region, hit=False, attempts=len(raw),
            ))

        return results

    async def _run_do(self) -> List[ProviderHuntResult]:
        if not getattr(settings, "DO_EIP_ENABLED", True):
            logger.info("ip_hunter: [do] disabled (DO_EIP_ENABLED=false)")
            return []

        from app.takeover.ip_hunter.providers.do_eip import DOReservedIPHunter
        try:
            hunter = DOReservedIPHunter(target_ips=self._all_targets, cidr_index=self._cidr_index)
        except RuntimeError as exc:
            return [ProviderHuntResult(provider="digitalocean", region="—", hit=False, error=str(exc))]

        regions = self._candidate_regions("do", hunter.target_regions())
        results: List[ProviderHuntResult] = []
        if not regions:
            logger.info("ip_hunter: [do] no confirmed-free candidate regions — skipping")
            return results

        logger.info(
            "ip_hunter: [do] rolling %d region(s): %s",
            len(regions), regions,
        )

        for region in regions:
            try:
                raw = await hunter.hunt(region=region)
            except Exception as exc:
                results.append(ProviderHuntResult(
                    provider="digitalocean", region=region, hit=False, error=str(exc)
                ))
                continue

            hit = next((r for r in raw if r.hit), None)
            if hit:
                sub_ids = await self._subdomain_ids_for_ip(hit.ip_allocated)
                results.append(ProviderHuntResult(
                    provider="digitalocean", region=region, hit=True,
                    hit_ip=hit.ip_allocated, hit_subdomain_ids=sub_ids,
                    attempts=len(raw),
                ))
                continue
            results.append(ProviderHuntResult(
                provider="digitalocean", region=region, hit=False, attempts=len(raw),
            ))

        return results

    async def _run_azure(self) -> List[ProviderHuntResult]:
        if not getattr(settings, "AZURE_PIP_ENABLED", True):
            logger.info("ip_hunter: [azure] disabled (AZURE_PIP_ENABLED=false)")
            return []

        from app.takeover.ip_hunter.providers.azure_pip import AzurePublicIPHunter
        try:
            hunter = AzurePublicIPHunter(target_ips=self._all_targets, cidr_index=self._cidr_index)
        except RuntimeError as exc:
            return [ProviderHuntResult(provider="azure", region="—", hit=False, error=str(exc))]

        regions  = self._candidate_regions("azure", hunter.target_regions())
        attempts = int(getattr(settings, "AZURE_PIP_ATTEMPTS", 20))
        results: List[ProviderHuntResult] = []
        if not regions:
            logger.info("ip_hunter: [azure] no confirmed-free candidate regions — skipping")
            return results

        logger.info("ip_hunter: [azure] rolling %d region(s) × %d attempts each: %s", len(regions), attempts, regions)

        for region in regions:
            try:
                raw = await hunter.hunt(region=region, attempts=attempts)
            except Exception as exc:
                results.append(ProviderHuntResult(
                    provider="azure", region=region, hit=False, error=str(exc)
                ))
                continue

            hit = next((r for r in raw if r.hit), None)
            if hit:
                sub_ids = await self._subdomain_ids_for_ip(hit.ip_allocated)
                results.append(ProviderHuntResult(
                    provider="azure", region=region, hit=True,
                    hit_ip=hit.ip_allocated, hit_subdomain_ids=sub_ids,
                    attempts=len(raw),
                ))
                continue
            results.append(ProviderHuntResult(
                provider="azure", region=region, hit=False, attempts=len(raw),
            ))

        return results

    async def _run_gcp(self) -> List[ProviderHuntResult]:
        if not getattr(settings, "GCP_EIP_ENABLED", True):
            logger.info("ip_hunter: [gcp] disabled (GCP_EIP_ENABLED=false)")
            return []

        from app.takeover.ip_hunter.providers.gcp_eip import GCPStaticIPHunter
        try:
            hunter = GCPStaticIPHunter(target_ips=self._all_targets, cidr_index=self._cidr_index)
        except RuntimeError as exc:
            return [ProviderHuntResult(provider="gcp", region="—", hit=False, error=str(exc))]

        regions    = self._candidate_regions("gcp", hunter.target_regions())
        batch_size = int(getattr(settings, "GCP_EIP_BATCH_SIZE", 3))
        results: List[ProviderHuntResult] = []
        if not regions:
            logger.info("ip_hunter: [gcp] no confirmed-free candidate regions — skipping")
            return results

        logger.info(
            "ip_hunter: [gcp] rolling %d region(s) × batch=%d: %s",
            len(regions), batch_size, regions,
        )

        for region in regions:
            try:
                raw = await hunter.hunt(region=region, batch_size=batch_size)
            except Exception as exc:
                logger.warning("ip_hunter: [gcp] %s failed: %s", region, exc)
                results.append(ProviderHuntResult(
                    provider="gcp", region=region, hit=False, error=str(exc)
                ))
                continue

            hit = next((r for r in raw if r.hit), None)
            if hit:
                sub_ids = await self._subdomain_ids_for_ip(hit.ip_allocated)
                results.append(ProviderHuntResult(
                    provider="gcp", region=region, hit=True,
                    hit_ip=hit.ip_allocated, hit_subdomain_ids=sub_ids,
                    attempts=len(raw),
                ))
                continue
            results.append(ProviderHuntResult(
                provider="gcp", region=region, hit=False, attempts=len(raw),
            ))

        return results

    # ── DB helpers ────────────────────────────────────────────────────────────

    async def _notify_hit(self, result: ProviderHuntResult) -> None:
        """Send a Discord alert when a target IP is claimed."""
        from sqlalchemy import select
        from app.db.db_models import Subdomain, Scope, Program
        from app.db.session import get_session
        from app.notify.discord import DiscordNotifier

        program_name = "unknown"
        platform = "unknown"
        scope_url = ""
        subdomain_names = []

        if result.hit_subdomain_ids:
            try:
                async with get_session() as session:
                    stmt = (
                        select(
                            Subdomain.name,
                            Program.name.label("program_name"),
                            Program.platform.label("platform"),
                            Scope.domain.label("scope_domain")
                        )
                        .join(Subdomain.scope)
                        .join(Scope.program)
                        .where(Subdomain.id.in_(result.hit_subdomain_ids))
                    )
                    rows = (await session.execute(stmt)).all()
                    subdomain_names = [row[0] for row in rows]
                    if rows:
                        program_name = rows[0][1] or "unknown"
                        platform_val = rows[0][2]
                        platform = platform_val.value if platform_val else "unknown"
                        scope_url = rows[0][3] or ""
                        logger.info(
                            "ip_hunter: found %d subdomains for hit IP %s, program=%s platform=%s",
                            len(rows), result.hit_ip, program_name, platform,
                        )
                    else:
                        logger.warning(
                            "ip_hunter: no subdomains found for hit IP %s (subdomain_ids: %s)",
                            result.hit_ip, result.hit_subdomain_ids,
                        )
            except Exception as exc:
                logger.error(
                    "ip_hunter: failed to look up subdomain context for hit IP %s: %s",
                    result.hit_ip, exc,
                )

        cidr_block = "unknown"
        if self._cidr_index and result.hit_ip:
            try:
                match = self._cidr_index.lookup(result.hit_ip)
                if match:
                    cidr_block = match.cidr
            except Exception:
                pass

        result.program_name = program_name
        result.platform     = platform
        result.scope_url    = scope_url

        try:
            notifier = DiscordNotifier()
            await notifier.notify_ip_hit(
                ip              = result.hit_ip or "",
                provider        = result.provider,
                region          = result.region,
                cidr_block      = cidr_block,
                score           = 0.0,
                attempts        = result.attempts,
                subdomain_names = subdomain_names,
                program_name    = program_name,
                platform        = platform,
                scope_url       = scope_url,
            )
            logger.info(
                "ip_hunter: Discord hit alert sent — ip=%s provider=%s region=%s "
                "program=%s platform=%s subdomains=%d",
                result.hit_ip, result.provider, result.region,
                program_name, platform, len(subdomain_names),
            )
        except Exception as exc:
            logger.error(
                "ip_hunter: Discord hit notification failed for %s: %s",
                result.hit_ip, exc,
            )

    async def _persist_result(self, result: ProviderHuntResult) -> None:
        """Persist a hit result to ip_hunt_attempts. Non-hits are skipped."""
        if not result.hit:
            return

        from sqlalchemy import text
        from app.db.session import get_session

        cidr_block = "unknown"
        if self._cidr_index and result.hit_ip:
            try:
                match = self._cidr_index.lookup(result.hit_ip)
                if match:
                    cidr_block = match.cidr
            except Exception:
                pass

        try:
            async with get_session() as session:
                await session.execute(
                    text(
                        "INSERT INTO ip_hunt_attempts "
                        "(provider, region, cidr_block, ip_hit, hit, attempts, attempted_at) "
                        "VALUES (:provider, :region, :cidr_block, :ip_hit, :hit, :attempts, :attempted_at)"
                    ),
                    {
                        "provider":     result.provider,
                        "region":       result.region,
                        "cidr_block":   cidr_block,
                        "ip_hit":       result.hit_ip,
                        "hit":          result.hit,
                        "attempts":     result.attempts,
                        "attempted_at": datetime.utcnow(),
                    },
                )
                await session.commit()
                logger.info(
                    "ip_hunter: persisted hit result — ip=%s provider=%s region=%s",
                    result.hit_ip, result.provider, result.region,
                )
        except Exception as exc:
            logger.error(
                "ip_hunter: failed to persist hunt result for %s: %s",
                result.hit_ip, exc,
            )
