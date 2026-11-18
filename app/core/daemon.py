import asyncio
import json
import signal
import sys
from datetime import datetime, timedelta

from sqlalchemy import and_, exists, select
from sqlalchemy.orm import selectinload

from app.core.config import settings
from app.core.logging import logger
from app.core.ratelimit import rate_limit_manager
from app.db.db_models import Notification, NotificationChannel, Scope, Subdomain, SubdomainState
from app.db.session import get_session
from app.discovery.active import ActiveDiscovery
from app.discovery.passive import PassiveDiscovery
from app.discovery.permutation import PermutationDiscovery
from app.discovery.js_scrape import JSDiscovery
from app.discovery.wayback import WaybackDiscovery
from app.discovery.certstream import CertstreamMonitor
from app.discovery.git_scanner import GitScanner
from app.probing.dns import DNSProber
from app.probing.http import HTTPProber
from app.probing.dns_scanner import (
    DNSScanner,
    SubdomainNSSweeper,
)
from app.probing.dns_scanner.ns_providers import VULNERABLE_NS_PROVIDERS
from app.probing.exposure_scanner import ExposureScanner
from app.probing.ip_check import check_ips_for_subdomain_verdicts
from app.probing.ip_verdicts import aggregate_subdomain_ip_free, serialize_ip_verdicts
from app.takeover.subdomain_hunter.evaluator import TakeoverEvaluator
from app.takeover.subdomain_hunter.providers.aws_route53 import Route53TakeoverQueue
from app.core.scheduler import Scheduler
from app.probing.domain_buy_scanner import DomainBuyScanner
from app.discovery.state import StateManager

try:
    from app.takeover.ip_hunter.cidr_index import CIDRIndex as _CIDRIndex
    _CIDR_AVAILABLE = True
except ImportError:
    _CIDRIndex = None
    _CIDR_AVAILABLE = False


class Daemon:

    def __init__(self):
        self.running = True
        self.iteration = 0
        self.active_tasks = set()
        self._last_scanned_program_ids: set = set()  # programs scanned this iteration
        self._certstream_task: asyncio.Task | None = None
        self._ns_sweep_task: asyncio.Task | None = None   # strong ref — prevents GC cancellation
        self._exposure_task: asyncio.Task | None = None   # strong ref — prevents GC cancellation
        self._ip_hunter_task: asyncio.Task | None = None  # strong ref — prevents GC cancellation
        self._git_scanner_task: asyncio.Task | None = None  # strong ref — prevents GC cancellation
        self._platform_sync_task: asyncio.Task | None = None  # strong ref — prevents GC cancellation
        self._platform_sync_warned: set[str] = set()
        self.components = {
            "passive": PassiveDiscovery(),
            "dns": DNSProber(),
            "http": HTTPProber(),
            "evaluator": TakeoverEvaluator(),
            "exposure": ExposureScanner(),
            "permutation": PermutationDiscovery(),
            "dns_scanner":  DNSScanner(),
            "dns_takeover": DNSScanner(),   # compat alias — used by _dns_takeover_scope_sweep
            "js_scrape": JSDiscovery(),
            "wayback": WaybackDiscovery(),
            "certstream": CertstreamMonitor(probe_callback=self._certstream_probe_callback),
        }

        if getattr(settings, "ACTIVE_DISCOVERY_ENABLED", True):
            self.components["active"] = ActiveDiscovery()

        if getattr(settings, "DOMAIN_BUY_SCANNER_ENABLED", True):
            self.components["domain_buy"] = DomainBuyScanner()

        if getattr(settings, "NS_SWEEP_ENABLED", True):
            self.components["ns_sweep"] = SubdomainNSSweeper(
                self.components["dns_scanner"],
                concurrency=getattr(settings, "NS_SWEEP_CONCURRENCY", 10),
            )

        if getattr(settings, "IP_HUNTER_ENABLED", False):
            from app.takeover.ip_hunter import IPHunter
            self.components["ip_hunter"] = IPHunter()

        if getattr(settings, "GIT_SCANNER_ENABLED", False):
            self.components["git_scanner"] = GitScanner()

        self.probe_sem = asyncio.Semaphore(settings.GLOBAL_CONCURRENCY_LIMIT)
        logger.debug(
            "Initialized global probe semaphore with limit %d",
            settings.GLOBAL_CONCURRENCY_LIMIT,
        )

        self.scope_sem = asyncio.Semaphore(getattr(settings, "SCOPE_CONCURRENCY", 5))
        logger.debug(
            "Initialized scope semaphore with limit %d",
            getattr(settings, "SCOPE_CONCURRENCY", 5),
        )

        self._cidr_task: asyncio.Task | None = None  # strong ref — prevents GC cancellation
        self._spf_dmarc_task: asyncio.Task | None = None  # strong ref
        self._dns_notify_locks: dict[str, asyncio.Lock] = {}

    # ------------------------------------------------------------------
    # Notify lock helper
    # ------------------------------------------------------------------

    def _get_notify_lock(self, scope_domain: str) -> asyncio.Lock:
        """
        Return the per-scope asyncio.Lock used to serialize DNS takeover
        Discord notifications. Lazily created on first access.

        All four notify handlers (_handle_dns_takeover_finding,
        _handle_subdomain_ns_finding, _handle_dangling_ip,
        _handle_spf_dmarc_finding) share the same lock dict so that any
        finding type for a given scope_domain is serialized against any
        other, preventing cross-handler races too.

        Callers must re-read the cooldown stamp (dns_takeover_notified_at)
        inside the lock: a concurrent handler may have stamped it after the
        value was first read.
        """
        if scope_domain not in self._dns_notify_locks:
            self._dns_notify_locks[scope_domain] = asyncio.Lock()
        return self._dns_notify_locks[scope_domain]

    def _is_yaml_ns_takeover_finding(self, finding) -> bool:
        """
        Only notify for NS takeover candidates that come from the vulnerable
        provider YAML registry. This intentionally excludes auxiliary findings
        like wildcard CNAME hops and lame delegation noise.
        """
        yaml_provider_names = {provider.name for provider in VULNERABLE_NS_PROVIDERS}
        if getattr(finding, "rcode", "") in {"WILDCARD_CNAME", "CNAME_HOP_AVAILABLE"}:
            return False
        return getattr(finding, "provider", "") in yaml_provider_names

    def _has_auto_ns_takeover_logic(self, finding) -> bool:
        ns = getattr(finding, "nameserver", "").lower()
        return (
            "awsdns" in ns
            or "azure-dns" in ns
            or "googledomains.com" in ns
        )

    # ------------------------------------------------------------------
    # Main loop
    # ------------------------------------------------------------------

    async def run(self):
        logger.info("STOscanner daemon starting")
        from app.db.session import create_tables, run_enum_migrations

        try:
            await create_tables()
            logger.info("Database tables initialized")
        except Exception as e:
            logger.warning("Database tables may already exist: %s", e)

        # Run BEFORE the iteration loop — alters existing enum types in Postgres
        # so new values like 'potential_long' are valid before any query fires.
        try:
            await run_enum_migrations()
            logger.info("Database enum migrations applied")
        except Exception as e:
            logger.error(
                "Enum migrations failed — some features may not work until fixed: %s", e
            )

        # Refresh resolver pool from configured URLs + local files.
        # Uses cached result if < DNS_RESOLVER_REFRESH_HOURS (default 48h) old.
        # Must run before any DNS work so the full validated pool is available.
        try:
            from app.discovery.resolvers import ensure_resolver_pool, get_resolver_list
            await ensure_resolver_pool()
            # Both DNS scanners cached the pool before the refresh ran.
            for _key in ("dns_scanner", "dns_takeover"):
                _scanner = self.components.get(_key)
                if _scanner is not None and hasattr(_scanner, "_pool"):
                    _scanner._pool = get_resolver_list()
        except Exception as e:
            logger.warning("Resolver pool refresh failed — using fallback resolvers: %s", e)

        # Start Route 53 NS-lottery worker — serialised background task,
        # max 1 attempt running at a time.  Idempotent if called again later.
        Route53TakeoverQueue.start_worker()

        # Start GCP Cloud DNS NS-lottery worker
        try:
            from app.takeover.ns_hunter.providers.gcp_dns_takeover import GCPDNSTakeoverQueue
            GCPDNSTakeoverQueue.start_worker()
        except Exception as _gcp_exc:
            logger.warning("gcp_dns_takeover: failed to start worker: %s", _gcp_exc)

        self._setup_signal_handlers()

        # Start certstream as a persistent background task
        if getattr(settings, "CERTSTREAM_ENABLED", True):
            self._certstream_task = asyncio.create_task(
                self.components["certstream"].run()
            )
            logger.info("certstream: background monitor started")
            if _CIDR_AVAILABLE:
                try:
                    logger.info("cidr_index: building provider IP range index...")
                    cidr_index = await asyncio.wait_for(_CIDRIndex.build(), timeout=90)
                    self._inject_cidr_index(cidr_index)
                    logger.info("cidr_index: index ready — injected into dns_scanner and dns_takeover")
                    self._cidr_task = asyncio.create_task(self._cidr_refresh_loop(cidr_index))
                except asyncio.TimeoutError:
                    logger.warning(
                        "cidr_index: build timed out after 90 s — "
                        "NS sweep will use ASN fallback; will retry on next refresh cycle"
                    )
                except Exception as exc:
                    logger.warning(
                        "cidr_index: initial build failed (%s) — NS sweep will use ASN fallback",
                        exc,
                    )
            else:
                logger.warning(
                    "cidr_index: CIDRIndex not importable (ip_hunter package missing?) — "
                    "NS sweep will use ASN fallback only"
                )

        # Start NS sweep as a fully independent background loop —
        # runs on its own interval, never touches the main scan loop.
        if "ns_sweep" in self.components:
            self._ns_sweep_task = asyncio.create_task(self._ns_sweep_loop())
            logger.info("ns_sweep: independent background loop started")

        # Start SPF/DMARC sweep as a fully independent background loop —
        # runs on the same interval as NS sweep, once per scope root per cycle.
        if getattr(settings, "DANGLING_SPF_DMARC_CHECK", True):
            self._spf_dmarc_task = asyncio.create_task(self._spf_dmarc_sweep_loop())
            logger.info("spf_dmarc: independent background loop started")

        # Start exposure scanner as a fully independent background loop —
        # runs continuously, picking random subdomains each cycle.
        if getattr(settings, "EXPOSURE_SCAN_ENABLED", False):
            self._exposure_task = asyncio.create_task(self._exposure_loop())
            logger.info("exposure: independent background loop started")

        # Start IP hunter as a fully independent background loop —
        # cycles through scored /24 blocks hunting dangling cloud IPs.
        if "ip_hunter" in self.components:
            self._ip_hunter_task = asyncio.create_task(self._ip_hunter_loop())
            logger.info("ip_hunter: independent background loop started")

        # Start git secret scanner as a fully independent background loop.
        # Expands git scopes → repos and runs trufflehog --only-verified on each.
        if "git_scanner" in self.components:
            self._git_scanner_task = asyncio.create_task(self._git_scanner_loop())
            logger.info("git_scanner: independent background loop started")

        # Start automatic platform resync as a fully independent background
        # loop. It checks per-platform intervals and never blocks scanning.
        if getattr(settings, "PLATFORM_SYNC_ENABLED", True):
            self._platform_sync_task = asyncio.create_task(self._platform_sync_loop())
            logger.info("platform_sync: independent background loop started")

        # Backfill domain_availability for existing scopes in the background —
        # fire-and-forget so it never blocks the main scan loop.
        if "domain_buy" in self.components:
            asyncio.create_task(self._domain_buy_backfill())

        while self.running:
            logger.debug("Daemon iteration %d starting", self.iteration)
            try:
                await self._iteration()

                # Wait for all background probe tasks to finish before
                # stamping scan times — probing must be complete first.
                if self.active_tasks:
                    pending = list(self.active_tasks)
                    self.active_tasks.clear()
                    logger.debug("Waiting for %d pending probes to finish...", len(pending))
                    timeout = getattr(settings, "ACTIVE_TASKS_TIMEOUT_SECONDS", 300)
                    try:
                        await asyncio.wait_for(
                            asyncio.gather(*pending, return_exceptions=True),
                            timeout=timeout,
                        )
                    except asyncio.TimeoutError:
                        logger.warning(
                            "active_tasks gather timed out after %ds — "
                            "%d task(s) still running, continuing to next iteration",
                            timeout,
                            sum(1 for t in pending if not t.done()),
                        )

                # Stamp program scan times NOW — after probing is done.
                # Programs from the last iteration are stored so we can
                # update them here rather than prematurely in _scan_program_isolated.
                if self._last_scanned_program_ids:
                    async with get_session() as session:
                        for pid in self._last_scanned_program_ids:
                            await Scheduler.update_program_scan_time(session, pid)
                        await session.commit()
                    logger.debug(
                        "Stamped last_scan_at for %d programs",
                        len(self._last_scanned_program_ids),
                    )
                    self._last_scanned_program_ids.clear()

                self.iteration += 1

                if (
                    settings.DAEMON_MAX_ITERATIONS
                    and self.iteration >= settings.DAEMON_MAX_ITERATIONS
                ):
                    logger.info("Reached max iterations, stopping")
                    break

                logger.debug(
                    "Sleeping for %d seconds before next iteration",
                    settings.DAEMON_SLEEP_SECONDS,
                )
                await asyncio.sleep(settings.DAEMON_SLEEP_SECONDS)
            except asyncio.CancelledError:
                for task in list(self.active_tasks):
                    task.cancel()
                logger.info("Daemon cancelled")
                break
            except Exception as e:
                logger.error("Error in daemon iteration: %s", e, exc_info=True)
                await asyncio.sleep(60)

        logger.info("STOscanner daemon stopped")

    # ------------------------------------------------------------------
    # Iteration — top-level fan-out across programs
    # ------------------------------------------------------------------

    async def _iteration(self):
        logger.info("Starting iteration %d", self.iteration)

        if self.iteration == 0:
            await self._process_notifications_isolated()

        async with get_session() as session:
            programs = await Scheduler.get_programs_needing_scan(
                session,
                limit=getattr(settings, "PROGRAMS_LIMIT_PER_ITERATION", 50),
            )
        logger.info("Found %d programs needing scan", len(programs))

        results = await asyncio.gather(
            *[self._scan_program_isolated(p) for p in programs],
            return_exceptions=True,
        )

        for program, result in zip(programs, results):
            if isinstance(result, Exception):
                logger.error(
                    "Unhandled exception scanning program %s (ID: %d): %s",
                    program.name,
                    program.id,
                    result,
                    exc_info=result,
                )
            else:
                self._last_scanned_program_ids.add(program.id)

        await self._recheck_potential_subdomains_isolated()
        await self._recheck_potential_long_subdomains_isolated()
        await self._recheck_dangling_retries_isolated()
        await self._process_notifications_isolated()
        await self._run_domain_buy_scanner_isolated()
        await self._run_exposure_loop_isolated()
        logger.info("Completed iteration %d", self.iteration)

    # ------------------------------------------------------------------
    # Program → Scopes
    # ------------------------------------------------------------------

    async def _scan_program_isolated(self, program):
        logger.info("Scanning program: %s (ID: %d)", program.name, program.id)

        async with get_session() as session:
            scopes = await Scheduler.get_scopes_needing_scan(session, program.id)
        logger.debug("Found %d scopes for program %s", len(scopes), program.name)

        if not scopes:
            logger.debug("No scopes to scan for program %s, skipping", program.name)
            return

        async def scan_scope_with_sem(scope):
            async with self.scope_sem:
                await self._scan_scope_isolated(scope)

        results = await asyncio.gather(
            *[scan_scope_with_sem(scope) for scope in scopes],
            return_exceptions=True,
        )

        for scope, result in zip(scopes, results):
            if isinstance(result, Exception):
                logger.error(
                    "Unhandled exception scanning scope %s: %s",
                    scope.domain,
                    result,
                    exc_info=result,
                )

        # NOTE: Do NOT stamp last_scan_at here.
        # _scan_scope only fires off create_task() calls and returns immediately —
        # the actual probing happens in background tasks collected in self.active_tasks.
        # Stamping here would make the program look "just scanned" on the
        # next iteration even though no subdomains were actually probed yet.
        # update_program_scan_time is now called from run() after all
        # active_tasks have been awaited and probing is truly complete.

    # ------------------------------------------------------------------
    # Scope → Subdomains
    # ------------------------------------------------------------------

    async def _scan_scope_isolated(self, scope):
        await self._scan_scope(scope)

    async def _scan_scope(self, scope):
        logger.debug("Scanning scope: %s (ID: %d)", scope.domain, scope.id)
        try:
            # Determine first scan vs rescan — drives permutation and wayback behaviour.
            from sqlalchemy import select as _sel, func as _func
            from app.db.db_models import Subdomain as _SD
            async with get_session() as count_session:
                count_result = await count_session.execute(
                    _sel(_func.count(_SD.id)).where(_SD.scope_id == scope.id)
                )
                existing_count = count_result.scalar_one()
            is_first_scan = existing_count == 0
            logger.info(
                "scope %s: %s (%d existing subdomains)",
                scope.domain,
                "first scan" if is_first_scan else "rescan",
                existing_count,
            )

            # On first scan: register domain with the buy scanner (WHOIS once).
            if is_first_scan and "domain_buy" in self.components:
                try:
                    async with get_session() as buy_session:
                        await self.components["domain_buy"].register_domain(
                            buy_session, scope.domain
                        )
                except Exception as exc:
                    logger.warning(
                        "domain_buy: register_domain failed for %s: %s",
                        scope.domain, exc,
                    )

            # Run passive and active discovery in isolated sessions.
            # They each call session.commit() internally — sharing one session
            # causes each commit to expire the other's loaded objects, leading
            # to stale state and missed subdomains in get_subdomains_needing_scan.
            new_from_passive: list = []
            new_from_active: list = []

            async def run_passive():
                async with get_session() as s:
                    result = await self.components["passive"].enrich(s, scope)
                    new_from_passive.extend(result if isinstance(result, list) else [])

            async def run_active():
                async with get_session() as s:
                    result = await self.components["active"].enrich(s, scope)
                    new_from_active.extend(result if isinstance(result, list) else [])

            enrich_tasks = [run_passive()]
            # Wordlist brute-force only on first scan — passive tools (subfinder,
            # crt.sh) and certstream cover new subdomains on rescans. Re-running
            # the full wordlist every SCAN_INTERVAL_HOURS wastes DNS queries on
            # names that haven't changed.
            if settings.ACTIVE_DISCOVERY_ENABLED and is_first_scan:
                enrich_tasks.append(run_active())

            # Inspect gather results so enricher exceptions are never silently
            # swallowed; subfinder failures must stay visible.
            enrich_labels = ["passive"] + (["active"] if settings.ACTIVE_DISCOVERY_ENABLED and is_first_scan else [])
            enrich_results = await asyncio.gather(*enrich_tasks, return_exceptions=True)
            for label, res in zip(enrich_labels, enrich_results):
                if isinstance(res, Exception):
                    logger.warning(
                        "scope %s: %s enricher raised an exception "
                        "(subdomains from this source may be missing): %s",
                        scope.domain, label, res, exc_info=res,
                    )

            # Permutation:
            # - New subdomains found → always run alterx on them
            # - First scan, nothing found → query DB for all seeds (thorough)
            # - Rescan, nothing new → SKIP (avoids 20-min silence on 500+ seeds)
            new_this_run = list(set(new_from_passive + new_from_active))
            if getattr(settings, "ALTERX_ENABLED", True):
                if new_this_run:
                    seeds = new_this_run
                    async with get_session() as perm_session:
                        # NOTE: permutation.enrich() logs "running alterx on X/Y seeds for <domain>"
                        # internally — do NOT add a duplicate log here.
                        try:
                            await self.components["permutation"].enrich(
                                perm_session, scope.domain, seeds
                            )
                        except Exception as e:
                            logger.warning(
                                "permutation scan failed for scope %s: %s",
                                scope.domain, e,
                            )
                elif is_first_scan:
                    # Nothing found at all on first scan — run on all known seeds
                    # from DB (passive may have found some via crt.sh/subfinder).
                    async with get_session() as seed_session:
                        seed_result = await seed_session.execute(
                            _sel(_SD.name).where(_SD.scope_id == scope.id)
                        )
                        seeds = [r for r, in seed_result.all()]
                    if seeds:
                        async with get_session() as perm_session:
                            try:
                                await self.components["permutation"].enrich(
                                    perm_session, scope.domain, seeds
                                )
                            except Exception as e:
                                logger.warning(
                                    "permutation scan failed for scope %s: %s",
                                    scope.domain, e,
                                )
                else:
                    logger.info(
                        "scope %s: rescan, no new subdomains — skipping permutation",
                        scope.domain,
                    )

            # Wayback — first scan only, historical results don't change weekly.
            if getattr(settings, "WAYBACK_ENABLED", True):
                if is_first_scan:
                    async with get_session() as wb_session:
                        try:
                            await self.components["wayback"].enrich(wb_session, scope)
                        except Exception as e:
                            logger.warning("wayback failed for %s: %s", scope.domain, e)
                else:
                    logger.debug("scope %s: rescan — skipping wayback", scope.domain)

            # JS scraping — gated by JSSCRAPE_RESCAN_HOURS (default 2 weeks).
            # JS files change with deployments, not every few hours — no need
            # to re-scrape on every subdomain rescan cycle.
            # NOTE: JSDiscovery.enrich() logs "js_scrape: starting for <domain>"
            # internally — do NOT add a duplicate log here.
            if getattr(settings, "JSSCRAPE_ENABLED", True):
                js_cutoff = datetime.utcnow() - timedelta(hours=settings.JSSCRAPE_RESCAN_HOURS)
                js_due = (
                    scope.last_js_scraped_at is None
                    or scope.last_js_scraped_at < js_cutoff
                )
                if js_due:
                    async with get_session() as js_session:
                        try:
                            await self.components["js_scrape"].enrich(js_session, scope)
                        except Exception as e:
                            logger.warning("js_scrape failed for %s: %s", scope.domain, e)
                    async with get_session() as js_stamp_session:
                        await Scheduler.update_scope_js_scrape_time(js_stamp_session, scope.id)
                else:
                    next_js = scope.last_js_scraped_at + timedelta(hours=settings.JSSCRAPE_RESCAN_HOURS)
                    logger.debug(
                        "scope %s: js_scrape skipped — next run at %s",
                        scope.domain, next_js.strftime("%Y-%m-%d %H:%M"),
                    )

            # Stamp scope scan time — discovery phase is complete.
            async with get_session() as stamp_session:
                await Scheduler.update_scope_scan_time(stamp_session, scope.id)
                await stamp_session.commit()

            # Fresh session for querying — sees all commits from all enrichers.
            async with get_session() as query_session:
                subdomains = await Scheduler.get_subdomains_needing_scan(
                    query_session, scope_id=scope.id
                )

            logger.debug(
                "Found %d subdomains for scope %s. Dispatching to background workers.",
                len(subdomains),
                scope.domain,
            )

            if not subdomains:
                return

            for sd in subdomains:
                task = asyncio.create_task(self._probe_task_wrapper(sd.id, sd.name))
                self.active_tasks.add(task)
                task.add_done_callback(self.active_tasks.discard)

        except Exception as e:
            logger.error("Error scanning scope %s: %s", scope.domain, e, exc_info=True)

    async def _probe_task_wrapper(self, sd_id: int, sd_name: str):
        async with self.probe_sem:
            async with get_session() as sub_sess:
                stmt = select(Subdomain).where(Subdomain.id == sd_id)
                res = await sub_sess.execute(stmt)
                db_sd = res.scalar_one_or_none()

                if db_sd:
                    await self._probe_subdomain(sub_sess, db_sd)

    # ------------------------------------------------------------------
    # Subdomain probing
    # ------------------------------------------------------------------

    async def _probe_subdomain(self, session, subdomain):
        subdomain_name = subdomain.name  # str — safe, loaded at query time
        subdomain_id = subdomain.id  # int — same

        logger.debug("Probing subdomain: %s (ID: %d)", subdomain_name, subdomain_id)
        try:
            # ── Step 1: DNS probe ─────────────────────────────────────────────
            dns_data = await self.components["dns"].probe(session, subdomain)

            # ── Step 2: TCP IP liveness/taken check ───────────────────────────
            #
            # Runs immediately after DNS so we have fresh IPs.
            # Only fires when the subdomain resolved to at least one A record.
            # Updates subdomain.ip_verdicts + subdomain.ip_free +
            # subdomain.ip_free_checked_at in-place;
            # the session.commit() at the end of this method persists both.
            #
            # This path is intentionally conservative:
            # ip_free = False → at least one IP clearly responded (open/refused)
            # ip_free = None  → only filtered/error responses; still ambiguous
            #
            # Generic TCP silence is NOT treated as free. Strong free verdicts
            # come from the NS sweep dangling-IP analyzer and are stored per IP.
            if dns_data and dns_data.get("ips"):
                try:
                    from datetime import datetime as _dt
                    verdicts = await check_ips_for_subdomain_verdicts(dns_data["ips"])
                    ip_free_result = aggregate_subdomain_ip_free(verdicts)
                    subdomain.ip_verdicts = serialize_ip_verdicts(verdicts)
                    subdomain.ip_free = ip_free_result
                    subdomain.ip_free_checked_at = _dt.utcnow()
                    logger.debug(
                        "ip_check: %s → ip_free=%s (IPs: %s)",
                        subdomain_name,
                        ip_free_result,
                        ", ".join(dns_data["ips"]),
                    )
                except Exception as _ice:
                    logger.debug("ip_check: error for %s: %s", subdomain_name, _ice)

            # ── Step 3: CDN detection + rate limiting ─────────────────────────
            #
            # Done after DNS (so we have the CNAME) but before HTTP (so we can
            # gate or throttle the actual web request).
            #
            # Three outcomes from check_cdn():
            #   "skip"  — CDN rate limit is 0 in config → skip HTTP entirely this
            #             iteration. DNS data is still evaluated (CNAME takeover
            #             scoring still runs) but no HTTP request is sent.
            #             last_scanned_at is stamped so the subdomain isn't
            #             immediately re-queued — it will be retried on the next
            #             scan cycle when RESCAN_STALE_HOURS elapses.
            #   "wait"  — CDN token acquired after waiting → proceed normally.
            #   None    — not a CDN → proceed normally.
            cdn_action = None
            cname_target = getattr(subdomain, "cname_target", None)
            if cname_target:
                # check_cdn() expects a raw CNAME string and calls detect_cdn_from_cname()
                # internally.  Passing the already-resolved provider key (e.g. "cloudflare")
                # makes the internal detection return None → rate limiting never fires.
                # Also unpack the returned (action, provider) tuple; comparing the tuple
                # itself against the string "skip" is always False.
                cdn_action, _cdn_provider = await rate_limit_manager.check_cdn(cname_target)
                if cdn_action == "skip":
                    logger.debug(
                        "CDN rate limit: skipping HTTP for %s (CDN=%s)",
                        subdomain_name, _cdn_provider,
                    )
                    await Scheduler.update_subdomain_scan_time(session, subdomain.id)
                    await session.commit()
                    return

            # ── Step 3: HTTP probe ────────────────────────────────────────────
            http_data = None
            if dns_data:
                http_data = await self.components["http"].probe(session, subdomain)

            # ── Step 4: Takeover evaluation ───────────────────────────────────
            eval_result = None
            if dns_data or http_data:
                eval_result = await self.components["evaluator"].evaluate(
                    session, subdomain, dns_data, http_data
                )

            # CLAIMED is terminal but still deserves the one success alert;
            # DANGLING is the pre-claim alert path.
            if subdomain.state in (SubdomainState.DANGLING, SubdomainState.CLAIMED):
                takeover_result = eval_result.get("takeover_result") if eval_result else None
                await self._notify_takeover_immediate(session, subdomain, takeover_result)

            # ── Step 5: Exposure scan (handled by separate loop) ──────────────
            # Exposure scanning runs in its own independent loop per iteration
            # (run_exposure_loop) so it doesn't block or slow subdomain probing.

            await Scheduler.update_subdomain_scan_time(session, subdomain.id)
            await session.commit()
        except Exception as e:
            await session.rollback()
            logger.error(
                # Use the pre-captured string — never touches ORM after async I/O
                "Error probing subdomain %s: %s", subdomain_name, e, exc_info=True
            )

    # ------------------------------------------------------------------
    # DNS takeover sweep — every iteration, all active scopes
    # ------------------------------------------------------------------

    async def _dns_takeover_all_scopes_isolated(self):
        """
        Legacy no-op.

        Scope-root DNS takeover checks now run inside the NS sweep loop so
        there is only one DNS/NS-focused sweep path.
        """
        logger.debug("dns_takeover: standalone sweep disabled; handled by ns_sweep")

    async def _ns_sweep_scope_roots(self) -> int:
        """
        Run scope-root NS takeover checks as part of the NS sweep cadence.

        This replaces the old standalone dns_takeover sweep so there is only
        one periodic DNS/NS sweep loop in the daemon.
        """
        try:
            async with get_session() as session:
                result = await session.execute(
                    select(Scope).options(selectinload(Scope.program)).where(Scope.is_active.is_(True))
                )
                scopes = result.scalars().all()
        except Exception as exc:
            logger.error("ns_sweep: failed to fetch scope roots: %s", exc)
            return 0

        seen_roots: set[str] = set()
        scope_data: list[tuple[str, str, str]] = []
        for scope in scopes:
            root = scope.domain.lstrip("*").lstrip(".").lower().strip()
            if not root or root in seen_roots:
                continue
            seen_roots.add(root)
            program_name = scope.program.name if scope.program else "unknown"
            platform = scope.program.platform.value if scope.program else "unknown"
            scope_data.append((root, program_name, platform))

        if not scope_data:
            return 0

        scanner = self.components["dns_scanner"]
        concurrency = getattr(settings, "DNS_TAKEOVER_SWEEP_CONCURRENCY", 10)
        sem = asyncio.Semaphore(concurrency)
        finding_count = 0

        logger.info("ns_sweep: checking %d scope roots", len(scope_data))

        async def _check_one(domain: str, program_name: str, platform: str) -> None:
            nonlocal finding_count
            async with sem:
                try:
                    finding = await scanner.check_scope(domain)
                    if finding:
                        finding.scope_domain = finding.scope_domain or domain
                        if not getattr(finding, "program_name", ""):
                            finding.program_name = program_name
                        if not getattr(finding, "platform", ""):
                            finding.platform = platform
                        await self._handle_dns_takeover_finding(finding)
                        finding_count += 1

                    wildcard_a = await scanner.check_wildcard_a_findings(
                        domain=domain,
                        scope_domain=domain,
                        program_name=program_name,
                        platform=platform,
                    )
                    for wf in wildcard_a:
                        await self._handle_dangling_ip(wf)
                        finding_count += 1
                except asyncio.CancelledError:
                    raise
                except Exception as exc:
                    logger.warning("ns_sweep: root check error for %s: %s", domain, exc)

        await asyncio.gather(
            *[_check_one(domain, program_name, platform) for domain, program_name, platform in scope_data],
            return_exceptions=True,
        )
        return finding_count

    async def _dns_takeover_scope_sweep(self):
        """
        Background task: run DNSTakeoverProber.check() on every active scope.

        Concurrency is capped by DNS_TAKEOVER_SWEEP_CONCURRENCY: without it,
        thousands of simultaneous DNS coroutines slow each other down under
        OS socket pressure.
        """
        try:
            async with get_session() as session:
                result = await session.execute(
                    select(Scope.domain).where(Scope.is_active.is_(True))
                )
                raw_domains = [row[0] for row in result.fetchall()]
        except Exception as exc:
            logger.error("dns_takeover: failed to fetch scope domains: %s", exc)
            return

        # Strip wildcard prefixes before passing to check_scope().
        # Scope domains are stored as "*.example.com" — passing the literal
        # string to _get_nameservers() queries for NS records of "*.example.com"
        # in the parent zone, which always returns NXDOMAIN.  check_scope() then
        # returns None for every wildcard-prefixed scope, silently skipping NS
        # takeover detection for the majority of program scopes.
        # Deduplicate so *.example.com and example.com don't double-check.
        seen_roots: set = set()
        domains: list = []
        for d in raw_domains:
            root = d.lstrip("*").lstrip(".").lower().strip()
            if root and root not in seen_roots:
                seen_roots.add(root)
                domains.append(root)

        if not domains:
            return

        logger.info("dns_takeover sweep: checking %d active scopes", len(domains))

        # Semaphore caps concurrent DNS coroutines — created lazily inside the
        # running loop (same pattern as subfinder/puredns semaphores).
        concurrency = getattr(settings, "DNS_TAKEOVER_SWEEP_CONCURRENCY", 10)
        sem = asyncio.Semaphore(concurrency)

        async def _check_one(domain):
            async with sem:
                try:
                    # ── Standard NS / wildcard CNAME check ───────────────────
                    finding = await self.components["dns_takeover"].check_scope(domain)
                    if finding:
                        await self._handle_dns_takeover_finding(finding)

                    # ── Wildcard A dangling IP check ─────────────────────────
                    # *.domain A <cloud_ip> — every subdomain is simultaneously
                    # vulnerable if the IP is free. Runs DanglingIPAnalyzer and
                    # routes confirmed findings to _handle_dangling_ip.
                    wildcard_a = await self.components["dns_takeover"].check_wildcard_a_findings(
                        domain=domain,
                        scope_domain=domain,
                        program_name="",
                        platform="",
                    )
                    for wf in wildcard_a:
                        await self._handle_dangling_ip(wf)

                except asyncio.CancelledError:
                    raise
                except Exception as e:
                    logger.warning(
                        "dns_takeover sweep: error checking %s: %s", domain, e
                    )

        await asyncio.gather(*[_check_one(d) for d in domains], return_exceptions=True)
        logger.debug("dns_takeover sweep: done")

    # ------------------------------------------------------------------
    # Recheck POTENTIAL subdomains
    # ------------------------------------------------------------------

    async def _recheck_potential_subdomains_isolated(self):
        async with get_session() as session:
            potential_subdomains = (
                await Scheduler.get_potential_subdomains_needing_recheck(
                    session, limit=50
                )
            )

        if not potential_subdomains:
            return

        logger.debug("Rechecking %d POTENTIAL subdomains", len(potential_subdomains))

        for sd in potential_subdomains:
            task = asyncio.create_task(self._probe_task_wrapper(sd.id, sd.name))
            self.active_tasks.add(task)
            task.add_done_callback(self.active_tasks.discard)

    async def _recheck_potential_long_subdomains_isolated(self):
        """Recheck POTENTIAL_LONG subdomains on the slower POTENTIAL_LONG_RECHECK_HOURS cadence.

        These are ownership-blocked findings (Vercel NEEDS_TXT, Netlify
        domain_claimed_elsewhere) where the blocking account needs to act first.
        We probe them far less often to avoid hammering provider APIs uselessly.
        """
        from sqlalchemy.exc import DBAPIError

        try:
            async with get_session() as session:
                potential_long_subdomains = (
                    await Scheduler.get_potential_long_subdomains_needing_recheck(
                        session, limit=50
                    )
                )
        except DBAPIError as exc:
            # Guard against the DB enum not yet containing 'potential_long'.
            # This happens if run_enum_migrations() failed at startup (e.g. DB
            # was unreachable).  Skip gracefully — will succeed next iteration.
            if "invalid input value for enum" in str(exc).lower():
                logger.warning(
                    "POTENTIAL_LONG recheck skipped — DB enum 'subdomainstate' missing "
                    "'potential_long' value. Run manually: "
                    "ALTER TYPE subdomainstate ADD VALUE IF NOT EXISTS 'potential_long';"
                )
            else:
                logger.warning("POTENTIAL_LONG recheck DB error (skipping): %s", exc)
            return
        except Exception as exc:
            logger.warning("POTENTIAL_LONG recheck skipped (unexpected error): %s", exc)
            return

        if not potential_long_subdomains:
            return

        logger.debug(
            "Rechecking %d POTENTIAL_LONG subdomains (ownership-blocked)",
            len(potential_long_subdomains),
        )

        for sd in potential_long_subdomains:
            task = asyncio.create_task(self._probe_task_wrapper(sd.id, sd.name))
            self.active_tasks.add(task)
            task.add_done_callback(self.active_tasks.discard)

    async def _recheck_dangling_retries_isolated(self):
        """Re-probe DANGLING findings whose attempt retry timestamp has elapsed.

        FAIL/UNAVAILABLE/validation-failed outcomes schedule a retry in
        TAKEOVER_RETRY_HOURS; NOT_IMPL/manual outcomes in TAKEOVER_RETRY_DAYS.
        Findings without a recorded outcome are never selected here — they are
        still covered by the normal stale-subdomain rescan.
        """
        try:
            async with get_session() as session:
                due = await Scheduler.get_dangling_subdomains_needing_retry(
                    session, limit=50
                )
        except Exception as exc:
            logger.warning("DANGLING retry recheck skipped: %s", exc)
            return

        if not due:
            return

        logger.debug("Rechecking %d DANGLING subdomains with a due retry", len(due))
        for sd in due:
            task = asyncio.create_task(self._probe_task_wrapper(sd.id, sd.name))
            self.active_tasks.add(task)
            task.add_done_callback(self.active_tasks.discard)

    # ------------------------------------------------------------------
    # Discord notifications
    # ------------------------------------------------------------------

    async def _process_notifications_isolated(self):
        async with get_session() as session:
            already_notified = (
                select(Notification.id)
                .where(
                    and_(
                        Notification.subdomain_id == Subdomain.id,
                        Notification.channel == NotificationChannel.DISCORD,
                        Notification.confidence >= Subdomain.confidence,
                    )
                )
                .correlate(Subdomain)
            )

            stmt = (
                select(Subdomain)
                .where(
                    and_(
                        Subdomain.state == SubdomainState.DANGLING,
                        Subdomain.confidence >= StateManager.DANGLING_THRESHOLD,
                        ~exists(already_notified),
                    )
                )
                # Eagerly load scope → program so discord.py can read
                # subdomain.scope.program.name without triggering lazy-load
                # errors in async SQLAlchemy.
                .options(selectinload(Subdomain.scope).selectinload(Scope.program))
                .order_by(Subdomain.confidence.desc())
                .limit(50)
            )

            result = await session.execute(stmt)
            candidates = list(result.scalars().all())
            if not candidates:
                return

            # Filter to only claimable subdomains before alerting.
            # NOT_VULN  — provider confirmed resource still exists, nothing to claim.
            # NEEDS_TXT — ownership-blocked, already in POTENTIAL_LONG (shouldn't be
            #             DANGLING), but guard here too.
            def _is_claimable(sd: Subdomain) -> bool:
                if not sd.takeover_evidence:
                    return True
                try:
                    ev = json.loads(sd.takeover_evidence)
                    takeover_ev = ev.get("takeover") or {}
                    status = takeover_ev.get("status", "")
                    if status in ("not_vuln", "needs_txt"):
                        return False
                    if takeover_ev.get("evidence", {}).get("domain_claimed_elsewhere"):
                        return False
                except (json.JSONDecodeError, TypeError, AttributeError):
                    pass
                return True

            to_notify = [sd for sd in candidates if _is_claimable(sd)]
            if not to_notify:
                return

            # Resolve program names NOW while the session is open and the
            # selectinload'd relationships are accessible. Once we hit any
            # asyncio.sleep() inside notify(), SQLAlchemy expires the attributes
            # and lazy-loading fails with a greenlet error.
            to_notify_with_names = [
                (
                    sd,
                    sd.scope.program.name
                    if sd.scope and sd.scope.program
                    else f"scope:{sd.scope_id}",
                    sd.scope.program.platform.value
                    if sd.scope and sd.scope.program
                    else "unknown",
                )
                for sd in to_notify
            ]

            from app.notify.discord import DiscordNotifier

            notifier = DiscordNotifier()

            try:
                await notifier.notify(to_notify_with_names)
            except Exception as e:
                logger.error("Discord notify failed: %s", e)

            for subdomain, _, __ in to_notify_with_names:
                session.add(
                    Notification(
                        subdomain_id=subdomain.id,
                        channel=NotificationChannel.DISCORD,
                        confidence=subdomain.confidence,
                        payload=json.dumps(
                            {
                                "subdomain": subdomain.name,
                                "confidence": subdomain.confidence,
                                "provider": subdomain.takeover_provider,
                                "state": subdomain.state.value,
                            }
                        ),
                    )
                )
            await session.commit()

    async def _run_domain_buy_scanner_isolated(self) -> None:
        """Fire-and-forget the domain buy scanner as a background task."""
        if not getattr(settings, "DOMAIN_BUY_SCANNER_ENABLED", True):
            return
        if self.components.get("domain_buy") is None:
            return
        asyncio.create_task(self._domain_buy_scan())

    async def _exposure_loop(self) -> None:
        """
        Independent exposure scanner loop — runs entirely outside the main scan loop.
        Starts immediately on daemon launch and runs continuously with a short
        sleep between cycles so the event loop stays responsive.
        """
        while self.running:
            try:
                await self.components["exposure"].run_exposure_loop(
                    notify_callback=self._notify_exposure,
                )
            except asyncio.CancelledError:
                raise
            except Exception as e:
                logger.error("exposure: loop error: %s", e, exc_info=True)
            # Short sleep between cycles — keeps the loop running continuously
            # without busy-spinning. The actual scan cadence is governed by
            # EXPOSURE_BATCH_SIZE and how fast run_exposure_loop completes.
            await asyncio.sleep(5)

    async def _run_exposure_loop_isolated(self) -> None:
        # No-op — exposure loop now runs as a persistent background task started
        # at daemon launch (_exposure_loop). Kept to avoid AttributeError if called.
        pass

    async def _git_scanner_loop(self) -> None:
        """
        Independent git repository secret scanner loop — runs entirely outside
        the main scan loop. Starts immediately on daemon launch, then repeats
        according to GIT_SCANNER_INTERVAL_HOURS inside GitScanner.run_loop().
        """
        if "git_scanner" not in self.components:
            return
        try:
            await self.components["git_scanner"].run_loop()
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            logger.error("git_scanner: loop crashed: %s", exc, exc_info=True)

    async def _platform_sync_loop(self) -> None:
        """Poll platform due-times and resync programs/scopes when due.

        Runs as an independent task so a slow or failing platform API cannot
        delay the main scan loop. Each platform is isolated inside
        run_platform_syncs().
        """
        from app.programs.sync import run_platform_syncs

        poll_seconds = max(
            10, int(getattr(settings, "PLATFORM_SYNC_POLL_SECONDS", 60) or 60)
        )
        while self.running:
            try:
                await run_platform_syncs(
                    missing_credentials_warned=self._platform_sync_warned,
                )
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                logger.error("platform_sync: loop error: %s", exc, exc_info=True)
            await asyncio.sleep(poll_seconds)

    async def _ns_sweep_loop(self) -> None:
        """
        Independent NS sweep loop — runs entirely outside the main scan loop.
        Starts immediately on daemon launch, then repeats every
        NS_SWEEP_INTERVAL_HOURS (default 168 = weekly).

        Batch size is controlled by NS_SWEEP_BATCH_SIZE (default 1000).
        Pagination is cursor-based (ORDER BY last_ns_sweep_at ASC NULLS FIRST
        + WHERE last_ns_sweep_at < sweep_start), which is why a true prefetch
        pipeline is not viable: the next batch of unprocessed rows only becomes
        visible to the DB query AFTER run_sweep() stamps last_ns_sweep_at for
        the current batch (inside _persist()). Starting a prefetch before
        run_sweep() returns would fetch the same rows again.
        """
        while self.running:
            interval_hours = getattr(settings, "NS_SWEEP_INTERVAL_HOURS", 168)
            logger.info("ns_sweep: launching sweep (interval=%dh)", interval_hours)
            try:
                total_count = 0
                loops_counter = 0
                batch_size = int(getattr(settings, "NS_SWEEP_BATCH_SIZE", 1000))

                from datetime import datetime as _dt
                sweep_start = _dt.utcnow()

                total_count += await self._ns_sweep_scope_roots()

                # Pre-filter dead resolvers before the sweep begins.
                # Samples the pool, removes resolvers that fail repeated probes
                # with a short timeout, so the sweep doesn't burn time on timeout
                # retries against IPs that never respond.  Expected effect:
                # removes 30-50% of dead entries, cutting dns= and ns_check= by ~50%.
                # Both dns_scanner and dns_takeover share the same pool object
                # (via get_pool()), so warming one effectively warms both.
                if getattr(settings, "NS_SWEEP_WARM_POOL_ENABLED", True):
                    for _scanner_key in ("dns_scanner", "dns_takeover"):
                        _scanner = self.components.get(_scanner_key)
                        if _scanner is not None and hasattr(_scanner, "warm_pool"):
                            try:
                                await _scanner.warm_pool()
                            except Exception as _wp_exc:
                                logger.warning(
                                    "ns_sweep: warm_pool failed for %s: %s",
                                    _scanner_key, _wp_exc,
                                )
                            break  # both components share the same pool — warm once

                _dead_states = [SubdomainState.DEAD, SubdomainState.FALSE_POSITIVE]

                while True:
                    async with get_session() as session:
                        result = await session.execute(
                            select(Subdomain)
                            .join(Subdomain.scope)
                            .options(
                                selectinload(Subdomain.scope).selectinload(Scope.program)
                            )
                            .where(
                                Scope.is_active.is_(True),
                                Subdomain.state.notin_(_dead_states),
                                (Subdomain.last_ns_sweep_at.is_(None)) |
                                (Subdomain.last_ns_sweep_at < sweep_start),
                            )
                            .order_by(Subdomain.last_ns_sweep_at.asc().nullsfirst())
                            .limit(batch_size)
                        )
                        batch = result.scalars().all()
                        session.expunge_all()

                    if not batch:
                        break

                    loops_counter += 1

                    logger.info(
                        "ns_sweep: processing batch of %d subdomains. Loops counter: %d",
                        len(batch), loops_counter,
                    )
                    count_result = await self.components["ns_sweep"].run_sweep(
                        batch,
                        ns_finding_callback=self._handle_subdomain_ns_finding,
                        dangling_ip_callback=self._handle_dangling_ip,
                    )
                    # run_sweep returns (ns_findings, dangling_findings)
                    ns_c, dangling_c = count_result if isinstance(count_result, tuple) else (count_result, 0)
                    total_count += ns_c + dangling_c


                    if len(batch) < batch_size:
                        break  # last (short) batch — no more rows to fetch

                logger.info("ns_sweep: finished — %d finding(s) total", total_count, )
            except asyncio.CancelledError:
                raise
            except Exception as e:
                logger.error("ns_sweep: error during sweep: %s", e, exc_info=True)

            logger.info("ns_sweep: next run in %dh", interval_hours)
            await asyncio.sleep(interval_hours * 3600)

    async def _spf_dmarc_sweep_loop(self) -> None:
        """
        Independent SPF/DMARC sweep loop — runs entirely outside the main scan loop.
        Starts immediately on daemon launch, then repeats every
        NS_SWEEP_INTERVAL_HOURS (same cadence as the NS sweep, default 168h = weekly).

        For each active scope root domain, calls check_spf_dmarc() to detect:
          - Dangling SPF include: targets (NXDOMAIN or NS takeover)
          - DMARC _dmarc NS delegation takeover

        Rate-limited per scope via dns_takeover_notified_at (same cooldown
        as NS sweep findings — DNS_TAKEOVER_RENOTIFY_HOURS, default 24h).
        """
        from app.probing.dns_scanner.ip_indicators import check_spf_dmarc

        while self.running:
            interval_hours = getattr(settings, "NS_SWEEP_INTERVAL_HOURS", 168)
            logger.info("spf_dmarc: launching sweep (interval=%dh)", interval_hours)

            try:
                # Fetch all active scope domains + program info
                async with get_session() as session:
                    from sqlalchemy.orm import selectinload as _sil
                    result = await session.execute(
                        select(Scope)
                        .options(_sil(Scope.program))
                        .where(Scope.is_active.is_(True))
                    )
                    scopes = result.scalars().all()
                    # Strip wildcard prefixes (*.example.com → example.com) and
                    # deduplicate — multiple wildcard + apex entries for the same
                    # root domain should only be checked once.
                    seen_roots: set = set()
                    scope_data = []
                    for s in scopes:
                        root = s.domain.lstrip("*").lstrip(".").lower()
                        if not root or root in seen_roots:
                            continue
                        seen_roots.add(root)
                        scope_data.append((
                            root,
                            s.program.name if s.program else "unknown",
                            s.program.platform.value if s.program else "unknown",
                        ))

                logger.info("spf_dmarc: checking %d active scope domains", len(scope_data))

                concurrency = getattr(settings, "DNS_TAKEOVER_SWEEP_CONCURRENCY", 10)
                sem = asyncio.Semaphore(concurrency)
                finding_count = 0

                async def _check_scope_spf(domain, prog_name, plat):
                    nonlocal finding_count
                    async with sem:
                        try:
                            findings = await check_spf_dmarc(
                                scope_domain=domain,
                                program_name=prog_name,
                                platform=plat,
                            )
                            for f in findings:
                                await self._handle_spf_dmarc_finding(f)
                                finding_count += 1
                        except asyncio.CancelledError:
                            raise
                        except Exception as exc:
                            logger.debug(
                                "spf_dmarc: error checking %s: %s", domain, exc
                            )

                await asyncio.gather(
                    *[_check_scope_spf(d, p, pl) for d, p, pl in scope_data],
                    return_exceptions=True,
                )

                logger.info("spf_dmarc: sweep finished — %d finding(s)", finding_count)

            except asyncio.CancelledError:
                raise
            except Exception as exc:
                logger.error("spf_dmarc: sweep error: %s", exc, exc_info=True)

            logger.info("spf_dmarc: next run in %dh", interval_hours)
            await asyncio.sleep(interval_hours * 3600)

    async def _handle_spf_dmarc_finding(self, finding) -> None:
        """
        Notify and optionally persist a SpfDmarcFinding from check_spf_dmarc().

        Rate-limited per scope via dns_takeover_notified_at (same cooldown used
        by NS sweep and dangling IP findings — DNS_TAKEOVER_RENOTIFY_HOURS).

        Finding types and severity:
          spf_include_nxdomain  — medium — SPF broken, re-register → bypass
          spf_include_takeover  — high   — NS claimable → arbitrary SPF → spoof email
          dmarc_ns_takeover     — high   — NS claimable → disable enforcement / exfil reports
        """
        from app.db.db_models import Scope as _SC
        from app.notify.discord import DiscordNotifier
        from sqlalchemy import select as _sel
        from sqlalchemy.orm import selectinload as _sil

        logger.info(
            "spf_dmarc: FINDING for %s — type=%s target=%s severity=%s",
            finding.scope_domain, finding.finding_type,
            finding.target_domain, finding.severity,
        )

        # Rate-limit check — reuse scope's dns_takeover_notified_at
        scope_id = None
        dns_takeover_notified_at = None
        program_name = finding.program_name or "unknown"
        platform     = finding.platform     or "unknown"

        try:
            async with get_session() as session:
                result = await session.execute(
                    _sel(_SC)
                    .options(_sil(_SC.program))
                    .where(_SC.domain == finding.scope_domain)
                )
                scope = result.scalar_one_or_none()
                if scope:
                    scope_id                 = scope.id
                    dns_takeover_notified_at = scope.dns_takeover_notified_at
                    if scope.program:
                        program_name = scope.program.name
                        platform     = scope.program.platform.value
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            logger.error(
                "spf_dmarc: scope lookup failed for %s: %s",
                finding.scope_domain, exc,
            )

        webhook_url = settings.DISCORD_WEBHOOK_URL
        if not webhook_url:
            return

        async with self._get_notify_lock(finding.scope_domain):
            renotify_hours  = getattr(settings, "DNS_TAKEOVER_RENOTIFY_HOURS", 24)
            renotify_cutoff = datetime.utcnow() - timedelta(hours=renotify_hours)

            _notified_at = None
            if scope_id is not None:
                try:
                    async with get_session() as chk_session:
                        _r = await chk_session.execute(
                            _sel(_SC).where(_SC.id == scope_id)
                        )
                        _chk = _r.scalar_one_or_none()
                        if _chk:
                            _notified_at = _chk.dns_takeover_notified_at
                except asyncio.CancelledError:
                    raise
                except Exception as exc:
                    logger.warning("spf_dmarc: cooldown re-read failed for %s: %s",
                                   finding.scope_domain, exc)

            if _notified_at and _notified_at > renotify_cutoff:
                logger.debug(
                    "spf_dmarc: suppressing repeat notify for %s "
                    "(last=%s cooldown=%dh)",
                    finding.scope_domain,
                    _notified_at.strftime("%Y-%m-%d %H:%M"),
                    renotify_hours,
                )
                return

            try:
                notifier = DiscordNotifier(webhook_url=webhook_url)
                await notifier.notify_spf_dmarc(
                    finding,
                    program_name=program_name,
                    platform=platform,
                )

                if scope_id is not None:
                    async with get_session() as stamp_session:
                        _r = await stamp_session.execute(
                            _sel(_SC).where(_SC.id == scope_id)
                        )
                        _scope_stamp = _r.scalar_one_or_none()
                        if _scope_stamp:
                            _scope_stamp.dns_takeover_notified_at = datetime.utcnow()
                            await stamp_session.commit()
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                logger.error(
                    "spf_dmarc: discord notify failed for %s: %s",
                    finding.target_domain, exc,
                )

    async def _cidr_refresh_loop(self, cidr_index) -> None:
        """
        Periodic CIDR index refresh — runs as a background task.

        Refreshes every CIDR_INDEX_MAX_AGE_HOURS (default 24h).
        After each successful refresh, re-injects the updated index so the
        next NS sweep batch immediately benefits from the new data.

        Failures are non-fatal — old index stays in place and the warning
        is logged. The loop always continues after a failed refresh.
        """
        from app.core.config import settings as _settings
        while self.running:
            max_age_hours = int(getattr(_settings, "CIDR_INDEX_MAX_AGE_HOURS", 24))
            await asyncio.sleep(max_age_hours * 3600)
            if not self.running:
                break
            logger.info("cidr_index: refreshing provider IP ranges (interval=%dh)...", max_age_hours)
            try:
                await cidr_index.refresh()
                self._inject_cidr_index(cidr_index)
                logger.info("cidr_index: refresh complete — index re-injected")
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                logger.warning("cidr_index: refresh failed (%s) — keeping stale index", exc)

    async def _domain_buy_scan(self) -> None:
        """Background task: run the buy scanner in its own DB session."""
        try:
            async with get_session() as session:
                await self.components["domain_buy"].run(session)
        except Exception as exc:
            logger.error("domain_buy_scanner error: %s", exc, exc_info=True)

    async def _domain_buy_backfill(self) -> None:
        """Background task: WHOIS-register all existing scope domains on startup."""
        try:
            from app.db.db_models import Scope as _Scope
            from sqlalchemy import select as _select
            from app.probing.domain_buy_scanner import _extract_root_domain as _erd

            async with get_session() as _session:
                _result = await _session.execute(
                    _select(_Scope.domain).where(_Scope.is_active.is_(True))
                )
                _domains = list({
                    _erd(row[0])
                    for row in _result.fetchall()
                    if _erd(row[0])
                })

            logger.info("domain_buy: backfilling %d unique root domain(s)", len(_domains))
            for _domain in _domains:
                try:
                    async with get_session() as _session:
                        await self.components["domain_buy"].register_domain(_session, _domain)
                except Exception as _exc:
                    logger.warning("domain_buy: backfill failed for %s: %s", _domain, _exc)

            logger.info("domain_buy: backfill complete")
        except Exception as exc:
            logger.warning("domain_buy: backfill error: %s", exc)

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def _handle_dns_takeover_finding(self, finding) -> None:
        """
        Persist and notify a DNS takeover finding.

        Stores the finding on the Scope row (takeover_provider, confidence)
        and sends a Discord alert. Uses a distinct message format to make
        clear this is a DNS-level issue, not a subdomain CNAME issue.
        """
        from app.db.db_models import Scope as _SC
        from app.notify.discord import DiscordNotifier

        logger.info(
            "dns_takeover: FINDING for %s — provider=%s ns=%s rcode=%s",
            finding.scope_domain, finding.provider, finding.nameserver, finding.rcode,
        )

        if not self._is_yaml_ns_takeover_finding(finding):
            logger.debug(
                "dns_takeover: suppressing non-YAML finding for %s "
                "(provider=%s rcode=%s)",
                finding.scope_domain, finding.provider, finding.rcode,
            )
            return

        # Persist on the Scope row so it shows up in the DB
        program_name = "unknown"
        platform = "unknown"
        scope_id = None
        dns_takeover_notified_at = None
        try:
            async with get_session() as session:
                from sqlalchemy.orm import selectinload as _sil
                result = await session.execute(
                    __import__('sqlalchemy').select(_SC)
                    .options(_sil(_SC.program))
                    .where(_SC.domain == finding.scope_domain)
                )
                scope = result.scalar_one_or_none()
                if scope:
                    scope_id = scope.id
                    dns_takeover_notified_at = scope.dns_takeover_notified_at
                    if scope.program:
                        program_name = scope.program.name
                        platform = scope.program.platform.value
                    await session.commit()
        except asyncio.CancelledError:
            raise
        except Exception as e:
            logger.error("dns_takeover: failed to persist finding for %s: %s", finding.scope_domain, e)

        # Discord notification — rate-limited to once per DNS_TAKEOVER_RENOTIFY_HOURS (default 24h)
        #
        # For scope root domains (handled here, not subdomain sweep) only notify
        # on NS mismatch — unclaimed zone on a root domain is a false positive
        # in practice and not worth the noise.
        if "AWS Route 53" in finding.provider and "NS mismatch" not in finding.provider:
            logger.debug(
                "dns_takeover: suppressing root-domain notify for %s — "
                "provider '%s' is not NS mismatch (unclaimed zone on root, skipping)",
                finding.scope_domain, finding.provider,
            )
            return

        if settings.DISCORD_WEBHOOK_URL:
            # Re-read dns_takeover_notified_at inside the lock so we see the
            # value written by any coroutine that beat us here.
            async with self._get_notify_lock(finding.scope_domain):
                renotify_hours = getattr(settings, "DNS_TAKEOVER_RENOTIFY_HOURS", 24)
                renotify_cutoff = datetime.utcnow() - timedelta(hours=renotify_hours)

                # Re-read stamp inside the lock
                _notified_at = None
                if scope_id is not None:
                    try:
                        async with get_session() as chk_session:
                            _r = await chk_session.execute(
                                __import__('sqlalchemy').select(_SC).where(_SC.id == scope_id)
                            )
                            _chk = _r.scalar_one_or_none()
                            if _chk:
                                _notified_at = _chk.dns_takeover_notified_at
                    except asyncio.CancelledError:
                        raise
                    except Exception as exc:
                        logger.warning("dns_takeover: cooldown re-read failed for %s: %s",
                                       finding.scope_domain, exc)

                if _notified_at and _notified_at > renotify_cutoff:
                    logger.debug(
                        "dns_takeover: suppressing repeat notify for %s "
                        "(last notified %s, cooldown %dh)",
                        finding.scope_domain,
                        _notified_at.strftime("%Y-%m-%d %H:%M"),
                        renotify_hours,
                    )
                    return

                try:
                    notifier = DiscordNotifier()
                    await notifier.notify_dns_takeover(finding, program_name=program_name, platform=platform)

                    # Stamp dns_takeover_notified_at so we don't fire again for 24h
                    if scope_id is not None:
                        async with get_session() as stamp_session:
                            _r = await stamp_session.execute(
                                __import__('sqlalchemy').select(_SC).where(_SC.id == scope_id)
                            )
                            _scope_stamp = _r.scalar_one_or_none()
                            if _scope_stamp:
                                _scope_stamp.dns_takeover_notified_at = datetime.utcnow()
                                await stamp_session.commit()
                except asyncio.CancelledError:
                    raise
                except Exception as e:
                    logger.error("dns_takeover: discord notify failed: %s", e)

        # ── Route 53 NS lottery — parent domain path ──────────────────────────
        # Scope-root domains are never taken over automatically.
        # We enqueue with is_parent=True so Route53TakeoverQueue fires a Discord
        # alert only and returns without attempting the lottery.
        if "awsdns" in finding.nameserver.lower():
            try:
                await Route53TakeoverQueue.enqueue(
                    subdomain_id   = scope_id or 0,
                    subdomain_name = finding.scope_domain,
                    nameservers    = getattr(finding, "all_nameservers", [finding.nameserver]),
                    program_name   = program_name,
                    platform       = platform,
                    scope_id       = scope_id or 0,
                    # Scope roots are never claimed automatically — the queue
                    # alerts only and returns without attempting the lottery.
                    is_parent      = True,
                )
            except Exception as _eq:
                logger.warning(
                    "dns_takeover: Route53TakeoverQueue.enqueue (parent) failed for %s: %s",
                    finding.scope_domain, _eq,
                )

    async def _handle_subdomain_ns_finding(self, finding) -> None:
        """
        Notify and persist a SubdomainNSFinding from the NS sweep.

        Distinct from _handle_dns_takeover_finding (scope-root path):
          - The vulnerable entity is the subdomain, not the scope root.
          - Route 53 / Azure DNS enqueue is already done inside
            SubdomainNSSweeper._check_one — we must NOT re-enqueue here.
          - Discord dedup reuses the scope's dns_takeover_notified_at so
            repeat notifications for the same scope are rate-limited to once
            per DNS_TAKEOVER_RENOTIFY_HOURS (default 24 h).
        """
        from app.db.db_models import Scope as _SC
        from app.notify.discord import DiscordNotifier

        logger.info(
            "ns_sweep: FINDING for subdomain %s — provider=%s ns=%s rcode=%s",
            finding.subdomain_name, finding.provider, finding.nameserver, finding.rcode,
        )

        if not self._is_yaml_ns_takeover_finding(finding):
            logger.debug(
                "ns_sweep: suppressing non-YAML finding for %s "
                "(provider=%s rcode=%s)",
                finding.subdomain_name, finding.provider, finding.rcode,
            )
            return

        # ── Persist on the Scope row ──────────────────────────────────────────
        scope_id = None
        dns_takeover_notified_at = None
        try:
            async with get_session() as session:
                from sqlalchemy.orm import selectinload as _sil
                result = await session.execute(
                    __import__('sqlalchemy').select(_SC)
                    .options(_sil(_SC.program))
                    .where(_SC.domain == finding.scope_domain)
                )
                scope = result.scalar_one_or_none()
                if scope:
                    scope_id = scope.id
                    dns_takeover_notified_at = scope.dns_takeover_notified_at
                    await session.commit()
        except asyncio.CancelledError:
            raise
        except Exception as e:
            logger.error(
                "ns_sweep: failed to persist finding for %s: %s",
                finding.subdomain_name, e,
            )

        if self._has_auto_ns_takeover_logic(finding):
            logger.info(
                "ns_sweep: suppressing discovery notify for %s — auto-confirmation "
                "logic exists for nameserver %s",
                finding.subdomain_name, finding.nameserver,
            )
            return

        # ── Discord notification — deduped per scope per DNS_TAKEOVER_RENOTIFY_HOURS ─
        if not settings.DISCORD_WEBHOOK_URL:
            return

        async with self._get_notify_lock(finding.scope_domain):
            renotify_hours  = getattr(settings, "DNS_TAKEOVER_RENOTIFY_HOURS", 24)
            renotify_cutoff = datetime.utcnow() - timedelta(hours=renotify_hours)

            _notified_at = None
            if scope_id is not None:
                try:
                    async with get_session() as chk_session:
                        _r = await chk_session.execute(
                            __import__('sqlalchemy').select(_SC).where(_SC.id == scope_id)
                        )
                        _chk = _r.scalar_one_or_none()
                        if _chk:
                            _notified_at = _chk.dns_takeover_notified_at
                except asyncio.CancelledError:
                    raise
                except Exception as exc:
                    logger.warning("ns_sweep: cooldown re-read failed for %s: %s",
                                   finding.scope_domain, exc)

            if _notified_at and _notified_at > renotify_cutoff:
                logger.debug(
                    "ns_sweep: suppressing repeat notify for %s "
                    "(scope last notified %s, cooldown %dh)",
                    finding.subdomain_name,
                    _notified_at.strftime("%Y-%m-%d %H:%M"),
                    renotify_hours,
                )
                return

            try:
                notifier = DiscordNotifier()
                # SubdomainNSFinding carries scope_domain, nameserver, provider,
                # provider_notes, rcode — all fields notify_dns_takeover uses.
                # The title will show the subdomain name (finding.scope_domain = subdomain_name).
                await notifier.notify_dns_takeover(
                    finding,
                    program_name=finding.program_name,
                    platform=finding.platform,
                )

                # Stamp the scope so the same scope doesn't fire again this window
                if scope_id is not None:
                    async with get_session() as stamp_session:
                        _r = await stamp_session.execute(
                            __import__('sqlalchemy').select(_SC).where(_SC.id == scope_id)
                        )
                        _scope_stamp = _r.scalar_one_or_none()
                        if _scope_stamp:
                            _scope_stamp.dns_takeover_notified_at = datetime.utcnow()
                            await stamp_session.commit()
            except asyncio.CancelledError:
                raise
            except Exception as e:
                logger.error("ns_sweep: discord notify failed for %s: %s", finding.subdomain_name, e)

    async def _handle_dangling_ip(self, finding) -> None:
        """
        Handle a DanglingIPFinding from the NS sweep dangling IP analysis.

        Three finding types, each with a distinct alert:

          "dangling"       — IP appears unallocated (no open ports, no allocation
                             signals). Could be claimed via provider API. Alert
                             includes claim command and confidence score.

          "foreign_cert"   — Port 443 open and TLS cert belongs to a DIFFERENT
                             company. The IP has ALREADY been taken by someone
                             else. The original subdomain's DNS is still pointing
                             there — operator must update DNS immediately.
                             This is NOT a claimable finding — it is an INFO/risk
                             alert so the program team can clean up stale DNS.

          "cname_dangling" — IP reached via CNAME chain is dangling. The CNAME
                             target service is gone and its IP is free. Confidence
                             is reduced by 15 vs direct dangling (extra hop).

        Rate-limited per scope via dns_takeover_notified_at cooldown
        (DNS_TAKEOVER_RENOTIFY_HOURS, default 24h).
        """
        from app.notify.discord import DiscordNotifier
        from app.db.db_models import Scope as _SC
        from sqlalchemy import select as _sel
        from sqlalchemy.orm import selectinload as _sil

        finding_type = getattr(finding, "finding_type", "dangling")

        # Decide whether this finding is worth alerting on
        is_alertable = (
            finding.confirmed_free          # dangling / cname_dangling
            or finding.foreign_tls_cert     # foreign cert — IP taken by someone else
            or finding.cloud_claim_confirmed  # AWS direct claim probe succeeded
        )
        if not is_alertable:
            logger.debug(
                "dangling_ip: skipping non-actionable finding for %s "
                "(ip=%s type=%s confidence=%d)",
                finding.subdomain_name, finding.ip, finding_type, finding.confidence,
            )
            return

        logger.info(
            "dangling_ip: FINDING for %s — ip=%s type=%s provider=%s region=%s "
            "confirmed_free=%s foreign_tls=%s cloud_claim=%s confidence=%d",
            finding.subdomain_name, finding.ip, finding_type,
            finding.provider_key, finding.region,
            finding.confirmed_free, finding.foreign_tls_cert,
            finding.cloud_claim_confirmed, finding.confidence,
        )

        # Rate-limit check via scope dns_takeover_notified_at
        scope_id = None
        dns_takeover_notified_at = None
        if finding.scope_domain:
            try:
                async with get_session() as session:
                    result = await session.execute(
                        _sel(_SC).options(_sil(_SC.program))
                        .where(_SC.domain == finding.scope_domain)
                    )
                    scope = result.scalar_one_or_none()
                    if scope:
                        scope_id                 = scope.id
                        dns_takeover_notified_at = scope.dns_takeover_notified_at
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                logger.error("dangling_ip: scope lookup failed for %s: %s",
                             finding.scope_domain, exc)

        if not settings.DISCORD_WEBHOOK_URL:
            return

        scope_key = finding.scope_domain or finding.subdomain_name
        async with self._get_notify_lock(scope_key):
            renotify_hours  = getattr(settings, "DNS_TAKEOVER_RENOTIFY_HOURS", 24)
            renotify_cutoff = datetime.utcnow() - timedelta(hours=renotify_hours)

            _notified_at = None
            if scope_id is not None:
                try:
                    async with get_session() as chk_session:
                        _r = await chk_session.execute(
                            _sel(_SC).where(_SC.id == scope_id)
                        )
                        _chk = _r.scalar_one_or_none()
                        if _chk:
                            _notified_at = _chk.dns_takeover_notified_at
                except asyncio.CancelledError:
                    raise
                except Exception as exc:
                    logger.warning("dangling_ip: cooldown re-read failed for %s: %s",
                                   scope_key, exc)

            if _notified_at and _notified_at > renotify_cutoff:
                logger.debug(
                    "dangling_ip: suppressing repeat notify for %s "
                    "(last=%s cooldown=%dh)",
                    finding.subdomain_name,
                    _notified_at.strftime("%Y-%m-%d %H:%M"),
                    renotify_hours,
                )
                return

            try:
                webhook_url = settings.DISCORD_WEBHOOK_URL
                notifier = DiscordNotifier(webhook_url=webhook_url)
                await notifier.notify_dangling_ip(finding)

                if scope_id is not None:
                    async with get_session() as stamp_session:
                        _r = await stamp_session.execute(
                            _sel(_SC).where(_SC.id == scope_id)
                        )
                        _scope_stamp = _r.scalar_one_or_none()
                        if _scope_stamp:
                            _scope_stamp.dns_takeover_notified_at = datetime.utcnow()
                            await stamp_session.commit()
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                logger.error("dangling_ip: discord notify failed for %s: %s",
                             finding.subdomain_name, exc)

    async def _certstream_probe_callback(
            self,
            new_names: list,
            scope_domain: str,
            cert_all_domains: list | None = None,
            is_cert_triggered: bool = False,
    ) -> None:
        """
        Callback from CertstreamMonitor when new subdomains are discovered
        via CT log cert issuance.

        Dispatches each new subdomain to _certstream_takeover_probe, which
        runs the full expedited takeover pipeline covering three attack windows:

          Scenario 1 — CNAME race:
            New cert → DNS probe finds `CNAME: unclaimed-app.herokudns.com`
            → TakeoverEvaluator fires provider checker immediately
            → HerokuTakeoverChecker creates the app before operator does.

          Scenario 2 — Shadow DNS / dangling cloud IP:
            New cert → NS sweep fires immediately on this subdomain
            → DanglingIPAnalyzer + CIDR index finds released AWS/Azure/GCP IP
            → Alert fires within seconds of cert issuance.

          Scenario 3 — SaaS verification race:
            New cert → HTTP probe fingerprints unclaimed provider state
            (e.g. Vercel verified=false + TXT requirement, Netlify 404 on site)
            → Provider checker attempts claim before operator finishes wizard.

        cert_all_domains is logged for investigative context — seeing all SANs
        on the triggering cert helps understand what else the operator was
        configuring (e.g. both `api.target.com` and `admin.target.com` on same
        cert often means a full infrastructure migration is in progress).
        """
        if cert_all_domains and len(cert_all_domains) > 1:
            logger.info(
                "certstream: cert for %s also covers %d other domain(s): %s",
                scope_domain,
                len(cert_all_domains) - 1,
                ", ".join(d for d in cert_all_domains if d not in new_names)[:200],
            )

        try:
            async with get_session() as session:
                from sqlalchemy import select as _sel
                from sqlalchemy.orm import selectinload as _sil
                scope_result = await session.execute(
                    _sel(Scope).where(Scope.domain == scope_domain)
                )
                scope = scope_result.scalar_one_or_none()
                if not scope:
                    return
                result = await session.execute(
                    _sel(Subdomain)
                    .options(_sil(Subdomain.scope).selectinload(Scope.program))
                    .where(
                        Subdomain.scope_id == scope.id,
                        Subdomain.name.in_(new_names),
                    )
                )
                subdomains = result.scalars().all()
                session.expunge_all()  # detach before closing session

        except asyncio.CancelledError:
            raise
        except Exception as e:
            logger.debug("certstream probe callback error: %s", e)
            return

        for sd in subdomains:
            if is_cert_triggered and getattr(settings, "CERTSTREAM_TAKEOVER_CHECK_ENABLED", True):
                # Expedited takeover pipeline: DNS+HTTP+evaluator+NS sweep now
                task = asyncio.create_task(
                    self._certstream_takeover_probe(
                        sd.id,
                        sd.name,
                        scope_domain,
                        cert_all_domains or [],
                    )
                )
            else:
                # Fallback: standard queued probe (no NS sweep)
                task = asyncio.create_task(
                    self._probe_task_wrapper(sd.id, sd.name)
                )
            self.active_tasks.add(task)
            task.add_done_callback(self.active_tasks.discard)

    async def _certstream_takeover_probe(
            self,
            sd_id: int,
            sd_name: str,
            scope_domain: str,
            cert_all_domains: list,
    ) -> None:
        """
        Expedited full takeover probe triggered by CT log cert issuance.

        Cert issuance is a time-sensitive signal — configuration mistakes and
        unclaimed provider resources are most exploitable in the minutes
        immediately after a cert is issued and before the operator finishes
        the setup wizard.

        Pipeline (runs under the global probe semaphore):

          Phase 1 — Standard probe (DNS + HTTP + TakeoverEvaluator):
            Covers CNAME race (scenario 1) and SaaS verification race (scenario 3).
            Identical to _probe_task_wrapper but logs cert context.

          Phase 2 — NS sweep on this single subdomain (SubdomainNSSweeper):
            Covers shadow DNS / dangling cloud IP (scenario 2).
            Runs CIDR index lookup + port scan + DanglingIPAnalyzer immediately
            rather than waiting for the weekly NS sweep cycle.
            If NS takeover findings are discovered they fire via the standard
            _handle_subdomain_ns_finding Discord pipeline.

        Both phases share the global probe_sem so certstream probes compete
        fairly with normal scan-cycle probes rather than starving them.
        """
        logger.info(
            "certstream takeover probe: starting expedited pipeline for %s "
            "(cert issued, scope=%s, cert_domains=%d)",
            sd_name,
            scope_domain,
            len(cert_all_domains),
        )

        async with self.probe_sem:
            # ── Phase 1: Standard DNS + HTTP + TakeoverEvaluator ──────────────
            # Scenario 1 (CNAME race) and scenario 3 (SaaS verification race)
            # are caught here.  TakeoverEvaluator calls provider checkers
            # (Vercel/Heroku/Netlify/etc.) immediately on DANGLING/POTENTIAL hits.
            try:
                async with get_session() as session:
                    from sqlalchemy import select as _sel
                    stmt = _sel(Subdomain).where(Subdomain.id == sd_id)
                    res = await session.execute(stmt)
                    db_sd = res.scalar_one_or_none()
                    if db_sd:
                        await self._probe_subdomain(session, db_sd)
                        logger.debug(
                            "certstream takeover probe: phase 1 (standard probe) "
                            "complete for %s — state=%s confidence=%s",
                            sd_name,
                            db_sd.state.value if db_sd.state else "?",
                            db_sd.confidence,
                        )
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                logger.debug(
                    "certstream takeover probe: phase 1 error for %s: %s",
                    sd_name, exc,
                )

            # ── Phase 2: NS sweep (CIDR dangling IP + NS takeover) ─────────────
            # Scenario 2 (shadow DNS / dangling cloud IP) is caught here.
            # Fetches the subdomain with eagerly-loaded scope→program so the
            # sweeper can read program_name/platform from the detached object.
            if "ns_sweep" not in self.components:
                logger.debug(
                    "certstream takeover probe: ns_sweep component not available — "
                    "skipping phase 2 for %s",
                    sd_name,
                )
                return

            try:
                async with get_session() as session:
                    from sqlalchemy import select as _sel
                    from sqlalchemy.orm import selectinload as _sil
                    stmt = (
                        _sel(Subdomain)
                        .options(_sil(Subdomain.scope).selectinload(Scope.program))
                        .where(Subdomain.id == sd_id)
                    )
                    res = await session.execute(stmt)
                    db_sd = res.scalar_one_or_none()
                    session.expunge_all()  # detach — sweeper reads plain attrs

                if not db_sd:
                    logger.debug(
                        "certstream takeover probe: subdomain %d not found for phase 2",
                        sd_id,
                    )
                    return

                # Skip NS sweep on states that already have a definitive verdict —
                # no point scanning a subdomain we already marked DEAD or CLAIMED.
                skip_states = {SubdomainState.DEAD, SubdomainState.FALSE_POSITIVE,
                               SubdomainState.CLAIMED}
                if db_sd.state in skip_states:
                    logger.debug(
                        "certstream takeover probe: skipping phase 2 for %s "
                        "(state=%s)",
                        sd_name, db_sd.state.value,
                    )
                    return

                logger.info(
                    "certstream takeover probe: phase 2 — NS sweep + CIDR dangling "
                    "IP check for %s",
                    sd_name,
                )

                ns_count, dangling_count = await self.components["ns_sweep"].run_sweep(
                    [db_sd],
                    ns_finding_callback=self._handle_subdomain_ns_finding,
                    dangling_ip_callback=self._handle_dangling_ip,
                )

                if ns_count or dangling_count:
                    logger.info(
                        "certstream takeover probe: phase 2 findings for %s — "
                        "ns=%d dangling_ip=%d",
                        sd_name, ns_count, dangling_count,
                    )
                else:
                    logger.debug(
                        "certstream takeover probe: phase 2 clean for %s "
                        "(no NS/IP findings)",
                        sd_name,
                    )

            except asyncio.CancelledError:
                raise
            except Exception as exc:
                logger.debug(
                    "certstream takeover probe: phase 2 error for %s: %s",
                    sd_name, exc,
                )

        logger.info(
            "certstream takeover probe: completed for %s "
            "(cert covered %d domain(s) total)",
            sd_name, len(cert_all_domains),
        )

    async def _notify_takeover_immediate(self, session, subdomain: Subdomain, takeover_result=None) -> None:
        """
        Fire a Discord alert immediately when a subdomain flips to DANGLING.
        Includes takeover attempt result label (Success / Fail / N/A).
        """
        if not settings.DISCORD_WEBHOOK_URL:
            return
        if subdomain.confidence < StateManager.DANGLING_THRESHOLD:
            return

        # A validated claim is a one-time terminal event: deliver it even if a
        # prior DANGLING alert exists at the same or higher confidence.
        is_claim_success = (
            takeover_result is not None
            and getattr(getattr(takeover_result, "status", None), "value", None) == "success"
        )

        # Dedup: skip if we already sent a notification at this confidence level
        from sqlalchemy import and_, select as _sel
        if not is_claim_success:
            already_notified = await session.execute(
                _sel(Notification.id).where(
                    and_(
                        Notification.subdomain_id == subdomain.id,
                        Notification.channel == NotificationChannel.DISCORD,
                        Notification.confidence >= subdomain.confidence,
                    )
                ).limit(1)
            )
            if already_notified.scalar_one_or_none() is not None:
                return

        # Resolve program name while session is open
        from sqlalchemy.orm import selectinload
        result = await session.execute(
            _sel(Subdomain)
            .options(selectinload(Subdomain.scope).selectinload(Scope.program))
            .where(Subdomain.id == subdomain.id)
        )
        sd_full = result.scalar_one_or_none()
        if not sd_full:
            return

        program_name = (
            sd_full.scope.program.name
            if sd_full.scope and sd_full.scope.program
            else f"scope:{subdomain.scope_id}"
        )
        platform = (
            sd_full.scope.program.platform.value
            if sd_full.scope and sd_full.scope.program
            else "unknown"
        )

        try:
            from app.notify.discord import DiscordNotifier
            notifier = DiscordNotifier()
            await notifier.notify([(sd_full, program_name, platform)], takeover_result=takeover_result)
        except Exception as e:
            logger.error("immediate takeover notify failed for %s: %s", subdomain.name, e)
            return

        # Commit the Notification row in its own isolated session
        # immediately after Discord confirms delivery.  If we add it to the
        # probe session and that session later rolls back (any exception
        # between here and the final commit), the dedup record is lost and
        # the next iteration re-notifies the same finding.
        import json as _json
        try:
            async with get_session() as notif_session:
                notif_session.add(Notification(
                    subdomain_id=subdomain.id,
                    channel=NotificationChannel.DISCORD,
                    confidence=subdomain.confidence,
                    payload=_json.dumps({
                        "subdomain": subdomain.name,
                        "confidence": subdomain.confidence,
                        "provider": subdomain.takeover_provider,
                        "state": subdomain.state.value,
                        "immediate": True,
                    }),
                ))
                await notif_session.commit()
        except Exception as e:
            logger.warning(
                "Failed to persist notification record for %s: %s — "
                "may re-notify on next cycle",
                subdomain.name, e,
            )

    async def _notify_exposure(self, finding, subdomain) -> None:
        webhook_url = settings.DISCORD_WEBHOOK_URL
        if not webhook_url:
            return
        try:
            from app.notify.discord import DiscordNotifier
            from sqlalchemy import select as _sel
            from sqlalchemy.orm import selectinload as _sil

            program_name = "unknown"
            platform     = "unknown"
            async with get_session() as session:
                result = await session.execute(
                    _sel(Subdomain)
                    .options(_sil(Subdomain.scope).selectinload(Scope.program))
                    .where(Subdomain.id == subdomain.id)
                )
                sd_full = result.scalar_one_or_none()
                if sd_full and sd_full.scope and sd_full.scope.program:
                    program_name = sd_full.scope.program.name
                    platform     = sd_full.scope.program.platform.value

            notifier = DiscordNotifier(webhook_url=webhook_url)
            await notifier.notify_exposure(finding, subdomain, program_name=program_name, platform=platform)
        except asyncio.CancelledError:
            raise
        except Exception as e:
            logger.error("exposure discord notify failed: %s", e)

    async def _ip_hunter_loop(self) -> None:
        try:
            await self.components["ip_hunter"].run()
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            logger.error("ip_hunter: fatal error: %s", exc, exc_info=True)

    def _setup_signal_handlers(self):
        loop = asyncio.get_running_loop()

        def signal_handler(signum):
            logger.info(
                "Received signal %d — starting graceful shutdown "
                "(flushing cloud IP allocations before exit)",
                signum,
            )
            self.running = False
            # Schedule graceful shutdown as a task so we can await the
            # ip_hunter cleanup before killing everything.  The signal handler
            # itself is synchronous and cannot await directly.
            loop.create_task(self._shutdown_gracefully())

        for sig in (signal.SIGINT, signal.SIGTERM):
            loop.add_signal_handler(sig, lambda s=sig: signal_handler(s))

    async def _shutdown_gracefully(self) -> None:
        """
        Graceful shutdown sequence:

          1. Cancel all background tasks EXCEPT ip_hunter immediately —
             they have no cloud resources to clean up.
          2. Cancel ip_hunter and wait up to 30 s for it to finish.
             During this window, aws_eip.hunt() catches CancelledError,
             flushes its EIP bucket (releases non-hit IPs back to AWS),
             and re-raises.  DO/GCP/Azure release per-round so they have
             no held state; _purge_stranded handles any leaks on next start.
          3. Cancel any tasks that are still alive and exit.
        """
        logger.info("ip_hunter: waiting for provider cleanup before exit...")

        # ── Step 1: cancel everything except ip_hunter ────────────────────
        for task, name in [
            (self._certstream_task,  "certstream"),
            (self._ns_sweep_task,    "ns_sweep"),
            (self._exposure_task,    "exposure"),
            (self._git_scanner_task, "git_scanner"),
            (self._platform_sync_task, "platform_sync"),
            (self._cidr_task,        "cidr"),
            (self._spf_dmarc_task,   "spf_dmarc"),
        ]:
            if task and not task.done():
                logger.debug("shutdown: cancelling %s task", name)
                task.cancel()

        # ── Step 2: cancel ip_hunter and wait for its cleanup ─────────────
        if self._ip_hunter_task and not self._ip_hunter_task.done():
            self._ip_hunter_task.cancel()
            try:
                await asyncio.wait_for(
                    asyncio.shield(self._ip_hunter_task),
                    timeout=30.0,
                )
            except (asyncio.CancelledError, asyncio.TimeoutError):
                pass
            logger.info("ip_hunter: provider cleanup complete")
        else:
            logger.info("ip_hunter: not running, nothing to flush")

        # ── Step 3: cancel all remaining tasks ────────────────────────────
        current = asyncio.current_task()
        for task in asyncio.all_tasks():
            if task is not current and not task.done():
                task.cancel()

    async def stop(self):
        self.running = False
        from app.db.session import engine
        await engine.dispose()

    def _inject_cidr_index(self, cidr_index) -> None:
        """Inject a fresh CIDRIndex into all scanner components that use it."""
        for key in ("dns_scanner", "dns_takeover"):
            scanner = self.components.get(key)
            if scanner is not None:
                scanner.set_cidr_index(cidr_index)
        # SubdomainNSSweeper holds a reference to dns_scanner internally —
        # set_cidr_index on dns_scanner propagates because sweeper._scanner
        # IS the same object. No extra injection needed for ns_sweep.
        logger.debug("cidr_index: injected into %d scanner component(s)", 2)


async def main():
    daemon = Daemon()
    try:
        await daemon.run()
    except (KeyboardInterrupt, asyncio.CancelledError):
        logger.info("STOscanner daemon stopped")
    except Exception as e:
        logger.error("Fatal error in daemon: %s", e, exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass  # already handled inside, suppress the traceback
