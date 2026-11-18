"""
Active discovery using puredns wordlist brute-forcing.

Strategy
--------
puredns bruteforce <wordlist> <domain> handles:
  - Wildcard detection and filtering (critical — aiodns had none)
  - Mass DNS resolution via massdns under the hood
  - Rate limiting via --rate-limit
  - Trusted resolver validation pass to eliminate false positives

Results are written to DB. Only subdomains that actually resolve and pass
puredns's wildcard filter are recorded.
"""

import asyncio
from pathlib import Path
from typing import Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.logging import logger
from app.discovery.resolvers import get_resolvers_file, get_resolver_list
from app.db.db_models import DiscoverySource, DiscoverySourceEntry, Scope, Subdomain


# ---------------------------------------------------------------------------
# Module-level semaphore — caps concurrent puredns processes
# ---------------------------------------------------------------------------

_puredns_semaphore: Optional[asyncio.Semaphore] = None


def _get_puredns_semaphore() -> asyncio.Semaphore:
    global _puredns_semaphore
    if _puredns_semaphore is None:
        limit = getattr(settings, "PUREDNS_MAX_CONCURRENT", 2)
        _puredns_semaphore = asyncio.Semaphore(limit)
        logger.debug("Initialized puredns semaphore with limit %d", limit)
    return _puredns_semaphore


# ---------------------------------------------------------------------------
# ActiveDiscovery
# ---------------------------------------------------------------------------

class ActiveDiscovery:
    """Active discovery using puredns wordlist brute-forcing."""

    def __init__(self):
        self.wordlist_path = self._get_wordlist_path()

        self._binary = getattr(settings, "PUREDNS_BINARY", "puredns")

        # Resolver file derived from DNS_RESOLVERS (15k+ IPs written to temp file)
        self._resolvers_path = get_resolvers_file()

        # DNS queries per second passed to puredns --rate-limit.
        # With 15k resolvers puredns/massdns can sustain very high QPS —
        # default bumped to 500; tune down if you see packet loss.
        self._rate_limit = getattr(settings, "PUREDNS_RATE_LIMIT", 500)

        # Timeout for the puredns subprocess in seconds.
        self._timeout = getattr(settings, "PUREDNS_TIMEOUT_SECS", 300)

        resolver_count = len(get_resolver_list())
        logger.debug(
            "ActiveDiscovery initialized — wordlist: %s | binary: %s | "
            "resolvers: %s (%d resolvers) | rate_limit: %d | timeout: %ds",
            self.wordlist_path,
            self._binary,
            self._resolvers_path,
            resolver_count,
            self._rate_limit,
            self._timeout,
        )

    # ── Public API ────────────────────────────────────────────────────────────

    async def enrich(self, session: AsyncSession, scope: Scope) -> list[str]:
        """
        Run puredns brute-force, persist results, and return newly inserted
        subdomain names so the daemon can use them as permutation seeds.
        """
        if not settings.ACTIVE_DISCOVERY_ENABLED:
            return []

        if not self.wordlist_path:
            logger.debug(
                "No wordlist configured — skipping active discovery for %s",
                scope.domain,
            )
            return []

        domain = scope.domain
        logger.debug("Starting active discovery for %s", domain)

        results = await self._run_puredns(domain)

        if not results:
            logger.debug("Active discovery found nothing for %s", domain)
            return []

        new_names: list[str] = []
        for name in results:
            new_name = await self._record_discovery(
                session, scope, name, DiscoverySource.PUREDNS
            )
            if new_name:
                new_names.append(new_name)

        await session.commit()
        logger.info(
            "Active discovery finished for %s — %d new subdomains (%d total resolved)",
            domain, len(new_names), len(results),
        )
        return new_names

    # ── puredns ──────────────────────────────────────────────────────────────

    async def _run_puredns(self, domain: str) -> list[str]:
        """
        Run puredns in bruteforce mode and return resolved subdomain names.

        puredns bruteforce <wordlist> <domain>
            --resolvers <resolvers_path>   # mass resolver pool
            --rate-limit <n>               # queries/sec per resolver
            --wildcard-tests 5             # wildcard detection rounds
            --wildcard-batch 1000000       # batch size for wildcard checks
            -q                             # quiet

        puredns outputs one verified subdomain per line to stdout and filters
        wildcards internally, so wildcard domains do not flood the DB.
        """
        sem = _get_puredns_semaphore()

        cmd = [
            self._binary,
            "bruteforce",
            str(self.wordlist_path),
            domain,
            "--rate-limit", str(self._rate_limit),
            "--wildcard-tests", "5",
            "--wildcard-batch", "1000000",
            "-q",
        ]

        if self._resolvers_path and Path(self._resolvers_path).exists():
            cmd += ["--resolvers", self._resolvers_path]
        else:
            logger.warning(
                "Resolver file missing — puredns will use system resolver only, results may be poor"
            )

        logger.debug("Running puredns: %s", " ".join(cmd))

        async with sem:
            try:
                proc = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.DEVNULL,
                )
                try:
                    stdout, _ = await asyncio.wait_for(
                        proc.communicate(), timeout=self._timeout
                    )
                except asyncio.TimeoutError:
                    proc.kill()
                    await proc.communicate()
                    logger.warning(
                        "puredns timed out after %ds for %s", self._timeout, domain
                    )
                    return []

                if proc.returncode != 0:
                    logger.warning(
                        "puredns exited with code %d for %s",
                        proc.returncode, domain,
                    )
                    # Still parse stdout — puredns may return non-zero but
                    # still have written valid results before failing.

                lines = stdout.decode(errors="ignore").splitlines()
                results = [
                    line.strip().lower()
                    for line in lines
                    if line.strip() and (
                        line.strip().endswith(f".{domain}")
                        or line.strip() == domain
                    )
                ]
                logger.info(
                    "puredns returned %d results for %s", len(results), domain
                )
                return results

            except FileNotFoundError:
                logger.error(
                    "puredns binary not found at '%s' — "
                    "install with: go install github.com/d3mondev/puredns/v2@latest",
                    self._binary,
                )
                return []
            except Exception as e:
                logger.error("puredns error for %s: %s", domain, e)
                return []

    # ── DB persistence ────────────────────────────────────────────────────────

    async def _record_discovery(
        self,
        session: AsyncSession,
        scope: Scope,
        subdomain_name: str,
        source: DiscoverySource,
    ) -> str | None:
        """
        Insert subdomain + discovery source if not already present.
        Returns the subdomain name if it was newly created, else None.
        Returning the name (rather than a bool) lets callers build seed
        lists for permutation scanning without an extra lookup.
        """
        stmt = select(Subdomain).where(
            Subdomain.scope_id == scope.id,
            Subdomain.name == subdomain_name,
        )
        result = await session.execute(stmt)
        existing = result.scalar_one_or_none()

        if existing:
            subdomain = existing
            new_name = None
        else:
            subdomain = Subdomain(
                scope_id=scope.id,
                name=subdomain_name,
            )
            session.add(subdomain)
            await session.flush()
            new_name = subdomain_name

        stmt = select(DiscoverySourceEntry).where(
            DiscoverySourceEntry.subdomain_id == subdomain.id,
            DiscoverySourceEntry.source == source,
        )
        result = await session.execute(stmt)
        source_entry = result.scalar_one_or_none()

        if not source_entry:
            session.add(DiscoverySourceEntry(
                subdomain_id=subdomain.id,
                source=source,
            ))

        return new_name


    @classmethod
    async def upsert_subdomains(
        cls,
        session: AsyncSession,
        scope_domain: str,
        hostnames: list[str],
        source: str = "permutation",
    ) -> list[str]:
        """
        Upsert a list of resolved hostnames for a given scope domain.

        Called by PermutationDiscovery (and any other component that needs to
        persist discovered subdomains without going through a full Scope object).

        Args:
            session:      AsyncSession for DB writes.
            scope_domain: Parent scope domain string (e.g. "example.com").
            hostnames:    Fully-qualified subdomain names to upsert.
            source:       Discovery source tag (default "permutation").

        Returns:
            List of subdomain names that were newly inserted (excludes
            hostnames that already existed in the DB).
        """
        if not hostnames:
            return []

        # Resolve the scope row — permutation results must belong to a known scope.
        from sqlalchemy import select as _select
        stmt = _select(Scope).where(Scope.domain == scope_domain)
        result = await session.execute(stmt)
        scope = result.scalar_one_or_none()

        if not scope:
            logger.warning(
                "upsert_subdomains: scope '%s' not found in DB, skipping %d hosts",
                scope_domain, len(hostnames),
            )
            return []

        # Map source string to DiscoverySource enum
        try:
            ds = DiscoverySource(source)
        except ValueError:
            logger.warning(
                "upsert_subdomains: unknown source '%s' — add it to DiscoverySource enum. "
                "Defaulting to PUREDNS for now.",
                source,
            )
            ds = DiscoverySource.PUREDNS

        instance = cls()
        new_names: list[str] = []
        for hostname in hostnames:
            name = await instance._record_discovery(session, scope, hostname, ds)
            if name:
                new_names.append(name)

        await session.commit()
        if new_names:
            logger.info(
                "upsert_subdomains: %d new / %d total for scope %s (source=%s)",
                len(new_names), len(hostnames), scope_domain, source,
            )
        else:
            logger.debug(
                "upsert_subdomains: 0 new / %d total for scope %s (source=%s) — all already known",
                len(hostnames), scope_domain, source,
            )
        return new_names

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _get_wordlist_path(self) -> Optional[Path]:
        """Return wordlist path from settings if it exists, else None."""
        raw = getattr(settings, "ACTIVE_WORDLIST_PATH", None)
        if not raw:
            return None
        path = Path(raw)
        if not path.exists():
            logger.warning(
                "Wordlist not found at %s — active brute-force disabled", path
            )
            return None
        return path