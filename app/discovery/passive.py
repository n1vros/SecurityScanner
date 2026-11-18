import asyncio
import re
from datetime import datetime
from typing import List, Set, Dict, Optional

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.logging import logger
from app.db import Scope
from app.db.db_models import Subdomain, DiscoverySource, DiscoverySourceEntry


# ---------------------------------------------------------------------------
# Module-level semaphore — lazy init inside running event loop.
#
# The semaphore must be created inside the running event loop. A class-level
# semaphore can be touched before the loop starts (import-time or tests), bind
# to no loop on Python 3.10+, and deadlock silently on every `async with`.
# Same lazy pattern as _puredns_semaphore in active.py.
# ---------------------------------------------------------------------------

_subfinder_semaphore: Optional[asyncio.Semaphore] = None


def _get_subfinder_semaphore() -> asyncio.Semaphore:
    global _subfinder_semaphore
    if _subfinder_semaphore is None:
        _subfinder_semaphore = asyncio.Semaphore(settings.SUBFINDER_MAX_CONCURRENT)
        logger.debug("Initialized subfinder semaphore with max %d", settings.SUBFINDER_MAX_CONCURRENT)
    return _subfinder_semaphore


class PassiveDiscovery:
    """Passive discovery using external tools."""

    async def enrich(self, session: AsyncSession, scope: Scope) -> list[str]:
        logger.debug("Starting passive discovery for domain: %s", scope.domain)
        results = await asyncio.gather(
            self._run_subfinder(scope.domain),
            self._run_crtsh(scope.domain),
            return_exceptions=True,
        )

        source_map = {0: DiscoverySource.SUBFINDER, 1: DiscoverySource.CRT_SH}
        discovered: Dict[str, Set[DiscoverySource]] = {}

        for idx, result in enumerate(results):
            if isinstance(result, Exception):
                # upgraded from debug to warning so failures are visible in production
                logger.warning(
                    "Passive tool error (%s) for %s: %s",
                    source_map[idx].value, scope.domain, result, exc_info=result,
                )
                continue
            logger.debug("Passive tool %s found %d subdomains for %s", source_map[idx].value, len(result), scope.domain)
            for name in result:
                discovered.setdefault(name, set()).add(source_map[idx])

        new_names: list[str] = []
        for name, sources in discovered.items():
            primary_source = sorted(sources, key=lambda s: s.value)[0]
            new_name = await self._record_discovery(session, scope, name, primary_source)
            if new_name:
                new_names.append(new_name)

        logger.debug(
            "Finished passive discovery for domain: %s, new: %d, total: %d",
            scope.domain, len(new_names), len(discovered),
        )
        return new_names

    async def _run_subfinder(self, domain: str) -> List[str]:
        # Subfinder is a subprocess — proxychains handles it automatically.
        semaphore = _get_subfinder_semaphore()
        async with semaphore:
            logger.debug("Running subfinder for domain: %s", domain)
            cmd = [
                settings.SUBFINDER_BINARY,
                "-d", domain,
                "-silent",
                "-timeout", "30",
            ]
            try:
                proc = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                try:
                    stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=settings.SUBFINDER_TIMEOUT)
                except asyncio.TimeoutError:
                    proc.kill()
                    await proc.communicate()
                    logger.warning("Subfinder timed out for %s", domain)
                    return []

                if proc.returncode != 0:
                    logger.warning("Subfinder failed for %s: %s", domain, stderr.decode().strip())
                    return []

                output = [l.strip() for l in stdout.decode().strip().split("\n") if l.strip()]
                logger.debug("Subfinder returned %d subdomains for %s", len(output), domain)
                return output
            except Exception as e:
                # upgraded from debug to warning with full traceback
                logger.warning("Subfinder error for %s: %s", domain, e, exc_info=True)
                return []

    async def _run_crtsh(self, domain: str) -> List[str]:
        import aiohttp
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        logger.debug("Querying crt.sh for domain: %s", domain)

        # Route through the configured SOCKS5 proxy so crt.sh queries
        # don't leak the home IP. Set HTTP_PROXY=socks5://127.0.0.1:1080 in .env
        proxy = getattr(settings, "HTTP_PROXY", None)

        try:
            async with aiohttp.ClientSession() as http_session:
                async with http_session.get(
                    url,
                    timeout=aiohttp.ClientTimeout(total=30),
                    proxy=proxy,
                ) as resp:
                    if resp.status != 200:
                        logger.debug("crt.sh returned status %d for domain %s", resp.status, domain)
                        return []
                    data = await resp.json(content_type=None)

            subdomains: Set[str] = set()
            for entry in data:
                name = entry.get("name_value", "")
                if name:
                    for part in re.split(r"[\n,]", name):
                        part = part.strip().lower()
                        if part and (part == domain or part.endswith(f".{domain}")) and not part.startswith("*."):
                            subdomains.add(part)
            logger.debug("crt.sh returned %d subdomains for %s", len(subdomains), domain)
            return list(subdomains)
        except Exception as e:
            logger.debug("crt.sh error for %s: %s", domain, e)
            return []

    async def _record_discovery(
        self,
        session: AsyncSession,
        scope: Scope,
        discovered_name: str,
        source: DiscoverySource,
    ) -> str | None:
        from sqlalchemy.dialects.postgresql import insert as pg_insert
        discovered_name = discovered_name.lower().strip()
        logger.debug("Recording discovery: %s from %s", discovered_name, source.value)

        # ON CONFLICT DO NOTHING + RETURNING: returns the new id only if the
        # row was actually inserted. Returns None for already-existing rows.
        # This lets enrich() build a seed list of *new* subdomains for
        # permutation scanning without an extra SELECT.
        subdomain_stmt = (
            pg_insert(Subdomain)
            .values(scope_id=scope.id, name=discovered_name, discovered_at=datetime.utcnow())
            .on_conflict_do_nothing(constraint="uq_scope_subdomain")
            .returning(Subdomain.id)
        )
        result = await session.execute(subdomain_stmt)
        row = result.scalar_one_or_none()

        if row is None:
            # Already exists — still record the source, but not a new discovery
            from sqlalchemy import select as _select
            existing = await session.execute(
                _select(Subdomain.id).where(
                    Subdomain.scope_id == scope.id,
                    Subdomain.name == discovered_name,
                )
            )
            subdomain_id = existing.scalar_one()
            new_name = None
        else:
            subdomain_id = row
            new_name = discovered_name

        source_stmt = (
            pg_insert(DiscoverySourceEntry)
            .values(subdomain_id=subdomain_id, source=source, discovered_at=datetime.utcnow())
            .on_conflict_do_nothing(constraint="uq_subdomain_source")
        )
        await session.execute(source_stmt)
        await session.commit()
        logger.debug("Finished recording %s for %s (new=%s)", discovered_name, scope.domain, new_name is not None)
        return new_name