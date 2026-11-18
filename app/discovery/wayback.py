"""
app/discovery/wayback.py

Historical URL archive subdomain discovery.

Queries gau (GetAllUrls) and waybackurls for every URL ever crawled under
a scope domain. Extracts unique hostnames from those URLs — including
subdomains that no longer have active DNS records, were decommissioned, or
never appeared in certificate transparency logs.

Why this finds things other sources miss:
  - Staging/dev subdomains that were never publicly announced
  - Subdomains that existed years ago and were deleted but still have
    dangling DNS records
  - Internal tooling that briefly hit the public internet
  - Subdomains discovered via crawling, not cert issuance

gau queries: Wayback Machine, Common Crawl, URLScan.io, AlienVault OTX
waybackurls queries: Wayback Machine CDX API directly

This module intentionally does NOT run katana (live crawl) — that belongs
to js_scrape.py. This is purely historical/passive, zero live traffic.

Config:
  WAYBACK_ENABLED          bool  default True
  WAYBACK_GAU_BINARY       str   default "gau"
  WAYBACK_WAYBACKURLS_BIN  str   default "waybackurls"
  WAYBACK_TOOL_TIMEOUT     int   default 90   (seconds — archives are slow)
  WAYBACK_MAX_URLS         int   default 50000 (cap to avoid memory issues)
"""

import asyncio
from typing import List, Set
from urllib.parse import urlparse

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.logging import logger
from app.db.db_models import DiscoverySource, Scope
from app.discovery.active import ActiveDiscovery


class WaybackDiscovery:
    """
    Historical archive subdomain discovery using gau + waybackurls.

    Instantiated once in Daemon.__init__, called from _scan_scope after
    passive discovery — same pattern as JSDiscovery.
    """

    def __init__(self) -> None:
        self._gau_bin     = getattr(settings, "WAYBACK_GAU_BINARY",      "gau")
        self._wayback_bin = getattr(settings, "WAYBACK_WAYBACKURLS_BIN", "waybackurls")
        self._timeout     = getattr(settings, "WAYBACK_TOOL_TIMEOUT",    90)
        self._max_urls    = getattr(settings, "WAYBACK_MAX_URLS",         50000)

    # ── Public API ─────────────────────────────────────────────────────────

    async def enrich(self, session: AsyncSession, scope: Scope) -> List[str]:
        """
        Query archives for all historical URLs under scope.domain,
        extract unique hostnames, upsert new ones. Returns new names.
        """
        if not getattr(settings, "WAYBACK_ENABLED", True):
            return []

        domain = scope.domain
        logger.info("wayback: starting for %s", domain)

        # Run gau and waybackurls in parallel — both are purely passive
        gau_lines, wayback_lines = await asyncio.gather(
            self._run_gau(domain),
            self._run_waybackurls(domain),
            return_exceptions=True,
        )

        all_lines: List[str] = []
        for result in (gau_lines, wayback_lines):
            if isinstance(result, Exception):
                logger.debug("wayback: tool error for %s: %s", domain, result)
            else:
                all_lines.extend(result)

        if not all_lines:
            logger.debug("wayback: no URLs returned for %s", domain)
            return []

        # Cap to avoid processing huge URL sets
        if len(all_lines) > self._max_urls:
            logger.debug(
                "wayback: capping %d URLs to %d for %s",
                len(all_lines), self._max_urls, domain,
            )
            all_lines = all_lines[: self._max_urls]

        logger.info("wayback: %d raw URLs for %s — extracting hostnames", len(all_lines), domain)

        # Extract unique in-scope hostnames from all URLs
        hostnames = self._extract_hostnames(all_lines, domain)

        if not hostnames:
            logger.debug("wayback: no in-scope hostnames found for %s", domain)
            return []

        logger.info(
            "wayback: %d unique hostnames extracted for %s",
            len(hostnames), domain,
        )

        # Upsert via existing ActiveDiscovery path
        upserted = await ActiveDiscovery.upsert_subdomains(
            session, domain, list(hostnames), source=DiscoverySource.WAYBACK.value
        )

        if upserted:
            logger.info(
                "wayback: %d new subdomains for %s: %s",
                len(upserted), domain, upserted,
            )

        return upserted

    # ── Tool runners ───────────────────────────────────────────────────────

    async def _run_gau(self, domain: str) -> List[str]:
        """
        Run gau with --subs to include subdomains across all archive sources.
        No blacklist — we want every URL type, not just JS.
        """
        cmd = [
            self._gau_bin,
            domain,
            "--subs",   # include subdomains
        ]
        return await self._run_tool(cmd, "gau", domain)

    async def _run_waybackurls(self, domain: str) -> List[str]:
        """Run waybackurls for Wayback Machine CDX API coverage."""
        cmd = [self._wayback_bin, domain]
        return await self._run_tool(cmd, "waybackurls", domain)

    async def _run_tool(self, cmd: List[str], tool_name: str, domain: str) -> List[str]:
        """Generic subprocess runner — shared pattern with js_scrape._run_tool."""
        logger.debug("wayback: running %s for %s", tool_name, domain)
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
                    "wayback: %s timed out after %ds for %s",
                    tool_name, self._timeout, domain,
                )
                return []

            lines = stdout.decode(errors="ignore").splitlines()
            logger.debug(
                "wayback: %s returned %d lines for %s",
                tool_name, len(lines), domain,
            )
            return lines

        except FileNotFoundError:
            logger.warning(
                "wayback: %s binary not found at '%s' — skipping",
                tool_name, cmd[0],
            )
            return []
        except Exception as e:
            logger.debug("wayback: %s error for %s: %s", tool_name, domain, e)
            return []

    # ── Hostname extraction ────────────────────────────────────────────────

    @staticmethod
    def _extract_hostnames(lines: List[str], scope_domain: str) -> Set[str]:
        """
        Extract unique in-scope hostnames from a list of URLs.

        Keeps only hostnames that equal scope_domain or are subdomains of it.
        Strips ports, skips IPs, lowercases everything.
        """
        suffix = f".{scope_domain}"
        found: Set[str] = set()

        for line in lines:
            url = line.strip()
            if not url:
                continue

            # Handle bare hostnames (no scheme) — waybackurls sometimes outputs these
            if not url.startswith("http"):
                url = f"http://{url}"

            try:
                host = urlparse(url).hostname or ""
            except Exception:
                continue

            host = host.lower()
            if not host:
                continue

            # Skip IPs
            if host.replace(".", "").isdigit():
                continue

            # Must be in scope
            if host == scope_domain or host.endswith(suffix):
                found.add(host)

        return found