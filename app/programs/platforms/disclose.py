"""
disclose.io platform integration.
https://disclose.io/programs/

Data source: Raw JSON from the open-source diodb GitHub repository.
  GET https://raw.githubusercontent.com/disclose/diodb/master/program-list.json
  No auth required — public dataset.

Each entry has:
  program_name    str
  policy_url      str   — the program's disclosure/bounty page URL
  offers_bounty   "yes" | "" — only import when "yes"
  contact_url     str   — fallback URL if policy_url is empty
  contact_email   str
  policy_url_status "alive" | "dead" | ...

Platform detection:
  The policy_url is inspected against a map of known platform domains
  (hackerone.com, bugcrowd.com, yeswehack.com, etc.).  Programs whose URL
  points to a known managed platform are skipped — they are already (or will
  be) collected by the dedicated platform scraper.

  Programs whose URL does NOT match a known platform are treated as
  self-hosted and saved with platform = SELF_HOSTED.

Scope extraction:
  disclose.io entries rarely list explicit sub-scopes, so we derive the
  scope from the registered domain of policy_url (or contact_url as fallback).
  If no URL is available the entry is skipped.
"""

import asyncio
from datetime import datetime
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import httpx
from sqlalchemy import and_, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.logging import logger
from app.db.db_models import Program, ProgramPlatform, Scope
from app.programs.base import PlatformBase
from app.programs.domain_utils import registered_domain


_JSON_URL = (
    "https://raw.githubusercontent.com/disclose/diodb/master/program-list.json"
)

# Known managed platform hostnames → their ProgramPlatform value.
# Programs whose policy_url matches one of these are SKIPPED (handled by
# the dedicated platform scraper).
_MANAGED_PLATFORM_HOSTS: Dict[str, str] = {
    "hackerone.com":      "hackerone",
    "bugcrowd.com":       "bugcrowd",
    "yeswehack.com":      "yeswehack",
    "intigriti.com":      "intigriti",
    "immunefi.com":       "immunefi",
    "bugbase.ai":         "bugbase",
    "federacy.com":       "federacy",
    "hackenproof.com":    "hackenproof",
    "openbugbounty.org":  None,   # skip — no bounty payout
    "vulnerability.circl.lu": None,
}


def _detect_platform(url: str) -> Optional[str]:
    """
    Return the platform key if the URL belongs to a managed platform,
    or None if the program is self-hosted / unknown.

    Returns the string "skip" for platforms we explicitly want to ignore.
    """
    if not url:
        return None
    try:
        host = urlparse(url).hostname or ""
        host = host.lower().removeprefix("www.")
    except Exception:
        return None

    for domain, platform in _MANAGED_PLATFORM_HOSTS.items():
        if host == domain or host.endswith(f".{domain}"):
            return platform or "skip"

    return None  # self-hosted


def _extract_scope_from_url(url: str) -> List[str]:
    """
    Derive a scope domain from a policy / contact URL.

    Uses registered_domain() directly rather than extract_domains() so that
    the PLATFORM_DOMAINS blocklist doesn't drop legitimate company domains
    that happen to be hosted on AWS, Azure, Cloudflare, etc.
    Only truly unusable URLs (no hostname, invalid TLD) return [].
    """
    if not url:
        return []
    try:
        host = urlparse(url).hostname or ""
        host = host.lower().removeprefix("www.")
    except Exception:
        return []
    domain = registered_domain(host)
    return [domain] if domain else []


class DisclosIOPlatform(PlatformBase):
    """disclose.io integration — self-hosted bug bounty programs only."""

    platform = ProgramPlatform.SELF_HOSTED

    def __init__(self):
        self.client = httpx.AsyncClient(
            timeout=60.0,
            headers={
                "Accept":     "application/json",
                "User-Agent": "STOscanner/1.0 (github.com/disclose/diodb)",
            },
            follow_redirects=True,
        )
        self._rate_limit_delay  = 0.0   # single bulk JSON — no per-request delay
        self._last_request_time = 0.0

    async def authenticate(self, cookie_file: Optional[str] = None) -> Dict[str, Any]:
        """No auth required — public dataset."""
        try:
            resp = await self.client.head(_JSON_URL)
            return {"authenticated": resp.status_code in (200, 301, 302)}
        except Exception as e:
            return {"authenticated": False, "error": str(e)}

    async def fetch_programs(
        self,
        session: AsyncSession,
        cookie_file: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """
        Download the full diodb JSON and return self-hosted bounty programs.

        Returns list of dicts:
          name, external_id, url, scopes (List[str]), metadata
        """
        logger.info("Fetching disclose.io program list from GitHub...")

        try:
            resp = await self.client.get(_JSON_URL)
            resp.raise_for_status()
            raw: List[Dict[str, Any]] = resp.json()
        except Exception as e:
            logger.error("disclose.io: failed to fetch program list: %s", e)
            return []

        logger.info("disclose.io: downloaded %d total entries", len(raw))

        results: List[Dict[str, Any]] = []
        skipped_no_bounty    = 0
        skipped_managed      = 0
        skipped_no_scope     = 0
        skipped_dead         = 0

        for entry in raw:
            name = (entry.get("program_name") or "").strip()
            if not name:
                continue

            # Only programs that offer monetary bounties
            if (entry.get("offers_bounty") or "").strip().lower() != "yes":
                skipped_no_bounty += 1
                continue

            # Skip dead policy URLs
            if (entry.get("policy_url_status") or "").strip().lower() == "dead":
                skipped_dead += 1
                continue

            policy_url  = (entry.get("policy_url")  or "").strip()
            contact_url = (entry.get("contact_url") or "").strip()
            primary_url = policy_url or contact_url

            # Detect managed platforms — skip those
            platform_hint = _detect_platform(primary_url)
            if platform_hint is not None:
                # Either a known managed platform (they handle it) or explicit skip
                skipped_managed += 1
                logger.debug(
                    "disclose.io: skipping '%s' — managed by %s",
                    name, platform_hint,
                )
                continue

            # Extract scope from the program's URL
            scopes = _extract_scope_from_url(primary_url)
            if not scopes and contact_url and contact_url != primary_url:
                scopes = _extract_scope_from_url(contact_url)

            if not scopes:
                skipped_no_scope += 1
                logger.debug("disclose.io: skipping '%s' — no extractable scope", name)
                continue

            external_id = name.lower().replace(" ", "-")

            results.append({
                "name":        name,
                "external_id": external_id,
                "url":         primary_url or None,
                "scopes":      scopes,
                "metadata": {
                    "source":       "disclose.io",
                    "offers_bounty": entry.get("offers_bounty", ""),
                    "offers_swag":   entry.get("offers_swag", ""),
                    "safe_harbor":   entry.get("safe_harbor", ""),
                    "launch_date":   entry.get("launch_date", ""),
                },
            })

        logger.info(
            "disclose.io: %d self-hosted bounty programs found "
            "(skipped: %d no-bounty, %d managed, %d no-scope, %d dead)",
            len(results),
            skipped_no_bounty,
            skipped_managed,
            skipped_no_scope,
            skipped_dead,
        )
        return results

    # -- DB sync with scope deduplication (mirrors other platforms) -----------

    async def sync_programs(
        self,
        session: AsyncSession,
        cookie_file: Optional[str] = None,
    ) -> List[Program]:
        """Sync disclose.io self-hosted programs to DB."""
        logger.info("Syncing programs from disclose.io (self-hosted)")
        programs_data = await self.fetch_programs(session, cookie_file)

        synced:    List[Program] = []
        total_new: int           = 0

        for data in programs_data:
            program = await self._create_or_update_program(session, data)
            if program:
                synced.append(program)
                total_new += await self._sync_scopes_with_deduplication(
                    session, program, data.get("scopes", [])
                )

        logger.info(
            "disclose.io: synced %d programs with %d new scopes",
            len(synced), total_new,
        )
        return synced

    async def _sync_scopes_with_deduplication(
        self,
        session: AsyncSession,
        program: Program,
        domains: List[str],
    ) -> int:
        if not domains:
            return 0

        result = await session.execute(
            select(Scope).where(
                Scope.program_id == program.id,
                Scope.is_active  == True,
            )
        )
        existing = {s.domain for s in result.scalars().all()}

        new_domains = set(domains) - existing
        for domain in new_domains:
            session.add(Scope(
                program_id=program.id,
                domain=domain,
                added_at=datetime.utcnow(),
            ))
        if new_domains:
            await session.commit()

        removed = existing - set(domains)
        if removed:
            await session.execute(
                update(Scope)
                .where(
                    and_(
                        Scope.program_id == program.id,
                        Scope.domain.in_(list(removed)),
                        Scope.is_active == True,
                    )
                )
                .values(is_active=False)
            )
            await session.commit()

        return len(new_domains)

    async def close(self) -> None:
        await self.client.aclose()