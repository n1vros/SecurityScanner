"""
BugBase platform integration.
https://bugbase.ai/programs

API (no auth — CSRF token is set by server as a cookie on first request):
  List programs:
    GET https://bugbase.ai/api/hacktivity
        ?current_page=1&limit=999&search_term=&filter=max
    Response: { companies: [...], info: { next_page, total_pages, total_items } }
    Each company: { _id, programName, programUsername, programType, isPrivate,
                    isAcceptingBugs, maxBounty, scopeGroups: [...] }

  Program assets:
    GET https://bugbase.ai/api/hacktivity/get-program-assets/{programUsername}
        ?current_page=1&limit=all&search_term=
    Response: { assets: [{ _id, url, assetType, assetName, status, labels }] }
    assetType: "web" | "api" | "mobile" | "network" | "other"

Filtering:
  - programType must be "bugbounty" (skip VDPs)
  - isPrivate must be False
  - isAcceptingBugs must be True
  - Only assetType "web" and "api" assets contain URLs worth scanning
  - Assets must belong to an isInScope=True scopeGroup
"""

import asyncio
from datetime import datetime
from typing import List, Optional, Dict, Any, Set

import httpx
from sqlalchemy import and_, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.logging import logger
from app.db.db_models import Program, ProgramPlatform, Scope
from app.programs.base import PlatformBase
from app.programs.domain_utils import extract_domains


_BASE_URL      = "https://bugbase.ai"
_LIST_URL      = f"{_BASE_URL}/api/hacktivity"
_ASSETS_URL    = f"{_BASE_URL}/api/hacktivity/get-program-assets/{{username}}"

# Asset types that carry web URLs worth scanning
_WEB_ASSET_TYPES = {"web", "api"}


class BugBasePlatform(PlatformBase):
    """BugBase platform integration — bug bounty programs only."""

    platform = ProgramPlatform.BUGBASE   # add BUGBASE = "bugbase" to ProgramPlatform enum

    def __init__(self):
        self.client = httpx.AsyncClient(
            base_url=_BASE_URL,
            timeout=30.0,
            headers={
                "Accept":     "application/json",
                "User-Agent": "Mozilla/5.0 (compatible; STOscanner/1.0)",
                "Referer":    f"{_BASE_URL}/programs",
            },
            follow_redirects=True,
        )
        self._csrf_token: Optional[str] = None

        # Conservative rate limit — no documented limit, be a good citizen
        self._rate_limit_delay  = 1.0
        self._last_request_time = 0.0

    async def authenticate(self, cookie_file: Optional[str] = None) -> Dict[str, Any]:
        """
        No credentials needed — fetch the CSRF token that the server issues
        automatically as a cookie on the first request.
        """
        try:
            resp = await self._make_request(
                "GET", "/api/hacktivity",
                params={"current_page": 1, "limit": 1, "search_term": ""},
            )
            return {"authenticated": resp.status_code == 200, "status": resp.status_code}
        except Exception as e:
            return {"authenticated": False, "error": str(e)}

    async def fetch_programs(
        self,
        session: AsyncSession,
        cookie_file: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """
        Fetch all public bug bounty programs and extract web/api scope domains.

        Returns list of dicts with keys:
          name, external_id, url, scopes (List[str]), metadata
        """
        logger.info("Fetching BugBase programs...")

        raw_programs = await self._fetch_all_programs()
        if not raw_programs:
            logger.error("BugBase: failed to fetch program list")
            return []

        logger.info(
            "BugBase: %d bug bounty programs found — fetching assets", len(raw_programs)
        )

        results       = []
        total_domains = 0

        for item in raw_programs:
            try:
                info = await self._process_program(item)
                if info:
                    results.append(info)
                    total_domains += len(info["scopes"])
            except Exception as e:
                logger.error(
                    "BugBase: error processing %s: %s",
                    item.get("programUsername", "?"), e,
                )

        logger.info(
            "Fetched %d BugBase programs with %d total web scopes",
            len(results), total_domains,
        )
        return results

    async def _fetch_all_programs(self) -> List[Dict[str, Any]]:
        """
        Page through GET /api/hacktivity and return all public bug bounty programs.

        Pagination: info.next_page == -1 means last page.
        Uses limit=20 per page (matches site default) to avoid timeouts.
        """
        programs  = []
        page      = 1

        while True:
            try:
                resp = await self._make_request(
                    "GET", "/api/hacktivity",
                    params={
                        "current_page": page,
                        "limit":        20,
                        "search_term":  "",
                        "filter":       "max",
                    },
                )
                data      = resp.json()
                companies = data.get("companies") or []
                info      = data.get("info", {})

                # Filter client-side: public bug bounty programs only
                for c in companies:
                    if c.get("programType") != "bugbounty":
                        continue
                    if c.get("isPrivate", True):
                        continue
                    if not c.get("isAcceptingBugs", False):
                        continue
                    programs.append(c)

                next_page = info.get("next_page", -1)
                if next_page == -1 or not companies:
                    break
                page = next_page

            except Exception as e:
                logger.error("BugBase: error fetching page %d: %s", page, e)
                break

        logger.info("BugBase: %d public bug bounty programs found", len(programs))
        return programs

    async def _process_program(self, item: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Fetch assets for one program, filter to in-scope web/api assets,
        and extract domains.

        The programs list includes scopeGroups with asset ID lists but not the
        asset URLs — we need the separate assets endpoint for those.

        In-scope asset IDs are collected from scopeGroups where isInScope=True,
        then cross-referenced against the fetched asset objects.
        """
        username = item.get("programUsername")
        name     = item.get("programName", username)

        if not username:
            return None

        # Collect asset IDs that belong to in-scope groups
        in_scope_ids: Set[str] = set()
        for group in item.get("scopeGroups") or []:
            if group.get("isInScope"):
                in_scope_ids.update(group.get("assets") or [])

        if not in_scope_ids:
            logger.debug("BugBase [%s]: no in-scope asset IDs", name)
            return None

        assets = await self._fetch_program_assets(username)
        if not assets:
            return None

        domains: List[str] = []

        for asset in assets:
            # Only process in-scope assets
            if asset.get("_id") not in in_scope_ids:
                continue

            asset_type = (asset.get("assetType") or "").lower()
            if asset_type not in _WEB_ASSET_TYPES:
                continue

            raw_url = (asset.get("url") or "").strip()
            if not raw_url:
                continue

            for domain in extract_domains(raw_url, name):
                if domain not in domains:
                    domains.append(domain)

        if not domains:
            logger.debug("BugBase [%s]: no web scopes after filtering", name)
            return None

        return {
            "name":        name,
            "external_id": username,
            "url":         f"{_BASE_URL}/programs/{username}",
            "scopes":      domains,
            "metadata": {
                "username":                username,
                "max_bounty":              item.get("maxBounty", 0),
                "total_assets":            len(assets),
                "in_scope_asset_ids":      len(in_scope_ids),
                "bounty_eligible_domains": len(domains),
            },
        }

    async def _fetch_program_assets(self, username: str) -> List[Dict[str, Any]]:
        """
        GET /api/hacktivity/get-program-assets/{username}?limit=all

        Returns all asset objects for the program.
        """
        try:
            resp = await self._make_request(
                "GET",
                f"/api/hacktivity/get-program-assets/{username}",
                params={"current_page": 1, "limit": "all", "search_term": ""},
            )
            return resp.json().get("assets") or []
        except Exception as e:
            logger.error("BugBase: failed to fetch assets for %s: %s", username, e)
            return []

    async def _make_request(self, method: str, path: str, **kwargs) -> httpx.Response:
        """
        Rate-limited request. Captures CSRF token from Set-Cookie on first
        response and injects it into subsequent requests as a header.
        """
        elapsed = asyncio.get_event_loop().time() - self._last_request_time
        if elapsed < self._rate_limit_delay:
            await asyncio.sleep(self._rate_limit_delay - elapsed)

        # Inject CSRF token if we have one
        if self._csrf_token:
            kwargs.setdefault("headers", {})["x-csrf-token"] = self._csrf_token

        max_retries = 3
        for attempt in range(max_retries):
            try:
                self._last_request_time = asyncio.get_event_loop().time()
                resp = await self.client.request(method, path, **kwargs)

                # Capture CSRF token issued by server for next requests
                new_token = resp.cookies.get("x-csrf-token")
                if new_token:
                    self._csrf_token = new_token
                    self.client.headers["x-csrf-token"] = new_token

                if resp.status_code == 429:
                    retry_after = int(resp.headers.get("Retry-After", 60))
                    logger.warning("BugBase: rate limited — retrying after %ds", retry_after)
                    await asyncio.sleep(retry_after)
                    continue

                resp.raise_for_status()
                return resp

            except httpx.HTTPError as e:
                if attempt < max_retries - 1:
                    wait = 2 ** attempt
                    logger.warning(
                        "BugBase: request failed (attempt %d/%d): %s — retrying in %ds",
                        attempt + 1, max_retries, e, wait,
                    )
                    await asyncio.sleep(wait)
                else:
                    raise

        raise httpx.HTTPError(f"BugBase: request failed after {max_retries} retries: {path}")

    async def sync_programs(
        self,
        session: AsyncSession,
        cookie_file: Optional[str] = None,
    ) -> List[Program]:
        """Sync BugBase programs to DB with scope deduplication."""
        logger.info("Syncing programs from %s", self.platform.value)

        programs_data = await self.fetch_programs(session, cookie_file)
        synced    = []
        total_new = 0

        for data in programs_data:
            program = await self._create_or_update_program(session, data)
            if program:
                synced.append(program)
                total_new += await self._sync_scopes_with_deduplication(
                    session, program, data.get("scopes", [])
                )

        logger.info(
            "Synced %d programs from %s with %d new domains",
            len(synced), self.platform.value, total_new,
        )
        return synced

    async def _sync_scopes_with_deduplication(
        self,
        session: AsyncSession,
        program: Program,
        domains: List[str],
    ) -> int:
        """Insert new scopes, deactivate removed ones. Returns count of new domains."""
        if not domains:
            return 0

        result = await session.execute(
            select(Scope).where(
                Scope.program_id == program.id,
                Scope.is_active == True,
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
            logger.debug("Added %d scopes to %s", len(new_domains), program.name)

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
            logger.debug("Deactivated %d scopes from %s", len(removed), program.name)

        return len(new_domains)

    async def close(self):
        await self.client.aclose()