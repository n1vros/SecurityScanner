"""
Immunefi platform integration.

Fetches all bug bounty programs and extracts web/app scope domains.

Data source: unofficial GitHub mirror that tracks Immunefi program changes.
  Program list:   https://raw.githubusercontent.com/infosec-us-team/
                  Immunefi-Bug-Bounty-Programs-Unofficial/main/projects.json
  Program detail: .../project/{project_id}.json

Asset types in Immunefi programs:
  - smart_contract          → blockchain address, skip
  - blockchain_dlt          → chain/node repo, skip
  - websites_and_applications → URL, extract domains ← we want these
  - other                   → skip

No authentication required — the GitHub raw URLs are public.
Rate limit: we self-impose a small delay to avoid hammering GitHub.
"""

import asyncio
from typing import List, Optional, Dict, Any

import httpx
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.logging import logger
from app.db.db_models import Program, ProgramPlatform
from app.programs.base import PlatformBase
from app.programs.domain_utils import extract_domains


_BASE_RAW = (
    "https://raw.githubusercontent.com/"
    "infosec-us-team/Immunefi-Bug-Bounty-Programs-Unofficial/main"
)
_PROJECTS_URL = f"{_BASE_RAW}/projects.json"
_PROJECT_URL  = f"{_BASE_RAW}/project/{{project_id}}.json"

# Only these asset types contain web URLs worth scanning.
_WEB_ASSET_TYPES = {"websites_and_applications"}


class ImmunefiPlatform(PlatformBase):
    """Immunefi platform integration — web/app scopes only."""

    platform = ProgramPlatform.IMMUNEFI   # add IMMUNEFI to ProgramPlatform enum

    def __init__(self):
        self.client = httpx.AsyncClient(
            timeout=30.0,
            headers={
                "Accept":     "application/json",
                "User-Agent": "STOscanner/1.0",
            },
        )
        # GitHub raw has a generous rate limit but be a good citizen
        self._rate_limit_delay  = 0.5
        self._last_request_time = 0.0

    async def authenticate(self, cookie_file: Optional[str] = None) -> Dict[str, Any]:
        """No auth needed — verify connectivity with a lightweight request."""
        try:
            resp = await self._make_request(_PROJECTS_URL)
            return {"authenticated": resp.status_code == 200, "status": resp.status_code}
        except Exception as e:
            return {"authenticated": False, "error": str(e)}

    async def fetch_programs(
        self,
        session: AsyncSession,
        cookie_file: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """
        Fetch all Immunefi programs and extract web/app scope domains.

        projects.json contains full program detail objects — no per-program
        detail fetch needed.

        Returns list of dicts with keys:
          name, external_id, url, scopes (List[str]), metadata
        """
        logger.info("Fetching Immunefi programs...")

        raw_programs = await self._fetch_all_programs()
        if not raw_programs:
            logger.error("Immunefi: failed to fetch program list")
            return []

        logger.info("Immunefi: %d programs found — extracting web scopes", len(raw_programs))

        results       = []
        total_domains = 0

        for item in raw_programs:
            try:
                info = await self._process_program(item)
                if info:
                    results.append(info)
                    total_domains += len(info["scopes"])
            except Exception as e:
                logger.error("Immunefi: error processing %s: %s", item.get("slug", "?"), e)

        logger.info(
            "Fetched %d Immunefi programs with %d total web scopes",
            len(results), total_domains,
        )
        return results

    async def _fetch_all_programs(self) -> List[Dict[str, Any]]:
        """
        GET projects.json — returns list of full program detail objects.

        The mirror's projects.json is a list where each item is a complete
        program object with 'slug', 'assets', 'maxBounty', etc.
        Falls back to fetching individual project/{slug}.json if the list
        contains plain strings.
        """
        try:
            resp = await self._make_request(_PROJECTS_URL)
            data = resp.json()
            items = data if isinstance(data, list) else (
                data.get("projects") or data.get("data") or []
            )
            if not items:
                return []

            # Already full objects — use directly
            if isinstance(items[0], dict):
                return items

            # Plain slug strings — fetch each detail individually
            logger.info("Immunefi: projects.json has slugs only, fetching details...")
            results = []
            for slug in items:
                try:
                    detail_resp = await self._make_request(
                        _PROJECT_URL.format(project_id=str(slug))
                    )
                    results.append(detail_resp.json())
                except Exception as e:
                    logger.debug("Immunefi: failed to fetch detail for %s: %s", slug, e)
            return results

        except Exception as e:
            logger.error("Immunefi: failed to fetch program list: %s", e)
            return []



    async def _process_program(self, data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Extract web/app domains from a program detail object.

        projects.json items shape (relevant parts):
          {
            "slug":      "ens",
            "project":   "ENS",
            "maxBounty": 250000,
            "assets": [
              { "type": "websites_and_applications", "url": "https://app.ens.domains", ... },
              { "type": "smart_contract",            "url": "0xabcd...",               ... }
            ]
          }
        """
        slug   = data.get("slug") or data.get("project") or "unknown"
        name   = data.get("project") or data.get("slug") or slug
        assets = data.get("assets") or []

        domains: List[str] = []

        for asset in assets:
            asset_type = (asset.get("type") or "").lower()
            if asset_type not in _WEB_ASSET_TYPES:
                continue

            raw_url = (asset.get("url") or "").strip()
            if not raw_url:
                continue

            for domain in extract_domains(raw_url, name):
                if domain not in domains:
                    domains.append(domain)

        if not domains:
            logger.debug("Immunefi [%s]: no web scopes, skipping", name)
            return None

        max_bounty = data.get("maxBounty") or data.get("maximumBounty") or 0
        try:
            max_bounty = int(max_bounty)
        except (TypeError, ValueError):
            max_bounty = 0

        return {
            "name":        name,
            "external_id": slug,
            "url":         f"https://immunefi.com/bug-bounty/{slug}/information/",
            "scopes":      domains,
            "metadata": {
                "project_id":              slug,
                "max_bounty":              max_bounty,
                "total_assets":            len(assets),
                "bounty_eligible_domains": len(domains),
            },
        }


    async def _make_request(self, url: str, **kwargs) -> httpx.Response:
        """Rate-limited GET with retry on transient errors."""
        elapsed = asyncio.get_event_loop().time() - self._last_request_time
        if elapsed < self._rate_limit_delay:
            await asyncio.sleep(self._rate_limit_delay - elapsed)

        max_retries = 3
        for attempt in range(max_retries):
            try:
                self._last_request_time = asyncio.get_event_loop().time()
                resp = await self.client.get(url, **kwargs)

                if resp.status_code == 429:
                    retry_after = int(resp.headers.get("Retry-After", 60))
                    logger.warning("Immunefi: rate limited — retrying after %ds", retry_after)
                    await asyncio.sleep(retry_after)
                    continue

                if resp.status_code == 404:
                    # Program detail missing from mirror — not an error
                    logger.debug("Immunefi: 404 for %s", url)
                    resp.raise_for_status()

                resp.raise_for_status()
                return resp

            except httpx.HTTPStatusError:
                raise
            except httpx.HTTPError as e:
                if attempt < max_retries - 1:
                    wait = 2 ** attempt
                    logger.warning(
                        "Immunefi: request failed (attempt %d/%d): %s — retrying in %ds",
                        attempt + 1, max_retries, e, wait,
                    )
                    await asyncio.sleep(wait)
                else:
                    raise

        raise httpx.HTTPError(f"Immunefi: request failed after {max_retries} retries: {url}")

    async def close(self):
        await self.client.aclose()